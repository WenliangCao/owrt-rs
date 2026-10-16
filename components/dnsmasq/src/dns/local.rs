//! Local DNS answer construction.
//!
//! This is the answer side of dnsmasq's local cache/hosts path.  It deliberately
//! returns `None` when a name is not owned locally; the caller can then run the
//! upstream forwarder.  Keeping that boundary explicit prevents an incomplete
//! forwarder from turning an upstream miss into a fake empty answer.

use super::cache::{Cache, Kind};
use super::lease_names::LeaseNames;
use super::wire::{Header, Name, PacketWriter, Section, WireError};
use crate::config::dns::{DnsConfig, DomainPattern, RuleTarget};
use crate::config::records::{MailRecord, NaptrRecord, RawRecord, RecordConfig};
use crate::hosts::Hosts;
use crate::query_logging::{self as qlog, QueryEvents};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const CLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_NAPTR: u16 = 35;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerError {
    Malformed,
    UnsupportedClass,
    Wire(WireError),
}

impl From<WireError> for AnswerError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

/// Construct configured records for standalone callers. Runtime reloads use
/// configured_hosts_bulk so all input sources share C's temporary load state.
pub fn configured_hosts(config: &DnsConfig, local_ttl: u32) -> Hosts {
    let mut hosts = Hosts::new();
    hosts.set_round_robin(!config.no_round_robin);
    for record in &config.host_records {
        for name in &record.names {
            let ttl = record.ttl.unwrap_or(local_ttl);
            if let Some(address) = record.address4 {
                if let Ok(name) = crate::hosts::try_copy(name) {
                    hosts.insert(name, IpAddr::V4(address), ttl, 1); // SRC_CONFIG
                }
            }
            if let Some(address) = record.address6 {
                if let Ok(name) = crate::hosts::try_copy(name) {
                    hosts.insert(name, IpAddr::V6(address), ttl, 1);
                }
            }
        }
    }
    hosts
}

/// Start cache_reload's bulk generation before any configured address is
/// inserted. The caller reads every hosts source and finishes the bulk state
/// before publishing. Allocation failure drops this unpublished generation.
/// packet_limit is C's whole packet buffer: max(edns_packet_max, 512) + 265.
pub fn configured_hosts_bulk(
    config: &DnsConfig,
    local_ttl: u32,
    packet_limit: usize,
    cache_size: usize,
    minimum_hash_capacity: usize,
    retained_leases: &LeaseNames,
) -> Result<Hosts, ()> {
    let mut hosts = Hosts::new();
    hosts.set_round_robin(!config.no_round_robin);
    hosts.begin_bulk(packet_limit, cache_size, minimum_hash_capacity).map_err(|_| ())?;
    // cache_reload retains DHCP entries until the later lease publication.
    // Their names participate in duplicate lookup's temporary next chain.
    for entry in retained_leases.active_entries() {
        hosts.add_bulk_lease(
            &entry.name,
            IpAddr::V4(entry.address),
            entry.reverse,
            entry.expires.is_none(),
        ).map_err(|_| ())?;
    }
    for record in &config.host_records {
        for name in &record.names {
            let ttl = record.ttl.unwrap_or(local_ttl);
            for address in record.address4.map(IpAddr::V4).into_iter()
                .chain(record.address6.map(IpAddr::V6))
            {
                hosts.insert_checked(
                    crate::hosts::try_copy(name).map_err(|_| ())?,
                    address,
                    ttl,
                    1, // SRC_CONFIG
                ).map_err(|_| ())?;
            }
        }
    }
    Ok(hosts)
}

/// A local answer engine owns no sockets and performs no upstream I/O.  The
/// hosts table is mutable because dnsmasq rotates same-name addresses unless
/// `no-round-robin` is set.
/// Runtime loaders start with [`configured_hosts_bulk`] and finish loading
/// before passing the published generation to this answerer.
pub struct LocalAnswerer<'a> {
    pub config: &'a DnsConfig,
    pub hosts: &'a mut Hosts,
    pub local_ttl: u32,
    pub max_packet: usize,
}

pub(crate) struct LocalAnswer {
    pub packet: Vec<u8>,
    /// Address/local rules use forward_query's OPT policy, while configured
    /// records and hosts use answer_request's policy.
    pub forward_rule: bool,
    pub query_events: Vec<qlog::QueryEvent>,
}

#[derive(Clone, Copy)]
struct LeaseView<'a> {
    synth: &'a crate::config::synth_domain::SynthConfig,
    names: &'a LeaseNames,
    now: i64,
    local_ttl: u32,
    local_network: Option<(Ipv4Addr, Ipv4Addr)>,
    interfaces: &'a super::interface_records::InterfaceRecords,
}

impl<'a> LocalAnswerer<'a> {
    pub fn answer(&mut self, query: &[u8]) -> Result<Option<Vec<u8>>, AnswerError> {
        Ok(self.answer_with_source(query)?.map(|answer| answer.packet))
    }

    pub(crate) fn answer_with_source(
        &mut self,
        query: &[u8],
    ) -> Result<Option<LocalAnswer>, AnswerError> {
        self.answer_with_lease_source(query, &mut Arc::new(LeaseNames::default()), 0)
    }

    pub fn answer_with_leases(
        &mut self,
        query: &[u8],
        leases: &mut Arc<LeaseNames>,
        now: i64,
    ) -> Result<Option<Vec<u8>>, AnswerError> {
        Ok(self
            .answer_with_lease_source(query, leases, now)?
            .map(|answer| answer.packet))
    }

    pub(crate) fn answer_with_lease_source(
        &mut self,
        query: &[u8],
        leases: &mut Arc<LeaseNames>,
        now: i64,
    ) -> Result<Option<LocalAnswer>, AnswerError> {
        self.answer_on_network(query, leases, now, None)
    }

    pub(crate) fn answer_on_network(
        &mut self,
        query: &[u8],
        leases: &mut Arc<LeaseNames>,
        now: i64,
        local_network: Option<(Ipv4Addr, Ipv4Addr)>,
    ) -> Result<Option<LocalAnswer>, AnswerError> {
        self.answer_on_network_with_cache(query, leases, now, local_network, None)
    }

    pub(crate) fn answer_on_network_with_cache(
        &mut self,
        query: &[u8],
        lease_names: &mut Arc<LeaseNames>,
        now: i64,
        local_network: Option<(Ipv4Addr, Ipv4Addr)>,
        cache: Option<&mut Cache>,
    ) -> Result<Option<LocalAnswer>, AnswerError> {
        self.answer_on_network_with_interface_cache(
            query,
            lease_names,
            now,
            local_network,
            cache,
            &super::interface_records::InterfaceRecords::default(),
        )
    }

    pub(crate) fn answer_on_network_with_interface_cache(
        &mut self,
        query: &[u8],
        lease_names: &mut Arc<LeaseNames>,
        now: i64,
        local_network: Option<(Ipv4Addr, Ipv4Addr)>,
        cache: Option<&mut Cache>,
        interfaces: &super::interface_records::InterfaceRecords,
    ) -> Result<Option<LocalAnswer>, AnswerError> {
        self.answer_with_query_events(
            query,
            lease_names,
            now,
            local_network,
            cache,
            interfaces,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn answer_with_query_events(
        &mut self,
        query: &[u8],
        lease_names: &mut Arc<LeaseNames>,
        now: i64,
        local_network: Option<(Ipv4Addr, Ipv4Addr)>,
        cache: Option<&mut Cache>,
        interfaces: &super::interface_records::InterfaceRecords,
        logging: bool,
    ) -> Result<Option<LocalAnswer>, AnswerError> {
        let header = Header::parse(query).map_err(|_| AnswerError::Malformed)?;
        let question = super::forward::Question::parse_with_header(query, header)
            .map_err(|_| AnswerError::Malformed)?;
        self.answer_parsed_with_query_events(
            query, header, &question, lease_names, now, local_network,
            cache, interfaces, logging, &mut None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn answer_parsed_with_query_events<'q>(
        &mut self,
        query: &[u8],
        header: Header,
        question: &'q super::forward::Question,
        lease_names: &mut Arc<LeaseNames>,
        now: i64,
        local_network: Option<(Ipv4Addr, Ipv4Addr)>,
        cache: Option<&mut Cache>,
        interfaces: &super::interface_records::InterfaceRecords,
        logging: bool,
        name_lookup: &mut Option<super::cache::NameLookup<'q>>,
    ) -> Result<Option<LocalAnswer>, AnswerError> {
        if header.opcode() != 0
            || header.flags & 0x8000 != 0
            || header.questions != 1
            || header.answers != 0
            || header.authorities != 0
        {
            return Err(AnswerError::Malformed);
        }
        // Configured local-only domains are selected by forward.c before
        // answer_request(), even for QCLASS values other than IN. Record data
        // itself remains class-IN only; a non-IN query can therefore receive
        // the local-only NXDOMAIN/NOERROR boundary but never an A/TXT/etc RR.
        let class_in = question.class == CLASS_IN;
        // answer_request inspects the NX prefix before interface addresses.
        // Defer this local answer to CacheContext so its SOA footer survives.
        if class_in
            && matches!(question.rrtype, TYPE_A | TYPE_AAAA)
            && !interfaces.is_empty()
            && interfaces.declared(&question.name.dnsmasq_bytes())
            && cache
                .as_deref()
                .is_some_and(|cache| cache.has_nxdomain(&question.name, now))
        {
            return Ok(None);
        }
        // Lease expiry and the subsequent local lookup use the same original
        // name. Retain that conversion; a configured CNAME still changes only
        // the expiry traversal cursor, not the caller's question.
        let dotted_name = if class_in && !lease_names.entries().is_empty()
            && lease_names.may_have_expired(now)
        {
            expire_lease_lookups(
                self.config,
                lease_names,
                &question.name,
                question.rrtype,
                now,
            )
        } else {
            None
        };
        let leases = LeaseView {
            names: lease_names,
            synth: &self.config.synth_domains,
            now,
            local_ttl: self.local_ttl,
            local_network,
            interfaces,
        };

        // CNAME processing runs before every other local record path in C.
        // Once an alias is found, its own address/TXT/etc. records are not
        // considered; the name is replaced with the terminal target and the
        // requested RR type is looked up there.  This also applies to unknown
        // RR types, which still receive a CNAME-only answer.
        let has_cname = class_in
            && !self.config.records.cnames.is_empty()
            && {
                let key = question.name.canonical_wire();
                self.config.records.cnames.iter()
                    .any(|record| dotted_key_matches(&record.alias, &key))
            };
        if !has_cname && class_in
            && cache
                .as_deref()
                .is_some_and(|cache| {
                    let (cname, lookup) = cache.inspect_name(&question.name, now);
                    *name_lookup = lookup;
                    cname
                })
        {
            // rfc1035.c:1754-1806 follows cached CNAMEs before TXT and other
            // local records. Let CacheContext use that chain, including its
            // RD/DO checks, instead of answering records at the alias owner.
            // NXDOMAIN alone must not defer typed local answers: a newly
            // published DHCP A can coexist with an older negative marker.
            return Ok(None);
        }
        if !has_cname && class_in {
            let address_kind = match question.rrtype {
                TYPE_A => Some(Kind::Ipv4), TYPE_AAAA => Some(Kind::Ipv6), _ => None,
            };
            if address_kind.is_some_and(|kind| cache.as_deref().is_some_and(|cache| {
                cache.single_fresh_address_id_with_hint(&question.name, kind, now, name_lookup.as_ref()).is_some()
            })) && self.cached_address_is_unclaimed(question, dotted_name.as_deref(), leases) {
                return Ok(None);
            }
        }
        self.answer_local_records(query, header, question, lease_names, now, local_network,
            cache, interfaces, logging, has_cname, dotted_name)
    }

    // Eligible fresh hits and cached CNAMEs have already returned. Keep record
    // assembly out of the common ownership/expiry/name-inspection entry path.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn answer_local_records(
        &mut self,
        query: &[u8],
        header: Header,
        question: &super::forward::Question,
        lease_names: &mut Arc<LeaseNames>,
        now: i64,
        local_network: Option<(Ipv4Addr, Ipv4Addr)>,
        mut cache: Option<&mut Cache>,
        interfaces: &super::interface_records::InterfaceRecords,
        logging: bool,
        has_cname: bool,
        dotted_name: Option<Vec<u8>>,
    ) -> Result<Option<LocalAnswer>, AnswerError> {
        let class_in = question.class == CLASS_IN;
        let leases = LeaseView {
            names: lease_names,
            synth: &self.config.synth_domains,
            now,
            local_ttl: self.local_ttl,
            local_network,
            interfaces,
        };
        let mut notices = QueryEvents::new(logging);
        let mut rows: Vec<(u16, u32, Vec<u8>)> = Vec::new();
        let mut extra_rows: Vec<(Vec<u8>, u16, u32, Vec<u8>)> = Vec::new();
        let mut owned = false;
        let mut windows_filtered = false;
        let mut preserve_negative_authority = true;
        let mut cname_terminal = None;

        if has_cname {
            let (local_owned, terminal) = add_cname_chain(
                self.config,
                self.hosts,
                &question.name,
                question.rrtype,
                leases,
                cache.as_deref_mut(),
                &mut rows,
                &mut extra_rows,
                &mut notices,
            );
            owned = local_owned;
            preserve_negative_authority = terminal.is_some();
            cname_terminal = terminal;
        } else if class_in {
            if let Some(name) = dotted_name.or_else(|| wire_to_dotted(&question.name)) {
                let (local_rows, local_owned, reverse_synthesized) = add_local_records_for_name(
                    self.config,
                    self.hosts,
                    &name,
                    question.rrtype,
                    self.local_ttl,
                    leases,
                    cache.as_deref(),
                    &mut notices,
                );
                rows.extend(local_rows);
                owned = local_owned;
                preserve_negative_authority = !reverse_synthesized;
            }
        }

        // rfc1035.c suppresses SOA after configured records, before generic
        // cache lookup. SRV and underscore ANY are suppressed only on a miss.
        // A cache candidate defers that decision to its actual lookup caller.
        if class_in && self.config.filter_win2k && !owned {
            let do_bit = super::wire::find_pseudoheader(query, true)?
                .opt
                .is_some_and(|opt| opt.dnssec_ok());
            let cache_candidate = !do_bit
                && header.flags & 0x0100 != 0
                && cache.as_deref().is_some_and(|cache| {
                    if question.rrtype == 6 {
                        cache.cname_terminal_name(&question.name, now).is_some()
                    } else if question.rrtype == 255 {
                        cache.cname_terminal_name(&question.name, now).is_some()
                            || cache.has_nxdomain(&question.name, now)
                    } else {
                        cache.has_forward_candidate(&question.name, question.rrtype, now)
                            || cache.has_nxdomain(&question.name, now)
                    }
                });
            if !cache_candidate && filter_win2k_question(&question.name, question.rrtype) {
                owned = true;
                windows_filtered = true;
                notices.label(
                    qlog::CONFIG | qlog::NEGATIVE,
                    &question.name.dnsmasq_bytes(),
                    None,
                    0,
                );
            }
        }

        // rfc1035.c answer_request refuses to forward CHAOS identity names
        // even in this image's NO_ID build, where no built-in TXT exists.
        let notimp = question.class == 3 && !owned && {
            let name = question.name.dnsmasq_bytes().to_ascii_lowercase();
            [b"bind".as_slice(), b"server"].iter().any(|suffix| {
                name == *suffix
                    || name
                        .strip_suffix(*suffix)
                        .is_some_and(|prefix| prefix.ends_with(b"."))
            })
        };
        owned |= notimp;
        if notimp && logging {
            notices.events.push(qlog::QueryEvent::error(
                qlog::CONFIG,
                &question.name.dnsmasq_bytes(),
                4,
                None,
            ));
        }

        // Domain rules belong to forward_query/tcp_request, after all local
        // record candidates. The owner can defer this answer behind its cache.
        if !owned && !has_cname {
            return self.answer_forward_rule(
                header, question, &question.name, lease_names, now,
                cache.as_deref(), logging,
            );
        }
        if !owned {
            return Ok(None);
        }

        let limit = self.max_packet.max(super::wire::HEADER_LEN);
        // QR + RA; local answers are authoritative for configured/host data.
        // Preserve RD from the request.  dnsmasq sets RA on every completed
        // answer (rfc1035.c:2455-2458), including answers that never queried
        // an upstream server.
        let flags = 0x8000
            | 0x0080
            | if !windows_filtered && rows.is_empty() && extra_rows.is_empty() {
                0
            } else {
                0x0400
            }
            | if notimp {
                4
            } else {
                0
            }
            | (header.flags & (0x0100 | 0x0040 | 0x0010));
        let mut writer = PacketWriter::new(header.id, flags, limit)?;
        writer.question(&question.name, question.rrtype, question.class)?;
        let question_end = writer.position();
        let mut truncated = false;
        let mut extra_owner = question.name.as_wire().to_vec();
        let mut owner_offset = 12;
        let mut additional = Vec::new();
        for (rrtype, ttl, data) in rows {
            let start = writer.position();
            if writer
                .record_at(Section::Answer, 12, rrtype, CLASS_IN, ttl, &data)
                .is_err()
            {
                truncated = true;
                break;
            }
            remember_mail_target(
                &mut additional,
                question.name.as_wire(),
                rrtype,
                &data,
                start + 12,
            );
            if rrtype == TYPE_CNAME {
                extra_owner = data;
                owner_offset = start + 12; // compressed owner and fixed RR header
            }
        }
        if !truncated {
            for (owner, rrtype, ttl, data) in extra_rows {
                let start = writer.position();
                let compressed = owner == extra_owner && owner_offset < 0x4000;
                let result = if compressed {
                    writer.record_at(
                        Section::Answer,
                        owner_offset as u16,
                        rrtype,
                        CLASS_IN,
                        ttl,
                        &data,
                    )
                } else {
                    writer.record_wire(Section::Answer, &owner, rrtype, CLASS_IN, ttl, &data)
                };
                if result.is_err() {
                    truncated = true;
                    break;
                }
                remember_mail_target(
                    &mut additional,
                    &owner,
                    rrtype,
                    &data,
                    start + if compressed { 12 } else { owner.len() + 10 },
                );
                if rrtype == TYPE_CNAME {
                    owner_offset = start + if compressed { 12 } else { owner.len() + 10 };
                    extra_owner = data;
                }
            }
        }
        // answer_request retains the NXDOMAIN prefix's SOA even when a
        // newer DHCP/configured record supplies a positive answer. DHCP
        // publication removes conflicting address entries, not NXDOMAIN.
        // Only completed local answers reach this lookup; ordinary cache
        // misses still return above without doing another name lookup.
        if class_in && preserve_negative_authority && !truncated {
            if let Some(cache) = cache.as_deref_mut() {
                // Only actual configured-CNAME traversal moves C's cursor.
                // Raw TYPE_CNAME bytes are opaque output, including pointers.
                let terminal = cname_terminal.as_deref().map(|name| {
                    // Configuration canonicalization already removed one
                    // trailing dot. Do not strip another and alias an
                    // invalid target to a real cached name (or the root).
                    if name.ends_with(b".") {
                        Err(WireError::InvalidName)
                    } else {
                        Name::from_dotted_bytes(name)
                    }
                });
                let name = match &terminal {
                    Some(Ok(name)) => Some(name),
                    // An accepted configuration target need not be a valid
                    // cache name. Preserve its existing answer behavior.
                    Some(Err(_)) => None,
                    None => Some(&question.name),
                };
                if let Some(name) = name {
                    if let Some(id) = cache
                        .lookup(name, &[Kind::NxDomain], now, !self.config.no_round_robin)
                        .first()
                        .copied()
                    {
                        match super::cache_reply::append_negative_authority(&mut writer, cache, id, now) {
                            Ok(_) => {}
                            Err(WireError::Full) => truncated = true,
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
            }
        }
        append_mail_addresses(
            &mut writer,
            self,
            lease_names,
            now,
            cache,
            &additional,
            truncated,
        )?;
        let mut packet = writer.finish();
        if truncated {
            // answer_request/make_local_answer discard the entire RRset on
            // overflow. A fitting prefix must not look like a complete set.
            packet.truncate(question_end);
            let mut header = Header::parse(&packet)?;
            header.flags |= 0x0200;
            header.answers = 0;
            header.authorities = 0;
            header.additionals = 0;
            header.write(&mut packet)?;
            notices.label(0, b"reply", Some(b"truncated"), 0);
        }
        Ok(Some(LocalAnswer {
            packet,
            forward_rule: false,
            query_events: notices.events,
        }))
    }

    // Only an existing fresh address reaches this check. Paths without such
    // an entry keep the original lookup; local/cache coexistence falls back.
    // Lease expiry has already run, and its converted name can be reused.
    #[inline(never)]
    fn cached_address_is_unclaimed(
        &self, question: &super::forward::Question, dotted_name: Option<&[u8]>, leases: LeaseView<'_>,
    ) -> bool {
        if !self.config.records.cnames.is_empty()
            || self.config.records.has_raw_type(question.rrtype)
            || !leases.interfaces.is_empty()
            || !self.config.interface_records.rules.is_empty()
            || !self.config.synth_domains.domains.is_empty()
            || !self.hosts.is_published()
            || self.config.rules.iter().any(|rule| matches!(rule.target,
                RuleTarget::Literal(_) | RuleTarget::ZeroAddresses | RuleTarget::LocalOnly))
        { return false; }
        let mut scratch = [0; 253];
        let name = match dotted_name {
            Some(name) => name,
            None => {
                let Some(length) = query_dotted_name(&question.name, &mut scratch) else { return false };
                &scratch[..length]
            }
        };
        !self.hosts.name_exists(name) && leases.names.lookup(name, leases.now).next().is_none()
    }

    /// domain-match.c::is_local_answer/make_local_answer. Select by the
    /// forwarding cursor, but write the original question and owner pointer.
    /// This boundary does not repeat local records, expiry or cache lookups.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn answer_forward_rule(
        &self,
        header: Header,
        question: &super::forward::Question,
        name: &Name,
        leases: &LeaseNames,
        now: i64,
        cache: Option<&Cache>,
        logging: bool,
    ) -> Result<Option<LocalAnswer>, AnswerError> {
        let mut rows = Vec::new();
        let mut notices = QueryEvents::new(logging);
        let (owned, local_only, _) = select_local_rules(
            self.config, name, question.class, question.rrtype,
            self.local_ttl, &mut rows, &mut notices,
        );
        if !owned && !local_only {
            return Ok(None);
        }
        let nxdomain = !owned && local_only
            && !has_descendant_local(self.config, self.hosts, name)
            && !cache.is_some_and(|cache| cache.contains_forward_name(name, now))
            && !wire_to_dotted(name).is_some_and(|name| leases.name_exists(&name, now));
        if local_only {
            let family = match question.rrtype {
                TYPE_A => qlog::IPV4,
                TYPE_AAAA => qlog::IPV6,
                255 => qlog::IPV4 | qlog::IPV6,
                _ => 0,
            };
            notices.label(
                qlog::CONFIG | qlog::NEGATIVE | family | if nxdomain { qlog::NXDOMAIN } else { 0 },
                &name.dnsmasq_bytes(), None, 0,
            );
        }
        let flags = 0x8080 | (header.flags & 0x0150)
            | if rows.is_empty() { 0 } else { 0x0400 }
            | if nxdomain { 3 } else { 0 };
        let mut writer = PacketWriter::new(header.id, flags, self.max_packet.max(super::wire::HEADER_LEN))?;
        writer.question(&question.name, question.rrtype, question.class)?;
        let question_end = writer.position();
        let mut truncated = false;
        for (rrtype, ttl, data) in rows {
            match writer.record_at(Section::Answer, 12, rrtype, CLASS_IN, ttl, &data) {
                Ok(()) => {}
                Err(WireError::Full) => { truncated = true; break; }
                Err(error) => return Err(error.into()),
            }
        }
        let mut packet = writer.finish();
        if truncated {
            packet.truncate(question_end);
            let mut header = Header::parse(&packet)?;
            header.flags |= 0x0200;
            header.answers = 0;
            header.write(&mut packet)?;
            notices.label(0, b"reply", Some(b"truncated"), 0);
        }
        Ok(Some(LocalAnswer { packet, forward_rule: true, query_events: notices.events }))
    }
}

#[cfg(test)]
#[path = "local_negative_tests.rs"]
mod local_negative_tests;

pub(crate) fn filter_win2k_question(name: &Name, rrtype: u16) -> bool {
    matches!(rrtype, 6 | 33) || (rrtype == 255 && name.dnsmasq_bytes().contains(&b'_'))
}

struct MailTarget {
    owner: Vec<u8>,
    rrtype: u16,
    target: Vec<u8>,
    offset: usize,
}

fn remember_mail_target(
    targets: &mut Vec<MailTarget>,
    owner: &[u8],
    rrtype: u16,
    data: &[u8],
    start: usize,
) {
    let prefix = match rrtype {
        TYPE_MX => 2,
        TYPE_SRV => 6,
        _ => return,
    };
    if data.len() > prefix {
        targets.push(MailTarget {
            owner: owner.to_vec(),
            rrtype,
            target: data[prefix..].to_vec(),
            offset: start + prefix,
        });
    }
}

fn append_mail_addresses(
    writer: &mut PacketWriter,
    answerer: &mut LocalAnswerer<'_>,
    lease_names: &mut Arc<LeaseNames>,
    now: i64,
    mut cache: Option<&mut Cache>,
    emitted: &[MailTarget],
    truncated: bool,
) -> Result<(), AnswerError> {
    if emitted.is_empty() {
        return Ok(());
    }
    let limit = answerer.max_packet.max(super::wire::HEADER_LEN);
    let config = answerer.config;
    let hosts = &mut *answerer.hosts;
    let mut seen = Vec::<Vec<u8>>::new();
    // SRV rotation has already occurred. C walks this updated list for
    // Additional, which can differ from its Answer record order.
    for entry in config.records.mail_order() {
        let (owner, target, rrtype) = match entry {
            MailRecord::Mx(index) => {
                let record = &config.records.mx[index];
                (&record.name, record.target.as_deref(), TYPE_MX)
            }
            MailRecord::Srv(index) => {
                let record = &config.records.srv[index];
                (&record.name, record.target.as_deref(), TYPE_SRV)
            }
        };
        let Some(target) = target else { continue };
        let Some(owner_wire) = wire_name(owner) else {
            continue;
        };
        let Some(target_wire) = wire_name(target) else {
            continue;
        };
        let Some(emitted) = emitted.iter().find(|row| {
            row.rrtype == rrtype
                && row.owner.eq_ignore_ascii_case(&owner_wire)
                && row.target.eq_ignore_ascii_case(&target_wire)
        }) else {
            continue;
        };
        if seen.iter().any(|name| name.eq_ignore_ascii_case(target)) {
            continue;
        }
        seen.push(target.to_vec());
        let mut addresses = Vec::new();
        for host in hosts.lookup(target, None, config.no_round_robin) {
            addresses.push((host.address, host.ttl));
        }
        if lease_names.has_expired_name(target, now) {
            Arc::make_mut(lease_names).expire_name(target, now);
        }
        for lease in lease_names.lookup(target, now) {
            addresses.push((
                IpAddr::V4(lease.address),
                lease.ttl(now, lease_names.policy()),
            ));
        }
        if let (Some(cache), Some(name)) =
            (cache.as_deref_mut(), Name::from_dotted_bytes(target).ok())
        {
            let ids = cache.lookup(
                &name,
                &[Kind::Ipv4, Kind::Ipv6],
                now,
                !config.no_round_robin,
            );
            for id in ids {
                let Some(entry) = cache.get(id) else { continue };
                if entry.record.negative {
                    continue;
                }
                let address = match (entry.record.kind, entry.record.data.as_slice()) {
                    (Kind::Ipv4, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                    (Kind::Ipv6, data) if data.len() == 16 => {
                        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap()))
                    }
                    _ => continue,
                };
                addresses.push((address, entry.reply_ttl(now, cache.policy())));
            }
        }
        if truncated {
            // C still performs the Additional cache lookup after an Answer
            // overflow, then discards all records in its final TC response.
            continue;
        }
        for (address, ttl) in addresses {
            let data = ip_bytes(address);
            let kind = if address.is_ipv4() { TYPE_A } else { TYPE_AAAA };
            // Optional Additional overflow must not set TC or discard answers.
            let owner_len = if emitted.offset < 0x4000 {
                2
            } else {
                target_wire.len()
            };
            if writer.position() + owner_len + 10 + data.len() > limit {
                continue;
            }
            if emitted.offset < 0x4000 {
                writer.record_at(
                    Section::Additional,
                    emitted.offset as u16,
                    kind,
                    CLASS_IN,
                    ttl,
                    &data,
                )?;
            } else {
                writer.record_wire(
                    Section::Additional,
                    &target_wire,
                    kind,
                    CLASS_IN,
                    ttl,
                    &data,
                )?;
            }
        }
    }
    Ok(())
}

/// These are the name/reverse lookup boundaries in answer_request, including
/// lookups that ultimately produce no local answer. Keep removals sticky when
/// wall time moves backwards without expiring untouched names globally.
/// The caller checks the same conservative expiry bound before reserving this
/// traversal's frame; live-only generations do not need its CNAME/PTR work.
#[inline(never)]
fn expire_lease_lookups(
    config: &DnsConfig,
    leases: &mut Arc<LeaseNames>,
    query: &Name,
    qtype: u16,
    now: i64,
) -> Option<Vec<u8>> {
    let query_name = wire_to_dotted(query)?;
    let mut name = query_name.as_slice();
    for _ in 0..100 {
        if leases.has_expired_name(&name, now) {
            Arc::make_mut(leases).expire_name(&name, now);
        }
        if qtype == TYPE_CNAME {
            return Some(query_name);
        }
        let Some(cname) = config
            .records
            .cnames
            .iter()
            .find(|cname| cname.alias.eq_ignore_ascii_case(&name))
        else {
            break;
        };
        name = &cname.target;
    }
    if (qtype == TYPE_PTR || qtype == 255)
        && arpa_address(&name).is_some()
        && !config
            .records
            .ptr
            .iter()
            .any(|record| record.name.eq_ignore_ascii_case(&name))
        && leases.has_expired_reverse(now)
    {
        Arc::make_mut(leases).expire_reverse(now);
    }
    Some(query_name)
}

fn dotted_key(name: &[u8]) -> Vec<u8> {
    wire_name(name)
        .map(|mut name| {
            name.make_ascii_lowercase();
            name
        })
        .unwrap_or_default()
}

/// Compare a canonical wire key without constructing each configured alias's
/// wire name. Invalid dotted names retain dotted_key's empty-key behavior.
fn dotted_key_matches(name: &[u8], key: &[u8]) -> bool {
    if name.is_empty() {
        return key == [0];
    }
    let valid = name.len() <= 253
        && name.split(|&byte| byte == b'.').all(|label| !label.is_empty() && label.len() <= 63);
    if !valid {
        return key.is_empty();
    }
    if key.len() != name.len() + 2 {
        return false;
    }
    let mut pos = 0;
    for label in name.split(|&byte| byte == b'.') {
        let end = pos + label.len() + 1;
        if key[pos] != label.len() as u8
            || !key[pos + 1..end].eq_ignore_ascii_case(label)
        {
            return false;
        }
        pos = end;
    }
    key[pos] == 0
}

pub(super) fn wire_to_dotted(name: &Name) -> Option<Vec<u8>> {
    let wire = name.as_wire();
    let mut out = Vec::with_capacity(wire.len().saturating_sub(2));
    let mut pos = 0;
    while pos < wire.len() {
        let len = usize::from(wire[pos]);
        pos += 1;
        if len == 0 {
            return Some(out);
        }
        if len > 63 || pos.checked_add(len)? > wire.len() {
            return None;
        }
        // C extract_name escapes a literal dot inside one label. Dotted
        // config/hosts keys cannot represent it as an ordinary separator.
        if wire[pos..pos + len].contains(&b'.') {
            return None;
        }
        if !out.is_empty() {
            out.push(b'.');
        }
        out.extend(wire[pos..pos + len].iter().map(u8::to_ascii_lowercase));
        pos += len;
    }
    None
}

/// Query-scoped counterpart of wire_to_dotted. A valid 255-byte wire name
/// needs at most 253 dotted bytes; no escaped-name expansion belongs here.
fn query_dotted_name(name: &Name, out: &mut [u8; 253]) -> Option<usize> {
    let wire = name.as_wire();
    let mut pos = 0;
    let mut written = 0;
    while pos < wire.len() {
        let len = usize::from(wire[pos]);
        pos += 1;
        if len == 0 {
            return Some(written);
        }
        if len > 63 || pos.checked_add(len)? > wire.len() {
            return None;
        }
        let label = &wire[pos..pos + len];
        if label.contains(&b'.') {
            return None;
        }
        let separator = usize::from(written != 0);
        let end = written + separator + len;
        if end > out.len() {
            return None;
        }
        if separator != 0 {
            out[written] = b'.';
        }
        for (target, source) in out[written + separator..end].iter_mut().zip(label) {
            *target = source.to_ascii_lowercase();
        }
        written = end;
        pos += len;
    }
    None
}

fn wire_name(name: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() {
        return Some(vec![0]);
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split(|&b| b == b'.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(value) => value.octets().to_vec(),
        IpAddr::V6(value) => value.octets().to_vec(),
    }
}

/// rfc1035.c::in_arpa_name_2_addr, including omitted low-order components,
/// defined decimal-to-byte narrowing, ip6.int and its textual bitstring form.
pub(super) fn arpa_address(name: &[u8]) -> Option<IpAddr> {
    if name.len() > 75 {
        return None;
    }
    let labels: Vec<_> = name.split(|&byte| byte == b'.').collect();
    let [prefix @ .., zone, suffix] = labels.as_slice() else {
        return None;
    };
    if prefix.is_empty() {
        return None;
    }
    if zone.eq_ignore_ascii_case(b"in-addr") && suffix.eq_ignore_ascii_case(b"arpa") {
        let mut address = [0; 4];
        for label in prefix {
            let value = label.iter().try_fold(0i32, |value, byte| {
                if !byte.is_ascii_digit() {
                    return None;
                }
                value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))
            })?;
            address.copy_within(0..3, 1);
            address[0] = value as u8;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(address)));
    }
    if !zone.eq_ignore_ascii_case(b"ip6")
        || !(suffix.eq_ignore_ascii_case(b"arpa") || suffix.eq_ignore_ascii_case(b"int"))
    {
        return None;
    }
    let hex = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    if prefix[0].starts_with(b"\\[x") || prefix[0].starts_with(b"\\[X") {
        let value = prefix[0];
        if value.len() < 36 || value[35] != b'/' {
            return None;
        }
        let mut address = [0; 16];
        for (index, byte) in address.iter_mut().enumerate() {
            *byte = (hex(value[3 + index * 2])? << 4) | hex(value[4 + index * 2])?;
        }
        return Some(IpAddr::V6(Ipv6Addr::from(address)));
    }
    let mut address = 0u128;
    for label in prefix {
        if label.len() != 1 {
            return None;
        }
        address = (address >> 4) | (u128::from(hex(label[0])?) << 124);
    }
    Some(IpAddr::V6(Ipv6Addr::from(address)))
}

/// Resolve a configured CNAME chain and answer the requested RR type at its
/// terminal owner.  `rows` contains the first CNAME (whose owner is the
/// question name); subsequent CNAMEs and terminal records use explicit owners
/// in `extra_rows`. Return the terminal visited for negative SOA lookup, unless
/// TYPE_CNAME stopped before visiting it or reverse synthesis changed it.
fn add_cname_chain(
    config: &DnsConfig,
    hosts: &mut Hosts,
    alias: &Name,
    qtype: u16,
    leases: LeaseView<'_>,
    cache: Option<&mut Cache>,
    rows: &mut Vec<(u16, u32, Vec<u8>)>,
    extra_rows: &mut Vec<(Vec<u8>, u16, u32, Vec<u8>)>,
    notices: &mut QueryEvents,
) -> (bool, Option<Vec<u8>>) {
    let ttl = leases.local_ttl;
    let Some(mut current) = wire_to_dotted(alias) else {
        return (false, None);
    };
    let mut visited = Vec::<Vec<u8>>::new();
    let mut first = true;
    loop {
        let current_key = dotted_key(&current);
        let Some(record) = config
            .records
            .cnames
            .iter()
            .find(|record| dotted_key_matches(&record.alias, &current_key))
        else {
            break;
        };
        if visited.iter().any(|name| name == &current_key) {
            // Configuration validation rejects loops. Keep this guard so a
            // caller constructing DnsConfig directly cannot make answering
            // recurse or emit an unbounded packet.
            break;
        }
        visited.push(current_key);
        notices.label(qlog::CONFIG | qlog::CNAME, &current, None, 0);
        let target_wire = wire_name(&record.target).unwrap_or_else(|| vec![0]);
        let record_ttl = record.ttl.unwrap_or(ttl);
        if first {
            rows.push((TYPE_CNAME, record_ttl, target_wire));
            first = false;
        } else {
            let owner = wire_name(&current).unwrap_or_else(|| vec![0]);
            extra_rows.push((owner, TYPE_CNAME, record_ttl, target_wire));
        }
        // C's CNAME query stops after the first alias record.
        if qtype == TYPE_CNAME {
            return (true, None);
        }
        current = record.target.clone();
    }

    let (terminal_rows, _terminal_owned, reverse_synthesized) = add_local_records_for_name(
        config,
        hosts,
        &current,
        qtype,
        ttl,
        leases,
        cache.as_deref(),
        notices,
    );
    let owner = wire_name(&current).unwrap_or_else(|| vec![0]);
    for (rrtype, record_ttl, data) in terminal_rows {
        extra_rows.push((owner.clone(), rrtype, record_ttl, data));
    }
    // The alias itself owns the answer even when its terminal target has no
    // matching RR (CNAME-only response).
    (true, (!reverse_synthesized).then_some(current))
}

/// Collect all local records for one owner. The returned rows are ownerless;
/// callers can use them for the question owner or attach an explicit owner
/// while following a CNAME. The final flag reports actual reverse synthesis,
/// which replaces C's name cursor and discards the old reverse-zone SOA.
fn add_local_records_for_name(
    config: &DnsConfig,
    hosts: &mut Hosts,
    name: &[u8],
    qtype: u16,
    ttl: u32,
    leases: LeaseView<'_>,
    cache: Option<&Cache>,
    notices: &mut QueryEvents,
) -> (Vec<(u16, u32, Vec<u8>)>, bool, bool) {
    if matches!(qtype, TYPE_A | TYPE_AAAA) && !config.records.has_raw_type(qtype) {
        // CNAME was resolved by the caller. Without raw records of this type,
        // only address sources can contribute to an A/AAAA answer here.
        let mut rows = Vec::new();
        let owned = add_address_records_for_name(
            config, hosts, name, qtype, ttl, leases, cache, notices, &mut rows,
        );
        return (rows, owned, false);
    }
    // Raw records and address sources compare dotted names directly. Only
    // the other configured RR loops need a wire-format key.
    let records = &config.records;
    let raw = if qtype == 255 || records.has_raw_type(qtype) {
        records.raw_records()
    } else {
        &[]
    };
    let needs_key = !records.txt.is_empty()
        || !records.ptr.is_empty()
        || !records.mx.is_empty()
        || !records.srv.is_empty()
        || !records.naptr.is_empty();
    let key = if needs_key { dotted_key(name) } else { Vec::new() };
    let mut rows = Vec::new();
    let mut owned = false;
    let mut synthetic_reverse_name = None;

    // answer_request emits configured TXT/raw/PTR before address records.
    let typed_start = rows.len();
    add_typed_records(
        &config.records.txt,
        TYPE_TXT,
        &key,
        qtype,
        ttl,
        &mut rows,
        &mut owned,
    );
    for row in &rows[typed_start..] {
        notices.record(qlog::CONFIG, name, row.0, &row.2);
    }
    let raw_start = rows.len();
    add_raw(raw, name, qtype, ttl, &mut rows, &mut owned);
    for row in &rows[raw_start..] {
        notices.label(qlog::CONFIG | qlog::RRNAME, name, None, row.0);
    }
    if qtype == TYPE_PTR || qtype == 255 {
        let interface_ptr =
            arpa_address(name).and_then(|address| leases.interfaces.reverse(address));
        if let Some(target) = interface_ptr {
            if let Some(address) = arpa_address(name) {
                notices.address(qlog::CONFIG | qlog::REVERSE, target, address, None);
            }
            owned = true;
            rows.push((TYPE_PTR, ttl, wire_name(target).unwrap_or_else(|| vec![0])));
        }
        let mut explicit_ptr = interface_ptr.is_some();
        for record in config.records.ptr.iter().rev() {
            if interface_ptr.is_none() && dotted_key(&record.name) == key {
                explicit_ptr = true;
                owned = true;
                notices.label(qlog::CONFIG | qlog::RRNAME, name, Some(b"<PTR>"), 0);
                rows.push((
                    TYPE_PTR,
                    ttl,
                    record.target.as_deref().map_or_else(
                        || vec![0],
                        |value| wire_name(value).unwrap_or_else(|| vec![0]),
                    ),
                ));
            }
        }
        if !explicit_ptr {
            let address = arpa_address(name);
            let mut reverse_hosts = address
                .into_iter()
                .flat_map(|address| hosts.reverse_all(address))
                .peekable();
            if reverse_hosts.peek().is_some() {
                // cache_find_by_addr can return several F_REVERSE hosts for
                // one address. answer_request emits every owner, with its own
                // TTL and source, before considering a DHCP/synthetic miss.
                owned = true;
                for host in reverse_hosts {
                    let origin = if host.configured {
                        qlog::CONFIG
                    } else {
                        qlog::HOSTS
                    };
                    notices.address(
                        origin | qlog::REVERSE,
                        &host.name,
                        host.address,
                        hosts.source_name(host.source),
                    );
                    rows.push((
                        TYPE_PTR,
                        host.ttl,
                        wire_name(&host.name).unwrap_or_else(|| vec![0]),
                    ));
                }
            } else if let Some(lease) = address.and_then(|address| match address {
                IpAddr::V4(address) => leases.names.reverse(address, leases.now),
                IpAddr::V6(_) => None,
            }) {
                notices.address(
                    qlog::DHCP | qlog::REVERSE,
                    &lease.name,
                    IpAddr::V4(lease.address),
                    None,
                );
                owned = true;
                rows.push((
                    TYPE_PTR,
                    lease.ttl(leases.now, leases.names.policy()),
                    wire_name(&lease.name).unwrap_or_else(|| vec![0]),
                ));
            } else if let Some(address) = address {
                if !cache.is_some_and(|cache| cache.has_reverse_candidate(address, leases.now)) {
                    if let Some(name) = leases.synth.reverse(address) {
                        notices.address(qlog::CONFIG | qlog::REVERSE, &name, address, None);
                        owned = true;
                        rows.push((TYPE_PTR, ttl, wire_name(&name).unwrap_or_else(|| vec![0])));
                        // is_rev_synth replaces C's name cursor. ANY then
                        // evaluates address/mail records at this generated name.
                        synthetic_reverse_name = Some(name);
                    }
                }
            }
        }
    }

    let name = synthetic_reverse_name.as_deref().unwrap_or(name);
    let key = if needs_key && synthetic_reverse_name.is_some() {
        dotted_key(name)
    } else {
        key
    };

    owned |= add_address_records_for_name(
        config, hosts, name, qtype, ttl, leases, cache, notices, &mut rows,
    );
    let mail_start = rows.len();
    add_mx(&config.records, &key, qtype, ttl, &mut rows, &mut owned);
    // rfc1035.c:2201-2214: selfmx applies to hosts/DHCP names, including
    // their non-terminals, unless an explicit MX record already matched.
    // F_NO_RR means this existence check must not rotate address records.
    if (qtype == TYPE_MX || qtype == 255)
        && (config.records.self_mx || config.records.local_mx)
        && !config
            .records
            .mx
            .iter()
            .any(|record| dotted_key(&record.name) == key)
        && (hosts.name_exists(name) || leases.names.name_exists(name, leases.now))
    {
        let mut data = 1u16.to_be_bytes().to_vec();
        let target = if config.records.self_mx {
            name
        } else {
            config.records.mx_target.as_deref().unwrap_or_default()
        };
        data.extend(wire_name(target).unwrap_or_else(|| vec![0]));
        rows.push((TYPE_MX, ttl, data));
        owned = true;
    }
    add_srv(&config.records, &key, qtype, ttl, &mut rows, &mut owned);
    if qtype == TYPE_SRV || qtype == 255 {
        config.records.rotate_srv(name);
    }
    add_naptr(
        &config.records.naptr,
        &key,
        qtype,
        ttl,
        &mut rows,
        &mut owned,
    );
    for row in &rows[mail_start..] {
        notices.record(qlog::CONFIG, name, row.0, &row.2);
    }
    (rows, owned, synthetic_reverse_name.is_some())
}

#[allow(clippy::too_many_arguments)]
fn add_address_records_for_name(
    config: &DnsConfig,
    hosts: &mut Hosts,
    name: &[u8],
    qtype: u16,
    ttl: u32,
    leases: LeaseView<'_>,
    cache: Option<&Cache>,
    notices: &mut QueryEvents,
    rows: &mut Vec<(u16, u32, Vec<u8>)>,
) -> bool {
    let mut owned = false;
    // The Hosts table passed to this function is already filtered by the
    // loader (`no-hosts` skips /etc/hosts but does not skip addn-hosts).
    // C performs separate IPv4 then IPv6 lookups for ANY. Non-address
    // questions do not rotate either address family as a side effect.
    for ipv6 in [false, true] {
        let rrtype = if ipv6 { TYPE_AAAA } else { TYPE_A };
        if qtype == 255 || qtype == rrtype {
            let network = leases
                .local_network
                .filter(|_| config.localise_queries && !ipv6);
            if let Some(addresses) = leases.interfaces.forward(name, ipv6, network) {
                for address in addresses {
                    notices.address(qlog::CONFIG, name, address, None);
                    rows.push((rrtype, ttl, ip_bytes(address)));
                    owned = true;
                }
                continue;
            }
            if !ipv6 {
                for lease in leases.names.lookup(name, leases.now) {
                    notices.address(qlog::DHCP, name, IpAddr::V4(lease.address), None);
                    rows.push((
                        TYPE_A,
                        lease.ttl(leases.now, leases.names.policy()),
                        lease.address.octets().to_vec(),
                    ));
                    owned = true;
                }
            }
            let host_rows = hosts.lookup(name, Some(ipv6), config.no_round_robin);
            let local_network = leases.local_network.filter(|(address, _)| {
                config.localise_queries && !ipv6 && !address.is_unspecified()
            });
            let same_network = |candidate: IpAddr| match (local_network, candidate) {
                (Some((address, netmask)), IpAddr::V4(candidate)) => {
                    u32::from(candidate) & u32::from(netmask)
                        == u32::from(address) & u32::from(netmask)
                }
                _ => false,
            };
            let localise = host_rows.iter().any(|host| same_network(host.address));
            let mut host_notices = Vec::new();
            for host in host_rows {
                if !localise || same_network(host.address) {
                    if notices.enabled {
                        host_notices.push((host.address, host.source, host.configured));
                    }
                    rows.push((rrtype, host.ttl, ip_bytes(host.address)));
                    owned = true;
                }
            }
            for (address, source, configured) in host_notices {
                notices.address(
                    if configured {
                        qlog::CONFIG
                    } else {
                        qlog::HOSTS
                    },
                    name,
                    address,
                    hosts.source_name(source),
                );
            }
            if !leases.synth.domains.is_empty()
                && !rows.iter().any(|row| row.0 == rrtype)
                && !cache.is_some_and(|cache| {
                    Name::from_dotted_bytes(name).ok().is_some_and(|query| {
                        cache.has_forward_candidate(&query, rrtype, leases.now)
                    })
                })
            {
                if let Some(address) = leases.synth.forward(name, ipv6) {
                    notices.address(qlog::CONFIG, name, address, None);
                    rows.push((rrtype, ttl, ip_bytes(address)));
                    owned = true;
                }
            }
        }
    }
    owned
}

fn add_typed_records(
    records: &[RawRecord],
    rrtype: u16,
    key: &[u8],
    qtype: u16,
    ttl: u32,
    rows: &mut Vec<(u16, u32, Vec<u8>)>,
    owned: &mut bool,
) {
    if qtype != 255 && qtype != rrtype {
        return;
    }
    for record in records.iter().rev() {
        if record.rr_type == rrtype && dotted_key(&record.name) == key {
            *owned = true;
            rows.push((rrtype, ttl, record.data.clone()));
        }
    }
}

fn add_mx(
    records: &RecordConfig,
    key: &[u8],
    qtype: u16,
    ttl: u32,
    rows: &mut Vec<(u16, u32, Vec<u8>)>,
    owned: &mut bool,
) {
    if qtype != 255 && qtype != TYPE_MX {
        return;
    }
    for entry in records.mail_order() {
        let MailRecord::Mx(index) = entry else {
            continue;
        };
        let record = &records.mx[index];
        if dotted_key(&record.name) == key {
            let Some(target) = record.target.as_deref() else {
                // The service must resolve C's hostname default before this
                // path is ready; do not turn an absent target into root MX.
                continue;
            };
            *owned = true;
            let mut data = record.preference.to_be_bytes().to_vec();
            data.extend(wire_name(target).unwrap_or_else(|| vec![0]));
            rows.push((TYPE_MX, ttl, data));
        }
    }
}

fn add_srv(
    records: &RecordConfig,
    key: &[u8],
    qtype: u16,
    ttl: u32,
    rows: &mut Vec<(u16, u32, Vec<u8>)>,
    owned: &mut bool,
) {
    if qtype != 255 && qtype != TYPE_SRV {
        return;
    }
    for entry in records.mail_order() {
        let MailRecord::Srv(index) = entry else {
            continue;
        };
        let record = &records.srv[index];
        if dotted_key(&record.name) == key {
            // C leaves an omitted target NULL and encodes the DNS root.
            let target = record.target.as_deref().unwrap_or_default();
            *owned = true;
            let mut data = Vec::with_capacity(8);
            data.extend(record.priority.to_be_bytes());
            data.extend(record.weight.to_be_bytes());
            data.extend(record.port.to_be_bytes());
            data.extend(wire_name(target).unwrap_or_else(|| vec![0]));
            rows.push((TYPE_SRV, ttl, data));
        }
    }
}

fn add_naptr(
    records: &[NaptrRecord],
    key: &[u8],
    qtype: u16,
    ttl: u32,
    rows: &mut Vec<(u16, u32, Vec<u8>)>,
    owned: &mut bool,
) {
    if qtype != 255 && qtype != TYPE_NAPTR {
        return;
    }
    for record in records.iter().rev() {
        if dotted_key(&record.name) == key {
            *owned = true;
            let mut data = Vec::new();
            data.extend(record.order.to_be_bytes());
            data.extend(record.preference.to_be_bytes());
            for field in [&record.flags, &record.services, &record.regexp] {
                let value = field.as_deref().unwrap_or_default();
                // add_resource_record('z') assigns strlen to unsigned short
                // before clamping the character-string to 255 bytes.
                let length = usize::from((value.len() as u16).min(255));
                data.push(length as u8);
                data.extend(&value[..length]);
            }
            data.extend(
                wire_name(record.replacement.as_deref().unwrap_or_default())
                    .unwrap_or_else(|| vec![0]),
            );
            rows.push((TYPE_NAPTR, ttl, data));
        }
    }
}

fn add_raw(
    records: &[RawRecord],
    name: &[u8],
    qtype: u16,
    ttl: u32,
    rows: &mut Vec<(u16, u32, Vec<u8>)>,
    owned: &mut bool,
) {
    for record in records.iter().rev() {
        // Match C's type-first hostname_isequal without allocating or
        // converting either dotted name, including same-type name misses.
        if (qtype == 255 || qtype == record.rr_type) && record.name.eq_ignore_ascii_case(name) {
            *owned = true;
            rows.push((record.rr_type, ttl, record.data.clone()));
        }
    }
}

fn select_local_rules(
    config: &DnsConfig,
    name: &Name,
    class: u16,
    qtype: u16,
    ttl: u32,
    rows: &mut Vec<(u16, u32, Vec<u8>)>,
    notices: &mut QueryEvents,
) -> (bool, bool, bool) {
    // Upstream-only rules cannot supply local rows or notices. Their domain
    // selection belongs to the forwarder; avoid building local score tiers.
    if !config.rules.iter().any(|rule| matches!(rule.target,
        RuleTarget::Literal(_) | RuleTarget::ZeroAddresses | RuleTarget::LocalOnly))
    {
        return (false, false, false);
    }
    let class_in = class == CLASS_IN;
    let mut scores = config
        .rules
        .iter()
        .filter(|rule| matches_domain(name, &rule.domain))
        .map(|rule| pattern_score(&rule.domain))
        .collect::<Vec<_>>();
    scores.sort_unstable_by(|left, right| right.cmp(left));
    scores.dedup();

    for score in scores {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut zeros = 0usize;
        let mut local_only = false;
        let mut blocks_upstream = false;
        for rule in config
            .rules
            .iter()
            .rev()
            .filter(|rule| pattern_score(&rule.domain) == score)
            .filter(|rule| matches_domain(name, &rule.domain))
        {
            match &rule.target {
                RuleTarget::Literal(address) if address.is_ipv4() => v4.push(*address),
                RuleTarget::Literal(address) => v6.push(*address),
                RuleTarget::ZeroAddresses => zeros += 1,
                RuleTarget::LocalOnly => local_only = true,
                RuleTarget::Upstream(_) | RuleTarget::DefaultResolvers => blocks_upstream = true,
            }
        }

        let selected = if !class_in {
            None
        } else if qtype == TYPE_A {
            (!v4.is_empty())
                .then_some(1)
                .or_else(|| (zeros != 0).then_some(3))
        } else if qtype == TYPE_AAAA {
            (!v6.is_empty())
                .then_some(2)
                .or_else(|| (zeros != 0).then_some(3))
        } else if qtype == 255 {
            (!v6.is_empty())
                .then_some(2)
                .or_else(|| (!v4.is_empty()).then_some(1))
                .or_else(|| (zeros != 0).then_some(3))
        } else {
            None
        };

        match selected {
            Some(1) => {
                for address in v4 {
                    notices.address(qlog::CONFIG, &name.dnsmasq_bytes(), address, None);
                    rows.push((TYPE_A, ttl, ip_bytes(address)));
                }
                return (true, false, false);
            }
            Some(2) => {
                for address in v6 {
                    notices.address(qlog::CONFIG, &name.dnsmasq_bytes(), address, None);
                    rows.push((TYPE_AAAA, ttl, ip_bytes(address)));
                }
                return (true, false, false);
            }
            Some(3) => {
                for _ in 0..zeros {
                    if qtype == 255 || qtype == TYPE_A {
                        notices.address(
                            qlog::CONFIG,
                            &name.dnsmasq_bytes(),
                            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                            None,
                        );
                    }
                    if qtype == 255 || qtype == TYPE_AAAA {
                        notices.address(
                            qlog::CONFIG,
                            &name.dnsmasq_bytes(),
                            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                            None,
                        );
                    }
                }
                if qtype == 255 || qtype == TYPE_A {
                    rows.extend((0..zeros).map(|_| (TYPE_A, ttl, vec![0; 4])));
                }
                if qtype == 255 || qtype == TYPE_AAAA {
                    rows.extend((0..zeros).map(|_| (TYPE_AAAA, ttl, vec![0; 16])));
                }
                return (true, false, false);
            }
            // is_local_answer rolls back within this domain tier: an
            // address of another family proves existence, hence NODATA.
            None if local_only => {
                return (!v4.is_empty() || !v6.is_empty() || zeros != 0, true, false)
            }
            None if blocks_upstream => return (false, false, true),
            Some(_) => unreachable!("local rule family tier is bounded"),
            None => {}
        }
    }
    (false, false, false)
}

fn matches_domain(name: &Name, pattern: &DomainPattern) -> bool {
    if !pattern.dotless && pattern.suffix.is_empty() {
        return true;
    }
    // Keep C's label escapes: an embedded dot cannot become a separator,
    // but later real labels must still match local/address suffix rules.
    let query = name.dnsmasq_bytes().to_ascii_lowercase();
    let suffix = pattern.suffix.to_ascii_lowercase();
    if pattern.dotless && (query.is_empty() || query.contains(&b'.')) {
        return false;
    }
    if suffix.is_empty() {
        return true;
    }
    if pattern.wildcard {
        if pattern.wildcard_dot {
            query.len() > suffix.len() && query.ends_with(&suffix)
        } else {
            query.len() >= suffix.len() && query.ends_with(&suffix)
        }
    } else {
        query == suffix
            || (query.len() > suffix.len()
                && query.ends_with(&suffix)
                && query[query.len() - suffix.len() - 1] == b'.')
    }
}

fn pattern_score(pattern: &DomainPattern) -> (usize, bool) {
    (pattern.suffix.len(), !pattern.wildcard)
}

pub(super) fn known_forwarded_domain(config: &DnsConfig, hosts: &Hosts, query: &Name) -> bool {
    // check_for_local_domain's explicit RR-name lists regard every name as a
    // descendant of root. cache make_non_terminals does not insert root for
    // hosts or CNAME records, so those alone cannot establish root ownership.
    if query.as_wire() == [0] {
        return !config.records.txt.is_empty()
            || !config.records.ptr.is_empty()
            || !config.records.mx.is_empty()
            || !config.records.srv.is_empty()
            || !config.records.naptr.is_empty();
    }
    has_descendant_local(config, hosts, query)
}

/// Presence used for local-only domains and upstream NXDOMAIN conversion.
/// This does not mean the name has a locally answerable requested RR type.
pub fn known_forwarded_domain_with_leases(
    config: &DnsConfig,
    hosts: &Hosts,
    query: &Name,
    leases: &LeaseNames,
    now: i64,
) -> bool {
    if let Some(dotted) = wire_to_dotted(query) {
        if config
            .interface_records
            .rules
            .iter()
            .any(|rule| is_interface_ancestor(&dotted, &rule.name))
        {
            return true;
        }
    }

    known_forwarded_domain(config, hosts, query)
        || wire_to_dotted(query).is_some_and(|name| config.synth_domains.name_exists(&name))
        || wire_to_dotted(query).is_some_and(|name| leases.name_exists(&name, now))
}

fn has_descendant_local(config: &DnsConfig, hosts: &Hosts, query: &Name) -> bool {
    let parent = query.canonical_wire();
    let is_descendant = |child: &[u8]| {
        let child_wire = dotted_key(child);
        let child_labels = labels(&child_wire);
        let parent_labels = labels(&parent);
        child_labels.len() >= parent_labels.len()
            && child_labels[child_labels.len() - parent_labels.len()..] == parent_labels[..]
    };
    if config
        .interface_records
        .rules
        .iter()
        .any(|rule| is_descendant(&rule.name))
    {
        return true;
    }
    config
        .records
        .txt
        .iter()
        .any(|record| is_descendant(&record.name))
        || config
            .records
            .cnames
            .iter()
            .any(|record| is_descendant(&record.alias))
        || config
            .records
            .ptr
            .iter()
            .any(|record| is_descendant(&record.name))
        || config
            .records
            .mx
            .iter()
            .any(|record| is_descendant(&record.name))
        || config
            .records
            .srv
            .iter()
            .any(|record| is_descendant(&record.name))
        || config
            .records
            .naptr
            .iter()
            .any(|record| is_descendant(&record.name))
        || wire_to_dotted(query)
            .as_deref()
            .is_some_and(|name| hosts.name_exists(name))
}

fn labels(wire: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < wire.len() {
        let len = usize::from(wire[pos]);
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 || pos + len > wire.len() {
            return Vec::new();
        }
        out.push(&wire[pos..pos + len]);
        pos += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{lex_line, validate_directive};

    #[test]
    fn query_dotted_buffer_matches_owned_conversion_for_binary_and_maximum_names() {
        let mut names = vec![Name::root(), Name::from_ascii("MiXeD.Example.").unwrap()];
        for byte in 0..=255 {
            for length in [1, 63] {
                let mut wire = vec![length as u8];
                wire.extend(std::iter::repeat_n(byte, length));
                wire.extend_from_slice(&[1, b'A', 0]);
                names.push(super::super::wire::decode_name(&wire, 0, 0).unwrap().0);
            }
        }
        let longest = ["A".repeat(63), "b".repeat(63), "C".repeat(63), "d".repeat(61)].join(".");
        assert_eq!(longest.len(), 253);
        names.push(Name::from_ascii(&longest).unwrap());
        let mut buffer = [0x7f; 253];
        for name in names {
            let expected = wire_to_dotted(&name);
            let actual = query_dotted_name(&name, &mut buffer).map(|length| &buffer[..length]);
            assert_eq!(actual, expected.as_deref(), "{:?}", name.as_wire());
        }
    }

    #[test]
    fn cname_alias_comparison_matches_allocated_keys() {
        let mut names = vec![
            Vec::new(), b".".to_vec(), b"a.".to_vec(), b".a".to_vec(),
            b"a..b".to_vec(), b"Alias.Example".to_vec(), b"alias.example".to_vec(),
            vec![b'a'; 63], vec![b'a'; 64],
        ];
        for last in [61, 62] {
            let mut name = Vec::new();
            for length in [63, 63, 63, last] {
                if !name.is_empty() { name.push(b'.'); }
                name.extend(std::iter::repeat_n(b'a', length));
            }
            names.push(name);
        }
        for byte in 0..=255 {
            names.push(vec![byte, b'.', b'A']);
        }
        let keys: Vec<_> = names.iter().map(|name| dotted_key(name)).collect();
        for (name, expected) in names.iter().zip(&keys) {
            for key in &keys {
                assert_eq!(dotted_key_matches(name, key), expected == key, "{name:?} vs {key:?}");
            }
        }
    }

    fn apply(config: &mut DnsConfig, line: &[u8]) {
        let directive = lex_line(line).unwrap().unwrap();
        validate_directive(&directive).unwrap();
        assert!(config.apply(&directive).unwrap());
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        query_class(name, qtype, CLASS_IN)
    }

    fn query_class(name: &str, qtype: u16, class: u16) -> Vec<u8> {
        let name = Name::from_ascii(name).unwrap();
        let mut packet = vec![0; 12];
        Header {
            id: 7,
            flags: 0x0100,
            questions: 1,
            ..Header::default()
        }
        .write(&mut packet)
        .unwrap();
        packet.extend(name.as_wire());
        packet.extend(qtype.to_be_bytes());
        packet.extend(class.to_be_bytes());
        packet
    }

    #[test]
    fn forward_rule_limit_uses_original_question_not_short_cursor() {
        let long_name = format!("{}.{}.{}.example", "a".repeat(63), "b".repeat(63), "c".repeat(63));
        let short = query("t", TYPE_AAAA);
        let long = query(&long_name, TYPE_AAAA);
        for limit in [512, 65535] {
            let mut config = DnsConfig::default();
            apply(&mut config, b"address=/t/2001:db8::9");
            // Each compressed-owner AAAA occupies 28 bytes. This fits the
            // cursor's short question but overflows the original client name.
            let count = (limit - short.len()) / 28;
            config.rules.resize(count, config.rules[0].clone());
            let mut hosts = Hosts::new();
            let answerer = LocalAnswerer {
                config: &config, hosts: &mut hosts, local_ttl: 0, max_packet: limit,
            };
            for (query, truncated) in [(&short, false), (&long, true)] {
                let header = Header::parse(query).unwrap();
                let question = super::super::forward::Question::parse(query).unwrap();
                let answer = answerer.answer_forward_rule(
                    header, &question, &Name::from_ascii("t").unwrap(),
                    &LeaseNames::default(), 100, None, false,
                ).unwrap().unwrap();
                let header = Header::parse(&answer.packet).unwrap();
                assert_eq!(header.flags & 0x0200 != 0, truncated);
                assert_eq!(header.answers as usize, if truncated { 0 } else { count });
                assert!(answer.packet.len() <= limit);
                if truncated { assert_eq!(answer.packet.len(), query.len()); }
            }
        }
    }

    #[test]
    fn naptr_character_strings_narrow_before_clamping() {
        let record = NaptrRecord {
            name: b"test".to_vec(),
            order: 1,
            preference: 2,
            flags: Some(vec![b'f'; 65536]),
            services: Some(vec![b's'; 65537]),
            regexp: Some(vec![b'r'; 257]),
            replacement: None,
        };
        let mut rows = Vec::new();
        let mut owned = false;
        add_naptr(
            &[record],
            &dotted_key(b"test"),
            TYPE_NAPTR,
            37,
            &mut rows,
            &mut owned,
        );
        assert!(owned);
        let mut expected = vec![0, 1, 0, 2, 0, 1, b's', 255];
        expected.extend([b'r'; 255]);
        expected.push(0);
        assert_eq!(rows, vec![(TYPE_NAPTR, 37, expected)]);
    }

    #[test]
    fn hosts_and_configured_records_answer_locally() {
        let mut config = DnsConfig::default();
        apply(
            &mut config,
            b"host-record=router.test,192.0.2.1,2001:db8::1,30",
        );
        apply(&mut config, b"txt-record=router.test,hello");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        let mut cd_query = query("router.test", TYPE_A);
        cd_query[2..4].copy_from_slice(&0x0110u16.to_be_bytes());
        let answer = answerer.answer(&cd_query).unwrap().unwrap();
        let message = super::super::wire::Message::parse(&answer).unwrap();
        assert_eq!(message.header.answers, 1);
        assert_ne!(message.header.flags & 0x0080, 0);
        assert_ne!(message.header.flags & 0x0010, 0);
        let answer = answerer
            .answer(&query("router.test", TYPE_TXT))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Message::parse(&answer)
                .unwrap()
                .header
                .answers,
            1
        );
    }

    #[test]
    fn unrelated_raw_types_do_not_change_address_answers_or_rotation() {
        let mut direct = DnsConfig::default();
        for line in [
            b"host-record=host.test,192.0.2.1,2001:db8::1,30".as_slice(),
            b"host-record=host.test,192.0.2.2,2001:db8::2,40",
            b"txt-record=host.test,hello",
            b"mx-host=host.test,mail.test,10",
            b"cname=alias.test,host.test",
        ] {
            apply(&mut direct, line);
        }
        let mut with_raw = direct.clone();
        apply(&mut with_raw, b"dns-rr=unrelated.test,1,c0000263");
        apply(&mut with_raw, b"dns-rr=unrelated.test,28,20010db8000000000000000000000063");
        let mut direct_hosts = configured_hosts(&direct, 37);
        let mut raw_hosts = configured_hosts(&with_raw, 37);
        for name in ["host.test", "alias.test", "missing.test"] {
            for qtype in [TYPE_A, TYPE_AAAA, TYPE_A, TYPE_TXT, TYPE_MX, 255, TYPE_AAAA] {
                let packet = query(name, qtype);
                let answer = LocalAnswerer {
                    config: &direct, hosts: &mut direct_hosts, local_ttl: 37, max_packet: 1232,
                }.answer(&packet).unwrap();
                let fallback = LocalAnswerer {
                    config: &with_raw, hosts: &mut raw_hosts, local_ttl: 37, max_packet: 1232,
                }.answer(&packet).unwrap();
                assert_eq!(answer, fallback, "{name} type {qtype}");
            }
        }
    }

    #[test]
    fn raw_addresses_precede_hosts_and_suppress_synthesis() {
        let mut config = DnsConfig::default();
        for line in [
            b"host-record=raw.test,192.0.2.1,2001:db8::1,30".as_slice(),
            b"dns-rr=raw.test,1,c0000263",
            b"dns-rr=raw.test,28,20010db8000000000000000000000063",
            b"synth-domain=synthetic.test,192.0.2.7,192.0.2.9",
            b"dns-rr=192-0-2-7.synthetic.test,1,c0000263",
        ] {
            apply(&mut config, line);
        }
        let mut hosts = configured_hosts(&config, 37);
        for (name, rrtype, expected) in [
            ("raw.test", TYPE_A, vec![vec![192, 0, 2, 99], vec![192, 0, 2, 1]]),
            ("raw.test", TYPE_AAAA, vec![
                "2001:db8::63".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
                "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
            ]),
            ("192-0-2-7.synthetic.test", TYPE_A, vec![vec![192, 0, 2, 99]]),
        ] {
            let packet = LocalAnswerer {
                config: &config, hosts: &mut hosts, local_ttl: 37, max_packet: 1232,
            }.answer(&query(name, rrtype)).unwrap().unwrap();
            let message = super::super::wire::Message::parse(&packet).unwrap();
            let actual: Vec<_> = message.records(Section::Answer)
                .map(|row| (row.rrtype, row.rdata.to_vec())).collect();
            assert_eq!(actual, expected.into_iter().map(|data| (rrtype, data)).collect::<Vec<_>>());
        }
    }

    #[test]
    fn raw_type_selection_keeps_typed_and_any_declaration_order() {
        let mut config = DnsConfig::default();
        for line in [
            b"dns-rr=RAW.test.,65401,abcd".as_slice(),
            b"dns-rr=raw.TEST,1,c0000207",
            b"dns-rr=raw.test,65400,0102",
            b"caa-record=raw.test,0,issue,ca.test",
            b"dns-rr=raw.test,65401,1234",
        ] {
            apply(&mut config, line);
        }
        let snapshot = config.clone();
        apply(&mut config, b"dns-rr=raw.test,16,0161");
        for (config, all_types) in [
            (&snapshot, &[65401, 257, 65400, 1, 65401][..]),
            (&config, &[16, 65401, 257, 65400, 1, 65401][..]),
        ] {
            let mut hosts = configured_hosts(config, 37);
            for qtype in [1, 16, 28, 255, 257, 65400, 65401] {
                let response = LocalAnswerer {
                    config, hosts: &mut hosts, local_ttl: 37, max_packet: 1232,
                }.answer(&query("RaW.TeSt.", qtype)).unwrap();
                let expected = all_types.iter().copied()
                    .filter(|rr_type| qtype == 255 || qtype == *rr_type)
                    .collect::<Vec<_>>();
                assert_eq!(response.is_some(), !expected.is_empty());
                if let Some(response) = response {
                    let message = super::super::wire::Message::parse(&response).unwrap();
                    let records = message.records(Section::Answer).collect::<Vec<_>>();
                    assert_eq!(records.iter().map(|record| record.rrtype).collect::<Vec<_>>(), expected);
                    let custom = records.iter().filter(|record| record.rrtype == 65401)
                        .map(|record| record.rdata).collect::<Vec<_>>();
                    if qtype == 65401 || qtype == 255 {
                        assert_eq!(custom, [&[0x12, 0x34][..], &[0xab, 0xcd][..]]);
                    }
                }
            }
        }
    }

    #[test]
    fn raw_root_name_matches_without_a_wire_key() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"dns-rr=.,65401,abcd");
        let mut hosts = configured_hosts(&config, 37);
        let packet = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 512,
        }
        .answer(&query(".", 65401))
        .unwrap()
        .unwrap();
        let message = super::super::wire::Message::parse(&packet).unwrap();
        let records = message.records(Section::Answer).collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name().unwrap(), Name::root());
        assert_eq!(records[0].rrtype, 65401);
        assert_eq!(records[0].rdata, &[0xab, 0xcd]);
    }

    #[test]
    fn configured_generation_keeps_first_ptr_owner_and_duplicate_ttl() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"no-round-robin");
        apply(
            &mut config,
            b"host-record=owner.test,alias.test,192.0.2.1,2001:db8::1,90",
        );
        apply(&mut config, b"host-record=mixed.test,192.0.2.1,11");
        apply(&mut config, b"host-record=mixed.test,192.0.2.2,22");
        apply(&mut config, b"host-record=mixed.test,192.0.2.2,999");
        let mut hosts = configured_hosts(&config, 37);
        hosts.read(
            b"192.0.2.3 mixed.test\n192.0.2.1 file.test\n192.0.2.2 mixed.test\n",
            4,
            37,
            false,
            |_| None,
        );
        let mixed: Vec<_> = hosts
            .addresses(b"mixed.test")
            .map(|host| (host.address.to_string(), host.ttl, host.reverse))
            .collect();
        assert_eq!(
            mixed,
            vec![
                ("192.0.2.2".into(), 22, true),
                ("192.0.2.3".into(), 37, true),
                ("192.0.2.1".into(), 11, false)
            ]
        );
        for address in ["192.0.2.1", "2001:db8::1"] {
            let host = hosts.reverse(address.parse().unwrap()).unwrap();
            assert_eq!(host.name, b"owner.test");
            assert_eq!(host.ttl, 90);
        }
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 512,
        };
        let ptr = answerer
            .answer(&query("1.2.0.192.in-addr.arpa", TYPE_PTR))
            .unwrap()
            .unwrap();
        let rr = super::super::wire::Message::parse(&ptr)
            .unwrap()
            .records(Section::Answer)
            .next()
            .unwrap();
        assert_eq!(
            (rr.rrtype, rr.ttl, rr.rdata),
            (TYPE_PTR, 90, b"\x05owner\x04test\0".as_slice())
        );
    }

    fn repeated_ptr_hosts(ipv6: bool, first: &str, second: &str) -> Hosts {
        let (address, control, collision, other) = if ipv6 {
            ("2001:db8::1", "2001:db8::2", "2001:db8::bc", "2001:db8::bb")
        } else {
            ("192.0.2.1", "192.0.2.2", "192.0.3.186", "192.0.3.185")
        };
        let mut config = DnsConfig::default();
        apply(&mut config, format!("host-record={first},{address},90").as_bytes());
        let mut hosts = configured_hosts_bulk(
            &config, 37, 1497, 1000, 1000, &LeaseNames::default(),
        ).unwrap();
        hosts.set_source_name(7, b"/fixture/repeated.hosts".to_vec());
        // The collision shares the configured address's C reverse bucket.
        // The second a.test lookup cuts its temporary chain, so the later
        // repeated address acquires another F_REVERSE record.
        let input = format!(
            "{control} old.test\n{collision} a.test\n{other} a.test\n\
             {address} {second}\n{control} {second}\n"
        );
        let stats = hosts.read(input.as_bytes(), 7, 37, false, |_| None);
        assert!(!stats.allocation_failed);
        assert_eq!(stats.inserted, 5);
        hosts.finish_bulk();
        hosts
    }

    #[test]
    fn repeated_address_ptr_emits_all_owners_with_their_ttls_and_sources() {
        for (ipv6, name, address) in [
            (false, "1.2.0.192.in-addr.arpa", "192.0.2.1"),
            (true, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1"),
        ] {
            let address: IpAddr = address.parse().unwrap();
            let mut hosts = repeated_ptr_hosts(ipv6, "x.test", "y.test");
            // Preserve the hosts iterator's order; separately verify its
            // complete membership instead of treating an arbitrary order as
            // the fixed output of C's process-specific name hash.
            let ordered = hosts.reverse_all(address)
                .map(|host| (host.name.clone(), host.ttl, host.configured))
                .collect::<Vec<_>>();
            assert_eq!(ordered.len(), 2);
            assert!(ordered.contains(&(b"x.test".to_vec(), 90, true)));
            assert!(ordered.contains(&(b"y.test".to_vec(), 37, false)));
            let config = DnsConfig::default();
            for qtype in [TYPE_PTR, 255] {
                let response = LocalAnswerer {
                    config: &config, hosts: &mut hosts, local_ttl: 37, max_packet: 512,
                }.answer_with_query_events(
                    &query(name, qtype), &mut Arc::new(LeaseNames::default()),
                    100, None, None, &Default::default(), true,
                ).unwrap().unwrap();
                let message = super::super::wire::Message::parse(&response.packet).unwrap();
                assert_eq!(message.header.flags, 0x8580);
                let records = message.records(Section::Answer).collect::<Vec<_>>();
                assert_eq!(records.len(), 2);
                assert_eq!(response.query_events.len(), 2);
                for ((record, event), (target, ttl, configured)) in records.iter()
                    .zip(&response.query_events).zip(&ordered)
                {
                    assert_eq!((record.rrtype, record.class, record.ttl), (TYPE_PTR, CLASS_IN, *ttl));
                    assert_eq!(record.rdata, wire_name(target).unwrap());
                    assert_eq!(event.name.as_deref(), Some(target.as_slice()));
                    assert_eq!(event.flags, qlog::REVERSE
                        | if ipv6 { qlog::IPV6 } else { qlog::IPV4 }
                        | if *configured { qlog::CONFIG } else { qlog::HOSTS });
                    assert_eq!(event.argument.as_deref(), if *configured {
                        None
                    } else {
                        Some(b"/fixture/repeated.hosts".as_slice())
                    });
                }
            }
        }
    }

    #[test]
    fn multiple_hosts_ptr_keeps_explicit_and_interface_precedence() {
        use super::super::interface_records::{InterfaceAddress, InterfaceRecords};
        let mut config = DnsConfig::default();
        apply(&mut config, b"ptr-record=1.2.0.192.in-addr.arpa,explicit.test");
        apply(&mut config, b"interface-name=interface.test,fixture0/4");
        let interface = InterfaceRecords::from_addresses(
            &config.interface_records.rules,
            &[InterfaceAddress {
                label: b"fixture0".to_vec(), address: "192.0.2.1".parse().unwrap(),
                prefix: 24, flags: 0,
            }],
        );
        for (interfaces, target) in [
            (InterfaceRecords::default(), "explicit.test"),
            (interface, "interface.test"),
        ] {
            let mut hosts = repeated_ptr_hosts(false, "x.test", "y.test");
            let response = LocalAnswerer {
                config: &config, hosts: &mut hosts, local_ttl: 37, max_packet: 512,
            }.answer_on_network_with_interface_cache(
                &query("1.2.0.192.in-addr.arpa", TYPE_PTR),
                &mut Arc::new(LeaseNames::default()), 100, None, None, &interfaces,
            ).unwrap().unwrap();
            let message = super::super::wire::Message::parse(&response.packet).unwrap();
            let records = message.records(Section::Answer).collect::<Vec<_>>();
            assert_eq!(records.len(), 1);
            assert_eq!((records[0].rrtype, records[0].ttl), (TYPE_PTR, 37));
            assert_eq!(records[0].rdata, wire_name(target.as_bytes()).unwrap());
        }
    }

    #[test]
    fn multiple_hosts_ptr_discards_an_overflowing_rrset_and_fits_tcp_limit() {
        let suffix = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(60));
        let first = format!("{}.{}", "x".repeat(63), suffix);
        let second = format!("{}.{}", "y".repeat(63), suffix);
        let mut hosts = repeated_ptr_hosts(false, &first, &second);
        let config = DnsConfig::default();
        let request = query("1.2.0.192.in-addr.arpa", TYPE_PTR);
        let mut answerer = LocalAnswerer {
            config: &config, hosts: &mut hosts, local_ttl: 37, max_packet: 65535,
        };
        let full = answerer.answer(&request).unwrap().unwrap();
        assert!(full.len() > 512);
        let full_header = Header::parse(&full).unwrap();
        assert_eq!((full_header.flags, full_header.answers), (0x8580, 2));
        answerer.max_packet = 512;
        let short = answerer.answer(&request).unwrap().unwrap();
        let short_header = Header::parse(&short).unwrap();
        assert_eq!((short_header.flags, short_header.answers), (0x8780, 0));
        assert_eq!((short_header.authorities, short_header.additionals), (0, 0));
        assert_eq!(short.len(), request.len());
        // A retry with the TCP limit still returns both owners: truncation
        // does not consume a shared reverse-owner cursor.
        answerer.max_packet = 65535;
        assert_eq!(answerer.answer(&request).unwrap().unwrap(), full);
    }

    #[test]
    fn ptr_forms_follow_c_prefix_and_explicit_record_rules() {
        for (name, address) in [
            (b"2.0.192.in-addr.arpa".as_slice(), "192.0.2.0"),
            (b"257.2.0.192.in-addr.arpa", "192.0.2.1"),
            (b"8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::"),
            (
                b"\\[x20010db8000000000000000000000001/128].ip6.int",
                "2001:db8::1",
            ),
        ] {
            assert_eq!(arpa_address(name), Some(address.parse().unwrap()));
        }
        assert_eq!(arpa_address(b"1.0/24.2.0.192.in-addr.arpa"), None);
        let mut config = DnsConfig::default();
        apply(&mut config, b"host-record=implicit.test,192.0.2.1,90");
        apply(
            &mut config,
            b"ptr-record=1.2.0.192.in-addr.arpa,explicit.test",
        );
        let mut hosts = configured_hosts(&config, 37);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 512,
        };
        let ptr = answerer
            .answer(&query("1.2.0.192.in-addr.arpa", TYPE_PTR))
            .unwrap()
            .unwrap();
        let rr = super::super::wire::Message::parse(&ptr)
            .unwrap()
            .records(Section::Answer)
            .next()
            .unwrap();
        assert_eq!(
            (rr.ttl, rr.rdata),
            (37, b"\x08explicit\x04test\0".as_slice())
        );
    }

    #[test]
    fn literal_label_dot_does_not_alias_a_dotted_host_raw_or_ptr_name() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"host-record=one.two.test,192.0.2.1");
        apply(&mut config, b"dns-rr=one.two.test,65401,abcd");
        let mut hosts = configured_hosts(&config, 37);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 512,
        };
        for (labels, kind) in [
            (vec![b"one.two".as_slice(), b"test"], TYPE_A),
            (vec![b"one.two".as_slice(), b"test"], 65401),
            (
                vec![b"1.2".as_slice(), b"0", b"192", b"in-addr", b"arpa"],
                TYPE_PTR,
            ),
        ] {
            let mut packet = query("unused", kind);
            packet.truncate(12);
            for label in labels {
                packet.push(label.len() as u8);
                packet.extend_from_slice(label);
            }
            packet.push(0);
            packet.extend_from_slice(&kind.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            assert!(answerer.answer(&packet).unwrap().is_none());
        }
        assert!(answerer
            .answer(&query("one.two.test", TYPE_A))
            .unwrap()
            .is_some());
        assert!(answerer
            .answer(&query("1.2.0.192.in-addr.arpa", TYPE_PTR))
            .unwrap()
            .is_some());
    }

    #[test]
    fn literal_label_dot_preserves_real_domain_suffixes() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"address=/route.test/192.0.2.13");
        apply(&mut config, b"local=/local.test/");
        let mut hosts = configured_hosts(&config, 37);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 512,
        };
        for (suffix, rcode, answers) in [(b"route", 0, 1), (b"local", 3, 0)] {
            let mut packet = query("unused", TYPE_A);
            packet.truncate(12);
            packet.extend_from_slice(b"\x07one.two\x05");
            packet.extend_from_slice(suffix);
            packet.extend_from_slice(b"\x04test\0\0\x01\0\x01");
            let reply = answerer.answer(&packet).unwrap().unwrap();
            let header = Header::parse(&reply).unwrap();
            assert_eq!(header.rcode(), rcode);
            assert_eq!(header.answers, answers);
        }
    }

    #[test]
    fn addressless_host_record_does_not_create_a_known_domain() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"host-record=empty.test,alias.test,90");
        let hosts = configured_hosts(&config, 37);
        assert!(hosts.is_empty());
        assert!(!known_forwarded_domain(
            &config,
            &hosts,
            &Name::from_ascii("empty.test").unwrap()
        ));
    }

    #[test]
    fn unowned_names_are_left_for_forwarder() {
        let config = DnsConfig::default();
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        assert!(answerer
            .answer(&query("outside.test", TYPE_A))
            .unwrap()
            .is_none());
    }

    #[test]
    fn host_record_without_requested_family_is_not_authoritative() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"host-record=router.test,192.0.2.1");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        assert!(answerer
            .answer(&query("router.test", TYPE_AAAA))
            .unwrap()
            .is_none());
    }

    #[test]
    fn address_rule_owns_name_and_can_truncate() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"address=/example.test/192.0.2.7");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 45,
        };
        let answer = answerer
            .answer(&query("www.example.test", TYPE_A))
            .unwrap()
            .unwrap();
        let message = super::super::wire::Message::parse(&answer).unwrap();
        assert_eq!(message.header.answers, 0);
        assert_ne!(message.header.flags & 0x0200, 0);
        assert!(answerer
            .answer(&query("www.example.test", TYPE_AAAA))
            .unwrap()
            .is_none());

        let mut zero_config = DnsConfig::default();
        apply(&mut zero_config, b"address=/zero.test/#");
        let mut zero_hosts = configured_hosts(&zero_config, 60);
        let mut zero_answerer = LocalAnswerer {
            config: &zero_config,
            hosts: &mut zero_hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        let zero_a = zero_answerer
            .answer(&query("zero.test", TYPE_A))
            .unwrap()
            .unwrap();
        let zero_aaaa = zero_answerer
            .answer(&query("zero.test", TYPE_AAAA))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Message::parse(&zero_a)
                .unwrap()
                .header
                .answers,
            1
        );
        assert_eq!(
            super::super::wire::Message::parse(&zero_aaaa)
                .unwrap()
                .header
                .answers,
            1
        );

        let mut local_config = DnsConfig::default();
        apply(&mut local_config, b"local=/local.test/");
        let mut local_hosts = configured_hosts(&local_config, 60);
        let mut local_answerer = LocalAnswerer {
            config: &local_config,
            hosts: &mut local_hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        let local = local_answerer
            .answer(&query("local.test", TYPE_A))
            .unwrap()
            .unwrap();
        let local_header = super::super::wire::Header::parse(&local).unwrap();
        assert_eq!(local_header.answers, 0);
        assert_eq!(local_header.flags & 0x0400, 0);
        assert_eq!(local_header.rcode(), 3);
        let local_any = local_answerer
            .answer(&query_class("local.test", TYPE_A, 255))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Header::parse(&local_any)
                .unwrap()
                .rcode(),
            3
        );
    }

    #[test]
    fn repeated_literals_reverse_configuration_order_and_prove_local_existence() {
        let mut config = DnsConfig::default();
        for line in [
            "address=/example.test/192.0.2.7",
            "address=/example.test/192.0.2.8",
            "local=/example.test/",
            "local=/absent.test/",
        ] {
            apply(&mut config, line.as_bytes());
        }
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        let answer = answerer
            .answer(&query("example.test", TYPE_A))
            .unwrap()
            .unwrap();
        let message = super::super::wire::Message::parse(&answer).unwrap();
        assert_eq!(
            message
                .records(Section::Answer)
                .map(|rr| rr.rdata)
                .collect::<Vec<_>>(),
            vec![&[192, 0, 2, 8][..], &[192, 0, 2, 7][..]]
        );
        for kind in [TYPE_AAAA, 16] {
            let answer = answerer
                .answer(&query("example.test", kind))
                .unwrap()
                .unwrap();
            let header = Header::parse(&answer).unwrap();
            assert_eq!(
                (header.rcode(), header.answers, header.flags & 0x0400),
                (0, 0, 0)
            );
        }
        let absent = answerer
            .answer(&query("absent.test", TYPE_AAAA))
            .unwrap()
            .unwrap();
        assert_eq!(Header::parse(&absent).unwrap().rcode(), 3);
    }

    #[test]
    fn empty_wildcard_literal_yields_to_a_default_upstream() {
        for with_server in [false, true] {
            let mut config = DnsConfig::default();
            apply(&mut config, b"address=/*./192.0.2.77");
            if with_server {
                apply(&mut config, b"server=192.0.2.53");
            }
            let mut hosts = configured_hosts(&config, 60);
            let mut answerer = LocalAnswerer {
                config: &config,
                hosts: &mut hosts,
                local_ttl: 60,
                max_packet: 512,
            };
            assert_eq!(
                answerer
                    .answer(&query("example.test", TYPE_A))
                    .unwrap()
                    .is_none(),
                with_server
            );
        }
    }

    #[test]
    fn routing_matches_wildcards_fallback_and_family_priority() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"address=/*example.test/192.0.2.7");
        apply(&mut config, b"address=/*.example.test/192.0.2.8");
        apply(&mut config, b"address=/example.test/192.0.2.9");
        apply(&mut config, b"address=/test/2001:db8::7");
        apply(&mut config, b"address=/families.test/192.0.2.10");
        apply(&mut config, b"address=/families.test/2001:db8::10");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };

        let answer = answerer
            .answer(&query("badexample.test", TYPE_A))
            .unwrap()
            .unwrap();
        let record = super::super::wire::Message::parse(&answer)
            .unwrap()
            .records(Section::Answer)
            .next()
            .unwrap();
        assert_eq!(record.rrtype, TYPE_A);
        assert_eq!(record.rdata, &[192, 0, 2, 7]);

        let answer = answerer
            .answer(&query("foo.example.test", TYPE_AAAA))
            .unwrap()
            .unwrap();
        let record = super::super::wire::Message::parse(&answer)
            .unwrap()
            .records(Section::Answer)
            .next()
            .unwrap();
        assert_eq!(
            record.rdata,
            &"2001:db8::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );

        let answer = answerer
            .answer(&query("families.test", 255))
            .unwrap()
            .unwrap();
        let records: Vec<_> = super::super::wire::Message::parse(&answer)
            .unwrap()
            .records(Section::Answer)
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rrtype, TYPE_AAAA);

        let mut dotted = DnsConfig::default();
        apply(&mut dotted, b"address=/*.example.test/192.0.2.11");
        let mut dotted_hosts = configured_hosts(&dotted, 60);
        let mut dotted_answerer = LocalAnswerer {
            config: &dotted,
            hosts: &mut dotted_hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        assert!(dotted_answerer
            .answer(&query("badexample.test", TYPE_A))
            .unwrap()
            .is_none());
        assert!(dotted_answerer
            .answer(&query("example.test", TYPE_A))
            .unwrap()
            .is_none());
        assert!(dotted_answerer
            .answer(&query("foo.example.test", TYPE_A))
            .unwrap()
            .is_some());
    }

    #[test]
    fn local_records_and_cname_suppress_address_rules() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"host-record=foo.test,192.0.2.8");
        apply(&mut config, b"address=/foo.test/192.0.2.7");
        apply(&mut config, b"address=/foo.test/#");
        apply(&mut config, b"cname=alias.test,target.test");
        apply(&mut config, b"host-record=target.test,192.0.2.9");
        apply(&mut config, b"address=/alias.test/192.0.2.10");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };

        let answer = answerer
            .answer(&query("foo.test", TYPE_A))
            .unwrap()
            .unwrap();
        let records: Vec<_> = super::super::wire::Message::parse(&answer)
            .unwrap()
            .records(Section::Answer)
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rdata, &[192, 0, 2, 8]);

        let answer = answerer
            .answer(&query("foo.test", TYPE_AAAA))
            .unwrap()
            .unwrap();
        let records: Vec<_> = super::super::wire::Message::parse(&answer)
            .unwrap()
            .records(Section::Answer)
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rdata, &[0; 16]);

        let answer = answerer
            .answer(&query("alias.test", TYPE_A))
            .unwrap()
            .unwrap();
        let records: Vec<_> = super::super::wire::Message::parse(&answer)
            .unwrap()
            .records(Section::Answer)
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].rrtype, TYPE_CNAME);
        assert_eq!(records[1].rdata, &[192, 0, 2, 9]);
    }

    #[test]
    fn cname_a_query_includes_target_address() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"cname=alias.test,target.test");
        apply(&mut config, b"host-record=target.test,192.0.2.9");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        let answer = answerer
            .answer(&query("alias.test", TYPE_A))
            .unwrap()
            .unwrap();
        let message = super::super::wire::Message::parse(&answer).unwrap();
        assert_eq!(message.header.answers, 2);
        let owners: Vec<_> = message
            .records(super::super::wire::Section::Answer)
            .map(|record| record.name().unwrap().canonical_wire())
            .collect();
        assert_eq!(
            owners[0],
            Name::from_ascii("alias.test").unwrap().canonical_wire()
        );
        assert_eq!(
            owners[1],
            Name::from_ascii("target.test").unwrap().canonical_wire()
        );

        let mut chain_config = DnsConfig::default();
        apply(&mut chain_config, b"cname=one.test,two.test");
        apply(&mut chain_config, b"cname=two.test,three.test");
        apply(&mut chain_config, b"host-record=three.test,192.0.2.10");
        let mut chain_hosts = configured_hosts(&chain_config, 60);
        let mut chain_answerer = LocalAnswerer {
            config: &chain_config,
            hosts: &mut chain_hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        let chain = chain_answerer
            .answer(&query("one.test", TYPE_A))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Message::parse(&chain)
                .unwrap()
                .header
                .answers,
            3
        );
    }

    #[test]
    fn local_parent_with_child_is_noerror_and_non_in_class_forwards() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"local=/local.test/");
        apply(&mut config, b"txt-record=child.local.test,hello");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        let answer = answerer
            .answer(&query("local.test", TYPE_A))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Message::parse(&answer)
                .unwrap()
                .header
                .rcode(),
            0
        );
        let any_class = answerer
            .answer(&query_class("local.test", TYPE_A, 255))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Header::parse(&any_class)
                .unwrap()
                .rcode(),
            0
        );
        let chaos = answerer
            .answer(&query_class("local.test", TYPE_A, 3))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Header::parse(&chaos).unwrap().rcode(),
            0
        );
    }

    #[test]
    fn cname_chain_uses_terminal_owner_and_independent_ttls() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"cname=one.test,two.test,11");
        apply(&mut config, b"cname=two.test,final.test,22");
        apply(&mut config, b"host-record=one.test,192.0.2.1");
        apply(&mut config, b"host-record=final.test,192.0.2.8");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        // Exact C fixture: alias data loses to CNAME; both links are emitted,
        // and the terminal host inherits local-ttl, not either alias TTL.
        for qtype in [TYPE_A, 255] {
            let answer = answerer.answer(&query("one.test", qtype)).unwrap().unwrap();
            let message = super::super::wire::Message::parse(&answer).unwrap();
            let records: Vec<_> = message.records(Section::Answer).collect();
            assert_eq!(records.len(), 3);
            assert_eq!(
                records.iter().map(|r| r.rrtype).collect::<Vec<_>>(),
                [5, 5, 1]
            );
            assert_eq!(
                records.iter().map(|r| r.ttl).collect::<Vec<_>>(),
                [11, 22, 60]
            );
            assert_eq!(
                records[2].name().unwrap().canonical_wire(),
                dotted_key(b"final.test")
            );
            assert_eq!(records[2].rdata, &[192, 0, 2, 8]);
        }
        let answer = answerer
            .answer(&query("one.test", TYPE_CNAME))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Header::parse(&answer).unwrap().answers,
            1
        );
    }

    #[test]
    fn cname_applies_to_all_record_types_and_ignores_alias_records() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"cname=alias.test,target.test");
        apply(&mut config, b"txt-record=alias.test,wrong");
        apply(&mut config, b"txt-record=target.test,hello");
        apply(&mut config, b"mx-host=target.test,mail.test,10");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        for (qtype, expected) in [
            (TYPE_TXT, vec![5, 16]),
            (TYPE_MX, vec![5, 15]),
            (65400, vec![5]),
            (255, vec![5, 16, 15]),
        ] {
            let answer = answerer
                .answer(&query("alias.test", qtype))
                .unwrap()
                .unwrap();
            let message = super::super::wire::Message::parse(&answer).unwrap();
            let records: Vec<_> = message.records(Section::Answer).collect();
            assert_eq!(
                records.iter().map(|r| r.rrtype).collect::<Vec<_>>(),
                expected
            );
            for record in records.iter().skip(1) {
                assert_eq!(
                    record.name().unwrap().canonical_wire(),
                    dotted_key(b"target.test")
                );
                if record.rrtype == TYPE_TXT {
                    assert_eq!(record.rdata, b"\x05hello");
                }
            }
        }
    }

    #[test]
    fn orphan_cname_still_answers_with_cname_only() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"cname=orphan.test,missing.test");
        let mut hosts = configured_hosts(&config, 60);
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        for qtype in [TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_TXT, 255] {
            let answer = answerer
                .answer(&query("orphan.test", qtype))
                .unwrap()
                .unwrap();
            let records: Vec<_> = super::super::wire::Message::parse(&answer)
                .unwrap()
                .records(Section::Answer)
                .collect();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].rrtype, TYPE_CNAME);
        }
    }

    #[test]
    fn local_known_names_include_hosts_but_not_raw_rr_nonterminals() {
        let mut config = DnsConfig::default();
        apply(&mut config, b"local=/LOCAL.test/");
        apply(&mut config, b"no-hosts");
        apply(&mut config, b"host-record=Exact.LOCAL.test,192.0.2.1");
        apply(&mut config, b"dns-rr=raw.LOCAL.test,16,0161");
        let mut hosts = configured_hosts(&config, 60);
        hosts.insert(
            b"fromfile.LOCAL.test".to_vec(),
            "192.0.2.2".parse().unwrap(),
            0,
            1,
        );
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        for name in ["local.test", "exact.local.test", "fromfile.local.test"] {
            let answer = answerer.answer(&query(name, TYPE_AAAA)).unwrap().unwrap();
            let header = super::super::wire::Header::parse(&answer).unwrap();
            assert_eq!(
                (header.rcode(), header.answers, header.flags & 0x0400),
                (0, 0, 0)
            );
        }
        // no-hosts is a source selection flag: an already loaded addn-hosts
        // entry must still answer.
        let answer = answerer
            .answer(&query("fromfile.local.test", TYPE_A))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Header::parse(&answer).unwrap().answers,
            1
        );

        let mut raw_config = DnsConfig::default();
        apply(&mut raw_config, b"local=/local.test/");
        apply(&mut raw_config, b"dns-rr=child.local.test,16,0161");
        let mut no_hosts = configured_hosts(&raw_config, 60);
        let mut raw_answerer = LocalAnswerer {
            config: &raw_config,
            hosts: &mut no_hosts,
            local_ttl: 60,
            max_packet: 512,
        };
        let answer = raw_answerer
            .answer(&query("local.test", TYPE_A))
            .unwrap()
            .unwrap();
        assert_eq!(
            super::super::wire::Header::parse(&answer).unwrap().rcode(),
            3
        );
    }
}

#[cfg(test)]
mod local_record_family_tests {
    use super::*;
    use crate::config::lex_line;
    use crate::dns::cache::{Policy, Record};
    use crate::dns::wire::Message;

    fn setup(lines: &[&str]) -> (DnsConfig, Hosts) {
        let mut config = DnsConfig::default();
        for line in lines {
            config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .unwrap();
        }
        config.finalize_hostname(b"gateway").unwrap();
        config.finalize().unwrap();
        let hosts = configured_hosts(&config, 37);
        (config, hosts)
    }

    fn request(owner: &str, rrtype: u16) -> Vec<u8> {
        let mut writer = PacketWriter::new(1, 0x100, 512).unwrap();
        writer
            .question(&Name::from_ascii(owner).unwrap(), rrtype, 1)
            .unwrap();
        writer.finish()
    }

    fn answer(
        config: &DnsConfig,
        hosts: &mut Hosts,
        owner: &str,
        rrtype: u16,
        limit: usize,
    ) -> Vec<u8> {
        LocalAnswerer {
            config,
            hosts,
            local_ttl: 37,
            max_packet: limit,
        }
        .answer(&request(owner, rrtype))
        .unwrap()
        .unwrap()
    }

    #[test]
    fn hostname_mx_defaults_and_srv_root_follow_c() {
        let (config, mut hosts) = setup(&[
            "domain=example.test",
            "localmx",
            "mx-host=mail.test",
            "srv-host=_none._tcp",
        ]);
        assert!(!config.records.needs_hostname());
        for (owner, rrtype, prefix) in [
            ("gateway", TYPE_MX, vec![0, 0]),
            ("mail.test", TYPE_MX, vec![0, 1]),
        ] {
            let packet = answer(&config, &mut hosts, owner, rrtype, 512);
            let message = Message::parse(&packet).unwrap();
            let record = message.records(Section::Answer).next().unwrap();
            let mut expected = prefix;
            expected.extend(Name::from_ascii("gateway").unwrap().as_wire());
            assert_eq!(record.rdata, expected);
        }
        let packet = answer(
            &config,
            &mut hosts,
            "_none._tcp.example.test",
            TYPE_SRV,
            512,
        );
        let message = Message::parse(&packet).unwrap();
        assert_eq!(
            message.records(Section::Answer).next().unwrap().rdata,
            [0, 0, 0, 0, 0, 1, 0]
        );
    }

    #[test]
    fn srv_rotates_before_additional_order_and_clones_keep_private_order() {
        let (config, mut hosts) = setup(&[
            "srv-host=service.test,a.test,1",
            "srv-host=service.test,b.test,2",
            "host-record=a.test,192.0.2.1",
            "host-record=b.test,192.0.2.2",
        ]);
        let snapshot = config.clone();
        let packet = answer(&config, &mut hosts, "service.test", TYPE_SRV, 512);
        let message = Message::parse(&packet).unwrap();
        let data: Vec<_> = message
            .records(Section::Additional)
            .map(|record| record.rdata.to_vec())
            .collect();
        assert_eq!(data, [vec![192, 0, 2, 1], vec![192, 0, 2, 2]]);
        assert_ne!(config.records.mail_order(), snapshot.records.mail_order());
        let packet = answer(&config, &mut hosts, "service.test", TYPE_SRV, 512);
        let message = Message::parse(&packet).unwrap();
        let data: Vec<_> = message
            .records(Section::Additional)
            .map(|record| record.rdata.to_vec())
            .collect();
        assert_eq!(data, [vec![192, 0, 2, 2], vec![192, 0, 2, 1]]);
    }

    #[test]
    fn optional_additional_overflow_keeps_answer_without_tc() {
        let (config, mut hosts) = setup(&[
            "mx-host=mail.test,a.test",
            "host-record=a.test,192.0.2.1,2001:db8::1",
        ]);
        let full = answer(&config, &mut hosts, "mail.test", TYPE_MX, 512);
        let message = Message::parse(&full).unwrap();
        assert_eq!(message.header.additionals, 2);
        let answer_end = message.records(Section::Answer).next().unwrap().end;
        let bounded = answer(&config, &mut hosts, "mail.test", TYPE_MX, answer_end);
        let header = Header::parse(&bounded).unwrap();
        assert_eq!(header.flags & 0x200, 0);
        assert_eq!((header.answers, header.additionals), (1, 0));
    }

    #[test]
    fn additional_cache_lookup_prunes_expired_addresses() {
        let (config, mut hosts) = setup(&["mx-host=mail.test,cached.test"]);
        let mut cache = Cache::new(8, Policy::default());
        cache.start_insert();
        cache
            .insert(
                Record {
                    name: Name::from_ascii("cached.test").unwrap(),
                    kind: Kind::Ipv4,
                    negative: false,
                    data: vec![192, 0, 2, 9],
                },
                100,
                10,
            )
            .unwrap();
        assert!(cache.commit());
        for (now, expected) in [(105, 1), (110, 0), (105, 0)] {
            let mut answerer = LocalAnswerer {
                config: &config,
                hosts: &mut hosts,
                local_ttl: 37,
                max_packet: 512,
            };
            let reply = answerer
                .answer_on_network_with_cache(
                    &request("mail.test", TYPE_MX),
                    &mut Arc::new(LeaseNames::default()),
                    now,
                    None,
                    Some(&mut cache),
                )
                .unwrap()
                .unwrap();
            assert_eq!(Header::parse(&reply.packet).unwrap().additionals, expected);
        }
    }
    #[test]
    fn additional_lease_expiry_is_sticky_after_clock_rollback() {
        let (config, mut hosts) = setup(&["mx-host=mail.test,lease.test"]);
        let mut leases = Arc::new(LeaseNames::build(
            &[crate::dhcp::persistence::DnsLeaseRecord {
                name: b"lease.test",
                address: Ipv4Addr::new(192, 0, 2, 8),
                expires: Some(110),
            }],
            &mut hosts,
            &[],
            crate::dns::lease_names::LeasePolicy::default(),
            &mut (),
        ));
        for (now, expected) in [(105, 1), (110, 0), (105, 0)] {
            let mut answerer = LocalAnswerer {
                config: &config,
                hosts: &mut hosts,
                local_ttl: 37,
                max_packet: 512,
            };
            let reply = answerer
                .answer_on_network_with_cache(
                    &request("mail.test", TYPE_MX),
                    &mut leases,
                    now,
                    None,
                    None,
                )
                .unwrap()
                .unwrap();
            assert_eq!(Header::parse(&reply.packet).unwrap().additionals, expected);
        }
    }

    #[test]
    fn truncated_answers_still_visit_their_successful_mail_targets() {
        let long = format!("mx-host=mail.test,{}.test", "x".repeat(60));
        let (config, mut hosts) = setup(&[&long, "mx-host=mail.test,cached.test"]);
        let mut cache = Cache::new(8, Policy::default());
        cache.start_insert();
        let id = cache
            .insert(
                Record {
                    name: Name::from_ascii("cached.test").unwrap(),
                    kind: Kind::Ipv4,
                    negative: false,
                    data: vec![192, 0, 2, 9],
                },
                100,
                10,
            )
            .unwrap();
        assert!(cache.commit());
        let mut answerer = LocalAnswerer {
            config: &config,
            hosts: &mut hosts,
            local_ttl: 37,
            max_packet: 60,
        };
        let reply = answerer
            .answer_on_network_with_cache(
                &request("mail.test", TYPE_MX),
                &mut Arc::new(LeaseNames::default()),
                110,
                None,
                Some(&mut cache),
            )
            .unwrap()
            .unwrap();
        let header = Header::parse(&reply.packet).unwrap();
        assert_ne!(header.flags & 0x200, 0);
        assert_eq!(header.answers, 0);
        assert!(cache.get(id).is_none());
    }
}

fn is_interface_ancestor(name: &[u8], configured: &[u8]) -> bool {
    name.is_empty()
        || configured.eq_ignore_ascii_case(name)
        || (configured.len() > name.len()
            && configured[configured.len() - name.len() - 1] == b'.'
            && configured[configured.len() - name.len()..].eq_ignore_ascii_case(name))
}

/// Resolve the configured CNAME terminal before the parent's enum decision.
/// Packet/cache wrappers remain the cache family's responsibility.
pub fn interface_forward_name(config: &DnsConfig, query: &[u8]) -> Option<Vec<u8>> {
    if config.interface_records.rules.is_empty() {
        return None;
    }
    let header = Header::parse(query).ok()?;
    let question = super::forward::Question::parse_with_header(query, header).ok()?;
    interface_forward_name_parsed(config, header, &question)
}

pub(crate) fn interface_forward_name_parsed(
    config: &DnsConfig,
    header: Header,
    question: &super::forward::Question,
) -> Option<Vec<u8>> {
    if config.interface_records.rules.is_empty()
        || header.opcode() != 0 || header.flags & 0x8000 != 0 || header.questions != 1
        || question.class != 1 || !matches!(question.rrtype, 1 | 28 | 255)
    {
        return None;
    }
    let mut name = wire_to_dotted(&question.name)?;
    for _ in 0..10 {
        if let Some(alias) = config
            .records
            .cnames
            .iter()
            .find(|alias| alias.alias.eq_ignore_ascii_case(&name))
        {
            name = alias.target.clone();
        } else {
            return config
                .interface_records
                .rules
                .iter()
                .any(|rule| rule.name.eq_ignore_ascii_case(&name))
                .then_some(name);
        }
    }
    None
}
