//! Borrowed DNS cache caller logic shared by UDP and TCP owners.
//! The context creates no transport, descriptor or owned local-name snapshot.
//! Insertion and answer selection retain the exact C contracts of the daemon
//! wrappers; ownership and synchronization remain with the containing caller.

use super::cache::{Cache, CacheCounters, CnameTarget, Kind, Record, StalePolicy};
use super::cache_reply::{append_cname_record, append_negative_authority, append_positive_record};
use super::local::AnswerError;
use super::service::LocalDnsService;
use super::wire::{
    find_pseudoheader, Header, Message, Name, PacketWriter, Question as WireQuestion, Section,
    WireError,
};
use std::net::IpAddr;

pub(super) struct CachedAnswer {
    pub packet: Option<Vec<u8>>,
    pub stale: bool,
}

#[derive(Debug)]
pub(super) enum CacheError {
    Wire(WireError),
    Local(AnswerError),
}

impl From<WireError> for CacheError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}
impl From<AnswerError> for CacheError {
    fn from(error: AnswerError) -> Self {
        Self::Local(error)
    }
}

pub(super) struct CacheContext<'a> {
    pub cache: &'a mut Cache,
    pub counters: &'a mut CacheCounters,
    pub negative_cache: bool,
    pub negative_ttl: u32,
}

/// Ordinary extraction can remove old records and evict entries even when
/// its final commit is suppressed. Bogus-wildcard caching is independent.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum OrdinaryCacheMode {
    Unsupported,
    ExtractOnly,
    Commit,
}

impl CacheContext<'_> {
    pub fn answer_udp(
        &mut self,
        query: &[u8],
        question: &super::forward::Question,
        now: i64,
        local: &mut LocalDnsService,
        max_udp: usize,
        edns_packet_max: u16,
    ) -> Result<CachedAnswer, CacheError> {
        let header = Header::parse(query)?;
        // Ordinary A/AAAA AD requests can consume unsigned cached records,
        // including CNAME/negative paths, without asserting validation. DO
        // still requires upstream DNSSEC data in the target no-DNSSEC build.
        // Other qtypes' AD, EDNS options and nonzero metadata stay outside
        // this measured subset; accepting DO on insertion is independent.
        let edns = find_pseudoheader(query, true)?;
        let dnssec_requested = edns.opt.as_ref().is_some_and(|opt| opt.dnssec_ok());
        if header.questions != 1
            || header.answers != 0
            || header.authorities != 0
            || header.additionals != u16::from(edns.opt.is_some())
            || header.opcode() != 0
            || header.flags & 0x8000 != 0
            || (header.flags & 0x0020 != 0 && !matches!(question.rrtype, 1 | 28))
            || (dnssec_requested && !matches!(question.rrtype, 1 | 28))
            || edns
                .opt
                .as_ref()
                .is_some_and(|opt| opt.record.ttl & !0x8000 != 0 || !opt.record.rdata.is_empty())
            || edns.signed
        {
            return Ok(CachedAnswer {
                packet: None,
                stale: false,
            });
        }
        if dnssec_requested {
            // answer_request looks up each group before rejecting unsigned
            // DO answers. Preserve LRU/rotation/expiry effects in that order,
            // stopping at a CNAME instead of following its target.
            let mut stale = false;
            if question.class == 1 {
                let round_robin = !local.config.no_round_robin;
                let first = self.cache.lookup(
                    &question.name,
                    &[Kind::Cname, Kind::NxDomain],
                    now,
                    round_robin,
                );
                let entry = first.first().and_then(|id| self.cache.get(*id));
                stale = entry.is_some_and(|entry| entry.is_stale(now));
                if !entry.is_some_and(|entry| entry.record.kind == Kind::Cname) {
                    let kind = if question.rrtype == 1 {
                        Kind::Ipv4
                    } else {
                        Kind::Ipv6
                    };
                    self.cache.lookup(&question.name, &[kind], now, round_robin);
                    self.cache.lookup(
                        &question.name,
                        &[Kind::Generic(question.rrtype), Kind::NxDomain],
                        now,
                        round_robin,
                    );
                }
            }
            return Ok(CachedAnswer {
                packet: None,
                stale,
            });
        }
        let limit = edns
            .opt
            .as_ref()
            .map_or(512, |opt| usize::from(opt.udp_size(edns_packet_max)));
        let mut answer = self.answer_records(question, header, now, local, max_udp.min(limit))?;
        if edns.opt.is_some() {
            if let Some(packet) = &mut answer.packet {
                // receive_query appends against the configured daemon limit,
                // after answer_request used the client's advertised limit.
                if answer.stale {
                    // Add the 17-byte OPT/EDE directly. Adding an empty OPT
                    // first would retain the wrong output at the fit boundary.
                    super::tcp_service::add_ede(
                        packet,
                        edns_packet_max,
                        false,
                        3,
                        usize::from(edns_packet_max),
                    )?;
                } else {
                    super::service::append_empty_opt(
                        packet,
                        edns_packet_max,
                        false,
                        usize::from(edns_packet_max),
                    )?;
                }
            }
        }
        Ok(answer)
    }

    pub fn answer_records(
        &mut self,
        question: &super::forward::Question,
        header: Header,
        now: i64,
        local: &mut LocalDnsService,
        limit: usize,
    ) -> Result<CachedAnswer, CacheError> {
        let mut stale = false;
        let round_robin = !local.config.no_round_robin;
        let cache = &mut *self.cache;
        if question.class != 1 {
            return Ok(CachedAnswer {
                packet: None,
                stale,
            });
        }
        let kind = match question.rrtype {
            1 => Kind::Ipv4,
            5 => Kind::Cname,
            28 => Kind::Ipv6,
            rrtype => Kind::Generic(rrtype),
        };
        let ordinary_kinds = [Kind::Cname, kind, Kind::NxDomain];
        let any_kinds = [Kind::Cname, Kind::Ipv4, Kind::Ipv6, kind, Kind::NxDomain];
        let kinds: &[Kind] = if question.rrtype == 255 {
            &any_kinds
        } else {
            &ordinary_kinds
        };
        let ids = cache.lookup(&question.name, kinds, now, round_robin);
        if ids.is_empty() {
            // An address/CNAME miss still reaches C's final F_RR lookup.
            // An unrelated generic record cannot answer this question, but
            // its lookup promotes it before the caller forwards the query.
            // Generic questions already visited that group above.
            if !matches!(kind, Kind::Generic(_)) {
                cache.lookup(
                    &question.name,
                    &[Kind::Generic(question.rrtype), Kind::NxDomain],
                    now,
                    round_robin,
                );
            }
            return Ok(CachedAnswer {
                packet: None,
                stale,
            });
        }
        // C inspects CNAME/NXDOMAIN before the requested type and before RD.
        // An old NXDOMAIN can mark a newer typed answer stale, or the caller
        // can observe staleness even though no answer can ultimately be sent.
        let mut direct_negative = None;
        for id in &ids {
            if let Some(entry) = cache.get(*id) {
                if entry.record.kind == Kind::NxDomain && entry.record.negative {
                    direct_negative.get_or_insert(*id);
                    stale |= entry.is_stale(now);
                } else if entry.record.kind == Kind::Cname {
                    stale |= entry.is_stale(now);
                }
            }
        }
        if header.flags & 0x0100 == 0 && !(question.rrtype == 5 && direct_negative.is_some()) {
            return Ok(CachedAnswer {
                packet: None,
                stale,
            });
        }
        if question.rrtype == 255 {
            // Dynamic A/AAAA cannot answer ANY, but C has inspected their
            // stale bits by the time it rejects this source for ANY output.
            stale |= ids
                .iter()
                .filter_map(|id| cache.get(*id))
                .filter(|entry| matches!(entry.record.kind, Kind::Ipv4 | Kind::Ipv6))
                .any(|entry| entry.is_stale(now));
        }
        if let Some(id) = direct_negative.filter(|_| {
            question.rrtype == 5
                || !ids.iter().any(|id| {
                    cache
                        .get(*id)
                        .is_some_and(|entry| entry.record.kind == kind)
                })
        }) {
            let mut writer = PacketWriter::new(header.id, (header.flags & 0x0110) | 0x8083, limit)?;
            writer.question(&question.name, question.rrtype, question.class)?;
            match append_negative_authority(&mut writer, cache, id, now) {
                Ok(_) | Err(WireError::Full) => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(finish_cached_answer(writer, stale)?);
        }
        if question.rrtype == 5 {
            if header.flags & 0x0100 == 0 {
                return Ok(CachedAnswer {
                    packet: None,
                    stale,
                });
            }
            // answer_request stops after the first CNAME for this qtype,
            // even when its target is another alias or a negative entry.
            // That exact C branch retains AA; only terminal address/negative
            // processing clears it for other qtypes.
            let mut writer = PacketWriter::new(header.id, (header.flags & 0x0110) | 0x8480, limit)?;
            writer.question(&question.name, question.rrtype, question.class)?;
            for id in ids {
                if let Some(entry) = cache
                    .get(id)
                    .filter(|entry| entry.record.kind == Kind::Cname)
                {
                    stale |= entry.is_stale(now);
                }
                match append_cname_record(&mut writer, cache, id, Section::Answer, now, Some(12)) {
                    Ok(None) => continue,
                    Ok(Some(_)) | Err(WireError::Full) => {
                        return Ok(finish_cached_answer(writer, stale)?);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            return Ok(CachedAnswer {
                packet: None,
                stale,
            });
        }
        let direct_cname = ids.iter().copied().find(|id| {
            cache
                .get(*id)
                .is_some_and(|entry| entry.record.kind == Kind::Cname)
        });
        let direct_nodata = direct_cname
            .is_none()
            .then(|| {
                ids.iter().find_map(|id| {
                    cache.get(*id).and_then(|entry| {
                        (entry.record.negative && entry.record.kind == kind).then_some(*id)
                    })
                })
            })
            .flatten();
        if let Some(id) = direct_nodata {
            stale |= cache.get(id).is_some_and(|entry| entry.is_stale(now));
            let mut writer = PacketWriter::new(header.id, (header.flags & 0x0110) | 0x8080, limit)?;
            writer.question(&question.name, question.rrtype, question.class)?;
            match append_negative_authority(&mut writer, cache, id, now) {
                Ok(_) | Err(WireError::Full) => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(finish_cached_answer(writer, stale)?);
        }

        // A CNAME can terminate in a cached negative entry.  Preflight the
        // linked target before creating the writer so its RCODE matches the
        // terminal result while still emitting every CNAME in the answer.
        let mut cname_negative = None;
        for id in &ids {
            let Some(entry) = cache.get(*id) else {
                continue;
            };
            if entry.record.kind != Kind::Cname {
                continue;
            }
            let mut current = *id;
            for _ in 0..10 {
                let Some(current_entry) = cache.get(current) else {
                    break;
                };
                if current_entry.record.kind != Kind::Cname {
                    if current_entry.record.negative {
                        cname_negative = Some((current, current_entry.record.kind));
                    }
                    break;
                }
                let Some(target) = current_entry.cname_target() else {
                    break;
                };
                match target {
                    CnameTarget::Dynamic(target) => current = target,
                    CnameTarget::Local(_) => break,
                }
            }
        }
        let mut writer = PacketWriter::new(
            header.id,
            (header.flags & 0x0110)
                | if cname_negative.is_some_and(|(_, kind)| kind == Kind::NxDomain) {
                    0x8083
                } else {
                    0x8080
                },
            limit,
        )?;
        writer.question(&question.name, question.rrtype, question.class)?;
        let mut written = false;
        for id in ids {
            // answer_request follows the first CNAME before looking for the
            // requested type, even if the same batch also cached an owner A.
            if direct_cname.is_some_and(|cname| cname != id) {
                continue;
            }
            if let Some(entry) = cache.get(id) {
                if entry.record.kind == Kind::Cname {
                    let mut current = id;
                    let mut owner_offset = 12;
                    let mut complete = false;
                    for _ in 0..10 {
                        stale |= cache.get(current).is_some_and(|entry| entry.is_stale(now));
                        // A compressed owner is two bytes, followed by the
                        // ten-byte RR header. The uncompressed target starts
                        // there and becomes the owner of the next record.
                        let target_offset = (writer.position() + 12) as u16;
                        let target = match append_cname_record(
                            &mut writer,
                            cache,
                            current,
                            Section::Answer,
                            now,
                            Some(owner_offset),
                        ) {
                            Ok(Some(target)) => target,
                            Ok(None) => break,
                            Err(WireError::Full) => {
                                return Ok(finish_cached_answer(writer, stale)?);
                            }
                            Err(error) => return Err(error.into()),
                        };
                        owner_offset = target_offset;
                        let target = match target {
                            CnameTarget::Dynamic(target) => target,
                            CnameTarget::Local(target) => {
                                let Some(flags) = append_local_terminal(
                                    &mut writer,
                                    local,
                                    &target.name,
                                    question,
                                    header,
                                    now,
                                    owner_offset,
                                )?
                                else {
                                    return Ok(CachedAnswer {
                                        packet: None,
                                        stale,
                                    });
                                };
                                return Ok(finish_cached_answer_flags(writer, Some(flags), stale)?);
                            }
                        };
                        let Some(target_entry) = cache.get(target) else {
                            break;
                        };
                        if matches!(target_entry.record.kind, Kind::Cname) {
                            current = target;
                            continue;
                        }
                        if target_entry.record.negative {
                            // A cached NODATA is specific to its original
                            // qtype. The CNAME link does not make it a
                            // name-wide negative, nor extend its expiry.
                            if target_entry.record.kind != kind
                                && target_entry.record.kind != Kind::NxDomain
                            {
                                return Ok(CachedAnswer {
                                    packet: None,
                                    stale,
                                });
                            }
                            let terminal_name = target_entry.record.name.clone();
                            if !cache
                                .lookup_question(&terminal_name, kind, now, round_robin)
                                .contains(&target)
                            {
                                return Ok(CachedAnswer {
                                    packet: None,
                                    stale,
                                });
                            }
                            stale |= cache.get(target).is_some_and(|entry| entry.is_stale(now));
                            match append_negative_authority(&mut writer, cache, target, now) {
                                Ok(_) => {}
                                Err(WireError::Full) => {
                                    return Ok(finish_cached_answer(writer, stale)?);
                                }
                                Err(error) => return Err(error.into()),
                            }
                            complete = true;
                        } else {
                            // A CNAME is reusable across qtypes, but its
                            // cached terminal RRset is not.  C's answer path
                            // abandons this cache hit when an A chain is
                            // queried as AAAA (and vice versa).
                            if target_entry.record.kind != kind {
                                return Ok(CachedAnswer {
                                    packet: None,
                                    stale,
                                });
                            }
                            let terminal_name = target_entry.record.name.clone();
                            let terminal_kind = target_entry.record.kind;
                            let terminal_ids =
                                cache.lookup(&terminal_name, &[terminal_kind], now, round_robin);
                            for terminal_id in terminal_ids {
                                if cache
                                    .get(terminal_id)
                                    .is_none_or(|entry| entry.record.kind != terminal_kind)
                                {
                                    continue;
                                }
                                stale |= cache
                                    .get(terminal_id)
                                    .is_some_and(|entry| entry.is_stale(now));
                                match append_positive_record(
                                    &mut writer,
                                    cache,
                                    terminal_id,
                                    Section::Answer,
                                    now,
                                    Some(owner_offset),
                                ) {
                                    Ok(true) => {
                                        complete = true;
                                    }
                                    Ok(false) => {}
                                    Err(WireError::Full) => {
                                        return Ok(finish_cached_answer(writer, stale)?);
                                    }
                                    Err(error) => return Err(error.into()),
                                }
                            }
                        }
                        break;
                    }
                    if !complete {
                        return Ok(CachedAnswer {
                            packet: None,
                            stale,
                        });
                    }
                    return Ok(finish_cached_answer(writer, stale)?);
                }
                if entry.record.kind != kind {
                    continue;
                }
                stale |= entry.is_stale(now);
            }
            match append_positive_record(&mut writer, cache, id, Section::Answer, now, Some(12)) {
                Ok(true) => written = true,
                Ok(false) => {}
                Err(WireError::Full) => break,
                Err(error) => return Err(error.into()),
            }
        }
        if written {
            return Ok(finish_cached_answer(writer, stale)?);
        }
        Ok(CachedAnswer {
            packet: None,
            stale,
        })
    }

    /// Preserve ordered cache effects, including a prefix before bad generic
    /// RDATA. Return that validation error so the caller rejects the reply;
    /// an insertion failure such as capacity exhaustion is not a wire error.
    pub fn insert_reply_with_policy(
        &mut self,
        packet: &[u8],
        now: i64,
        local: &LocalDnsService,
        policy: &super::process::AddressPolicy,
        original_rcode: u16,
        ordinary: OrdinaryCacheMode,
    ) -> Result<(), WireError> {
        let Ok(header) = Header::parse(packet) else {
            return Ok(());
        };
        if header.opcode() != 0 || !matches!(original_rcode, 0 | 3) || header.flags & 0x0200 != 0 {
            return Ok(());
        }
        let cache = &mut *self.cache;
        let counters = &mut *self.counters;
        if original_rcode != 3 {
            if let Some((name, ttl)) =
                super::process::bogus_cache_entry(packet, header.answers, policy)
            {
                // This independent branch uses the matching RR's owner/TTL;
                // --no-negcache, RA and CD do not suppress its commit in C.
                cache.start_insert();
                insert_cache_record(
                    cache,
                    counters,
                    local,
                    Record {
                        name,
                        kind: Kind::NxDomain,
                        negative: true,
                        data: Vec::new(),
                    },
                    now,
                    ttl,
                );
                let _ = cache.commit_counted(counters);
                return Ok(());
            }
        }
        // Unsupported query metadata stays outside ordinary extraction.
        // CD/no_cache instead run its ordered effects and gate only commit.
        if ordinary == OrdinaryCacheMode::Unsupported {
            return Ok(());
        }
        cache.start_insert();
        if header.questions != 1 {
            return Ok(());
        }
        let Ok(question) = WireQuestion::parse(packet, super::wire::HEADER_LEN) else {
            return Ok(());
        };
        if question.class != 1 {
            return Ok(());
        }
        // Address-form PTR replies need C's separate reverse-cache index.
        // Keep that unimplemented boundary explicit instead of storing a
        // forward Generic(12) entry with different lookup/conflict semantics.
        if question.qtype == 12
            && header.rcode() != 3
            && super::local::arpa_address(&question.name.dnsmasq_bytes()).is_some()
        {
            return Ok(());
        }
        let Ok(edns) = find_pseudoheader(packet, false) else {
            return Ok(());
        };
        if edns
            .opt
            .as_ref()
            .is_some_and(|opt| opt.extended_rcode() != 0)
        {
            return Ok(());
        }

        let kind = match question.qtype {
            1 => Kind::Ipv4,
            28 => Kind::Ipv6,
            rrtype => Kind::Generic(rrtype),
        };
        let insert = question.qtype != 5
            && (matches!(question.qtype, 1 | 12 | 28 | 33)
                || (question.qtype != 0 && local.config.cache_rr.contains(&question.qtype))
                || local.config.cache_rr.contains(&255));
        let max_reply_ttl = cache.policy().max_reply_ttl;
        let mut current = question.name.clone();
        let mut cname_left = 10;
        let mut cname_target = None;
        let mut found = false;
        let answer_end;
        // C restarts the Answer scan after each CNAME and inserts as it goes.
        // A later malformed RR/rebind abort leaves pending records uncommitted,
        // while old RRset removal and live-eviction counters remain observable.
        'cname: loop {
            let mut position = question.end;
            for _ in 0..header.answers {
                let Ok(rr) = super::wire::RecordRef::parse(packet, position) else {
                    return Ok(());
                };
                position = rr.end;
                let Ok(owner) = rr.name() else { return Ok(()) };
                if rr.class != 1 || !owner.eq_ignore_ascii_case(&current) {
                    continue;
                }
                let ttl = if max_reply_ttl == 0 {
                    rr.ttl
                } else {
                    rr.ttl.min(max_reply_ttl)
                };
                if rr.rrtype == 5 {
                    if cname_left == 0 {
                        return Ok(());
                    }
                    cname_left -= 1;
                    // Act on failure only after insertion: C removes the old
                    // owner before validating this target.
                    let target = super::wire::decode_name(packet, rr.fixed + 10, 0);
                    let next = if insert {
                        match insert_cache_record(
                            cache,
                            counters,
                            local,
                            Record {
                                name: current.clone(),
                                kind: Kind::Cname,
                                negative: false,
                                data: target
                                    .as_ref()
                                    .map_or_else(|_| Vec::new(), |(name, _)| name.canonical_wire()),
                            },
                            now,
                            ttl,
                        ) {
                            Some(CacheInsert::Dynamic(id)) => Some(id),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    if let (Some(previous), Some(next)) = (cname_target, next) {
                        cache.set_cname_target(previous, next);
                    }
                    cname_target = next;
                    // extract_name checks packet bounds, not the declared
                    // RDLEN. Keep that bounded behavior for ordinary CNAMEs.
                    let Ok((target, _)) = target else {
                        return Ok(());
                    };
                    current = target;
                    if question.qtype != 5 {
                        continue 'cname;
                    }
                    found = true;
                } else if question.qtype != 255
                    && rr.rrtype == question.qtype
                    && header.rcode() != 3
                {
                    found = true;
                    if !insert {
                        continue;
                    }
                    let data = if matches!(kind, Kind::Ipv4 | Kind::Ipv6) {
                        let width = if question.qtype == 1 { 4 } else { 16 };
                        let Some(data) = packet.get(rr.fixed + 10..rr.fixed + 10 + width) else {
                            return Ok(());
                        };
                        let address = if question.qtype == 1 {
                            IpAddr::V4(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(data).unwrap()))
                        } else {
                            IpAddr::V6(std::net::Ipv6Addr::from(
                                <[u8; 16]>::try_from(data).unwrap(),
                            ))
                        };
                        if policy.rejects_rebind(&question.name, address) {
                            return Ok(());
                        }
                        data.to_vec()
                    } else {
                        match rr.canonical_rdata() {
                            Ok(data) => data,
                            // Compression expansion can exceed the cache's
                            // representable RDATA length without making the
                            // original wire reply invalid. Keep forwarding it.
                            Err(WireError::RecordTooLong) => return Ok(()),
                            Err(error) => return Err(error),
                        }
                    };
                    let inserted = insert_cache_record(
                        cache,
                        counters,
                        local,
                        Record {
                            name: current.clone(),
                            kind,
                            negative: false,
                            data,
                        },
                        now,
                        ttl,
                    );
                    if let Some(previous) = cname_target.take() {
                        match inserted {
                            Some(CacheInsert::Dynamic(id)) => {
                                cache.set_cname_target(previous, id);
                            }
                            Some(CacheInsert::Local(name, lease)) => {
                                let target = cache.local_target(name, lease);
                                cache.set_local_cname_target(previous, target);
                            }
                            None => {}
                        }
                    }
                }
            }
            answer_end = position;
            break;
        }
        if !found
            && self.negative_cache
            && ((insert && question.qtype != 255) || header.rcode() == 3)
        {
            let soa = authority_soa(packet, answer_end, header.authorities, &current);
            let mut soa_ttl = soa.as_ref().and_then(|(_, ttl, minimum, _)| {
                (*ttl != 0 || cache.policy().stale != StalePolicy::Disabled)
                    .then_some((*ttl).min(*minimum))
            });
            let mut authority = soa_ttl.and(soa.as_ref());
            // A direct negative inserts its SOA first; a CNAME target must
            // immediately follow its alias, so its SOA is inserted afterwards.
            if cname_target.is_none()
                && authority.is_some()
                && insert_authority(cache, counters, local, authority, now).is_none()
            {
                authority = None;
                soa_ttl = None;
            }
            if let Some(ttl) = soa_ttl.or((self.negative_ttl != 0).then_some(self.negative_ttl)) {
                let inserted = insert_cache_record(
                    cache,
                    counters,
                    local,
                    Record {
                        name: current,
                        kind: if header.rcode() == 3 {
                            Kind::NxDomain
                        } else {
                            kind
                        },
                        negative: true,
                        data: Vec::new(),
                    },
                    now,
                    ttl,
                );
                if let Some(CacheInsert::Dynamic(id)) = inserted {
                    if let Some(previous) = cname_target {
                        cache.set_cname_target(previous, id);
                        if insert_authority(cache, counters, local, authority, now).is_none() {
                            authority = None;
                        }
                    }
                    if let Some((name, _, _, _)) = authority {
                        cache.set_negative_authority(id, name.clone());
                    }
                }
            }
        }
        if ordinary == OrdinaryCacheMode::Commit && header.flags & 0x0090 == 0x0080 {
            let _ = cache.commit_counted(counters);
        }
        Ok(())
    }
}

/// `answer_request` clears all response sections when any cached RR cannot
/// fit, while the reusable PacketWriter intentionally retains complete RRs.
fn finish_cached_answer(writer: PacketWriter, stale: bool) -> Result<CachedAnswer, WireError> {
    finish_cached_answer_flags(writer, None, stale)
}

fn finish_cached_answer_flags(
    writer: PacketWriter,
    local_flags: Option<u16>,
    stale: bool,
) -> Result<CachedAnswer, WireError> {
    let mut packet = writer.finish();
    let mut header = Header::parse(&packet)?;
    if let Some(flags) = local_flags {
        header.flags = (header.flags & !0x040f) | (flags & 0x060f);
        header.write(&mut packet)?;
    }
    if header.flags & 0x0200 != 0 {
        packet.truncate(super::wire::skip_questions(&packet)?);
        header.answers = 0;
        header.authorities = 0;
        header.additionals = 0;
        header.write(&mut packet)?;
    }
    Ok(CachedAnswer {
        packet: Some(packet),
        stale,
    })
}

/// Reuse the local answer engine for a cached alias's terminal name, including
/// configured CNAME precedence, lease expiry and address rotation. Forwarding
/// rules are not an answer_request terminal and must not synthesize this hit.
fn append_local_terminal(
    writer: &mut PacketWriter,
    local: &mut LocalDnsService,
    target: &Name,
    question: &super::forward::Question,
    header: Header,
    now: i64,
    owner_offset: u16,
) -> Result<Option<u16>, CacheError> {
    let mut query = PacketWriter::new(header.id, header.flags, u16::MAX as usize)?;
    query.question(target, question.rrtype, question.class)?;
    let mut answerer = super::local::LocalAnswerer {
        config: &local.config,
        hosts: &mut local.hosts,
        local_ttl: local.local_ttl,
        max_packet: u16::MAX as usize,
    };
    let Some(answer) =
        answerer.answer_on_network(&query.finish(), &mut local.leases, now, local.local_network)?
    else {
        return Ok(None);
    };
    if answer.forward_rule {
        return Ok(None);
    }
    let message = Message::parse(&answer.packet)?;
    let mut previous_name = target.clone();
    let mut previous_offset = owner_offset;
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        for record in message.records(section) {
            let owner = record.name()?;
            let data = record.canonical_rdata()?;
            let compressed = owner.eq_ignore_ascii_case(&previous_name);
            let target_offset =
                writer.position() + if compressed { 2 } else { owner.as_wire().len() } + 10;
            let result = if compressed {
                writer.record_at(
                    section,
                    previous_offset,
                    record.rrtype,
                    record.class,
                    record.ttl,
                    &data,
                )
            } else {
                writer.record(
                    section,
                    &owner,
                    record.rrtype,
                    record.class,
                    record.ttl,
                    &data,
                )
            };
            match result {
                Ok(()) => {}
                Err(WireError::Full) => return Ok(Some(message.header.flags | 0x0200)),
                Err(error) => return Err(error.into()),
            }
            if record.rrtype == 5 {
                previous_name = super::wire::decode_name(&data, 0, 0)?.0;
                previous_offset =
                    u16::try_from(target_offset).map_err(|_| WireError::RecordTooLong)?;
            }
        }
    }
    Ok(Some(message.header.flags))
}

/// Select the first IN SOA in the authority section whose owner is a label
/// suffix of the terminal answer name, as `rfc1035.c::find_soa` does.  The
/// returned negative TTL uses the wire SOA TTL and MINIMUM; the SOA itself is
/// inserted as a normal Generic(6) cache entry so its own policy/expiry and
/// capacity accounting remain independent.
fn authority_soa(
    packet: &[u8],
    mut position: usize,
    count: u16,
    name: &Name,
) -> Option<(Name, u32, u32, Vec<u8>)> {
    // find_soa stops at the first malformed authority, but an earlier matching
    // SOA remains usable even if a later authority/additional is incomplete.
    for _ in 0..count {
        let rr = super::wire::RecordRef::parse(packet, position).ok()?;
        position = rr.end;
        let owner = rr.name().ok()?;
        if rr.class != 1 || rr.rrtype != 6 {
            continue;
        }
        if !is_name_suffix(name, &owner) {
            continue;
        }
        let data = rr.canonical_rdata().ok()?;
        if data.len() < 24 {
            continue;
        }
        let minimum = u32::from_be_bytes(data[data.len() - 4..].try_into().ok()?);
        return Some((owner, rr.ttl, minimum, data));
    }
    None
}

fn insert_authority(
    cache: &mut Cache,
    counters: &mut CacheCounters,
    local: &LocalDnsService,
    soa: Option<&(Name, u32, u32, Vec<u8>)>,
    now: i64,
) -> Option<super::cache::EntryId> {
    let (name, ttl, _, data) = soa?;
    match insert_cache_record(
        cache,
        counters,
        local,
        Record {
            name: name.clone(),
            kind: Kind::Generic(6),
            negative: false,
            data: data.clone(),
        },
        now,
        *ttl,
    ) {
        Some(CacheInsert::Dynamic(id)) => Some(id),
        _ => None,
    }
}

enum CacheInsert {
    Dynamic(super::cache::EntryId),
    Local(Name, bool),
}

fn insert_cache_record(
    cache: &mut Cache,
    counters: &mut CacheCounters,
    local: &LocalDnsService,
    record: Record,
    now: i64,
    ttl: u32,
) -> Option<CacheInsert> {
    let name = record.name.dnsmasq_bytes();
    let matches_address = |address: IpAddr| {
        !record.negative
            && match (record.kind, address) {
                (Kind::Ipv4, IpAddr::V4(address)) => record.data == address.octets(),
                (Kind::Ipv6, IpAddr::V6(address)) => record.data == address.octets(),
                _ => false,
            }
    };
    let host = local.hosts.addresses(&name).find(|host| match record.kind {
        Kind::Ipv4 => host.address.is_ipv4(),
        Kind::Ipv6 => host.address.is_ipv6(),
        Kind::Cname => true,
        _ => false,
    });
    // scan_free checks a local match before expiry. Do not silently revive a
    // previously unhashed entry, or ignore one not yet touched by lookup.
    let lease = matches!(record.kind, Kind::Ipv4 | Kind::Cname)
        .then(|| local.leases.active_lookup(&name).next())
        .flatten();
    let cname = local
        .config
        .records
        .cnames
        .iter()
        .any(|cname| cname.alias.eq_ignore_ascii_case(&name));
    // C loads configured CNAMEs before non-reverse immortal hosts. Reverse
    // owners precede both; mortal non-reverse leases precede immortal records.
    let existing = host
        .filter(|host| host.reverse)
        .map(|host| (matches_address(host.address), false))
        .or_else(|| {
            lease
                .filter(|lease| lease.reverse || lease.expires.is_some())
                .map(|lease| (matches_address(IpAddr::V4(lease.address)), true))
        })
        .or_else(|| cname.then_some((false, false)))
        .or_else(|| host.map(|host| (matches_address(host.address), false)))
        .or_else(|| lease.map(|lease| (matches_address(IpAddr::V4(lease.address)), true)));
    if let Some((same_address, from_lease)) = existing {
        cache.insert_against_local(ttl, same_address).ok()?;
        Some(CacheInsert::Local(record.name, from_lease))
    } else {
        cache
            .insert_counted(record, now, ttl, counters)
            .ok()
            .map(CacheInsert::Dynamic)
    }
}

fn is_name_suffix(name: &Name, suffix: &Name) -> bool {
    let name = name.canonical_wire();
    let suffix = suffix.canonical_wire();
    let mut offset = 0;
    while offset < name.len() {
        if name[offset..].starts_with(&suffix) {
            return true;
        }
        let length = usize::from(name[offset]);
        if length == 0 {
            break;
        }
        offset = offset.checked_add(length + 1).unwrap_or(name.len());
    }
    false
}
