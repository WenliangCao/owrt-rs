//! Borrowed DNS cache caller logic shared by UDP and TCP owners.
//! The context creates no transport, descriptor or owned local-name snapshot.
//! Insertion and answer selection retain the exact C contracts of the daemon
//! wrappers; ownership and synchronization remain with the containing caller.

use super::cache::{Cache, CacheCounters, CnameTarget, Kind, Record};
use super::cache_reply::{append_cname_record, append_negative_authority, append_positive_record};
use super::local::AnswerError;
use super::service::LocalDnsService;
use super::wire::{
    find_pseudoheader, Header, Message, Name, PacketWriter, Question as WireQuestion, Section,
    WireError,
};
use crate::query_logging::{self as qlog, QueryData, QueryEvent};
use std::net::IpAddr;

pub struct CachedAnswer {
    pub packet: Option<Vec<u8>>,
    pub stale: bool,
    pub filtered: bool,
    /// answer_request's name cursor after following a usable cached CNAME.
    pub forward_name: Option<Name>,
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
    pub negative_ttl: u64,
    pub filter_rr: &'a [u16],
}

/// Ordinary extraction can remove old records and evict entries even when
/// its final commit is suppressed. Bogus-wildcard caching is independent.
pub(super) use super::cache::Extraction as OrdinaryCacheMode;

impl CacheContext<'_> {
    /// The caller has evaluated add_edns0_config's cacheable flag. EDNS
    /// request options then need no per-record cache representation.
    #[allow(clippy::too_many_arguments)]
    pub fn answer_udp_with_edns(
        &mut self,
        query: &[u8],
        question: &super::forward::Question,
        now: i64,
        local: &mut LocalDnsService,
        max_udp: usize,
        edns_packet_max: u16,
        _allow_options: bool,
    ) -> Result<CachedAnswer, CacheError> {
        Self::answer_from_cache(
            self.cache,
            query,
            Header::parse(query)?,
            question,
            now,
            local,
            max_udp,
            edns_packet_max,
            false,
            self.filter_rr.contains(&question.rrtype),
            None,
        )
    }

    /// tcp_request supplies a 65536-byte output envelope independently of the
    /// client's UDP advertisement. Caller uses its accepted cache/clock view.
    pub fn answer_tcp(
        &mut self,
        query: &[u8],
        header: Header,
        question: &super::forward::Question,
        now: i64,
        local: &mut LocalDnsService,
        edns_packet_max: u16,
    ) -> Result<CachedAnswer, CacheError> {
        Self::answer_from_cache(
            self.cache,
            query,
            header,
            question,
            now,
            local,
            65536,
            edns_packet_max,
            true,
            self.filter_rr.contains(&question.rrtype),
            None,
        )
    }

    #[cfg(test)]
    pub fn answer_records(
        &mut self,
        question: &super::forward::Question,
        header: Header,
        now: i64,
        local: &mut LocalDnsService,
        limit: usize,
        dnssec_requested: bool,
    ) -> Result<CachedAnswer, CacheError> {
        Self::answer_records_filtered(self.cache, question, header, now, local, limit,
            dnssec_requested, self.filter_rr.contains(&question.rrtype), None)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn answer_from_cache(
        cache: &mut Cache,
        query: &[u8],
        header: Header,
        question: &super::forward::Question,
        now: i64,
        local: &mut LocalDnsService,
        max_udp: usize,
        edns_packet_max: u16,
        tcp: bool,
        filtered_type: bool,
        name_lookup: Option<&super::cache::NameLookup<'_>>,
    ) -> Result<CachedAnswer, CacheError> {
        // interface-name owns this family even when the current interface
        // enumeration is empty. NXDOMAIN is the earlier cache exception.
        if super::local::interface_forward_name_parsed(&local.config, header, question).is_some()
            && !cache.has_nxdomain(&question.name, now)
        {
            return Ok(CachedAnswer { packet: None, stale: false, filtered: false, forward_name: None });
        }
        // answer_request overwrites the Additional section with its own OPT.
        // Request signatures, OPT version/flags and opaque options do not
        // change the cached record representation. Source-bound NO_CACHE is
        // evaluated by the owner before entering this context. DO still
        // rejects unsigned dynamic records in the exact no-DNSSEC image.
        let edns = find_pseudoheader(query, true)?;
        let dnssec_requested = edns.opt.as_ref().is_some_and(|opt| opt.dnssec_ok());
        if header.questions != 1
            || header.answers != 0
            || header.authorities != 0
            || header.opcode() != 0
            || header.flags & 0x8000 != 0
        {
            return Ok(CachedAnswer {
                forward_name: None,
                filtered: false,
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
                let first = cache.lookup_with_hint(
                    &question.name,
                    &[Kind::Cname, Kind::NxDomain],
                    now,
                    round_robin,
                    name_lookup,
                );
                let entry = first.first().and_then(|id| cache.get(*id));
                stale = entry.is_some_and(|entry| entry.is_stale(now));
                if !entry.is_some_and(|entry| entry.record.kind == Kind::Cname) {
                    if question.rrtype == 12 {
                        if let Some(address) =
                            super::local::arpa_address(&question.name.dnsmasq_bytes())
                        {
                            cache.lookup_reverse(address, now);
                        }
                    }
                    let kind = match question.rrtype {
                        1 => Some(Kind::Ipv4),
                        28 => Some(Kind::Ipv6),
                        _ => None,
                    };
                    if let Some(kind) = kind {
                        cache.lookup_with_hint(&question.name, &[kind], now, round_robin, name_lookup);
                    }
                    cache.lookup_with_hint(
                        &question.name,
                        &[Kind::Generic(question.rrtype), Kind::NxDomain],
                        now,
                        round_robin,
                        name_lookup,
                    );
                }
            }
            return Ok(CachedAnswer {
                forward_name: None,
                filtered: false,
                packet: None,
                stale,
            });
        }
        let limit = if tcp {
            65536
        } else {
            edns.opt
                .as_ref()
                .map_or(512, |opt| usize::from(opt.udp_size(edns_packet_max)))
        };
        let mut answer = Self::answer_records_filtered(
            cache,
            question,
            header,
            now,
            local,
            max_udp.min(limit),
            dnssec_requested,
            filtered_type,
            name_lookup,
        )?;
        // The selected cache writer reports overflow before EDNS is appended.
        // Its source is known here independently of the final owner response.
        if answer.packet.as_ref().is_some_and(|packet| {
            Header::parse(packet).is_ok_and(|header| header.flags & 0x0200 != 0)
        }) {
            local.record_query_event(QueryEvent::label(0, b"reply", Some(b"truncated"), 0));
        }
        if edns.opt.is_some() {
            if let Some(packet) = &mut answer.packet {
                let append_limit = if tcp {
                    65536
                } else {
                    usize::from(edns_packet_max)
                };
                // receive_query appends against the configured daemon limit,
                // after answer_request used the client's advertised limit.
                if answer.stale || answer.filtered {
                    // Add the 17-byte OPT/EDE directly. Adding an empty OPT
                    // first would retain the wrong output at the fit boundary.
                    super::tcp_service::add_ede(
                        packet,
                        edns_packet_max,
                        false,
                        if answer.filtered { 17 } else { 3 },
                        append_limit,
                    )?;
                } else {
                    super::service::append_empty_opt(packet, edns_packet_max, false, append_limit)?;
                }
            }
        }
        Ok(answer)
    }

    fn answer_records_filtered(
        cache: &mut Cache,
        question: &super::forward::Question,
        header: Header,
        now: i64,
        local: &mut LocalDnsService,
        limit: usize,
        dnssec_requested: bool,
        filtered_type: bool,
        name_lookup: Option<&super::cache::NameLookup<'_>>,
    ) -> Result<CachedAnswer, CacheError> {
        let kind = match question.rrtype { 1 => Some(Kind::Ipv4), 28 => Some(Kind::Ipv6), _ => None };
        if question.class == 1 && header.opcode() == 0 && header.flags & 0x8100 == 0x0100
            && header.questions == 1 && header.answers == 0 && header.authorities == 0
            && !dnssec_requested && !filtered_type
        {
            if let Some(id) = kind.and_then(|kind| cache.single_fresh_address_with_hint(
                &question.name, kind, now, name_lookup,
            )) {
                return Self::answer_fresh_address(cache, question, header, now, local, limit, id);
            }
        }
        Self::answer_records_general(cache, question, header, now, local, limit,
            dnssec_requested, filtered_type, name_lookup)
    }

    // Only a selected fresh hit needs this writer frame. Keep it out of the
    // shared caller so a fallback does not reserve its space as well.
    #[inline(never)]
    fn answer_fresh_address(
        cache: &Cache,
        question: &super::forward::Question,
        header: Header,
        now: i64,
        local: &mut LocalDnsService,
        limit: usize,
        id: super::cache::EntryId,
    ) -> Result<CachedAnswer, CacheError> {
        if !local.query_logging {
            if let Some(entry) = cache.get(id) {
                let data = &entry.record.data;
                let name = question.name.as_wire();
                let length = 12 + name.len() + 4 + 12 + data.len();
                // Keep the original writer for logging, overflow and any
                // buffer growth. A warm, complete address reply has only one
                // question and one fixed-owner RR, so write that layout once.
                if matches!((question.rrtype, data.len()), (1, 4) | (28, 16))
                    && length <= limit
                    && local.cached_reply_buffer.capacity() >= length.max(limit.min(128))
                {
                    let mut packet = std::mem::take(&mut local.cached_reply_buffer);
                    packet.clear();
                    packet.extend_from_slice(&header.id.to_be_bytes());
                    packet.extend_from_slice(&((header.flags & 0x0110) | 0x8080).to_be_bytes());
                    packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
                    packet.extend_from_slice(name);
                    packet.extend_from_slice(&question.rrtype.to_be_bytes());
                    packet.extend_from_slice(&question.class.to_be_bytes());
                    packet.extend_from_slice(&[0xc0, 12]);
                    packet.extend_from_slice(&question.rrtype.to_be_bytes());
                    packet.extend_from_slice(&1u16.to_be_bytes());
                    packet.extend_from_slice(&entry.reply_ttl(now, cache.policy()).to_be_bytes());
                    packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    packet.extend_from_slice(data);
                    return Ok(CachedAnswer {
                        packet: Some(packet), stale: false, filtered: false, forward_name: None,
                    });
                }
            }
        }
        let mut writer = PacketWriter::with_buffer(header.id, (header.flags & 0x0110) | 0x8080,
            limit, std::mem::take(&mut local.cached_reply_buffer))?;
        writer.question(&question.name, question.rrtype, question.class)?;
        record_cached(local, cache, id, now);
        let entry = cache.get(id).expect("selected fresh address remains live");
        let kind = if question.rrtype == 1 { Kind::Ipv4 } else { Kind::Ipv6 };
        let data = entry.positive_address(kind).expect("selected fresh address has its original bytes");
        match writer.record_at(Section::Answer, 12, question.rrtype, 1,
            entry.reply_ttl(now, cache.policy()), data)
        {
            Ok(()) | Err(WireError::Full) => Ok(finish_cached_answer(writer, false)?),
            Err(error) => Err(error.into()),
        }
    }

    // Keep the unchanged general state machine and its large frame off the
    // ordinary fresh one-address path; this remains every fallback's owner.
    #[inline(never)]
    fn answer_records_general(
        cache: &mut Cache,
        question: &super::forward::Question,
        header: Header,
        now: i64,
        local: &mut LocalDnsService,
        limit: usize,
        dnssec_requested: bool,
        filtered_type: bool,
        name_lookup: Option<&super::cache::NameLookup<'_>>,
    ) -> Result<CachedAnswer, CacheError> {
        let mut stale = false;
        let round_robin = !local.config.no_round_robin;
        if question.class != 1 {
            return Ok(CachedAnswer {
                forward_name: None,
                filtered: false,
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
        let ids = cache.lookup_with_hint(&question.name, kinds, now, round_robin, name_lookup);
        if question.rrtype == 12
            && !ids.iter().any(|id| {
                cache
                    .get(*id)
                    .is_some_and(|entry| entry.record.kind == Kind::Cname)
            })
        {
            if let Some(address) = super::local::arpa_address(&question.name.dnsmasq_bytes()) {
                let reverse = cache.lookup_reverse(address, now);
                if !reverse.is_empty() {
                    if header.flags & 0x0100 == 0 || dnssec_requested {
                        return Ok(CachedAnswer {
                            forward_name: None,
                            packet: None,
                            stale,
                            filtered: false,
                        });
                    }
                    let mut writer =
                        PacketWriter::new(header.id, (header.flags & 0x0110) | 0x8080, limit)?;
                    writer.question(&question.name, question.rrtype, question.class)?;
                    for id in reverse {
                        let entry = cache.get(id).expect("reverse lookup yields live entries");
                        stale |= entry.is_stale(now);
                        record_cached(local, cache, id, now);
                        match writer.record_at(
                            Section::Answer,
                            12,
                            12,
                            1,
                            entry.reply_ttl(now, cache.policy()),
                            entry.record.name.as_wire(),
                        ) {
                            Ok(()) => {}
                            Err(WireError::Full) => break,
                            Err(error) => return Err(error.into()),
                        }
                    }
                    return Ok(finish_cached_answer(writer, stale)?);
                }
            }
        }
        if question.rrtype == 12
            && !ids.is_empty()
            && !ids.iter().any(|id| {
                cache
                    .get(*id)
                    .is_some_and(|entry| entry.record.kind == Kind::Cname)
            })
        {
            let mut writer = PacketWriter::new(header.id, (header.flags & 0x0110) | 0x8080, limit)?;
            writer.question(&question.name, question.rrtype, question.class)?;
            if let Some(flags) =
                append_reverse_synth_terminal(&mut writer, local, &question.name, question, 12)?
            {
                // is_rev_synth replaces C's name cursor; a previous generic
                // negative's original SOA suffix does not survive that cursor.
                return Ok(finish_cached_answer_flags(writer, Some(flags), stale)?);
            }
        }
        if ids.is_empty() {
            // rfc1035.c uses an existing cached RR of any family/type to
            // answer filtered requests as NODATA, avoiding an upstream round
            // trip. DNSSEC/DO requests bypass this unauthenticated shortcut.
            if !dnssec_requested
                && question.rrtype != 255
                && filtered_type
                && !cache
                    .lookup_with_hint(
                        &question.name,
                        &[Kind::Cname, Kind::Ipv4, Kind::Ipv6, Kind::Generic(0)],
                        now,
                        round_robin,
                        name_lookup,
                    )
                    .is_empty()
            {
                let mut writer =
                    PacketWriter::new(header.id, (header.flags & 0x0110) | 0x8080, limit)?;
                writer.question(&question.name, question.rrtype, question.class)?;
                record_filter(local, &question.name, Kind::Generic(question.rrtype));
                return Ok(finish_filtered_answer(writer, false)?);
            }
            // An address/CNAME miss still reaches C's final F_RR lookup.
            // An unrelated generic record cannot answer this question, but
            // its lookup promotes it before the caller forwards the query.
            // Generic questions already visited that group above.
            if !matches!(kind, Kind::Generic(_)) {
                cache.lookup_with_hint(
                    &question.name,
                    &[Kind::Generic(question.rrtype), Kind::NxDomain],
                    now,
                    round_robin,
                    name_lookup,
                );
            }
            return Ok(CachedAnswer {
                forward_name: None,
                filtered: false,
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
            // The final filtered-name existence shortcut is independent of
            // RD, unlike ordinary recursive cache answers.
            if question.rrtype != 255
                && filtered_type
                && !dnssec_requested
                && !ids.iter().any(|id| {
                    cache
                        .get(*id)
                        .is_some_and(|entry| entry.record.kind == Kind::Cname)
                })
                && !cache
                    .lookup_with_hint(
                        &question.name,
                        &[Kind::Ipv4, Kind::Ipv6, Kind::Generic(0)],
                        now,
                        round_robin,
                        name_lookup,
                    )
                    .is_empty()
            {
                let mut writer =
                    PacketWriter::new(header.id, (header.flags & 0x0110) | 0x8080, limit)?;
                writer.question(&question.name, question.rrtype, question.class)?;
                record_filter(local, &question.name, Kind::Generic(question.rrtype));
                return Ok(finish_filtered_answer(writer, false)?);
            }
            return Ok(CachedAnswer {
                forward_name: None,
                filtered: false,
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
            let interface =
                append_interface_terminal(&mut writer, local, &question.name, question, 12)?;
            let local_flags = match interface {
                InterfaceTerminal::Answered(flags) => Some(flags),
                InterfaceTerminal::Empty => None,
                InterfaceTerminal::Unclaimed => append_synth_terminal(
                    &mut writer,
                    local,
                    &question.name,
                    question,
                    12,
                    ids.iter().any(|id| {
                        cache
                            .get(*id)
                            .is_some_and(|entry| entry.record.kind == Kind::Ipv4)
                    }),
                    ids.iter().any(|id| {
                        cache
                            .get(*id)
                            .is_some_and(|entry| entry.record.kind == Kind::Ipv6)
                    }),
                )?,
            };
            if local_flags.is_none() {
                record_cached(local, cache, id, now);
            }
            match append_negative_authority(&mut writer, cache, id, now) {
                Ok(_) | Err(WireError::Full) => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(finish_cached_answer_flags(writer, local_flags, stale)?);
        }
        if question.rrtype == 5 {
            if header.flags & 0x0100 == 0 {
                return Ok(CachedAnswer {
                    forward_name: None,
                    filtered: false,
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
                if cache.get(id).is_some_and(|entry| {
                    entry.record.kind == Kind::Cname && entry.cname_target().is_some()
                }) {
                    record_cached(local, cache, id, now);
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
                forward_name: None,
                filtered: false,
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
            record_cached(local, cache, id, now);
            stale |= cache.get(id).is_some_and(|entry| entry.is_stale(now));
            let mut writer = PacketWriter::new(header.id, (header.flags & 0x0110) | 0x8080, limit)?;
            writer.question(&question.name, question.rrtype, question.class)?;
            match append_negative_authority(&mut writer, cache, id, now) {
                Ok(_) | Err(WireError::Full) => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(finish_cached_answer(writer, stale)?);
        }

        let mut writer = PacketWriter::new(header.id, (header.flags & 0x0110) | 0x8080, limit)?;
        writer.question(&question.name, question.rrtype, question.class)?;
        let mut written = false;
        let mut forward_name = None;
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
                        if cache
                            .get(current)
                            .is_some_and(|entry| entry.cname_target().is_some())
                        {
                            record_cached(local, cache, current, now);
                        }
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
                                forward_name = Some(target.name.clone());
                                let Some(flags) = append_local_terminal(
                                    &mut writer,
                                    local,
                                    &target.name,
                                    question,
                                    header,
                                    now,
                                    owner_offset,
                                    cache,
                                    None,
                                )?
                                else {
                                    return Ok(CachedAnswer {
                                        forward_name,
                                        filtered: false,
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
                        forward_name = Some(target_entry.record.name.clone());
                        if target_entry.record.kind == Kind::Cname {
                            current = target;
                            continue;
                        }
                        // The link validates the CNAME lifetime, but C looks
                        // up the terminal name again for the current qtype.
                        let terminal_name = target_entry.record.name.clone();
                        let nx_target = (target_entry.record.kind == Kind::NxDomain
                            && target_entry.record.negative)
                            .then_some(target);
                        stale |= nx_target.is_some_and(|id| {
                            // C re-looks up the terminal name before observing
                            // NXDOMAIN staleness. A retained CNAME handle can
                            // still point at a negative entry whose finite
                            // retention just ended; that entry contributes no
                            // stale bit. Keep the later lookup's pruning/LRU
                            // effects in their existing order.
                            cache.is_valid(id, now)
                                && cache.get(id).is_some_and(|entry| entry.is_stale(now))
                        });
                        if question.rrtype == 12 {
                            if let Some(address) =
                                super::local::arpa_address(&terminal_name.dnsmasq_bytes())
                            {
                                let reverse = cache.lookup_reverse(address, now);
                                if !reverse.is_empty() {
                                    for id in reverse {
                                        let entry = cache.get(id).expect("live reverse entry");
                                        stale |= entry.is_stale(now);
                                        record_cached(local, cache, id, now);
                                        match writer.record_at(
                                            Section::Answer,
                                            owner_offset,
                                            12,
                                            1,
                                            entry.reply_ttl(now, cache.policy()),
                                            entry.record.name.as_wire(),
                                        ) {
                                            Ok(()) => {}
                                            Err(WireError::Full) => break,
                                            Err(error) => return Err(error.into()),
                                        }
                                    }
                                    return Ok(finish_cached_answer(writer, stale)?);
                                }
                            }
                            if let Some(flags) = append_reverse_synth_terminal(
                                &mut writer,
                                local,
                                &terminal_name,
                                question,
                                owner_offset,
                            )? {
                                return Ok(finish_cached_answer_flags(writer, Some(flags), stale)?);
                            }
                        }
                        // Keep reverse address/synthesis above: is_rev_synth
                        // changes C's name cursor and discards the old zone's
                        // negative SOA. It is not an ordinary local RR footer.
                        // rfc1035.c follows CNAMEs before the configured RR
                        // loops, regardless of the cache entry which keeps
                        // the alias alive. A dynamic A target can therefore
                        // terminate at a configured TXT, MX or SRV answer.
                        if let Some(flags) = append_local_terminal(
                            &mut writer,
                            local,
                            &terminal_name,
                            question,
                            header,
                            now,
                            owner_offset,
                            cache,
                            nx_target,
                        )? {
                            return Ok(finish_cached_answer_flags(writer, Some(flags), stale)?);
                        }
                        if local.config.filter_win2k && question.rrtype == 6 {
                            record_windows_filter(local, &terminal_name);
                            return Ok(finish_cached_answer_flags(writer, Some(0x8480), stale)?);
                        }
                        match append_interface_terminal(
                            &mut writer,
                            local,
                            &terminal_name,
                            question,
                            owner_offset,
                        )? {
                            InterfaceTerminal::Answered(flags) => {
                                if let Some(id) = nx_target {
                                    match append_negative_authority(&mut writer, cache, id, now) {
                                        Ok(_) | Err(WireError::Full) => {}
                                        Err(error) => return Err(error.into()),
                                    }
                                }
                                return Ok(finish_cached_answer_flags(writer, Some(flags), stale)?);
                            }
                            InterfaceTerminal::Empty if nx_target.is_none() => {
                                // A declared interface with no eligible address
                                // bypasses the ordinary cached terminal and
                                // lets the forwarder retry against upstream.
                                return Ok(CachedAnswer {
                                    forward_name,
                                    packet: None,
                                    stale,
                                    filtered: false,
                                });
                            }
                            InterfaceTerminal::Empty | InterfaceTerminal::Unclaimed => {}
                        }
                        let terminal_ids =
                            cache.lookup_question(&terminal_name, kind, now, round_robin);
                        let selected = terminal_ids.iter().copied().find(|id| {
                            cache.get(*id).is_some_and(|entry| {
                                entry.record.kind == kind || entry.record.kind == Kind::NxDomain
                            })
                        });
                        let Some(target) = selected else {
                            if local.config.filter_win2k
                                && super::local::filter_win2k_question(
                                    &terminal_name,
                                    question.rrtype,
                                )
                            {
                                record_windows_filter(local, &terminal_name);
                                return Ok(finish_cached_answer_flags(
                                    writer,
                                    Some(0x8480),
                                    stale,
                                )?);
                            }
                            if question.rrtype != 255
                                && filtered_type
                                && !dnssec_requested
                            {
                                record_filter(local, &terminal_name, kind);
                                return Ok(finish_filtered_answer(writer, stale)?);
                            }
                            return Ok(CachedAnswer {
                                forward_name,
                                packet: None,
                                stale,
                                filtered: false,
                            });
                        };
                        let Some(target_entry) = cache.get(target) else {
                            break;
                        };
                        if target_entry.record.negative {
                            if target_entry.record.kind == Kind::NxDomain
                                && !local.interfaces.declared(&terminal_name.dnsmasq_bytes())
                            {
                                if let Some(flags) = append_synth_terminal(
                                    &mut writer,
                                    local,
                                    &terminal_name,
                                    question,
                                    owner_offset,
                                    terminal_ids.iter().any(|id| {
                                        cache
                                            .get(*id)
                                            .is_some_and(|entry| entry.record.kind == Kind::Ipv4)
                                    }),
                                    terminal_ids.iter().any(|id| {
                                        cache
                                            .get(*id)
                                            .is_some_and(|entry| entry.record.kind == Kind::Ipv6)
                                    }),
                                )? {
                                    match append_negative_authority(&mut writer, cache, target, now)
                                    {
                                        Ok(_) | Err(WireError::Full) => {}
                                        Err(error) => return Err(error.into()),
                                    }
                                    return Ok(finish_cached_answer_flags(
                                        writer,
                                        Some(flags),
                                        stale,
                                    )?);
                                }
                            }
                            record_cached(local, cache, target, now);
                            let negative_flags = if target_entry.record.kind == Kind::NxDomain {
                                0x8083
                            } else {
                                0x8080
                            };
                            stale |= cache.get(target).is_some_and(|entry| entry.is_stale(now));
                            match append_negative_authority(&mut writer, cache, target, now) {
                                Ok(_) => {}
                                Err(WireError::Full) => {
                                    return Ok(finish_cached_answer(writer, stale)?);
                                }
                                Err(error) => return Err(error.into()),
                            }
                            return Ok(finish_cached_answer_flags(
                                writer,
                                Some(negative_flags),
                                stale,
                            )?);
                        } else {
                            if question.rrtype != 255 && filtered_type {
                                record_filter(local, &terminal_name, kind);
                                let mut answer = finish_cached_answer(writer, stale)?;
                                answer.filtered = matches!(kind, Kind::Ipv4 | Kind::Ipv6);
                                return Ok(answer);
                            }
                            let terminal_kind = target_entry.record.kind;
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
                                record_cached(local, cache, terminal_id, now);
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
                            forward_name,
                            filtered: false,
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
            if question.rrtype != 255 && filtered_type {
                record_filter(local, &question.name, kind);
                let mut answer = finish_cached_answer(writer, stale)?;
                // C marks address filtering for EDE. The generic F_RR path
                // suppresses the RR without setting answer_request's flag.
                answer.filtered = matches!(kind, Kind::Ipv4 | Kind::Ipv6);
                return Ok(answer);
            }
            record_cached(local, cache, id, now);
            match append_positive_record(&mut writer, cache, id, Section::Answer, now, Some(12)) {
                Ok(true) => written = true,
                Ok(false) => {}
                Err(WireError::Full) => return Ok(finish_cached_answer(writer, stale)?),
                Err(error) => return Err(error.into()),
            }
        }
        if written {
            return Ok(finish_cached_answer(writer, stale)?);
        }
        // F_RR lookup returns every generic type. An unrelated generic RR
        // still proves the name exists for C's final filtered-NODATA shortcut.
        if question.rrtype != 255
            && filtered_type
            && !dnssec_requested
            && !cache
                .lookup_with_hint(
                    &question.name,
                    &[Kind::Cname, Kind::Ipv4, Kind::Ipv6, Kind::Generic(0)],
                    now,
                    round_robin,
                    name_lookup,
                )
                .is_empty()
        {
            record_filter(local, &question.name, Kind::Generic(question.rrtype));
            return Ok(finish_filtered_answer(writer, stale)?);
        }
        Ok(CachedAnswer {
                forward_name,            filtered: false,
            packet: None,
            stale,
        })
    }

    /// check_for_bogus_wildcard commits independently of ordinary extraction.
    /// TCP preserves this event before rewriting its reply to an empty NXDOMAIN.
    pub fn insert_bogus(&mut self, name: Name, ttl: u32, now: i64, local: &LocalDnsService) {
        self.stage_bogus(name, ttl, now, local);
        let _ = self.cache.commit_counted(self.counters);
    }

    pub fn insert_bogus_for_transfer(
        &mut self,
        name: Name,
        ttl: u32,
        now: i64,
        local: &LocalDnsService,
    ) -> Option<super::cache::CacheTransaction> {
        self.stage_bogus(name, ttl, now, local);
        self.cache.capture_commit_counted(self.counters)
    }

    fn stage_bogus(&mut self, name: Name, ttl: u32, now: i64, local: &LocalDnsService) {
        self.cache.start_insert();
        insert_cache_record(
            self.cache,
            self.counters,
            local,
            Record {
                name,
                kind: Kind::NxDomain,
                negative: true,
                data: Vec::new(),
            },
            now,
            u64::from(ttl),
        );
    }

    pub fn import_transfer(
        &mut self,
        transaction: super::cache::CacheTransaction,
        now: i64,
        local: &LocalDnsService,
    ) -> bool {
        self.cache
            .import_counted(transaction, now, self.counters, |record| {
                local_cache_match(record, local)
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
        self.insert_reply_transaction(
            packet,
            now,
            local,
            policy,
            original_rcode,
            ordinary,
            false,
            None,
        )
        .map(|_| ())
    }

    /// Preserve the child extraction policy and return the exact commit order.
    /// Parent import applies current local conflicts without reprocessing wire
    /// bytes under a newer HUP/doctor/filter configuration.
    pub fn insert_reply_for_transfer(
        &mut self,
        packet: &[u8],
        now: i64,
        local: &LocalDnsService,
        policy: &super::process::AddressPolicy,
        original_rcode: u16,
        ordinary: OrdinaryCacheMode,
    ) -> Result<Option<super::cache::CacheTransaction>, WireError> {
        self.insert_reply_transaction(
            packet,
            now,
            local,
            policy,
            original_rcode,
            ordinary,
            true,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_reply_with_events(
        &mut self,
        packet: &[u8],
        now: i64,
        local: &LocalDnsService,
        policy: &super::process::AddressPolicy,
        original_rcode: u16,
        ordinary: OrdinaryCacheMode,
        capture: bool,
        events: &mut Vec<QueryEvent>,
    ) -> Result<Option<super::cache::CacheTransaction>, WireError> {
        self.insert_reply_transaction(
            packet,
            now,
            local,
            policy,
            original_rcode,
            ordinary,
            capture,
            Some(events),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_reply_transaction(
        &mut self,
        packet: &[u8],
        now: i64,
        local: &LocalDnsService,
        policy: &super::process::AddressPolicy,
        original_rcode: u16,
        ordinary: OrdinaryCacheMode,
        capture: bool,
        mut notices: Option<&mut Vec<QueryEvent>>,
    ) -> Result<Option<super::cache::CacheTransaction>, WireError> {
        macro_rules! query_notice {
            ($event:expr) => {
                if local.query_logging {
                    if let Some(events) = notices.as_deref_mut() {
                        events.push($event);
                    }
                }
            };
        }
        let Ok(header) = Header::parse(packet) else {
            return Ok(None);
        };
        if header.opcode() != 0 || !matches!(original_rcode, 0 | 3) || header.flags & 0x0200 != 0 {
            return Ok(None);
        }
        if original_rcode != 3 {
            if let Some((name, ttl)) =
                super::process::bogus_cache_entry(packet, header.answers, policy)
            {
                query_notice!(QueryEvent::label(
                    qlog::CONFIG | qlog::NEGATIVE | qlog::NXDOMAIN,
                    &name.dnsmasq_bytes(),
                    None,
                    0
                ));
                // This independent branch uses the matching RR's owner/TTL;
                // --no-negcache, RA and CD do not suppress its commit in C.
                if capture {
                    return Ok(self.insert_bogus_for_transfer(name, ttl, now, local));
                }
                self.insert_bogus(name, ttl, now, local);
                return Ok(None);
            }
        }
        let cache = &mut *self.cache;
        let counters = &mut *self.counters;
        // Unsupported query metadata stays outside ordinary extraction.
        // CD/no_cache instead run its ordered effects and gate only commit.
        if ordinary == OrdinaryCacheMode::Unsupported {
            return Ok(None);
        }
        cache.start_insert();
        if header.questions != 1 {
            return Ok(None);
        }
        let Ok(question) = WireQuestion::parse(packet, super::wire::HEADER_LEN) else {
            return Ok(None);
        };
        if question.class != 1 {
            return Ok(None);
        }
        if question.qtype == 12 && header.rcode() != 3 {
            if let Some(address) = super::local::arpa_address(&question.name.dnsmasq_bytes()) {
                let (kind, data) = match address {
                    IpAddr::V4(value) => (Kind::ReverseIpv4, value.octets().to_vec()),
                    IpAddr::V6(value) => (Kind::ReverseIpv6, value.octets().to_vec()),
                };
                let mut found = false;
                let mut position = question.end;
                for _ in 0..header.answers {
                    let rr = super::wire::RecordRef::parse(packet, position)?;
                    position = rr.end;
                    if rr.class != 1
                        || rr.rrtype != 12
                        || !rr.name()?.eq_ignore_ascii_case(&question.name)
                    {
                        continue;
                    }
                    found = true;
                    // Reverse PTR extraction checks the packet boundary, not
                    // RDLEN, when decoding the target name.
                    let (target, _) = super::wire::decode_name(packet, rr.fixed + 10, 0)?;
                    query_notice!(QueryEvent::address(
                        qlog::REPLY | qlog::REVERSE,
                        &target.dnsmasq_bytes(),
                        address,
                        None
                    ));
                    let ttl = if cache.policy().max_reply_ttl == 0 {
                        u64::from(rr.ttl)
                    } else {
                        u64::from(rr.ttl).min(cache.policy().max_reply_ttl)
                    };
                    let _ = cache.insert_ttl_counted(
                        Record {
                            name: target,
                            kind,
                            negative: false,
                            data: data.clone(),
                        },
                        now,
                        ttl,
                        counters,
                    );
                }
                if found {
                    if ordinary == OrdinaryCacheMode::Commit && header.flags & 0x0090 == 0x0080 {
                        if capture {
                            return Ok(cache.capture_commit_counted(counters));
                        }
                        cache.commit_counted(counters);
                    }
                    return Ok(None);
                }
                // CNAME and missing-PTR replies fall through to the ordinary
                // Generic(12)/negative path; that path may link CNAME targets.
            }
        }
        let Ok(edns) = find_pseudoheader(packet, false) else {
            return Ok(None);
        };
        if edns
            .opt
            .as_ref()
            .is_some_and(|opt| opt.extended_rcode() != 0)
        {
            return Ok(None);
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
                    return Ok(None);
                };
                position = rr.end;
                let Ok(owner) = rr.name() else {
                    return Ok(None);
                };
                if rr.class != 1 || !owner.eq_ignore_ascii_case(&current) {
                    continue;
                }
                let ttl = if max_reply_ttl == 0 {
                    u64::from(rr.ttl)
                } else {
                    u64::from(rr.ttl).min(max_reply_ttl)
                };
                if rr.rrtype == 5 {
                    if cname_left == 0 {
                        return Ok(None);
                    }
                    cname_left -= 1;
                    query_notice!(QueryEvent::label(
                        qlog::REPLY | qlog::CNAME,
                        &current.dnsmasq_bytes(),
                        None,
                        0
                    ));
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
                        return Ok(None);
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
                    let log_flags = qlog::REPLY
                        | if self.filter_rr.contains(&question.qtype) {
                            qlog::CONFIG | qlog::NEGATIVE
                        } else {
                            0
                        };
                    if !matches!(kind, Kind::Ipv4 | Kind::Ipv6) {
                        if question.qtype == 16 && local.query_logging {
                            if let Some(events) = notices.as_deref_mut() {
                                qlog::txt_events(
                                    log_flags,
                                    &current.dnsmasq_bytes(),
                                    rr.rdata,
                                    events,
                                );
                            }
                        } else {
                            query_notice!(QueryEvent::label(
                                log_flags | qlog::RRNAME,
                                &current.dnsmasq_bytes(),
                                None,
                                question.qtype
                            ));
                        }
                    }
                    // Address replies are extracted/logged even when cache
                    // commit is disabled. Generic RDATA needs no fake decode.
                    if !insert && !matches!(kind, Kind::Ipv4 | Kind::Ipv6) {
                        continue;
                    }
                    let data = if matches!(kind, Kind::Ipv4 | Kind::Ipv6) {
                        let width = if question.qtype == 1 { 4 } else { 16 };
                        let Some(data) = packet.get(rr.fixed + 10..rr.fixed + 10 + width) else {
                            return Ok(None);
                        };
                        let address = if question.qtype == 1 {
                            IpAddr::V4(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(data).unwrap()))
                        } else {
                            IpAddr::V6(std::net::Ipv6Addr::from(
                                <[u8; 16]>::try_from(data).unwrap(),
                            ))
                        };
                        if policy.rejects_rebind(&question.name, address) {
                            if let Some(events) = notices.as_deref_mut() {
                                let mut message = b"possible DNS-rebind attack detected: ".to_vec();
                                message.extend_from_slice(&current.dnsmasq_bytes());
                                events.push(QueryEvent::warning(message));
                            }
                            return Ok(None);
                        }
                        query_notice!(QueryEvent::address(
                            log_flags,
                            &current.dnsmasq_bytes(),
                            address,
                            None
                        ));
                        data.to_vec()
                    } else {
                        match rr.canonical_rdata() {
                            Ok(data) => data,
                            // Compression expansion can exceed the cache's
                            // representable RDATA length without making the
                            // original wire reply invalid. Keep forwarding it.
                            Err(WireError::RecordTooLong) => return Ok(None),
                            Err(error) => return Err(error),
                        }
                    };
                    if !insert {
                        continue;
                    }
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
        if !found && question.qtype != 255 {
            let family = match question.qtype {
                1 => qlog::IPV4,
                28 => qlog::IPV6,
                _ => 0,
            };
            query_notice!(QueryEvent::label(
                qlog::REPLY
                    | qlog::NEGATIVE
                    | family
                    | if header.rcode() == 3 {
                        qlog::NXDOMAIN
                    } else {
                        0
                    },
                &current.dnsmasq_bytes(),
                None,
                0
            ));
        }
        if !found
            && self.negative_cache
            && ((insert && question.qtype != 255) || header.rcode() == 3)
        {
            let soa = authority_soa(packet, answer_end, header.authorities, &current);
            // find_soa lets cache_insert apply min-cache-ttl before rejecting
            // raw TTL0. Treating TTL0 as an absent SOA here loses that case.
            let mut soa_ttl = soa
                .as_ref()
                .map(|(_, ttl, minimum, _)| u64::from((*ttl).min(*minimum)));
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
            if capture {
                return Ok(cache.capture_commit_counted(counters));
            }
            let _ = cache.commit_counted(counters);
        }
        Ok(None)
    }
}

fn record_windows_filter(local: &mut LocalDnsService, name: &Name) {
    if local.query_logging {
        local.record_query_event(QueryEvent::label(
            qlog::CONFIG | qlog::NEGATIVE,
            &name.dnsmasq_bytes(),
            None,
            0,
        ));
    }
}

fn record_filter(local: &mut LocalDnsService, name: &Name, kind: Kind) {
    if !local.query_logging {
        return;
    }
    let family = match kind {
        Kind::Ipv4 => qlog::IPV4,
        Kind::Ipv6 => qlog::IPV6,
        _ => 0,
    };
    local.record_query_event(QueryEvent::label(
        qlog::CONFIG | qlog::NEGATIVE | family,
        &name.dnsmasq_bytes(),
        None,
        0,
    ));
}

fn record_cached(local: &mut LocalDnsService, cache: &Cache, id: super::cache::EntryId, now: i64) {
    if !local.query_logging {
        return;
    }
    let Some(entry) = cache.get(id) else {
        return;
    };
    let record = &entry.record;
    if record.kind == Kind::Generic(16) && !record.negative {
        let mut events = Vec::new();
        qlog::txt_events(
            if entry.is_stale(now) { qlog::STALE } else { 0 },
            &record.name.dnsmasq_bytes(),
            &record.data,
            &mut events,
        );
        for event in events {
            local.record_query_event(event);
        }
        return;
    }
    let mut flags = if entry.is_stale(now) { qlog::STALE } else { 0 };
    flags |= match record.kind {
        Kind::Ipv4 | Kind::ReverseIpv4 => qlog::IPV4,
        Kind::Ipv6 | Kind::ReverseIpv6 => qlog::IPV6,
        Kind::Cname => qlog::CNAME,
        Kind::NxDomain => qlog::NXDOMAIN,
        Kind::Generic(_) => qlog::RR,
    };
    if record.negative {
        flags |= qlog::NEGATIVE;
    }
    if matches!(record.kind, Kind::ReverseIpv4 | Kind::ReverseIpv6) {
        flags |= qlog::REVERSE;
    }
    let data = match record.kind {
        Kind::Ipv4 | Kind::ReverseIpv4 if record.data.len() == 4 => QueryData::Address(IpAddr::V4(
            <[u8; 4]>::try_from(record.data.as_slice()).unwrap().into(),
        )),
        Kind::Ipv6 | Kind::ReverseIpv6 if record.data.len() == 16 => QueryData::Address(
            IpAddr::V6(<[u8; 16]>::try_from(record.data.as_slice()).unwrap().into()),
        ),
        Kind::Generic(kind) => QueryData::RrType(kind),
        _ => QueryData::None,
    };
    local.record_query_event(QueryEvent {
        flags,
        name: Some(record.name.dnsmasq_bytes()),
        data,
        argument: None,
        kind: 0,
    });
}

/// `answer_request` clears all response sections when any cached RR cannot
/// fit, while the reusable PacketWriter intentionally retains complete RRs.
fn finish_filtered_answer(writer: PacketWriter, stale: bool) -> Result<CachedAnswer, WireError> {
    let mut answer = finish_cached_answer(writer, stale)?;
    answer.filtered = true;
    Ok(answer)
}

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
        forward_name: None,
        filtered: false,
        packet: Some(packet),
        stale,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InterfaceTerminal {
    Unclaimed,
    Empty,
    Answered(u16),
}

/// Apply a dynamic interface-name terminal to a cached CNAME chain. `None`
/// means the terminal is not declared; `Some(empty)` is an explicit
/// declaration with no eligible address and must bypass the cached terminal.
fn append_interface_terminal(
    writer: &mut PacketWriter,
    local: &mut LocalDnsService,
    terminal: &Name,
    question: &super::forward::Question,
    owner_offset: u16,
) -> Result<InterfaceTerminal, CacheError> {
    let families: &[bool] = match question.rrtype {
        1 => &[false],
        28 => &[true],
        255 => &[false, true],
        _ => return Ok(InterfaceTerminal::Unclaimed),
    };
    let mut declared = false;
    let mut written = false;
    for &ipv6 in families {
        let Some(addresses) =
            local
                .interfaces
                .forward(&terminal.dnsmasq_bytes(), ipv6, local.local_network)
        else {
            continue;
        };
        declared = true;
        if addresses.is_empty() {
            record_filter(local, terminal, if ipv6 { Kind::Ipv6 } else { Kind::Ipv4 });
        }
        for address in addresses {
            let (rrtype, data) = match address {
                IpAddr::V4(value) if !ipv6 => (1, value.octets().to_vec()),
                IpAddr::V6(value) if ipv6 => (28, value.octets().to_vec()),
                _ => continue,
            };
            if local.query_logging {
                local.record_query_event(QueryEvent::address(
                    qlog::CONFIG,
                    &terminal.dnsmasq_bytes(),
                    address,
                    None,
                ));
            }
            match writer.record_at(
                Section::Answer,
                owner_offset,
                rrtype,
                1,
                local.local_ttl,
                &data,
            ) {
                Ok(()) => written = true,
                Err(WireError::Full) => return Ok(InterfaceTerminal::Answered(0x0400 | 0x0200)),
                Err(error) => return Err(error.into()),
            }
        }
    }
    if written {
        Ok(InterfaceTerminal::Answered(0x0400))
    } else if declared {
        Ok(InterfaceTerminal::Empty)
    } else {
        Ok(InterfaceTerminal::Unclaimed)
    }
}

/// NXDOMAIN is a generic cache marker in this image: it has no address
/// family flags. Local synthesis therefore runs before that final NX tier.
#[allow(clippy::too_many_arguments)]
fn append_synth_terminal(
    writer: &mut PacketWriter,
    local: &mut LocalDnsService,
    terminal: &Name,
    question: &super::forward::Question,
    owner_offset: u16,
    blocked4: bool,
    blocked6: bool,
) -> Result<Option<u16>, CacheError> {
    let families: &[bool] = match question.rrtype {
        1 => &[false],
        28 => &[true],
        255 => &[false, true],
        _ => return Ok(None),
    };
    let mut answered = false;
    for &ipv6 in families {
        if if ipv6 { blocked6 } else { blocked4 } {
            continue;
        }
        let Some(address) = local
            .config
            .synth_domains
            .forward(&terminal.dnsmasq_bytes(), ipv6)
        else {
            continue;
        };
        let (rrtype, data) = match address {
            IpAddr::V4(value) => (1, value.octets().to_vec()),
            IpAddr::V6(value) => (28, value.octets().to_vec()),
        };
        if local.query_logging {
            local.record_query_event(QueryEvent::address(
                qlog::CONFIG,
                &terminal.dnsmasq_bytes(),
                address,
                None,
            ));
        }
        match writer.record_at(
            Section::Answer,
            owner_offset,
            rrtype,
            1,
            local.local_ttl,
            &data,
        ) {
            Ok(()) => answered = true,
            Err(WireError::Full) => return Ok(Some(0x0400 | 0x0200)),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(answered.then_some(0x0400))
}

/// PTR address/synthetic lookup precedes the forward generic PTR/NX tier.
/// C's synthetic reverse path replaces its name cursor, so an earlier generic
/// negative does not attach its original reverse-zone SOA to this answer.
fn append_reverse_synth_terminal(
    writer: &mut PacketWriter,
    local: &mut LocalDnsService,
    terminal: &Name,
    question: &super::forward::Question,
    owner_offset: u16,
) -> Result<Option<u16>, CacheError> {
    if question.rrtype != 12 {
        return Ok(None);
    }
    let Some(address) = super::local::arpa_address(&terminal.dnsmasq_bytes()) else {
        return Ok(None);
    };
    let Some(target) = local.config.synth_domains.reverse(address) else {
        return Ok(None);
    };
    if local.query_logging {
        local.record_query_event(QueryEvent::address(
            qlog::CONFIG | qlog::REVERSE,
            &target,
            address,
            None,
        ));
    }
    let target = Name::from_dotted_bytes(&target)?;
    match writer.record_at(
        Section::Answer,
        owner_offset,
        12,
        1,
        local.local_ttl,
        target.as_wire(),
    ) {
        Ok(()) => Ok(Some(0x0400)),
        Err(WireError::Full) => Ok(Some(0x0400 | 0x0200)),
        Err(error) => Err(error.into()),
    }
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
    cache: &mut Cache,
    negative: Option<super::cache::EntryId>,
) -> Result<Option<u16>, CacheError> {
    let mut query = PacketWriter::new(header.id, header.flags, u16::MAX as usize)?;
    query.question(target, question.rrtype, question.class)?;
    let mut answerer = super::local::LocalAnswerer {
        config: &local.config,
        hosts: &mut local.hosts,
        local_ttl: local.local_ttl,
        max_packet: u16::MAX as usize,
    };
    let Some(answer) = answerer.answer_with_query_events(
        &query.finish(),
        &mut local.leases,
        now,
        local.local_network,
        Some(cache),
        &local.interfaces,
        local.query_logging,
    )?
    else {
        return Ok(None);
    };
    if answer.forward_rule {
        return Ok(None);
    }
    for event in answer.query_events {
        local.record_query_event(event);
    }
    let message = Message::parse(&answer.packet)?;
    // Scratch byte ranges already copied verbatim, as (start, end, final start).
    // Owner pointers are translated through these so the reply keeps the
    // scratch layout: the terminal question maps to the cached CNAME target,
    // configured CNAME targets to their copied RDATA. Raw RRs never move
    // C's name cursor (rfc1035.c passes NULL), and neither does this.
    let mut spans: Vec<(usize, usize, usize)> = Vec::new();
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        if matches!(section, Section::Authority) && message.header.authorities == 0 {
            if let Some(id) = negative {
                match append_negative_authority(writer, cache, id, now) {
                    Ok(_) | Err(WireError::Full) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        for record in message.records(section) {
            let owner = record.name()?;
            // The local answerer writes configured names uncompressed and
            // dns-rr bytes opaque, as rfc1035.c's raw loop does. Copy RDATA
            // verbatim: decoding a raw pointer against this scratch packet
            // would rewrite or reject bytes C emits unchanged.
            let data = record.rdata;
            let pointer = owner_pointer(&answer.packet, record.start).and_then(|scratch| {
                if scratch == 12 {
                    return Some(owner_offset);
                }
                spans
                    .iter()
                    .find(|(start, end, _)| (*start..*end).contains(&scratch))
                    .and_then(|(start, _, copied)| u16::try_from(copied + scratch - start).ok())
            })
            // A pointer holds 14 bits; a later name falls back to full form.
            .filter(|offset| *offset < 0x4000);
            let start = writer.position();
            // record_at validates before appending, so an unusable pointer
            // falls back to the full owner instead of dropping the answer.
            let mut pointer = pointer;
            let result = match pointer.map(|offset| {
                writer.record_at(section, offset, record.rrtype, record.class, record.ttl, data)
            }) {
                Some(Err(WireError::InvalidName)) | None => {
                    pointer = None;
                    writer.record(section, &owner, record.rrtype, record.class, record.ttl, data)
                }
                Some(result) => result,
            };
            match result {
                Ok(()) => {}
                Err(WireError::Full) => return Ok(Some(message.header.flags | 0x0200)),
                Err(error) => return Err(error.into()),
            }
            let owner_len = if pointer.is_some() { 2 } else { owner.as_wire().len() };
            if pointer.is_none() && owner_pointer(&answer.packet, record.start).is_none() {
                spans.push((record.start, record.fixed, start));
            }
            spans.push((record.fixed + 10, record.end, start + owner_len + 10));
        }
    }
    // A filterwin2k terminal has no local RR of its own, but the retained
    // CNAME prefix keeps answer_request's initial authoritative bit.
    let flags = if message.header.answers == 0 && local.config.filter_win2k {
        message.header.flags | 0x0400
    } else {
        message.header.flags
    };
    Ok(Some(flags))
}

/// Offset named by an RR owner that is a single compression pointer.
fn owner_pointer(packet: &[u8], start: usize) -> Option<usize> {
    match packet.get(start..start + 2) {
        Some(&[high, low]) if high & 0xc0 == 0xc0 => {
            Some(usize::from(u16::from_be_bytes([high & 0x3f, low])))
        }
        _ => None,
    }
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
        u64::from(*ttl),
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
    ttl: u64,
) -> Option<CacheInsert> {
    if let Some(existing) = local_cache_match(&record, local) {
        cache
            .insert_against_local(ttl, existing.same_address)
            .ok()?;
        Some(CacheInsert::Local(record.name, existing.from_lease))
    } else {
        cache
            .insert_ttl_counted(record, now, ttl, counters)
            .ok()
            .map(CacheInsert::Dynamic)
    }
}

fn local_cache_match(
    record: &Record,
    local: &LocalDnsService,
) -> Option<super::cache::LocalCacheMatch> {
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
    existing.map(|(same_address, from_lease)| super::cache::LocalCacheMatch {
        same_address,
        from_lease,
    })
}

fn is_name_suffix(name: &Name, suffix: &Name) -> bool {
    // find_soa compares the decoded name's byte suffix, including a suffix
    // beginning inside a label. Preserve that observable image behavior.
    let name = name.dnsmasq_bytes();
    let suffix = suffix.dnsmasq_bytes();
    name.len() >= suffix.len() && name[name.len() - suffix.len()..] == suffix
}

#[cfg(test)]
mod tests {

    #[test]
    fn fresh_address_reply_matches_general_flags_ttl_limits_and_logging() {
        let binary = super::super::wire::decode_name(&[3, 0xff, 0, b'A', 0], 0, 0).unwrap().0;
        let longest = ["A".repeat(63), "b".repeat(63), "C".repeat(63), "d".repeat(61)].join(".");
        for name in [Name::root(), Name::from_ascii("HiT.test").unwrap(), binary,
                     Name::from_ascii(&longest).unwrap()] {
        for logging in [false, true] {
        for capacity in [0, 64, 128, 512] {
        for rrtype in [1,28] {
            for now in [100,159,160] {
                for flags in [0,0x0100,0x0110] {
                    for dnssec in [false,true] {
                        for filtered in [false,true] {
                            for limit in [12,25,26,41,42,53,54,512] {
                                let name = name.clone();
                                let kind = if rrtype==1 { Kind::Ipv4 } else { Kind::Ipv6 };
                                let question = super::super::forward::Question { name, rrtype, class: 1 };
                                let header = Header { id: 7, flags, questions: 1, ..Header::default() };
                                let make = || {
                                    let capacity = if question.name.dnsmasq_bytes_len() >= 75 { 16 } else { 4 };
                                    let mut cache = Cache::new(capacity,Default::default());
                                    cache.start_insert();
                                    cache.insert(Record { name: super::super::wire::decode_name(&question.name.canonical_wire(), 0, 0).unwrap().0,
                                        kind, negative: false, data: if rrtype==1 { vec![192,0,2,7] } else { vec![7;16] } },100,60).unwrap();
                                    assert!(cache.commit());
                                    cache
                                };
                                let mut reference = make(); let mut candidate = make();
                                let (_, left_hint) = reference.inspect_name(&question.name,now);
                                let (_, right_hint) = candidate.inspect_name(&question.name,now);
                                let mut left = LocalDnsService::new(DnsConfig::default(),Hosts::new(),60,1232);
                                let mut right = LocalDnsService::new(DnsConfig::default(),Hosts::new(),60,1232);
                                left.query_logging=logging;right.query_logging=logging;
                                // Previous packet contents must not survive a
                                // reused writer, including error/TC boundaries.
                                right.recycle_cached_reply(vec![0xff; capacity]);
                                let a = CacheContext::answer_records_general(&mut reference,&question,header,now,
                                    &mut left,limit,dnssec,filtered,left_hint.as_ref());
                                let b = CacheContext::answer_records_filtered(&mut candidate,&question,header,now,
                                    &mut right,limit,dnssec,filtered,right_hint.as_ref());
                                match (a,b) {
                                    (Ok(a),Ok(b)) => assert_eq!((a.packet,a.stale,a.filtered,a.forward_name),
                                                               (b.packet,b.stale,b.filtered,b.forward_name)),
                                    (Err(a),Err(b)) => assert_eq!(format!("{a:?}"),format!("{b:?}")),
                                    _ => panic!("fresh/general success boundary differs"),
                                }
                                assert_eq!(format!("{:?}",left.take_query_events()), format!("{:?}",right.take_query_events()));
                            }
                        }
                    }
                }
            }
        }
        }
        }
        }
    }
    use super::*;
    use crate::config::dns::DnsConfig;
    use crate::config::interface_records::InterfaceRule;
    use crate::dns::cache::Policy;
    use crate::dns::interface_records::{InterfaceAddress, InterfaceRecords};
    use crate::hosts::Hosts;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    #[test]
    fn query_events_follow_upstream_extraction_and_selected_cache_chain() {
        let owner = Name::from_ascii("alias.logging.test").unwrap();
        let terminal = Name::from_ascii("terminal.logging.test").unwrap();
        let mut writer = PacketWriter::new(1, 0x8180, 1232).unwrap();
        writer.question(&owner, 1, 1).unwrap();
        writer
            .record_at(Section::Answer, 12, 5, 1, 60, terminal.as_wire())
            .unwrap();
        writer
            .record(Section::Answer, &terminal, 1, 1, 60, &[192, 0, 2, 7])
            .unwrap();
        let reply = writer.finish();
        let mut cache = Cache::new(8, Default::default());
        let mut counters = CacheCounters::default();
        let mut local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
        local.query_logging = true;
        let mut context = CacheContext {
            cache: &mut cache,
            counters: &mut counters,
            negative_cache: true,
            negative_ttl: 60,
            filter_rr: &[],
        };
        let mut events = Vec::new();
        context
            .insert_reply_with_events(
                &reply,
                100,
                &local,
                &Default::default(),
                0,
                OrdinaryCacheMode::Commit,
                false,
                &mut events,
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].flags, qlog::REPLY | qlog::CNAME);
        assert_eq!(
            events[1].name.as_deref(),
            Some(b"terminal.logging.test".as_slice())
        );
        assert_eq!(events[1].flags, qlog::REPLY | qlog::IPV4);
        assert_eq!(context.counters.inserted, 2);
        local.query_logging = true;
        let mut request = PacketWriter::new(2, 0x0100, 1232).unwrap();
        request.question(&owner, 1, 1).unwrap();
        let request = request.finish();
        let question = super::super::forward::Question::parse(&request).unwrap();
        let answer = context
            .answer_tcp(&request, Header::parse(&request).unwrap(), &question, 101, &mut local, 1232)
            .unwrap()
            .packet
            .unwrap();
        assert_eq!(Message::parse(&answer).unwrap().header.answers, 2);
        let events = local.take_query_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].flags, qlog::CNAME);
        assert_eq!(events[1].flags, qlog::IPV4);
        assert_eq!(
            events[1].name.as_deref(),
            Some(b"terminal.logging.test".as_slice())
        );
    }

    #[test]
    fn positive_reverse_ptr_extracts_by_ip_and_imports_independently_of_target_name() {
        let owner = Name::from_ascii("17.2.0.192.in-addr.arpa").unwrap();
        let target = Name::from_ascii("target.reverse.test").unwrap();
        let mut writer = PacketWriter::new(1, 0x8180, 1232).unwrap();
        writer.question(&owner, 12, 1).unwrap();
        writer
            .record_at(Section::Answer, 12, 12, 1, 600, target.as_wire())
            .unwrap();
        let reply = writer.finish();
        let local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
        let mut child = Cache::new(8, Default::default());
        let mut counters = CacheCounters::default();
        let transaction = CacheContext {
            cache: &mut child,
            counters: &mut counters,
            negative_cache: true,
            negative_ttl: 0,
            filter_rr: &[],
        }
        .insert_reply_for_transfer(
            &reply,
            100,
            &local,
            &Default::default(),
            0,
            OrdinaryCacheMode::Commit,
        )
        .unwrap()
        .unwrap();
        assert_eq!(counters.inserted, 1);
        assert!(!child.contains_forward_name(&target, 100));
        let mut parent = Cache::new(8, Default::default());
        let mut counters = CacheCounters::default();
        let mut local = local;
        let mut context = CacheContext {
            cache: &mut parent,
            counters: &mut counters,
            negative_cache: true,
            negative_ttl: 0,
            filter_rr: &[12],
        };
        assert!(context.import_transfer(transaction, 103, &local));
        let mut query = PacketWriter::new(2, 0x0100, 512).unwrap();
        query.question(&owner, 12, 1).unwrap();
        let question = super::super::forward::Question {
            name: owner,
            rrtype: 12,
            class: 1,
        };
        let answer = context
            .answer_udp_with_edns(
                &query.finish(),
                &question,
                103,
                &mut local,
                1232,
                1232,
                true,
            )
            .unwrap()
            .packet
            .unwrap();
        let message = Message::parse(&answer).unwrap();
        assert_eq!(message.header.answers, 1);
        let record = message.records(Section::Answer).next().unwrap();
        assert_eq!(record.rrtype, 12);
        assert_eq!(record.ttl, 597);
        assert_eq!(record.canonical_rdata().unwrap(), target.as_wire());
        assert_eq!(counters.inserted, 1);
    }

    #[test]
    fn synth_overrides_generic_nx_and_keeps_cached_soa_for_direct_and_alias() {
        use crate::config::synth_domain::{SynthDomain, SynthRange};
        let alias = Name::from_ascii("alias.records.test").unwrap();
        let terminal = Name::from_ascii("192-0-2-7.synthetic.records.test").unwrap();
        let authority = Name::from_ascii("synthetic.records.test").unwrap();
        let mut config = DnsConfig::default();
        config.synth_domains.domains.push(SynthDomain {
            domain: b"synthetic.records.test".to_vec(),
            prefix: Vec::new(),
            indexed: false,
            range: SynthRange::V4 {
                start: u32::from(Ipv4Addr::new(192, 0, 2, 0)),
                end: u32::from(Ipv4Addr::new(192, 0, 2, 15)),
            },
        });
        let mut local = LocalDnsService::new(config, Hosts::new(), 60, 1232);
        let mut soa = Name::from_ascii("ns.synthetic.records.test")
            .unwrap()
            .as_wire()
            .to_vec();
        soa.extend_from_slice(
            Name::from_ascii("hm.synthetic.records.test")
                .unwrap()
                .as_wire(),
        );
        for value in [1u32, 60, 60, 600, 300] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        let mut writer = PacketWriter::new(1, 0x8183, 1232).unwrap();
        writer.question(&alias, 1, 1).unwrap();
        writer
            .record_at(Section::Answer, 12, 5, 1, 600, terminal.as_wire())
            .unwrap();
        writer
            .record(Section::Authority, &authority, 6, 1, 600, &soa)
            .unwrap();
        let reply = writer.finish();
        let mut cache = Cache::new(8, Default::default());
        let mut counters = CacheCounters::default();
        let mut context = CacheContext {
            cache: &mut cache,
            counters: &mut counters,
            negative_cache: true,
            negative_ttl: 0,
            filter_rr: &[],
        };
        context
            .insert_reply_with_policy(
                &reply,
                100,
                &local,
                &Default::default(),
                3,
                OrdinaryCacheMode::Commit,
            )
            .unwrap();
        for name in [&terminal, &alias] {
            let question = super::super::forward::Question {
                name: name.clone(),
                rrtype: 1,
                class: 1,
            };
            let answer = context
                .answer_records(
                    &question,
                    Header {
                        id: 2,
                        flags: 0x0100,
                        questions: 1,
                        answers: 0,
                        authorities: 0,
                        additionals: 0,
                    },
                    101,
                    &mut local,
                    1232,
                    false,
                )
                .unwrap()
                .packet
                .unwrap();
            let message = Message::parse(&answer).unwrap();
            assert_eq!(message.header.rcode(), 0);
            assert_ne!(message.header.flags & 0x0400, 0);
            assert_eq!(message.header.authorities, 1);
            let address = message
                .records(Section::Answer)
                .find(|record| record.rrtype == 1)
                .unwrap();
            assert_eq!(address.rdata, &[192, 0, 2, 7]);
            assert_eq!(address.ttl, 60);
            assert_eq!(
                message.records(Section::Authority).next().unwrap().rrtype,
                6
            );
        }
    }

    #[test]
    fn negative_soa_suffix_uses_exact_bytes_like_c_memcmp() {
        let name = Name::from_ascii("node.cache.test").unwrap();
        assert!(is_name_suffix(
            &name,
            &Name::from_ascii("cache.test").unwrap()
        ));
        assert!(is_name_suffix(
            &name,
            &Name::from_ascii("ache.test").unwrap()
        ));
        assert!(!is_name_suffix(
            &name,
            &Name::from_ascii("CaChE.TeSt").unwrap()
        ));
    }

    #[test]
    fn reverse_synth_precedes_generic_negatives_and_keeps_positive_ip_priority() {
        use crate::config::synth_domain::{SynthDomain, SynthRange};
        let alias = Name::from_ascii("10.2.0.192.in-addr.arpa").unwrap();
        let terminal = Name::from_ascii("7.2.0.192.in-addr.arpa").unwrap();
        let authority = Name::from_ascii("in-addr.arpa").unwrap();
        let mut config = DnsConfig::default();
        config.synth_domains.domains.push(SynthDomain {
            domain: b"synthetic.records.test".to_vec(),
            prefix: Vec::new(),
            indexed: false,
            range: SynthRange::V4 {
                start: u32::from(Ipv4Addr::new(192, 0, 2, 0)),
                end: u32::from(Ipv4Addr::new(192, 0, 2, 8)),
            },
        });
        for rcode in [0u16, 3] {
            let mut local = LocalDnsService::new(config.clone(), Hosts::new(), 77, 1232);
            let mut soa = Name::from_ascii("ns.records.test")
                .unwrap()
                .as_wire()
                .to_vec();
            soa.extend_from_slice(Name::from_ascii("hm.records.test").unwrap().as_wire());
            for value in [1u32, 60, 60, 600, 300] {
                soa.extend_from_slice(&value.to_be_bytes());
            }
            let mut writer = PacketWriter::new(1, 0x8180 | rcode, 1232).unwrap();
            writer.question(&alias, 12, 1).unwrap();
            writer
                .record_at(Section::Answer, 12, 5, 1, 600, terminal.as_wire())
                .unwrap();
            writer
                .record(Section::Authority, &authority, 6, 1, 600, &soa)
                .unwrap();
            let reply = writer.finish();
            let mut cache = Cache::new(8, Default::default());
            let mut counters = CacheCounters::default();
            let mut context = CacheContext {
                cache: &mut cache,
                counters: &mut counters,
                negative_cache: true,
                negative_ttl: 0,
                filter_rr: &[],
            };
            let miss_question = super::super::forward::Question {
                name: terminal.clone(),
                rrtype: 12,
                class: 1,
            };
            let miss = context
                .answer_records(
                    &miss_question,
                    Header {
                        id: 2,
                        flags: 0x0100,
                        questions: 1,
                        answers: 0,
                        authorities: 0,
                        additionals: 0,
                    },
                    101,
                    &mut local,
                    1232,
                    false,
                )
                .unwrap();
            assert!(miss.packet.is_none(), "an empty cache must defer reverse PTR/lease/synthesis precedence to the local caller");
            context
                .insert_reply_with_policy(
                    &reply,
                    100,
                    &local,
                    &Default::default(),
                    rcode,
                    OrdinaryCacheMode::Commit,
                )
                .unwrap();
            assert!(!context
                .cache
                .has_reverse_candidate("192.0.2.7".parse().unwrap(), 101));
            for name in [&terminal, &alias] {
                let question = super::super::forward::Question {
                    name: name.clone(),
                    rrtype: 12,
                    class: 1,
                };
                let answer = context
                    .answer_records(
                        &question,
                        Header {
                            id: 2,
                            flags: 0x0100,
                            questions: 1,
                            answers: 0,
                            authorities: 0,
                            additionals: 0,
                        },
                        101,
                        &mut local,
                        1232,
                        false,
                    )
                    .unwrap()
                    .packet
                    .unwrap();
                let message = Message::parse(&answer).unwrap();
                assert_eq!(message.header.rcode(), 0);
                assert_ne!(message.header.flags & 0x0400, 0);
                assert_eq!(message.header.authorities, 0);
                let ptr = message
                    .records(Section::Answer)
                    .find(|record| record.rrtype == 12)
                    .unwrap();
                assert_eq!(
                    ptr.canonical_rdata().unwrap(),
                    Name::from_ascii("192-0-2-7.synthetic.records.test")
                        .unwrap()
                        .as_wire()
                );
                assert_eq!(ptr.ttl, 77);
            }
            context.cache.start_insert();
            context
                .cache
                .insert(
                    Record {
                        name: Name::from_ascii("upstream.records.test").unwrap(),
                        kind: Kind::ReverseIpv4,
                        negative: false,
                        data: vec![192, 0, 2, 7],
                    },
                    101,
                    60,
                )
                .unwrap();
            assert!(context.cache.commit());
            assert!(context
                .cache
                .has_reverse_candidate("192.0.2.7".parse().unwrap(), 101));
            let question = super::super::forward::Question {
                name: terminal.clone(),
                rrtype: 12,
                class: 1,
            };
            let answer = context
                .answer_records(
                    &question,
                    Header {
                        id: 3,
                        flags: 0x0100,
                        questions: 1,
                        answers: 0,
                        authorities: 0,
                        additionals: 0,
                    },
                    101,
                    &mut local,
                    1232,
                    false,
                )
                .unwrap()
                .packet
                .unwrap();
            let message = Message::parse(&answer).unwrap();
            assert_eq!(message.header.flags & 0x0400, 0);
            assert_eq!(
                message
                    .records(Section::Answer)
                    .next()
                    .unwrap()
                    .canonical_rdata()
                    .unwrap(),
                Name::from_ascii("upstream.records.test").unwrap().as_wire()
            );
        }
    }

    #[test]
    fn cached_reply_replaces_request_metadata_with_empty_opt() {
        let name = Name::from_ascii("metadata.cache.test").unwrap();
        let question = super::super::forward::Question {
            name: name.clone(),
            rrtype: 1,
            class: 1,
        };
        let mut cache = Cache::new(8, Default::default());
        cache.start_insert();
        cache
            .insert(
                Record {
                    name: name.clone(),
                    kind: Kind::Ipv4,
                    negative: false,
                    data: vec![198, 51, 100, 7],
                },
                100,
                600,
            )
            .unwrap();
        assert!(cache.commit());
        let mut counters = CacheCounters::default();
        let mut local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 600, 1232);
        for (ttl, additional_type) in [(0x10000, None), (0x40, None), (0, Some(250)), (0, Some(16))]
        {
            let mut query = PacketWriter::new(2, 0x100, 1232).unwrap();
            query.question(&name, 1, 1).unwrap();
            query
                .record(Section::Additional, &Name::root(), 41, 1232, ttl, &[])
                .unwrap();
            if let Some(kind) = additional_type {
                query
                    .record(Section::Additional, &Name::root(), kind, 255, 0, b"opaque")
                    .unwrap();
            }
            let answer = CacheContext {
                cache: &mut cache,
                counters: &mut counters,
                negative_cache: true,
                negative_ttl: 0,
                filter_rr: &[],
            }
            .answer_udp_with_edns(
                &query.finish(),
                &question,
                100,
                &mut local,
                1232,
                1232,
                true,
            )
            .unwrap()
            .packet
            .unwrap();
            let message = Message::parse(&answer).unwrap();
            assert_eq!(message.header.answers, 1);
            assert_eq!(message.header.additionals, 1);
            let opt = message.records(Section::Additional).next().unwrap();
            assert_eq!((opt.rrtype, opt.ttl, opt.rdata), (41, 0, &[][..]));
        }
    }

    #[test]
    fn child_transfer_keeps_selected_generic_data_and_tcp_ignores_udp_limit() {
        let name = Name::from_ascii("large.transfer.test").unwrap();
        let mut writer = PacketWriter::new(1, 0x8180, 1232).unwrap();
        writer.question(&name, 65000, 1).unwrap();
        writer
            .record_at(Section::Answer, 12, 65000, 1, 600, &vec![b'x'; 650])
            .unwrap();
        let reply = writer.finish();
        let mut child_config = DnsConfig::default();
        child_config.cache_rr.push(255);
        let child_local = LocalDnsService::new(child_config, Hosts::new(), 600, 1232);
        let mut child = Cache::new(8, Default::default());
        let mut child_counters = CacheCounters::default();
        let transaction = CacheContext {
            cache: &mut child,
            counters: &mut child_counters,
            negative_cache: true,
            negative_ttl: 0,
            filter_rr: &[],
        }
        .insert_reply_for_transfer(
            &reply,
            100,
            &child_local,
            &Default::default(),
            0,
            OrdinaryCacheMode::Commit,
        )
        .unwrap()
        .unwrap();
        let mut parent = Cache::new(8, Default::default());
        let mut parent_counters = CacheCounters::default();
        // Parent selectors changed since accept. Import is a record operation;
        // it must not parse this packet again under the new empty selector list.
        let mut parent_local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 600, 1232);
        let mut context = CacheContext {
            cache: &mut parent,
            counters: &mut parent_counters,
            negative_cache: true,
            negative_ttl: 0,
            filter_rr: &[],
        };
        assert!(context.import_transfer(transaction, 103, &parent_local));
        let mut query = PacketWriter::new(2, 0x100, 512).unwrap();
        query.question(&name, 65000, 1).unwrap();
        let query = query.finish();
        let question = super::super::forward::Question {
            name: name.clone(),
            rrtype: 65000,
            class: 1,
        };
        let answer = context
            .answer_tcp(&query, Header::parse(&query).unwrap(), &question, 103, &mut parent_local, 1232)
            .unwrap()
            .packet
            .unwrap();
        assert!(answer.len() > 512);
        assert_eq!(Header::parse(&answer).unwrap().flags & 0x200, 0);
        let id = parent.lookup(&name, &[Kind::Generic(65000)], 103, false)[0];
        assert_eq!(parent.get(id).unwrap().expires, 700);
        assert_eq!(parent_counters.inserted, 1);
        assert_eq!(child_counters.inserted, 1);
        let truncated = CacheContext {
            cache: &mut parent,
            counters: &mut parent_counters,
            negative_cache: true,
            negative_ttl: 0,
            filter_rr: &[],
        }
        .answer_udp_with_edns(&query, &question, 103, &mut parent_local, 1232, 1232, true)
        .unwrap()
        .packet
        .expect("a cached RR too large for UDP still answers with TC");
        assert_eq!(Header::parse(&truncated).unwrap().answers, 0);
        assert_ne!(Header::parse(&truncated).unwrap().flags & 0x200, 0);
    }

    #[test]
    fn cached_alias_reselects_terminal_family_and_filter_keeps_the_cname() {
        for filter in [Vec::new(), vec![28]] {
            let mut cache = Cache::new(8, Default::default());
            let alias_name = Name::from_ascii("alias.test").unwrap();
            let terminal_name = Name::from_ascii("target.test").unwrap();
            cache.start_insert();
            let alias = cache
                .insert(
                    Record {
                        name: alias_name.clone(),
                        kind: Kind::Cname,
                        negative: false,
                        data: terminal_name.as_wire().to_vec(),
                    },
                    100,
                    60,
                )
                .unwrap();
            let target = cache
                .insert(
                    Record {
                        name: terminal_name.clone(),
                        kind: Kind::Ipv4,
                        negative: false,
                        data: vec![192, 0, 2, 1],
                    },
                    100,
                    60,
                )
                .unwrap();
            cache
                .insert(
                    Record {
                        name: terminal_name,
                        kind: Kind::Ipv6,
                        negative: false,
                        data: vec![0; 16],
                    },
                    100,
                    60,
                )
                .unwrap();
            assert!(cache.set_cname_target(alias, target));
            assert!(cache.commit());
            let question = super::super::forward::Question {
                name: alias_name,
                rrtype: 28,
                class: 1,
            };
            let mut counters = CacheCounters::default();
            let mut local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
            let answer = CacheContext {
                cache: &mut cache,
                counters: &mut counters,
                negative_cache: true,
                negative_ttl: 0,
                filter_rr: &filter,
            }
            .answer_records(
                &question,
                Header {
                    id: 1,
                    flags: 0x0100,
                    questions: 1,
                    answers: 0,
                    authorities: 0,
                    additionals: 0,
                },
                101,
                &mut local,
                1232,
                false,
            )
            .unwrap();
            assert_eq!(answer.filtered, !filter.is_empty());
            let packet = answer
                .packet
                .expect("the cached AAAA RRset answers the alias");
            let message = Message::parse(&packet).unwrap();
            let types: Vec<_> = message
                .records(Section::Answer)
                .map(|rr| rr.rrtype)
                .collect();
            assert_eq!(
                types,
                if filter.is_empty() {
                    vec![5, 28]
                } else {
                    vec![5]
                }
            );
        }
    }
    #[test]
    fn dynamic_cname_interface_terminal_overrides_cache_and_empty_refetches() {
        let alias = Name::from_ascii("alias.interface.test").unwrap();
        let target = Name::from_ascii("target.interface.test").unwrap();
        let question = super::super::forward::Question {
            name: alias.clone(),
            rrtype: 1,
            class: 1,
        };
        let rule = InterfaceRule {
            name: target.dnsmasq_bytes(),
            interface: b"cache0".to_vec(),
            family4: true,
            family6: false,
            prototype4: None,
            prototype6: None,
        };
        let inputs = vec![InterfaceAddress {
            label: b"cache0".to_vec(),
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            prefix: 24,
            flags: 0,
        }];
        let records = Arc::new(InterfaceRecords::from_addresses(&[rule.clone()], &inputs));
        let empty_records = Arc::new(InterfaceRecords::from_addresses(&[rule], &[]));
        let make_cache = || {
            let mut cache = Cache::new(8, Policy::default());
            cache.start_insert();
            let alias_id = cache
                .insert(
                    Record {
                        name: alias.clone(),
                        kind: Kind::Cname,
                        negative: false,
                        data: target.as_wire().to_vec(),
                    },
                    100,
                    600,
                )
                .unwrap();
            let target_id = cache
                .insert(
                    Record {
                        name: target.clone(),
                        kind: Kind::Ipv4,
                        negative: false,
                        data: vec![198, 51, 100, 7],
                    },
                    100,
                    600,
                )
                .unwrap();
            assert!(cache.set_cname_target(alias_id, target_id));
            assert!(cache.commit());
            cache
        };
        let mut local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
        local.interfaces = records;
        let mut cache = make_cache();
        let mut counters = CacheCounters::default();
        let answer = CacheContext {
            cache: &mut cache,
            counters: &mut counters,
            negative_cache: true,
            negative_ttl: 0,
            filter_rr: &[],
        }
        .answer_records(
            &question,
            Header {
                id: 1,
                flags: 0x0100,
                questions: 1,
                answers: 0,
                authorities: 0,
                additionals: 0,
            },
            101,
            &mut local,
            1232,
            false,
        )
        .unwrap()
        .packet
        .unwrap();
        let message = Message::parse(&answer).unwrap();
        assert_eq!(
            message
                .records(Section::Answer)
                .map(|record| record.rrtype)
                .collect::<Vec<_>>(),
            vec![5, 1]
        );
        assert_eq!(
            message
                .records(Section::Answer)
                .nth(1)
                .unwrap()
                .canonical_rdata()
                .unwrap(),
            vec![192, 0, 2, 1]
        );
        local.interfaces = empty_records;
        let mut cache = make_cache();
        let mut counters = CacheCounters::default();
        let answer = CacheContext {
            cache: &mut cache,
            counters: &mut counters,
            negative_cache: true,
            negative_ttl: 0,
            filter_rr: &[],
        }
        .answer_records(
            &question,
            Header {
                id: 1,
                flags: 0x0100,
                questions: 1,
                answers: 0,
                authorities: 0,
                additionals: 0,
            },
            101,
            &mut local,
            1232,
            false,
        )
        .unwrap();
        assert!(answer.packet.is_none());
    }
}
