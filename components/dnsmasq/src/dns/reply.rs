//! Upstream reply envelope, before address/cache/rebind processing.
//!
//! References: forward.c::process_reply/return_reply, rrfilter.c::rrfilter,
//! rfc1035.c::resize_packet. This is not the whole process_reply contract:
//! address validation, policy filtering, cache insertion and EDE belong to
//! the caller. All offsets below refer to a fully bounded wire packet.

use super::wire::{
    find_pseudoheader, name_descriptor, skip_name, skip_questions, Header, Message, Name, Question,
    Section, WireError, HEADER_LEN, TYPE_OPT,
};
use std::ops::Range;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilterResult {
    pub matched: usize,
    pub removed: usize,
}

/// Remove additional-section OPTs and relocate compression pointers in kept
/// owner names and known IN RDATA. As in C, a pointer into an elided record
/// causes the entire operation to leave the packet unchanged. Unknown RDATA
/// is opaque. Collect/check first, then mutate, so failure is atomic.
pub fn strip_opt(packet: &mut Vec<u8>) -> Result<FilterResult, WireError> {
    // rrfilter.c scans bounded sections and simply leaves malformed/clipped
    // replies unchanged. The caller still performs the strict policy checks
    // elsewhere; filtering must not turn a clipped upstream packet into a
    // transport failure.
    let Ok(message) = Message::parse(packet) else {
        return Ok(FilterResult::default());
    };
    if message.header.questions != 1 {
        return Ok(FilterResult::default());
    }
    let removed: Vec<Range<usize>> = message
        .records(Section::Additional)
        .filter(|rr| rr.rrtype == TYPE_OPT)
        .map(|rr| rr.start..rr.end)
        .collect();
    let mut result = FilterResult {
        matched: removed.len(),
        removed: 0,
    };
    if removed.is_empty() {
        return Ok(result);
    }

    let mut fixups = Vec::new();
    if relocate_name(packet, HEADER_LEN, &removed, &mut fixups).is_err() {
        return Ok(result);
    }
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        for rr in message.records(section) {
            if removed.iter().any(|range| range.start == rr.start) {
                continue;
            }
            if relocate_name(packet, rr.start, &removed, &mut fixups).is_err() {
                return Ok(result);
            }
            if rr.class == 1 {
                let mut cursor = rr.fixed + 10;
                for &part in name_descriptor(rr.rrtype) {
                    if part == 0 {
                        // Only the encoded name belongs to this RDATA; its
                        // compression target may still refer elsewhere. Do not
                        // record fixups in a later RR that will be removed.
                        match relocate_name(&packet[..rr.end], cursor, &removed, &mut fixups) {
                            Ok(next) => cursor = next,
                            Err(_) => return Ok(result),
                        }
                    } else {
                        cursor += part;
                    }
                }
            }
        }
    }
    let mut header = message.header;
    // Keep pointer locations in the pre-compaction coordinate space until all
    // bytes have moved. A pointer in a record after the removed OPT shifts by
    // the same number of removed bytes preceding that location.
    let fixups: Vec<_> = fixups
        .into_iter()
        .map(|(at, target)| {
            (
                at - removed
                    .iter()
                    .filter(|range| range.start < at)
                    .map(Range::len)
                    .sum::<usize>(),
                target,
            )
        })
        .collect();
    let mut write = removed[0].start;
    for (index, range) in removed.iter().enumerate() {
        let end = removed
            .get(index + 1)
            .map_or(packet.len(), |next| next.start);
        packet.copy_within(range.end..end, write);
        write += end - range.end;
    }
    packet.truncate(write);
    header.additionals -= removed.len() as u16;
    header.write(packet)?;
    for (at, target) in fixups {
        packet[at..at + 2].copy_from_slice(&(0xc000 | target as u16).to_be_bytes());
    }
    result.removed = removed.len();
    Ok(result)
}

/// Apply `--filter-A`, `--filter-AAAA` and `--filter-rr` to an answer.
///
/// `rrfilter.c::rrfilter(RRFILTER_CONF)` only elides IN records in the answer
/// section.  `filter-rr=ANY` has the RFC 8482 special case for ANY queries:
/// retain A, AAAA, MX and CNAME while removing every other IN answer.  The
/// packet is left byte-for-byte unchanged when a kept name points into a
/// record selected for removal, matching C's conservative pointer check.
pub fn filter_rrs(packet: &mut Vec<u8>, filter_rr: &[u16]) -> Result<FilterResult, WireError> {
    if filter_rr.is_empty() {
        return Ok(FilterResult::default());
    }
    let Ok(message) = Message::parse(packet) else {
        return Ok(FilterResult::default());
    };
    if message.header.questions != 1 {
        return Ok(FilterResult::default());
    }
    let Ok(question) = Question::parse(packet, HEADER_LEN) else {
        return Ok(FilterResult::default());
    };
    let any_filter = question.qtype == 255 && filter_rr.contains(&255);
    let mut header = message.header;
    let mut retained = Vec::new();
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        retained.extend(
            message
                .records(section)
                .map(|rr| (rr.start, rr.end, rr.fixed, rr.class, rr.rrtype)),
        );
    }
    let sections = if any_filter {
        vec![Section::Answer, Section::Authority, Section::Additional]
    } else {
        vec![Section::Answer]
    };
    let mut selected = Vec::new();
    for section in sections {
        for (start, end, _fixed, class, rrtype) in message
            .records(section)
            .map(|rr| (rr.start, rr.end, rr.fixed, rr.class, rr.rrtype))
        {
            if class == 1
                && if any_filter {
                    !matches!(rrtype, 1 | 28 | 15 | 5)
                } else {
                    filter_rr.contains(&rrtype)
                }
            {
                selected.push((start..end, section));
            }
        }
    }
    let removed: Vec<Range<usize>> = selected.iter().map(|(range, _)| range.clone()).collect();
    let matched = removed.len();
    if removed.is_empty() {
        return Ok(FilterResult::default());
    }

    let mut fixups = Vec::new();
    if relocate_name(packet, HEADER_LEN, &removed, &mut fixups).is_err() {
        return Ok(FilterResult {
            matched,
            removed: 0,
        });
    }
    for (start, end, fixed, class, rrtype) in retained {
        if removed.iter().any(|range| range.start == start) {
            continue;
        }
        if relocate_name(packet, start, &removed, &mut fixups).is_err() {
            return Ok(FilterResult {
                matched,
                removed: 0,
            });
        }
        if class == 1 {
            let mut cursor = fixed + 10;
            for &part in name_descriptor(rrtype) {
                if part == 0 {
                    cursor = match relocate_name(&packet[..end], cursor, &removed, &mut fixups) {
                        Ok(next) => next,
                        Err(_) => {
                            return Ok(FilterResult {
                                matched,
                                removed: 0,
                            })
                        }
                    };
                } else {
                    cursor += part;
                }
            }
        }
    }

    let fixups: Vec<_> = fixups
        .into_iter()
        .map(|(at, target)| {
            (
                at - removed
                    .iter()
                    .filter(|range| range.start < at)
                    .map(Range::len)
                    .sum::<usize>(),
                target,
            )
        })
        .collect();
    let mut write = removed[0].start;
    for (index, range) in removed.iter().enumerate() {
        let end = removed
            .get(index + 1)
            .map_or(packet.len(), |next| next.start);
        packet.copy_within(range.end..end, write);
        write += end - range.end;
    }
    packet.truncate(write);
    let answer_removed = selected
        .iter()
        .filter(|(_, section)| matches!(section, Section::Answer))
        .count();
    let authority_removed = selected
        .iter()
        .filter(|(_, section)| matches!(section, Section::Authority))
        .count();
    let additional_removed = selected
        .iter()
        .filter(|(_, section)| matches!(section, Section::Additional))
        .count();
    header.answers -= answer_removed as u16;
    header.authorities -= authority_removed as u16;
    header.additionals -= additional_removed as u16;
    header.write(packet)?;
    for (at, target) in fixups {
        packet[at..at + 2].copy_from_slice(&(0xc000 | target as u16).to_be_bytes());
    }
    Ok(FilterResult {
        matched,
        removed: matched,
    })
}

fn relocate_name(
    packet: &[u8],
    mut at: usize,
    removed: &[Range<usize>],
    fixups: &mut Vec<(usize, usize)>,
) -> Result<usize, WireError> {
    // Validate the encoded name first; pointers are intentionally not followed,
    // matching check_name. Their locations, not pointed-to names, need moving.
    let next = skip_name(packet, at, 0)?;
    loop {
        match packet[at] {
            0 => return Ok(next),
            1..=63 => at += usize::from(packet[at]) + 1,
            65 => {
                let bits = usize::from(packet[at + 1]);
                at += 2 + if bits == 0 { 32 } else { bits.div_ceil(8) };
            }
            192..=255 => {
                let target = usize::from(u16::from_be_bytes([packet[at], packet[at + 1]]) & 0x3fff);
                let mut reduction = 0;
                for range in removed {
                    if target < range.start {
                        break;
                    }
                    if range.contains(&target) {
                        return Err(WireError::InvalidName);
                    }
                    reduction += range.len();
                }
                fixups.push((at, target - reduction));
                return Ok(next);
            }
            _ => return Err(WireError::LabelType),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReplyPolicy {
    pub client_had_opt: bool,
    pub checking_disabled: bool,
    pub proxy_dnssec: bool,
    pub edns_packet_max: u16,
}

#[derive(Debug)]
pub struct ReplyEnvelope {
    pub packet: Vec<u8>,
    /// RCODE including the OPT extension, captured before possible OPT removal.
    pub rcode: u16,
    pub signed: bool,
}

/// check_for_local_domain/lookup_domain at reply time. Both transports use
/// their own accepted local and dynamic-cache generation with this predicate.
pub(super) fn known_name(
    name: &Name,
    local: Option<&super::service::LocalDnsService>,
    routing: Option<&super::routing::RoutingTable>,
    cached_name: bool,
    now: i64,
) -> bool {
    local.is_some_and(|local| {
        super::local::known_forwarded_domain_with_leases(
            &local.config, &local.hosts, name, &local.leases, now,
        )
    }) || routing.is_some_and(|routing| routing.has_configured_address(name))
        || cached_name
}

/// process_reply's known-local NXDOMAIN conversion. Keep name ownership in
/// the caller so UDP can use its current generation and TCP its fork-equivalent
/// connection snapshot. `rcode` was captured before any OPT stripping.
pub(super) fn apply_known_local_nxdomain(
    packet: &mut [u8],
    rcode: u16,
    known: impl FnOnce(&Name) -> bool,
) -> Result<(), WireError> {
    let mut header = Header::parse(packet)?;
    if rcode == 3 && header.opcode() == 0 && header.flags & 0x0200 == 0 {
        let question = Question::parse(packet, HEADER_LEN)?;
        if known(&question.name) {
            header.flags = (header.flags & !0x000f) | 0x0400;
            header.write(packet)?;
        }
    }
    Ok(())
}

/// Apply CD restoration, EDNS removal/size, AD proxy policy, RA and trailing
/// byte removal. Caller must still perform process_reply's remaining checks
/// before delivering or caching. Signed OPT and AD are kept as in C; CD and
/// RA follow return_reply/process_reply even in that case.
pub fn prepare_reply(packet: &[u8], policy: ReplyPolicy) -> Result<ReplyEnvelope, WireError> {
    Message::parse(packet)?;
    let mut envelope = prepare_udp_reply(packet, policy)?;
    resize_reply(&mut envelope.packet);
    Ok(envelope)
}

/// UDP recvfrom may clip the packet in the middle of an RR. C still applies
/// envelope and address policy to the received bytes; a strict whole-message
/// parse here would discard SERVFAIL/TC replies and earlier policy effects.
/// Delay resize until after policy, whose packet-bound reads may use trailing
/// bytes outside the declared sections.
pub fn prepare_udp_reply(packet: &[u8], policy: ReplyPolicy) -> Result<ReplyEnvelope, WireError> {
    let header = Header::parse(packet)?;
    skip_questions(packet)?;
    let scan = find_pseudoheader(packet, true)?;
    let rcode = u16::from(header.rcode())
        | scan
            .opt
            .as_ref()
            .map_or(0, |opt| u16::from(packet[opt.record.fixed + 4]) << 4);
    let mut output = packet.to_vec();
    if !scan.signed {
        if let Some(opt) = scan.opt {
            if policy.client_had_opt {
                output[opt.record.fixed + 2..opt.record.fixed + 4]
                    .copy_from_slice(&policy.edns_packet_max.to_be_bytes());
            } else {
                strip_opt(&mut output)?;
            }
        }
    }
    let mut header = Header::parse(&output)?;
    header.flags = (header.flags & !0x10) | if policy.checking_disabled { 0x10 } else { 0 };
    if !scan.signed && !policy.proxy_dnssec {
        header.flags &= !0x20;
    }
    header.flags |= 0x80;
    header.write(&mut output)?;
    Ok(ReplyEnvelope {
        packet: output,
        rcode,
        signed: scan.signed,
    })
}

/// C resize_packet preserves the received length when any section is clipped.
/// Section clearing/OPT restoration is done by the policy branch before this.
pub fn resize_reply(packet: &mut Vec<u8>) {
    if let Ok(message) = Message::parse(packet) {
        packet.truncate(message.end);
    }
}

/// return_reply's UDP fanout truncation: discard every RR except the last
/// OPT, retain the original question and flags, and set TC. Do not cut a wire
/// packet at an arbitrary byte or retain only a prefix of its answer section.
pub fn limit_udp_reply(packet: &[u8], limit: u16) -> Result<Vec<u8>, WireError> {
    if packet.len() <= usize::from(limit) {
        return Ok(packet.to_vec());
    }
    let mut header = Header::parse(packet)?;
    let question_end = skip_questions(packet)?;
    let scan = find_pseudoheader(packet, false)?;
    let mut output = packet[..question_end].to_vec();
    header.answers = 0;
    header.authorities = 0;
    header.additionals = 0;
    header.flags |= 0x200;
    if let Some(opt) = scan.opt {
        output.extend_from_slice(&packet[opt.record.start..opt.record.end]);
        header.additionals = 1;
    }
    header.write(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{Name, PacketWriter};

    #[test]
    fn filters_preserve_packets_when_rdata_name_would_cross_into_a_removed_record() {
        // Independent DNS bytes: one root question, an empty CNAME RDATA,
        // then a compressed-owner RR. Reading the second owner's pointer as
        // CNAME RDATA would produce a fixup beyond the compacted packet.
        let prefix = [
            0, 7, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0,
            60, 0, 0,
        ];
        let mut opt = prefix.to_vec();
        opt.extend_from_slice(&[0xc0, 12, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        let original = opt.clone();
        assert_eq!(
            strip_opt(&mut opt).unwrap(),
            FilterResult {
                matched: 1,
                removed: 0
            }
        );
        assert_eq!(opt, original);

        let mut txt = prefix.to_vec();
        txt[7] = 2;
        txt[11] = 0;
        txt.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 2, 1, b'x']);
        let original = txt.clone();
        assert_eq!(
            filter_rrs(&mut txt, &[16]).unwrap(),
            FilterResult {
                matched: 1,
                removed: 0
            }
        );
        assert_eq!(txt, original);
    }

    fn packet() -> Vec<u8> {
        let name = Name::from_ascii("reply.test").unwrap();
        let mut writer = PacketWriter::new(7, 0x8130, 1232).unwrap();
        writer.question(&name, 1, 1).unwrap();
        writer
            .record(Section::Answer, &name, 1, 1, 30, &[192, 0, 2, 1])
            .unwrap();
        writer
            .record(Section::Additional, &Name::root(), 41, 4096, 0x1008000, &[])
            .unwrap();
        writer.finish()
    }

    #[test]
    fn envelope_restores_cd_ra_ad_and_preserves_extended_rcode() {
        let input = packet();
        let result = prepare_reply(
            &input,
            ReplyPolicy {
                client_had_opt: false,
                checking_disabled: false,
                proxy_dnssec: false,
                edns_packet_max: 1232,
            },
        )
        .unwrap();
        assert_eq!(result.rcode, 16);
        assert!(!result.signed);
        let header = Header::parse(&result.packet).unwrap();
        assert_eq!(header.flags, 0x8180);
        assert_eq!(header.additionals, 0);
        assert_eq!(header.answers, 1);
    }

    #[test]
    fn truncation_keeps_question_and_opt_only() {
        let input = packet();
        let output = limit_udp_reply(&input, 40).unwrap();
        let message = Message::parse(&output).unwrap();
        assert_eq!(message.header.flags, 0x8330);
        assert_eq!(message.header.answers, 0);
        assert_eq!(message.header.additionals, 1);
        assert_eq!(
            &output[12..message.questions.end],
            &input[12..message.questions.end]
        );
        assert_eq!(limit_udp_reply(&input, 1232).unwrap(), input);
    }

    #[test]
    fn udp_envelope_keeps_clipped_rr_for_later_policy_and_tc_limiting() {
        let mut input = packet();
        input.pop(); // Incomplete OPT: it must not be retained by find_pseudoheader.
        let policy = ReplyPolicy {
            client_had_opt: true,
            checking_disabled: false,
            proxy_dnssec: false,
            edns_packet_max: 512,
        };
        assert!(prepare_reply(&input, policy).is_err());
        let mut output = prepare_udp_reply(&input, policy).unwrap().packet;
        assert_eq!(output.len(), input.len());
        assert_eq!(Header::parse(&output).unwrap().flags, 0x8180);
        resize_reply(&mut output);
        assert_eq!(output.len(), input.len());
        let limited = limit_udp_reply(&output, 40).unwrap();
        let message = Message::parse(&limited).unwrap();
        assert_eq!(message.header.flags, 0x8380);
        assert_eq!((message.header.answers, message.header.additionals), (0, 0));
        assert_eq!(limited.len(), message.questions.end);
    }

    #[test]
    fn udp_trailing_bytes_remain_until_after_policy() {
        let mut input = packet();
        let end = input.len();
        input.extend_from_slice(&[7; 16]);
        let policy = ReplyPolicy {
            client_had_opt: true,
            checking_disabled: false,
            proxy_dnssec: false,
            edns_packet_max: 1232,
        };
        let mut output = prepare_udp_reply(&input, policy).unwrap().packet;
        assert_eq!(output.len(), end + 16);
        resize_reply(&mut output);
        assert_eq!(output.len(), end);
    }

    #[test]
    fn configured_rr_filter_elides_only_in_answer_records() {
        let name = Name::from_ascii("filter.test").unwrap();
        let mut writer = PacketWriter::new(9, 0x8180, 1232).unwrap();
        writer.question(&name, 1, 1).unwrap();
        writer
            .record(Section::Answer, &name, 1, 1, 30, &[192, 0, 2, 1])
            .unwrap();
        writer
            .record(Section::Answer, &name, 28, 1, 30, &[0; 16])
            .unwrap();
        writer
            .record(Section::Answer, &name, 1, 3, 30, &[192, 0, 2, 2])
            .unwrap();
        writer
            .record(Section::Authority, &name, 1, 1, 30, &[192, 0, 2, 3])
            .unwrap();
        let mut packet = writer.finish();
        let result = filter_rrs(&mut packet, &[1]).unwrap();
        assert_eq!(
            result,
            FilterResult {
                matched: 1,
                removed: 1
            }
        );
        let message = Message::parse(&packet).unwrap();
        assert_eq!(message.header.answers, 2);
        assert_eq!(message.header.authorities, 1);
        let records = message.records(Section::Answer).collect::<Vec<_>>();
        assert_eq!(records[0].rrtype, 28);
        assert_eq!(records[1].class, 3);
    }

    #[test]
    fn any_filter_keeps_address_mx_cname_and_removes_other_in_types() {
        let name = Name::from_ascii("any.test").unwrap();
        let mut writer = PacketWriter::new(10, 0x8180, 1232).unwrap();
        writer.question(&name, 255, 1).unwrap();
        writer
            .record(Section::Answer, &name, 1, 1, 30, &[192, 0, 2, 1])
            .unwrap();
        writer
            .record(Section::Answer, &name, 16, 1, 30, &[1, b'x'])
            .unwrap();
        writer
            .record(Section::Answer, &name, 16, 3, 30, &[1, b'y'])
            .unwrap();
        writer
            .record(Section::Additional, &name, 16, 1, 30, &[1, b'z'])
            .unwrap();
        writer
            .record(Section::Additional, &name, 16, 3, 30, &[1, b'w'])
            .unwrap();
        let mut packet = writer.finish();
        let result = filter_rrs(&mut packet, &[255]).unwrap();
        assert_eq!(result.removed, 2);
        let message = Message::parse(&packet).unwrap();
        assert_eq!(message.header.answers, 2);
        assert_eq!(message.header.additionals, 1);
        assert!(message
            .records(Section::Answer)
            .all(|rr| rr.rrtype == 1 || rr.class != 1));
    }

    #[test]
    fn clipped_answer_is_left_unchanged_for_rr_filtering() {
        let mut packet = packet();
        packet.pop();
        let before = packet.clone();
        assert_eq!(
            filter_rrs(&mut packet, &[1]).unwrap(),
            FilterResult::default()
        );
        assert_eq!(packet, before);
    }
}
