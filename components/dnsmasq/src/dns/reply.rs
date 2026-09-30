//! Upstream reply envelope, before address/cache/rebind processing.
//!
//! References: forward.c::process_reply/return_reply, rrfilter.c::rrfilter,
//! rfc1035.c::resize_packet. This is not the whole process_reply contract:
//! address validation, policy filtering, cache insertion and EDE belong to
//! the caller. All offsets below refer to a fully bounded wire packet.

use super::wire::{
    find_pseudoheader, name_descriptor, skip_name, Header, Message, Section, WireError, HEADER_LEN,
    TYPE_OPT,
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
    let message = Message::parse(packet)?;
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
                        match relocate_name(packet, cursor, &removed, &mut fixups) {
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

/// Apply CD restoration, EDNS removal/size, AD proxy policy, RA and trailing
/// byte removal. Caller must still perform process_reply's remaining checks
/// before delivering or caching. Signed OPT and AD are kept as in C; CD and
/// RA follow return_reply/process_reply even in that case.
pub fn prepare_reply(packet: &[u8], policy: ReplyPolicy) -> Result<ReplyEnvelope, WireError> {
    let message = Message::parse(packet)?;
    let scan = find_pseudoheader(packet, true)?;
    let rcode = u16::from(message.header.rcode())
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
    let end = Message::parse(&output)?.end;
    output.truncate(end);
    Ok(ReplyEnvelope {
        packet: output,
        rcode,
        signed: scan.signed,
    })
}

/// return_reply's UDP fanout truncation: discard every RR except the last
/// OPT, retain the original question and flags, and set TC. Do not cut a wire
/// packet at an arbitrary byte or retain only a prefix of its answer section.
pub fn limit_udp_reply(packet: &[u8], limit: u16) -> Result<Vec<u8>, WireError> {
    if packet.len() <= usize::from(limit) {
        return Ok(packet.to_vec());
    }
    let message = Message::parse(packet)?;
    let scan = find_pseudoheader(packet, false)?;
    let mut output = packet[..message.questions.end].to_vec();
    let mut header = message.header;
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
}
