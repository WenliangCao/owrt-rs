//! Reply processing that runs after an authenticated upstream response.
//!
//! The C implementation keeps this work in `forward.c::process_reply` and
//! `rfc1035.c::extract_addresses`.  Transport matching and cache insertion are
//! deliberately outside this module; this boundary only applies the address
//! safety decisions that must happen before a packet can reach a client.

use super::wire::{decode_name, find_pseudoheader, Message, Question, Section, WireError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressPrefix {
    pub address: IpAddr,
    pub prefix: u8,
}

impl AddressPrefix {
    pub fn new(address: IpAddr, prefix: u8) -> Option<Self> {
        let valid = match address {
            IpAddr::V4(_) => prefix <= 32,
            IpAddr::V6(_) => prefix <= 128,
        };
        valid.then_some(Self { address, prefix })
    }

    fn contains(self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let bits = self.prefix;
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                (u32::from(network) & mask) == (u32::from(candidate) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let network = u128::from_be_bytes(network.octets());
                let candidate = u128::from_be_bytes(candidate.octets());
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                network & mask == candidate & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AddressPolicy {
    /// Implements `--stop-dns-rebind` and its localhost exception.  The
    /// caller supplies domain exceptions in wire-name form, including the root
    /// terminator; matching is case insensitive and label bounded.
    pub stop_rebind: bool,
    pub rebind_localhost_ok: bool,
    pub rebind_domains: Vec<Vec<u8>>,
    /// Prefixes from `--bogus-nxdomain`; a match changes a successful reply to
    /// NXDOMAIN, exactly as `check_for_bogus_wildcard` does.
    pub bogus_addresses: Vec<AddressPrefix>,
    /// Prefixes from `--ignore-address`; a match abandons this upstream reply
    /// before any reply or cache processing.
    pub ignore_addresses: Vec<AddressPrefix>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAction {
    Deliver,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessReport {
    pub action: ProcessAction,
    pub blocked_rebind: bool,
    pub malformed_address: bool,
    pub bogus_nxdomain: bool,
    pub ignored_address: bool,
}

#[derive(Debug)]
pub enum ProcessError {
    Wire(WireError),
    InvalidQuestion,
}

impl From<WireError> for ProcessError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

/// Pre-completion ignore-address predicate from `reply_query`. A match leaves
/// both packet and forwarding transaction untouched: the transport must call
/// this after authentication and before its retry/completion state changes.
/// Only the header's low RCODE gates this check, even with TC or an OPT RCODE.
pub fn ignore_reply(packet: &[u8], policy: &AddressPolicy) -> Result<bool, ProcessError> {
    let message = Message::parse(packet)?;
    Ok(message.header.rcode() == 0
        && scan_bad_addresses(packet, &message, &policy.ignore_addresses, false))
}

/// Address-policy subset of `process_reply`; the caller owns reply envelope,
/// cache, SOA, local NXDOMAIN conversion, doctor/UBus, RR filters and EDE.
///
/// Input must be structurally bounded. A/AAAA address reads intentionally use
/// packet bounds, as C does, rather than requiring an exact RDLEN; no read can
/// escape the supplied packet. Structural failures return an error atomically.
/// Ignore must also be checked before transport completion via `ignore_reply`.
pub fn process_reply(
    packet: &mut Vec<u8>,
    policy: &AddressPolicy,
) -> Result<ProcessReport, ProcessError> {
    let message = Message::parse(packet)?;
    let mut report = ProcessReport {
        action: ProcessAction::Deliver,
        blocked_rebind: false,
        malformed_address: false,
        bogus_nxdomain: false,
        ignored_address: false,
    };
    if message.header.rcode() == 0
        && scan_bad_addresses(packet, &message, &policy.ignore_addresses, false)
    {
        report.action = ProcessAction::Ignore;
        report.ignored_address = true;
        return Ok(report);
    }
    let scan = find_pseudoheader(packet, false)?;
    let rcode = u16::from(message.header.rcode())
        | scan
            .opt
            .as_ref()
            .map_or(0, |opt| u16::from(packet[opt.record.fixed + 4]) << 4);
    if message.header.opcode() != 0 || !matches!(rcode, 0 | 3) || message.header.flags & 0x0200 != 0
    {
        return Ok(report);
    }

    // C's bogus wildcard branch runs before extract_addresses, so its first
    // match suppresses both rebind and malformed-address processing.
    report.bogus_nxdomain =
        rcode != 3 && scan_bad_addresses(packet, &message, &policy.bogus_addresses, true);
    if !report.bogus_nxdomain {
        match extract_address_policy(packet, &message, policy) {
            1 => report.blocked_rebind = true,
            2 => report.malformed_address = true,
            _ => {}
        }
    }
    if report.blocked_rebind || report.malformed_address || report.bogus_nxdomain {
        let mut header = message.header;
        header.answers = 0;
        header.authorities = 0;
        header.additionals = 0;
        if report.bogus_nxdomain {
            header.flags = (header.flags & !0x040f) | 3;
        } else if report.malformed_address {
            header.flags = (header.flags & !0x000f) | 2;
        }
        // resize_packet restores the last OPT after clearing the sections.
        // Preserve it byte-for-byte; EDE insertion belongs to the caller.
        let opt = scan
            .opt
            .map(|opt| packet[opt.record.start..opt.record.end].to_vec());
        let question_end = message.questions.end;
        packet.truncate(question_end);
        if let Some(opt) = opt {
            packet.extend_from_slice(&opt);
            header.additionals = 1;
        }
        header.write(packet)?;
    }
    Ok(report)
}

/// check_bad_address stops at the first malformed address, but an earlier
/// matching address wins. Ignore skips owner-name decoding; bogus extracts it.
fn scan_bad_addresses(
    packet: &[u8],
    message: &Message<'_>,
    prefixes: &[AddressPrefix],
    decode_owner: bool,
) -> bool {
    if prefixes.is_empty() {
        return false;
    }
    for rr in message.records(Section::Answer) {
        if decode_owner && decode_name(packet, rr.start, 10).is_err() {
            return false;
        }
        if rr.class != 1 || !matches!(rr.rrtype, 1 | 28) {
            continue;
        }
        let Some(address) = packet_address(packet, rr.fixed + 10, rr.rrtype) else {
            return false;
        };
        if prefixes.iter().any(|prefix| prefix.contains(address)) {
            return true;
        }
    }
    false
}

/// Return C extract_addresses' 0/1/2 decision for the address/CNAME subset.
fn extract_address_policy(packet: &[u8], message: &Message<'_>, policy: &AddressPolicy) -> u8 {
    if message.header.questions != 1 {
        return 2;
    }
    let Ok(question) = Question::parse(packet, message.questions.start) else {
        return 2;
    };
    if question.class != 1 {
        return 0;
    }
    let check_rebind = policy.stop_rebind
        && !policy
            .rebind_domains
            .iter()
            .any(|domain| suffix_match(&question.name.canonical_wire(), domain));
    let mut current = question.name;
    let mut cnames_left = 10;
    'cname: loop {
        for rr in message.records(Section::Answer) {
            // C decodes every owner even when its class/type/name is unrelated.
            let Ok((owner, _)) = decode_name(packet, rr.start, 10) else {
                return 2;
            };
            if rr.class != 1 || !owner.eq_ignore_ascii_case(&current) {
                continue;
            }
            if rr.rrtype == 5 {
                if cnames_left == 0 {
                    return 0;
                }
                cnames_left -= 1;
                let Ok((target, _)) = decode_name(packet, rr.fixed + 10, 0) else {
                    return 2;
                };
                current = target;
                if question.qtype != 5 {
                    continue 'cname;
                }
            } else if rr.rrtype == question.qtype
                && matches!(question.qtype, 1 | 28)
                && message.header.rcode() != 3
            {
                let Some(address) = packet_address(packet, rr.fixed + 10, question.qtype) else {
                    return 2;
                };
                if check_rebind && !is_allowed_address(address, policy.rebind_localhost_ok) {
                    return 1;
                }
            }
        }
        return 0;
    }
}

fn packet_address(packet: &[u8], start: usize, rrtype: u16) -> Option<IpAddr> {
    match rrtype {
        1 => Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(packet.get(start..start + 4)?).ok()?,
        ))),
        28 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(packet.get(start..start + 16)?).ok()?,
        ))),
        _ => None,
    }
}

fn suffix_match(name: &[u8], suffix: &[u8]) -> bool {
    fn labels(mut wire: &[u8]) -> Option<Vec<&[u8]>> {
        let mut result = Vec::new();
        while wire.first().copied()? != 0 {
            let length = usize::from(wire[0]);
            if length > 63 || wire.len() < length + 1 {
                return None;
            }
            result.push(&wire[1..length + 1]);
            wire = &wire[length + 1..];
        }
        Some(result)
    }
    let Some(name) = labels(name) else {
        return false;
    };
    let Some(suffix) = labels(suffix) else {
        return false;
    };
    suffix.len() <= name.len()
        && name[name.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn is_allowed_address(address: IpAddr, allow_localhost: bool) -> bool {
    match address {
        IpAddr::V4(value) => {
            let ip = u32::from(value);
            let private = (ip & 0xff00_0000) == 0x0a00_0000
                || (ip & 0xffc0_0000) == 0x6440_0000
                || (ip & 0xfff0_0000) == 0xac10_0000
                || (ip & 0xffff_0000) == 0xc0a8_0000
                || (ip & 0xffff_0000) == 0xa9fe_0000
                || (ip & 0xffff_ff00) == 0xc000_0200
                || (ip & 0xffff_ff00) == 0xc633_6400
                || (ip & 0xffff_ff00) == 0xcb00_7100
                || ip == u32::MAX
                || (!allow_localhost
                    && ((ip & 0xff00_0000) == 0x7f00_0000 || ip & 0xff00_0000 == 0));
            !private
        }
        IpAddr::V6(value) => {
            let bytes = value.octets();
            let mapped = bytes[..10] == [0; 10] && bytes[10..12] == [0xff, 0xff];
            if mapped {
                return is_allowed_address(
                    IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                    allow_localhost,
                );
            }
            let localhost = value.is_unspecified() || value.is_loopback();
            !(localhost && !allow_localhost
                || bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80
                || bytes[0] == 0xfe && bytes[1] & 0xc0 == 0xc0
                || bytes[0] & 0xfe == 0xfc
                || bytes[..4] == [0x20, 0x01, 0x0d, 0xb8])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{Header, Message, Name, PacketWriter, Section};

    fn packet(address: IpAddr) -> Vec<u8> {
        let name = Name::from_ascii("rebind.test").unwrap();
        let mut writer = PacketWriter::new(7, 0x8180, 1232).unwrap();
        writer
            .question(&name, if address.is_ipv4() { 1 } else { 28 }, 1)
            .unwrap();
        let bytes = match address {
            IpAddr::V4(value) => value.octets().to_vec(),
            IpAddr::V6(value) => value.octets().to_vec(),
        };
        writer
            .record(
                Section::Answer,
                &name,
                if address.is_ipv4() { 1 } else { 28 },
                1,
                30,
                &bytes,
            )
            .unwrap();
        writer.finish()
    }

    fn named_packet(
        query_name: &str,
        qtype: u16,
        owner: &str,
        address: IpAddr,
        flags: u16,
        opt: bool,
    ) -> Vec<u8> {
        let query_name = Name::from_ascii(query_name).unwrap();
        let owner = Name::from_ascii(owner).unwrap();
        let mut writer = PacketWriter::new(7, flags, 1232).unwrap();
        writer.question(&query_name, qtype, 1).unwrap();
        let rrtype = if address.is_ipv4() { 1 } else { 28 };
        let data = match address {
            IpAddr::V4(value) => value.octets().to_vec(),
            IpAddr::V6(value) => value.octets().to_vec(),
        };
        writer
            .record(Section::Answer, &owner, rrtype, 1, 30, &data)
            .unwrap();
        if opt {
            writer
                .record(Section::Additional, &Name::root(), 41, 1232, 0, &[])
                .unwrap();
        }
        writer.finish()
    }

    #[test]
    fn stop_rebind_clears_sections_but_keeps_question() {
        let mut packet = packet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let report = process_reply(
            &mut packet,
            &AddressPolicy {
                stop_rebind: true,
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert!(report.blocked_rebind);
        let message = Message::parse(&packet).unwrap();
        assert_eq!(message.header.answers, 0);
        assert_eq!(message.questions.end, packet.len());
    }

    #[test]
    fn localhost_exception_and_bogus_prefix_follow_c_order() {
        let mut localhost_packet = packet(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let report = process_reply(
            &mut localhost_packet,
            &AddressPolicy {
                stop_rebind: true,
                rebind_localhost_ok: true,
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert!(!report.blocked_rebind);

        let mut packet = packet(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)));
        let report = process_reply(
            &mut packet,
            &AddressPolicy {
                bogus_addresses: vec![AddressPrefix::new(
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                    24,
                )
                .unwrap()],
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert!(report.bogus_nxdomain);
        assert_eq!(Header::parse(&packet).unwrap().rcode(), 3);
    }

    #[test]
    fn ignore_address_abandons_without_mutating_packet() {
        let mut packet = packet(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        let before = packet.clone();
        let report = process_reply(
            &mut packet,
            &AddressPolicy {
                ignore_addresses: vec![AddressPrefix::new(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
                    24,
                )
                .unwrap()],
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert_eq!(report.action, ProcessAction::Ignore);
        assert_eq!(packet, before);
    }

    #[test]
    fn malformed_address_is_servfail_and_domain_exception_is_label_bounded() {
        let name = Name::from_ascii("foo.example.test").unwrap();
        let mut writer = PacketWriter::new(9, 0x8180, 512).unwrap();
        writer.question(&name, 1, 1).unwrap();
        writer
            .record(Section::Answer, &name, 1, 1, 30, &[10, 0, 0])
            .unwrap();
        let mut malformed_packet = writer.finish();
        let report = process_reply(
            &mut malformed_packet,
            &AddressPolicy {
                stop_rebind: true,
                rebind_domains: vec![Name::from_ascii("example.test").unwrap().canonical_wire()],
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert!(report.malformed_address);
        assert_eq!(Header::parse(&malformed_packet).unwrap().rcode(), 2);

        let mut packet = packet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let report = process_reply(
            &mut packet,
            &AddressPolicy {
                stop_rebind: true,
                rebind_domains: vec![Name::from_ascii("badexample.test")
                    .unwrap()
                    .canonical_wire()],
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert!(report.blocked_rebind);
    }

    #[test]
    fn rebind_matches_only_the_queried_type_and_cname_chain() {
        let mut unrelated = named_packet(
            "rebind.test",
            1,
            "other.test",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            0x8180,
            false,
        );
        let report = process_reply(
            &mut unrelated,
            &AddressPolicy {
                stop_rebind: true,
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert!(!report.blocked_rebind);

        let mut any = named_packet(
            "rebind.test",
            255,
            "rebind.test",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            0x8180,
            false,
        );
        let report = process_reply(
            &mut any,
            &AddressPolicy {
                stop_rebind: true,
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert!(!report.blocked_rebind);

        let alias = Name::from_ascii("alias.test").unwrap();
        let target = Name::from_ascii("target.test").unwrap();
        let mut writer = PacketWriter::new(7, 0x8180, 1232).unwrap();
        writer.question(&alias, 1, 1).unwrap();
        writer
            .record(Section::Answer, &alias, 5, 1, 30, target.as_wire())
            .unwrap();
        writer
            .record(
                Section::Answer,
                &target,
                1,
                1,
                30,
                &[10, 0, 0, 1],
            )
            .unwrap();
        let mut cname = writer.finish();
        let report = process_reply(
            &mut cname,
            &AddressPolicy {
                stop_rebind: true,
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert!(report.blocked_rebind);
    }

    #[test]
    fn policy_gates_skip_tc_errors_and_preserve_opt_on_block() {
        for flags in [0x8200, 0x8182, 0x0900] {
            let mut packet = named_packet(
                "rebind.test",
                1,
                "rebind.test",
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                flags,
                false,
            );
            let report = process_reply(
                &mut packet,
                &AddressPolicy {
                    stop_rebind: true,
                    ..AddressPolicy::default()
                },
            )
            .unwrap();
            assert!(!report.blocked_rebind);
            assert_eq!(Message::parse(&packet).unwrap().header.answers, 1);
        }

        let mut packet = named_packet(
            "rebind.test",
            1,
            "other.test",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            0x8180,
            true,
        );
        let before_opt = Message::parse(&packet)
            .unwrap()
            .records(Section::Additional)
            .next()
            .unwrap();
        let before_opt_bytes = packet[before_opt.start..before_opt.end].to_vec();
        let report = process_reply(
            &mut packet,
            &AddressPolicy {
                bogus_addresses: vec![AddressPrefix::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    8,
                )
                .unwrap()],
                ..AddressPolicy::default()
            },
        )
        .unwrap();
        assert!(report.bogus_nxdomain);
        let message = Message::parse(&packet).unwrap();
        assert_eq!(message.header.answers, 0);
        assert_eq!(message.header.additionals, 1);
        let after_opt = message.records(Section::Additional).next().unwrap();
        assert_eq!(&packet[after_opt.start..after_opt.end], before_opt_bytes);
    }

    #[test]
    fn ignore_reply_is_low_rcode_gated_and_does_not_mutate() {
        for flags in [0x8180, 0x8200, 0x8182] {
            let packet = named_packet(
                "ignore.test",
                1,
                "unrelated.test",
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                flags,
                false,
            );
            let ignored = ignore_reply(
                &packet,
                &AddressPolicy {
                    ignore_addresses: vec![AddressPrefix::new(
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                        8,
                    )
                    .unwrap()],
                    ..AddressPolicy::default()
                },
            )
            .unwrap();
            assert_eq!(ignored, flags == 0x8180 || flags == 0x8200);
        }
    }
}
