//! Reply processing that runs after an authenticated upstream response.
//!
//! The C implementation keeps this work in `forward.c::process_reply` and
//! `rfc1035.c::extract_addresses`.  Transport matching and cache insertion are
//! deliberately outside this module; this boundary only applies the address
//! safety decisions that must happen before a packet can reach a client.

use super::doctor::{self, Alias, DoctorOutcome};
use super::wire::{
    decode_name, find_pseudoheader, skip_name, skip_questions, validate_name, Header, Question, RecordRef,
    WireError, HEADER_LEN,
};
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
                    // util.c shifts a 32-bit value by 32 here. The exact
                    // AArch64 image treats /0 as /32; preserve that observed
                    // policy without reproducing the undefined C shift.
                    u32::MAX
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

impl AddressPolicy {
    pub(super) fn rejects_rebind(&self, question: &super::wire::Name, address: IpAddr) -> bool {
        let name = question.as_wire();
        self.stop_rebind
            && !self.rebind_domains.iter().any(|domain| {
                // forward.c::domain_no_rebind: an empty configured
                // domain exempts root/single-label names, not all suffixes.
                if domain == &[0] {
                    name.len() <= usize::from(name[0]) + 2
                } else {
                    suffix_match(&question.canonical_wire(), domain)
                }
            })
            && !is_allowed_address(address, self.rebind_localhost_ok)
    }
}

#[derive(Debug, Clone, Default)]
pub struct AddressPolicy {
    /// Static doctor rules in configuration evaluation order. The upstream
    /// owner applies these once, before cache and recipient copies diverge.
    pub static_aliases: Vec<Alias>,
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
    let header = Header::parse(packet)?;
    Ok(header.rcode() == 0
        && scan_bad_addresses(packet, header.answers, &policy.ignore_addresses, false).is_some())
}

/// Static subset of C's do_doctor stage. The owner calls this exactly once on
/// an admitted upstream reply, after envelope/known-local NXDOMAIN handling
/// and before bogus/rebind/cache processing. Never call on local/cache answers.
/// `rcode` is the original full RCODE, captured before OPT removal.
pub fn apply_static_aliases(
    packet: &mut [u8],
    aliases: &[Alias],
    rcode: u16,
) -> Result<DoctorOutcome, ProcessError> {
    apply_doctor(packet, aliases, rcode, None)
}

/// Shared UDP doctor stage: one scan applies ubus before the matching static
/// rule on each record. TCP supplies no callback through apply_static_aliases.
pub fn apply_doctor(
    packet: &mut [u8],
    aliases: &[Alias],
    rcode: u16,
    notify: Option<&mut doctor::Notify<'_>>,
) -> Result<DoctorOutcome, ProcessError> {
    let header = Header::parse(packet)?;
    if (aliases.is_empty() && notify.is_none())
        || header.opcode() != 0
        || !matches!(rcode, 0 | 3)
        || header.flags & 0x0200 != 0
    {
        return Ok(DoctorOutcome::default());
    }
    Ok(doctor::apply(packet, aliases, notify))
}

/// Address-policy subset of `process_reply`; the caller owns reply envelope,
/// cache, SOA, local NXDOMAIN conversion, doctor/UBus, RR filters and EDE.
///
/// The question must be bounded; incomplete RRs are processed in source order.
/// A/AAAA address reads intentionally use
/// packet bounds, as C does, rather than requiring an exact RDLEN; no read can
/// escape the supplied packet. A malformed Answer becomes SERVFAIL unless an
/// earlier bogus/rebind decision wins. TC/errors bypass address extraction.
/// Ignore must also be checked before transport completion via `ignore_reply`.
pub fn process_reply(
    packet: &mut Vec<u8>,
    policy: &AddressPolicy,
) -> Result<ProcessReport, ProcessError> {
    let header = Header::parse(packet)?;
    if ignore_reply(packet, policy)? {
        return Ok(ProcessReport {
            action: ProcessAction::Ignore,
            blocked_rebind: false,
            malformed_address: false,
            bogus_nxdomain: false,
            ignored_address: true,
        });
    }
    let scan = find_pseudoheader(packet, false)?;
    let rcode = u16::from(header.rcode())
        | scan
            .opt
            .as_ref()
            .map_or(0, |opt| u16::from(packet[opt.record.fixed + 4]) << 4);
    process_admitted_reply(packet, policy, rcode)
}

/// Post-admission address checks for real UDP/TCP callers. UDP already checked
/// ignore-address against the original upstream packet before completion;
/// checking it again here could incorrectly ignore a doctor's replacement.
/// TCP has no ignore-address predicate. Preserve the original full RCODE even
/// after stripping OPT or converting a known-local NXDOMAIN to NODATA.
pub fn process_admitted_reply(
    packet: &mut Vec<u8>,
    policy: &AddressPolicy,
    rcode: u16,
) -> Result<ProcessReport, ProcessError> {
    let mut header = Header::parse(packet)?;
    skip_questions(packet)?;
    find_pseudoheader(packet, false)?;
    let mut report = ProcessReport {
        action: ProcessAction::Deliver,
        blocked_rebind: false,
        malformed_address: false,
        bogus_nxdomain: false,
        ignored_address: false,
    };
    if header.opcode() != 0 || !matches!(rcode, 0 | 3) || header.flags & 0x0200 != 0 {
        return Ok(report);
    }

    // C's bogus wildcard branch runs before extract_addresses, so its first
    // match suppresses both rebind and malformed-address processing.
    report.bogus_nxdomain = rcode != 3
        && scan_bad_addresses(packet, header.answers, &policy.bogus_addresses, true).is_some();
    if !report.bogus_nxdomain {
        match extract_address_policy(packet, header, policy) {
            1 => report.blocked_rebind = true,
            2 => report.malformed_address = true,
            _ => {}
        }
    }
    if report.blocked_rebind || report.malformed_address || report.bogus_nxdomain {
        if report.bogus_nxdomain {
            header.flags = (header.flags & !0x040f) | 3;
        } else if report.malformed_address {
            header.flags = (header.flags & !0x000f) | 2;
        }
        discard_reply_records(packet, header)?;
    }
    Ok(report)
}

/// Propagate an ordered cache-extraction failure to the client. The caller
/// retains cache prefix effects and supplies EDE after restoring the OPT.
pub(super) fn reject_malformed_reply(packet: &mut Vec<u8>) -> Result<(), WireError> {
    let mut header = Header::parse(packet)?;
    header.flags = (header.flags & !0x000f) | 2;
    discard_reply_records(packet, header)
}

fn discard_reply_records(packet: &mut Vec<u8>, mut header: Header) -> Result<(), WireError> {
    let question_end = skip_questions(packet)?;
    let scan = find_pseudoheader(packet, false)?;
    // resize_packet restores the last OPT after clearing the sections.
    // Preserve it byte-for-byte; EDE insertion belongs to the caller.
    let opt = scan
        .opt
        .map(|opt| packet[opt.record.start..opt.record.end].to_vec());
    header.answers = 0;
    header.authorities = 0;
    header.additionals = 0;
    packet.truncate(question_end);
    if let Some(opt) = opt {
        packet.extend_from_slice(&opt);
        header.additionals = 1;
    }
    header.write(packet)
}

/// check_bad_address stops at the first malformed address, but an earlier
/// matching address wins. Ignore skips owner-name decoding; bogus extracts it.
fn scan_bad_addresses(
    packet: &[u8],
    answers: u16,
    prefixes: &[AddressPrefix],
    decode_owner: bool,
) -> Option<(usize, u32)> {
    if prefixes.is_empty() {
        return None;
    }
    let Ok(mut position) = skip_questions(packet) else {
        return None;
    };
    for _ in 0..answers {
        let fixed = if decode_owner {
            validate_name(packet, position, 10)
        } else {
            skip_name(packet, position, 10)
        };
        let Ok(fixed) = fixed else {
            return None;
        };
        let rrtype = u16::from_be_bytes([packet[fixed], packet[fixed + 1]]);
        let class = u16::from_be_bytes([packet[fixed + 2], packet[fixed + 3]]);
        let rdlen = u16::from_be_bytes([packet[fixed + 8], packet[fixed + 9]]);
        // check_bad_address tests the bounded address before ADD_RDLEN. An
        // earlier match wins even when this RR's declared tail is incomplete.
        if class == 1 && matches!(rrtype, 1 | 28) {
            let address = packet_address(packet, fixed + 10, rrtype)?;
            if prefixes.iter().any(|prefix| prefix.contains(address)) {
                let ttl = u32::from_be_bytes(packet[fixed + 4..fixed + 8].try_into().ok()?);
                return Some((position, ttl));
            }
        }
        position = fixed + 10 + usize::from(rdlen);
        if position > packet.len() {
            return None;
        }
    }
    None
}

/// check_for_bogus_wildcard caches the first matching RR's owner and TTL,
/// before ordinary address extraction, even if a later record is malformed.
pub(super) fn bogus_cache_entry(
    packet: &[u8],
    answers: u16,
    policy: &AddressPolicy,
) -> Option<(super::wire::Name, u32)> {
    let (position, ttl) = scan_bad_addresses(packet, answers, &policy.bogus_addresses, true)?;
    Some((decode_name(packet, position, 10).ok()?.0, ttl))
}

/// Return C extract_addresses' 0/1/2 decision for the address/CNAME subset.
fn extract_address_policy(packet: &[u8], header: Header, policy: &AddressPolicy) -> u8 {
    if header.questions != 1 {
        return 2;
    }
    let Ok(question) = Question::parse(packet, HEADER_LEN) else {
        return 2;
    };
    if question.class != 1 {
        return 0;
    }
    let mut current = question.name.clone();
    let mut cnames_left = 10;
    'cname: loop {
        let mut position = question.end;
        for _ in 0..header.answers {
            // The ordinary extract_addresses path checks endrr before any
            // CNAME/address policy, but only after earlier RRs have run.
            let Ok(rr) = RecordRef::parse(packet, position) else {
                return 2;
            };
            position = rr.end;
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
                && header.rcode() != 3
            {
                let Some(address) = packet_address(packet, rr.fixed + 10, question.qtype) else {
                    return 2;
                };
                if policy.rejects_rebind(&question.name, address) {
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

pub(super) fn is_allowed_address(address: IpAddr, allow_localhost: bool) -> bool {
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

    #[test]
    fn zero_prefix_follows_the_image_for_each_address_family() {
        let v4 = AddressPrefix::new("192.0.2.1".parse().unwrap(), 0).unwrap();
        assert!(v4.contains("192.0.2.1".parse().unwrap()));
        assert!(!v4.contains("192.0.2.2".parse().unwrap()));
        assert!(!v4.contains("8.8.8.8".parse().unwrap()));
        let v6 = AddressPrefix::new("2001:db8::1".parse().unwrap(), 0).unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(v6.contains("2001:db8::2".parse().unwrap()));
        assert!(v6.contains("::1".parse().unwrap()));
        assert!(!v6.contains("192.0.2.1".parse().unwrap()));
    }

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
    fn static_alias_is_gated_by_original_rcode_opcode_and_truncation() {
        let aliases = [Alias {
            from: Ipv4Addr::new(192, 0, 2, 10),
            end: Ipv4Addr::UNSPECIFIED,
            to: Ipv4Addr::new(198, 51, 100, 20),
            mask: Ipv4Addr::BROADCAST,
        }];
        for (flags, rcode, changed) in [
            (0x8580, 0, true),
            (0x8583, 3, true),
            (0x8580, 16, false),
            (0x8582, 2, false),
            (0x8780, 0, false),
            (0x8d80, 0, false),
        ] {
            let mut packet = named_packet(
                "upstream.test",
                1,
                "upstream.test",
                aliases[0].from.into(),
                flags,
                false,
            );
            let original = packet.clone();
            let report = apply_static_aliases(&mut packet, &aliases, rcode).unwrap();
            assert_eq!(report.static_rewrites, usize::from(changed));
            if changed {
                assert_eq!(Header::parse(&packet).unwrap().flags & 0x400, 0);
            } else {
                assert_eq!(packet, original);
            }
        }
    }

    #[test]
    fn admitted_reply_does_not_ignore_the_alias_destination() {
        let mut packet = named_packet(
            "upstream.test",
            1,
            "upstream.test",
            "192.0.2.10".parse().unwrap(),
            0x8580,
            false,
        );
        let policy = AddressPolicy {
            static_aliases: vec![Alias {
                from: "192.0.2.10".parse().unwrap(),
                end: Ipv4Addr::UNSPECIFIED,
                to: "198.51.100.20".parse().unwrap(),
                mask: Ipv4Addr::BROADCAST,
            }],
            ignore_addresses: vec![
                AddressPrefix::new("198.51.100.20".parse().unwrap(), 32).unwrap()
            ],
            ..Default::default()
        };
        assert!(!ignore_reply(&packet, &policy).unwrap());
        apply_static_aliases(&mut packet, &policy.static_aliases, 0).unwrap();
        assert!(ignore_reply(&packet, &policy).unwrap());
        assert_eq!(
            process_admitted_reply(&mut packet, &policy, 0)
                .unwrap()
                .action,
            ProcessAction::Deliver
        );
        assert_eq!(Message::parse(&packet).unwrap().header.answers, 1);
    }

    #[test]
    fn admitted_known_local_nxdomain_keeps_original_bogus_gate() {
        // The upstream NXDOMAIN was converted to local NODATA before doctor.
        // C still uses the captured original RCODE to skip bogus wildcard.
        let mut packet = named_packet(
            "known.test",
            1,
            "known.test",
            "192.0.2.10".parse().unwrap(),
            0x8580,
            false,
        );
        let policy = AddressPolicy {
            bogus_addresses: vec![AddressPrefix::new("192.0.2.10".parse().unwrap(), 32).unwrap()],
            ..Default::default()
        };
        let report = process_admitted_reply(&mut packet, &policy, 3).unwrap();
        assert!(!report.bogus_nxdomain);
        assert_eq!(Message::parse(&packet).unwrap().header.rcode(), 0);
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
    fn empty_rebind_exception_is_only_for_single_label_queries() {
        let policy = AddressPolicy {
            stop_rebind: true,
            rebind_domains: vec![vec![0]],
            ..AddressPolicy::default()
        };
        let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!policy.rejects_rebind(&Name::root(), private));
        assert!(!policy.rejects_rebind(&Name::from_ascii("host").unwrap(), private));
        assert!(policy.rejects_rebind(&Name::from_ascii("host.test").unwrap(), private));
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
            .record(Section::Answer, &target, 1, 1, 30, &[10, 0, 0, 1])
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

    #[test]
    fn clipped_answer_becomes_servfail_but_tc_keeps_received_bytes() {
        let mut clipped = packet("8.8.8.8".parse().unwrap());
        clipped.pop();
        for tc in [false, true] {
            let mut input = clipped.clone();
            if tc {
                input[2] |= 2;
            }
            let original = input.clone();
            let report = process_reply(&mut input, &AddressPolicy::default()).unwrap();
            assert_eq!(report.malformed_address, !tc);
            if tc {
                assert_eq!(input, original);
            } else {
                let message = Message::parse(&input).unwrap();
                assert_eq!((message.header.rcode(), message.header.answers), (2, 0));
                assert_eq!(input.len(), message.questions.end);
            }
        }
    }

    #[test]
    fn clipped_additional_does_not_malformed_a_complete_answer() {
        let mut input = packet("8.8.8.8".parse().unwrap());
        input[11] = 1;
        input.push(0); // Additional owner exists, fixed fields do not.
        let original = input.clone();
        let report = process_reply(&mut input, &AddressPolicy::default()).unwrap();
        assert!(!report.malformed_address);
        assert_eq!(input, original);
    }

    #[test]
    fn prefix_policy_decisions_precede_later_clipped_answers() {
        let mut input = packet("10.0.0.1".parse().unwrap());
        input[7] = 2;
        input.push(0);
        let prefix = AddressPrefix::new("10.0.0.0".parse().unwrap(), 8).unwrap();
        let policy = AddressPolicy {
            stop_rebind: true,
            ignore_addresses: vec![prefix],
            ..Default::default()
        };
        assert!(ignore_reply(&input, &policy).unwrap());
        let report = process_admitted_reply(&mut input.clone(), &policy, 0).unwrap();
        assert!(report.blocked_rebind && !report.malformed_address);
        let policy = AddressPolicy {
            bogus_addresses: vec![prefix],
            ..policy
        };
        let report = process_admitted_reply(&mut input, &policy, 0).unwrap();
        assert!(report.bogus_nxdomain && !report.blocked_rebind && !report.malformed_address);
        assert_eq!(Header::parse(&input).unwrap().rcode(), 3);
    }

    #[test]
    fn bogus_reads_address_before_declared_end_but_extract_checks_end_first() {
        let mut input = packet("10.0.0.1".parse().unwrap());
        let len = input.len();
        input[len - 5] = 5; // Four address bytes present, RDLEN declares five.
        let prefix = AddressPrefix::new("10.0.0.0".parse().unwrap(), 8).unwrap();
        let policy = AddressPolicy {
            stop_rebind: true,
            ignore_addresses: vec![prefix],
            ..Default::default()
        };
        assert!(ignore_reply(&input, &policy).unwrap());
        let report = process_admitted_reply(&mut input.clone(), &policy, 0).unwrap();
        assert!(!report.blocked_rebind && report.malformed_address);
        let policy = AddressPolicy {
            bogus_addresses: vec![prefix],
            ..policy
        };
        let report = process_admitted_reply(&mut input, &policy, 0).unwrap();
        assert!(report.bogus_nxdomain && !report.malformed_address);
    }
}
