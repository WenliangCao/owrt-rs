//! Reply processing that runs after an authenticated upstream response.
//!
//! The C implementation keeps this work in `forward.c::process_reply` and
//! `rfc1035.c::extract_addresses`.  Transport matching and cache insertion are
//! deliberately outside this module; this boundary only applies the address
//! safety decisions that must happen before a packet can reach a client.

use super::wire::{Message, Question, Section, WireError};
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
    /// caller supplies domain exceptions in wire-name form, without a root
    /// label requirement; matching is case insensitive and label bounded.
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

/// Apply the address portions of `process_reply` to one validated upstream
/// packet.  Address violations clear all answer/authority/additional records,
/// retaining the question and setting the same header flags as C.  This is
/// intentionally atomic with respect to parsing: malformed packets are
/// rejected before the caller mutates its pending transaction.
pub fn process_reply(
    packet: &mut Vec<u8>,
    policy: &AddressPolicy,
) -> Result<ProcessReport, ProcessError> {
    let message = Message::parse(packet)?;
    let question = if message.header.questions == 1 {
        Question::parse(packet, message.questions.start)?
    } else {
        return Err(ProcessError::InvalidQuestion);
    };

    // C checks ignore-address before retry/error handling and does not send a
    // response at all.  It is therefore the only action that leaves bytes
    // unchanged.
    for rr in message.records(Section::Answer) {
        if let Ok(Some(address)) = address_record(&rr) {
            if policy
                .ignore_addresses
                .iter()
                .copied()
                .any(|prefix| prefix.contains(address))
            {
                return Ok(ProcessReport {
                    action: ProcessAction::Ignore,
                    blocked_rebind: false,
                    malformed_address: false,
                    bogus_nxdomain: false,
                    ignored_address: true,
                });
            }
        }
    }

    let mut blocked_rebind = false;
    let mut malformed_address = false;
    let mut bogus_nxdomain = false;
    let rebind_exception = policy
        .rebind_domains
        .iter()
        .any(|domain| suffix_match(&question.name.canonical_wire(), domain));
    for rr in message.records(Section::Answer) {
        let address = match address_record(&rr) {
            Ok(Some(address)) => address,
            Ok(None) => continue,
            Err(_) => {
                malformed_address = true;
                continue;
            }
        };
        if policy
            .bogus_addresses
            .iter()
            .copied()
            .any(|prefix| prefix.contains(address))
        {
            bogus_nxdomain = true;
        }
        if policy.stop_rebind
            && !rebind_exception
            && !is_allowed_address(address, policy.rebind_localhost_ok)
        {
            blocked_rebind = true;
        }
    }

    let clear_records = blocked_rebind || malformed_address || bogus_nxdomain;
    if clear_records {
        let mut header = message.header;
        header.answers = 0;
        header.authorities = 0;
        header.additionals = 0;
        if bogus_nxdomain {
            header.flags = (header.flags & !0x000f) | 3;
            header.flags &= !0x0400; // C removes AA for bogus wildcard.
        }
        // `extract_addresses` reports malformed RDATA as SERVFAIL.
        if malformed_address {
            header.flags = (header.flags & !0x000f) | 2;
        }
        packet.truncate(message.questions.end);
        header.write(packet)?;
    }
    Ok(ProcessReport {
        action: ProcessAction::Deliver,
        blocked_rebind,
        malformed_address,
        bogus_nxdomain,
        ignored_address: false,
    })
}

fn address_record(rr: &super::wire::RecordRef<'_>) -> Result<Option<IpAddr>, ProcessError> {
    match (rr.class, rr.rrtype) {
        (1, 1) => {
            if rr.rdata.len() != 4 {
                return Err(ProcessError::Wire(WireError::InvalidName));
            }
            Ok(Some(IpAddr::V4(Ipv4Addr::new(
                rr.rdata[0],
                rr.rdata[1],
                rr.rdata[2],
                rr.rdata[3],
            ))))
        }
        (1, 28) => {
            if rr.rdata.len() != 16 {
                return Err(ProcessError::Wire(WireError::InvalidName));
            }
            Ok(Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(rr.rdata).unwrap(),
            ))))
        }
        _ => Ok(None),
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
                || (!allow_localhost && ((ip & 0xff00_0000) == 0x7f00_0000 || ip == 0));
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
    use crate::dns::wire::{Header, Name, PacketWriter};

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
}
