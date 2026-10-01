//! OpenWrt rfc1035.c::do_doctor packet boundary, before cache insertion.
//! The owner selects upstream replies eligible for this stage. Never run this
//! over local/cache answers or once per merged recipient. TCP passes no callback.

use super::wire::{decode_name, skip_questions, skip_records, Header, WireError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Already-validated static alias in evaluation order. C prepends configuration
/// entries, so the caller supplies later declarations first. A zero `end` uses
/// masked network matching; otherwise endpoints are an inclusive IPv4 range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Alias {
    pub from: Ipv4Addr,
    pub end: Ipv4Addr,
    pub to: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl Alias {
    fn rewrite(self, address: Ipv4Addr) -> Option<Ipv4Addr> {
        let address = u32::from(address);
        let mask = u32::from(self.mask);
        let matches = if self.end.is_unspecified() {
            address & mask == u32::from(self.from) & mask
        } else {
            u32::from(self.from) <= address && address <= u32::from(self.end)
        };
        matches.then(|| Ipv4Addr::from((address & !mask) | (u32::from(self.to) & mask)))
    }
}

/// Completed effects remain in the packet when `stopped` is present. A partial
/// failure is not an atomic rollback. Unlike C's short-AAAA branch, a failure
/// never erases the fact that an earlier static rewrite invalidated security.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DoctorOutcome {
    pub clear_cache_secure: bool,
    pub static_rewrites: usize,
    pub ubus_rewrites: usize,
    pub notifications: usize,
    pub stopped: Option<WireError>,
}

/// Borrowed owner-name bytes use dnsmasq's internal escaped representation,
/// preserving case, literal label punctuation and non-UTF-8 bytes. The callback
/// returns an owned address; transport errors should be logged by the owner and
/// represented as None, preserving this record before its static alias stage.
pub type Notify<'a> = dyn FnMut(&[u8], u32, IpAddr) -> Option<IpAddr> + 'a;

/// Visit Answer records in order, skip Authority, then visit Additional.
/// Only IN A/AAAA records notify. Apply a same-family callback result first,
/// clearing AA even if unchanged; then use the first matching IPv4 static alias.
/// Static matching alone sets clear_cache_secure; ubus-only rewriting does not.
///
/// Reads/writes stay inside both the packet and the declared RDATA length. C
/// only checks packet bounds for address reads; its cross-RR short-RDLEN behavior
/// is deliberately not reproduced. All earlier completed effects are retained.
pub fn apply(
    packet: &mut [u8],
    aliases: &[Alias],
    mut notify: Option<&mut Notify<'_>>,
) -> DoctorOutcome {
    let mut outcome = DoctorOutcome::default();
    let result = (|| -> Result<(), WireError> {
        let header = Header::parse(packet)?;
        let mut position = skip_questions(packet)?;
        let answer_count = u32::from(header.answers);
        let record_count = answer_count + u32::from(header.additionals);
        for index in 0..record_count {
            if index == answer_count {
                position = skip_records(packet, position, u32::from(header.authorities))?;
            }
            let (owner, fixed) = decode_name(packet, position, 10)?;
            let rrtype = u16::from_be_bytes(packet[fixed..fixed + 2].try_into().unwrap());
            let class = u16::from_be_bytes(packet[fixed + 2..fixed + 4].try_into().unwrap());
            let ttl = u32::from_be_bytes(packet[fixed + 4..fixed + 8].try_into().unwrap());
            let rdlen =
                u16::from_be_bytes(packet[fixed + 8..fixed + 10].try_into().unwrap()) as usize;
            let start = fixed + 10;
            let width = match (class, rrtype) {
                (1, 1) => 4,
                (1, 28) => 16,
                _ => 0,
            };
            if width != 0 {
                if rdlen < width {
                    return Err(WireError::Truncated);
                }
                let address_end = start.checked_add(width).ok_or(WireError::Truncated)?;
                let data = packet.get(start..address_end).ok_or(WireError::Truncated)?;
                let mut address = if width == 4 {
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).unwrap()))
                } else {
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap()))
                };
                if let Some(callback) = notify.as_deref_mut() {
                    outcome.notifications += 1;
                    if let Some(replacement) = callback(&owner.dnsmasq_bytes(), ttl, address) {
                        if replacement.is_ipv4() == address.is_ipv4() {
                            address = replacement;
                            write_address(packet, start, address);
                            packet[2] &= !4;
                            outcome.ubus_rewrites += 1;
                        }
                    }
                }
                if let IpAddr::V4(address) = address {
                    if let Some(replacement) =
                        aliases.iter().find_map(|alias| alias.rewrite(address))
                    {
                        write_address(packet, start, IpAddr::V4(replacement));
                        packet[2] &= !4;
                        outcome.static_rewrites += 1;
                        outcome.clear_cache_secure = true;
                    }
                }
            }
            position = start
                .checked_add(rdlen)
                .filter(|end| *end <= packet.len())
                .ok_or(WireError::Truncated)?;
        }
        Ok(())
    })();
    outcome.stopped = result.err();
    outcome
}

fn write_address(packet: &mut [u8], start: usize, address: IpAddr) {
    match address {
        IpAddr::V4(value) => packet[start..start + 4].copy_from_slice(&value.octets()),
        IpAddr::V6(value) => packet[start..start + 16].copy_from_slice(&value.octets()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{Name, PacketWriter, Section};

    fn record(packet: &mut PacketWriter, section: Section, name: &str, address: [u8; 4]) {
        packet
            .record(
                section,
                &Name::from_ascii(name).unwrap(),
                1,
                1,
                120,
                &address,
            )
            .unwrap();
    }

    #[test]
    fn visits_answer_then_additional_and_applies_alias_after_callback() {
        let mut packet = PacketWriter::new(7, 0x8580, 512).unwrap();
        packet
            .question(&Name::from_ascii("question.test").unwrap(), 1, 1)
            .unwrap();
        record(&mut packet, Section::Answer, "First.test", [192, 0, 2, 1]);
        record(
            &mut packet,
            Section::Authority,
            "ignored.test",
            [192, 0, 2, 2],
        );
        record(
            &mut packet,
            Section::Additional,
            "Last.test",
            [192, 0, 2, 3],
        );
        let mut packet = packet.finish();
        let alias = Alias {
            from: "198.51.100.0".parse().unwrap(),
            end: Ipv4Addr::UNSPECIFIED,
            to: "203.0.113.0".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
        };
        let mut events = Vec::new();
        let outcome = apply(
            &mut packet,
            &[alias],
            Some(&mut |name, ttl, address| {
                events.push((name.to_vec(), ttl, address));
                Some("198.51.100.9".parse().unwrap())
            }),
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.0.as_slice())
                .collect::<Vec<_>>(),
            [b"First.test".as_slice(), b"Last.test"]
        );
        assert_eq!(
            (
                outcome.static_rewrites,
                outcome.ubus_rewrites,
                outcome.notifications
            ),
            (2, 2, 2)
        );
        assert!(outcome.clear_cache_secure && outcome.stopped.is_none());
        assert_eq!(&packet[packet.len() - 4..], &[203, 0, 113, 9]);
        assert_eq!(packet[2] & 4, 0);
    }

    #[test]
    fn rejects_short_rdata_without_overwriting_the_next_record() {
        let mut packet = PacketWriter::new(7, 0x8580, 512).unwrap();
        packet
            .record(Section::Answer, &Name::root(), 1, 1, 120, &[192, 0])
            .unwrap();
        record(&mut packet, Section::Answer, "next.test", [192, 0, 2, 1]);
        let mut packet = packet.finish();
        let original = packet.clone();
        let outcome = apply(
            &mut packet,
            &[],
            Some(&mut |_, _, _| panic!("invalid address must not notify")),
        );
        assert_eq!(outcome.stopped, Some(WireError::Truncated));
        assert_eq!(packet, original);
    }

    #[test]
    fn later_failure_retains_completed_static_effect_and_security_invalidation() {
        let mut packet = PacketWriter::new(7, 0x8580, 512).unwrap();
        record(&mut packet, Section::Answer, "first.test", [192, 0, 2, 1]);
        packet
            .record(Section::Answer, &Name::root(), 28, 1, 120, &[0; 15])
            .unwrap();
        let mut packet = packet.finish();
        let alias = Alias {
            from: "192.0.2.1".parse().unwrap(),
            end: Ipv4Addr::UNSPECIFIED,
            to: "198.51.100.1".parse().unwrap(),
            mask: Ipv4Addr::BROADCAST,
        };
        let outcome = apply(&mut packet, &[alias], None);
        assert_eq!(outcome.static_rewrites, 1);
        assert!(outcome.clear_cache_secure);
        assert_eq!(outcome.stopped, Some(WireError::Truncated));
        assert_eq!(packet[2] & 4, 0);
    }

    #[test]
    fn bounded_input_screen_preserves_packet_length_and_unrelated_header_fields() {
        let mut state = 0x17a450efu32;
        for length in 0..256 {
            for _ in 0..16 {
                let mut packet = Vec::with_capacity(length);
                for _ in 0..length {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    packet.push(state as u8);
                }
                let original = packet.clone();
                let _ = apply(&mut packet, &[], Some(&mut |_, _, address| Some(address)));
                assert_eq!(packet.len(), original.len());
                if length >= 12 {
                    assert_eq!(packet[..2], original[..2]);
                    assert_eq!(packet[3..12], original[3..12]);
                }
            }
        }
    }
}
