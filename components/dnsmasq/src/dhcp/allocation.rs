//! Address selection follows dhcp.c:687-924. ICMP and its bounded cache are
//! explicit caller dependencies, allowing network-free state-machine tests.

use super::lease::LeaseStore;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeKind {
    Dynamic,
    Static,
    Proxy,
}

#[derive(Clone, Debug)]
pub struct AddressRange {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub router: Ipv4Addr,
    pub local: Ipv4Addr,
    pub lease_time: u32,
    pub kind: RangeKind,
    pub filter: Vec<Vec<u8>>,
    pub epoch: u32,
}

impl AddressRange {
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        self.start <= address && address <= self.end
    }

    pub fn same_subnet(&self, address: Ipv4Addr) -> bool {
        u32::from(address) & u32::from(self.netmask)
            == u32::from(self.start) & u32::from(self.netmask)
    }
}

/// dhcp-common.c:224-251: all positive tags required; ! and legacy # negate.
pub fn match_tags(filter: &[Vec<u8>], tags: &[&[u8]], allow_untagged: bool) -> bool {
    if filter.is_empty() && !allow_untagged {
        return false;
    }
    filter.iter().all(|tag| {
        if let Some(negative) = tag.strip_prefix(b"!").or_else(|| tag.strip_prefix(b"#")) {
            !tags.contains(&negative)
        } else {
            tags.contains(&tag.as_slice())
        }
    })
}

pub fn available(ranges: &[AddressRange], address: Ipv4Addr, tags: &[&[u8]]) -> Option<usize> {
    if ranges.iter().any(|range| range.router == address) {
        return None;
    }
    ranges.iter().position(|range| {
        range.kind == RangeKind::Dynamic
            && range.contains(address)
            && match_tags(&range.filter, tags, true)
    })
}

pub fn narrow(ranges: &[AddressRange], address: Ipv4Addr, tags: &[&[u8]]) -> Option<usize> {
    available(ranges, address, tags)
        .or_else(|| {
            ranges.iter().position(|range| {
                range.kind == RangeKind::Static
                    && range.same_subnet(address)
                    && match_tags(&range.filter, tags, true)
            })
        })
        .or_else(|| {
            ranges.iter().position(|range| {
                range.kind != RangeKind::Proxy
                    && range.same_subnet(address)
                    && match_tags(&range.filter, tags, true)
            })
        })
}

/// The C SDBM seed intentionally wraps at 32 bits. Zero is reserved.
pub fn client_hash(bytes: &[u8]) -> u32 {
    let hash = bytes.iter().fold(0u32, |hash, &byte| {
        u32::from(byte)
            .wrapping_add(hash.wrapping_shl(6))
            .wrapping_add(hash.wrapping_shl(16))
            .wrapping_sub(hash)
    });
    hash.max(1)
}

pub fn seed(range: &AddressRange, hash: u32) -> Option<Ipv4Addr> {
    let start = u32::from(range.start);
    let count = u32::from(range.end).checked_sub(start)?.checked_add(1)?;
    Some(Ipv4Addr::from(
        start + hash.wrapping_add(range.epoch) % count,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    InUse,
    Available { offer_hash: u32 },
}

/// Performs the reference's two passes: tag-matched pools, then untagged pools.
/// A successful OFFER does not allocate a lease; REQUEST/BOOTP commits it later.
pub fn allocate_address(
    ranges: &mut [AddressRange],
    leases: &LeaseStore,
    hardware_id: &[u8],
    tags: &[&[u8]],
    consecutive: bool,
    mut reserved: impl FnMut(Ipv4Addr) -> bool,
    mut probe: impl FnMut(Ipv4Addr, u32) -> ProbeResult,
) -> Option<(usize, Ipv4Addr)> {
    let hash = client_hash(hardware_id);
    for allow_untagged in [false, true] {
        for index in 0..ranges.len() {
            let range = &ranges[index];
            if range.kind != RangeKind::Dynamic || !match_tags(&range.filter, tags, allow_untagged)
            {
                continue;
            }
            // Reject invalid/full-u32 ranges rather than C's zero divisor.
            let default_seed = seed(range, hash)?;
            let start = if consecutive {
                leases
                    .greatest_address(range.start, range.end)
                    .unwrap_or(range.start)
            } else {
                default_seed
            };
            let mut address = start;
            loop {
                let bits = u32::from(address);
                let class_c_broken =
                    bits & 0xe0000000 == 0xc0000000 && (bits & 255 == 0 || bits & 255 == 255);
                if !ranges.iter().any(|range| range.router == address)
                    && leases.get(address).is_none()
                    && !reserved(address)
                    && !class_c_broken
                {
                    if consecutive && ranges[index].epoch != 0 {
                        ranges[index].epoch -= 1;
                    } else {
                        match probe(address, hash) {
                            ProbeResult::Available { offer_hash }
                                if !consecutive || offer_hash == hash =>
                            {
                                return Some((index, address))
                            }
                            ProbeResult::InUse if !consecutive => {
                                ranges[index].epoch = ranges[index].epoch.wrapping_add(1)
                            }
                            _ => {}
                        }
                    }
                }
                address = if address == ranges[index].end {
                    ranges[index].start
                } else {
                    Ipv4Addr::from(bits.wrapping_add(1))
                };
                if address == start {
                    break;
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range() -> AddressRange {
        AddressRange {
            start: Ipv4Addr::new(192, 0, 2, 10),
            end: Ipv4Addr::new(192, 0, 2, 12),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 0, 2, 1),
            local: Ipv4Addr::new(192, 0, 2, 1),
            lease_time: 43200,
            kind: RangeKind::Dynamic,
            filter: vec![],
            epoch: 0,
        }
    }

    #[test]
    fn tags_match_all_and_preserve_negative_legacy_form() {
        assert!(!match_tags(&[], &[], false));
        assert!(match_tags(&[], &[], true));
        assert!(match_tags(
            &[b"lan".to_vec(), b"!blocked".to_vec(), b"#guest".to_vec()],
            &[b"lan"],
            false
        ));
        assert!(!match_tags(
            &[b"lan".to_vec(), b"!blocked".to_vec()],
            &[b"lan", b"blocked"],
            true
        ));
    }

    #[test]
    fn offer_is_not_a_committed_lease_and_tagged_pool_has_priority() {
        let untagged = range();
        let mut tagged = range();
        tagged.start = Ipv4Addr::new(192, 0, 2, 20);
        tagged.end = tagged.start;
        tagged.filter.push(b"lan".to_vec());
        let leases = LeaseStore::new(10);
        let result = allocate_address(
            &mut [untagged, tagged],
            &leases,
            &[1, 2, 3],
            &[b"lan"],
            false,
            |_| false,
            |_, hash| ProbeResult::Available { offer_hash: hash },
        );
        assert_eq!(result, Some((1, Ipv4Addr::new(192, 0, 2, 20))));
        assert!(leases.is_empty());
    }

    #[test]
    fn no_available_address_terminates_and_perturbs_epoch_only_on_conflict() {
        let mut ranges = [range()];
        let leases = LeaseStore::new(10);
        let mut calls = 0;
        assert!(allocate_address(
            &mut ranges,
            &leases,
            &[1],
            &[],
            false,
            |_| false,
            |_, _| {
                calls += 1;
                ProbeResult::InUse
            }
        )
        .is_none());
        assert_eq!(calls, 3);
        assert_eq!(ranges[0].epoch, 3);
    }

    #[test]
    fn router_is_never_dynamically_available() {
        let first = range();
        let mut second = range();
        second.router = first.start;
        assert_eq!(available(&[first.clone(), second], first.start, &[]), None);
        let mut static_range = first.clone();
        static_range.kind = RangeKind::Static;
        assert_eq!(
            narrow(&[static_range], Ipv4Addr::new(192, 0, 2, 99), &[]),
            Some(0)
        );
    }

    #[test]
    fn seed_and_wrap_boundaries() {
        assert_eq!(client_hash(&[]), 1);
        assert_eq!(client_hash(&[1]), 1);
        assert_eq!(client_hash(&[1, 2]), 65601);
        let mut value = range();
        value.epoch = u32::MAX;
        assert_eq!(seed(&value, 1), Some(value.start));
        value.start = Ipv4Addr::UNSPECIFIED;
        value.end = Ipv4Addr::BROADCAST;
        assert_eq!(seed(&value, 1), None);
    }
}
