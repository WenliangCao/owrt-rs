//! domain.c selectors consume the latest C enumeration independently of DNS
//! listener selection and IPv6 forward eligibility.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct DomainAddress {
    pub label: Vec<u8>,
    pub address: IpAddr,
    pub prefix: u8,
}

#[derive(Clone, Debug, Default)]
pub struct DomainInterfaces {
    pub addresses: Vec<DomainAddress>,
}

impl DomainInterfaces {
    pub fn matches(&self, interface: &[u8], address: IpAddr) -> bool {
        self.addresses.iter().any(|entry| {
            let label = entry
                .label
                .split(|&byte| byte == 0)
                .next()
                .unwrap_or_default();
            let same_label = label.iter().copied().chain([0]).take(16).eq(interface
                .iter()
                .copied()
                .chain([0])
                .take(16));
            if !same_label {
                return false;
            }
            match (entry.address, address) {
                (IpAddr::V4(source), IpAddr::V4(address)) => {
                    // AArch64 is_same_net_prefix shares the image's /0=>/32
                    // shift behavior, unlike its IPv6 /0 comparison.
                    let mask = u32::MAX.wrapping_shl(32u32.wrapping_sub(u32::from(entry.prefix)));
                    u32::from(source) & mask == u32::from(address) & mask
                }
                (IpAddr::V6(source), IpAddr::V6(address)) => {
                    let mask = u128::MAX
                        .checked_shl(128u32.wrapping_sub(u32::from(entry.prefix)))
                        .unwrap_or(0);
                    u128::from(source) & mask == u128::from(address) & mask
                }
                _ => false,
            }
        })
    }
}

/// read_opts selects only the first token after a case-sensitive `search`.
/// An invalid first token overwrites a prior literal with NULL; later tokens
/// on that line are never a fallback. The next search line can recover it.
pub fn resolver_search_domain(bytes: &[u8], mut previous: Option<Vec<u8>>) -> Option<Vec<u8>> {
    for line in bytes.split(|&byte| byte == b'\n') {
        let mut tokens = line
            .split(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
            .filter(|token| !token.is_empty());
        if tokens.next() != Some(b"search".as_slice()) {
            continue;
        }
        if let Some(token) = tokens.next() {
            previous = crate::hosts::canonicalise(token);
            if previous.is_some() {
                break;
            }
        }
    }
    previous
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolver_first_token_assignment_preserves_image_latch_order() {
        assert_eq!(
            resolver_search_domain(
                b"domain ignored.test\nsearch first.test second.test\n",
                None
            ),
            Some(b"first.test".to_vec())
        );
        assert_eq!(
            resolver_search_domain(b"nameserver 127.0.0.2\n", Some(b"literal.test".to_vec())),
            Some(b"literal.test".to_vec())
        );
        assert_eq!(
            resolver_search_domain(
                b"search bad\x01name good.test\n",
                Some(b"literal.test".to_vec())
            ),
            None
        );
        assert_eq!(
            resolver_search_domain(
                b"search bad\x01name good.test\nsearch recovered.test\n",
                None
            ),
            Some(b"recovered.test".to_vec())
        );
    }
    #[test]
    fn domain_interface_labels_and_dual_family_subnets_are_independent() {
        let snapshot = DomainInterfaces {
            addresses: vec![
                DomainAddress {
                    label: b"lan:1".to_vec(),
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    prefix: 24,
                },
                DomainAddress {
                    label: b"lan".to_vec(),
                    address: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
                    prefix: 64,
                },
            ],
        };
        assert!(snapshot.matches(b"lan:1", "192.0.2.99".parse().unwrap()));
        assert!(!snapshot.matches(b"lan", "192.0.2.99".parse().unwrap()));
        assert!(snapshot.matches(b"lan", "2001:db8::99".parse().unwrap()));
        assert!(!snapshot.matches(b"lan*", "2001:db8::99".parse().unwrap()));
    }
}
