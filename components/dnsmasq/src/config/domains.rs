//! domain.c selectors consume the latest C enumeration independently of DNS
//! listener selection and IPv6 forward eligibility.
use std::net::IpAddr;
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};

/// option.c:760 atoi_check accepts decimal digits then the image atoi folds
/// them into a C int. Keep that signed result for the caller's range checks.
pub fn image_prefix_length(bytes: &[u8]) -> Result<i32, super::Error> {
    bytes
        .iter()
        .try_fold(0u32, |value, byte| {
            byte.is_ascii_digit()
                .then(|| value.wrapping_mul(10).wrapping_add(u32::from(byte - b'0')))
                .ok_or(super::Error("error"))
        })
        .map(|value| value as i32)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainAddress {
    pub label: Vec<u8>,
    pub address: IpAddr,
    pub prefix: u8,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
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
pub fn resolver_search_domain(bytes: &[u8], previous: Option<Vec<u8>>) -> Option<Vec<u8>> {
    resolver_search_domain_reader(bytes, previous)
}

/// get_line_alloc treats a read error as EOF and still returns a partial last
/// line. Stop reading as soon as the first valid search assignment is found.
pub fn resolver_search_domain_reader(
    mut reader: impl std::io::BufRead,
    mut previous: Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        line.clear();
        let finished = match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => false,
            Err(_) if line.is_empty() => break,
            Err(_) => true,
        };
        let line = line.split(|&byte| byte == 0).next().unwrap_or_default();
        let mut tokens = line
            .split(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
            .filter(|token| !token.is_empty());
        if tokens.next() != Some(b"search".as_slice()) {
            if finished {
                break;
            }
            continue;
        }
        if let Some(token) = tokens.next() {
            previous = crate::hosts::canonicalise(token);
            if previous.is_some() {
                break;
            }
        }
        if finished {
            break;
        }
    }
    previous
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;

    #[test]
    fn image_decimal_prefix_preserves_int_wrap_without_unsafe_arithmetic() {
        assert_eq!(image_prefix_length(b"4294967296"), Ok(0));
        assert_eq!(image_prefix_length(b"4294967295"), Ok(-1));
        assert_eq!(image_prefix_length(b"2147483648"), Ok(i32::MIN));
        assert_eq!(image_prefix_length(b""), Ok(0));
        assert!(image_prefix_length(b"-1").is_err());
    }
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
    fn resolver_read_error_keeps_partial_final_search_and_stops_after_assignment() {
        struct ErrorAfter {
            bytes: &'static [u8],
        }
        impl std::io::Read for ErrorAfter {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                let available = self.fill_buf()?;
                let length = bytes.len().min(available.len());
                bytes[..length].copy_from_slice(&available[..length]);
                self.consume(length);
                Ok(length)
            }
        }
        impl std::io::BufRead for ErrorAfter {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                if self.bytes.is_empty() {
                    Err(std::io::Error::from_raw_os_error(5))
                } else {
                    Ok(self.bytes)
                }
            }
            fn consume(&mut self, count: usize) {
                self.bytes = &self.bytes[count..];
            }
        }
        assert_eq!(
            resolver_search_domain_reader(
                ErrorAfter {
                    bytes: b"search partial.test"
                },
                None
            ),
            Some(b"partial.test".to_vec())
        );
        assert_eq!(
            resolver_search_domain_reader(
                ErrorAfter {
                    bytes: b"search first.test\nsearch later.test"
                },
                None
            ),
            Some(b"first.test".to_vec())
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
