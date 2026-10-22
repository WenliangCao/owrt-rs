//! option.c:2621-2801 and domain.c's synthetic range representation.
use super::{Directive, EncodedArg, Error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub enum SynthRange {
    V4 { start: u32, end: u32 },
    V6 { start: u128, end: u128, prefix: i32 },
}

#[derive(Clone, Debug)]
pub struct SynthDomain {
    pub domain: Vec<u8>,
    pub prefix: Vec<u8>,
    pub indexed: bool,
    pub range: SynthRange,
}

#[derive(Clone, Debug, Default)]
pub struct SynthConfig {
    /// option.c prepends declarations; the newest matching range wins.
    pub domains: Vec<SynthDomain>,
}

fn canonical(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    crate::hosts::canonicalise(bytes).ok_or(Error("error"))
}

fn address(bytes: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn width(bytes: &[u8]) -> Result<i32, Error> {
    bytes
        .iter()
        .try_fold(0u32, |value, byte| {
            byte.is_ascii_digit()
                .then(|| value.wrapping_mul(10).wrapping_add(u32::from(byte - b'0')))
                .ok_or(Error("error"))
        })
        .map(|value| value as i32)
}

pub fn parse(argument: &EncodedArg) -> Result<SynthDomain, Error> {
    let (domain, rest) = argument.split_once(b',');
    let domain = canonical(&domain.decoded())?;
    // C unhides the complete range before looking for slash/comma separators.
    let rest = EncodedArg::command_line(&rest.ok_or(Error("error"))?.decoded());
    let (start, subnet) = rest.split_once(b'/');
    let (range, prefix, limit) = if let Some(subnet) = subnet {
        let (size, prefix) = subnet.split_once(b',');
        let size = width(size.encoded())?;
        match address(start.encoded()).ok_or(Error("error"))? {
            IpAddr::V4(start) => {
                if size > 32 {
                    return Err(Error("bad prefix length"));
                }
                // Actual AArch64 image /0 shifts by 32 and produces mask zero.
                let mask = 1u32
                    .wrapping_shl(32u32.wrapping_sub(size as u32))
                    .wrapping_sub(1);
                let start = u32::from(start) & !mask;
                (
                    SynthRange::V4 {
                        start,
                        end: start | mask,
                    },
                    prefix,
                    24,
                )
            }
            IpAddr::V6(start) => {
                // util.c:524 converts a negative prefix byte count to size_t
                // for memcmp, reading outside in6_addr. Do not reproduce it.
                if !(0..=128).contains(&size) {
                    return Err(Error("bad prefix length"));
                }
                let mask = if size <= 64 {
                    u64::MAX
                } else {
                    1u64.wrapping_shl(128u32.wrapping_sub(size as u32))
                        .wrapping_sub(1)
                } as u128;
                let start = u128::from(start);
                (
                    SynthRange::V6 {
                        start: start & !mask,
                        end: start | mask,
                        prefix: size,
                    },
                    prefix,
                    17,
                )
            }
        }
    } else {
        let parts = rest.split(b',');
        let start = address(parts[0].encoded()).ok_or(Error("error"))?;
        let end = match parts.get(1) {
            Some(end) => address(end.encoded()).ok_or(Error("error"))?,
            None => start,
        };
        let range = match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => SynthRange::V4 {
                start: u32::from(start),
                end: u32::from(end),
            },
            (IpAddr::V6(start), IpAddr::V6(end)) => SynthRange::V6 {
                start: u128::from(start),
                end: u128::from(end),
                prefix: 0,
            },
            _ => return Err(Error("error")),
        };
        (range, parts.get(2).cloned(), 47)
    };
    let mut prefix = match prefix {
        Some(prefix) => canonical(&prefix.decoded()).map_err(|_| Error("bad prefix"))?,
        None => Vec::new(),
    };
    if prefix.len() > limit {
        return Err(Error("bad prefix"));
    }
    let indexed = prefix.last() == Some(&b'*');
    if indexed {
        prefix.pop();
        if matches!(range, SynthRange::V6 { prefix, .. } if prefix < 64) {
            return Err(Error("prefix length too small"));
        }
    }
    Ok(SynthDomain {
        domain,
        prefix,
        indexed,
        range,
    })
}

impl SynthConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        if directive.name != b"synth-domain" {
            return Ok(false);
        }
        self.domains.insert(
            0,
            parse(
                directive
                    .argument
                    .as_ref()
                    .ok_or(Error("missing parameter"))?,
            )?,
        );
        Ok(true)
    }

    pub fn forward(&self, name: &[u8], ipv6: bool) -> Option<IpAddr> {
        self.domains
            .iter()
            .find_map(|domain| domain.forward(name, ipv6))
    }

    pub fn reverse(&self, address: IpAddr) -> Option<Vec<u8>> {
        self.domains
            .iter()
            .find_map(|domain| domain.reverse(address))
    }

    pub fn name_exists(&self, name: &[u8]) -> bool {
        self.forward(name, false).is_some() || self.forward(name, true).is_some()
    }
}

impl SynthRange {
    fn contains(&self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { start, end }, IpAddr::V4(address)) => {
                (*start..=*end).contains(&u32::from(address))
            }
            (Self::V6 { start, end, prefix }, IpAddr::V6(address)) => {
                let address = u128::from(address);
                if *prefix >= 64 {
                    address >> 64 == start >> 64
                        && (address as u64) >= (*start as u64)
                        && (address as u64) <= (*end as u64)
                } else {
                    let mask = u128::MAX
                        .checked_shl(128u32.wrapping_sub(*prefix as u32))
                        .unwrap_or(0);
                    address & mask == start & mask
                }
            }
            _ => false,
        }
    }
}

impl SynthDomain {
    fn forward(&self, name: &[u8], ipv6: bool) -> Option<IpAddr> {
        if !name
            .get(..self.prefix.len())?
            .eq_ignore_ascii_case(&self.prefix)
        {
            return None;
        }
        let tail = &name[self.prefix.len()..];
        let at = tail.iter().position(|&byte| byte == b'.')?;
        let number = &tail[..at];
        if !tail[at + 1..].eq_ignore_ascii_case(&self.domain) {
            return None;
        }
        let address = if self.indexed {
            if !number.iter().all(u8::is_ascii_digit) {
                return None;
            }
            match self.range {
                SynthRange::V4 { start, end } if !ipv6 => {
                    let index = number.iter().fold(0u32, |value, byte| {
                        value.wrapping_mul(10).wrapping_add(u32::from(byte - b'0'))
                    });
                    if index > end.wrapping_sub(start) {
                        return None;
                    }
                    IpAddr::V4(Ipv4Addr::from(start.wrapping_add(index)))
                }
                SynthRange::V6 { start, end, .. } if ipv6 => {
                    let index = number.iter().fold(0u64, |value, byte| {
                        value.wrapping_mul(10).wrapping_add(u64::from(byte - b'0'))
                    });
                    if index > (end as u64).wrapping_sub(start as u64) {
                        return None;
                    }
                    IpAddr::V6(Ipv6Addr::from(
                        (start & !(u64::MAX as u128))
                            | u128::from((start as u64).wrapping_add(index)),
                    ))
                }
                _ => return None,
            }
        } else {
            let allowed = |byte: &u8| {
                byte.is_ascii_digit() || *byte == b'-' || (ipv6 && byte.is_ascii_hexdigit())
            };
            if !number.iter().all(allowed) {
                return None;
            }
            let text: Vec<_> = number
                .iter()
                .map(|&byte| {
                    if byte == b'-' {
                        if ipv6 {
                            b':'
                        } else {
                            b'.'
                        }
                    } else {
                        byte
                    }
                })
                .collect();
            let address = address(&text)?;
            if address.is_ipv6() != ipv6 || !self.range.contains(address) {
                return None;
            }
            address
        };
        Some(address)
    }

    fn reverse(&self, address: IpAddr) -> Option<Vec<u8>> {
        if !self.range.contains(address) {
            return None;
        }
        let label = match (&self.range, address, self.indexed) {
            (SynthRange::V4 { start, .. }, IpAddr::V4(address), true) => {
                u32::from(address).wrapping_sub(*start).to_string()
            }
            (SynthRange::V6 { start, .. }, IpAddr::V6(address), true) => (u128::from(address)
                as u64)
                .wrapping_sub(*start as u64)
                .to_string(),
            (_, IpAddr::V4(address), false) => address.to_string().replace('.', "-"),
            (_, IpAddr::V6(address), false) => address
                .segments()
                .map(|segment| format!("{segment:04x}"))
                .join("-"),
            _ => return None,
        };
        let mut name = self.prefix.clone();
        name.extend_from_slice(label.as_bytes());
        name.push(b'.');
        name.extend_from_slice(&self.domain);
        // domain.c:153-209 constructs PTR targets without DNS label or wire
        // length checks. Only publish a target the ordinary encoder can emit;
        // its root fallback would fabricate a PTR for an invalid target.
        crate::dns::wire::Name::from_dotted_bytes(&name)
            .ok()
            .map(|_| name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_ipv6_prefix_is_rejected_before_image_out_of_bounds_comparison() {
        assert!(matches!(
            parse(&EncodedArg::command_line(b"test,2001:db8::7/4294967295")),
            Err(Error("bad prefix length"))
        ));
        assert!(parse(&EncodedArg::command_line(b"test,2001:db8::7/4294967296")).is_ok());
        let ipv4 = parse(&EncodedArg::command_line(b"test,192.0.2.7/4294967295")).unwrap();
        assert!(ipv4.range.contains("192.0.2.6".parse().unwrap()));
        assert!(!ipv4.range.contains("192.0.2.5".parse().unwrap()));
    }
    #[test]
    fn reverse_derivation_requires_representable_target() {
        let mut argument = b"test,2001:db8::7,2001:db8::9,".to_vec();
        argument.extend_from_slice(&[b'p'; 47]);
        let domain = parse(&EncodedArg::command_line(&argument)).unwrap();
        assert!(domain.reverse("2001:db8::7".parse().unwrap()).is_none());
        let mut forward = [b'p'; 47].to_vec();
        forward.extend_from_slice(b"2001-db8--7.test");
        assert_eq!(
            domain.forward(&forward, true),
            Some("2001:db8::7".parse().unwrap())
        );

        for (prefix, valid) in [(24, true), (25, false)] {
            let argument = format!("test,2001:db8::7,2001:db8::9,{}", "p".repeat(prefix));
            let domain = parse(&EncodedArg::command_line(argument.as_bytes())).unwrap();
            assert_eq!(
                domain.reverse("2001:db8::7".parse().unwrap()).is_some(),
                valid
            );
        }
        for (last_label, valid) in [(51, true), (52, false)] {
            let suffix = format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(last_label)
            );
            let argument = format!("{suffix},192.0.2.7,192.0.2.9");
            let domain = parse(&EncodedArg::command_line(argument.as_bytes())).unwrap();
            assert_eq!(
                domain.reverse("192.0.2.7".parse().unwrap()).is_some(),
                valid
            );
        }
    }

    #[test]
    fn image_explicit_ipv6_range_and_indexed_literal_boundaries() {
        let domain = parse(&EncodedArg::command_line(b"test,2001:db8::7,2001:db8::9")).unwrap();
        assert!(domain.range.contains("fd00::42".parse().unwrap()));
        assert_eq!(
            domain.reverse("2001:db8::7".parse().unwrap()).unwrap(),
            b"2001-0db8-0000-0000-0000-0000-0000-0007.test"
        );
        let domain = parse(&EncodedArg::command_line(b"test,192.0.2.7,192.0.2.9,p*")).unwrap();
        assert_eq!(
            domain.forward(b"p0002.test", false),
            Some("192.0.2.9".parse().unwrap())
        );
        assert!(domain.forward(b"p3.test", false).is_none());
        assert_eq!(
            domain.forward(b"p4294967296.test", false),
            Some("192.0.2.7".parse().unwrap())
        );
    }
}
