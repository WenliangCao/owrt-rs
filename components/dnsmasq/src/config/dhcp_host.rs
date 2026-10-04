//! Ordinary IPv4 dhcp-host rules from option.c:4004-4244 and dhcp-common.c.

use super::{ip, tags::TagPredicate, Error};
use crate::config::EncodedArg;
use std::net::Ipv4Addr;

pub(super) fn unsupported(_error: &Error) -> bool {
    false
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareAddress {
    /// Zero matches every hardware type, as in config_has_mac.
    pub kind: u32,
    pub address: Vec<u8>,
    /// Bit zero corresponds to the last byte, matching parse_hex.
    pub wildcard_mask: u16,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostConfig {
    pub address: Option<Ipv4Addr>,
    pub lease_time: Option<u32>,
    pub hostname: Option<Vec<u8>>,
    /// Configured suffix; it does not replace get_domain(address).
    pub domain: Option<Vec<u8>>,
    pub client_id: Option<Vec<u8>>,
    pub hardware: Vec<HardwareAddress>,
    pub ignore_client_id: bool,
    pub ignore: bool,
    pub set_tags: Vec<Vec<u8>>,
    pub filter: TagPredicate,
}

/// util.c parse_hex without wildcard selectors. Like C, validate each whole
/// group, accept odd/compact groups, and stop at the hardware length limit.
pub(super) fn parse_hardware(
    input: &[u8],
    maximum: usize,
    mut typed: bool,
    wildcards: bool,
) -> Result<HardwareAddress, Error> {
    let mut result = HardwareAddress {
        kind: 0,
        address: Vec::new(),
        wildcard_mask: 0,
    };
    let mut rest = input;
    while result.address.len() < maximum {
        let end = rest
            .iter()
            .position(|b| b":- ".contains(b))
            .unwrap_or(rest.len());
        let group = &rest[..end];
        if !group
            .iter()
            .all(|b| b.is_ascii_hexdigit() || (wildcards && *b == b'*'))
        {
            return Err(Error("bad hex constant"));
        }
        if !group.is_empty() {
            if typed && result.address.is_empty() && rest.get(end) == Some(&b'-') {
                result.kind = group
                    .iter()
                    .try_fold(0u32, |value, digit| {
                        value
                            .checked_mul(16)?
                            .checked_add((*digit as char).to_digit(16)?)
                    })
                    .ok_or(Error("DHCP hardware type exceeds defined integer range"))?;
                typed = false;
            } else if group == b"*" {
                result.address.push(0);
                result.wildcard_mask = (result.wildcard_mask << 1) | 1;
            } else {
                if group.contains(&b'*') {
                    return Err(Error("bad hex constant"));
                }
                for pair in group.chunks(2).take(maximum - result.address.len()) {
                    result.address.push(pair.iter().fold(0u8, |value, digit| {
                        value * 16 + (*digit as char).to_digit(16).unwrap() as u8
                    }));
                    result.wildcard_mask <<= 1;
                }
            }
        }
        if end == rest.len() {
            break;
        }
        rest = &rest[end + 1..];
    }
    Ok(result)
}

fn duration(input: &[u8]) -> Result<Option<u32>, Error> {
    let (digits, factor) = if input.len() > 1 {
        match input.last() {
            Some(b's' | b'S') => (&input[..input.len() - 1], 1),
            Some(b'm' | b'M') => (&input[..input.len() - 1], 60),
            Some(b'h' | b'H') => (&input[..input.len() - 1], 3600),
            Some(b'd' | b'D') => (&input[..input.len() - 1], 86400),
            Some(b'w' | b'W') => (&input[..input.len() - 1], 604800),
            _ => (input, 1),
        }
    } else {
        (input, 1)
    };
    if digits.iter().any(|b| !b.is_ascii_digit() && *b != b' ') {
        return Ok(None);
    }
    if !digits.iter().any(u8::is_ascii_digit) {
        return Ok(None);
    }
    // C checks every character, but atoi consumes only the first number.
    let value = digits
        .iter()
        .skip_while(|b| **b == b' ')
        .take_while(|b| b.is_ascii_digit())
        .try_fold(0u32, |value, digit| {
            value.checked_mul(10)?.checked_add(u32::from(digit - b'0'))
        })
        .and_then(|value| value.checked_mul(factor))
        .filter(|value| *value <= i32::MAX as u32)
        .ok_or(Error("DHCP host lease time exceeds defined C int range"))?;
    Ok(Some(value.max(120)))
}

impl HostConfig {
    pub(super) fn parse(argument: &EncodedArg, existing: &[Self]) -> Result<Self, Error> {
        let mut host = Self::default();
        for part in argument.split(b',') {
            let bytes = part.encoded();
            if bytes.contains(&b':') {
                if bytes
                    .get(..3)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"id:"))
                {
                    if bytes.get(3) == Some(&b'*') {
                        host.ignore_client_id = true;
                    } else {
                        host.client_id = Some(if bytes[3..].contains(&b':') {
                            parse_hardware(&bytes[3..], usize::MAX, false, false)?.address
                        } else {
                            part.decoded()[3..].to_vec()
                        });
                    }
                } else if bytes.starts_with(b"net:") || bytes.starts_with(b"set:") {
                    host.set_tags.insert(0, part.decoded()[4..].to_vec());
                } else if bytes.starts_with(b"tag:") {
                    let mut tags = host.filter.tags().to_vec();
                    tags.insert(0, part.decoded()[4..].to_vec());
                    host.filter = TagPredicate::from_tags(tags);
                } else {
                    host.hardware
                        .insert(0, parse_hardware(bytes, 16, true, true)?);
                }
            } else if let Ok(address) = ip(bytes) {
                if existing.iter().any(|entry| entry.address == Some(address)) {
                    return Err(Error("duplicate DHCP host IPv4 address"));
                }
                host.address = Some(address);
            } else if let Some(time) = duration(bytes)? {
                host.lease_time = Some(time);
            } else if bytes.iter().all(|b| *b == b' ') {
                // Empty/space-only comma fields have neither name nor time.
            } else if bytes == b"infinite" {
                host.lease_time = Some(u32::MAX);
            } else if bytes == b"ignore" {
                host.ignore = true;
            } else {
                if host.hostname.is_some() {
                    return Err(Error("DHCP host has multiple names"));
                }
                let mut name = crate::hosts::canonicalise(&part.decoded())
                    .ok_or(Error("bad DHCP host name"))?;
                let dot = name.iter().position(|b| *b == b'.').unwrap_or(name.len());
                if !name.first().is_some_and(u8::is_ascii_alphanumeric)
                    || !name[..dot]
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                {
                    return Err(Error("bad DHCP host name"));
                }
                if dot < name.len() {
                    host.domain = Some(name[dot + 1..].to_vec());
                    name.truncate(dot);
                }
                host.hostname = Some(name);
            }
        }
        Ok(host)
    }

    pub fn matches_hardware(&self, kind: u32, address: &[u8]) -> bool {
        self.hardware.iter().any(|hardware| {
            hardware.wildcard_mask == 0
                && (hardware.kind == 0 || hardware.kind == kind)
                && hardware.address == address
        })
    }

    /// C considers wildcard MACs only after client-id, exact MAC and hostname
    /// passes. A larger score wins, equal scores preserve list order.
    pub fn wildcard_score(&self, kind: u32, address: &[u8]) -> usize {
        self.hardware
            .iter()
            .filter_map(|hardware| {
                if hardware.wildcard_mask == 0
                    || hardware.address.len() != address.len()
                    || (hardware.kind != 0 && hardware.kind != kind)
                {
                    return None;
                }
                let mut score = 1;
                for (index, (left, right)) in hardware.address.iter().zip(address).enumerate() {
                    if hardware.wildcard_mask & (1 << (address.len() - index - 1)) == 0 {
                        if left != right {
                            return None;
                        }
                        score += 1;
                    }
                }
                Some(score)
            })
            .max()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_tags_name_only_and_masked_hardware_preserve_distinct_selectors() {
        let host = HostConfig::parse(
            &EncodedArg::command_line(
                b"tag:lan,set:chosen,net:legacy,02:00:*:00:00:01,host,192.0.2.10",
            ),
            &[],
        )
        .unwrap();
        assert!(host.filter.matches_with(&[b"lan"], false));
        assert!(!host.filter.matches_with(&[], false));
        assert_eq!(host.set_tags, [b"legacy".to_vec(), b"chosen".to_vec()]);
        assert!(!host.matches_hardware(1, &[2, 0, 9, 0, 0, 1]));
        assert_eq!(host.wildcard_score(1, &[2, 0, 9, 0, 0, 1]), 6);
        assert_eq!(host.wildcard_score(1, &[2, 1, 9, 0, 0, 1]), 0);
        let named = HostConfig::parse(&EncodedArg::command_line(b"named,192.0.2.11"), &[]).unwrap();
        assert!(named.hardware.is_empty());
        assert_eq!(named.hostname.as_deref(), Some(b"named".as_slice()));
    }
    #[test]
    fn compact_and_typed_hex_keep_c_octet_limits_and_mask_positions() {
        let address = parse_hardware(b"1-0200:ab:*:00:01", 16, true, true).unwrap();
        assert_eq!(address.kind, 1);
        assert_eq!(address.address, [2, 0, 171, 0, 0, 1]);
        assert_eq!(address.wildcard_mask, 4);
        assert!(parse_hardware(b"02:0*:00", 16, true, true).is_err());
        assert!(parse_hardware(b"01:*", usize::MAX, false, false).is_err());
    }
}
