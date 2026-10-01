//! Ordinary IPv4 dhcp-host rules from option.c:4004-4244 and dhcp-common.c.

use super::{ip, Error};
use crate::config::EncodedArg;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareAddress {
    /// Zero matches every hardware type, as in config_has_mac.
    pub kind: u32,
    pub address: Vec<u8>,
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
}

/// util.c parse_hex without wildcard selectors. Like C, validate each whole
/// group, accept odd/compact groups, and stop at the hardware length limit.
fn hex(input: &[u8], maximum: usize, mut typed: bool) -> Result<HardwareAddress, Error> {
    let mut result = HardwareAddress {
        kind: 0,
        address: Vec::new(),
    };
    let mut rest = input;
    while result.address.len() < maximum {
        let end = rest
            .iter()
            .position(|b| b":- ".contains(b))
            .unwrap_or(rest.len());
        let group = &rest[..end];
        if group.contains(&b'*') {
            return Err(Error("DHCP host wildcard selectors are not implemented"));
        }
        if !group.iter().all(u8::is_ascii_hexdigit) {
            return Err(Error("bad DHCP host hex constant"));
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
            } else {
                for pair in group.chunks(2).take(maximum - result.address.len()) {
                    result.address.push(pair.iter().fold(0u8, |value, digit| {
                        value * 16 + (*digit as char).to_digit(16).unwrap() as u8
                    }));
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
                            hex(&bytes[3..], usize::MAX, false)?.address
                        } else {
                            part.decoded()[3..].to_vec()
                        });
                    }
                } else if [b"net:".as_slice(), b"set:", b"tag:"]
                    .iter()
                    .any(|prefix| bytes.starts_with(prefix))
                {
                    return Err(Error("DHCP host tag selectors are not implemented"));
                } else {
                    host.hardware.insert(0, hex(bytes, 16, true)?);
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
        if host.client_id.is_none() && host.hardware.is_empty() {
            return Err(Error("DHCP host name-only selectors are not implemented"));
        }
        Ok(host)
    }

    pub fn matches_hardware(&self, kind: u32, address: &[u8]) -> bool {
        self.hardware.iter().any(|hardware| {
            (hardware.kind == 0 || hardware.kind == kind) && hardware.address == address
        })
    }
}
