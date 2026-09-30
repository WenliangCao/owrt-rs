//! File tokenization and IPv4 restoration records from lease.c:23-172.
//! Tokens use the same scanf field widths, including splitting oversized tokens
//! across fields. Files are parsed without opening paths or executing init hooks.

use std::net::Ipv4Addr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRecord {
    pub address: Ipv4Addr,
    pub expires: i64,
    pub hardware_type: u32,
    pub hardware_address: Vec<u8>,
    pub client_id: Option<Vec<u8>>,
    pub hostname: Option<Vec<u8>>,
    pub agent_id: Option<Vec<u8>>,
    pub vendor_class: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeaseFile {
    /// File order, which is reversed when inserted into C's active lease list.
    pub records: Vec<LeaseRecord>,
    pub invalid_records: usize,
    pub clean_end: bool,
}

struct Tokens<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Tokens<'a> {
    fn take(&mut self, limit: usize) -> Option<&'a [u8]> {
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
        let start = self.position;
        while self.position - start < limit
            && self
                .bytes
                .get(self.position)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            self.position += 1;
        }
        (self.position != start).then(|| {
            let token = &self.bytes[start..self.position];
            &token[..token
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(token.len())]
        })
    }
}

pub fn parse(bytes: &[u8]) -> LeaseFile {
    let mut tokens = Tokens { bytes, position: 0 };
    let mut result = LeaseFile::default();
    loop {
        let Some(first) = tokens.take(255) else {
            result.clean_end = true;
            break;
        };
        let Some(second) = tokens.take(255) else {
            break;
        };
        if first == b"vendorclass" || first == b"agent-info" {
            if let Some(data) = tokens.take(764) {
                if let Some(address) = parse_address(second) {
                    if let Some(record) = result
                        .records
                        .iter_mut()
                        .rev()
                        .find(|record| record.address == address)
                    {
                        let (parsed, _) = parse_hex(data, 255, false);
                        if let Some(parsed) = parsed {
                            if first == b"vendorclass" {
                                record.vendor_class = Some(parsed);
                            } else {
                                record.agent_id = Some(parsed);
                            }
                        }
                    }
                }
            }
            continue;
        }
        let address = tokens.take(64);
        let hostname = tokens.take(255);
        let client_id = tokens.take(764);
        let (Some(address), Some(hostname), Some(client_id)) = (address, hostname, client_id)
        else {
            result.invalid_records += 1;
            continue;
        };
        let Some(address) = parse_address(address) else {
            result.invalid_records += 1;
            continue;
        };
        let (hardware, mut hardware_type) = parse_hex(second, 16, true);
        let hardware = hardware.unwrap_or_default();
        if hardware_type == 0 && !hardware.is_empty() {
            hardware_type = 1;
        }
        let client_id = if client_id == b"*" {
            None
        } else {
            parse_hex(client_id, 255, false)
                .0
                .filter(|bytes| !bytes.is_empty())
        };
        result.records.push(LeaseRecord {
            address,
            expires: decimal_prefix(first),
            hardware_type,
            hardware_address: hardware,
            client_id,
            hostname: (hostname != b"*").then(|| hostname.to_vec()),
            agent_id: None,
            vendor_class: None,
        });
    }
    result
}

fn parse_address(bytes: &[u8]) -> Option<Ipv4Addr> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// util.c:612-681. The source parser allows compact/odd-width groups, skips
/// repeated separators, and stops at maxlen without validating the suffix.
/// In lease.c input and output alias; a wildcard leaves that destination byte
/// unchanged. Preserve that defined aliasing behavior in a private work buffer.
pub fn parse_hex(input: &[u8], maximum: usize, mut typed: bool) -> (Option<Vec<u8>>, u32) {
    let mut work = input.to_vec();
    work.push(0);
    let mut position = 0;
    let mut written = 0;
    let mut hardware_type = 0;
    while written < maximum {
        let mut end = position;
        while work[end] != 0 && !b":- ".contains(&work[end]) {
            if work[end] != b'*' && !work[end].is_ascii_hexdigit() {
                return (None, hardware_type);
            }
            end += 1;
        }
        let delimiter = work[end];
        if end != position {
            if delimiter == b'-' && written == 0 && typed {
                hardware_type = hexadecimal_prefix(&work[position..end]) as u32;
                typed = false;
            } else if &work[position..end] == b"*" {
                written += 1;
            } else {
                let mut cursor = position;
                while cursor < end && written < maximum {
                    let next = (cursor + 2).min(end);
                    let pair = &work[cursor..next];
                    if pair.contains(&b'*') {
                        return (None, hardware_type);
                    }
                    let value = hexadecimal_prefix(pair) as u8;
                    work[written] = value;
                    written += 1;
                    cursor = next;
                }
            }
        }
        if delimiter == 0 {
            break;
        }
        position = end + 1;
    }
    work.truncate(written);
    (Some(work), hardware_type)
}

fn hexadecimal_prefix(bytes: &[u8]) -> i64 {
    bytes
        .iter()
        .take_while(|byte| byte.is_ascii_hexdigit())
        .fold(0i64, |value, byte| {
            value
                .saturating_mul(16)
                .saturating_add(i64::from((*byte as char).to_digit(16).unwrap()))
        })
}

fn decimal_prefix(bytes: &[u8]) -> i64 {
    let (negative, digits) = match bytes.first() {
        Some(b'-') => (true, &bytes[1..]),
        Some(b'+') => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    let mut value = 0i64;
    for byte in digits.iter().take_while(|byte| byte.is_ascii_digit()) {
        if negative {
            value = value
                .saturating_mul(10)
                .saturating_sub(i64::from(byte - b'0'));
        } else {
            value = value
                .saturating_mul(10)
                .saturating_add(i64::from(byte - b'0'));
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_basic_and_extension_records() {
        let result = parse(b"200 00:01:02:03:04:05 192.0.2.7 host 01:02\n0 06-aabbcc 192.0.2.8 * *\nagent-info 192.0.2.7 01:02:03\nvendorclass 192.0.2.7 74:65:73:74\n");
        assert!(result.clean_end);
        assert_eq!(result.invalid_records, 0);
        assert_eq!(result.records[0].expires, 200);
        assert_eq!(result.records[0].agent_id, Some(vec![1, 2, 3]));
        assert_eq!(result.records[0].vendor_class, Some(b"test".to_vec()));
        assert_eq!(result.records[1].hardware_type, 6);
        assert_eq!(result.records[1].hardware_address, [0xaa, 0xbb, 0xcc]);
        assert_eq!(result.records[1].hostname, None);
    }

    #[test]
    fn malformed_hex_clears_identity_as_c_does() {
        let result = parse(b"123junk nothex 192.0.2.1 * broken\n");
        assert_eq!(result.records[0].expires, 123);
        assert!(result.records[0].hardware_address.is_empty());
        assert_eq!(result.records[0].hardware_type, 0);
        assert_eq!(result.records[0].client_id, None);
    }

    #[test]
    fn compact_odd_hex_and_limit_semantics() {
        assert_eq!(
            parse_hex(b"abc:1::", 16, false),
            (Some(vec![0xab, 0x0c, 1]), 0)
        );
        assert_eq!(parse_hex(b"01:02:invalid", 2, false), (Some(vec![1, 2]), 0));
        assert_eq!(parse_hex(b"01:*", 16, false), (Some(vec![1, b'1']), 0));
        assert_eq!(parse_hex(b"01-", 16, true), (Some(vec![]), 1));
    }

    #[test]
    fn scanf_fields_span_lines_and_truncated_tail_is_reported() {
        let result = parse(b"200 010203\n192.0.2.1\nhost *\ntrailing");
        assert_eq!(result.records.len(), 1);
        assert!(!result.clean_end);
        assert_eq!(decimal_prefix(b"-9223372036854775809"), i64::MIN);
    }
}
