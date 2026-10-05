//! File tokenization and IPv4 restoration records from lease.c:23-172.
//! Tokens use the same scanf field widths, including splitting oversized tokens
//! across fields. Files are parsed without opening paths or executing init hooks.

use std::io::{self, BufRead};
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
    pub warnings: Vec<Vec<u8>>,
}

struct Tokens<R> {
    reader: R,
}

fn scanf_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

impl<R: BufRead> Tokens<R> {
    fn take(&mut self, limit: usize) -> io::Result<Option<Vec<u8>>> {
        loop {
            let buffer = self.reader.fill_buf()?;
            if buffer.is_empty() {
                return Ok(None);
            }
            let length = buffer.len();
            let spaces = buffer.iter().take_while(|byte| scanf_space(**byte)).count();
            self.reader.consume(spaces);
            if spaces != length {
                break;
            }
        }
        let mut token = Vec::new();
        loop {
            let buffer = self.reader.fill_buf()?;
            let count = buffer
                .iter()
                .take_while(|byte| !scanf_space(**byte))
                .count()
                .min(limit - token.len());
            let done = count < buffer.len() || count == 0 || token.len() + count == limit;
            token.extend_from_slice(&buffer[..count]);
            self.reader.consume(count);
            if done {
                break;
            }
        }
        token.truncate(
            token
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(token.len()),
        );
        Ok(Some(token))
    }
}

pub fn parse(bytes: &[u8]) -> LeaseFile {
    parse_reader(bytes, usize::MAX).expect("reading a byte slice cannot fail")
}

/// lease.c read_leases uses EC_MISC for capacity exhaustion, distinct from
/// EC_FILE for an open/read failure. Preserve that distinction through io::Error.
#[derive(Debug)]
pub struct CapacityExceeded;

impl std::fmt::Display for CapacityExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("too many stored leases")
    }
}

impl std::error::Error for CapacityExceeded {}

/// An early fatal read/capacity error must retain diagnostics from preceding
/// records. C emitted these while scanning, before its final startup failure.
#[derive(Debug)]
struct ParseFailure {
    source: io::Error,
    warnings: Vec<Vec<u8>>,
}

impl std::fmt::Display for ParseFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = self.source.to_string();
        let suffix = self
            .source
            .raw_os_error()
            .map(|code| format!(" (os error {code})"));
        formatter.write_str(
            suffix
                .as_ref()
                .and_then(|suffix| description.strip_suffix(suffix))
                .unwrap_or(&description),
        )
    }
}

impl std::error::Error for ParseFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub fn warnings(error: &io::Error) -> &[Vec<u8>] {
    error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ParseFailure>())
        .map_or(&[], |failure| &failure.warnings)
}

pub fn capacity_exceeded(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|cause| {
        cause.is::<CapacityExceeded>()
            || cause
                .downcast_ref::<ParseFailure>()
                .is_some_and(|failure| capacity_exceeded(&failure.source))
    })
}

fn failure(file: &mut LeaseFile, source: io::Error) -> io::Error {
    if file.warnings.is_empty() {
        return source;
    }
    io::Error::new(
        source.kind(),
        ParseFailure {
            source,
            warnings: std::mem::take(&mut file.warnings),
        },
    )
}

/// Stream a startup database without allocating its complete contents. Field
/// widths stay identical to scanf and capacity exhaustion is startup-fatal.
pub fn parse_reader(reader: impl BufRead, maximum_records: usize) -> io::Result<LeaseFile> {
    let mut warnings = Vec::new();
    let parsed = parse_reader_with_warnings(reader, maximum_records, |warning| {
        warnings.push(warning);
        Ok(())
    });
    match parsed {
        Ok(mut file) => {
            file.warnings = warnings;
            Ok(file)
        }
        Err(error) if warnings.is_empty() => Err(error),
        Err(error) => Err(io::Error::new(
            error.kind(),
            ParseFailure {
                source: error,
                warnings,
            },
        )),
    }
}

/// Production startup emits each warning as it is scanned. Arbitrarily many
/// invalid rows therefore do not accumulate diagnostic text in daemon memory.
pub fn parse_reader_with_warnings(
    reader: impl BufRead,
    maximum_records: usize,
    mut emit: impl FnMut(Vec<u8>) -> io::Result<()>,
) -> io::Result<LeaseFile> {
    let mut tokens = Tokens { reader };
    let mut result = LeaseFile::default();
    loop {
        let Some(first) = tokens
            .take(255)
            .map_err(|error| failure(&mut result, error))?
        else {
            result.clean_end = true;
            break;
        };
        let Some(second) = tokens
            .take(255)
            .map_err(|error| failure(&mut result, error))?
        else {
            break;
        };
        if first == b"vendorclass" || first == b"agent-info" {
            if let Some(data) = tokens
                .take(764)
                .map_err(|error| failure(&mut result, error))?
            {
                if let Some(address) = parse_address(&second) {
                    if let Some(record) = result
                        .records
                        .iter_mut()
                        .rev()
                        .find(|record| record.address == address)
                    {
                        let (parsed, _) = parse_hex(&data, 255, false);
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
        let address = tokens
            .take(64)
            .map_err(|error| failure(&mut result, error))?;
        let hostname = tokens
            .take(255)
            .map_err(|error| failure(&mut result, error))?;
        let client_id = tokens
            .take(764)
            .map_err(|error| failure(&mut result, error))?;
        if address.is_none() || hostname.is_none() || client_id.is_none() {
            let mut message = b"ignoring invalid line in lease database: ".to_vec();
            for (index, field) in [
                first.as_slice(),
                second.as_slice(),
                address.as_deref().unwrap_or_default(),
                hostname.as_deref().unwrap_or_default(),
            ]
            .into_iter()
            .enumerate()
            {
                if index != 0 {
                    message.push(b' ');
                }
                message.extend_from_slice(field);
            }
            message.extend_from_slice(b" ...");
            emit(message)?;
            result.invalid_records += 1;
            continue;
        }
        let address = address.unwrap();
        let hostname = hostname.unwrap();
        let client_id = client_id.unwrap();
        let Some(address) = parse_address(&address) else {
            let mut message = b"ignoring invalid line in lease database, bad address: ".to_vec();
            message.extend_from_slice(&address);
            emit(message)?;
            result.invalid_records += 1;
            continue;
        };
        if result.records.len() >= maximum_records {
            return Err(failure(
                &mut result,
                io::Error::new(io::ErrorKind::InvalidData, CapacityExceeded),
            ));
        }
        let (hardware, mut hardware_type) = parse_hex(&second, 16, true);
        let hardware = hardware.unwrap_or_default();
        if hardware_type == 0 && !hardware.is_empty() {
            hardware_type = 1;
        }
        let client_id = if client_id == b"*" {
            None
        } else {
            parse_hex(&client_id, 255, false)
                .0
                .filter(|bytes| !bytes.is_empty())
        };
        result.records.push(LeaseRecord {
            address,
            expires: decimal_prefix(&first),
            hardware_type,
            hardware_address: hardware,
            client_id,
            hostname: (hostname != b"*").then(|| hostname.to_vec()),
            agent_id: None,
            vendor_class: None,
        });
    }
    Ok(result)
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
    // This image's musl atol accumulates in a wrapping signed long. Unlike
    // strtol, it does not report or saturate an out-of-range decimal value.
    let value = digits
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .fold(0i64, |value, byte| {
            value.wrapping_mul(10).wrapping_add(i64::from(byte - b'0'))
        });
    if negative {
        value.wrapping_neg()
    } else {
        value
    }
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
        assert_eq!(decimal_prefix(b"-9223372036854775809"), i64::MAX);
        assert_eq!(decimal_prefix(b"9223372036854775808"), i64::MIN);
    }

    #[test]
    fn streaming_keeps_scanf_whitespace_width_and_capacity_rules() {
        let bytes = b"200\x0b02:00:00:00:00:01\x0c192.0.2.10\thost *\n";
        for size in [1, 2, 7, 64] {
            let file =
                parse_reader(std::io::BufReader::with_capacity(size, &bytes[..]), 1).unwrap();
            assert!(file.clean_end);
            assert_eq!(file.records.len(), 1);
            assert_eq!(file.records[0].hostname.as_deref(), Some(&b"host"[..]));
        }
        assert_eq!(
            parse_reader(&bytes[..], 0).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn fatal_read_and_capacity_keep_preceding_record_diagnostics() {
        struct Failed<'a>(&'a [u8]);
        impl std::io::Read for Failed<'_> {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                unreachable!()
            }
        }
        impl BufRead for Failed<'_> {
            fn fill_buf(&mut self) -> io::Result<&[u8]> {
                if self.0.is_empty() {
                    Err(io::Error::from_raw_os_error(5))
                } else {
                    Ok(self.0)
                }
            }
            fn consume(&mut self, count: usize) {
                self.0 = &self.0[count..];
            }
        }
        let bytes = b"0 01 invalid bad *\n0 01 192.0.2.1 first *\n";
        let error = parse_reader(Failed(bytes), 2).unwrap_err();
        assert_eq!(
            warnings(&error),
            [b"ignoring invalid line in lease database, bad address: invalid".to_vec()]
        );
        assert!(!capacity_exceeded(&error));
        let error = parse_reader(&bytes[..], 0).unwrap_err();
        assert_eq!(warnings(&error).len(), 1);
        assert!(capacity_exceeded(&error));
    }

    #[test]
    fn production_warning_stream_does_not_retain_invalid_row_text() {
        let bytes = b"0 01 invalid bad *\n".repeat(10_000);
        let mut warnings = 0;
        let parsed = parse_reader_with_warnings(&bytes[..], 0, |_| {
            warnings += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(warnings, 10_000);
        assert_eq!(parsed.invalid_records, 10_000);
        assert!(parsed.clean_end && parsed.records.is_empty() && parsed.warnings.is_empty());
    }

    #[test]
    fn invalid_address_diagnostic_preserves_non_utf8_input_octets() {
        let parsed = parse(b"0 01 \xff bad *\n");
        assert_eq!(parsed.invalid_records, 1);
        assert_eq!(
            parsed.warnings,
            [b"ignoring invalid line in lease database, bad address: \xff".to_vec()]
        );
    }
}
