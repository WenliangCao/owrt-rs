//! Image option.c dumpfile/dumpmask state; opening belongs to the startup owner.
use super::{Directive, Error};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DumpConfig {
    pub file: Option<PathBuf>,
    pub mask: i32,
}

impl Default for DumpConfig {
    fn default() -> Self {
        Self {
            file: None,
            mask: -1,
        }
    }
}

impl DumpConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        match directive.name.as_slice() {
            b"dumpfile" => {
                let bytes = directive
                    .argument
                    .as_ref()
                    .ok_or(Error("missing parameter"))?
                    .decoded();
                self.file = (!bytes.is_empty()).then(|| std::ffi::OsString::from_vec(bytes).into());
            }
            b"dumpmask" => {
                let bytes = directive
                    .argument
                    .as_ref()
                    .ok_or(Error("missing parameter"))?
                    .encoded();
                // option.c passes the encoded argument directly to strtol;
                // unlike dumpfile, this consumer does not unhide metacharacters.
                self.mask = mask(bytes);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

// The C caller does not validate strtol's end pointer or errno. Keep its
// ordinary base-zero/sign/trailing-input behavior and long-width narrowing.
fn mask(bytes: &[u8]) -> i32 {
    let bytes = &bytes[bytes
        .iter()
        // musl strtol uses C isspace, which also accepts vertical tab.
        .position(|c| !matches!(c, b' ' | b'\t'..=b'\r'))
        .unwrap_or(bytes.len())..];
    let (negative, bytes) = bytes
        .strip_prefix(b"-")
        .map_or((false, bytes), |v| (true, v));
    let bytes = if negative {
        bytes
    } else {
        bytes.strip_prefix(b"+").unwrap_or(bytes)
    };
    let (radix, bytes) = if bytes.len() > 2
        && bytes[0] == b'0'
        && matches!(bytes[1], b'x' | b'X')
        && bytes[2].is_ascii_hexdigit()
    {
        (16, &bytes[2..])
    } else if bytes.first() == Some(&b'0') {
        (8, bytes)
    } else {
        (10, bytes)
    };
    let limit = i64::MAX as u64 + u64::from(negative);
    let mut value = 0u64;
    for &byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => break,
        };
        if digit >= radix {
            break;
        }
        value = value.saturating_mul(radix).saturating_add(digit).min(limit);
    }
    if negative {
        value.wrapping_neg() as i32
    } else {
        value as i32
    }
}

#[cfg(test)]
mod tests {
    use super::{mask, DumpConfig};
    use crate::config::{lex_line, Directive, EncodedArg};
    #[test]
    fn directive_mask_keeps_the_c_strtol_input_encoding() {
        let mut config = DumpConfig::default();
        config
            .apply(&Directive {
                name: b"dumpmask".to_vec(),
                argument: Some(EncodedArg::command_line(b"\x0b1")),
            })
            .unwrap();
        assert_eq!(config.mask, 1);
        let directive = lex_line(b"dumpmask=\"7\"").unwrap().unwrap();
        config.apply(&directive).unwrap();
        assert_eq!(config.mask, 0);
    }
    #[test]
    fn unchecked_base_zero_mask_uses_sign_and_stops_at_first_non_digit() {
        for (bytes, value) in [
            (b"15".as_slice(), 15),
            (b"\x0b15", 15),
            (b"017", 15),
            (b"0x0fignored", 15),
            (b"-1", -1),
            (b"09", 0),
            (b"invalid", 0),
        ] {
            assert_eq!(mask(bytes), value);
        }
    }
}
