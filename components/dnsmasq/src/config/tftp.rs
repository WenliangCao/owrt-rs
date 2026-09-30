//! TFTP scalar configuration consumed by the Linux listener.
//!
//! This keeps the wire/path policy in `tftp_runtime` while preserving the
//! option.c spelling and byte-oriented arguments at the loader boundary.

use super::{validate_directive, Directive, EncodedArg, Error};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TftpConfig {
    pub enabled: bool,
    pub root: Option<Vec<u8>>,
    pub lowercase: bool,
    pub no_block_size: bool,
    pub secure: bool,
    pub no_fail: bool,
    pub single_port: bool,
    pub max_transfers: usize,
    pub mtu: Option<u32>,
}

impl Default for TftpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            root: None,
            lowercase: false,
            no_block_size: false,
            secure: false,
            no_fail: false,
            single_port: false,
            max_transfers: 50,
            mtu: None,
        }
    }
}

fn integer(argument: Option<&EncodedArg>) -> Result<u32, Error> {
    let bytes = argument.ok_or(Error("missing parameter"))?.decoded();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error("bad integer"));
    }
    bytes.iter().try_fold(0u32, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .ok_or(Error("integer exceeds defined C int range"))
    })
}

impl TftpConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        validate_directive(directive)?;
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"enable-tftp" => self.enabled = true,
            b"tftp-root" => {
                let value = argument.ok_or(Error("missing parameter"))?.decoded();
                let root = value.split(|&byte| byte == b',').next().unwrap_or(&[]);
                if root.is_empty() {
                    return Err(Error("empty tftp-root"));
                }
                self.root = Some(root.to_vec());
                self.enabled = true;
            }
            b"tftp-lowercase" => self.lowercase = true,
            b"tftp-no-blocksize" => self.no_block_size = true,
            b"tftp-secure" => self.secure = true,
            b"tftp-no-fail" => self.no_fail = true,
            b"tftp-single-port" => self.single_port = true,
            b"tftp-max" => {
                let value = integer(argument)? as usize;
                if value == 0 {
                    return Err(Error("tftp-max must be positive"));
                }
                self.max_transfers = value;
            }
            b"tftp-mtu" => {
                let value = integer(argument)?;
                if value < 512 {
                    return Err(Error("tftp-mtu below minimum"));
                }
                self.mtu = Some(value);
            }
            b"tftp-port-range" => {
                let value = argument.ok_or(Error("missing parameter"))?.decoded();
                let parts: Vec<_> = value.split(|&byte| byte == b',').collect();
                if parts.len() != 2
                    || parts.iter().any(|part| part.is_empty())
                    || !parts.iter().all(|part| part.iter().all(u8::is_ascii_digit))
                {
                    return Err(Error("bad tftp port range"));
                }
                let start = parts[0]
                    .iter()
                    .fold(0u32, |n, byte| n * 10 + u32::from(byte - b'0'));
                let end = parts[1]
                    .iter()
                    .fold(0u32, |n, byte| n * 10 + u32::from(byte - b'0'));
                if start == 0 || start > end || end > u32::from(u16::MAX) {
                    return Err(Error("bad tftp port range"));
                }
                // Port allocation is owned by the listener. Keep validating
                // the configured range here; the first listener integration
                // uses the kernel-selected port when no range allocator is
                // supplied.
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;

    fn apply(config: &mut TftpConfig, text: &[u8]) -> Result<bool, Error> {
        config.apply(&lex_line(text)?.unwrap())
    }

    #[test]
    fn tftp_options_keep_byte_root_and_runtime_bounds() {
        let mut config = TftpConfig::default();
        assert!(apply(&mut config, b"enable-tftp").unwrap());
        assert!(apply(&mut config, b"tftp-root=/srv/tftp").unwrap());
        assert!(apply(&mut config, b"tftp-max=12").unwrap());
        assert!(apply(&mut config, b"tftp-mtu=1468").unwrap());
        assert!(apply(&mut config, b"tftp-port-range=40000,40010").unwrap());
        assert_eq!(config.root, Some(b"/srv/tftp".to_vec()));
        assert_eq!(config.max_transfers, 12);
        assert_eq!(config.mtu, Some(1468));
        assert!(apply(&mut config, b"tftp-mtu=511").is_err());
    }
}
