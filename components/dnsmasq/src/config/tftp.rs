//! TFTP scalar configuration consumed by the Linux listener.
//!
//! This keeps the wire/path policy in `tftp_runtime` while preserving the
//! option.c spelling and byte-oriented arguments at the loader boundary.

use super::{validate_directive, Directive, EncodedArg, Error};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TftpRoot {
    /// `None` represents C's empty `tftp-root` string, which is accepted and
    /// stored as a null pointer by `opt_string_alloc`.
    pub path: Option<Vec<u8>>,
    /// A per-interface root has an interface selector; a global root keeps
    /// this as `None` and is represented by [`TftpConfig::root`].
    pub interface: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TftpConfig {
    pub enabled: bool,
    pub root: Option<Vec<u8>>,
    /// `--enable-tftp=<iface>[,<iface>...]` selectors. C prepends entries as
    /// it parses them, so this vector keeps the same newest-first order.
    pub interfaces: Vec<Option<Vec<u8>>>,
    /// `--tftp-root=<path>,<iface>` entries, also newest-first like C's
    /// `daemon->if_prefix` list. These are parsed even though the current
    /// listener has no per-interface prefix hook.
    pub interface_roots: Vec<TftpRoot>,
    /// C's `start_tftp_port`/`end_tftp_port`; reversed bounds are swapped.
    pub port_range: Option<(u16, u16)>,
    /// C stores these as independent option bits, so both may be enabled.
    pub unique_root_ip: bool,
    pub unique_root_mac: bool,
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
            interfaces: Vec::new(),
            interface_roots: Vec::new(),
            port_range: None,
            unique_root_ip: false,
            unique_root_mac: false,
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

/// `atoi_check` in option.c accepts an explicitly empty string as zero, but
/// rejects non-digits. Keep the result inside the defined C `int` domain so
/// Rust never reproduces signed-overflow behaviour from `atoi`.
fn integer(argument: Option<&EncodedArg>) -> Result<u32, Error> {
    let bytes = argument.ok_or(Error("missing parameter"))?.decoded();
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error("bad integer"));
    }
    bytes.iter().try_fold(0u32, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
            .filter(|value| *value <= i32::MAX as u32)
            .ok_or(Error("integer exceeds defined C int range"))
    })
}

fn optional_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    (!bytes.is_empty()).then(|| bytes.to_vec())
}

impl TftpConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        validate_directive(directive)?;
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"enable-tftp" => {
                self.enabled = true;
                if let Some(argument) = argument {
                    // one_opt() splits and prepends each selector. Empty
                    // selectors are accepted by C and retained as null names.
                    for selector in argument.split(b',') {
                        self.interfaces
                            .insert(0, optional_bytes(&selector.decoded()));
                    }
                }
            }
            b"tftp-root" => {
                let argument = argument.ok_or(Error("missing parameter"))?;
                let (root, interface) = argument.split_once(b',');
                let root = root.decoded();
                if let Some(interface) = interface {
                    let interface = interface.decoded();
                    self.interface_roots.insert(
                        0,
                        TftpRoot {
                            path: optional_bytes(&root),
                            interface: optional_bytes(&interface),
                        },
                    );
                } else {
                    // LOPT_PREFIX overwrites the global pointer on every
                    // occurrence and does not itself enable TFTP.
                    self.root = optional_bytes(&root);
                }
            }
            b"tftp-unique-root" => match argument.map(EncodedArg::decoded) {
                None => self.unique_root_ip = true,
                Some(value) if value.eq_ignore_ascii_case(b"ip") => self.unique_root_ip = true,
                Some(value) if value.eq_ignore_ascii_case(b"mac") => self.unique_root_mac = true,
                Some(_) => return Err(Error("bad tftp unique root")),
            },
            b"tftp-lowercase" => self.lowercase = true,
            b"tftp-no-blocksize" => self.no_block_size = true,
            b"tftp-secure" => self.secure = true,
            b"tftp-no-fail" => self.no_fail = true,
            b"tftp-single-port" => self.single_port = true,
            b"tftp-max" => {
                self.max_transfers = integer(argument)? as usize;
            }
            b"tftp-mtu" => {
                let value = integer(argument)?;
                self.mtu = Some(value);
            }
            b"tftp-port-range" => {
                let argument = argument.ok_or(Error("missing parameter"))?;
                let parts = argument.split(b',');
                if parts.len() != 2 {
                    return Err(Error("bad tftp port range"));
                }
                let start = integer(Some(&parts[0]))?;
                let end = integer(Some(&parts[1]))?;
                let (mut start, mut end) = (
                    u16::try_from(start).map_err(|_| Error("bad tftp port range"))?,
                    u16::try_from(end).map_err(|_| Error("bad tftp port range"))?,
                );
                if start > end {
                    std::mem::swap(&mut start, &mut end);
                }
                self.port_range = Some((start, end));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Validate options against the currently wired listener capabilities.
    /// Parsing retains every C option; callers must invoke this gate before
    /// starting a listener so unsupported selectors cannot be silently lost.
    pub fn validate_ready(&self) -> Result<(), Error> {
        if !self.interfaces.is_empty() {
            return Err(Error("TFTP interface selectors are not wired"));
        }
        if !self.interface_roots.is_empty() {
            return Err(Error("TFTP per-interface roots are not wired"));
        }
        if self.unique_root_ip || self.unique_root_mac {
            return Err(Error("TFTP unique-root is not wired"));
        }
        Ok(())
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
    fn tftp_options_match_c_defaults_and_repetition() {
        let mut config = TftpConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_transfers, 50);
        assert!(apply(&mut config, b"tftp-root=/srv/tftp").unwrap());
        assert!(!config.enabled, "tftp-root does not enable the server in C");
        assert!(apply(&mut config, b"tftp-root=/new-root").unwrap());
        assert_eq!(config.root, Some(b"/new-root".to_vec()));
        assert!(apply(&mut config, b"tftp-root=\"/quoted,root\"").unwrap());
        assert_eq!(config.root, Some(b"/quoted,root".to_vec()));
        assert!(apply(&mut config, b"enable-tftp=eth0,eth1").unwrap());
        assert_eq!(
            config.interfaces,
            vec![Some(b"eth1".to_vec()), Some(b"eth0".to_vec())]
        );
        assert!(apply(&mut config, b"tftp-root=/srv/eth,tun0,tail").unwrap());
        assert_eq!(
            config.interface_roots,
            vec![TftpRoot {
                path: Some(b"/srv/eth".to_vec()),
                interface: Some(b"tun0,tail".to_vec()),
            }]
        );
    }

    #[test]
    fn tftp_numbers_follow_atoi_check_and_port_swap() {
        let mut config = TftpConfig::default();
        assert!(apply(&mut config, b"tftp-max=12").unwrap());
        assert_eq!(config.max_transfers, 12);
        assert!(apply(&mut config, b"tftp-max=0").is_ok());
        assert_eq!(config.max_transfers, 0);
        assert!(apply(&mut config, b"tftp-mtu=1468").unwrap());
        assert!(apply(&mut config, b"tftp-mtu=0").unwrap());
        assert_eq!(config.mtu, Some(0));
        assert!(apply(&mut config, b"tftp-mtu=511").unwrap());
        assert_eq!(config.mtu, Some(511));
        assert!(apply(&mut config, b"tftp-port-range=40010,40000").unwrap());
        assert_eq!(config.port_range, Some((40000, 40010)));
        assert!(apply(&mut config, b"tftp-port-range=,").unwrap());
        assert_eq!(config.port_range, Some((0, 0)));
        assert!(apply(&mut config, b"tftp-port-range=65536,1").is_err());
        assert!(apply(&mut config, b"tftp-max=2147483648").is_err());
        assert!(apply(&mut config, b"tftp-max=abc").is_err());
    }

    #[test]
    fn unique_root_bits_and_runtime_gate_are_explicit() {
        let mut config = TftpConfig::default();
        assert!(apply(&mut config, b"tftp-unique-root").unwrap());
        assert!(apply(&mut config, b"tftp-unique-root=mac").unwrap());
        assert!(config.unique_root_ip);
        assert!(config.unique_root_mac);
        assert!(apply(&mut config, b"tftp-unique-root=").is_err());
        assert!(config.validate_ready().is_err());

        let mut supported = TftpConfig::default();
        assert!(apply(&mut supported, b"enable-tftp").unwrap());
        assert!(supported.validate_ready().is_ok());
    }

    #[test]
    fn empty_root_is_accepted_as_c_null_pointer() {
        let mut config = TftpConfig::default();
        assert!(apply(&mut config, b"tftp-root=").unwrap());
        assert_eq!(config.root, None);
        assert!(apply(&mut config, b"tftp-root=,eth0").unwrap());
        assert_eq!(
            config.interface_roots[0],
            TftpRoot {
                path: None,
                interface: Some(b"eth0".to_vec())
            }
        );
    }

    #[test]
    fn port_range_is_ready_but_interface_selectors_remain_explicit() {
        let mut config = TftpConfig::default();
        apply(&mut config, b"tftp-port-range=69,70").unwrap();
        assert_eq!(config.port_range, Some((69, 70)));
        assert!(config.validate_ready().is_ok());
        apply(&mut config, b"enable-tftp=eth0").unwrap();
        assert_eq!(
            config.validate_ready().unwrap_err(),
            Error("TFTP interface selectors are not wired")
        );
    }
}
