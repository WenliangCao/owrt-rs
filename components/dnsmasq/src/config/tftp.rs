//! TFTP scalar configuration consumed by the Linux listener.
//!
//! This keeps the wire/path policy in `tftp_runtime` while preserving the
//! option.c spelling and byte-oriented arguments at the loader boundary.

use super::{validate_directive, Directive, EncodedArg, Error};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootWarning {
    pub path: Vec<u8>,
    pub interface: bool,
}

#[derive(Debug)]
pub struct RootAccessError {
    pub path: Vec<u8>,
    pub error: std::io::Error,
}

impl RootAccessError {
    pub fn message_bytes(&self) -> Vec<u8> {
        #[cfg(target_os = "linux")]
        let error_text = crate::logging::error_text(&self.error);
        #[cfg(not(target_os = "linux"))]
        let error_text = self.error.to_string();
        let mut message = b"TFTP directory ".to_vec();
        message.extend_from_slice(if self.path.is_empty() {
            error_text.as_bytes()
        } else {
            &self.path
        });
        message.extend_from_slice(b" inaccessible: ");
        message.extend_from_slice(error_text.as_bytes());
        message
    }
}

impl std::fmt::Display for RootAccessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&String::from_utf8_lossy(&self.message_bytes()))
    }
}
impl std::error::Error for RootAccessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

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
    /// `daemon->if_prefix` list. The last matching list node wins at runtime.
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
    pub quiet: bool,
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
            quiet: false,
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

/// network.c:246,539-558: dedicated TFTP names override DHCP exclusions.
/// This is shared by listener admission and DHCP's server-ID alias check.
#[cfg(any(test, all(target_os = "linux", target_pointer_width = "64")))]
pub(crate) fn interface_enabled(
    enabled: bool,
    interfaces: &[Option<Vec<u8>>],
    no_dhcp: &[Option<Vec<u8>>],
    name: &[u8],
) -> bool {
    enabled
        && if !interfaces.is_empty() {
            interfaces
                .iter()
                .flatten()
                .any(|pattern| matches_name(pattern, name))
        } else {
            !no_dhcp
                .iter()
                .flatten()
                .any(|pattern| matches_name(pattern, name))
        }
}

#[cfg(any(test, all(target_os = "linux", target_pointer_width = "64")))]
pub(crate) fn matches_name(pattern: &[u8], name: &[u8]) -> bool {
    for (pattern, actual) in pattern.iter().zip(name) {
        if *pattern == b'*' {
            return true;
        }
        if pattern != actual {
            return false;
        }
    }
    pattern.len() == name.len()
}

impl TftpConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        validate_directive(directive)?;
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"quiet-tftp" => self.quiet = true,
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

    /// Every parsed TFTP option is consumed by the integrated listener.
    pub fn validate_ready(&self) -> Result<(), Error> {
        Ok(())
    }

    /// C iterates the entire newest-first prefix list without breaking, so
    /// the earliest matching directive wins (unlike the global root).
    pub fn root_for_interface(&self, name: &[u8]) -> Option<&[u8]> {
        let mut root = self.root.as_deref();
        for entry in &self.interface_roots {
            if entry.interface.as_deref() == Some(name) {
                root = entry.path.as_deref();
            }
        }
        root
    }

    /// dnsmasq.c reserves the DNS random socket pool and normal service FDs,
    /// then estimates one/two descriptors per transfer and caps port ranges.
    /// A negative C limit means no new request can be admitted.
    pub fn transfer_limit(&self, open_max: u64, random_sockets: usize) -> Option<usize> {
        usize::try_from(self.signed_transfer_limit(open_max, random_sockets)).ok()
    }

    /// Retain the signed C estimate for the startup restriction warning.
    pub fn signed_transfer_limit(&self, open_max: u64, random_sockets: usize) -> i128 {
        let mut available = i128::from(open_max) - 30 - random_sockets as i128;
        available = if available < 0 {
            5
        } else if available < 100 && !self.single_port {
            available / 2
        } else {
            available - 20
        };
        if let Some((start, end)) = self.port_range.filter(|(start, _)| *start != 0) {
            available = available.min(i128::from(end - start) + 1);
        }
        available.min(self.max_transfers as i128)
    }

    /// Must run after dropping privileges, matching C's opendir checks.
    /// Returns inaccessible roots only when --tftp-no-fail permits startup.
    #[cfg(unix)]
    pub fn validate_roots(&self) -> std::io::Result<Vec<Vec<u8>>> {
        self.root_accesses()
            .map(|warnings| warnings.into_iter().map(|warning| warning.path).collect())
            .map_err(|error| error.error)
    }

    /// Retain path identity for fatal_event and the two distinct startup
    /// warnings. Checks still occur after the selected process identity drop.
    #[cfg(unix)]
    pub fn root_accesses(&self) -> Result<Vec<RootWarning>, RootAccessError> {
        use std::os::unix::ffi::OsStrExt;
        let mut warnings = Vec::new();
        if !self.enabled {
            return Ok(warnings);
        }
        for (root, interface) in self.root.iter().map(|root| (Some(root), false)).chain(
            self.interface_roots
                .iter()
                .map(|entry| (entry.path.as_ref(), true)),
        ) {
            let access = match root {
                Some(root) => std::fs::read_dir(std::ffi::OsStr::from_bytes(root)),
                // The image's musl opendir(NULL) fails EFAULT. Global NULL
                // is skipped above, but every interface-prefix node is checked.
                None => Err(std::io::Error::from_raw_os_error(14)),
            };
            if let Err(error) = access {
                if !self.no_fail {
                    return Err(RootAccessError {
                        path: root.cloned().unwrap_or_default(),
                        error,
                    });
                }
                warnings.push(RootWarning {
                    path: root.cloned().unwrap_or_default(),
                    interface,
                });
            }
        }
        Ok(warnings)
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
    fn unique_root_bits_are_independent() {
        let mut config = TftpConfig::default();
        assert!(apply(&mut config, b"tftp-unique-root").unwrap());
        assert!(apply(&mut config, b"tftp-unique-root=mac").unwrap());
        assert!(config.unique_root_ip);
        assert!(config.unique_root_mac);
        assert!(apply(&mut config, b"tftp-unique-root=").is_err());
        assert!(config.validate_ready().is_ok());

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
    fn port_range_and_interface_selectors_are_ready() {
        let mut config = TftpConfig::default();
        apply(&mut config, b"tftp-port-range=69,70").unwrap();
        assert_eq!(config.port_range, Some((69, 70)));
        assert!(config.validate_ready().is_ok());
        apply(&mut config, b"enable-tftp=eth0").unwrap();
        assert!(config.validate_ready().is_ok());
    }
    #[test]
    fn interface_root_order_and_fd_budget_follow_c() {
        let mut config = TftpConfig::default();
        apply(&mut config, b"tftp-root=/global").unwrap();
        apply(&mut config, b"tftp-root=/first,lan").unwrap();
        apply(&mut config, b"tftp-root=/last,lan").unwrap();
        assert_eq!(
            config.root_for_interface(b"lan"),
            Some(b"/first".as_slice())
        );
        assert_eq!(
            config.root_for_interface(b"other"),
            Some(b"/global".as_slice())
        );
        assert_eq!(config.transfer_limit(1024, 75), Some(50));
        assert_eq!(config.transfer_limit(64, 21), Some(6));
        assert_eq!(config.transfer_limit(16, 0), Some(5));
        config.single_port = true;
        assert_eq!(config.transfer_limit(64, 21), None);
        config.port_range = Some((40000, 40003));
        assert_eq!(config.transfer_limit(1024, 75), Some(4));
    }

    #[cfg(unix)]
    #[test]
    fn no_fail_only_tolerates_inaccessible_roots() {
        let path = std::env::temp_dir().join(format!("tftp-roots-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        let missing = path.join("missing");
        use std::os::unix::ffi::OsStrExt;
        let mut config = TftpConfig {
            enabled: true,
            root: Some(missing.as_os_str().as_bytes().to_vec()),
            ..TftpConfig::default()
        };
        assert_eq!(
            config.validate_roots().unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(
            config.root_accesses().unwrap_err().path,
            config.root.clone().unwrap()
        );
        config.no_fail = true;
        assert_eq!(
            config.validate_roots().unwrap(),
            vec![config.root.clone().unwrap()]
        );
        let interface_root = path.join("interface-missing");
        config.interface_roots.push(TftpRoot {
            path: Some(interface_root.as_os_str().as_bytes().to_vec()),
            interface: Some(b"lo".to_vec()),
        });
        assert_eq!(
            config.root_accesses().unwrap(),
            vec![
                RootWarning {
                    path: config.root.clone().unwrap(),
                    interface: false
                },
                RootWarning {
                    path: interface_root.as_os_str().as_bytes().to_vec(),
                    interface: true
                },
            ]
        );
        std::fs::create_dir(&missing).unwrap();
        std::fs::create_dir(&interface_root).unwrap();
        assert!(config.validate_roots().unwrap().is_empty());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn interface_eligibility_keeps_global_disable_and_dedicated_override() {
        let no_dhcp = [Some(b"lan".to_vec())];
        assert!(!interface_enabled(false, &[], &[], b"lan"));
        assert!(interface_enabled(true, &[], &[], b"lan"));
        assert!(!interface_enabled(true, &[], &no_dhcp, b"lan"));
        let dedicated = [Some(b"lan".to_vec())];
        assert!(interface_enabled(true, &dedicated, &no_dhcp, b"lan"));
        assert!(!interface_enabled(true, &dedicated, &[], b"lo"));
        assert!(!interface_enabled(true, &[None], &[], b"lan"));
        assert!(!interface_enabled(
            true,
            &[Some(b"lan*".to_vec())],
            &[],
            b"lan"
        ));
        assert!(interface_enabled(
            true,
            &[Some(b"lan*".to_vec())],
            &[],
            b"lan0"
        ));
    }
}
