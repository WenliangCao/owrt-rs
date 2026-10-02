//! Foreground service identity and PID lifecycle from dnsmasq.c startup.
use crate::config::{Directive, Error};
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct ProcessConfig {
    pub user: Option<Vec<u8>>,
    pub group: Option<Vec<u8>>,
    pub group_set: bool,
    pub pid_file: Option<PathBuf>,
    pub debug: bool,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            user: Some(b"nobody".to_vec()),
            group: None,
            group_set: false,
            pid_file: Some("/var/run/dnsmasq.pid".into()),
            debug: false,
        }
    }
}

impl ProcessConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        let value = || {
            directive
                .argument
                .as_ref()
                .map(|value| value.decoded())
                .filter(|value| !value.is_empty())
        };
        match directive.name.as_slice() {
            b"user" => self.user = value(),
            b"group" => {
                self.group = value();
                self.group_set = true;
            }
            b"pid-file" => {
                self.pid_file = value().map(|value| PathBuf::from(OsString::from_vec(value)))
            }
            b"no-daemon" => self.debug = true,
            b"keep-in-foreground" => {}
            _ => return Ok(false),
        }
        Ok(true)
    }
}

#[derive(Debug)]
pub struct StartupError {
    pub code: i32,
    pub message: String,
}
impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for StartupError {}
#[cfg(target_os = "linux")]
fn failure(code: i32, context: &str) -> StartupError {
    StartupError {
        code,
        message: format!("{context}: {}", io::Error::last_os_error()),
    }
}

pub struct PidFile(Option<PathBuf>);
impl Drop for PidFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// dnsmasq.c needs ARP injection only when the head broadcast rule is
/// conditional or absent. UBus can configure privileged ports and device
/// binding later, independently of the current DHCP settings.
pub fn network_capabilities(
    dhcp: bool,
    no_ping: bool,
    unconditional_broadcast: bool,
    dynamic_ports: bool,
    ubus: bool,
) -> u32 {
    (if dhcp && !unconditional_broadcast {
        1 << 12
    } else {
        0
    }) | (if dynamic_ports || ubus { 1 << 10 } else { 0 })
        | (if (dhcp && !no_ping) || ubus {
            1 << 13
        } else {
            0
        })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::{c_char, c_int, CString};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    #[repr(C)]
    struct Passwd {
        name: *mut c_char,
        password: *mut c_char,
        uid: u32,
        gid: u32,
        gecos: *mut c_char,
        directory: *mut c_char,
        shell: *mut c_char,
    }
    #[repr(C)]
    struct Group {
        name: *mut c_char,
        password: *mut c_char,
        gid: u32,
        members: *mut *mut c_char,
    }
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    extern "C" {
        fn getpwnam(name: *const c_char) -> *mut Passwd;
        fn getgrnam(name: *const c_char) -> *mut Group;
        fn getgrgid(gid: u32) -> *mut Group;
        fn getuid() -> u32;
        fn geteuid() -> u32;
        fn setuid(uid: u32) -> c_int;
        fn setgid(gid: u32) -> c_int;
        fn setgroups(count: usize, groups: *const u32) -> c_int;
        fn fchown(fd: c_int, uid: u32, gid: u32) -> c_int;
        fn capget(header: *mut CapHeader, data: *mut CapData) -> c_int;
        fn capset(header: *const CapHeader, data: *const CapData) -> c_int;
        fn prctl(option: c_int, a: usize, b: usize, c: usize, d: usize) -> c_int;
    }
    pub struct Identity {
        uid: Option<u32>,
        user_gid: Option<u32>,
        gid: Option<u32>,
        root: bool,
    }
    impl Identity {
        /// File-policy consumers are constructed before the UID transition.
        /// Use the same identity they will execute under after that transition.
        pub fn runtime_uid(&self, config: &ProcessConfig) -> u32 {
            if !config.debug && self.root {
                self.uid
                    .filter(|uid| *uid != 0)
                    .unwrap_or_else(|| unsafe { geteuid() })
            } else {
                unsafe { geteuid() }
            }
        }

        pub fn check_capabilities(&self, required: u32) -> Result<(), StartupError> {
            let mut header = CapHeader {
                version: 0x20080522,
                pid: 0,
            };
            let mut data = [CapData::default(); 2];
            // SAFETY: Linux capability v3 reads exactly two initialized entries.
            if unsafe { capget(&mut header, data.as_mut_ptr()) } < 0 {
                return Err(failure(5, "capget"));
            }
            if data[0].permitted & required != required {
                return Err(StartupError {
                    code: 5,
                    message: "process is missing required network capabilities".into(),
                });
            }
            Ok(())
        }

        pub fn resolve(config: &ProcessConfig) -> Result<Self, StartupError> {
            let unknown = |name: &[u8]| StartupError {
                code: 1,
                message: format!("unknown user or group: {}", String::from_utf8_lossy(name)),
            };
            let (uid, user_gid) = match &config.user {
                None => (None, None),
                Some(name) => {
                    let name_c = CString::new(name.as_slice()).map_err(|_| unknown(name))?;
                    // SAFETY: the NUL-terminated name is live; copy fields before another lookup.
                    let entry = unsafe { getpwnam(name_c.as_ptr()).as_ref() }
                        .ok_or_else(|| unknown(name))?;
                    (Some(entry.uid), Some(entry.gid))
                }
            };
            let gid = if let Some(name) = &config.group {
                let name_c = CString::new(name.as_slice()).map_err(|_| unknown(name))?;
                // SAFETY: same libc lookup contract as above.
                Some(
                    unsafe { getgrnam(name_c.as_ptr()).as_ref() }
                        .ok_or_else(|| unknown(name))?
                        .gid,
                )
            } else if !config.group_set {
                // C chooses dip first, then the selected user's primary group.
                let dip = unsafe { getgrnam(c"dip".as_ptr()).as_ref() }.map(|entry| entry.gid);
                dip.or_else(|| {
                    user_gid
                        .and_then(|gid| unsafe { getgrgid(gid).as_ref() }.map(|entry| entry.gid))
                })
            } else {
                None
            };
            Ok(Self {
                uid,
                user_gid,
                gid,
                root: unsafe { getuid() } == 0,
            })
        }
        pub fn write_pid(&self, config: &ProcessConfig) -> Result<PidFile, StartupError> {
            let Some(path) = config.pid_file.as_ref() else {
                return Ok(PidFile(None));
            };
            if config.debug {
                // Debug mode skips creation, but C still removes the configured
                // PID path when handling SIGTERM.
                return Ok(PidFile(Some(path.clone())));
            }
            // Match unlink then exclusive creation: never follow a stale symlink.
            let _ = std::fs::remove_file(path);
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(path);
            let mut file = match file {
                Ok(file) => file,
                Err(_) if !self.root => return Ok(PidFile(None)),
                Err(error) => {
                    return Err(StartupError {
                        code: 3,
                        message: format!("failed to open pidfile {}: {error}", path.display()),
                    })
                }
            };
            if self.root && self.uid.is_some_and(|uid| uid != 0) {
                // SAFETY: fd belongs to file and scalar IDs came from libc.
                if unsafe { fchown(file.as_raw_fd(), self.uid.unwrap(), self.user_gid.unwrap()) }
                    < 0
                {
                    eprintln!(
                        "dnsmasq-rs: failed to change PID file owner: {}",
                        io::Error::last_os_error()
                    );
                }
            }
            writeln!(file, "{}", std::process::id()).map_err(|error| StartupError {
                code: 3,
                message: format!("failed to write pidfile {}: {error}", path.display()),
            })?;
            Ok(PidFile(Some(path.clone())))
        }
        pub fn drop_privileges(
            &self,
            config: &ProcessConfig,
            keep: u32,
        ) -> Result<(), StartupError> {
            let header = CapHeader {
                version: 0x20080522,
                pid: 0,
            };
            let mut data = [CapData::default(); 2];
            if config.debug || !self.root {
                return Ok(());
            }
            if let Some(gid) = self.gid {
                // SAFETY: no extra groups; this runs before spawning any threads.
                if unsafe { setgroups(0, std::ptr::null()) } < 0 || unsafe { setgid(gid) } < 0 {
                    return Err(failure(5, "failed to set group"));
                }
            }
            if let Some(uid) = self.uid.filter(|uid| *uid != 0) {
                data = [CapData::default(); 2];
                data[0].effective = keep | (1 << 7);
                data[0].permitted = data[0].effective;
                // SAFETY: Linux capability v3 has two entries. Keep only network + temporary SETUID.
                if unsafe { capset(&header, data.as_ptr()) } < 0
                    || unsafe { prctl(8, 1, 0, 0, 0) } < 0
                {
                    return Err(failure(5, "failed to retain capabilities"));
                }
                if unsafe { setuid(uid) } < 0 {
                    return Err(failure(5, "failed to set user"));
                }
                data[0].effective = keep;
                data[0].permitted = keep;
                if unsafe { capset(&header, data.as_ptr()) } < 0 {
                    return Err(failure(5, "failed to reduce capabilities"));
                }
            }
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::Identity;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_capabilities_follow_broadcast_ping_and_dynamic_configuration() {
        assert_eq!(network_capabilities(true, true, true, false, false), 0);
        assert_eq!(
            network_capabilities(true, true, false, false, false),
            1 << 12
        );
        assert_eq!(
            network_capabilities(true, false, true, false, false),
            1 << 13
        );
        assert_eq!(
            network_capabilities(false, false, false, true, false),
            1 << 10
        );
        assert_eq!(
            network_capabilities(false, false, false, false, true),
            (1 << 10) | (1 << 13)
        );
    }
    #[test]
    fn explicit_empty_values_disable_identity_and_pid_defaults() {
        let mut config = ProcessConfig::default();
        for line in [b"user=".as_slice(), b"group=", b"pid-file=", b"no-daemon"] {
            assert!(config
                .apply(&crate::config::lex_line(line).unwrap().unwrap())
                .unwrap());
        }
        assert!(
            config.user.is_none()
                && config.group.is_none()
                && config.group_set
                && config.pid_file.is_none()
                && config.debug
        );
    }
}
