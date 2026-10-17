//! Foreground service identity and PID lifecycle from dnsmasq.c startup.
pub mod cli;
#[cfg(target_os = "linux")]
pub mod daemonize;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod lease_init;
use crate::config::{Directive, Error};
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct ProcessConfig {
    pub user: Option<Vec<u8>>,
    pub group: Option<Vec<u8>>,
    pub group_set: bool,
    pub pid_file: Option<PathBuf>,
    pub debug: bool,
    pub keep_in_foreground: bool,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            user: Some(b"nobody".to_vec()),
            group: None,
            group_set: false,
            pid_file: Some("/var/run/dnsmasq.pid".into()),
            debug: false,
            keep_in_foreground: false,
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
            b"keep-in-foreground" => self.keep_in_foreground = true,
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

/// EVENT_PIDFILE retains the original Unix argument and errno separately.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct PidStartError {
    pub code: i32,
    pub message: String,
    argument: Vec<u8>,
    error: io::Error,
}

#[cfg(target_os = "linux")]
impl PidStartError {
    fn new(path: &std::path::Path, error: io::Error) -> Self {
        let argument = path.as_os_str().as_bytes().to_vec();
        Self {
            code: 3,
            message: format!(
                "failed to open pidfile {}: {}",
                path.display(),
                crate::logging::error_text(&error)
            ),
            argument,
            error,
        }
    }
    pub fn argument(&self) -> &[u8] {
        &self.argument
    }
    pub fn errno(&self) -> i32 {
        self.error.raw_os_error().unwrap_or(5)
    }
    pub fn message_bytes(&self) -> Vec<u8> {
        let mut message = b"failed to open pidfile ".to_vec();
        message.extend_from_slice(&self.argument);
        message.extend_from_slice(b": ");
        message.extend_from_slice(crate::logging::error_text(&self.error).as_bytes());
        message
    }
}
#[cfg(target_os = "linux")]
impl std::fmt::Display for PidStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
#[cfg(target_os = "linux")]
impl std::error::Error for PidStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// option.c finalizes MX/SRV defaults before returning from syntax-check mode.
/// This is a local kernel query, never a DNS resolver lookup.
pub fn hostname() -> Result<Vec<u8>, StartupError> {
    unsafe extern "C" {
        fn gethostname(name: *mut std::ffi::c_char, length: usize) -> std::ffi::c_int;
    }
    let mut name = [0u8; 503]; // C MAXDNAMESTR, including room for its terminator.
                               // SAFETY: gethostname receives the complete writable buffer and its size.
    if unsafe { gethostname(name.as_mut_ptr().cast(), name.len()) } != 0 {
        return Err(StartupError {
            code: 5,
            message: format!("cannot get host-name: {}", std::io::Error::last_os_error()),
        });
    }
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| StartupError {
            code: 5,
            message: "host-name exceeds the configuration buffer".into(),
        })?;
    Ok(name[..end].to_vec())
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
        message: format!(
            "{context}: {}",
            crate::logging::error_text(&io::Error::last_os_error())
        ),
    }
}

pub struct PidFile {
    path: Option<PathBuf>,
    ownership_warning: Option<std::io::Error>,
}
impl PidFile {
    #[cfg(any(test, target_os = "linux"))]
    fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            ownership_warning: None,
        }
    }
    pub fn ownership_warning(&self) -> Option<&std::io::Error> {
        self.ownership_warning.as_ref()
    }
    /// C removes the configured PID path on its normal termination event,
    /// but leaves a newly written file when later initialization fails.
    pub fn cleanup(self) {
        if let Some(path) = &self.path {
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
    use std::os::fd::{AsRawFd, IntoRawFd};
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
        fn close(fd: c_int) -> c_int;
        fn capget(header: *mut CapHeader, data: *mut CapData) -> c_int;
        fn capset(header: *const CapHeader, data: *const CapData) -> c_int;
        fn prctl(option: c_int, a: usize, b: usize, c: usize, d: usize) -> c_int;
    }
    pub struct Identity {
        uid: Option<u32>,
        user_gid: Option<u32>,
        gid: Option<u32>,
        group_name: Option<Vec<u8>>,
        root: bool,
    }
    impl Identity {
        /// File-policy consumers are constructed before the UID transition.
        /// Use the same identity they will execute under after that transition.
        pub fn runtime_uid(&self, config: &ProcessConfig) -> u32 {
            // SAFETY: geteuid reads process state and has no pointer arguments.
            let current = unsafe { geteuid() };
            if !config.debug && self.root {
                self.uid.filter(|uid| *uid != 0).unwrap_or(current)
            } else {
                current
            }
        }

        /// log_start uses the selected passwd entry before dropping privilege,
        /// including debug mode. It preserves the log file's existing group.
        pub fn log_owner_uid(&self) -> Option<u32> {
            self.uid.filter(|uid| *uid != 0)
        }

        pub fn check_capabilities(&self, required: u32) -> Result<bool, StartupError> {
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
                for (bit, name) in [(12, "NET_ADMIN"), (13, "NET_RAW"), (10, "NET_BIND_SERVICE")] {
                    if required & (1 << bit) != 0 && data[0].permitted & (1 << bit) == 0 {
                        return Err(StartupError {
                            code: 5,
                            message: format!("process is missing required capability {name}"),
                        });
                    }
                }
                return Err(StartupError {
                    code: 5,
                    message: "process is missing required capabilities".into(),
                });
            }
            Ok(data[0].permitted & 1 != 0)
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
            let (gid, group_name) = if let Some(name) = &config.group {
                let name_c = CString::new(name.as_slice()).map_err(|_| unknown(name))?;
                // SAFETY: the live CString is terminated; libc owns the result.
                // Copy its fields before another group database lookup.
                let group =
                    unsafe { getgrnam(name_c.as_ptr()).as_ref() }.ok_or_else(|| unknown(name))?;
                (Some(group.gid), Some(name.clone()))
            } else if !config.group_set {
                // SAFETY: the constant name is terminated. A gid fallback is
                // queried only when the first lookup returned a null pointer.
                // Returned group storage is copied before another libc lookup.
                let group = unsafe { getgrnam(c"dip".as_ptr()).as_ref() }.or_else(|| {
                    user_gid.and_then(|gid| {
                        // SAFETY: this fallback passes a scalar gid to libc;
                        // the returned record is copied below before another
                        // group lookup can invalidate its storage.
                        unsafe { getgrgid(gid).as_ref() }
                    })
                });
                match group {
                    Some(group) => (
                        Some(group.gid),
                        Some(
                            // SAFETY: libc's successful group record owns a
                            // terminated name valid until the next group lookup.
                            unsafe { std::ffi::CStr::from_ptr(group.name) }
                                .to_bytes()
                                .to_vec(),
                        ),
                    ),
                    None => (None, None),
                }
            } else {
                (None, None)
            };
            Ok(Self {
                uid,
                user_gid,
                gid,
                group_name,
                // SAFETY: getuid reads process state without pointer arguments.
                root: unsafe { getuid() } == 0,
            })
        }
        pub fn write_pid(&self, config: &ProcessConfig) -> Result<PidFile, PidStartError> {
            let Some(path) = config.pid_file.as_ref() else {
                return Ok(PidFile::new(None));
            };
            if config.debug {
                // Debug mode skips creation, but C still removes the configured
                // PID path when handling SIGTERM.
                return Ok(PidFile::new(Some(path.clone())));
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
                Err(_) if !self.root => return Ok(PidFile::new(Some(path.clone()))),
                Err(error) => return Err(PidStartError::new(path, error)),
            };
            let mut pid = PidFile::new(Some(path.clone()));
            if let Some((uid, gid)) = self
                .uid
                .filter(|uid| self.root && *uid != 0)
                .zip(self.user_gid)
            {
                // SAFETY: fd belongs to file and scalar IDs came from libc.
                if unsafe { fchown(file.as_raw_fd(), uid, gid) } < 0 {
                    pid.ownership_warning = Some(io::Error::last_os_error());
                }
            }
            writeln!(file, "{}", std::process::id())
                .map_err(|error| PidStartError::new(path, error))?;
            // Taking the raw descriptor prevents a second close. C treats a
            // failed close exactly like open/write failure and keeps the path.
            // SAFETY: into_raw_fd transfers the live descriptor once to close.
            if unsafe { close(file.into_raw_fd()) } != 0 {
                return Err(PidStartError::new(path, io::Error::last_os_error()));
            }
            Ok(pid)
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
            if config.debug || !self.root {
                return Ok(());
            }
            if let Some(gid) = self.gid {
                // SAFETY: a zero group count permits the null pointer; group
                // and user IDs are copied scalars. Startup is single-threaded.
                if unsafe { setgroups(0, std::ptr::null()) } < 0 || unsafe { setgid(gid) } < 0 {
                    return Err(failure(
                        5,
                        &format!(
                            "failed to change group-id to {}",
                            String::from_utf8_lossy(self.group_name.as_deref().unwrap_or_default())
                        ),
                    ));
                }
            }
            if let Some(uid) = self.uid.filter(|uid| *uid != 0) {
                let mut data = [CapData::default(); 2];
                data[0].effective = keep | (1 << 7);
                data[0].permitted = data[0].effective;
                // SAFETY: Linux capability v3 reads the two initialized live
                // entries; PR_SET_KEEPCAPS takes scalar arguments only.
                if unsafe { capset(&header, data.as_ptr()) } < 0
                    || unsafe { prctl(8, 1, 0, 0, 0) } < 0
                {
                    return Err(failure(5, "setting capabilities failed"));
                }
                // SAFETY: setuid takes a scalar ID from the resolved passwd record.
                if unsafe { setuid(uid) } < 0 {
                    return Err(failure(
                        5,
                        &format!(
                            "failed to change user-id to {}",
                            String::from_utf8_lossy(config.user.as_deref().unwrap_or_default())
                        ),
                    ));
                }
                data[0].effective = keep;
                data[0].permitted = keep;
                // SAFETY: header and both capability entries remain initialized
                // and live after setuid; capset does not retain their pointers.
                if unsafe { capset(&header, data.as_ptr()) } < 0 {
                    return Err(failure(5, "setting capabilities failed"));
                }
            }
            Ok(())
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::Identity;

/// Call after log_start has duplicated a configured stderr destination and
/// before helper startup/UID changes. C tolerates a failed /dev/null open.
#[cfg(target_os = "linux")]
pub fn redirect_standard_streams(config: &ProcessConfig) {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn dup2(old: i32, new: i32) -> i32;
    }
    if config.debug {
        return;
    }
    if let Ok(null) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        for target in [0, 1, 2] {
            // SAFETY: /dev/null is owned and live. dup2 takes scalar FDs and
            // atomically replaces only this process's standard stream target.
            unsafe {
                dup2(null.as_raw_fd(), target);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pid_cleanup_is_explicit_after_successful_startup() {
        let path = std::env::temp_dir().join(format!("dnsmasq-pid-cleanup-{}", std::process::id()));
        std::fs::write(&path, b"sentinel\n").unwrap();
        let failed_startup = PidFile::new(Some(path.clone()));
        drop(failed_startup);
        assert_eq!(std::fs::read(&path).unwrap(), b"sentinel\n");
        PidFile::new(Some(path.clone())).cleanup();
        assert!(!path.exists());
    }
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
