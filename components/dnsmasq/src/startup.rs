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
    // Linux uname uses the same kernel nodename as gethostname. Its fixed
    // field is smaller than C MAXDNAMESTR=503, so truncation is impossible.
    Ok(rustix::system::uname().nodename().to_bytes().to_vec())
}
impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for StartupError {}
#[cfg(target_os = "linux")]
fn failure(code: i32, context: &str, error: io::Error) -> StartupError {
    StartupError {
        code,
        message: format!("{context}: {}", crate::logging::error_text(&error)),
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
    use dnsmasq_platform::process;
    use rustix::thread::{CapabilitySet, CapabilitySets};
    use std::os::unix::fs::OpenOptionsExt;
    fn capability_sets(bits: u32) -> CapabilitySets {
        let flags = CapabilitySet::from_bits_retain(bits as u64);
        CapabilitySets {
            effective: flags,
            permitted: flags,
            inheritable: CapabilitySet::empty(),
        }
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
            let current = rustix::process::geteuid().as_raw();
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
            let permitted = rustix::thread::capabilities(None)
                .map_err(|error| failure(5, "capget", error.into()))?
                .permitted
                .bits() as u32;
            if permitted & required != required {
                for (bit, name) in [(12, "NET_ADMIN"), (13, "NET_RAW"), (10, "NET_BIND_SERVICE")] {
                    if required & (1 << bit) != 0 && permitted & (1 << bit) == 0 {
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
            Ok(permitted & 1 != 0)
        }

        pub fn resolve(config: &ProcessConfig) -> Result<Self, StartupError> {
            let unknown = |name: &[u8]| StartupError {
                code: 1,
                message: format!("unknown user or group: {}", String::from_utf8_lossy(name)),
            };
            let (uid, user_gid) = match &config.user {
                None => (None, None),
                Some(name) => {
                    let (uid, gid) = process::user_ids(name).ok_or_else(|| unknown(name))?;
                    (Some(uid), Some(gid))
                }
            };
            let (gid, group_name) = if let Some(name) = &config.group {
                let (gid, _) = process::group_by_name(name).ok_or_else(|| unknown(name))?;
                (Some(gid), Some(name.clone()))
            } else if !config.group_set {
                match process::group_by_name(b"dip")
                    .or_else(|| user_gid.and_then(process::group_by_id))
                {
                    Some((gid, name)) => (Some(gid), Some(name)),
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
                root: rustix::process::getuid().is_root(),
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
                if let Err(error) = rustix::fs::fchown(
                    &file,
                    Some(rustix::process::Uid::from_raw(uid)),
                    Some(rustix::process::Gid::from_raw(gid)),
                ) {
                    pid.ownership_warning = Some(error.into());
                }
            }
            writeln!(file, "{}", std::process::id())
                .map_err(|error| PidStartError::new(path, error))?;
            process::close_file(file).map_err(|error| PidStartError::new(path, error))?;
            Ok(pid)
        }
        pub fn drop_privileges(
            &self,
            config: &ProcessConfig,
            keep: u32,
        ) -> Result<(), StartupError> {
            if config.debug || !self.root {
                return Ok(());
            }
            if let Some(gid) = self.gid {
                if let Err(error) = process::set_process_group(gid) {
                    return Err(failure(
                        5,
                        &format!(
                            "failed to change group-id to {}",
                            String::from_utf8_lossy(self.group_name.as_deref().unwrap_or_default())
                        ),
                        error,
                    ));
                }
            }
            if let Some(uid) = self.uid.filter(|uid| *uid != 0) {
                rustix::thread::set_capabilities(None, capability_sets(keep | (1 << 7)))
                    .and_then(|()| rustix::thread::set_keep_capabilities(true))
                    .map_err(|error| failure(5, "setting capabilities failed", error.into()))?;
                process::set_process_user(uid).map_err(|error| {
                    failure(
                        5,
                        &format!(
                            "failed to change user-id to {}",
                            String::from_utf8_lossy(config.user.as_deref().unwrap_or_default())
                        ),
                        error,
                    )
                })?;
                rustix::thread::set_capabilities(None, capability_sets(keep))
                    .map_err(|error| failure(5, "setting capabilities failed", error.into()))?;
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
    if config.debug {
        return;
    }
    if let Ok(null) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        let _ = rustix::stdio::dup2_stdin(&null);
        let _ = rustix::stdio::dup2_stdout(&null);
        let _ = rustix::stdio::dup2_stderr(&null);
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
