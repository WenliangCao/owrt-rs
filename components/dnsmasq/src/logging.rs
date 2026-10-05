//! Explicit logging owner for the single service poll loop.
//!
//! The image's log.c is the formatting, reconnect and overflow reference.
//! Writes and retry work are bounded: the owner never sleeps for a logger.
pub mod startup;
use crate::config::logging::LoggingConfig;
use crate::startup::{ProcessConfig, StartupError};
use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const PROGRAM: &str = "dnsmasq";
const MAX_MESSAGE: usize = 1024;
const O_NONBLOCK: i32 = 0x800;
const SOCK_CLOEXEC: i32 = 0x80000;
const SOCK_NONBLOCK: i32 = 0x800;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Service {
    Dns,
    Dhcp,
    Tftp,
    Script,
    Debug,
}
impl Service {
    fn suffix(self) -> &'static str {
        match self {
            Self::Dns => "",
            Self::Dhcp => "-dhcp",
            Self::Tftp => "-tftp",
            Self::Script => "-script",
            Self::Debug => "-debug",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Priority {
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

#[derive(Debug)]
pub struct LogEvent {
    pub service: Service,
    pub priority: Priority,
    pub message: Vec<u8>,
}
impl LogEvent {
    pub fn new(service: Service, priority: Priority, message: impl Into<Vec<u8>>) -> Self {
        Self {
            service,
            priority,
            message: message.into(),
        }
    }
}

struct Record {
    bytes: Vec<u8>,
    offset: usize,
    pid: u32,
}

impl Record {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            offset: 0,
            pid: std::process::id(),
        }
    }
}
enum Destination {
    File(File),
    Stderr(OwnedFd),
    Syslog { fd: OwnedFd, stream: bool },
}
impl AsRawFd for Destination {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::File(fd) => fd.as_raw_fd(),
            Self::Stderr(fd) => fd.as_raw_fd(),
            Self::Syslog { fd, .. } => fd.as_raw_fd(),
        }
    }
}

pub struct Logger {
    config: LoggingConfig,
    destination: Destination,
    echo: Option<OwnedFd>,
    echo_queue: VecDeque<Record>,
    queue: VecDeque<Record>,
    limit: usize,
    lost: u32,
    facility: i32,
    omit_timestamp: bool,
    connection_good: bool,
    debug_enabled: bool,
    fallback: bool,
}

impl Logger {
    /// Before log_start, C uses libc syslog with its default DAEMON facility.
    /// Keep one explicit owner across initial lease diagnostics and helper RO
    /// notices: their identity is the parent, independent of the configured sink.
    pub fn early() -> Result<Self, StartupError> {
        let config = LoggingConfig {
            facility: Some(24),
            file: None,
        };
        let (mut logger, _) = Self::start(&config, &ProcessConfig::default(), None)?;
        logger.fallback = true;
        Ok(logger)
    }
    /// Construct before redirecting standard streams or changing UID.
    /// A file destination disables async queuing just as log_start does.
    pub fn start(
        config: &LoggingConfig,
        process: &ProcessConfig,
        owner_uid: Option<u32>,
    ) -> Result<(Self, Option<io::Error>), StartupError> {
        let destination = open_destination(config).map_err(|error| StartupError {
            code: 3,
            message: format!(
                "cannot open log {}: {}",
                config
                    .file
                    .as_deref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                error_text(&error)
            ),
        })?;
        let stderr = matches!(destination, Destination::Stderr(_));
        let echo = if process.debug && !stderr {
            Some(duplicate_stderr().map_err(|error| StartupError {
                code: 3,
                message: format!("cannot duplicate stderr: {}", error_text(&error)),
            })?)
        } else {
            None
        };
        let mut ownership_warning = None;
        if let (Destination::File(file), Some(uid)) = (&destination, owner_uid) {
            if let Ok(metadata) = file.metadata() {
                // C makes a root-group file group-writable before changing its
                // owner; it never changes the existing group ID.
                if unsafe { getgid() } == 0 && metadata.gid() == 0 && metadata.mode() & 0o020 == 0 {
                    let _ = file
                        .set_permissions(std::fs::Permissions::from_mode(metadata.mode() | 0o020));
                }
            }
            if unsafe { fchown(file.as_raw_fd(), uid, u32::MAX) } != 0 {
                ownership_warning = Some(io::Error::last_os_error());
            }
        }
        Ok((
            Self {
                config: config.clone(),
                destination,
                echo,
                echo_queue: VecDeque::new(),
                queue: VecDeque::new(),
                limit: 1,
                lost: 0,
                facility: config
                    .facility
                    .unwrap_or(if process.debug { 128 } else { 24 }),
                omit_timestamp: stderr && process.keep_in_foreground,
                connection_good: true,
                debug_enabled: false,
                fallback: false,
            },
            ownership_warning,
        ))
    }

    /// The caller enables this only after the log-debug option is implemented.
    pub fn set_debug_enabled(&mut self, enabled: bool) {
        self.debug_enabled = enabled;
    }

    /// log-async accepts 0..100; file and stderr destinations always use one
    /// record. A zero async limit retains the C single preallocated buffer.
    pub fn set_queue_limit(&mut self, limit: usize) {
        if matches!(self.destination, Destination::Syslog { .. }) {
            self.limit = limit.clamp(1, 100);
        }
    }

    pub fn emit(&mut self, event: LogEvent) {
        if event.service == Service::Debug && !self.debug_enabled {
            return;
        }
        let message = &event.message[..event
            .message
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(event.message.len())
            .min(MAX_MESSAGE)];
        if self.echo.is_some() {
            let mut bytes = format!("{PROGRAM}{}: ", event.service.suffix()).into_bytes();
            bytes.extend_from_slice(message);
            bytes.push(b'\n');
            // Debug echo is independently bounded; blocked stderr must not
            // stop DNS/DHCP or consume the syslog queue's capacity.
            if self.echo_queue.len() < 100 {
                self.echo_queue.push_back(Record::new(bytes));
            }
        }
        if self.queue.len() >= self.limit {
            self.lost = self.lost.wrapping_add(1);
        } else {
            self.queue.push_back(Record::new(self.format(
                event.service,
                event.priority,
                message,
            )));
        }
        self.flush_ready();
    }

    fn format(&self, service: Service, priority: Priority, message: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_MESSAGE);
        if matches!(self.destination, Destination::Syslog { .. }) {
            bytes.extend_from_slice(format!("<{}>", self.facility | priority as i32).as_bytes());
        }
        if !self.omit_timestamp {
            let mut timestamp = [0u8; 26];
            let mut now = 0;
            // ctime_r is local-time and yields the RFC3164 field at bytes4..19.
            unsafe {
                time(&mut now);
                ctime_r(&now, timestamp.as_mut_ptr().cast());
            }
            bytes.extend_from_slice(&timestamp[4..19]);
            bytes.push(b' ');
        }
        bytes.extend_from_slice(
            format!("{PROGRAM}{}[{}]: ", service.suffix(), std::process::id()).as_bytes(),
        );
        let terminators = 1 + usize::from(self.fallback);
        bytes.extend_from_slice(
            &message[..message
                .len()
                .min(MAX_MESSAGE.saturating_sub(bytes.len() + terminators))],
        );
        // musl's syslog fallback retains its newline inside the datagram.
        // log.c's direct socket path elides only its terminating NUL.
        if self.fallback && bytes.last() != Some(&b'\n') {
            bytes.push(b'\n');
        }
        bytes.push(if matches!(self.destination, Destination::Syslog { .. }) {
            0
        } else {
            b'\n'
        });
        bytes
    }

    /// Include this descriptor with POLLOUT only while it is returned. Failed
    /// connections retry on the next event, avoiding a permanently-ready spin.
    pub fn poll_fd(&self) -> Option<RawFd> {
        (!self.queue.is_empty() && self.connection_good).then(|| self.destination.as_raw_fd())
    }

    pub fn poll_fds(&self) -> impl Iterator<Item = RawFd> {
        self.poll_fd().into_iter().chain(
            self.echo
                .as_ref()
                .filter(|_| !self.echo_queue.is_empty())
                .map(AsRawFd::as_raw_fd),
        )
    }

    /// Safe both after readiness and once per owner step: every write is
    /// nonblocking and a finite budget bounds short-write/EINTR/reconnect work.
    pub fn flush_ready(&mut self) {
        if let Some(echo) = &self.echo {
            drain_echo(echo.as_raw_fd(), &mut self.echo_queue);
        }
        for _ in 0..128 {
            let Some(record) = self.queue.front_mut() else {
                break;
            };
            // An early owner may survive daemon fork. Never deliver records
            // already queued by another process, matching log.c's PID guard.
            if record.pid != std::process::id() {
                self.queue.pop_front();
                continue;
            }
            let datagram = matches!(self.destination, Destination::Syslog { stream: false, .. });
            let bytes = &record.bytes[record.offset..record.bytes.len() - usize::from(datagram)];
            self.connection_good = true;
            let result = unsafe {
                write(
                    self.destination.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                )
            };
            if result >= 0 {
                if result == 0 {
                    break;
                }
                record.offset += result as usize;
                if record.offset == record.bytes.len() - usize::from(datagram) {
                    self.queue.pop_front();
                    if self.lost != 0 {
                        let lost = std::mem::take(&mut self.lost);
                        let bytes = self.format(
                            Service::Dns,
                            Priority::Warning,
                            format!("overflow: {lost} log entries lost").as_bytes(),
                        );
                        self.queue.push_back(Record::new(bytes));
                    }
                }
                continue;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(4) => continue, // EINTR
                Some(11) => break,   // EAGAIN
                Some(105) => {
                    self.connection_good = false;
                    break;
                } // ENOBUFS
                _ => {}
            }
            if let Destination::Syslog { fd, stream } = &self.destination {
                if error.raw_os_error() == Some(32) {
                    // EPIPE
                    if let Ok(replacement) = syslog_socket(*stream) {
                        self.destination = replacement;
                        continue;
                    }
                } else if matches!(error.raw_os_error(), Some(111 | 107 | 89 | 104)) {
                    match connect_syslog(fd.as_raw_fd()) {
                        Ok(()) => continue,
                        Err(error) if error.raw_os_error() == Some(91) => {
                            // EPROTOTYPE
                            if let Ok(replacement) = syslog_socket(!stream) {
                                self.destination = replacement;
                                continue;
                            }
                        }
                        Err(error)
                            if matches!(
                                error.raw_os_error(),
                                Some(2 | 114 | 111 | 106 | 4 | 11)
                            ) =>
                        {
                            self.connection_good = false;
                            break;
                        }
                        Err(_) => {}
                    }
                }
            }
            if self.fallback && matches!(self.destination, Destination::Syslog { .. }) {
                // libc syslog silently drops an undeliverable fallback record;
                // it does not recursively generate another "log failed".
                self.queue.clear();
                self.connection_good = false;
                break;
            }
            // C abandons its queued records and reports the failure through
            // libc syslog. Use the same destination without a blocking libc call.
            self.queue.clear();
            if let Ok(destination) = syslog_socket(false) {
                self.destination = destination;
                self.omit_timestamp = false;
                self.fallback = true;
                if self.echo.is_some() && self.echo_queue.len() < 100 {
                    let bytes =
                        format!("{PROGRAM}: log failed: {}\n", error_text(&error)).into_bytes();
                    self.echo_queue.push_back(Record::new(bytes));
                }
                let bytes = self.format(
                    Service::Dns,
                    Priority::Critical,
                    format!("log failed: {}", error_text(&error)).as_bytes(),
                );
                self.queue.push_back(Record::new(bytes));
                // Complete the immediate fallback attempt before accepting the
                // next producer. Otherwise the single file buffer drops that
                // next line and incorrectly emits an overflow warning.
                continue;
            }
            self.connection_good = false;
            break;
        }
    }

    /// SIGUSR2 reopens file destinations only. The old FD is closed before the
    /// open attempt, matching log_reopen; subsequent events report write failure.
    pub fn reopen(&mut self) -> io::Result<()> {
        if self
            .config
            .file
            .as_deref()
            .is_none_or(|path| path == Path::new("-"))
        {
            return Ok(());
        }
        // Remove the previous file before attempting the replacement.
        self.destination = syslog_socket(false)?;
        match open_destination(&self.config) {
            Ok(destination) => self.destination = destination,
            Err(error) => {
                self.queue.clear();
                self.omit_timestamp = false;
                self.fallback = true;
                return Err(error);
            }
        }
        self.connection_good = true;
        self.fallback = false;
        Ok(())
    }

    /// Make one bounded shutdown attempt. The owner can poll and retry while
    /// false. A failed syslog connection ends draining, matching flush_log.
    pub fn finish(&mut self) -> bool {
        self.flush_ready();
        (self.queue.is_empty() || !self.connection_good) && self.echo_queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_append_reopen_and_maximum_message_preserve_record_boundaries() {
        let path = std::env::temp_dir().join(format!("dnsmasq-log-{}", std::process::id()));
        let rotated = path.with_extension("old");
        std::fs::write(&path, b"existing\n").unwrap();
        let config = LoggingConfig {
            file: Some(path.clone()),
            facility: None,
        };
        let (mut logger, warning) =
            Logger::start(&config, &ProcessConfig::default(), None).unwrap();
        assert!(warning.is_none());
        logger.emit(LogEvent::new(
            Service::Dhcp,
            Priority::Info,
            b"before\0ignored".to_vec(),
        ));
        std::fs::rename(&path, &rotated).unwrap();
        logger.reopen().unwrap();
        logger.emit(LogEvent::new(
            Service::Tftp,
            Priority::Error,
            vec![b'x'; 4096],
        ));
        assert!(logger.finish());
        let previous = std::fs::read(&rotated).unwrap();
        assert!(previous.starts_with(b"existing\n"));
        assert!(previous.ends_with(b": before\n"));
        assert!(!previous.windows(7).any(|bytes| bytes == b"ignored"));
        let current = std::fs::read(&path).unwrap();
        assert_eq!(current.len(), MAX_MESSAGE);
        assert_eq!(current.last(), Some(&b'\n'));
        assert_eq!(current.iter().filter(|byte| **byte == b'\n').count(), 1);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(rotated).unwrap();
    }
}

fn drain_echo(fd: RawFd, records: &mut VecDeque<Record>) {
    for _ in 0..128 {
        let Some(record) = records.front_mut() else {
            break;
        };
        let bytes = &record.bytes[record.offset..];
        let written = unsafe { write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written > 0 {
            record.offset += written as usize;
            if record.offset == record.bytes.len() {
                records.pop_front();
            }
        } else if written < 0 && io::Error::last_os_error().raw_os_error() == Some(4) {
            continue;
        } else {
            break;
        }
    }
}

fn open_destination(config: &LoggingConfig) -> io::Result<Destination> {
    match config.file.as_deref() {
        Some(path) if path == Path::new("-") => duplicate_stderr().map(Destination::Stderr),
        Some(path) => OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .custom_flags(O_NONBLOCK)
            .open(path)
            .map(Destination::File),
        None => syslog_socket(false),
    }
}
fn duplicate_stderr() -> io::Result<OwnedFd> {
    let fd = unsafe { dup(2) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let flags = unsafe { fcntl(fd.as_raw_fd(), 3) };
    if flags < 0 || unsafe { fcntl(fd.as_raw_fd(), 4, flags | O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
fn syslog_socket(stream: bool) -> io::Result<Destination> {
    let fd = unsafe {
        socket(
            1,
            (if stream { 1 } else { 2 }) | SOCK_NONBLOCK | SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Destination::Syslog {
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
        stream,
    })
}
fn connect_syslog(fd: RawFd) -> io::Result<()> {
    #[repr(C)]
    struct Address {
        family: u16,
        path: [u8; 108],
    }
    let mut address = Address {
        family: 1,
        path: [0; 108],
    };
    address.path[..8].copy_from_slice(b"/dev/log");
    if unsafe {
        connect(
            fd,
            (&address as *const Address).cast(),
            std::mem::size_of::<Address>() as u32,
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn error_text(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(code) => unsafe {
            CStr::from_ptr(strerror(code))
                .to_string_lossy()
                .into_owned()
        },
        None => error.to_string(),
    }
}
unsafe extern "C" {
    fn time(result: *mut i64) -> i64;
    fn ctime_r(value: *const i64, output: *mut c_char) -> *mut c_char;
    fn strerror(error: c_int) -> *mut c_char;
    fn getgid() -> u32;
    fn fchown(fd: c_int, uid: u32, gid: u32) -> c_int;
    fn dup(fd: c_int) -> c_int;
    fn fcntl(fd: c_int, operation: c_int, ...) -> c_int;
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn connect(fd: c_int, address: *const c_void, length: u32) -> c_int;
    fn write(fd: c_int, bytes: *const c_void, length: usize) -> isize;
}

/// log_start failure reaches fatal_event/die before a logging destination is
/// usable. Report both critical records through the libc-format syslog path;
/// the entry point separately prints only the first message to stderr.
pub fn report_startup_failure(config: &LoggingConfig, process: &ProcessConfig, message: &str) {
    let fallback = LoggingConfig {
        file: None,
        facility: Some(
            config
                .facility
                .unwrap_or(if process.debug { 128 } else { 24 }),
        ),
    };
    if let Ok((mut logger, _)) = Logger::start(&fallback, &ProcessConfig::default(), None) {
        logger.fallback = true;
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Critical,
            message.as_bytes().to_vec(),
        ));
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Critical,
            b"FAILED to start up".to_vec(),
        ));
        logger.finish();
    }
}
