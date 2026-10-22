//! Explicit logging owner for the single service poll loop.
//!
//! The image's log.c is the formatting, reconnect and overflow reference.
//! Writes and retry work are bounded: the owner never sleeps for a logger.
pub use crate::query_logging as query;
pub mod startup;
use crate::config::logging::LoggingConfig;
use crate::startup::{ProcessConfig, StartupError};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

const PROGRAM: &str = "dnsmasq";
const MAX_MESSAGE: usize = 1024;
const O_NONBLOCK: i32 = rustix::fs::OFlags::NONBLOCK.bits() as i32;

/// Keep the original log argument and errno for the startup parent's C event.
/// Formatting it before transport loses read_event's missing-argument fallback.
#[derive(Debug)]
pub struct LogStartError {
    pub code: i32,
    pub message: String,
    argument: Vec<u8>,
    error: io::Error,
}

impl LogStartError {
    fn new(config: &LoggingConfig, error: io::Error) -> Self {
        let argument = config
            .file
            .as_ref()
            .map_or_else(Vec::new, |path| path.as_os_str().as_bytes().to_vec());
        Self {
            code: 3,
            message: format!(
                "cannot open log {}: {}",
                String::from_utf8_lossy(&argument),
                error_text(&error)
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

    /// Preserve opaque Unix path bytes in standalone foreground/debug errors,
    /// just as the typed startup frame preserves them for the original parent.
    pub fn message_bytes(&self) -> Vec<u8> {
        let mut message = b"cannot open log ".to_vec();
        message.extend_from_slice(&self.argument);
        message.extend_from_slice(b": ");
        message.extend_from_slice(error_text(&self.error).as_bytes());
        message
    }
}

impl std::fmt::Display for LogStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for LogStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
impl From<LogStartError> for StartupError {
    fn from(error: LogStartError) -> Self {
        Self {
            code: error.code,
            message: error.message,
        }
    }
}

pub use crate::address_logging::address_text;

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
#[derive(Clone)]
enum Destination {
    File(Rc<File>),
    Closed,
    /// A FIFO without a reader. Opening it must not block the service owner.
    WaitingFile,
    Stderr(Rc<OwnedFd>),
    Syslog {
        fd: Rc<OwnedFd>,
        stream: bool,
    },
}
impl Destination {
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        match self {
            Self::File(fd) => Some(fd.as_ref().as_fd()),
            Self::WaitingFile | Self::Closed => None,
            Self::Stderr(fd) | Self::Syslog { fd, .. } => Some(fd.as_ref().as_fd()),
        }
    }
}
impl AsRawFd for Destination {
    fn as_raw_fd(&self) -> RawFd {
        self.fd().map_or(-1, |fd| fd.as_raw_fd())
    }
}

pub struct Logger {
    config: LoggingConfig,
    destination: Destination,
    // Debug mode preserves inherited stderr for the process lifetime. C
    // writes it directly; allocating another FD adds a spurious EMFILE gate.
    echo: Option<BorrowedFd<'static>>,
    echo_queue: VecDeque<Record>,
    queue: VecDeque<Record>,
    limit: usize,
    lost: u32,
    facility: i32,
    omit_timestamp: bool,
    connection_good: bool,
    debug_enabled: bool,
    fallback: bool,
    fifo_retry_at: Option<Instant>,
}

/// The normal C TCP worker copies its counters at accept, then discards the
/// inherited parent-PID records. Only new producer records need buffering.
/// A shared descriptor pins the accepted destination across parent reopen;
/// cloning it creates no extra FD, process, thread or inherited payload copy.
pub struct TcpLogContext {
    destination: Destination,
    fifo_retry_at: Option<Instant>,
    fallback: bool,
    omit_timestamp: bool,
    queue: VecDeque<Record>,
    limit: usize,
    lost: u32,
    connection_good: bool,
}

impl Logger {
    pub fn tcp_context(&self) -> TcpLogContext {
        TcpLogContext {
            destination: self.destination.clone(),
            fifo_retry_at: self.fifo_retry_at,
            fallback: self.fallback,
            omit_timestamp: self.omit_timestamp,
            queue: VecDeque::new(),
            limit: self.limit,
            lost: self.lost,
            connection_good: self.connection_good,
        }
    }

    pub fn emit_tcp(&mut self, context: &mut TcpLogContext, event: LogEvent) {
        self.exchange_tcp_context(context);
        self.emit(event);
        self.exchange_tcp_context(context);
    }

    pub fn flush_tcp_ready(&mut self, context: &mut TcpLogContext) {
        self.exchange_tcp_context(context);
        self.flush_ready();
        self.exchange_tcp_context(context);
    }

    pub fn finish_tcp(&mut self, context: &mut TcpLogContext) -> bool {
        self.exchange_tcp_context(context);
        let finished = self.finish();
        self.exchange_tcp_context(context);
        finished
    }

    pub fn tcp_poll_fd(&self, context: &TcpLogContext) -> Option<RawFd> {
        let fd = context.destination.as_raw_fd();
        (!context.queue.is_empty() && context.connection_good && fd >= 0).then_some(fd)
    }

    pub fn tcp_retry_deadline(&self, context: &TcpLogContext) -> Option<Instant> {
        matches!(context.destination, Destination::WaitingFile)
            .then_some(context.fifo_retry_at)
            .flatten()
    }

    pub fn tcp_finished(&self, context: &TcpLogContext) -> bool {
        (context.queue.is_empty() || !context.connection_good) && self.echo_queue.is_empty()
    }

    pub fn retry_deadline(&self) -> Option<Instant> {
        matches!(self.destination, Destination::WaitingFile)
            .then_some(self.fifo_retry_at)
            .flatten()
    }

    fn exchange_tcp_context(&mut self, context: &mut TcpLogContext) {
        std::mem::swap(&mut self.destination, &mut context.destination);
        std::mem::swap(&mut self.fifo_retry_at, &mut context.fifo_retry_at);
        std::mem::swap(&mut self.fallback, &mut context.fallback);
        std::mem::swap(&mut self.omit_timestamp, &mut context.omit_timestamp);
        std::mem::swap(&mut self.queue, &mut context.queue);
        std::mem::swap(&mut self.limit, &mut context.limit);
        std::mem::swap(&mut self.lost, &mut context.lost);
        std::mem::swap(&mut self.connection_good, &mut context.connection_good);
    }

    /// Before log_start, C uses libc syslog with its default DAEMON facility.
    /// Keep one explicit owner across initial lease diagnostics and helper RO
    /// notices: their identity is the parent, independent of the configured sink.
    pub fn early() -> Result<Self, StartupError> {
        let config = LoggingConfig {
            facility: Some(24),
            file: None,
            ..Default::default()
        };
        let (mut logger, _) =
            Self::start(&config, &ProcessConfig::default(), None).map_err(StartupError::from)?;
        logger.fallback = true;
        Ok(logger)
    }
    /// Construct before redirecting standard streams or changing UID.
    /// A file destination disables async queuing just as log_start does.
    pub fn start(
        config: &LoggingConfig,
        process: &ProcessConfig,
        owner_uid: Option<u32>,
    ) -> Result<(Self, Option<io::Error>), LogStartError> {
        let destination =
            open_destination(config).map_err(|error| LogStartError::new(config, error))?;
        let stderr = matches!(destination, Destination::Stderr(_));
        let echo = if process.debug && !stderr {
            make_nonblocking(rustix::stdio::stderr())
                .ok()
                .map(|()| rustix::stdio::stderr())
        } else {
            None
        };
        let mut ownership_warning = None;
        // A read-only nonblocking FIFO descriptor lets startup apply the
        // selected owner before dropping credentials. Close it immediately;
        // retaining our own reader would hide EPIPE when real readers leave.
        let fifo_owner = if matches!(destination, Destination::WaitingFile) {
            config.file.as_ref().and_then(|path| {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(O_NONBLOCK)
                    .open(path)
                    .ok()
            })
        } else {
            None
        };
        let ownership_file = match &destination {
            Destination::File(file) => Some(file.as_ref()),
            Destination::WaitingFile => fifo_owner.as_ref(),
            _ => None,
        };
        if let (Some(file), Some(uid)) = (ownership_file, owner_uid) {
            if let Ok(metadata) = file.metadata() {
                // C makes a root-group file group-writable before changing its
                // owner; it never changes the existing group ID.
                if rustix::process::getgid().is_root()
                    && metadata.gid() == 0
                    && metadata.mode() & 0o020 == 0
                {
                    let _ = file
                        .set_permissions(std::fs::Permissions::from_mode(metadata.mode() | 0o020));
                }
            }
            if let Err(error) =
                rustix::fs::fchown(file, Some(rustix::process::Uid::from_raw(uid)), None)
            {
                ownership_warning = Some(error.into());
            }
        }
        let limit = if matches!(destination, Destination::Syslog { .. }) {
            if config.async_queue == 0 {
                1
            } else {
                config.async_queue.max(0) as usize
            }
        } else {
            1
        };
        Ok((
            Self {
                config: config.clone(),
                destination,
                echo,
                echo_queue: VecDeque::new(),
                queue: VecDeque::new(),
                limit,
                lost: 0,
                facility: config
                    .facility
                    .unwrap_or(if process.debug { 128 } else { 24 }),
                omit_timestamp: stderr && process.keep_in_foreground,
                connection_good: true,
                debug_enabled: config.debug,
                fallback: false,
                fifo_retry_at: None,
            },
            ownership_warning,
        ))
    }

    /// The caller enables this only after the log-debug option is implemented.
    pub fn set_debug_enabled(&mut self, enabled: bool) {
        self.debug_enabled = enabled;
    }

    /// File and stderr ignore log-async; negative wrapped C ints cannot
    /// allocate any entries. Zero retains the single preallocated buffer.
    pub fn set_queue_limit(&mut self, limit: i32) {
        let syslog = matches!(
            self.destination,
            Destination::Syslog { .. } | Destination::Closed
        );
        if syslog {
            self.limit = if limit == 0 {
                1
            } else {
                limit.clamp(0, 100) as usize
            };
        }
    }

    pub fn async_queue_limit(&self) -> i32 {
        if self.config.file.is_none() {
            self.config.async_queue
        } else {
            0
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
            .unwrap_or(event.message.len())];
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
            let record = self.format_record(event.service, event.priority, message);
            self.queue.push_back(record);
        }
        // C retries a down connection on my_syslog, not every owner poll.
        self.connection_good = true;
        self.flush_ready();
    }

    /// log.c::die echoes only the first critical record, with a leading blank
    /// line unless stderr is itself the selected primary destination.
    pub fn fatal(&mut self, message: &[u8]) -> bool {
        if self.echo.is_some() {
            self.echo_queue.push_back(Record::new(b"\n".to_vec()));
        }
        self.emit(LogEvent::new(
            Service::Dns,
            Priority::Critical,
            message.to_vec(),
        ));
        let echo = self.echo.take();
        self.emit(LogEvent::new(
            Service::Dns,
            Priority::Critical,
            b"FAILED to start up".to_vec(),
        ));
        self.echo = echo;
        self.finish()
    }

    fn format_record(&self, service: Service, priority: Priority, message: &[u8]) -> Record {
        // Formatting and queue ownership share this event's PID. The flush
        // guard still reads the current PID so a later fork cannot replay it.
        let pid = std::process::id();
        let mut bytes = Vec::with_capacity(MAX_MESSAGE);
        let syslog = matches!(
            self.destination,
            Destination::Syslog { .. } | Destination::Closed
        );
        if syslog {
            // Vec writes are infallible; avoid a separate formatting buffer.
            let _ = write!(bytes, "<{}>", self.facility | priority as i32);
        }
        if !self.omit_timestamp {
            bytes.extend_from_slice(&dnsmasq_platform::libc_format::log_timestamp());
            bytes.push(b' ');
        }
        // libc openlog keeps one program identifier after log.c falls back;
        // subsystem suffixes still apply to its separate debug echo only.
        let suffix = if self.fallback { "" } else { service.suffix() };
        let _ = write!(bytes, "{PROGRAM}{suffix}[{pid}]: ");
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
        bytes.push(if syslog { 0 } else { b'\n' });
        Record {
            bytes,
            offset: 0,
            pid,
        }
    }

    /// Include this descriptor with POLLOUT only while it is returned. Failed
    /// connections retry on the next event, avoiding a permanently-ready spin.
    pub fn poll_fd(&self) -> Option<RawFd> {
        (!self.queue.is_empty() && self.connection_good && self.destination.as_raw_fd() >= 0)
            .then(|| self.destination.as_raw_fd())
    }

    pub fn poll_fds(&self) -> impl Iterator<Item = RawFd> {
        self.poll_fd().into_iter().chain(
            self.echo
                .as_ref()
                .filter(|_| !self.echo_queue.is_empty())
                .map(AsRawFd::as_raw_fd),
        )
    }

    /// Whether this logger has work that can make progress in the owner turn.
    /// Waiting FIFO destinations remain eligible so their retry timer is
    /// preserved even though they do not yet expose a writable fd.
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
            || !self.echo_queue.is_empty()
            || (matches!(self.destination, Destination::WaitingFile)
                && self
                    .fifo_retry_at
                    .is_some_and(|deadline| Instant::now() >= deadline))
    }

    /// Safe both after readiness and once per owner step: every write is
    /// nonblocking and a finite budget bounds short-write/EINTR/reconnect work.
    pub fn flush_ready(&mut self) {
        if let Some(echo) = self.echo {
            drain_echo(echo, &mut self.echo_queue);
        }
        if matches!(self.destination, Destination::WaitingFile) {
            if self
                .fifo_retry_at
                .is_some_and(|deadline| Instant::now() < deadline)
            {
                return;
            }
            match open_destination(&self.config) {
                Ok(Destination::WaitingFile) => {
                    self.fifo_retry_at = Some(Instant::now() + Duration::from_millis(100));
                    return;
                }
                Ok(destination) => {
                    self.destination = destination;
                    self.fifo_retry_at = None;
                }
                Err(error) => {
                    self.queue.clear();
                    self.fifo_retry_at = None;
                    if let Ok(destination) = syslog_socket(false) {
                        self.destination = destination;
                        self.omit_timestamp = false;
                        self.fallback = true;
                        let record = self.format_record(
                            Service::Dns,
                            Priority::Critical,
                            format!("log failed: {}", error_text(&error)).as_bytes(),
                        );
                        self.queue.push_back(record);
                    } else {
                        self.connection_good = false;
                        return;
                    }
                }
            }
        }
        if !self.connection_good {
            return;
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
            let datagram = matches!(
                self.destination,
                Destination::Syslog { stream: false, .. } | Destination::Closed
            );
            let bytes = &record.bytes[record.offset..record.bytes.len() - usize::from(datagram)];
            self.connection_good = true;
            let result = self
                .destination
                .fd()
                .ok_or(rustix::io::Errno::BADF)
                .and_then(|fd| rustix::io::write(fd, bytes));
            if let Ok(result) = result {
                if result == 0 {
                    break;
                }
                record.offset += result;
                if record.offset == record.bytes.len() - usize::from(datagram) {
                    self.queue.pop_front();
                    if self.lost != 0 {
                        let lost = std::mem::take(&mut self.lost);
                        let record = self.format_record(
                            Service::Dns,
                            Priority::Warning,
                            format!("overflow: {lost} log entries lost").as_bytes(),
                        );
                        self.queue.push_back(record);
                    }
                }
                continue;
            }
            let error = io::Error::from(result.unwrap_err());
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
                    match connect_syslog(fd.as_ref()) {
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
            if self.fallback
                && matches!(
                    self.destination,
                    Destination::Syslog { .. } | Destination::Closed
                )
            {
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
                let record = self.format_record(
                    Service::Dns,
                    Priority::Critical,
                    format!("log failed: {}", error_text(&error)).as_bytes(),
                );
                self.queue.push_back(record);
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
        self.destination = Destination::Closed;
        match open_destination(&self.config) {
            Ok(destination) => self.destination = destination,
            Err(error) => {
                self.queue.clear();
                self.omit_timestamp = false;
                self.fallback = true;
                self.destination = syslog_socket(false).unwrap_or(Destination::Closed);
                return Err(error);
            }
        }
        self.connection_good = true;
        self.fallback = false;
        self.fifo_retry_at = None;
        Ok(())
    }

    /// Make one bounded shutdown attempt. The owner can poll and retry while
    /// false. A failed syslog connection ends draining, matching flush_log.
    pub fn finish(&mut self) -> bool {
        // flush_log makes one forced attempt before honoring connection_good.
        self.connection_good = true;
        self.flush_ready();
        (self.queue.is_empty() || !self.connection_good) && self.echo_queue.is_empty()
    }
}


fn drain_echo(fd: impl AsFd, records: &mut VecDeque<Record>) {
    for _ in 0..128 {
        let Some(record) = records.front_mut() else {
            break;
        };
        let bytes = &record.bytes[record.offset..];
        match rustix::io::write(&fd, bytes) {
            Ok(0) | Err(rustix::io::Errno::AGAIN) => break,
            Ok(written) => {
                record.offset += written;
                if record.offset == record.bytes.len() {
                    records.pop_front();
                }
            }
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => {
                records.clear();
                break;
            }
        }
    }
}

fn open_destination(config: &LoggingConfig) -> io::Result<Destination> {
    match config.file.as_deref() {
        Some(path) if path == Path::new("-") => {
            duplicate_stderr().map(|fd| Destination::Stderr(Rc::new(fd)))
        }
        Some(path) => match OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .custom_flags(O_NONBLOCK)
            .open(path)
        {
            Ok(file) => Ok(Destination::File(Rc::new(file))),
            Err(error)
                if error.raw_os_error() == Some(6)
                    && path.metadata().is_ok_and(|meta| meta.file_type().is_fifo()) =>
            {
                Ok(Destination::WaitingFile)
            }
            Err(error) => Err(error),
        },
        None => syslog_socket(false),
    }
}
fn duplicate_stderr() -> io::Result<OwnedFd> {
    let fd = rustix::io::dup(rustix::stdio::stderr())?;
    make_nonblocking(&fd)?;
    Ok(fd)
}
fn make_nonblocking(fd: impl AsFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    Ok(rustix::fs::fcntl_setfl(
        fd,
        flags | rustix::fs::OFlags::NONBLOCK,
    )?)
}
fn syslog_socket(stream: bool) -> io::Result<Destination> {
    let fd = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        if stream {
            rustix::net::SocketType::STREAM
        } else {
            rustix::net::SocketType::DGRAM
        },
        rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    Ok(Destination::Syslog {
        fd: Rc::new(fd),
        stream,
    })
}
fn connect_syslog(fd: impl AsFd) -> io::Result<()> {
    let address = rustix::net::SocketAddrUnix::new("/dev/log")?;
    Ok(rustix::net::connect(fd, &address)?)
}
pub use dnsmasq_platform::libc_format::error_text;

pub fn ownership_warning(path: &Path, error: &io::Error) -> LogEvent {
    let mut message = b"warning: failed to change owner of ".to_vec();
    message.extend_from_slice(path.as_os_str().as_bytes());
    message.extend_from_slice(b": ");
    message.extend_from_slice(error_text(error).as_bytes());
    LogEvent::new(Service::Dns, Priority::Warning, message)
}
/// log_start failure reaches fatal_event/die before a logging destination is
/// usable. Report both critical records through the libc-format syslog path;
/// the entry point separately prints only the first message to stderr.
pub fn report_startup_failure(config: &LoggingConfig, process: &ProcessConfig, message: &str) {
    report_startup_failure_bytes(config, process, message.as_bytes());
}

pub fn report_startup_failure_bytes(
    config: &LoggingConfig,
    process: &ProcessConfig,
    message: &[u8],
) {
    let fallback = LoggingConfig {
        file: None,
        facility: Some(
            config
                .facility
                .unwrap_or(if process.debug { 128 } else { 24 }),
        ),
        ..Default::default()
    };
    if let Ok((mut logger, _)) = Logger::start(&fallback, &ProcessConfig::default(), None) {
        logger.fallback = true;
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Critical,
            message.to_vec(),
        ));
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Critical,
            b"FAILED to start up".to_vec(),
        ));
        logger.finish();
    }
}

/// C opens its libc syslog connection only when the first early diagnostic is
/// produced. Failed logging never turns a lease warning into a startup error.
pub fn emit_early(owner: &mut Option<Logger>, priority: Priority, message: &[u8]) {
    if owner.is_none() {
        *owner = Logger::early().ok();
    }
    if let Some(logger) = owner {
        logger.emit(LogEvent::new(Service::Dns, priority, message.to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_and_external_flushes_discard_inherited_records() {
        let path = std::env::temp_dir().join(format!("dnsmasq-log-pid-{}", std::process::id()));
        let config = LoggingConfig {
            file: Some(path.clone()),
            ..Default::default()
        };
        let (mut logger, _) = Logger::start(&config, &ProcessConfig::default(), None).unwrap();
        let inherited = || Record {
            bytes: b"inherited\n".to_vec(),
            offset: 0,
            pid: 0,
        };
        logger.queue.push_back(inherited());
        logger.flush_ready();
        assert!(std::fs::read(&path).unwrap().is_empty());

        logger.limit = 2;
        logger.queue.push_back(inherited());
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Info,
            b"current".to_vec(),
        ));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("inherited"));
        assert!(text.contains(&format!("dnsmasq[{}]: current\n", std::process::id())));
        assert!(logger.queue.is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn accepted_tcp_records_keep_the_old_file_after_parent_reopen() {
        let path = std::env::temp_dir().join(format!("dnsmasq-tcp-log-{}", std::process::id()));
        let old = path.with_extension("old");
        let config = LoggingConfig {
            file: Some(path.clone()),
            debug: true,
            ..Default::default()
        };
        let (mut logger, _) = Logger::start(&config, &ProcessConfig::default(), None).unwrap();
        let mut tcp = logger.tcp_context();
        std::fs::rename(&path, &old).unwrap();
        logger.reopen().unwrap();
        logger.emit_tcp(
            &mut tcp,
            LogEvent::new(Service::Debug, Priority::Debug, b"child".to_vec()),
        );
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Info,
            b"parent".to_vec(),
        ));
        assert!(logger.finish_tcp(&mut tcp));
        assert!(logger.finish());
        let old_text = std::fs::read_to_string(&old).unwrap();
        let current = std::fs::read_to_string(&path).unwrap();
        assert!(old_text.contains(": child\n") && !old_text.contains(": parent\n"));
        assert!(current.contains(": parent\n") && !current.contains(": child\n"));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(old).unwrap();
    }

    #[test]
    fn fifo_without_reader_keeps_service_nonblocking_and_recovers_records() {
        let path = std::env::temp_dir().join(format!("dnsmasq-log-fifo-{}", std::process::id()));
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::from_bits_retain(0o600),
        )
        .unwrap();
        let config = LoggingConfig {
            file: Some(path.clone()),
            ..Default::default()
        };
        let (mut logger, _) = Logger::start(&config, &ProcessConfig::default(), None).unwrap();
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Info,
            b"first".to_vec(),
        ));
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Info,
            b"dropped".to_vec(),
        ));
        assert_eq!(logger.poll_fd(), None);
        assert!(!logger.finish());
        let mut reader = OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(&path)
            .unwrap();
        // Make the retry eligible directly; wall-clock scheduling is not the
        // behavior under test, and the reader is already open above.
        logger.fifo_retry_at = Some(Instant::now());
        logger.flush_ready();
        assert!(logger.finish());
        let mut captured = String::new();
        use std::io::Read;
        match reader.read_to_string(&mut captured) {
            Ok(_) => (),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
        }
        assert!(captured.contains(": first\n"));
        assert!(captured.contains(": overflow: 1 log entries lost\n"));
        assert!(!captured.contains(": dropped\n"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn file_append_reopen_and_maximum_message_preserve_record_boundaries() {
        let path = std::env::temp_dir().join(format!("dnsmasq-log-{}", std::process::id()));
        let rotated = path.with_extension("old");
        std::fs::write(&path, b"existing\n").unwrap();
        let config = LoggingConfig {
            file: Some(path.clone()),
            facility: None,
            ..Default::default()
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
