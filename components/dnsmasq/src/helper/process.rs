use super::*;
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::process::{Pid, WaitOptions};
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, Read, Write};
#[cfg(feature = "process-test-support")]
use std::os::fd::AsFd;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};

const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?)
}
#[cfg(feature = "process-test-support")]
fn nonblocking(fd: impl AsFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    Ok(rustix::fs::fcntl_setfl(
        fd,
        flags | rustix::fs::OFlags::NONBLOCK,
    )?)
}

// Only pure owned data crosses the restricted platform fork boundary. No
// borrowed parent state, FD owner, lock guard or callback is in this snapshot.
#[doc(hidden)]
#[derive(Debug)]
pub struct HelperStartup {
    config: Config,
    init_capacity: Option<usize>,
    identity: Option<(u32, u32)>,
    initialization_only: bool,
}

#[doc(hidden)]
pub type HelperWorker =
    dnsmasq_platform::process::AuditedWorker<fn(HelperStartup, File, File) -> i32>;

static WORKER: std::sync::OnceLock<HelperWorker> = std::sync::OnceLock::new();

/// Install the executable's fixed helper entry exactly once.
#[doc(hidden)]
pub fn install_worker(worker: HelperWorker) -> Result<(), HelperWorker> {
    WORKER.set(worker)
}

fn start_error(error: io::Error) -> StartError {
    StartError {
        code: 5,
        message: format!("failed to create helper: {error}"),
    }
}

pub struct Helper {
    pid: i32,
    script: std::path::PathBuf,
    script_user: Option<Vec<u8>>,
    writer: Option<File>,
    reader: Option<File>,
    pending: Vec<u8>,
    written: usize,
    incoming: Vec<u8>,
    stopping: bool,
    eof: bool,
    reaped: Option<i32>,
    ready: bool,
    init_capacity: Option<usize>,
}

impl Helper {
    /// Call before daemon privilege drop. The platform executable must have
    /// installed the fixed helper worker before any helper is requested.
    pub fn start(config: Config) -> Result<Self, StartError> {
        Self::start_with_init(config, None)
    }

    /// Leasefile-ro initialization runs in the helper before credentials drop.
    /// The owner consumes bounded InitRecord/InitEnd/InitExit notices in its poll.
    pub fn start_with_init(
        config: Config,
        init_capacity: Option<usize>,
    ) -> Result<Self, StartError> {
        Self::start_inner(config, init_capacity, false)
    }

    /// Preflight has no pipes, fork, credential changes or producer execution.
    pub fn validate_startup(
        config: &Config,
        init_capacity: Option<usize>,
    ) -> Result<(), StartError> {
        Self::startup_identity(config, init_capacity).map(|_| ())
    }

    fn startup_identity(
        config: &Config,
        init_capacity: Option<usize>,
    ) -> Result<Option<(u32, u32)>, StartError> {
        if init_capacity.is_some() && config.script.as_os_str().as_bytes().len() + 6 > 256 {
            return Err(StartError {
                code: 3,
                message: "lease-change script name is too long".into(),
            });
        }
        if config.script.as_os_str().as_bytes().contains(&0) || config.script.as_os_str().is_empty()
        {
            return Err(StartError {
                code: 1,
                message: "invalid lease-change script path".into(),
            });
        }
        let identity = match &config.script_user {
            None => None,
            Some(name) => {
                let invalid_user = || StartError {
                    code: 1,
                    message: format!("unknown script user {}", String::from_utf8_lossy(name)),
                };
                Some(dnsmasq_platform::process::user_ids(name).ok_or_else(invalid_user)?)
            }
        };
        Ok(identity)
    }

    /// The prefork owner receives only initialization records and diagnostics.
    /// This child never drops script credentials, emits READY or reads commands.
    pub fn start_initializer(config: Config, maximum: usize) -> Result<Self, StartError> {
        Self::start_inner(config, Some(maximum), true)
    }

    fn start_inner(
        config: Config,
        init_capacity: Option<usize>,
        initialization_only: bool,
    ) -> Result<Self, StartError> {
        let identity = Self::startup_identity(&config, init_capacity)?;
        let startup = HelperStartup {
            config,
            init_capacity,
            identity,
            initialization_only,
        };
        let worker = WORKER
            .get()
            .ok_or_else(|| start_error(io::Error::other("helper worker is not installed")))?;
        let (startup, pid, writer, reader) =
            dnsmasq_platform::process::spawn_helper(startup, worker).map_err(start_error)?;
        let config = startup.config;
        Ok(Self {
            pid: pid.as_raw_nonzero().get(),
            script: config.script,
            script_user: config.script_user,
            writer: Some(writer),
            reader: Some(reader),
            pending: Vec::new(),
            written: 0,
            incoming: Vec::new(),
            stopping: false,
            eof: false,
            reaped: None,
            ready: false,
            init_capacity,
        })
    }
    pub fn pid(&self) -> i32 {
        self.pid
    }
    pub fn script_path(&self) -> &std::path::Path {
        &self.script
    }
    pub fn credential_failure(&self, errno: i32) -> StartError {
        let error = crate::logging::error_text(&io::Error::from_raw_os_error(errno));
        let user = self
            .script_user
            .as_deref()
            .map(String::from_utf8_lossy)
            .map_or_else(|| error.clone(), |user| user.into_owned());
        StartError {
            code: 5,
            message: format!("failed to change user-id to {user}: {error}"),
        }
    }
    pub fn initializes_leases(&self) -> bool {
        self.init_capacity.is_some()
    }
    pub fn init_capacity(&self) -> Option<usize> {
        self.init_capacity
    }
    pub fn ready(&self) -> bool {
        self.ready
    }
    pub fn can_enqueue(&self) -> bool {
        self.ready
            && !self.stopping
            && self.reaped.is_none()
            && self.pending.is_empty()
            && self.writer.is_some()
    }
    /// false means backpressure; caller retains the event and retries later.
    pub fn enqueue(&mut self, event: &Event) -> io::Result<bool> {
        if !self.can_enqueue() {
            return Ok(false);
        }
        self.pending = if let Event::Arp {
            added,
            hardware_address,
            address,
        } = event
        {
            wire::arp_frame(*added, hardware_address, *address)?
        } else {
            wire::frame(&wire::encode(event)?)
        };
        self.written = 0;
        Ok(true)
    }

    /// Queue one DHCP lease callback using the same bounded command channel as
    /// ARP/TFTP events.  Conversion happens before touching the pipe, so a
    /// malformed event leaves the caller's lease ownership unchanged.
    pub fn enqueue_lease(
        &mut self,
        event: &crate::dhcp::lease::ScriptEvent,
        context: LeaseEventContext,
    ) -> io::Result<bool> {
        let event = Event::Lease(LeaseEvent::from_script_event(event, context));
        self.enqueue(&event)
    }

    /// Queue an owned lease callback while the caller retains ownership of the
    /// [`LeaseDelivery`] across a false (backpressure) result.  The delivery's
    /// packet snapshot is converted only when the single bounded command slot
    /// is available, so the owner can retry the exact same callback later.
    pub fn enqueue_delivery(&mut self, delivery: &LeaseDelivery) -> io::Result<bool> {
        if !self.can_enqueue() {
            return Ok(false);
        }
        self.enqueue(&Event::Lease(delivery.lease_event()))
    }
    /// FDs are -1 when inactive, compatible with poll's ignored entries.
    pub fn poll_fds(&self) -> [(RawFd, i16); 2] {
        [
            (
                if self.eof {
                    -1
                } else {
                    self.reader.as_ref().map_or(-1, AsRawFd::as_raw_fd)
                },
                POLLIN,
            ),
            (
                self.writer
                    .as_ref()
                    .filter(|_| !self.pending.is_empty())
                    .map_or(-1, AsRawFd::as_raw_fd),
                POLLOUT,
            ),
        ]
    }
    /// The owner must drain its lease event source before beginning shutdown.
    /// Buffered pipe commands finish in order; EOF then asks the helper to exit.
    pub fn begin_shutdown(&mut self) {
        self.stopping = true;
    }
    /// EVENT_TERM hands queued work to the helper, then closes its command
    /// pipe. The parent does not wait for the helper's last script to finish.
    pub fn commands_drained(&self) -> bool {
        self.stopping && self.pending.is_empty() && self.writer.is_none()
    }
    pub fn is_finished(&self) -> bool {
        self.reaped.is_some() && self.eof
    }

    /// Pipe EOF may precede waitpid(WNOHANG) observing the helper's exit.
    /// Once the pipe is closed the owner needs a bounded recheck, rather than
    /// waiting for an unrelated network event. Live helpers need no timer.
    pub fn needs_reap(&self) -> bool {
        self.eof && self.reaped.is_none()
    }

    /// Bounded work on each service turn. No read, write, or wait can block.
    pub fn step(&mut self) -> io::Result<Vec<Notice>> {
        let mut notices = Vec::new();
        let mut buffer = [0u8; 8192];
        let mut channel_error = None;
        // Read first, preventing child log output from stalling command progress.
        // A malformed/partial notification disables IPC but must still reach
        // WNOHANG below. Returning early here can leave a dead helper a zombie.
        'reads: for _ in 0..8 {
            let Some(reader) = self.reader.as_mut() else {
                break;
            };
            match reader.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(length) => {
                    self.incoming.extend_from_slice(&buffer[..length]);
                    let mut consumed = 0;
                    while self.incoming.len() - consumed >= 4 {
                        let size = u32::from_le_bytes(
                            self.incoming[consumed..consumed + 4].try_into().unwrap(),
                        ) as usize;
                        if size == 0 || size > wire::MAX_FRAME {
                            channel_error = Some(invalid());
                            break 'reads;
                        }
                        if self.incoming.len() - consumed < 4 + size {
                            break;
                        }
                        let notice = match decode_notice(
                            &self.incoming[consumed + 4..consumed + 4 + size],
                        ) {
                            Ok(notice) => notice,
                            Err(error) => {
                                channel_error = Some(error);
                                break 'reads;
                            }
                        };
                        if notice == Notice::Ready {
                            self.ready = true;
                        }
                        notices.push(notice);
                        consumed += 4 + size;
                    }
                    self.incoming.drain(..consumed);
                    if self.incoming.len() > wire::MAX_FRAME + 4 {
                        channel_error = Some(invalid());
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    channel_error = Some(error);
                    break;
                }
            }
        }
        if self.eof && !self.incoming.is_empty() {
            channel_error = Some(invalid());
        }
        if let Some(error) = channel_error {
            notices.push(Notice::Error(error.raw_os_error().unwrap_or(22)));
            self.eof = true;
        }
        if self.eof {
            // Closing both directions wakes a live helper as well as cleaning
            // up a dead one; no future frame can reach its fixed command.
            self.reader.take();
            self.writer.take();
            self.incoming.clear();
            self.pending.clear();
            self.written = 0;
            self.stopping = true;
        }
        if let Some(writer) = &mut self.writer {
            // C writes only after POLLOUT. An optimistic small write can
            // fill more pipe capacity and expose extra callbacks on TERM.
            let mut readiness = [PollFd::new(&*writer, PollFlags::OUT)];
            if !self.pending.is_empty()
                && (self.stopping
                    || rustix::event::poll(
                        &mut readiness,
                        Some(&Timespec {
                            tv_sec: 0,
                            tv_nsec: 0,
                        }),
                    )
                    .is_ok_and(|count| count > 0))
            {
                match writer.write(&self.pending[self.written..]) {
                    Ok(0) => {
                        self.pending.clear();
                        self.written = 0;
                        notices.push(Notice::Error(5));
                    }
                    Ok(length) => {
                        self.written += length;
                        if self.written == self.pending.len() {
                            self.pending.clear();
                            self.written = 0;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => {
                        // C helper_write drops a failed frame but keeps DNS and
                        // DHCP alive. Still reach waitpid below on EPIPE.
                        self.pending.clear();
                        self.written = 0;
                        notices.push(Notice::Error(error.raw_os_error().unwrap_or(5)));
                    }
                }
            }
        }
        if self.stopping && self.pending.is_empty() {
            self.writer.take();
        }
        if self.reaped.is_none() {
            match rustix::process::waitpid(Pid::from_raw(self.pid), WaitOptions::NOHANG) {
                Ok(Some((_, status))) => {
                    let status = status.as_raw();
                    self.reaped = Some(status);
                    self.pending.clear();
                    self.written = 0;
                    self.writer.take();
                    notices.push(Notice::Reaped(status));
                }
                Ok(None) | Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(notices)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Normal shutdown waits only for commands_drained. On startup errors
        // EOF likewise preserves queued-script completion; never wait here for
        // an arbitrary script. init/systemd or the test subreaper owns orphans.
        self.writer.take();
        if self.reaped.is_none() {
            let _ = rustix::process::waitpid(Pid::from_raw(self.pid), WaitOptions::NOHANG);
        }
    }
}

fn notice_payload(notice: Notice) -> io::Result<Vec<u8>> {
    Ok(match notice {
        Notice::Ready => vec![0],
        Notice::Output(mut bytes) => {
            bytes.insert(0, 1);
            bytes
        }
        Notice::InitWarning(mut bytes) => {
            bytes.insert(0, 11);
            bytes
        }
        Notice::InitRecord(record) => {
            let mut bytes = vec![7];
            bytes.extend(wire::encode_init(&record)?);
            bytes
        }
        Notice::InitEnd {
            invalid_records,
            clean_end,
        } => {
            let mut bytes = vec![9, u8::from(clean_end)];
            bytes.extend((invalid_records as u64).to_le_bytes());
            bytes
        }
        Notice::InitError(value)
        | Notice::InitExit(value)
        | Notice::ScriptExit(value)
        | Notice::ScriptSignal(value)
        | Notice::ExecError(value)
        | Notice::CredentialError(value)
        | Notice::Error(value)
        | Notice::Reaped(value) => {
            let code = match notice {
                Notice::InitError(_) => 10,
                Notice::InitExit(_) => 8,
                Notice::ScriptExit(_) => 2,
                Notice::ScriptSignal(_) => 3,
                Notice::ExecError(_) => 4,
                Notice::Error(_) => 5,
                Notice::CredentialError(_) => 12,
                _ => 6,
            };
            let mut bytes = vec![code];
            bytes.extend(value.to_le_bytes());
            bytes
        }
    })
}

fn decode_notice(bytes: &[u8]) -> io::Result<Notice> {
    let (&kind, data) = bytes.split_first().ok_or_else(invalid)?;
    if kind == 0 && data.is_empty() {
        return Ok(Notice::Ready);
    }
    if kind == 1 {
        return Ok(Notice::Output(data.to_vec()));
    }
    if kind == 11 {
        return Ok(Notice::InitWarning(data.to_vec()));
    }
    if kind == 7 {
        return wire::decode_init(data).map(Notice::InitRecord);
    }
    if kind == 9 {
        if data.len() != 9 || data[0] > 1 {
            return Err(invalid());
        }
        return Ok(Notice::InitEnd {
            clean_end: data[0] == 1,
            invalid_records: u64::from_le_bytes(data[1..].try_into().unwrap()) as usize,
        });
    }
    let value = i32::from_le_bytes(data.try_into().map_err(|_| invalid())?);
    match kind {
        2 => Ok(Notice::ScriptExit(value)),
        3 => Ok(Notice::ScriptSignal(value)),
        4 => Ok(Notice::ExecError(value)),
        5 => Ok(Notice::Error(value)),
        8 => Ok(Notice::InitExit(value)),
        10 => Ok(Notice::InitError(value)),
        12 => Ok(Notice::CredentialError(value)),
        _ => Err(invalid()),
    }
}
fn send(events: &mut File, notice: Notice) -> io::Result<()> {
    let runtime_notice = matches!(
        &notice,
        Notice::Ready
            | Notice::Output(_)
            | Notice::ExecError(_)
            | Notice::ScriptSignal(_)
            | Notice::ScriptExit(_)
    );
    match events.write_all(&wire::frame(&notice_payload(notice)?)) {
        // C send_event ignores a departed parent's event pipe. Its helper
        // still consumes every command queued before EOF. Initialization and
        // IPC/setup errors remain strict, as do all non-EPIPE failures.
        Err(error) if runtime_notice && error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

#[doc(hidden)]
pub fn worker_entry(startup: HelperStartup, mut commands: File, mut events: File) -> i32 {
    let HelperStartup {
        config,
        init_capacity,
        identity,
        initialization_only,
    } = startup;
    if let Some(maximum) = init_capacity {
        match run_init(&config, maximum, &mut events) {
            Ok(code) if initialization_only => return code,
            Ok(0) => {}
            Ok(_) | Err(_) => return 3,
        }
    }
    if !config.debug {
        if let Some((uid, gid)) = identity.filter(|(uid, _)| *uid != 0) {
            if let Err(error) = dnsmasq_platform::process::set_process_group(gid)
                .and_then(|()| dnsmasq_platform::process::set_process_user(uid))
            {
                let _ = send(
                    &mut events,
                    Notice::CredentialError(error.raw_os_error().unwrap_or(1)),
                );
                return 5;
            }
        }
    }
    if send(&mut events, Notice::Ready).is_err() {
        return 5;
    }
    loop {
        let mut header = [0; 4];
        match commands.read(&mut header[..1]) {
            Ok(0) => return 0,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return 5,
        }
        if commands.read_exact(&mut header[1..]).is_err() {
            let _ = send(&mut events, Notice::Error(22));
            return 5;
        }
        let size = u32::from_le_bytes(header) as usize;
        if size == 0 || size > wire::MAX_FRAME {
            let _ = send(&mut events, Notice::Error(22));
            return 5;
        }
        let mut payload = vec![0; size];
        if commands.read_exact(&mut payload).is_err() {
            let _ = send(&mut events, Notice::Error(22));
            return 5;
        }
        let call = match wire::decode(&payload).and_then(|event| invocation(&event)) {
            Ok(call) => call,
            Err(_) => {
                let _ = send(&mut events, Notice::Error(22));
                return 5;
            }
        };
        if run_script(&config, call, &mut events).is_err() {
            return 5;
        }
    }
}

fn run_init(config: &Config, maximum: usize, events: &mut File) -> io::Result<i32> {
    // lease.c parses popen("<fixed script> init", "r") before privilege drop.
    // The existing scanf-width parser bounds scratch space and record count.
    // Only the helper child waits; raw stdout never reaches owner memory.
    let mut command = config.script.as_os_str().to_os_string();
    command.push(" init");
    let mut producer = Command::new("/bin/sh");
    producer.arg("-c").arg(command).stdout(Stdio::piped());
    // lease.c uses popen, which retains the daemon's ignored SIGPIPE. std's
    // Command resets it unless this fixed async-signal-safe hook restores it.
    dnsmasq_platform::process::preserve_ignored_sigpipe(&mut producer);
    let mut process = producer.spawn()?;
    // Successful spawn with Stdio::piped always supplies this owned stdout.
    let output = process.stdout.take().unwrap();
    let parsed = crate::dhcp::lease_file::parse_reader_with_warnings(
        BufReader::new(output),
        maximum,
        |warning| send(events, Notice::InitWarning(warning)),
    );
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            for warning in crate::dhcp::lease_file::warnings(&error) {
                send(events, Notice::InitWarning(warning.clone()))?;
            }
            let code = if crate::dhcp::lease_file::capacity_exceeded(&error) {
                5
            } else {
                3
            };
            let sent = send(events, Notice::InitError(code));
            // Parent learns the failure before this child reaps the producer.
            // Its stdout has been closed, matching C's fatal parse boundary.
            let _ = process.wait();
            sent?;
            return Ok(code);
        }
    };
    for warning in &parsed.warnings {
        send(events, Notice::InitWarning(warning.clone()))?;
    }
    if !parsed.clean_end {
        send(
            events,
            Notice::InitWarning(b"failed to parse lease database cleanly".to_vec()),
        )?;
    }
    let status = process.wait()?;
    // C uses WEXITSTATUS without checking WIFEXITED, yielding zero on signal.
    let status = (status.into_raw() >> 8) & 255;
    if status == 0 {
        for record in parsed.records {
            send(events, Notice::InitRecord(record))?;
        }
        send(
            events,
            Notice::InitEnd {
                invalid_records: parsed.invalid_records,
                clean_end: parsed.clean_end,
            },
        )?;
    }
    send(events, Notice::InitExit(status))?;
    Ok(status)
}

fn run_script(config: &Config, call: Invocation, events: &mut File) -> io::Result<()> {
    let mut command = Command::new(&config.script);
    command.arg0(
        config
            .script
            .file_name()
            .unwrap_or(config.script.as_os_str()),
    );
    for value in call.args {
        command.arg(OsString::from_vec(value));
    }
    for (key, value) in call.env {
        if let Some(value) = value {
            command.env(key, OsString::from_vec(value));
        } else {
            command.env_remove(key);
        }
    }
    dnsmasq_platform::process::preserve_ignored_sigpipe(&mut command);
    let mut output = None;
    if !config.debug {
        let (read, write) = pipe()?;
        // dnsmasq.c redirects the daemon's stdin to /dev/null before helper
        // creation outside debug mode. Preserve the script boundary even when
        // our foreground owner keeps its own stderr attached to its logger.
        command.stdin(Stdio::null());
        command
            .stdout(Stdio::from(write.try_clone()?))
            .stderr(Stdio::from(write));
        output = Some(File::from(read));
    }
    let mut process = loop {
        match command.spawn() {
            Ok(process) => break process,
            // helper.c retries temporary resource failures; the service owner
            // remains runnable, and its command pipe eventually applies pressure.
            Err(error) if matches!(error.raw_os_error(), Some(11 | 12)) => {
                std::thread::sleep(std::time::Duration::from_secs(2))
            }
            Err(error) => {
                send(events, Notice::ExecError(error.raw_os_error().unwrap_or(5)))?;
                return Ok(());
            }
        }
    };
    // Command owns configured write descriptors; drop it before reading EOF.
    drop(command);
    let mut event_error = None;
    if let Some(mut output) = output {
        let mut bytes = [0; 8192];
        let mut line = Vec::with_capacity(1024);
        let mut has_tail = false;
        loop {
            match output.read(&mut bytes) {
                Ok(0) => {
                    if has_tail && event_error.is_none() {
                        event_error = send(events, Notice::Output(line)).err();
                    }
                    break;
                }
                Ok(length) => {
                    // helper.c/get_line_alloc consumes each complete line,
                    // including empty lines and an unterminated EOF tail. Its
                    // normal-mode logger cannot use more than 1024 bytes.
                    for &byte in &bytes[..length] {
                        if byte == b'\n' {
                            if event_error.is_none() {
                                event_error =
                                    send(events, Notice::Output(std::mem::take(&mut line))).err();
                            }
                            line.clear();
                            has_tail = false;
                        } else {
                            has_tail = true;
                            if line.len() < 1024 {
                                line.push(byte);
                            }
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    event_error = Some(error);
                    break;
                }
            }
        }
    }
    let status = process.wait()?;
    if let Some(error) = event_error {
        return Err(error);
    }
    if let Some(signal) = status.signal() {
        send(events, Notice::ScriptSignal(signal))?;
    } else if let Some(code) = status.code().filter(|&code| code != 0) {
        send(events, Notice::ScriptExit(code))?;
    }
    Ok(())
}

#[cfg(feature = "process-test-support")]
#[path = "process_tests.rs"]
mod process_tests;

#[cfg(feature = "process-test-support")]
#[doc(hidden)]
pub fn run_process_tests() {
    process_tests::run();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_runtime_notices_tolerate_broken_parent_pipe() {
        let (reader, writer) = pipe().unwrap();
        drop(reader);
        let mut writer = File::from(writer);
        for notice in [
            Notice::Ready,
            Notice::Output(b"late log".to_vec()),
            Notice::ExecError(2),
            Notice::ScriptSignal(10),
            Notice::ScriptExit(7),
        ] {
            send(&mut writer, notice).unwrap();
        }
        let record = crate::dhcp::lease_file::parse(b"0 02:00:00:00:00:01 192.0.2.10 client *\n")
            .records
            .remove(0);
        for notice in [
            Notice::InitRecord(record),
            Notice::InitEnd {
                invalid_records: 0,
                clean_end: true,
            },
            Notice::InitExit(7),
            Notice::InitError(5),
            Notice::Error(22),
            Notice::CredentialError(1),
        ] {
            assert_eq!(
                send(&mut writer, notice).unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
        let mut read_only = File::open("/dev/null").unwrap();
        assert_ne!(
            send(&mut read_only, Notice::Ready).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
