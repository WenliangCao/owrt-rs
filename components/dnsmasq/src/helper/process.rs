use super::*;
use std::ffi::{c_char, c_int, CString, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};

const O_CLOEXEC: c_int = 0x80000;
const O_NONBLOCK: c_int = 0x800;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const WNOHANG: c_int = 1;
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;

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
extern "C" {
    fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn fork() -> c_int;
    fn close(fd: c_int) -> c_int;
    fn signal(signum: c_int, handler: usize) -> usize;
    fn setuid(uid: u32) -> c_int;
    fn setgid(gid: u32) -> c_int;
    fn setgroups(count: usize, groups: *const u32) -> c_int;
    fn getpwnam(name: *const c_char) -> *mut Passwd;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn getrlimit(resource: c_int, limit: *mut [usize; 2]) -> c_int;
    fn _exit(code: c_int) -> !;
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: pipe2 writes exactly two descriptors, owned only after success.
    if unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}
fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 || unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn start_error(error: io::Error) -> StartError {
    StartError {
        code: 5,
        message: format!("failed to create helper: {error}"),
    }
}

pub struct Helper {
    pid: c_int,
    writer: Option<File>,
    reader: File,
    pending: Vec<u8>,
    written: usize,
    incoming: Vec<u8>,
    stopping: bool,
    eof: bool,
    reaped: Option<c_int>,
    ready: bool,
}

impl Helper {
    /// Call before daemon privilege drop, from the sole service thread. Like C,
    /// the helper retains startup credentials unless script-user changes them.
    pub fn start(config: Config) -> Result<Self, StartError> {
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
                let c_name = CString::new(name.as_slice()).map_err(|_| invalid_user())?;
                // SAFETY: getpwnam returns borrowed static storage. Copy before fork.
                let value =
                    unsafe { getpwnam(c_name.as_ptr()).as_ref() }.ok_or_else(invalid_user)?;
                Some((value.uid, value.gid))
            }
        };
        let (commands_read, commands_write) = pipe().map_err(start_error)?;
        let (events_read, events_write) = pipe().map_err(start_error)?;
        nonblocking(commands_write.as_raw_fd()).map_err(start_error)?;
        nonblocking(events_read.as_raw_fd()).map_err(start_error)?;
        // SAFETY: production calls before the single owner starts serving. Child
        // never returns into the parent's Rust ownership graph, using _exit.
        let pid = unsafe { fork() };
        if pid < 0 {
            return Err(start_error(io::Error::last_os_error()));
        }
        if pid == 0 {
            drop(commands_write);
            drop(events_read);
            let code = child(
                config,
                identity,
                File::from(commands_read),
                File::from(events_write),
            );
            unsafe { _exit(code) }
        }
        drop(commands_read);
        drop(events_write);
        Ok(Self {
            pid,
            writer: Some(File::from(commands_write)),
            reader: File::from(events_read),
            pending: Vec::new(),
            written: 0,
            incoming: Vec::new(),
            stopping: false,
            eof: false,
            reaped: None,
            ready: false,
        })
    }
    pub fn pid(&self) -> i32 {
        self.pid
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
        self.pending = wire::frame(&wire::encode(event)?);
        self.written = 0;
        Ok(true)
    }
    /// FDs are -1 when inactive, compatible with poll's ignored entries.
    pub fn poll_fds(&self) -> [(RawFd, i16); 2] {
        [
            (
                if self.eof {
                    -1
                } else {
                    self.reader.as_raw_fd()
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
    pub fn is_finished(&self) -> bool {
        self.reaped.is_some() && self.eof
    }

    /// Bounded work on each service turn. No read, write, or wait can block.
    pub fn step(&mut self) -> io::Result<Vec<Notice>> {
        let mut notices = Vec::new();
        let mut buffer = [0u8; 8192];
        // Read first, preventing child log output from stalling command progress.
        for _ in 0..8 {
            match self.reader.read(&mut buffer) {
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
                            return Err(invalid());
                        }
                        if self.incoming.len() - consumed < 4 + size {
                            break;
                        }
                        let notice =
                            decode_notice(&self.incoming[consumed + 4..consumed + 4 + size])?;
                        if notice == Notice::Ready {
                            self.ready = true;
                        }
                        notices.push(notice);
                        consumed += 4 + size;
                    }
                    self.incoming.drain(..consumed);
                    if self.incoming.len() > wire::MAX_FRAME + 4 {
                        return Err(invalid());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if self.eof && !self.incoming.is_empty() {
            return Err(invalid());
        }
        if let Some(writer) = &mut self.writer {
            if !self.pending.is_empty() {
                match writer.write(&self.pending[self.written..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "helper pipe closed",
                        ))
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
                    Err(error) => return Err(error),
                }
            }
        }
        if self.stopping && self.pending.is_empty() {
            self.writer.take();
        }
        if self.reaped.is_none() {
            let mut status = 0;
            let result = unsafe { waitpid(self.pid, &mut status, WNOHANG) };
            if result == self.pid {
                self.reaped = Some(status);
                notices.push(Notice::Reaped(status));
            } else if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
        Ok(notices)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Normal owner shutdown calls step until is_finished. On an early
        // startup error, EOF still preserves C's queued-script completion; this
        // destructor must never wait for an arbitrary user script.
        self.writer.take();
        if self.reaped.is_none() {
            let mut status = 0;
            unsafe {
                waitpid(self.pid, &mut status, WNOHANG);
            }
        }
    }
}

fn notice_payload(notice: Notice) -> Vec<u8> {
    match notice {
        Notice::Ready => vec![0],
        Notice::Output(mut bytes) => {
            bytes.insert(0, 1);
            bytes
        }
        Notice::ScriptExit(value)
        | Notice::ScriptSignal(value)
        | Notice::ExecError(value)
        | Notice::Error(value)
        | Notice::Reaped(value) => {
            let code = match notice {
                Notice::ScriptExit(_) => 2,
                Notice::ScriptSignal(_) => 3,
                Notice::ExecError(_) => 4,
                Notice::Error(_) => 5,
                _ => 6,
            };
            let mut bytes = vec![code];
            bytes.extend(value.to_le_bytes());
            bytes
        }
    }
}
fn decode_notice(bytes: &[u8]) -> io::Result<Notice> {
    let (&kind, data) = bytes.split_first().ok_or_else(invalid)?;
    if kind == 0 && data.is_empty() {
        return Ok(Notice::Ready);
    }
    if kind == 1 {
        return Ok(Notice::Output(data.to_vec()));
    }
    let value = i32::from_le_bytes(data.try_into().map_err(|_| invalid())?);
    match kind {
        2 => Ok(Notice::ScriptExit(value)),
        3 => Ok(Notice::ScriptSignal(value)),
        4 => Ok(Notice::ExecError(value)),
        5 => Ok(Notice::Error(value)),
        _ => Err(invalid()),
    }
}
fn send(events: &mut File, notice: Notice) -> io::Result<()> {
    events.write_all(&wire::frame(&notice_payload(notice)))
}

fn close_inherited(keep: [RawFd; 2]) -> io::Result<()> {
    // Snapshot first; closing the directory iterator's own FD during iteration
    // would be unsafe. /proc is available in the exact OpenWrt rootfs lifecycle.
    let fds = match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str()?.parse::<RawFd>().ok())
            .collect::<Vec<_>>(),
        Err(_) => {
            // Match C's fallback when /proc is unavailable in a minimal jail.
            let mut limit = [0; 2];
            if unsafe { getrlimit(7, &mut limit) } < 0 {
                return Err(io::Error::last_os_error());
            }
            for fd in 3..limit[0].min(i32::MAX as usize) {
                if !keep.contains(&(fd as RawFd)) {
                    unsafe {
                        close(fd as RawFd);
                    }
                }
            }
            return Ok(());
        }
    };
    for fd in fds {
        if fd > 2 && !keep.contains(&fd) {
            unsafe {
                close(fd);
            }
        }
    }
    Ok(())
}
fn child(
    config: Config,
    identity: Option<(u32, u32)>,
    mut commands: File,
    mut events: File,
) -> i32 {
    // C ignores these in the helper and its script descendants. SIGCHLD must
    // have its default disposition so wait works, independent of owner hooks.
    unsafe {
        for sig in [2, 13, 14, 15] {
            signal(sig, 1);
        }
        signal(17, 0);
    }
    if let Err(error) = close_inherited([commands.as_raw_fd(), events.as_raw_fd()]) {
        let _ = send(
            &mut events,
            Notice::Error(error.raw_os_error().unwrap_or(5)),
        );
        return 5;
    }
    if !config.debug {
        if let Some((uid, gid)) = identity.filter(|(uid, _)| *uid != 0) {
            if unsafe { setgroups(0, std::ptr::null()) } < 0
                || unsafe { setgid(gid) } < 0
                || unsafe { setuid(uid) } < 0
            {
                let _ = send(
                    &mut events,
                    Notice::Error(io::Error::last_os_error().raw_os_error().unwrap_or(1)),
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
    // Rust Command resets SIGPIPE before exec. Restore C's ignored disposition;
    // nothing else in this hook allocates or touches shared Rust state.
    unsafe {
        command.pre_exec(|| {
            signal(13, 1);
            Ok(())
        });
    }
    let mut output = None;
    if !config.debug {
        let (read, write) = pipe()?;
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
        loop {
            match output.read(&mut bytes) {
                Ok(0) => break,
                Ok(length) => {
                    if event_error.is_none() {
                        if let Err(error) = send(events, Notice::Output(bytes[..length].to_vec())) {
                            event_error = Some(error);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    fn script(text: &str) -> (std::path::PathBuf, Config) {
        let folder = std::env::temp_dir().join(format!(
            "dnsmasq-helper-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&folder).unwrap();
        let path = folder.join("script");
        std::fs::write(&path, format!("#!/bin/sh\n{text}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (
            folder,
            Config {
                script: path,
                script_user: None,
                debug: false,
            },
        )
    }
    fn until(helper: &mut Helper, predicate: impl Fn(&Helper, &[Notice]) -> bool) -> Vec<Notice> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut notices = Vec::new();
        while !predicate(helper, &notices) {
            assert!(Instant::now() < deadline, "helper timeout: {notices:?}");
            notices.extend(helper.step().unwrap());
            std::thread::sleep(Duration::from_millis(1));
        }
        notices
    }
    #[test]
    fn serial_scripts_progress_without_blocking_owner_and_eof_reaps() {
        let (folder, config) = script("sleep 0.2; printf '%s\\n' \"$*\"; exit 7");
        let mut helper = Helper::start(config).unwrap();
        until(&mut helper, |h, _| h.ready());
        let event = Event::Lease(super::super::tests::lease());
        assert!(helper.enqueue(&event).unwrap());
        assert!(!helper.enqueue(&event).unwrap());
        let start = Instant::now();
        helper.step().unwrap();
        assert!(start.elapsed() < Duration::from_millis(100));
        helper.begin_shutdown();
        let notices = until(&mut helper, |h, _| h.is_finished());
        assert!(notices.contains(&Notice::ScriptExit(7)));
        assert!(notices.contains(&Notice::Reaped(0)));
        let output = notices
            .iter()
            .filter_map(|n| match n {
                Notice::Output(value) => Some(value.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        assert!(
            String::from_utf8_lossy(&output).contains("add 02:00:00:00:00:01 192.0.2.10 client")
        );
        assert!(!std::path::Path::new(&format!("/proc/{}", helper.pid())).exists());
        drop(helper);
        std::fs::remove_dir_all(folder).unwrap();
    }
    #[test]
    fn helper_closes_inherited_service_fds_before_script() {
        let (folder, mut config) = script("for f in /proc/self/fd/*; do readlink \"$f\"; done");
        let marker = folder.join("must-not-inherit");
        let file = File::create(&marker).unwrap();
        // Clear CLOEXEC to verify helper isolation, not Command's exec closure.
        assert_eq!(unsafe { fcntl(file.as_raw_fd(), 2, 0) }, 0);
        config.debug = false;
        let mut helper = Helper::start(config).unwrap();
        until(&mut helper, |h, _| h.ready());
        assert!(helper
            .enqueue(&Event::Lease(super::super::tests::lease()))
            .unwrap());
        helper.begin_shutdown();
        let notices = until(&mut helper, |h, _| h.is_finished());
        let output = notices
            .iter()
            .filter_map(|n| match n {
                Notice::Output(value) => Some(value.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        assert!(!String::from_utf8_lossy(&output).contains("must-not-inherit"));
        drop(helper);
        drop(file);
        std::fs::remove_dir_all(folder).unwrap();
    }
    #[test]
    fn unknown_user_is_configuration_failure_and_missing_script_is_event() {
        let (folder, mut config) = script("exit 0");
        config.script_user = Some(b"dnsmasq-m5-nonexistent-user-87943".to_vec());
        assert_eq!(Helper::start(config.clone()).err().unwrap().code, 1);
        config.script_user = None;
        config.script = folder.join("missing");
        let mut helper = Helper::start(config).unwrap();
        until(&mut helper, |h, _| h.ready());
        helper
            .enqueue(&Event::Lease(super::super::tests::lease()))
            .unwrap();
        helper.begin_shutdown();
        let notices = until(&mut helper, |h, _| h.is_finished());
        assert!(notices.contains(&Notice::ExecError(2)));
        assert!(notices.contains(&Notice::Reaped(0)));
        drop(helper);
        std::fs::remove_dir_all(folder).unwrap();
    }
    #[test]
    fn malformed_ipc_is_rejected_without_executing_fixed_script() {
        let (folder, config) = script("echo unexpected");
        let mut helper = Helper::start(config).unwrap();
        until(&mut helper, |h, _| h.ready());
        helper.pending = wire::frame(&[1, 255]);
        helper.begin_shutdown();
        let notices = until(&mut helper, |h, _| h.is_finished());
        assert!(notices.contains(&Notice::Error(22)));
        assert!(!notices.iter().any(|n| matches!(n, Notice::Output(_))));
        drop(helper);
        std::fs::remove_dir_all(folder).unwrap();
    }
}
