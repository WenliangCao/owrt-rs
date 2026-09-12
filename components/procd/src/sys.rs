//! The syscalls the supervisor needs that `std` does not expose: rlimits,
//! priority, supplementary groups, and passwd/group lookup.
//!
//! Same house style as `owrt-ubus`'s `sys`: plain `extern "C"` declarations
//! against the platform libc, no third-party crate.

use std::ffi::CString;
use std::io;

#[repr(C)]
#[derive(Clone, Copy)]
struct RLimit {
    cur: u64,
    max: u64,
}

#[repr(C)]
struct Passwd {
    pw_name: *const u8,
    pw_passwd: *const u8,
    pw_uid: u32,
    pw_gid: u32,
    pw_gecos: *const u8,
    pw_dir: *const u8,
    pw_shell: *const u8,
}

#[repr(C)]
struct Group {
    gr_name: *const u8,
    gr_passwd: *const u8,
    gr_gid: u32,
    gr_mem: *const *const u8,
}

extern "C" {
    fn getrlimit(resource: i32, rlim: *mut RLimit) -> i32;
    fn setrlimit(resource: i32, rlim: *const RLimit) -> i32;
    fn setpriority(which: i32, who: u32, prio: i32) -> i32;
    fn initgroups(user: *const u8, group: u32) -> i32;
    fn getpwnam(name: *const u8) -> *const Passwd;
    fn getgrnam(name: *const u8) -> *const Group;
}

const PRIO_PROCESS: i32 = 0;
const RLIM_INFINITY: u64 = u64::MAX;

/// `rlimit_names[]` from `instance.c:176`, including the four Linux-only
/// entries. Values are the Linux asm-generic numbers, which is what this
/// target uses -- they differ per platform (RLIMIT_NOFILE is 7 on Linux and 8
/// on Darwin), and a wrong one silently sets a different limit than the
/// service asked for. `tools/check_rlimit_consts.sh` diffs this table against
/// <sys/resource.h>; run it with the target toolchain, not the build host's.
pub const RLIMIT_NAMES: &[(&str, i32)] = &[
    ("as", 9),
    ("core", 4),
    ("cpu", 0),
    ("data", 2),
    ("fsize", 1),
    ("memlock", 8),
    ("nofile", 7),
    ("nproc", 6),
    ("rss", 5),
    ("stack", 3),
    ("nice", 13),
    ("rtprio", 14),
    ("msgqueue", 12),
    ("sigpending", 11),
];

/// `instance_limits()`. An unknown limit name, an unreadable current limit or
/// a value that parses to nothing all leave the limit alone -- the C returns
/// without touching it, and so does this.
///
/// The value is `"<cur>"` or `"<cur> <max>"`, or the word `unlimited`. When
/// only `cur` is given the existing `max` is kept, which is why the current
/// limit has to be read first.
pub fn apply_limit(name: &str, value: &str) -> io::Result<()> {
    let Some(&(_, resource)) = RLIMIT_NAMES.iter().find(|(n, _)| *n == name) else {
        return Ok(());
    };

    let rlim = if value == "unlimited" {
        RLimit { cur: RLIM_INFINITY, max: RLIM_INFINITY }
    } else {
        let mut cur_max = RLimit { cur: 0, max: 0 };
        // SAFETY: getrlimit(2) writes one struct rlimit through the pointer.
        if unsafe { getrlimit(resource, &mut cur_max) } != 0 {
            return Ok(());
        }
        let mut it = value.split_whitespace();
        let Some(cur) = it.next().and_then(|s| s.parse::<u64>().ok()) else {
            return Ok(());
        };
        let max = it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(cur_max.max);
        RLimit { cur, max }
    };

    // SAFETY: setrlimit(2) reads one struct rlimit through the pointer. A
    // failure is the C's silent no-op, so the result is deliberately dropped.
    unsafe { setrlimit(resource, &rlim) };
    Ok(())
}

/// `setpriority(PRIO_PROCESS, 0, nice)`. Only called when nice is non-zero,
/// as in the C.
pub fn set_nice(nice: i32) {
    // SAFETY: setpriority(2) takes three scalars and touches no memory.
    unsafe {
        setpriority(PRIO_PROCESS, 0, nice);
    }
}

/// `initgroups(user, gid)`. Returns false on failure; the C exits 127.
pub fn init_groups(user: &str, gid: u32) -> bool {
    let Ok(c) = CString::new(user) else {
        return false;
    };
    // SAFETY: `c` is a NUL-terminated string that outlives the call.
    unsafe { initgroups(c.as_ptr().cast(), gid) == 0 }
}

/// C `atoi()`, which procd uses for the respawn and watchdog string
/// arrays: optional leading whitespace, optional sign, then the longest
/// digit prefix -- "5x" is 5, "" is 0 -- returned as `int` and stored into
/// a `uint32_t`, so "-1" becomes 0xffffffff.
pub fn atoi_u32(s: &str) -> u32 {
    let t = s.trim_start();
    let (neg, t) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let mut v: i64 = 0;
    for c in t.chars().take_while(|c| c.is_ascii_digit()) {
        v = v * 10 + (c as i64 - '0' as i64);
        if v > i64::from(i32::MAX) {
            v = i64::from(i32::MAX);
            break;
        }
    }
    let v = if neg { -v } else { v };
    v as i32 as u32
}

/// `getpwnam()` -> (uid, gid, home). None when the user does not exist.
/// STATE_UBUS needs the home directory to mkdir/chown it for ubusd.
pub fn lookup_user_home(name: &str) -> Option<(u32, u32, String)> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` outlives the call; the returned static buffer is copied
    // out immediately.
    let p = unsafe { getpwnam(c.as_ptr().cast()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: non-null means a valid struct passwd; pw_dir is NUL-terminated.
    let pw = unsafe { &*p };
    let home = if pw.pw_dir.is_null() {
        String::new()
    } else {
        // SAFETY: pw_dir points at a NUL-terminated string in the buffer.
        unsafe { std::ffi::CStr::from_ptr(pw.pw_dir.cast()) }
            .to_string_lossy()
            .into_owned()
    };
    Some((pw.pw_uid, pw.pw_gid, home))
}

/// `getpwnam()` -> (uid, gid). None when the user does not exist.
pub fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` outlives the call. getpwnam returns a pointer into a static
    // buffer, read immediately and not retained.
    let p = unsafe { getpwnam(c.as_ptr().cast()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: non-null means it points at a valid struct passwd.
    let pw = unsafe { &*p };
    Some((pw.pw_uid, pw.pw_gid))
}

/// `getgrnam()` -> gid. None when the group does not exist.
pub fn lookup_group(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` outlives the call. getgrnam returns a pointer into a static
    // buffer, read immediately and not retained.
    let p = unsafe { getgrnam(c.as_ptr().cast()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: non-null means it points at a valid struct group.
    Some(unsafe { &*p }.gr_gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn full_sigchld_pipe_preserves_the_interrupted_error() {
        use std::os::fd::AsRawFd;
        extern "C" {
            fn write(fd: i32, bytes: *const u8, length: usize) -> isize;
            fn __errno_location() -> *mut i32;
        }
        let (_read, write_end) = owrt_ubus::sys::pipe().unwrap();
        let fd = write_end.as_raw_fd();
        owrt_ubus::sys::set_nonblocking(fd).unwrap();
        let bytes = [0u8; 4096];
        // SAFETY: the pipe and stack buffer stay live; O_NONBLOCK bounds writes.
        while unsafe { write(fd, bytes.as_ptr(), bytes.len()) } > 0 {}
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        // Call the handler directly, without changing the process signal disposition.
        let previous = SIGCHLD_WAKEUP.swap(fd, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: __errno_location returns this thread's live errno cell.
        let errno = unsafe { __errno_location() };
        // SAFETY: save an interrupted error before the real handler's EAGAIN.
        unsafe { *errno = 22; }
        sigchld_signal(17);
        // SAFETY: the thread-local cell remains valid.
        let after = unsafe { *errno };
        SIGCHLD_WAKEUP.store(previous, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(after, 22);
    }

    #[test]
    fn an_unknown_limit_is_a_no_op_not_an_error() {
        assert!(apply_limit("no-such-limit", "1234").is_ok());
    }

    #[test]
    fn root_resolves() {
        // Present on every system this runs on, including the build hosts.
        let (uid, _) = lookup_user("root").expect("root must exist");
        assert_eq!(uid, 0);
    }

    /// R81 F01. PID 1's stderr is the console with O_NONBLOCK set
    /// (set_stdio); once it stops draining (XOFF, a >4 KiB burst at 115200)
    /// write(2) fails with EAGAIN, and `eprintln!` turned that into a panic
    /// -- an abort of init under panic = "abort". Build exactly that fd:
    /// a full non-blocking pipe on fd 2, then log through the sink.
    #[test]
    fn a_full_nonblocking_stderr_drops_the_line_instead_of_panicking() {
        extern "C" {
            fn pipe(fds: *mut i32) -> i32;
            fn write(fd: i32, buf: *const u8, n: usize) -> isize;
            fn dup(fd: i32) -> i32;
        }
        const EAGAIN: i32 = 11;
        let mut fds = [0i32; 2];
        // SAFETY: plain fd syscalls on fds this test owns; fd 2 is put back
        // before the test returns.
        unsafe {
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let (r, w) = (fds[0], fds[1]);
            fcntl(w, F_SETFL, fcntl(w, F_GETFL, 0) | O_NONBLOCK);
            let junk = [b'x'; 4096];
            while write(w, junk.as_ptr(), junk.len()) > 0 {}
            // The fixture is the finding: a raw write now fails with EAGAIN.
            assert!(write(w, junk.as_ptr(), 1) < 0);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(EAGAIN));

            let saved = dup(2);
            assert!(saved >= 0);
            assert!(dup2(w, 2) >= 0);
            ulog_stdio("- init -");
            stderr_line("Failed to exec upgraded.");
            // Reached: no panic. Restore before any assertion can print.
            assert!(dup2(saved, 2) >= 0);
            close(saved);
            close(r);
            close(w);
        }
    }
}

extern "C" {
    fn openlog(ident: *const u8, option: i32, facility: i32);
    fn syslog(priority: i32, format: *const u8, arg: *const u8);
    fn closelog();
}

/// `LOG_INFO` and `LOG_ERR`: an instance's stdout is logged at info, its
/// stderr at error (`instance_stdout` / `instance_stderr`). procd's own
/// lines: `LOG()` is ULOG_INFO, `ERROR()` is ULOG_ERR, `ULOG_WARN` and
/// `DEBUG()`/`ULOG_NOTE` are the two in between.
pub const LOG_ERR: i32 = 3;
pub const LOG_WARNING: i32 = 4;
pub const LOG_NOTICE: i32 = 5;
pub const LOG_INFO: i32 = 6;
/// `LOG_DAEMON`, the facility procd restores after each instance line.
pub const LOG_DAEMON: i32 = 3 << 3;

/// `facilitynames` from <syslog.h>, which `syslog_facility_str_to_int()`
/// walks. An unmatched name yields the terminator's value, -1; the caller
/// (`instance_config_parse`) keeps LOG_DAEMON in that case.
pub const FACILITY_NAMES: &[(&str, i32)] = &[
    ("auth", 4 << 3),
    ("authpriv", 10 << 3),
    ("cron", 9 << 3),
    ("daemon", 3 << 3),
    ("ftp", 11 << 3),
    ("kern", 0),
    ("lpr", 6 << 3),
    ("mail", 2 << 3),
    ("mark", 24 << 3),
    ("news", 7 << 3),
    ("security", 4 << 3),
    ("syslog", 5 << 3),
    ("user", 1 << 3),
    ("uucp", 8 << 3),
    ("local0", 16 << 3),
    ("local1", 17 << 3),
    ("local2", 18 << 3),
    ("local3", 19 << 3),
    ("local4", 20 << 3),
    ("local5", 21 << 3),
    ("local6", 22 << 3),
    ("local7", 23 << 3),
];

/// `syslog_facility_str_to_int()`. Case-insensitive; -1 when nothing matches.
pub fn facility_from_str(name: &str) -> i32 {
    FACILITY_NAMES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
        .unwrap_or(-1)
}

// -- ulog ------------------------------------------------------------------
//
// libubox's ulog, as procd uses it: ONE sink for every message procd itself
// prints. procd.c main() opens ULOG_KMSG (or ULOG_STDIO with -S), state.c's
// STATE_INIT switches to ULOG_SYSLOG. Nothing here can panic: as PID 1 the
// console stderr is O_NONBLOCK (set_stdio), and `eprintln!` on an EAGAIN was
// an abort of init -- a kernel panic on the device (R81 F01). A line that
// cannot be written is dropped, which is what ulog_stdio/ulog_kmsg do too.

/// `ULOG_STDIO` / `ULOG_KMSG` / `ULOG_SYSLOG`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogChannel {
    Stdio,
    Kmsg,
    Syslog,
}

static LOG_CHANNEL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
/// `debug` from `-d <level>` / `DBGLVL`; `DEBUG(level, ...)` prints at or
/// below it. Default 0: the C's DEBUG lines are silent on a stock boot.
static DEBUG_LEVEL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// `ulog_open(channel, LOG_DAEMON, "procd")`.
pub fn ulog_open(ch: LogChannel) {
    use std::sync::atomic::Ordering::SeqCst;
    if ch == LogChannel::Syslog {
        // SAFETY: a static NUL-terminated ident that lives forever.
        unsafe { openlog(c"procd".as_ptr().cast(), 0, LOG_DAEMON) };
    }
    LOG_CHANNEL.store(ch as u8, SeqCst);
}

pub fn log_channel() -> LogChannel {
    match LOG_CHANNEL.load(std::sync::atomic::Ordering::SeqCst) {
        1 => LogChannel::Kmsg,
        2 => LogChannel::Syslog,
        _ => LogChannel::Stdio,
    }
}

pub fn set_debug_level(level: i32) {
    DEBUG_LEVEL.store(level, std::sync::atomic::Ordering::SeqCst);
}

pub fn debug_level() -> i32 {
    DEBUG_LEVEL.load(std::sync::atomic::Ordering::SeqCst)
}

/// `ulog(priority, "%s\n", line)` on whichever channel is open.
pub fn ulog(priority: i32, line: &str) {
    match log_channel() {
        LogChannel::Stdio => ulog_stdio(line),
        LogChannel::Kmsg => ulog_kmsg(priority, line),
        LogChannel::Syslog => ulog_syslog(priority, line),
    }
}

/// `ulog_stdio()`: `<ident>: <line>` on stderr. A short or failed write is
/// dropped, never reported -- stderr may be a non-blocking console.
pub fn ulog_stdio(line: &str) {
    use std::io::Write;
    let _ = writeln!(io::stderr().lock(), "procd: {line}");
}

/// A bare line on stderr, for the few places the C uses `fprintf(stderr)`
/// directly (sysupgrade.c). Same non-panicking write.
pub fn stderr_line(line: &str) {
    use std::io::Write;
    let _ = writeln!(io::stderr().lock(), "{line}");
}

/// `ulog_kmsg()`: one `<prio>procd: line` record per call, opened and closed
/// around it like the C's fopen/fclose. The prefix is the bare syslog
/// priority (`<6>` for LOG_INFO), which is exactly what libubox writes --
/// the kernel supplies the facility.
fn ulog_kmsg(priority: i32, line: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = f.write_all(format!("<{priority}>procd: {line}\n").as_bytes());
    }
}

/// `vsyslog(priority, ...)` under the `procd`/LOG_DAEMON openlog.
fn ulog_syslog(priority: i32, line: &str) {
    let end = line.bytes().position(|b| b == 0).unwrap_or(line.len());
    let Ok(c) = CString::new(&line[..end]) else { return };
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe { syslog(priority, c"%s".as_ptr().cast(), c.as_ptr().cast()) };
}

/// `do_reboot()` (signal.c): sync, a two-second window for the last output
/// to reach the console, reboot, then hang forever -- the C never exits
/// here. process::exit would run atexit handlers (not async-signal-safe)
/// and, on a reboot(2) failure, would make PID 1 exit and panic the kernel
/// where the C hangs and lets the hardware watchdog bite. (R73/5.)
pub fn crash_reboot() -> ! {
    extern "C" {
        fn sleep(secs: u32) -> u32;
    }
    sync_fs();
    // SAFETY: sleep(3) and reboot(2) are async-signal-safe.
    unsafe {
        sleep(2);
        reboot(RB_AUTOBOOT);
    }
    loop {
        std::hint::spin_loop();
    }
}

/// The Rust-only failure the C cannot have: a panic. With `panic = "abort"`
/// this hook is the last code to run before the process dies, so as PID 1
/// it does what `signal_crash()` does for SIGSEGV -- log, then
/// `do_reboot()` -- instead of aborting into a kernel panic. Any other
/// process (the supervisor, or a forked child that has not exec'd yet) logs
/// and lets the abort proceed. The pid is read at panic time, not cached:
/// children inherit the hook across fork.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("panic: {info}");
        ulog(LOG_ERR, &msg);
        if std::process::id() != 1 {
            return;
        }
        // The open channel may be syslog with logd already gone; the kernel
        // log is the one place a dying init can still be heard.
        if log_channel() != LogChannel::Kmsg {
            ulog_kmsg(LOG_ERR, &msg);
            ulog_kmsg(LOG_ERR, "Rebooting as procd has crashed");
        }
        ulog(LOG_ERR, "Rebooting as procd has crashed");
        crash_reboot();
    }));
}

/// One line of an instance's output, logged the way `instance_stdio` does:
/// reopen the log with the instance's ident and facility, write, then put the
/// log back to `procd`/LOG_DAEMON so procd's own messages are unaffected.
///
/// Using the platform's syslog(3) rather than formatting a datagram by hand
/// is deliberate: libubox's ulog calls the same function, so the framing,
/// timestamp and truncation behaviour cannot drift apart.
pub fn log_instance_line(ident: &str, facility: i32, priority: i32, line: &[u8]) {
    // The line is raw child output. syslog's %s stops at the first NUL, so
    // an interior NUL truncates the line exactly as the C's ulog would.
    let end = line.iter().position(|b| *b == 0).unwrap_or(line.len());
    let (Ok(cid), Ok(cline)) = (CString::new(ident), CString::new(&line[..end])) else {
        return;
    };
    let fmt = c"%s";
    // SAFETY: all three strings are NUL-terminated and outlive the calls.
    // openlog retains `cid`'s pointer until the next openlog, which is why
    // the restore below happens before this function returns.
    unsafe {
        openlog(cid.as_ptr().cast(), 0, facility);
        syslog(priority, fmt.as_ptr().cast(), cline.as_ptr().cast());
        closelog();
        openlog(c"procd".as_ptr().cast(), 0, LOG_DAEMON);
    }
}

#[cfg(test)]
mod log_tests {
    use super::*;

    #[test]
    fn an_unknown_facility_is_minus_one_not_a_default() {
        assert_eq!(facility_from_str("daemon"), LOG_DAEMON);
        assert_eq!(facility_from_str("DAEMON"), LOG_DAEMON);
        assert_eq!(facility_from_str("local3"), 19 << 3);
        assert_eq!(facility_from_str("no-such-facility"), -1);
    }
}

extern "C" {
    #[link_name = "if_nametoindex"]
    fn if_nametoindex_c(name: *const u8) -> u32;
}

/// `if_nametoindex()`. Zero when the interface does not exist, which is what
/// the C stores too -- `instance_netdev_update` does not special-case a
/// missing interface, so two absent interfaces compare equal and an
/// interface that appears later counts as a change.
pub fn if_nametoindex(name: &str) -> u32 {
    let Ok(c) = CString::new(name) else {
        return 0;
    };
    // SAFETY: `c` is NUL-terminated and outlives the call.
    unsafe { if_nametoindex_c(c.as_ptr().cast()) }
}

/// MD5 of a file's contents, as `instance_file_update` computes with
/// `md5sum(...)`. An unreadable file yields all zeroes, so two unreadable
/// files compare equal and a file that becomes readable counts as a change.
///
/// This is a digest for change detection, never for authentication; MD5 is
/// what the C stores and matching it is the whole point.
pub fn file_md5(path: &str) -> [u8; 16] {
    let Ok(data) = std::fs::read(path) else {
        return [0u8; 16];
    };
    md5(&data)
}

use owrt_ubus::digest::md5;

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn an_unreadable_file_digests_to_zero() {
        assert_eq!(file_md5("/no/such/file/at/all"), [0u8; 16]);
    }
}

extern "C" {
    fn setgid(gid: u32) -> i32;
    fn setuid(uid: u32) -> i32;
}

/// `setgid(2)`. Separate from setuid because `instance_run` guards each on
/// its own non-zero check and exits 127 on either failure.
pub fn set_gid(gid: u32) -> io::Result<()> {
    // SAFETY: setgid(2) takes a plain id and touches no memory.
    if unsafe { setgid(gid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `setuid(2)`. Must come after `set_gid`.
pub fn set_uid(uid: u32) -> io::Result<()> {
    // SAFETY: setuid(2) takes a plain id and touches no memory.
    if unsafe { setuid(uid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod atoi_tests {
    use super::*;

    #[test]
    fn atoi_prefix_semantics() {
        assert_eq!(atoi_u32("3600"), 3600);
        assert_eq!(atoi_u32("5x"), 5, "digits before the first non-digit");
        assert_eq!(atoi_u32(""), 0);
        assert_eq!(atoi_u32("x5"), 0);
        assert_eq!(atoi_u32("  7"), 7);
        assert_eq!(atoi_u32("-1"), 0xffff_ffff, "atoi -> int -> uint32_t");
    }
}

// -- PID 1 plumbing (state.c, inittab.c, signal.c helpers) -------------------

extern "C" {
    /// Variadic, like the real prototype, so one declaration serves the
    /// int-argument (TIOCSCTTY) and pointer-argument (WDIOC) callers.
    pub fn ioctl(fd: i32, req: u64, ...) -> i32;
    fn open(path: *const u8, flags: i32, mode: u32) -> i32;
    fn close(fd: i32) -> i32;
    fn dup2(old: i32, new: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    fn chown(path: *const u8, uid: u32, gid: u32) -> i32;
    fn sync();
    fn reboot(cmd: i32) -> i32;
    fn fork() -> i32;
}

const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_NOCTTY: i32 = 0o400;
const O_NONBLOCK: i32 = 0o4000;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;

/// `reboot(2)` magic (linux/reboot.h). `RB_DISABLE_CAD` makes ctrl-alt-del
/// deliver SIGINT to PID 1 instead of hard-rebooting.
pub const RB_AUTOBOOT: i32 = 0x01234567;
pub const RB_HALT_SYSTEM: i32 = 0xcdef0123u32 as i32;
pub const RB_POWER_OFF: i32 = 0x4321fedc;
pub const RB_DISABLE_CAD: i32 = 0;

/// `patch_fd()`: redirect one of stdin/stdout/stderr to a device. A relative
/// name is under /dev; a failed open falls back to /dev/null; NULL means
/// /dev/null outright.
pub fn patch_fd(device: Option<&str>, fd: i32, write: bool) -> bool {
    let flags = if write { O_WRONLY } else { O_RDONLY } | O_NOCTTY;
    let path = match device {
        None => "/dev/null".to_string(),
        Some(d) if d.starts_with('/') => d.to_string(),
        Some(d) => format!("/dev/{d}"),
    };
    let Ok(c) = CString::new(path.clone()) else { return false };
    // SAFETY: NUL-terminated path, no retained pointers.
    let mut nfd = unsafe { open(c.as_ptr().cast(), flags, 0) };
    if nfd < 0 && path != "/dev/null" {
        // SAFETY: as above.
        nfd = unsafe { open(c"/dev/null".as_ptr().cast(), flags, 0) };
    }
    if nfd < 0 {
        return false;
    }
    // SAFETY: plain fd ops.
    unsafe {
        let ok = dup2(nfd, fd) >= 0;
        if nfd > 2 {
            close(nfd);
        }
        ok
    }
}

/// `set_stdio()`: point 0/1/2 at a tty and make stderr non-blocking, as
/// STATE_UBUS does with "console".
pub fn set_stdio(tty: &str) {
    // The C uses freopen, which on failure leaves the old stdio in place --
    // it does NOT fall back to /dev/null the way patch_fd does for children.
    // Booting in a mount namespace without a console must keep its stderr.
    if !dev_exist(tty) && !tty.starts_with('/') {
        ulog(LOG_ERR, &format!("failed to set stdio: no /dev/{tty}"));
        return;
    }
    // freopen carries NO O_NOCTTY: the session leader acquires the console
    // as its controlling terminal here, which is how ^C on the serial
    // console reaches PID 1. patch_fd (used for CHILDREN) does pass
    // O_NOCTTY, matching utils.c. (R73/6g.)
    let ok = stdio_open(tty, 0, false) & stdio_open(tty, 1, true) & stdio_open(tty, 2, true);
    if !ok {
        ulog(LOG_ERR, &format!("failed to set stdio to {tty}"));
        return;
    }
    // SAFETY: fcntl on stderr with integer args only.
    unsafe {
        let fl = fcntl(2, F_GETFL, 0);
        if fl >= 0 {
            fcntl(2, F_SETFL, fl | O_NONBLOCK);
        }
    }
}

/// One freopen leg: open WITHOUT O_NOCTTY and dup2 onto the std fd.
fn stdio_open(tty: &str, fd: i32, write: bool) -> bool {
    let path = if tty.starts_with('/') { tty.to_string() } else { format!("/dev/{tty}") };
    let Ok(c) = CString::new(path) else { return false };
    let flags = if write { O_WRONLY } else { O_RDONLY };
    // SAFETY: NUL-terminated path; fd ops on the result.
    unsafe {
        let nfd = open(c.as_ptr().cast(), flags, 0);
        if nfd < 0 {
            return false;
        }
        let ok = dup2(nfd, fd) >= 0;
        if nfd > 2 {
            close(nfd);
        }
        ok
    }
}

/// `set_console()`: the shutdown path's best-effort console -- cmdline
/// `console=`, then tty0, then console.
pub fn set_console() {
    let tty = cmdline_val("console", 0)
        .map(|v| v.split(',').next().unwrap_or("").to_string())
        .filter(|t| dev_exist(t));
    let tty = tty.or_else(|| ["tty0", "console"].iter().find(|t| dev_exist(t)).map(|t| t.to_string()));
    if let Some(t) = tty {
        set_stdio(&t);
    }
}

/// `close(2)` for a raw fd whose ownership was just taken back.
///
/// # Safety
/// `fd` must be open and not owned by anything that will close it again.
pub unsafe fn close_fd(fd: i32) -> i32 {
    close(fd)
}

/// `dev_exist()`: can the name be opened under /dev? An empty id cannot,
/// which is why an inittab respawn entry with an empty id never respawns.
pub fn dev_exist(dev: &str) -> bool {
    // openat(dfd, "", ...) is ENOENT: an empty id NEVER exists. Formatting
    // it into a path would name the /dev directory itself, which opens --
    // measured: the empty-id respawn entry came back after a kill, where the
    // C runs it exactly once.
    if dev.is_empty() {
        return false;
    }
    let Ok(c) = CString::new(format!("/dev/{dev}")) else { return false };
    // SAFETY: NUL-terminated path.
    let fd = unsafe { open(c.as_ptr().cast(), O_RDONLY | O_NOCTTY, 0) };
    if fd < 0 {
        return false;
    }
    // SAFETY: fd is open.
    unsafe { close(fd) };
    true
}

/// `get_cmdline_val_offset()`: the value of the nth `name=value` word in
/// /proc/cmdline (0-based).
pub fn cmdline_val(name: &str, nth: usize) -> Option<String> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
    cmdline
        .split_ascii_whitespace()
        .filter_map(|w| w.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
        .nth(nth)
        .map(str::to_string)
}

/// `get_active_console()`: the first word of /sys/class/tty/console/active.
pub fn active_console() -> Option<String> {
    let s = std::fs::read_to_string("/sys/class/tty/console/active").ok()?;
    s.split_ascii_whitespace().next().map(str::to_string)
}

/// `chown(2)` for the ubus home directory in STATE_UBUS.
pub fn chown_path(path: &str, uid: u32, gid: u32) -> bool {
    let Ok(c) = CString::new(path) else { return false };
    // SAFETY: NUL-terminated path.
    unsafe { chown(c.as_ptr().cast(), uid, gid) == 0 }
}

/// `is_container()`: the `container` environment variable, as container.c
/// tests it.
pub fn is_container() -> bool {
    std::env::var_os("container").is_some()
}

/// `sync(2)`.
pub fn sync_fs() {
    // SAFETY: no arguments.
    unsafe { sync() };
}

/// `reboot(2)` with one of the RB_* commands. In a PID namespace this ends
/// the namespace rather than the host, which is exactly what the isolated
/// boot probes rely on.
pub fn reboot_cmd(cmd: i32) -> bool {
    // SAFETY: integer command only.
    unsafe { reboot(cmd) == 0 }
}

/// `perform_halt()`'s tail: fork so the kernel's do_exit on init does not
/// panic the machine, reboot from the child, spin in the parent.
pub fn halt_forever(event: i32) -> ! {
    // SAFETY: fork + reboot, no memory.
    unsafe {
        if fork() == 0 {
            reboot(event);
            std::process::exit(0);
        }
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// The shutdown signals PID 1 must answer (signal.c). The handler only
/// stores the reboot event and wakes the loop; the main loop acts on it.
pub static SHUTDOWN_EVENT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn shutdown_signal(sig: i32) {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    const SIGUSR1: i32 = 10;
    const SIGUSR2: i32 = 12;
    const SIGPWR: i32 = 30;
    let event = match sig {
        SIGINT | SIGTERM => RB_AUTOBOOT,
        SIGUSR1 => RB_HALT_SYSTEM,
        SIGUSR2 | SIGPWR => RB_POWER_OFF,
        _ => return,
    };
    SHUTDOWN_EVENT.store(event, std::sync::atomic::Ordering::SeqCst);
    wake_loop();
}

/// One byte down the loop's self-pipe, errno preserved: the loop may be
/// sleeping until a deadline rather than ticking, so a signal that changes
/// what it must do next has to interrupt that sleep.
fn wake_loop() {
    extern "C" {
        fn write(fd: i32, buf: *const u8, n: usize) -> isize;
    }
    #[cfg(target_os = "linux")]
    // SAFETY: errno is thread-local and must survive an asynchronous handler.
    let (errno, saved_errno) = unsafe {
        extern "C" { fn __errno_location() -> *mut i32; }
        let errno = __errno_location();
        (errno, *errno)
    };
    let fd = SIGCHLD_WAKEUP.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write(2) of one byte to a non-blocking pipe; a full pipe
        // (EAGAIN) already means a wakeup is pending.
        unsafe { write(fd, b"s".as_ptr(), 1) };
    }
    #[cfg(target_os = "linux")]
    // SAFETY: the pointer still names this thread's errno cell.
    unsafe { *errno = saved_errno; }
}

extern "C" fn crash_signal(_sig: i32) {
    // signal_crash(): the ERROR() line is skipped here -- formatting is not
    // async-signal-safe -- and do_reboot() follows.
    crash_reboot();
}

static SIGCHLD_WAKEUP: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
// Start armed so children inherited/created before entering the main loop
// get an initial sweep. A signal during a sweep arms the following one.
static CHILD_EXIT_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

extern "C" fn sigchld_signal(_sig: i32) {
    extern "C" {
        fn write(fd: i32, buf: *const u8, n: usize) -> isize;
    }
    #[cfg(target_os = "linux")]
    // SAFETY: errno is thread-local and must survive an asynchronous handler.
    let (errno, saved_errno) = unsafe {
        extern "C" { fn __errno_location() -> *mut i32; }
        let errno = __errno_location();
        (errno, *errno)
    };
    CHILD_EXIT_PENDING.store(true, std::sync::atomic::Ordering::Relaxed);
    let fd = SIGCHLD_WAKEUP.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write(2) of one byte to a non-blocking pipe; a full pipe
        // (EAGAIN) already means a wakeup is pending.
        unsafe { write(fd, b"c".as_ptr(), 1) };
    }
    #[cfg(target_os = "linux")]
    // SAFETY: the pointer still names this thread's errno cell.
    unsafe { *errno = saved_errno; }
}

pub fn take_child_exit_pending() -> bool {
    CHILD_EXIT_PENDING.swap(false, std::sync::atomic::Ordering::Relaxed)
}

/// uloop's SIGCHLD self-pipe: a child exit wakes the main loop's poll()
/// instead of waiting for its next tick. Returns the read end; the loop
/// drains it after every poll. Installed in both modes, like uloop_init().
pub fn install_sigchld_wakeup() -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    const SIGCHLD: i32 = 17;
    let (r, w) = owrt_ubus::sys::pipe()?;
    owrt_ubus::sys::set_nonblocking(r.as_raw_fd())?;
    owrt_ubus::sys::set_nonblocking(w.as_raw_fd())?;
    SIGCHLD_WAKEUP.store(w.as_raw_fd(), std::sync::atomic::Ordering::SeqCst);
    // The write end lives for the process; the handler owns it from here.
    std::mem::forget(w);
    owrt_ubus::sys::set_signal_handler(SIGCHLD, sigchld_signal);
    Ok(r)
}

/// Empty a wakeup pipe after poll() reported it readable.
pub fn drain_wakeup(fd: std::os::fd::RawFd) {
    extern "C" {
        fn read(fd: i32, buf: *mut u8, n: usize) -> isize;
    }
    let mut buf = [0u8; 64];
    // SAFETY: read(2) into a live buffer on a non-blocking fd.
    while unsafe { read(fd, buf.as_mut_ptr(), buf.len()) } > 0 {}
}

/// `procd_signal()` for the PID 1 half: shutdown signals, crash-to-reboot,
/// a dummy HUP, and ctrl-alt-del routed to SIGINT.
pub fn procd_signal_pid1() {
    use owrt_ubus::sys::set_signal_handler;
    for sig in [2, 15, 10, 12, 30] {
        set_signal_handler(sig, shutdown_signal);
    }
    // SIGSEGV and SIGBUS as in the C, plus SIGABRT: a Rust abort (an
    // allocation failure, or a panic whose hook did not get to reboot) must
    // end the same way, not as an init exit and a kernel panic.
    for sig in [11, 7, 6] {
        set_signal_handler(sig, crash_signal);
    }
    extern "C" fn dummy(_sig: i32) {}
    set_signal_handler(1, dummy);
    reboot_cmd(RB_DISABLE_CAD);
}
