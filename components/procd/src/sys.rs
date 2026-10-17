//! The syscalls the supervisor needs that `std` does not expose: rlimits,
//! priority, supplementary groups, and passwd/group lookup.
//!
//! Business policy uses rustix/std; libc compatibility and signal handlers
//! live behind the small owrt-platform boundaries.

use std::ffi::CString;
use std::io;

pub use owrt_platform::procd::identity::{lookup_group, lookup_user};
use owrt_platform::procd::process::reboot_cmd;
use owrt_platform::procd::signals::crash_reboot;

pub fn take_inherited_watchdog(parse: fn(&str) -> u32) -> Option<io::Result<std::os::fd::OwnedFd>> {
    owrt_platform::procd::watchdog::take_inherited_watchdog(parse)
}
pub fn watchdog_set_timeout(fd: impl std::os::fd::AsFd, value: &mut i32) -> io::Result<()> {
    owrt_platform::procd::watchdog::set_timeout(fd, value)
}
pub fn watchdog_support(
    fd: impl std::os::fd::AsFd,
) -> io::Result<owrt_platform::procd::watchdog::WatchdogInfo> {
    owrt_platform::procd::watchdog::support(fd)
}
pub fn watchdog_boot_status(fd: impl std::os::fd::AsFd) -> io::Result<i32> {
    owrt_platform::procd::watchdog::boot_status(fd)
}

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
    use rustix::process::{Resource, Rlimit};
    let Some(&(_, number)) = RLIMIT_NAMES.iter().find(|(n, _)| *n == name) else {
        return Ok(());
    };
    let resource = match number {
        9 => Resource::As,
        4 => Resource::Core,
        0 => Resource::Cpu,
        2 => Resource::Data,
        1 => Resource::Fsize,
        8 => Resource::Memlock,
        7 => Resource::Nofile,
        6 => Resource::Nproc,
        5 => Resource::Rss,
        3 => Resource::Stack,
        13 => Resource::Nice,
        14 => Resource::Rtprio,
        12 => Resource::Msgqueue,
        11 => Resource::Sigpending,
        _ => return Ok(()),
    };
    let limit = if value == "unlimited" {
        Rlimit {
            current: None,
            maximum: None,
        }
    } else {
        let previous = rustix::process::getrlimit(resource);
        let mut fields = value.split_whitespace();
        let Some(current) = fields.next().and_then(|v| v.parse::<u64>().ok()) else {
            return Ok(());
        };
        let maximum = fields
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(previous.maximum.unwrap_or(u64::MAX));
        Rlimit {
            current: (current != u64::MAX).then_some(current),
            maximum: (maximum != u64::MAX).then_some(maximum),
        }
    };
    let _ = rustix::process::setrlimit(resource, limit);
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn full_sigchld_pipe_preserves_the_interrupted_error() {
        let (_reader, writer) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::NONBLOCK | rustix::pipe::PipeFlags::CLOEXEC,
        )
        .unwrap();
        let bytes = [0; 4096];
        while rustix::io::write(&writer, &bytes).is_ok() {}
        assert_eq!(
            rustix::io::write(&writer, &bytes).unwrap_err(),
            rustix::io::Errno::AGAIN
        );
        assert_eq!(
            owrt_platform::procd::signals::sigchld_errno_probe(&writer, 22),
            22
        );
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
        let (_reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::NONBLOCK).unwrap();
        let bytes = [b'x'; 4096];
        while rustix::io::write(&writer, &bytes).is_ok() {}
        assert_eq!(
            rustix::io::write(&writer, b"x").unwrap_err(),
            rustix::io::Errno::AGAIN
        );
        let saved = rustix::io::dup(rustix::stdio::stderr()).unwrap();
        rustix::stdio::dup2_stderr(&writer).unwrap();
        ulog_stdio("- init -");
        stderr_line("Failed to exec upgraded.");
        rustix::stdio::dup2_stderr(&saved).unwrap();
    }
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
        owrt_platform::procd::compatibility::open_procd_log();
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
    let Ok(c) = CString::new(&line[..end]) else {
        return;
    };
    owrt_platform::procd::compatibility::syslog_line(priority, &c);
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
    owrt_platform::procd::compatibility::syslog_instance(&cid, facility, priority, &cline);
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

pub use owrt_platform::procd::compatibility::interface_index as if_nametoindex;

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

/// `reboot(2)` magic (linux/reboot.h). `RB_DISABLE_CAD` makes ctrl-alt-del
/// deliver SIGINT to PID 1 instead of hard-rebooting.
pub const RB_AUTOBOOT: i32 = 0x01234567;
pub const RB_POWER_OFF: i32 = 0x4321fedc;
pub const RB_DISABLE_CAD: i32 = 0;

/// `patch_fd()`: redirect one of stdin/stdout/stderr to a device. A relative
/// name is under /dev; a failed open falls back to /dev/null; NULL means
/// /dev/null outright.
pub fn patch_fd(device: Option<&str>, fd: i32, write: bool) -> bool {
    let path = match device {
        None => "/dev/null".to_string(),
        Some(d) if d.starts_with('/') => d.to_string(),
        Some(d) => format!("/dev/{d}"),
    };
    let Ok(path_c) = CString::new(path.as_str()) else {
        return false;
    };
    let flags = (if write {
        rustix::fs::OFlags::WRONLY
    } else {
        rustix::fs::OFlags::RDONLY
    }) | rustix::fs::OFlags::NOCTTY;
    let file = rustix::fs::open(&path_c, flags, rustix::fs::Mode::empty()).or_else(|error| {
        if path != "/dev/null" {
            rustix::fs::open(c"/dev/null", flags, rustix::fs::Mode::empty())
        } else {
            Err(error)
        }
    });
    file.is_ok_and(|file| replace_standard(file, fd))
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
    let fd = rustix::stdio::stderr();
    if let Ok(flags) = rustix::fs::fcntl_getfl(fd) {
        let _ = rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK);
    }
}

/// One freopen leg: open WITHOUT O_NOCTTY and dup2 onto the std fd.
fn stdio_open(tty: &str, fd: i32, write: bool) -> bool {
    let path = if tty.starts_with('/') {
        tty.to_string()
    } else {
        format!("/dev/{tty}")
    };
    let Ok(path) = CString::new(path) else {
        return false;
    };
    let flags = if write {
        rustix::fs::OFlags::WRONLY
    } else {
        rustix::fs::OFlags::RDONLY
    };
    rustix::fs::open(&path, flags, rustix::fs::Mode::empty())
        .is_ok_and(|file| replace_standard(file, fd))
}
fn replace_standard(file: std::os::fd::OwnedFd, target: i32) -> bool {
    use std::os::fd::{AsRawFd, IntoRawFd};
    let result = match target {
        0 => rustix::stdio::dup2_stdin(&file),
        1 => rustix::stdio::dup2_stdout(&file),
        2 => rustix::stdio::dup2_stderr(&file),
        _ => return false,
    };
    // Existing patch_fd leaves an open which filled 0/1/2 attached to stdio.
    if file.as_raw_fd() <= 2 {
        let _ = file.into_raw_fd();
    }
    result.is_ok()
}

/// `set_console()`: the shutdown path's best-effort console -- cmdline
/// `console=`, then tty0, then console.
pub fn set_console() {
    let tty = cmdline_val("console", 0)
        .map(|v| v.split(',').next().unwrap_or("").to_string())
        .filter(|t| dev_exist(t));
    let tty = tty.or_else(|| {
        ["tty0", "console"]
            .iter()
            .find(|t| dev_exist(t))
            .map(|t| t.to_string())
    });
    if let Some(t) = tty {
        set_stdio(&t);
    }
}

/// `dev_exist()`: can the name be opened under /dev? An empty id cannot,
/// which is why an inittab respawn entry with an empty id never respawns.
pub fn dev_exist(dev: &str) -> bool {
    if dev.is_empty() {
        return false;
    }
    let Ok(path) = CString::new(format!("/dev/{dev}")) else {
        return false;
    };
    rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOCTTY,
        rustix::fs::Mode::empty(),
    )
    .is_ok()
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
    rustix::fs::chown(
        path,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )
    .is_ok()
}

/// `is_container()`: the `container` environment variable, as container.c
/// tests it.
pub fn is_container() -> bool {
    std::env::var_os("container").is_some()
}

/// `sync(2)`.
pub fn sync_fs() {
    rustix::fs::sync();
}

/// Preserve ignored/invalid numeric event-loop descriptor behavior.
pub fn drain_wakeup(fd: std::os::fd::RawFd) {
    let mut bytes = [0; 64];
    while owrt_platform::unix::read_fd(fd, &mut bytes).is_ok_and(|count| count > 0) {}
}

pub fn procd_signal_pid1() {
    owrt_platform::procd::signals::install_pid1_handlers();
    reboot_cmd(RB_DISABLE_CAD);
}
