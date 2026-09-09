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
}

extern "C" {
    fn openlog(ident: *const u8, option: i32, facility: i32);
    fn syslog(priority: i32, format: *const u8, arg: *const u8);
    fn closelog();
}

/// `LOG_INFO` and `LOG_ERR`: an instance's stdout is logged at info, its
/// stderr at error (`instance_stdout` / `instance_stderr`).
pub const LOG_ERR: i32 = 3;
pub const LOG_INFO: i32 = 6;
/// `LOG_DAEMON`, the facility procd restores after each instance line.
pub const LOG_DAEMON: i32 = 3 << 3;

/// `facilitynames` from <syslog.h>, which `syslog_facility_str_to_int()`
/// walks. An unmatched name yields the terminator's value, -1, and the C
/// stores that verbatim -- so an unknown facility is -1, not a default.
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

/// One line of an instance's output, logged the way `instance_stdio` does:
/// reopen the log with the instance's ident and facility, write, then put the
/// log back to `procd`/LOG_DAEMON so procd's own messages are unaffected.
///
/// Using the platform's syslog(3) rather than formatting a datagram by hand
/// is deliberate: libubox's ulog calls the same function, so the framing,
/// timestamp and truncation behaviour cannot drift apart.
/// `ulog(LOG_NOTICE, ...)` as PID 1 goes to /dev/kmsg (ulog_open(ULOG_KMSG))
/// -- that is where the "procd: - early -" boot lines land on a real serial
/// log. Kept alongside stderr so namespace probes still see the lines.
pub fn klog(line: &str) {
    eprintln!("procd: {line}");
    if std::process::id() != 1 {
        return;
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        // <29> = LOG_DAEMON | LOG_NOTICE, ulog's default for these lines.
        let _ = f.write_all(format!("<29>procd: {line}\n").as_bytes());
    }
}

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

/// RFC 1321 MD5. Small enough to carry than to take a dependency for, and
/// only ever used to answer "did this file change".
fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] = core::array::from_fn(|i| {
        ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32
    });

    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);

    for chunk in msg.as_chunks::<64>().0 {
        let m: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ])
        });
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a
                .wrapping_add(f)
                .wrapping_add(k[i])
                .wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn md5_matches_the_rfc_vectors() {
        let hex = |d: [u8; 16]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            hex(md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

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
        eprintln!("procd-rs: failed to set stdio: no /dev/{tty}");
        return;
    }
    // freopen carries NO O_NOCTTY: the session leader acquires the console
    // as its controlling terminal here, which is how ^C on the serial
    // console reaches PID 1. patch_fd (used for CHILDREN) does pass
    // O_NOCTTY, matching utils.c. (R73/6g.)
    let ok = stdio_open(tty, 0, false) & stdio_open(tty, 1, true) & stdio_open(tty, 2, true);
    if !ok {
        eprintln!("procd-rs: failed to set stdio to {tty}");
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
/// stores the reboot event; the main loop acts on it.
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
}

extern "C" fn crash_signal(_sig: i32) {
    // do_reboot(): sync, a two-second window for the last output to reach
    // the console, reboot, then hang forever -- the C never exits here.
    // process::exit would run atexit handlers (not async-signal-safe) and,
    // on a reboot(2) failure, would make PID 1 exit and panic the kernel
    // where the C hangs and lets the hardware watchdog bite. (R73/5.)
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

/// `procd_signal()` for the PID 1 half: shutdown signals, crash-to-reboot,
/// a dummy HUP, and ctrl-alt-del routed to SIGINT.
pub fn procd_signal_pid1() {
    use owrt_ubus::sys::set_signal_handler;
    for sig in [2, 15, 10, 12, 30] {
        set_signal_handler(sig, shutdown_signal);
    }
    for sig in [11, 7] {
        set_signal_handler(sig, crash_signal);
    }
    extern "C" fn dummy(_sig: i32) {}
    set_signal_handler(1, dummy);
    reboot_cmd(RB_DISABLE_CAD);
}
