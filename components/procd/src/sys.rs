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
    unsafe { initgroups(c.as_ptr() as *const u8, gid) == 0 }
}

/// `getpwnam()` -> (uid, gid). None when the user does not exist.
pub fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` outlives the call. getpwnam returns a pointer into a static
    // buffer, read immediately and not retained.
    let p = unsafe { getpwnam(c.as_ptr() as *const u8) };
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
    let p = unsafe { getgrnam(c.as_ptr() as *const u8) };
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
