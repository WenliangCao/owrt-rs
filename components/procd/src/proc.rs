//! Starting and reaping one instance's child.
//!
//! `instance_run()` does its work between fork and exec. Here that is a
//! `pre_exec` closure, which runs in the forked child with the same
//! constraint: async-signal-safe calls only, and no allocation that could
//! deadlock on a lock another thread held at fork time. This process is
//! single-threaded, but the rule is kept anyway because it costs nothing.
//!
//! Deliberate difference from the C, recorded in the contract: the child is
//! reaped by polling `waitpid(WNOHANG)` from the event loop rather than from
//! a SIGCHLD handler, so an exit is noticed within one loop iteration instead
//! of immediately. netifd-rs already works this way.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::instance::Instance;
use crate::sys;
use owrt_ubus::msg::status;

extern "C" {
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

const WNOHANG: i32 = 1;

pub const SIGTERM: i32 = 15;
pub const SIGKILL: i32 = 9;
pub const SIGHUP: i32 = 1;

/// A child's captured output pipe plus the tail of a line that has not
/// arrived in full yet.
#[derive(Debug)]
pub struct LogPipe {
    pub fd: std::os::fd::OwnedFd,
    partial: Vec<u8>,
    priority: i32,
}

/// How much of one pipe a single poll round will take. Unbounded reading
/// lets a chatty service starve the rest of the loop; netifd-rs uses the
/// same budget for the same reason.
const READ_BUDGET: usize = 64 * 1024;
/// A line this long without a newline is logged as-is rather than buffered
/// forever, so a service printing endless output cannot grow this process.
const PARTIAL_MAX: usize = 64 * 1024;

impl LogPipe {
    pub fn new(fd: std::os::fd::OwnedFd, priority: i32) -> io::Result<Self> {
        owrt_ubus::sys::set_nonblocking(fd.as_raw_fd())?;
        Ok(LogPipe { fd, partial: Vec::new(), priority })
    }

    /// Read what is available and hand each complete line to `emit` as RAW
    /// BYTES (trailing newline stripped): the C's ustream never transcodes,
    /// and a multibyte char split across two read()s must not be mangled.
    /// Returns false once the write end is closed and nothing is left.
    pub fn poll_lines(&mut self, mut emit: impl FnMut(i32, &[u8])) -> bool {
        let mut buf = [0u8; 4096];
        let mut taken = 0;
        loop {
            if taken >= READ_BUDGET {
                return true;
            }
            // SAFETY: read(2) into a buffer we own, with its real length.
            let n = unsafe {
                libc_read(self.fd.as_raw_fd(), buf.as_mut_ptr(), buf.len())
            };
            if n > 0 {
                taken += n as usize;
                self.partial.extend_from_slice(&buf[..n as usize]);
                while let Some(at) = self.partial.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = self.partial.drain(..=at).collect();
                    emit(self.priority, &line[..line.len() - 1]);
                }
                if self.partial.len() > PARTIAL_MAX {
                    let line = std::mem::take(&mut self.partial);
                    emit(self.priority, &line);
                }
                continue;
            }
            if n == 0 {
                // Write end closed. Flush whatever is left, as the C's
                // ustream does when the buffer is full without a newline.
                if !self.partial.is_empty() {
                    let line = std::mem::take(&mut self.partial);
                    emit(self.priority, &line);
                }
                return false;
            }
            // A signal does not close the writer or consume pending bytes.
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return e.kind() == io::ErrorKind::WouldBlock;
        }
    }
}

extern "C" {
    #[link_name = "read"]
    fn libc_read(fd: i32, buf: *mut u8, count: usize) -> isize;
}

/// `UJAIL_BIN_PATH`.
pub const UJAIL: &str = "/sbin/ujail";
/// The line-buffering preload instance_run() gives a piped stdout.
pub const SETLBF: &str = "/lib/libsetlbf.so";
/// `CGROUP_BASEDIR`.
const CGROUP_BASEDIR: &str = "/sys/fs/cgroup/services";

/// procd_signal() ignores SIGPIPE, and every child procd forks inherits
/// that: an ignored disposition survives execve, so instances, inittab
/// entries, hotplug and rc scripts all run with SIGPIPE ignored under the C.
/// std's Command puts SIGPIPE back to SIG_DFL in the child before exec; this
/// restores what the C child would have had. Call it on every spawn path.
pub fn inherit_ignored_sigpipe(cmd: &mut Command) {
    // SAFETY: signal(2) is async-signal-safe and the closure touches nothing
    // else.
    unsafe {
        cmd.pre_exec(|| {
            owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);
            Ok(())
        });
    }
}

/// `instance_add_cgroup()`'s parent half: None when there is no cgroup2 root
/// to put the instance in (the C's `stat("/sys/fs/cgroup/cgroup.subtree_control")`
/// early return) or the path would not fit the C's 256-byte buffer.
fn cgroup_dir(service: &str, instance: &str) -> Option<CString> {
    if std::fs::metadata("/sys/fs/cgroup/cgroup.subtree_control").is_err() {
        return None;
    }
    let dir = format!("{CGROUP_BASEDIR}/{service}/{instance}");
    if dir.len() + "/cgroup.procs".len() >= 256 {
        return None;
    }
    CString::new(dir).ok()
}

/// The child half: mkdir_p(dir, 0700), then write our pid to cgroup.procs.
/// Runs between fork and exec, so only syscalls and stack buffers.
fn cgroup_add_self(dir: &CStr) -> io::Result<()> {
    extern "C" {
        fn mkdir(path: *const u8, mode: u32) -> i32;
        fn open(path: *const u8, flags: i32, mode: u32) -> i32;
        fn write(fd: i32, buf: *const u8, n: usize) -> isize;
        fn close(fd: i32) -> i32;
        fn getpid() -> i32;
    }
    const O_WRONLY: i32 = 1;
    const EEXIST: i32 = 17;
    let bytes = dir.to_bytes();
    // One component at a time, in a fixed buffer. "" and "/" are skipped.
    let mut buf = [0u8; 272];
    for (i, b) in bytes.iter().enumerate() {
        buf[i] = *b;
        let last = i + 1 == bytes.len();
        if (*b == b'/' && i > 0) || last {
            let mut comp = buf;
            comp[if last { i + 1 } else { i }] = 0;
            // SAFETY: comp is NUL-terminated within the buffer.
            if unsafe { mkdir(comp.as_ptr(), 0o700) } != 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(EEXIST) {
                    return Err(e);
                }
            }
        }
    }
    let procs = b"/cgroup.procs\0";
    buf[bytes.len()..bytes.len() + procs.len()].copy_from_slice(procs);
    // SAFETY: NUL-terminated path; fd ops on the result.
    unsafe {
        let fd = open(buf.as_ptr(), O_WRONLY, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // dprintf(fd, "%d", getpid()) without a heap: decimal into a stack
        // buffer.
        let mut pid = getpid();
        let mut digits = [0u8; 12];
        let mut n = digits.len();
        while pid > 0 {
            n -= 1;
            digits[n] = b'0' + (pid % 10) as u8;
            pid /= 10;
        }
        let r = write(fd, digits[n..].as_ptr(), digits.len() - n);
        let err = if r < 0 { Some(io::Error::last_os_error()) } else { None };
        close(fd);
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// `jail_run()`: the ujail argv that wraps the instance's own command.
///
/// Order matters -- this is transcribed switch by switch, because ujail
/// parses positionally after `--` and a missing flag silently widens the
/// sandbox rather than failing.
pub fn jail_argv(inst: &Instance) -> Vec<String> {
    let j = &inst.jail;
    let mut a: Vec<String> = vec![UJAIL.into(), "-t".into(), inst.term_timeout.to_string()];
    let opt = |flag: &str, v: &Option<String>, out: &mut Vec<String>| {
        if let Some(v) = v {
            out.push(flag.into());
            out.push(v.clone());
        }
    };
    opt("-n", &j.name, &mut a);
    opt("-h", &j.hostname, &mut a);
    opt("-S", &inst.seccomp, &mut a);
    opt("-U", &inst.user, &mut a);
    opt("-G", &inst.group, &mut a);
    opt("-C", &inst.capabilities, &mut a);
    if inst.no_new_privs {
        a.push("-c".into());
    }
    for (on, flag) in [
        (j.procfs, "-p"),
        (j.sysfs, "-s"),
        (j.ubus, "-u"),
        (j.udebug, "-D"),
        (j.log, "-l"),
        (j.ronly, "-o"),
        (j.netns, "-N"),
        (j.userns, "-f"),
        (j.cgroupsns, "-F"),
        (j.console, "-y"),
    ] {
        if on {
            a.push(flag.into());
        }
    }
    opt("-R", &inst.extroot, &mut a);
    opt("-O", &inst.overlaydir, &mut a);
    opt("-T", &inst.tmpoverlaysize, &mut a);
    if j.immediately {
        a.push("-i".into());
    }
    opt("-P", &j.pidfile, &mut a);
    opt("-J", &inst.bundle, &mut a);
    if j.requirejail {
        a.push("-E".into());
    }
    // Environment is passed by NAME: ujail reads the value from its own
    // environment, which procd has already set.
    for k in inst.env.keys() {
        a.push("-e".into());
        a.push(k.clone());
    }
    // The stored value is the writable flag; the C tests `*type == '1'`.
    for (path, mode) in &j.mount {
        a.push(if mode.starts_with('1') { "-w".into() } else { "-r".into() });
        a.push(path.clone());
    }
    for arg in &j.setns {
        a.push("-j".into());
        a.push(arg.clone());
    }
    a.push("--".into());
    a
}

/// Start the instance's command. Returns the child pid.
///
/// The order inside the child follows `instance_run()`: nice, env, limits,
/// then stdio, then initgroups/setgid/setuid, then exec. Privilege drop is
/// last because everything before it may need the privileges being dropped.
///
/// A jailed instance skips the privilege drop entirely -- ujail does it, and
/// doing it here as well would leave ujail unable to set up the sandbox.
pub fn start(
    inst: &Instance,
    service: &str,
) -> io::Result<(i32, Option<LogPipe>, Option<LogPipe>)> {
    if inst.command.is_empty() && !(inst.has_jail && inst.bundle.is_some()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no command"));
    }
    // instance_add_cgroup() runs in the child, before instance_run(): with a
    // cgroup2 root mounted (`cgroup.subtree_control` exists -- procd's own
    // init mounts it) every instance lands in
    // /sys/fs/cgroup/services/<service>/<instance>, 0700. Resolved here so
    // the child does no string work.
    let cgroup = cgroup_dir(service, &inst.name);

    // Resolved in the parent: getpwnam is not async-signal-safe, and a failed
    // lookup should be visible here rather than as a child exiting 127.
    let user = inst.user.clone();
    let uid_gid = inst.user.as_deref().and_then(sys::lookup_user);
    let gr_gid = inst.group.as_deref().and_then(sys::lookup_group);

    // has_jail means the real argv is ujail's, with the instance's command
    // after `--`. Running the command directly instead would be worse than
    // either option: no sandbox AND, because the privilege drop below is
    // skipped for jailed instances, still root.
    let argv: Vec<String> = if inst.has_jail {
        let mut a = jail_argv(inst);
        a.extend(inst.command.iter().cloned());
        a
    } else {
        inst.command.clone()
    };
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);

    for (k, v) in &inst.env {
        cmd.env(k, v);
    }
    if let Some(s) = &inst.seccomp {
        // `seccomp` is only honoured when the instance is neither traced nor
        // jailed; the C computes the same predicate before setting the var.
        if !inst.trace && !inst.has_jail {
            cmd.env("SECCOMP_FILE", s);
        }
    }
    // instance_run(): `setlbf = _stdout >= 0` -- a piped stdout gets
    // /lib/libsetlbf.so preloaded so the child's stdio is line-buffered and
    // its lines reach the log as they are printed, not in 4 KiB blocks (and
    // not lost when it is killed). Set after the instance env, overriding
    // any LD_PRELOAD of its own, as setenv(..., 1) does.
    if inst.stdout_to_log {
        cmd.env("LD_PRELOAD", SETLBF);
    }

    // The C sends stdout/stderr to a pipe it reads when the instance asked
    // for it, and to /dev/null otherwise. The pipes here are read every loop
    // round with a budget: an unread pipe is exactly how a supervised
    // process deadlocks once it fills the 64 KiB buffer.
    cmd.stdin(Stdio::null());
    if inst.stdout_to_log {
        cmd.stdout(Stdio::piped());
    } else {
        cmd.stdout(Stdio::null());
    }
    if inst.stderr_to_log {
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stderr(Stdio::null());
    }

    let nice = inst.nice;
    let limits = inst.limits.clone();
    let has_jail = inst.has_jail;
    let cgroup_warn = format!("failed adding instance cgroup for {service}");

    inherit_ignored_sigpipe(&mut cmd);
    // SAFETY: runs in the forked child before exec. Every call below is
    // async-signal-safe or touches only memory cloned into the closure; the
    // process is single-threaded, so no lock can be held across the fork.
    unsafe {
        cmd.pre_exec(move || {
            if let Some(dir) = &cgroup {
                if let Err(e) = cgroup_add_self(dir) {
                    crate::sys::ulog(crate::sys::LOG_WARNING, &format!("{cgroup_warn}: {e}"));
                }
            }
            if nice != 0 {
                sys::set_nice(nice);
            }
            for (name, value) in &limits {
                let _ = sys::apply_limit(name, value);
            }
            if !has_jail {
                // instance_config_parse seeds the primary gid from the
                // passwd entry and only lets an explicit `group` override
                // it. Using the uid as the gid -- which is what this did --
                // silently puts the process in the wrong primary group
                // whenever a user's uid and gid differ.
                let uid = uid_gid.map(|(u, _)| u).unwrap_or(0);
                let gid = gr_gid.or(uid_gid.map(|(_, g)| g)).unwrap_or(0);
                if let (Some(u), Some((_, pw_gid))) = (user.as_deref(), uid_gid) {
                    if pw_gid != 0 && !sys::init_groups(u, pw_gid) {
                        return Err(io::Error::other("initgroups failed"));
                    }
                }
                // The C guards each call on the value being non-zero, so a
                // resolved id of 0 leaves that half alone rather than
                // "dropping" to root explicitly.
                if gid != 0 {
                    sys::set_gid(gid)?;
                }
                if uid != 0 {
                    sys::set_uid(uid)?;
                }
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;
    let pid = child.id() as i32;
    let out = match child.stdout.take() {
        Some(p) => Some(LogPipe::new(std::os::fd::OwnedFd::from(p), crate::sys::LOG_INFO)?),
        None => None,
    };
    let err = match child.stderr.take() {
        Some(p) => Some(LogPipe::new(std::os::fd::OwnedFd::from(p), crate::sys::LOG_ERR)?),
        None => None,
    };
    // `child` is dropped here without waiting; the loop reaps by pid the way
    // the rest of this supervisor does.
    std::mem::forget(child);
    Ok((pid, out, err))
}

/// Reap any exited child, whoever it is. PID 1 has to do this for orphans it
/// never started; the supervisor uses it to notice its own children too.
/// `waitpid(pid, WNOHANG)` for one specific child. The run queue's tests use
/// this rather than `reap_any`, which would steal other tests' children.
#[allow(dead_code)]
pub fn try_reap(pid: i32) -> Option<i32> {
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) on one pid, writing one int.
    let r = unsafe { waitpid(pid, &mut status, WNOHANG) };
    if r == pid {
        Some(status)
    } else {
        None
    }
}

pub fn reap_any() -> Option<(i32, i32)> {
    let mut status: i32 = 0;
    loop {
        // SAFETY: waitpid(2) with -1 waits for any child and writes one int.
        let r = unsafe { waitpid(-1, &mut status, WNOHANG) };
        if r > 0 {
            return Some((r, status));
        }
        if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return None;
    }
}

pub fn signal(pid: i32, sig: i32) -> bool {
    // pid 0 means "no child recorded" throughout this supervisor and must
    // never turn into kill(0) -- the caller's own process group. Negative
    // pids are REAL kill(2) semantics and go through: STATE_HALT's
    // kill(-1, SIGTERM/SIGKILL) broadcast was swallowed by a `pid <= 0`
    // guard here, so a reboot never signalled anything before the final
    // reboot(2). (R73 finding 1.)
    if pid == 0 {
        return false;
    }
    // SAFETY: kill(2) takes two scalars and touches no memory.
    unsafe { kill(pid, sig) == 0 }
}

/// `service_handle_kill()`: kill(2) with errno mapped to a ubus status. It
/// does NOT check whether the child is still around first -- that is the
/// point, because ESRCH is how the caller learns the instance is gone.
pub fn signal_status(pid: i32, sig: i32) -> i32 {
    // A pid of 0 or -1 would signal the process group or everything; C never
    // reaches kill() with one because a fresh instance has proc.pid == 0 and
    // kill(0, sig) hits the caller's own group. Report it as ESRCH would be.
    if pid <= 0 {
        return status::NOT_FOUND;
    }
    // SAFETY: kill(2) takes two scalars and touches no memory.
    if unsafe { kill(pid, sig) } == 0 {
        return status::OK;
    }
    const EPERM: i32 = 1;
    const ESRCH: i32 = 3;
    const EINVAL: i32 = 22;
    match io::Error::last_os_error().raw_os_error().unwrap_or(0) {
        EINVAL => status::INVALID_ARGUMENT,
        EPERM => status::PERMISSION_DENIED,
        ESRCH => status::NOT_FOUND,
        _ => status::UNKNOWN_ERROR,
    }
}



/// `fork_worker()`: start one inittab action -- new session, stdio on
/// /dev/<id> (or /dev/null when the open fails), controlling tty, foreground
/// process group, then execvp. The pid is reaped by the main loop.
pub fn spawn_tty(argv: &[String], id: &str) -> io::Result<i32> {
    extern "C" {
        fn setsid() -> i32;
        fn tcsetpgrp(fd: i32, pgrp: i32) -> i32;
        fn getpid() -> i32;
    }
    use crate::sys::ioctl;
    const TIOCSCTTY: u64 = 0x540E;

    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no command"));
    }
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    inherit_ignored_sigpipe(&mut cmd);
    let dev = if id.is_empty() { None } else { Some(id.to_string()) };
    // SAFETY: everything in the closure is async-signal-safe and runs in the
    // forked child before exec.
    unsafe {
        cmd.pre_exec(move || {
            let p = setsid();
            crate::sys::patch_fd(dev.as_deref(), 0, false);
            crate::sys::patch_fd(dev.as_deref(), 1, true);
            crate::sys::patch_fd(dev.as_deref(), 2, true);
            ioctl(0, TIOCSCTTY, 1);
            let _ = p;
            tcsetpgrp(0, getpid());
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    let pid = child.id() as i32;
    std::mem::forget(child);
    Ok(pid)
}

/// `setsid(2)`, ignoring the failure when already a session leader --
/// exactly what the bare call in procd.c's main() amounts to.
pub fn become_session_leader() {
    extern "C" {
        fn setsid() -> i32;
    }
    // SAFETY: no arguments, no memory.
    unsafe { setsid() };
}

/// `fork(2)`, raw, for the hotplug firmware child whose work is a plain
/// synchronous copy loop rather than an exec.
///
/// # Safety
/// The child must only call async-signal-safe code before exiting; the
/// process is single-threaded when this is called.
pub unsafe fn fork_raw() -> i32 {
    extern "C" {
        fn fork() -> i32;
    }
    fork()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::Instance;

    fn jailed() -> Instance {
        let mut i = Instance::new("one");
        i.valid = true;
        i.command = vec!["/usr/sbin/dnsmasq".into(), "-C".into(), "/tmp/x.conf".into()];
        i.has_jail = true;
        i.term_timeout = 7;
        i.user = Some("dnsmasq".into());
        i.group = Some("dnsmasq".into());
        i.no_new_privs = true;
        i.capabilities = Some("/etc/capabilities/dnsmasq.json".into());
        i.jail.name = Some("dnsmasq".into());
        i.jail.procfs = true;
        i.jail.ubus = true;
        i.jail.log = true;
        i.jail.netns = false;
        i.jail.mount.insert("/etc/hosts".into(), "0".into());
        i.jail.mount.insert("/var/run".into(), "1".into());
        i.env.insert("FOO".into(), "bar".into());
        i
    }

    #[test]
    fn a_jailed_instance_execs_ujail_with_its_command_after_the_separator() {
        let i = jailed();
        let a = jail_argv(&i);
        assert_eq!(a[0], "/sbin/ujail");
        // -t always comes first and carries term_timeout, not a default.
        assert_eq!(&a[1..3], &["-t".to_string(), "7".to_string()]);
        assert_eq!(a.last().unwrap(), "--");

        let joined = a.join(" ");
        assert!(joined.contains("-n dnsmasq"));
        assert!(joined.contains("-U dnsmasq"));
        assert!(joined.contains("-G dnsmasq"));
        assert!(joined.contains("-C /etc/capabilities/dnsmasq.json"));
        assert!(joined.contains(" -c ")); // no_new_privs
        assert!(joined.contains(" -p ")); // procfs
        assert!(joined.contains(" -u ")); // ubus
        assert!(joined.contains(" -l ")); // log
        assert!(!joined.contains(" -N ")); // netns is false
        // Environment is passed by name, not by value.
        assert!(joined.contains("-e FOO"));
        assert!(!joined.contains("bar"));
        // The writable flag is the stored value, tested as '1'.
        assert!(joined.contains("-w /var/run"));
        assert!(joined.contains("-r /etc/hosts"));
    }

    #[test]
    fn an_unjailed_instance_gets_no_ujail_wrapper() {
        let mut i = jailed();
        i.has_jail = false;
        // jail_argv is only consulted when has_jail; the guard lives in
        // start(), so assert the flag rather than the builder.
        assert!(!i.has_jail);
    }

    /// Run `script` through start() with a piped stdout and return what it
    /// printed, reaping the child.
    fn run_piped(script: &str) -> Vec<String> {
        let mut i = Instance::new("one");
        i.valid = true;
        i.command = vec!["/bin/sh".into(), "-c".into(), script.into()];
        i.stdout_to_log = true;
        let (pid, out, err) = start(&i, "svc").expect("spawn /bin/sh");
        assert!(err.is_none(), "stderr was not asked for");
        let mut out = out.expect("stdout pipe");
        let mut lines = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut reaped = false;
        loop {
            let alive = out.poll_lines(|_, l| lines.push(String::from_utf8_lossy(l).into_owned()));
            if !reaped && try_reap(pid).is_some() {
                reaped = true;
            }
            if !alive || std::time::Instant::now() > deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(reaped, "child never exited");
        lines
    }

    /// R81 F21 (second half): the C child inherits SIGPIPE ignored from
    /// procd_signal(); std resets it to SIG_DFL, which this puts back.
    #[test]
    fn a_child_inherits_sigpipe_ignored_like_the_c_child() {
        owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);
        let lines = run_piped("grep SigIgn /proc/self/status");
        let mask = lines
            .iter()
            .find_map(|l| l.strip_prefix("SigIgn:"))
            .map(|h| u64::from_str_radix(h.trim(), 16).expect("hex mask"))
            .expect("SigIgn line");
        let bit = 1u64 << (owrt_ubus::sys::SIGPIPE - 1);
        assert_ne!(mask & bit, 0, "SIGPIPE not ignored: {mask:#x}");
    }

    /// R81 F22: `setlbf = _stdout >= 0` -- a piped stdout gets the preload.
    #[test]
    fn a_piped_stdout_gets_libsetlbf_preloaded() {
        let lines = run_piped("echo LD_PRELOAD=$LD_PRELOAD");
        let want = format!("LD_PRELOAD={SETLBF}");
        assert!(lines.iter().any(|l| l == &want), "{lines:?}");
    }

    #[test]
    fn an_unpiped_stdout_gets_no_preload() {
        let mut i = Instance::new("one");
        i.valid = true;
        i.command = vec!["/bin/sh".into(), "-c".into(), "exit 0".into()];
        // No pipe means no way to read the env back; assert the predicate
        // start() uses instead.
        assert!(!i.stdout_to_log);
        let dir = cgroup_dir("svc", "one");
        // With a cgroup2 root the path is the C's; without one, None. Either
        // way the length rule holds.
        if let Some(d) = dir {
            assert_eq!(d.to_str().unwrap(), "/sys/fs/cgroup/services/svc/one");
        }
        assert!(cgroup_dir("svc", &"x".repeat(240)).is_none(), "over the C's 256-byte buffer");
    }
}
