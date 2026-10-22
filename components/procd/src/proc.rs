//! Starting and reaping one instance's child.
//!
//! `instance_run()` does its work between fork and exec. Here that is a
//! `pre_exec` closure. The inherited credential, logging and terminal setup
//! requires the caller's single-threaded process lifecycle, with no application
//! lock held across spawning. The unsafe entry points expose that requirement;
//! their tests run on a standalone main thread rather than a libtest worker.
//!
//! Deliberate difference from the C, recorded in the contract: the child is
//! reaped by polling `waitpid(WNOHANG)` from the event loop rather than from
//! a SIGCHLD handler, so an exit is noticed within one loop iteration instead
//! of immediately. netifd-rs already works this way.

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

use crate::instance::Instance;
use crate::sys;
use owrt_ubus::msg::status;

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
        Ok(LogPipe {
            fd,
            partial: Vec::new(),
            priority,
        })
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
            let n = match rustix::io::read(&self.fd, &mut buf) {
                Ok(n) => n,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return error == rustix::io::Errno::AGAIN,
            };
            if n == 0 {
                if !self.partial.is_empty() {
                    let line = std::mem::take(&mut self.partial);
                    emit(self.priority, &line);
                }
                return false;
            }
            taken += n;
            self.partial.extend_from_slice(&buf[..n]);
            while let Some(at) = self.partial.iter().position(|b| *b == b'\n') {
                let line: Vec<_> = self.partial.drain(..=at).collect();
                emit(self.priority, &line[..line.len() - 1]);
            }
            if self.partial.len() > PARTIAL_MAX {
                let line = std::mem::take(&mut self.partial);
                emit(self.priority, &line);
            }
        }
    }
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
    owrt_platform::procd::process::inherit_ignored_sigpipe(cmd);
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
        a.push(if mode.starts_with('1') {
            "-w".into()
        } else {
            "-r".into()
        });
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
/// # Safety
/// Spawn only from a single-threaded process with no held application locks.
/// The inherited cgroup-warning and NSS setup must remain valid after fork.
#[expect(unsafe_code, reason = "callers must establish the inherited post-fork setup contract")]
pub unsafe fn start(
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

    let uid = uid_gid.map(|(uid, _)| uid).unwrap_or(0);
    let gid = gr_gid.or(uid_gid.map(|(_, gid)| gid)).unwrap_or(0);
    let user_groups = if inst.has_jail {
        None
    } else {
        user.zip(uid_gid)
            .and_then(|(user, (_, gid))| (gid != 0).then_some((user, gid)))
    };
    let setup = owrt_platform::procd::process::InstanceSetup {
        cgroup,
        cgroup_warning: format!("failed adding instance cgroup for {service}"),
        nice: inst.nice,
        limits: inst.limits.clone(),
        user_groups,
        gid: (!inst.has_jail && gid != 0).then_some(gid),
        uid: (!inst.has_jail && uid != 0).then_some(uid),
    };
    fn cgroup_warning(context: &str, error: &io::Error) {
        sys::ulog(sys::LOG_WARNING, &format!("{context}: {error}"));
    }
    inherit_ignored_sigpipe(&mut cmd);
    #[expect(unsafe_code, reason = "fixed instance setup in the single-threaded supervisor")]
    // SAFETY: the supervisor is single-threaded; setup owns every captured
    // value and these fixed callbacks retain no parent locks or borrows. The
    // child executes the configured setup once and then execs or exits.
    unsafe {
        owrt_platform::procd::process::configure_instance(
            &mut cmd,
            setup,
            cgroup_warning,
            sys::apply_limit,
        );
    }

    let mut child = cmd.spawn()?;
    let pid = child.id() as i32;
    let pipes = (|| -> io::Result<_> {
        let out = child.stdout.take()
            .map(|pipe| LogPipe::new(pipe.into(), crate::sys::LOG_INFO))
            .transpose()?;
        let err = child.stderr.take()
            .map(|pipe| LogPipe::new(pipe.into(), crate::sys::LOG_ERR))
            .transpose()?;
        Ok((out, err))
    })();
    let (out, err) = match pipes {
        Ok(pipes) => pipes,
        Err(error) => {
            // A successfully spawned child must not keep running after its
            // supervision setup failed. The event loop reaps it without a
            // blocking wait, exactly as it reaps other untracked children.
            let _ = child.kill();
            return Err(error);
        }
    };
    // `child` is dropped here without waiting; the loop reaps by pid the way
    // the rest of this supervisor does.
    drop(child);
    Ok((pid, out, err))
}

/// `waitpid(pid, WNOHANG)` for one specific child. The run queue's tests use
/// this rather than `reap_any`, which would steal other tests' children.
#[allow(dead_code)]
pub fn try_reap(pid: i32) -> Option<i32> {
    let pid = rustix::process::Pid::from_raw(pid)?;
    rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
        .ok()
        .flatten()
        .map(|(_, status)| status.as_raw())
}

/// Reap any exited child, including inittab sessions and adopted orphans.
pub fn reap_any() -> Option<(i32, i32)> {
    loop {
        // waitpid(None) means PID 0 (our process group), not libc's PID -1.
        // Inittab workers call setsid(), so they require the all-child wait.
        match rustix::process::wait(rustix::process::WaitOptions::NOHANG) {
            Ok(Some((pid, status))) => return Some((pid.as_raw_pid(), status.as_raw())),
            Err(rustix::io::Errno::INTR) => continue,
            _ => return None,
        }
    }
}

pub fn signal(pid: i32, sig: i32) -> bool {
    // Zero still means no recorded child; negative pids retain kill's
    // broadcast/process-group semantics used by the PID1 shutdown path.
    pid != 0 && owrt_platform::procd::process::send_signal(pid, sig).is_ok()
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
    let Err(error) = owrt_platform::procd::process::send_signal(pid, sig) else {
        return status::OK;
    };
    const EPERM: i32 = 1;
    const ESRCH: i32 = 3;
    const EINVAL: i32 = 22;
    match error.raw_os_error().unwrap_or(0) {
        EINVAL => status::INVALID_ARGUMENT,
        EPERM => status::PERMISSION_DENIED,
        ESRCH => status::NOT_FOUND,
        _ => status::UNKNOWN_ERROR,
    }
}

/// `fork_worker()`: start one inittab action -- new session, stdio on
/// /dev/<id> (or /dev/null when the open fails), controlling tty, foreground
/// process group, then execvp. The pid is reaped by the main loop.
/// # Safety
/// Spawn only from a single-threaded process with no held application locks;
/// the existing terminal path setup allocates after fork and before exec.
#[expect(unsafe_code, reason = "callers must establish the inherited terminal setup contract")]
pub unsafe fn spawn_tty(argv: &[String], id: &str) -> io::Result<i32> {
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no command"));
    }
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    inherit_ignored_sigpipe(&mut cmd);
    let dev = if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    };
    #[expect(unsafe_code, reason = "fixed tty setup in the single-threaded supervisor")]
    // SAFETY: this is the single-threaded inittab path; the callback captures
    // no parent locks or borrows, and the owned tty name lives through exec.
    unsafe { owrt_platform::procd::process::configure_tty(&mut cmd, dev, sys::patch_fd) };
    let child = cmd.spawn()?;
    let pid = child.id() as i32;
    drop(child);
    Ok(pid)
}

/// `setsid(2)`, ignoring the failure when already a session leader --
/// exactly what the bare call in procd.c's main() amounts to.
pub fn become_session_leader() {
    let _ = rustix::process::setsid();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::Instance;

    fn jailed() -> Instance {
        let mut i = Instance::new("one");
        i.valid = true;
        i.command = vec![
            "/usr/sbin/dnsmasq".into(),
            "-C".into(),
            "/tmp/x.conf".into(),
        ];
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
    fn cgroup_path_keeps_the_upstream_length_limit() {
        let dir = cgroup_dir("svc", "one");
        // With a cgroup2 root the path is the C's; without one, None. Either
        // way the length rule holds.
        if let Some(d) = dir {
            assert_eq!(d.to_str().unwrap(), "/sys/fs/cgroup/services/svc/one");
        }
        assert!(
            cgroup_dir("svc", &"x".repeat(240)).is_none(),
            "over the C's 256-byte buffer"
        );
    }
}
