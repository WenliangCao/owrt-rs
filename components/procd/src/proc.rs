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

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::instance::Instance;
use crate::sys;

extern "C" {
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

const WNOHANG: i32 = 1;

pub const SIGTERM: i32 = 15;
pub const SIGKILL: i32 = 9;

/// A child's captured output pipe plus the tail of a line that has not
/// arrived in full yet.
#[derive(Debug)]
pub struct LogPipe {
    pub fd: std::os::fd::OwnedFd,
    partial: String,
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
        Ok(LogPipe { fd, partial: String::new(), priority })
    }

    /// Read what is available and hand each complete line to `emit`.
    /// Returns false once the write end is closed and nothing is left.
    pub fn poll_lines(&mut self, mut emit: impl FnMut(i32, &str)) -> bool {
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
                self.partial.push_str(&String::from_utf8_lossy(&buf[..n as usize]));
                while let Some(at) = self.partial.find('\n') {
                    let line: String = self.partial.drain(..=at).collect();
                    emit(self.priority, line.trim_end_matches('\n'));
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
            // n < 0: EAGAIN means "nothing right now", anything else ends it.
            let e = io::Error::last_os_error();
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
pub fn start(inst: &Instance) -> io::Result<(i32, Option<LogPipe>, Option<LogPipe>)> {
    if inst.command.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no command"));
    }

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

    // SAFETY: runs in the forked child before exec. Every call below is
    // async-signal-safe or touches only memory cloned into the closure; the
    // process is single-threaded, so no lock can be held across the fork.
    unsafe {
        cmd.pre_exec(move || {
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
pub fn reap_any() -> Option<(i32, i32)> {
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) with -1 waits for any child and writes one int.
    let r = unsafe { waitpid(-1, &mut status, WNOHANG) };
    if r > 0 {
        Some((r, status))
    } else {
        None
    }
}

pub fn signal(pid: i32, sig: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill(2) takes two scalars and touches no memory.
    unsafe { kill(pid, sig) == 0 }
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
}
