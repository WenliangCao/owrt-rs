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

/// Start the instance's command. Returns the child pid.
///
/// The order inside the child follows `instance_run()`: nice, env, limits,
/// then stdio, then initgroups/setgid/setuid, then exec. Privilege drop is
/// last because everything before it may need the privileges being dropped.
///
/// A jailed instance skips the privilege drop entirely -- ujail does it, and
/// doing it here as well would leave ujail unable to set up the sandbox.
pub fn start(inst: &Instance) -> io::Result<i32> {
    if inst.command.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no command"));
    }

    // Resolved in the parent: getpwnam is not async-signal-safe, and a failed
    // lookup should be visible here rather than as a child exiting 127.
    let user = inst.user.clone();
    let uid_gid = inst.user.as_deref().and_then(sys::lookup_user);
    let gr_gid = inst.group.as_deref().and_then(sys::lookup_group);

    let mut cmd = Command::new(&inst.command[0]);
    cmd.args(&inst.command[1..]);

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

    // The C sends stdout/stderr to a log pipe when the instance asked for it,
    // and to /dev/null otherwise. Nothing consumes the pipe in this stage, and
    // an unread pipe is how a supervised process deadlocks, so both go to
    // /dev/null until the log path lands. Recorded as a gap, not a decision.
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

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
                if let (Some(u), Some((_, pw_gid))) = (user.as_deref(), uid_gid) {
                    if pw_gid != 0 && !sys::init_groups(u, pw_gid) {
                        return Err(io::Error::other("initgroups failed"));
                    }
                }
                if let Some(g) = gr_gid {
                    if g != 0 {
                        owrt_ubus::sys::drop_privileges(
                            uid_gid.map(|(u, _)| u).unwrap_or(0),
                            g,
                        )?;
                        return Ok(());
                    }
                }
                if let Some((u, _)) = uid_gid {
                    if u != 0 {
                        // No explicit group: setuid alone, as the C does when
                        // gr_gid is unset.
                        owrt_ubus::sys::drop_privileges(u, u)?;
                    }
                }
            }
            Ok(())
        });
    }

    let child = cmd.spawn()?;
    Ok(child.id() as i32)
}

/// `waitpid(pid, &status, WNOHANG)`. `Some(status)` when the child reaped,
/// `None` while it is still running or already gone.
pub fn try_reap(pid: i32) -> Option<i32> {
    let mut status: i32 = 0;
    // SAFETY: waitpid(2) writes one int through the pointer.
    let r = unsafe { waitpid(pid, &mut status, WNOHANG) };
    if r == pid {
        Some(status)
    } else {
        None
    }
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
