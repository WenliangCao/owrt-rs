//! Supervised child processes.
//!
//! netifd starts both the protocol scripts and the protocol helpers itself and
//! keeps their pids, so it knows when a helper dies. `dhcp.sh` never starts
//! `udhcpc` — it hands argv and env to netifd through `notify_proto` action 1
//! (see docs/contracts/netifd-proto-shell.md). Anything that backgrounded the
//! helper from the shell instead would leave netifd blind to its exit.
//!
//! Two deliberate differences from `netifd_start_process`, both recorded in the
//! contract:
//!
//!   * The C points stdin, stdout and stderr at one pipe it reads. Here stdout
//!     and stderr are separate pipes and stdin is /dev/null. Script output
//!     still reaches the log; a script that read stdin would see EOF rather
//!     than a pipe, and none of the handlers on this device do.
//!   * Children are reaped by polling `try_wait` from the event loop rather
//!     than from a SIGCHLD handler, so an exit is noticed within one loop
//!     iteration instead of immediately.

use std::io::{self, Read};
use std::process::{Child, Command, Stdio};

/// One supervised child. Dropping this does NOT kill the child; call `kill`.
pub struct Process {
    child: Child,
    argv0: String,
}

impl Process {
    /// `netifd_start_process`: exec `argv`, with `env` added on top of the
    /// inherited environment (the C uses `putenv`, which does not clear).
    pub fn start(argv: &[String], env: &[(String, String)]) -> io::Result<Self> {
        let Some((cmd, args)) = argv.split_first() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
        };
        let child = Command::new(cmd)
            .args(args)
            .envs(env.iter().map(|(k, v)| (k.clone(), v.clone())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(Self { child, argv0: cmd.clone() })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn argv0(&self) -> &str {
        &self.argv0
    }

    /// `Some(status)` once it has exited, `None` while it runs.
    pub fn try_wait(&mut self) -> io::Result<Option<i32>> {
        Ok(self.child.try_wait()?.map(|s| s.code().unwrap_or(-1)))
    }

    /// Whatever the child has written so far, for the log. Reading here is
    /// non-destructive to the process; it just drains the pipes.
    pub fn drain_output(&mut self) -> String {
        let mut out = String::new();
        for pipe in [
            self.child.stdout.as_mut().map(|p| p as &mut dyn Read),
            self.child.stderr.as_mut().map(|p| p as &mut dyn Read),
        ]
        .into_iter()
        .flatten()
        {
            let mut buf = Vec::new();
            // a closed pipe or a partial read are both fine: this is logging
            let _ = pipe.read_to_end(&mut buf);
            out.push_str(&String::from_utf8_lossy(&buf));
        }
        out
    }

    /// Send a signal. `signal > 31` becomes SIGTERM, as
    /// `proto_shell_kill_command` does.
    pub fn signal(&self, sig: u32) -> io::Result<()> {
        let sig = if sig > 31 { SIGTERM } else { sig as i32 };
        // SAFETY: kill(2) with our own child's pid and a signal number
        // clamped to the range the kernel defines. The pid is live because
        // `Child` has not been reaped.
        if unsafe { kill(self.child.id() as i32, sig) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `netifd_kill_process`: SIGTERM, then reap. Called before starting a new
    /// process in the same slot, so a second setup never leaves the first
    /// script running.
    pub fn terminate(&mut self) {
        let _ = self.signal(SIGTERM as u32);
        let _ = self.child.wait();
    }
}

pub const SIGTERM: i32 = 15;
pub const SIGKILL: i32 = 9;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

/// A process slot: at most one child, replaced rather than accumulated.
#[derive(Default)]
pub struct Slot {
    proc: Option<Process>,
}

impl Slot {
    pub fn is_running(&self) -> bool {
        self.proc.is_some()
    }

    pub fn pid(&self) -> Option<u32> {
        self.proc.as_ref().map(|p| p.pid())
    }

    /// Start a process here, terminating whatever was in the slot first.
    pub fn start(&mut self, argv: &[String], env: &[(String, String)]) -> io::Result<()> {
        if let Some(mut old) = self.proc.take() {
            old.terminate();
        }
        self.proc = Some(Process::start(argv, env)?);
        Ok(())
    }

    pub fn signal(&self, sig: u32) -> io::Result<()> {
        match &self.proc {
            Some(p) => p.signal(sig),
            None => Ok(()),
        }
    }

    pub fn terminate(&mut self) {
        if let Some(mut p) = self.proc.take() {
            p.terminate();
        }
    }

    /// Poll for exit. Returns `(argv0, status, output)` once, then nothing.
    pub fn reap(&mut self) -> Option<(String, i32, String)> {
        let p = self.proc.as_mut()?;
        match p.try_wait() {
            Ok(Some(status)) => {
                let out = p.drain_output();
                let name = p.argv0().to_string();
                self.proc = None;
                Some((name, status, out))
            }
            Ok(None) => None,
            Err(e) => {
                let name = p.argv0().to_string();
                self.proc = None;
                Some((name, -1, format!("wait failed: {e}")))
            }
        }
    }
}

/// Run a command to completion and return its stdout. Used for the one-shot
/// `dump` that registers a protocol handler.
pub fn run_capture(argv: &[String]) -> io::Result<(i32, String)> {
    let Some((cmd, args)) = argv.split_first() else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
    };
    let out = Command::new(cmd).args(args).stdin(Stdio::null()).output()?;
    Ok((out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    #[test]
    fn a_process_reports_its_exit_status_once() {
        let mut s = Slot::default();
        s.start(&sh("exit 3"), &[]).unwrap();
        assert!(s.is_running());
        let mut got = None;
        for _ in 0..200 {
            if let Some(r) = s.reap() {
                got = Some(r);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let (_, status, _) = got.expect("the process never exited");
        assert_eq!(status, 3);
        // reaped once, and the slot is empty afterwards
        assert!(!s.is_running());
        assert!(s.reap().is_none());
    }

    #[test]
    fn output_reaches_the_caller() {
        let mut s = Slot::default();
        s.start(&sh("echo out; echo err >&2"), &[]).unwrap();
        let mut out = String::new();
        for _ in 0..200 {
            if let Some((_, _, o)) = s.reap() {
                out = o;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(out.contains("out"), "{out:?}");
        assert!(out.contains("err"), "{out:?}");
    }

    #[test]
    fn the_environment_is_added_not_replaced() {
        let mut s = Slot::default();
        // PATH is inherited, MYVAR is added
        s.start(&sh("test -n \"$PATH\" && echo \"$MYVAR\""), &[("MYVAR".into(), "set".into())])
            .unwrap();
        let mut out = String::new();
        for _ in 0..200 {
            if let Some((_, _, o)) = s.reap() {
                out = o;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(out.contains("set"), "{out:?}");
    }

    #[test]
    fn starting_in_an_occupied_slot_replaces_the_occupant() {
        let mut s = Slot::default();
        s.start(&sh("sleep 30"), &[]).unwrap();
        let first = s.pid().unwrap();
        s.start(&sh("sleep 30"), &[]).unwrap();
        let second = s.pid().unwrap();
        assert_ne!(first, second);
        s.terminate();
        assert!(!s.is_running());
    }

    #[test]
    fn a_signal_above_31_becomes_sigterm() {
        let mut s = Slot::default();
        s.start(&sh("sleep 30"), &[]).unwrap();
        // ~0u32 is what proto_shell_kill_command starts with when no signal
        // is given; it must not be passed to kill(2) as-is
        s.signal(u32::MAX).unwrap();
        let mut status = None;
        for _ in 0..300 {
            if let Some((_, st, _)) = s.reap() {
                status = Some(st);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // killed by a signal: no exit code, so our -1 stand-in
        assert_eq!(status, Some(-1));
    }

    #[test]
    fn an_empty_argv_is_refused_rather_than_spawned() {
        let mut s = Slot::default();
        assert!(s.start(&[], &[]).is_err());
        assert!(!s.is_running());
    }

    #[test]
    fn run_capture_returns_stdout_and_status() {
        let (status, out) = run_capture(&sh("echo hello; exit 0")).unwrap();
        assert_eq!(status, 0);
        assert_eq!(out.trim(), "hello");
    }
}
