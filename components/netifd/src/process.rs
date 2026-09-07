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
//!
//! Output is read line by line while the child runs, as `netifd_process_cb`
//! does. Waiting for exit instead is not an option: `udhcpc -f -t 0` never
//! exits, so everything `dhcp.script` printed -- including its errors -- would
//! sit unread in the pipe, and a full pipe would then block the helper.
//!   * Children are reaped by polling `try_wait` from the event loop rather
//!     than from a SIGCHLD handler, so an exit is noticed within one loop
//!     iteration instead of immediately.

use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};

/// One supervised child. Dropping this does NOT kill the child; call `kill`.
pub struct Process {
    child: Child,
    argv0: String,
    /// Output read but not yet ending in a newline.
    partial: String,
}

impl Process {
    /// `netifd_start_process`: exec `argv`, with `env` added on top of the
    /// inherited environment (the C uses `putenv`, which does not clear), and
    /// with a working directory — `fchdir(proc->dir_fd)`. The
    /// protocol scripts source `../netifd-proto.sh`, so running one without
    /// this fails on its seventh line and still exits 0.
    pub fn start_in(
        argv: &[String],
        env: &[(String, String)],
        dir: Option<&str>,
    ) -> io::Result<Self> {
        let Some((cmd, args)) = argv.split_first() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
        };
        let mut c = Command::new(cmd);
        c.args(args)
            .envs(env.iter().map(|(k, v)| (k.clone(), v.clone())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(d) = dir {
            c.current_dir(d);
        }
        let child = c.spawn()?;
        // non-blocking, so reading while the child runs cannot stall the loop
        for fd in [
            child.stdout.as_ref().map(|p| p.as_raw_fd()),
            child.stderr.as_ref().map(|p| p.as_raw_fd()),
        ]
        .into_iter()
        .flatten()
        {
            // SAFETY: fcntl on a pipe fd this Child owns and keeps open.
            unsafe {
                let f = fcntl(fd, F_GETFL, 0);
                if f >= 0 {
                    fcntl(fd, F_SETFL, f | O_NONBLOCK);
                }
            }
        }
        Ok(Self { child, argv0: cmd.clone(), partial: String::new() })
    }

    /// Complete lines the child has printed since the last call. Partial
    /// output is held back until its newline arrives, so a line is never
    /// logged in halves.
    pub fn poll_lines(&mut self) -> Vec<String> {
        let fresh = self.read_available();
        self.partial.push_str(&fresh);
        let mut lines: Vec<String> = Vec::new();
        while let Some(nl) = self.partial.find('\n') {
            let line = self.partial[..nl].to_string();
            self.partial.drain(..nl + 1);
            if !line.trim().is_empty() {
                lines.push(line);
            }
        }
        lines
    }

    /// Read whatever is buffered in either pipe right now.
    fn read_available(&mut self) -> String {
        let mut out = String::new();
        for pipe in [
            self.child.stdout.as_mut().map(|p| p as &mut dyn Read),
            self.child.stderr.as_mut().map(|p| p as &mut dyn Read),
        ]
        .into_iter()
        .flatten()
        {
            let mut buf = [0u8; 4096];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => out.push_str(&String::from_utf8_lossy(&buf[..n])),
                    // WouldBlock is the normal "nothing more for now"; any
                    // other error means this pipe is done.
                    Err(_) => break,
                }
            }
        }
        out
    }

    #[cfg(test)]
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

    /// Everything left in the pipes, including a last line with no newline.
    /// Called once the child has exited, so the pipes are at EOF.
    pub fn drain_output(&mut self) -> String {
        let rest = self.read_available();
        let mut out = std::mem::take(&mut self.partial);
        out.push_str(&rest);
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

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0o4000;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
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

    #[cfg(test)]
    pub fn pid(&self) -> Option<u32> {
        self.proc.as_ref().map(|p| p.pid())
    }

    /// Start a process here, terminating whatever was in the slot first.
    pub fn start(&mut self, argv: &[String], env: &[(String, String)]) -> io::Result<()> {
        self.start_in(argv, env, "")
    }

    /// The same, in `dir`. An empty `dir` inherits ours.
    pub fn start_in(
        &mut self,
        argv: &[String],
        env: &[(String, String)],
        dir: &str,
    ) -> io::Result<()> {
        if let Some(mut old) = self.proc.take() {
            old.terminate();
        }
        let d = if dir.is_empty() { None } else { Some(dir) };
        self.proc = Some(Process::start_in(argv, env, d)?);
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

    /// Lines a running child has printed, for the log.
    pub fn poll_lines(&mut self) -> Vec<String> {
        match &mut self.proc {
            Some(p) => p.poll_lines(),
            None => Vec::new(),
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
    fn output_is_readable_while_the_child_still_runs() {
        let mut s = Slot::default();
        // the shape that matters: a helper that prints and then keeps running,
        // like `udhcpc -f -t 0` after dhcp.script has reported a lease
        s.start(&sh("echo early; echo late >&2; sleep 30"), &[]).unwrap();
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..300 {
            seen.extend(s.poll_lines());
            if seen.len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(s.is_running(), "the child must not have to exit first");
        assert!(seen.iter().any(|l| l == "early"), "{seen:?}");
        assert!(seen.iter().any(|l| l == "late"), "{seen:?}");
        s.terminate();
    }

    #[test]
    fn a_partial_line_is_held_back_until_its_newline() {
        let mut s = Slot::default();
        s.start(&sh("printf half; sleep 0.4; printf 'done\n'; sleep 30"), &[]).unwrap();
        // "half" alone must never be logged as a line of its own
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..200 {
            for l in s.poll_lines() {
                assert_eq!(l, "halfdone", "a line was logged in halves: {l:?}");
                seen.push(l);
            }
            if !seen.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(seen, vec!["halfdone".to_string()]);
        s.terminate();
    }

    #[test]
    fn a_working_directory_is_honoured() {
        let mut s = Slot::default();
        s.start_in(&sh("pwd"), &[], "/tmp").unwrap();
        let mut out = String::new();
        for _ in 0..200 {
            if let Some((_, _, o)) = s.reap() {
                out = o;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // the proto scripts source ../netifd-proto.sh, so this is load-bearing
        assert!(out.trim().ends_with("tmp"), "{out:?}");
    }
}
