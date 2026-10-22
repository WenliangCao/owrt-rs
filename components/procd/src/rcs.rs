//! `rcS.c`: running init scripts through a run queue.
//!
//! Two queues with different widths, which is the part that matters:
//!
//! - `rcS(pattern, param)` globs `<rc.d>/<pattern>*` and runs them with
//!   `max_running_tasks = 1`, i.e. strictly serial and in glob order. That is
//!   what makes `S00sysfixtime` finish before `S10boot` starts. Boot and
//!   shutdown only -- nothing on the P3.1 bus path calls it, PID 1 does.
//! - `rc(file, param)` globs `<init.d>/<file>` -- no wildcard suffix -- and
//!   runs on a *separate* queue with `max_running_tasks = 8`. This is the one
//!   `service_update()` calls with `"running"`, so it is reachable from an
//!   ordinary `ubus call service set`.
//!
//! `add_initd` deduplicates only when the parameter is exactly `"running"`;
//! every other parameter can be queued twice. `stop` and `shutdown` get a
//! 15 s run timeout (SIGTERM, `runqueue_process_cancel_cb`) followed by a
//! 10 s cancel timeout (SIGKILL). A script's stdout and stderr go through
//! one pipe and are logged a line at a time as `<file>: <line>` (`pipe_cb`,
//! `ULOG_NOTE`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::proc::{self, LogPipe, SIGKILL, SIGTERM};
use crate::sys::LOG_NOTICE;
use crate::sys;

/// The `rc()` queue's width (`r.max_running_tasks = 8`).
pub const RC_WIDTH: usize = 8;
/// The `rcS()` queue's width (`q.max_running_tasks = 1`).
pub const RCS_WIDTH: usize = 1;

/// `s->proc.task.run_timeout` for stop/shutdown, in ms.
pub const STOP_RUN_TIMEOUT_MS: i64 = 15_000;
/// `s->proc.task.cancel_timeout` for stop/shutdown, in ms.
pub const STOP_CANCEL_TIMEOUT_MS: i64 = 10_000;

/// `ULOG_NOTE`.

#[derive(Debug)]
pub struct Job {
    pub file: PathBuf,
    pub param: String,
    pub pid: Option<i32>,
    /// `run_timeout`: only stop/shutdown carry one.
    pub run_timeout_ms: Option<i64>,
    /// Monotonic ms when the child was started.
    pub started: Option<i64>,
    /// Set when the run timeout has sent SIGTERM; the SIGKILL is due at this
    /// time (`cancel_timeout` later).
    pub kill_at: Option<i64>,
    /// The child's stdout+stderr, read back and logged like `pipe_cb`.
    pub out: Option<LogPipe>,
}

/// One runqueue: `r` (width 8) by default, `q` (width 1) for `rcS`.
#[derive(Debug)]
pub struct RunQueue {
    pub width: usize,
    pub jobs: Vec<Job>,
}

impl Default for RunQueue {
    fn default() -> Self {
        Self::with_width(RC_WIDTH)
    }
}

impl RunQueue {
    pub fn with_width(width: usize) -> Self {
        RunQueue { width: width.max(1), jobs: Vec::new() }
    }

    /// `rcS()`'s queue: `runqueue_init(&q); q.max_running_tasks = 1;`
    #[allow(dead_code)]
    pub fn serial() -> Self {
        Self::with_width(RCS_WIDTH)
    }

    /// `add_initd()`: dedup applies to "running" only; stop/shutdown carry
    /// the two timeouts.
    fn add_initd(&mut self, file: PathBuf, param: &str) {
        if param == "running"
            && self
                .jobs
                .iter()
                .any(|j| j.file == file && j.param == param)
        {
            return;
        }
        let run_timeout_ms = if param == "stop" || param == "shutdown" {
            Some(STOP_RUN_TIMEOUT_MS)
        } else {
            None
        };
        self.jobs.push(Job {
            file,
            param: param.to_string(),
            pid: None,
            run_timeout_ms,
            started: None,
            kill_at: None,
            out: None,
        });
    }

    /// `_rc(&r, init_d_path, file, "", param)`. The glob has no wildcard, so
    /// this is really "does `<init.d>/<file>` exist"; a name that matches
    /// nothing queues nothing, which is the normal case for a service with no
    /// init script.
    pub fn queue(&mut self, init_d: &str, file: &str, param: &str, _now: i64) {
        let path = PathBuf::from(init_d).join(file);
        if !path.is_file() {
            return;
        }
        self.add_initd(path, param);
    }

    /// `_rc(&q, rc_d_path, pattern, "*", param)`: every entry of `<rc_d>`
    /// whose name starts with `pattern`, in glob order (bytewise sort, which
    /// is what glob(3) does in the C locale), each queued with `param`.
    /// `rcS("S", "boot")` and `rcS("K", "shutdown")` are the two callers.
    #[allow(dead_code)]
    pub fn queue_all(&mut self, rc_d: &str, pattern: &str, param: &str) {
        let Ok(dir) = std::fs::read_dir(Path::new(rc_d)) else {
            // glob() failing is DEBUG-level in the C, not an error.
            return;
        };
        let mut names: Vec<String> = dir
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(pattern))
            .collect();
        names.sort();
        for n in names {
            self.add_initd(Path::new(rc_d).join(n), param);
        }
    }

    /// True once nothing is queued or running -- `q->empty_cb` territory.
    #[allow(dead_code)]
    pub fn is_idle(&self) -> bool {
        self.jobs.is_empty()
    }

    /// One turn of the queue: drain output, apply timeouts, start what fits.
    pub fn pump(&mut self, now: i64) {
        self.pump_output();
        self.enforce_timeouts(now);
        self.start_jobs(now);
    }

    /// `pipe_cb`: `ULOG_NOTE("%s: %s", initd->file, line)`.
    fn pump_output(&mut self) {
        for j in self.jobs.iter_mut() {
            let Some(p) = j.out.as_mut() else { continue };
            let file = j.file.display().to_string();
            let alive = p.poll_lines(|prio, line| {
                let mut msg = format!("{file}: ").into_bytes();
                msg.extend_from_slice(line);
                sys::log_instance_line("procd", sys::LOG_DAEMON, prio, &msg);
            });
            if !alive {
                j.out = None;
            }
        }
    }

    /// `runqueue_task_timeout`: at `run_timeout` the task is cancelled, which
    /// for a process task is SIGTERM; `cancel_timeout` later it is killed.
    fn enforce_timeouts(&mut self, now: i64) {
        for j in self.jobs.iter_mut() {
            let (Some(pid), Some(started), Some(rt)) = (j.pid, j.started, j.run_timeout_ms) else {
                continue;
            };
            match j.kill_at {
                None if now >= started + rt => {
                    log!(sys::LOG_ERR, "{} {} ran past {rt} ms, cancelling", j.file.display(), j.param);
                    proc::signal(pid, SIGTERM);
                    j.kill_at = Some(now + STOP_CANCEL_TIMEOUT_MS);
                }
                Some(at) if now >= at => {
                    log!(sys::LOG_ERR, "{} {} ignored SIGTERM, killing", j.file.display(), j.param);
                    proc::signal(pid, SIGKILL);
                    j.kill_at = Some(i64::MAX);
                }
                _ => {}
            }
        }
    }

    /// `q_initd_run` for as many queued tasks as the width allows, in queue
    /// order.
    fn start_jobs(&mut self, now: i64) {
        let running = self.jobs.iter().filter(|j| j.pid.is_some()).count();
        if running >= self.width {
            return;
        }
        let mut slots = self.width - running;
        for j in self.jobs.iter_mut() {
            if slots == 0 {
                break;
            }
            if j.pid.is_some() {
                continue;
            }
            let spawned = owrt_ubus::sys::pipe().and_then(|(r, w)| {
                let w2 = w.try_clone()?;
                let mut cmd = Command::new(&j.file);
                cmd.arg(&j.param)
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(w))
                    .stderr(Stdio::from(w2));
                proc::inherit_ignored_sigpipe(&mut cmd);
                // Prepare the reader before spawning so a setup error cannot
                // leave a running script without a queue entry.
                let out = LogPipe::new(r, LOG_NOTICE)?;
                let child = cmd.spawn()?;
                Ok((child.id() as i32, out))
            });
            match spawned {
                Ok((pid, out)) => {
                    j.pid = Some(pid);
                    j.started = Some(now);
                    j.out = Some(out);
                    slots -= 1;
                }
                Err(e) => {
                    log!(sys::LOG_ERR, "{} {}: {e}", j.file.display(), j.param);
                    // Mark it done so the entry is collected below.
                    j.param = String::new();
                }
            }
        }
        self.jobs.retain(|j| !(j.pid.is_none() && j.param.is_empty()));
    }

    /// Called by the main loop's waitpid when one of these children exits.
    /// Returns true when the pid belonged to this queue.
    pub fn reaped(&mut self, pid: i32) -> bool {
        let Some(i) = self.jobs.iter().position(|j| j.pid == Some(pid)) else {
            return false;
        };
        // Whatever the script wrote last, without a trailing newline, is
        // still in the pipe; flush it the way ustream does on close.
        {
            let j = &mut self.jobs[i];
            if let Some(p) = j.out.as_mut() {
                let file = j.file.display().to_string();
                p.poll_lines(|prio, line| {
                    let mut msg = format!("{file}: ").into_bytes();
                    msg.extend_from_slice(line);
                    sys::log_instance_line("procd", sys::LOG_DAEMON, prio, &msg);
                });
            }
        }
        self.jobs.remove(i);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rcs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn script(dir: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Pump with a fake clock until the queue is idle, reaping only this
    /// queue's own children.
    fn drive(q: &mut RunQueue, mut now: i64, step_ms: i64, max_ms: i64) -> i64 {
        let end = now + max_ms;
        while !q.is_idle() && now < end {
            q.pump(now);
            let pids: Vec<i32> = q.jobs.iter().filter_map(|j| j.pid).collect();
            for pid in pids {
                if proc::try_reap(pid).is_some() {
                    q.reaped(pid);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            now += step_ms;
        }
        now
    }

    #[test]
    fn a_name_with_no_script_queues_nothing() {
        let mut q = RunQueue::default();
        q.queue("/nonexistent", "whatever", "running", 0);
        assert!(q.jobs.is_empty());
    }

    #[test]
    fn dedup_is_running_only() {
        let dir = tmpdir("dedup");
        script(&dir, "svc", "");
        let d = dir.to_str().unwrap();
        let mut q = RunQueue::default();
        q.queue(d, "svc", "running", 0);
        q.queue(d, "svc", "running", 0);
        assert_eq!(q.jobs.len(), 1, "running is deduplicated");

        q.queue(d, "svc", "reload", 0);
        q.queue(d, "svc", "reload", 0);
        assert_eq!(q.jobs.len(), 3, "anything else is not");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stop_and_shutdown_carry_a_run_timeout() {
        let dir = tmpdir("timeouts");
        script(&dir, "svc", "");
        let d = dir.to_str().unwrap();

        let mut q = RunQueue::default();
        q.queue(d, "svc", "stop", 1000);
        q.queue(d, "svc", "shutdown", 1000);
        q.queue(d, "svc", "running", 1000);
        assert_eq!(q.jobs[0].run_timeout_ms, Some(STOP_RUN_TIMEOUT_MS));
        assert_eq!(q.jobs[1].run_timeout_ms, Some(STOP_RUN_TIMEOUT_MS));
        assert_eq!(q.jobs[2].run_timeout_ms, None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rcs_runs_matching_scripts_serially_in_glob_order_with_the_param() {
        let dir = tmpdir("serial");
        let log = dir.join("log");
        for name in ["S20b", "S10a", "S30c", "K99z"] {
            script(
                &dir,
                name,
                &format!(
                    "echo start {name} $1 >> {log}; sleep 0.2; echo end {name} >> {log}",
                    log = log.display()
                ),
            );
        }
        let mut q = RunQueue::serial();
        q.queue_all(dir.to_str().unwrap(), "S", "boot");
        assert_eq!(q.jobs.len(), 3, "K99z does not match the S pattern");
        assert_eq!(q.width, 1);

        drive(&mut q, 0, 50, 20_000);
        assert!(q.is_idle(), "queue did not drain: {:?}", q.jobs);

        let got = std::fs::read_to_string(&log).unwrap();
        let want = "start S10a boot\nend S10a\nstart S20b boot\nend S20b\nstart S30c boot\nend S30c\n";
        assert_eq!(got, want, "one at a time, sorted, each with the param");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_rc_queue_runs_up_to_eight_at_once() {
        let dir = tmpdir("parallel");
        let log = dir.join("log");
        script(&dir, "svc", &format!("echo start >> {log}; sleep 0.3; echo end >> {log}", log = log.display()));
        let d = dir.to_str().unwrap();
        let mut q = RunQueue::default();
        for _ in 0..3 {
            q.queue(d, "svc", "reload", 0);
        }
        assert_eq!(q.jobs.len(), 3);
        drive(&mut q, 0, 50, 20_000);
        let got = std::fs::read_to_string(&log).unwrap();
        // All three started before any finished.
        assert!(got.starts_with("start\nstart\nstart\n"), "{got:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_stop_that_ignores_sigterm_is_killed_after_the_cancel_timeout() {
        let dir = tmpdir("kill");
        script(&dir, "svc", "trap '' TERM; kill -STOP $$; exec sleep 60");
        let d = dir.to_str().unwrap();
        let mut q = RunQueue::default();
        q.queue(d, "svc", "stop", 0);

        // Fake clock: start at 0, jump past the run timeout, then past the
        // cancel timeout. Real time barely moves.
        q.pump(0);
        let pid = q.jobs[0].pid.expect("started");
        // The shell stops itself only after installing the trap. Observe that
        // state without consuming its eventual exit status or guessing when
        // it has run; even a heavily loaded test host now has a fixed order.
        use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};
        let child = Pid::from_raw(pid).expect("spawned child pid");
        waitid(WaitId::Pid(child), WaitIdOptions::STOPPED | WaitIdOptions::NOWAIT)
            .unwrap()
            .expect("child stopped after installing its TERM trap");
        assert!(proc::signal(pid, 18)); // SIGCONT: the trap is now installed.
        q.pump(STOP_RUN_TIMEOUT_MS);
        assert_eq!(q.jobs[0].kill_at, Some(STOP_RUN_TIMEOUT_MS + STOP_CANCEL_TIMEOUT_MS));
        assert!(proc::try_reap(pid).is_none(), "SIGTERM is ignored by the script");

        q.pump(STOP_RUN_TIMEOUT_MS + STOP_CANCEL_TIMEOUT_MS);
        let mut status = None;
        for _ in 0..50 {
            status = proc::try_reap(pid);
            if status.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let status = status.expect("SIGKILL ends it");
        assert_eq!(status & 0x7f, SIGKILL);
        assert!(q.reaped(pid));
        assert!(q.is_idle());
        std::fs::remove_dir_all(&dir).ok();
    }
}
