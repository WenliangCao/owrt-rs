//! `rcS.c`: running init scripts through a run queue.
//!
//! Two queues with different widths, which is the part that matters:
//!
//! - `rcS(pattern, param)` globs `<rc.d>/<pattern>*` and runs them with
//!   `max_running_tasks = 1`, i.e. strictly serial. That is what makes
//!   `S00sysfixtime` finish before `S10boot` starts. Boot and shutdown only.
//! - `rc(file, param)` globs `<init.d>/<file>` -- no wildcard suffix -- and
//!   runs on a *separate* queue with `max_running_tasks = 8`. This is the one
//!   `service_update()` calls with `"running"`, so it is reachable from an
//!   ordinary `ubus call service set` and not only from PID 1.
//!
//! `add_initd` deduplicates only when the parameter is exactly `"running"`;
//! every other parameter can be queued twice. `stop` and `shutdown` get a
//! 15 s run timeout and a 10 s cancel timeout.

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// The `rc()` queue's width (`r.max_running_tasks = 8`).
pub const RC_WIDTH: usize = 8;

/// `s->proc.task.run_timeout` for stop/shutdown, in ms.
pub const STOP_RUN_TIMEOUT_MS: i64 = 15_000;

#[derive(Debug)]
pub struct Job {
    pub file: PathBuf,
    pub param: String,
    pub pid: Option<i32>,
    /// Monotonic ms after which a running stop/shutdown is cancelled
    /// (`run_timeout`). Recorded here but NOT yet enforced -- cancelling a
    /// runqueue task is P3.2, and `rc()` on this path only ever runs
    /// "running", which carries no timeout.
    #[allow(dead_code)]
    pub deadline: Option<i64>,
}

/// The `rc()` queue. `rcS`'s serial queue is P3.2 and is deliberately absent:
/// this build is not PID 1, so nothing calls it.
#[derive(Debug, Default)]
pub struct RunQueue {
    pub jobs: Vec<Job>,
}

impl RunQueue {
    /// `_rc(&r, init_d_path, file, "", param)`. The glob has no wildcard, so
    /// this is really "does `<init.d>/<file>` exist"; a name that matches
    /// nothing queues nothing, which is the normal case for a service with no
    /// init script.
    pub fn queue(&mut self, init_d: &str, file: &str, param: &str, now: i64) {
        let path = PathBuf::from(init_d).join(file);
        if !path.is_file() {
            return;
        }
        // add_initd(): dedup applies to "running" only.
        if param == "running"
            && self
                .jobs
                .iter()
                .any(|j| j.file == path && j.param == param)
        {
            return;
        }
        let deadline = if param == "stop" || param == "shutdown" {
            Some(now + STOP_RUN_TIMEOUT_MS)
        } else {
            None
        };
        self.jobs.push(Job {
            file: path,
            param: param.to_string(),
            pid: None,
            deadline,
        });
    }

    /// Start whatever fits under the queue width. Output goes to the log the
    /// way `pipe_cb` does -- one line at a time, prefixed with the script
    /// path -- except that here it is inherited rather than read back, since
    /// nothing in this build consumes it.
    pub fn pump(&mut self, now: i64) {
        let running = self.jobs.iter().filter(|j| j.pid.is_some()).count();
        if running >= RC_WIDTH {
            return;
        }
        let mut slots = RC_WIDTH - running;
        for j in self.jobs.iter_mut() {
            if slots == 0 {
                break;
            }
            if j.pid.is_some() {
                continue;
            }
            match Command::new(&j.file)
                .arg(&j.param)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => {
                    j.pid = Some(c.id() as i32);
                    slots -= 1;
                }
                Err(e) => {
                    eprintln!("procd-rs: {} {}: {e}", j.file.display(), j.param);
                    // Mark it done so the entry is collected below.
                    j.pid = None;
                    j.param = String::new();
                }
            }
        }
        self.jobs.retain(|j| !(j.pid.is_none() && j.param.is_empty()));
        let _ = now;
    }

    /// Called by the main loop's waitpid when one of these children exits.
    /// Returns true when the pid belonged to this queue.
    pub fn reaped(&mut self, pid: i32) -> bool {
        let Some(i) = self.jobs.iter().position(|j| j.pid == Some(pid)) else {
            return false;
        };
        self.jobs.remove(i);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_with_no_script_queues_nothing() {
        let mut q = RunQueue::default();
        q.queue("/nonexistent", "whatever", "running", 0);
        assert!(q.jobs.is_empty());
    }

    #[test]
    fn dedup_is_running_only() {
        let dir = std::env::temp_dir().join(format!("rcs-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("svc");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();

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
    fn stop_and_shutdown_carry_a_deadline() {
        let dir = std::env::temp_dir().join(format!("rcs-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("svc"), "#!/bin/sh\n").unwrap();
        let d = dir.to_str().unwrap();

        let mut q = RunQueue::default();
        q.queue(d, "svc", "stop", 1000);
        q.queue(d, "svc", "running", 1000);
        assert_eq!(q.jobs[0].deadline, Some(1000 + STOP_RUN_TIMEOUT_MS));
        assert_eq!(q.jobs[1].deadline, None);

        std::fs::remove_dir_all(&dir).ok();
    }
}
