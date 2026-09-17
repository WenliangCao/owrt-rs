use std::io;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::unix;

#[derive(Debug)]
pub enum WaitResult {
    Exited(ExitStatus),
    TimedOut,
    Cancelled,
}

/// Wait for `child` to exit, killing it on `timeout` or when `cancelled` is set.
///
/// The child's exit is observed through a pidfd polled with the remaining
/// timeout, so there is no helper thread (the earlier design spawned one per
/// child: a 2 MiB stack mapping, a guard page, two sigaltstack calls and a
/// futex pair for every wait) and no tick.  SIGINT/SIGTERM interrupt the poll,
/// which is how the cancel flag is noticed while the child still runs.
#[cfg(target_os = "linux")]
pub fn wait(
    child: &mut Child,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> io::Result<WaitResult> {
    let pid = child.id() as i32;
    let pidfd = unix::pidfd_open(pid)?;
    let deadline = Instant::now() + timeout;
    loop {
        let outcome = if cancelled.load(Ordering::Relaxed) {
            Some(WaitResult::Cancelled)
        } else if Instant::now() >= deadline {
            Some(WaitResult::TimedOut)
        } else {
            None
        };
        if let Some(outcome) = outcome {
            unix::kill(pid, unix::SIGKILL)?;
            child.wait()?;
            return Ok(outcome);
        }
        match unix::poll_readable(&pidfd, deadline.saturating_duration_since(Instant::now())) {
            Ok(true) => return child.wait().map(WaitResult::Exited),
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Smoke builds on other hosts have no pidfd; they only need to compile and
/// run the unit tests, none of which time a child out.
#[cfg(not(target_os = "linux"))]
pub fn wait(
    child: &mut Child,
    _timeout: Duration,
    _cancelled: &AtomicBool,
) -> io::Result<WaitResult> {
    child.wait().map(WaitResult::Exited)
}
