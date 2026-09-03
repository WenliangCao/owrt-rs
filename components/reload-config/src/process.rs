use std::io;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
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
/// The blocking `wait()` runs on a helper thread so the exit is observed the
/// moment it happens; the 10 ms tick below only bounds how quickly a cancel or
/// timeout is noticed. (The earlier `try_wait` + sleep loop cost up to one tick
/// per child, which added ~330 ms to a run that spawns 38 children.)
pub fn wait(
    child: &mut Child,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> io::Result<WaitResult> {
    let pid = child.id() as i32;
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(move || {
            let _ = tx.send(child.wait());
        });
        loop {
            match rx.recv_timeout(Duration::from_millis(10)) {
                Ok(result) => return result.map(WaitResult::Exited),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("child wait thread ended without a status"))
                }
            }
            let outcome = if cancelled.load(Ordering::Relaxed) {
                WaitResult::Cancelled
            } else if started.elapsed() >= timeout {
                WaitResult::TimedOut
            } else {
                continue;
            };
            unix::kill(pid, unix::SIGKILL)?;
            let _ = rx.recv();
            return Ok(outcome);
        }
    })
}
