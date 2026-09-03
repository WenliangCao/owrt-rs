//! Wait for a child process with a timeout and without polling.
//!
//! The blocking `wait()` runs on a scoped helper thread so the exit is seen
//! the moment it happens (the C rpcd gets the same from uloop's SIGCHLD
//! handling). The 50 ms tick only bounds how late a timeout is noticed.
//! Replaces the `try_wait` + `sleep` loops that added up to one tick of
//! latency per spawned child (`file exec`, `rc list`).
use std::io;
use std::process::{Child, ExitStatus};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

const SIGKILL: i32 = 9;

pub enum Outcome {
    Exited(ExitStatus),
    TimedOut,
}

pub fn wait(child: &mut Child, timeout: Duration) -> io::Result<Outcome> {
    let pid = child.id() as i32;
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(move || {
            let _ = tx.send(child.wait());
        });
        loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => return result.map(Outcome::Exited),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("child wait thread ended without a status"))
                }
            }
            if started.elapsed() >= timeout {
                // SAFETY: plain kill(2); ESRCH (already gone) is harmless here.
                unsafe { crate::iwinfo::sys::kill(pid, SIGKILL) };
                let _ = rx.recv();
                return Ok(Outcome::TimedOut);
            }
        }
    })
}
