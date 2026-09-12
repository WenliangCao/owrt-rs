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
        // Scope::spawn panics when the OS refuses a thread; under panic=abort
        // that would take the daemon down. Fall back to polling the child
        // when no helper thread can be created (R88 rpcd F1).
        let waiter = thread::Builder::new().spawn_scoped(scope, move || {
            let _ = tx.send(child.wait());
        });
        if waiter.is_err() {
            return wait_polling(pid, timeout, started);
        }
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

/// waitpid(WNOHANG) every 50 ms until exit or timeout; used only when the
/// helper thread could not be created.
fn wait_polling(pid: i32, timeout: Duration, started: Instant) -> io::Result<Outcome> {
    unsafe extern "C" {
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    }
    const WNOHANG: i32 = 1;
    loop {
        let mut status = 0i32;
        // SAFETY: plain waitpid(2) on our own child with a valid status pointer.
        let r = unsafe { waitpid(pid, &mut status, WNOHANG) };
        if r == pid {
            return Ok(Outcome::Exited(std::os::unix::process::ExitStatusExt::from_raw(status)));
        }
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        if started.elapsed() >= timeout {
            // SAFETY: plain kill(2); ESRCH (already gone) is harmless here.
            unsafe { crate::iwinfo::sys::kill(pid, SIGKILL) };
            // SAFETY: as above, blocking until the killed child is reaped.
            unsafe { waitpid(pid, &mut status, 0) };
            return Ok(Outcome::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
