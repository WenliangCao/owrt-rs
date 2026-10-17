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
                let _ = rustix::process::kill_process(rustix::process::Pid::from_raw(pid).unwrap(), rustix::process::Signal::KILL);
                let _ = rx.recv();
                return Ok(Outcome::TimedOut);
            }
        }
    })
}

/// waitpid(WNOHANG) every 50 ms until exit or timeout; used only when the
/// helper thread could not be created.
fn wait_polling(pid: i32, timeout: Duration, started: Instant) -> io::Result<Outcome> {
    let pid = rustix::process::Pid::from_raw(pid).unwrap();
    loop {
        match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
            Ok(Some((_, status))) => return Ok(Outcome::Exited(std::os::unix::process::ExitStatusExt::from_raw(status.as_raw()))),
            Ok(None) => {},
            Err(error) => return Err(error.into()),
        }
        if started.elapsed() >= timeout {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            let _ = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty());
            return Ok(Outcome::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
