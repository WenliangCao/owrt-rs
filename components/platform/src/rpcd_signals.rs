//! Fixed rpcd signals and the process-owned nonblocking wake pipe.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::OnceLock;

const SIGHUP: i32 = 1;
const SIGUSR1: i32 = 10;
const SIGCHLD: i32 = 17;
static SIGNAL: AtomicI32 = AtomicI32::new(0);
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);
static PIPE: OnceLock<Result<(OwnedFd, OwnedFd), i32>> = OnceLock::new();

/// A non-child signal consumed by the rpcd event loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Hangup,
    Stop,
}

extern "C" fn handle_signal(signal: i32) {
    if signal != SIGCHLD {
        SIGNAL.store(signal, Ordering::SeqCst);
    }
    wake();
}

/// Install rpcd's fixed handlers and return its wake reader's descriptor.
///
/// The platform owns both nonblocking, close-on-exec ends until process exit
/// or exec, matching the daemon's lifetime. Repeated calls reuse them. Keeping
/// ownership here prevents an in-flight handler from writing to a reused FD.
/// Pipe creation errors propagate; signal registration remains best effort,
/// as in rpcd's existing startup path. No arbitrary callback is accepted.
pub fn install() -> io::Result<RawFd> {
    let pipe = PIPE.get_or_init(|| {
        rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )
        .map_err(|error| error.raw_os_error())
    });
    let (reader, writer) = pipe
        .as_ref()
        .map_err(|code| io::Error::from_raw_os_error(*code))?;
    WAKE_FD.store(writer.as_raw_fd(), Ordering::SeqCst);
    // SAFETY: only this fixed atomic/errno-preserving write handler is
    // registered. PIPE permanently owns its nonblocking writer before the
    // handler can run; no callback, allocation, lock or unwind occurs there.
    unsafe {
        let _ = crate::unix::set_signal_handler(SIGHUP, handle_signal);
        let _ = crate::unix::set_signal_handler(SIGUSR1, handle_signal);
        let _ = crate::unix::set_signal_handler(SIGCHLD, handle_signal);
    }
    Ok(reader.as_raw_fd())
}

/// Wake the event loop after a worker completion or fixed signal callback.
pub fn wake() {
    let fd = WAKE_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        crate::rpcd::wake(fd);
    }
}

/// Drain queued wake bytes without changing the pending action.
pub fn drain() {
    if let Some(Ok((reader, _))) = PIPE.get() {
        crate::rpcd::drain_pipe(reader.as_raw_fd());
    }
}

/// Consume the last HUP/USR1 action; SIGCHLD only wakes child reaping.
pub fn take_action() -> Option<Action> {
    match SIGNAL.swap(0, Ordering::SeqCst) {
        0 => None,
        SIGHUP => Some(Action::Hangup),
        _ => Some(Action::Stop),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    unsafe extern "C" {
        fn raise(signal: i32) -> i32;
    }

    fn deliver(signal: i32) {
        // SAFETY: the isolated test installed our fixed handler for this
        // signal; raise delivers it to the calling thread before returning.
        assert_eq!(unsafe { raise(signal) }, 0);
    }

    #[test]
    fn saturated_pipe_keeps_signals_live_and_preserves_errno() {
        if std::env::var_os("OWRT_RPCD_SIGNAL_CHILD").is_some() {
            let read = install().unwrap();
            assert_eq!(install().unwrap(), read, "registration must reuse its pipe");
            let (reader, writer) = PIPE.get().unwrap().as_ref().unwrap();
            for fd in [reader, writer] {
                assert!(rustix::fs::fcntl_getfl(fd)
                    .unwrap()
                    .contains(rustix::fs::OFlags::NONBLOCK));
                assert!(rustix::io::fcntl_getfd(fd)
                    .unwrap()
                    .contains(rustix::io::FdFlags::CLOEXEC));
            }
            while rustix::io::write(writer, &[0; 4096]).is_ok() {}
            for signal in [SIGCHLD, SIGHUP, SIGUSR1] {
                let (_, errno) = crate::unix::with_errno(22, || deliver(signal));
                assert_eq!(errno, 22);
            }
            assert_eq!(take_action(), Some(Action::Stop));
            assert_eq!(take_action(), None);
            deliver(SIGHUP);
            deliver(SIGCHLD);
            assert_eq!(take_action(), Some(Action::Hangup));
            drain();
            let mut byte = [0];
            assert_eq!(
                rustix::io::read(reader, &mut byte),
                Err(rustix::io::Errno::AGAIN)
            );
            wake();
            assert_eq!(rustix::io::read(reader, &mut byte).unwrap(), 1);
            assert_eq!(byte, [1]);
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "rpcd_signals::tests::saturated_pipe_keeps_signals_live_and_preserves_errno",
            ])
            .env("OWRT_RPCD_SIGNAL_CHILD", "1")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "isolated rpcd signal test failed: {status}"
                );
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("rpcd signal handler blocked on its saturated pipe");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
