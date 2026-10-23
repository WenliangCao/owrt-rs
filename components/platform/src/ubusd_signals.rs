//! Fixed ubusd reload/stop signals and their process-owned wake pipe.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::OnceLock;

static RELOAD: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);
static PIPE: OnceLock<Result<(OwnedFd, OwnedFd), i32>> = OnceLock::new();

extern "C" fn on_hangup(_: i32) {
    RELOAD.store(true, Ordering::SeqCst);
    wake();
}

extern "C" fn on_stop(_: i32) {
    STOP.store(true, Ordering::SeqCst);
    wake();
}

fn wake() {
    let fd = WAKE_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        crate::ubusd::wake(fd);
    }
}

/// Install fixed HUP/TERM/INT handlers and return the wake reader's descriptor.
///
/// Both nonblocking, close-on-exec ends remain platform-owned until process
/// exit or exec, so handlers cannot target a dropped/reused descriptor.
/// Repeated calls reuse the same pipe. Pipe errors propagate; registration is
/// best effort, preserving ubusd startup behavior. No callbacks are accepted.
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
    // SAFETY: these fixed callbacks touch only lock-free static atomics and
    // the errno-preserving write to the permanent nonblocking pipe above.
    // Neither callback allocates, locks, unwinds or invokes application code.
    unsafe {
        let _ = crate::unix::set_signal_handler(1, on_hangup);
        let _ = crate::unix::set_signal_handler(15, on_stop);
        let _ = crate::unix::set_signal_handler(2, on_stop);
    }
    Ok(reader.as_raw_fd())
}

/// Consume the reload request; draining the pipe never consumes this flag.
pub fn take_reload() -> bool {
    RELOAD.swap(false, Ordering::SeqCst)
}

/// Whether TERM/INT has requested event-loop termination.
pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Drain queued bytes before the event loop examines reload and stop flags.
pub fn drain() {
    if let Some(Ok((reader, _))) = PIPE.get() {
        let mut bytes = [0; 64];
        while crate::unix::read_fd(reader.as_raw_fd(), &mut bytes).unwrap_or(0) > 0 {}
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
    fn saturated_pipe_preserves_errno_and_independent_reload_stop_flags() {
        if std::env::var_os("OWRT_UBUSD_SIGNAL_CHILD").is_some() {
            let read = install().unwrap();
            assert_eq!(install().unwrap(), read);
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
            let (_, errno) = crate::unix::with_errno(22, || deliver(1));
            assert_eq!(errno, 22);
            assert!(take_reload());
            assert!(!take_reload());
            assert!(!stop_requested());
            for signal in [2, 15] {
                STOP.store(false, Ordering::SeqCst);
                let (_, errno) = crate::unix::with_errno(22, || deliver(signal));
                assert_eq!(errno, 22);
                assert!(stop_requested());
            }
            deliver(1);
            drain();
            assert!(take_reload());
            assert!(stop_requested());
            wake();
            let mut byte = [1];
            assert_eq!(rustix::io::read(reader, &mut byte).unwrap(), 1);
            assert_eq!(byte, [0]);
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ubusd_signals::tests::saturated_pipe_preserves_errno_and_independent_reload_stop_flags"])
            .env("OWRT_UBUSD_SIGNAL_CHILD", "1")
            .spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "isolated ubusd signal test failed: {status}"
                );
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("ubusd signal handler blocked on its saturated pipe");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
