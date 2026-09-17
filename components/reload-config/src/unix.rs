use std::io;
use std::os::fd::RawFd;

const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;
const SIG_ERR: usize = usize::MAX;
pub const SIGINT: i32 = 2;
pub const SIGTERM: i32 = 15;
pub const SIGKILL: i32 = 9;
const ESRCH: i32 = 3;

extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn signal(signal: i32, handler: usize) -> usize;
    #[link_name = "kill"]
    fn libc_kill(pid: i32, signal: i32) -> i32;
}

#[cfg(target_os = "linux")]
mod pidfd {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;

    /// pidfd_open(2) has the same number on every Linux architecture.
    const SYS_PIDFD_OPEN: i64 = 434;
    const POLLIN: i16 = 1;

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    extern "C" {
        fn syscall(number: i64, ...) -> i64;
        fn poll(fds: *mut PollFd, count: u64, timeout_ms: i32) -> i32;
    }

    /// A descriptor that becomes readable when `pid` exits.
    pub fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
        // SAFETY: pidfd_open takes two integers and returns a descriptor or -1.
        let fd = unsafe { syscall(SYS_PIDFD_OPEN, pid as i64, 0i64) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor the kernel just created for this caller alone.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    /// poll(2) for readability; Ok(false) on timeout, Interrupted on a signal.
    pub fn poll_readable(fd: &OwnedFd, timeout: Duration) -> io::Result<bool> {
        let mut pfd = PollFd { fd: fd.as_raw_fd(), events: POLLIN, revents: 0 };
        let timeout_ms = i32::try_from(timeout.as_millis().max(1)).unwrap_or(i32::MAX);
        // SAFETY: one PollFd, live for the duration of the call.
        let ready = unsafe { poll(&mut pfd, 1, timeout_ms) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ready > 0)
    }
}

#[cfg(target_os = "linux")]
pub use pidfd::{pidfd_open, poll_readable};

/// flock(fd, LOCK_EX) that waits for the holder to finish while honouring the
/// cancel flag the same way every other blocking wait in this program does:
/// a non-blocking attempt every 10 ms, so SIGINT/SIGTERM stay fail-closed
/// even while another instance holds the lock (R88 reload-config F1).
/// Returns Ok(false) when cancelled before the lock was taken.
pub fn lock(fd: RawFd, cancelled: &std::sync::atomic::AtomicBool) -> io::Result<bool> {
    loop {
        // SAFETY: fd is owned by a live File and flock does not retain a pointer.
        if unsafe { flock(fd, LOCK_EX | LOCK_NB) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => {}
            _ => return Err(error),
        }
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(false);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub fn set_signal_handler(signal_number: i32, handler: extern "C" fn(i32)) -> io::Result<()> {
    // SAFETY: the handler has C ABI, captures no state and only sets an AtomicBool.
    let previous = unsafe { signal(signal_number, handler as usize) };
    if previous == SIG_ERR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// kill(2); a child that already exited (ESRCH) is not an error.
pub fn kill(pid: i32, signal_number: i32) -> io::Result<()> {
    // SAFETY: plain syscall wrapper with no pointers.
    if unsafe { libc_kill(pid, signal_number) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod lock_tests {
    use super::lock;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn a_held_lock_returns_false_once_cancelled_instead_of_blocking() {
        let dir = std::env::temp_dir().join(format!("reload-config-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lock");
        let holder = std::fs::File::create(&path).unwrap();
        let waiter = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let live = AtomicBool::new(false);
        assert!(lock(holder.as_raw_fd(), &live).unwrap());
        let cancelled = AtomicBool::new(true);
        let started = std::time::Instant::now();
        assert!(!lock(waiter.as_raw_fd(), &cancelled).unwrap());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        drop(holder);
        assert!(lock(waiter.as_raw_fd(), &live).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
