use std::io;
use std::os::fd::RawFd;

const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;
const SIG_ERR: usize = usize::MAX;
pub const SIGINT: i32 = 2;
pub const SIGTERM: i32 = 15;

extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn signal(signal: i32, handler: usize) -> usize;
}

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
