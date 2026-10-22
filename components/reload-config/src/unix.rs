//! Cancellable advisory locking and Linux signal registration.

use std::io;
use std::os::fd::AsFd;

pub const SIGINT: i32 = 2;
pub const SIGTERM: i32 = 15;

/// flock(fd, LOCK_EX) that waits for the holder to finish while honouring the
/// cancel flag the same way every other blocking wait in this program does:
/// a non-blocking attempt every 10 ms, so SIGINT/SIGTERM stay fail-closed
/// even while another instance holds the lock (R88 reload-config F1).
/// Returns Ok(false) when cancelled before the lock was taken.
pub fn lock(fd: impl AsFd, cancelled: &std::sync::atomic::AtomicBool) -> io::Result<bool> {
    loop {
        let error =
            match rustix::fs::flock(&fd, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(true),
                Err(error) => io::Error::from(error),
            };
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

pub use owrt_platform::unix::set_signal_handler;

#[cfg(test)]
mod lock_tests {
    use super::lock;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn a_held_lock_returns_false_once_cancelled_instead_of_blocking() {
        let dir = std::env::temp_dir().join(format!("reload-config-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lock");
        let holder = std::fs::File::create(&path).unwrap();
        let waiter = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let live = AtomicBool::new(false);
        assert!(lock(&holder, &live).unwrap());
        let cancelled = AtomicBool::new(true);
        let started = std::time::Instant::now();
        assert!(!lock(&waiter, &cancelled).unwrap());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        drop(holder);
        assert!(lock(&waiter, &live).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
