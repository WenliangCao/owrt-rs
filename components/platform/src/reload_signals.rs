//! Fixed SIGINT/SIGTERM cancellation for the reload-config process.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

static CANCELLED: AtomicBool = AtomicBool::new(false);

extern "C" fn cancel(_: i32) {
    CANCELLED.store(true, Ordering::Relaxed);
}

/// Install the fixed cancellation handler, preserving libc signal semantics.
///
/// Errors from either registration propagate to the startup caller. An earlier
/// successful registration remains installed if the later registration fails.
pub fn install() -> io::Result<()> {
    for signal in [2, 15] {
        // SAFETY: cancel only stores a lock-free atomic in permanent storage;
        // it cannot allocate, lock, access thread-local state or unwind.
        unsafe { crate::unix::set_signal_handler(signal, cancel)? };
    }
    Ok(())
}

/// Shared cancellation state used by the reload engine's ordinary I/O waits.
pub fn cancellation_flag() -> &'static AtomicBool {
    &CANCELLED
}

/// Callback for synchronous, cancellable ubus I/O; never a signal callback.
pub fn is_cancelled() -> bool {
    CANCELLED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn raise(signal: i32) -> i32;
    }

    fn deliver(signal: i32) {
        // SAFETY: the isolated test installed our fixed handler for this
        // signal; raise delivers it to the calling thread before returning.
        assert_eq!(unsafe { raise(signal) }, 0);
    }

    #[test]
    fn cancellation_handler_preserves_errno_and_latches_both_signals() {
        if std::env::var_os("OWRT_RELOAD_SIGNAL_CHILD").is_some() {
            install().unwrap();
            assert!(!is_cancelled());
            for signal in [2, 15] {
                CANCELLED.store(false, Ordering::Relaxed);
                let (_, errno) = crate::unix::with_errno(22, || deliver(signal));
                assert_eq!(errno, 22);
                assert!(is_cancelled());
                assert!(cancellation_flag().load(Ordering::Relaxed));
            }
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "reload_signals::tests::cancellation_handler_preserves_errno_and_latches_both_signals"])
            .env("OWRT_RELOAD_SIGNAL_CHILD", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "isolated cancellation test failed: {status}"
        );
    }
}
