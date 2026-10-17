//! Fixed daemon signal handlers and the bounded async-signal-safe wake operation.
//! A raw descriptor is intentional here: shutdown may make it invalid. We never
//! fabricate a BorrowedFd or assume ownership; write(2) defines EBADF for it.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
pub static RELOAD_REQUESTED: AtomicUsize = AtomicUsize::new(0);
pub static DEBUG_MODE: AtomicBool = AtomicBool::new(false);
pub static LOG_REOPEN_REQUESTED: AtomicUsize = AtomicUsize::new(0);
pub static CACHE_DUMP_REQUESTED: AtomicUsize = AtomicUsize::new(0);
pub static ALARM_REQUESTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
pub static SIGNAL_WAKE_WRITE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
// SIGHUP is 1 on the supported Linux and Darwin hosts.
pub const SIGHUP: i32 = 1;
#[cfg(target_os = "linux")]
pub const SIGUSR1: i32 = 10;
#[cfg(target_os = "linux")]
pub const SIGUSR2: i32 = 12;
#[cfg(not(target_os = "linux"))]
pub const SIGUSR1: i32 = 30;
#[cfg(not(target_os = "linux"))]
pub const SIGUSR2: i32 = 31;
pub const SIGALRM: i32 = 14;
#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn write(fd: i32, buffer: *const u8, length: usize) -> isize;
    fn __errno_location() -> *mut i32;
}

#[cfg(target_os = "linux")]
fn wake_signal_waiter() {
    let fd = SIGNAL_WAKE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = [1u8; 1];
        // SAFETY: the handler writes one byte from a live stack buffer to the
        // process-owned nonblocking pipe; write(2) is async-signal-safe. Linux
        // errno is thread-local; preserve the interrupted caller's value.
        unsafe {
            let errno = __errno_location();
            let saved_errno = *errno;
            let _ = write(fd, byte.as_ptr(), 1);
            *errno = saved_errno;
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn wake_signal_waiter() {}

pub extern "C" fn request_stop(_signal: i32) {
    STOP_REQUESTED.store(true, Ordering::Release);
    wake_signal_waiter();
}

pub extern "C" fn request_reload(_signal: i32) {
    // Standard signals coalesce in the kernel. Each delivered handler maps
    // to a distinct C EVENT_RELOAD and must survive an active file read.
    let _ = RELOAD_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
    wake_signal_waiter();
}

pub extern "C" fn request_log_reopen(_signal: i32) {
    let _ = LOG_REOPEN_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
    wake_signal_waiter();
}

pub extern "C" fn request_cache_dump(_signal: i32) {
    let _ = CACHE_DUMP_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
    wake_signal_waiter();
}

pub extern "C" fn request_alarm(_signal: i32) {
    let _ = ALARM_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
    wake_signal_waiter();
}

pub extern "C" fn request_interrupt(_signal: i32) {
    if DEBUG_MODE.load(Ordering::Relaxed) {
        unsafe extern "C" {
            fn _exit(status: i32) -> !;
        }
        // SAFETY: _exit is async-signal-safe and takes only a scalar status.
        // rustix has no stable public runtime exit API (its runtime module is
        // private); do not depend on its version-hashed experimental module.
        // PID cleanup belongs to SIGTERM, not this debug-mode SIGINT path.
        unsafe { _exit(5) }
    }
    wake_signal_waiter();
    // The nodhcpv6/no-DNSSEC C variant has no EVENT_TIME work in normal mode.
}

/// Register only this module's fixed atomic/pipe handlers, matching libc signal.
pub fn install_handlers(debug: bool) {
    unsafe extern "C" {
        fn signal(number: i32, handler: usize) -> usize;
    }
    DEBUG_MODE.store(debug, Ordering::Relaxed);
    // SAFETY: each signal number is valid on the supported Unix targets. Each
    // handler has the C ABI, static lifetime and only uses lock-free atomics,
    // the bounded write above or _exit; no allocation, mutex or Rust unwind.
    unsafe {
        signal(2, request_interrupt as *const () as usize);
        signal(15, request_stop as *const () as usize);
        signal(SIGHUP, request_reload as *const () as usize);
        signal(SIGUSR2, request_log_reopen as *const () as usize);
        signal(SIGUSR1, request_cache_dump as *const () as usize);
        signal(SIGALRM, request_alarm as *const () as usize);
    }
}

/// Set, observe and restore this thread's errno for the signal regression test.
/// The callback is ordinary synchronous Rust code, not a signal callback.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn with_errno<R>(value: i32, action: impl FnOnce() -> R) -> (R, i32) {
    struct Restore {
        pointer: *mut i32,
        previous: i32,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: errno is storage owned by this live thread. The guard
            // never crosses a thread boundary and also restores during unwind.
            unsafe {
                *self.pointer = self.previous;
            }
        }
    }
    // SAFETY: Linux libc supplies this thread's writable errno cell. No Rust
    // reference is retained while the callback may invoke libc again.
    let (pointer, previous) = unsafe {
        let p = __errno_location();
        let previous = *p;
        *p = value;
        (p, previous)
    };
    let _restore = Restore { pointer, previous };
    let result = action();
    // SAFETY: the callback returned synchronously on this same live thread.
    let observed = unsafe { *pointer };
    (result, observed)
}
