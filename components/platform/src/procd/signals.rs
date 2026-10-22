//! Fixed procd signal handlers; business shutdown/logging policy stays in procd.
use std::io;
const RB_AUTOBOOT: i32 = 0x01234567;
const RB_HALT_SYSTEM: i32 = 0xcdef0123u32 as i32;
const RB_POWER_OFF: i32 = 0x4321fedc;

/// Preserve PID1's crash path: sync, two-second async-safe delay, reboot,
/// then spin forever if the kernel refuses the request. Never exit PID1.
pub fn crash_reboot() -> ! {
    unsafe extern "C" {
        fn sleep(seconds: u32) -> u32;
    }
    rustix::fs::sync();
    // SAFETY: sleep is async-signal-safe and receives only a scalar interval.
    unsafe {
        sleep(2);
    }
    let _ = rustix::system::reboot(rustix::system::RebootCommand::Restart);
    loop {
        std::hint::spin_loop();
    }
}

/// The shutdown signals PID 1 must answer (signal.c). The handler only
/// stores the reboot event and wakes the loop; the main loop acts on it.
pub static SHUTDOWN_EVENT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn shutdown_signal(sig: i32) {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    const SIGUSR1: i32 = 10;
    const SIGUSR2: i32 = 12;
    const SIGPWR: i32 = 30;
    let event = match sig {
        SIGINT | SIGTERM => RB_AUTOBOOT,
        SIGUSR1 => RB_HALT_SYSTEM,
        SIGUSR2 | SIGPWR => RB_POWER_OFF,
        _ => return,
    };
    SHUTDOWN_EVENT.store(event, std::sync::atomic::Ordering::SeqCst);
    wake_loop();
}

/// One byte down the loop's self-pipe, errno preserved: the loop may be
/// sleeping until a deadline rather than ticking, so a signal that changes
/// what it must do next has to interrupt that sleep.
fn wake_loop() {
    #[cfg(target_os = "linux")]
    // SAFETY: errno is thread-local and must survive an asynchronous handler.
    let (errno, saved_errno) = unsafe {
        extern "C" {
            fn __errno_location() -> *mut i32;
        }
        let errno = __errno_location();
        (errno, *errno)
    };
    let fd = SIGCHLD_WAKEUP.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write(2) of one byte to a non-blocking pipe; a full pipe
        // (EAGAIN) already means a wakeup is pending.
        crate::unix::write_fd(fd, b"s");
    }
    #[cfg(target_os = "linux")]
    // SAFETY: the pointer still names this thread's errno cell.
    unsafe {
        *errno = saved_errno;
    }
}

extern "C" fn crash_signal(_sig: i32) {
    // signal_crash(): the ERROR() line is skipped here -- formatting is not
    // async-signal-safe -- and do_reboot() follows.
    crash_reboot();
}

static SIGCHLD_WAKEUP: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
// Start armed so children inherited/created before entering the main loop
// get an initial sweep. A signal during a sweep arms the following one.
static CHILD_EXIT_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

extern "C" fn sigchld_signal(_sig: i32) {
    #[cfg(target_os = "linux")]
    // SAFETY: errno is thread-local and must survive an asynchronous handler.
    let (errno, saved_errno) = unsafe {
        extern "C" {
            fn __errno_location() -> *mut i32;
        }
        let errno = __errno_location();
        (errno, *errno)
    };
    CHILD_EXIT_PENDING.store(true, std::sync::atomic::Ordering::Relaxed);
    let fd = SIGCHLD_WAKEUP.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write(2) of one byte to a non-blocking pipe; a full pipe
        // (EAGAIN) already means a wakeup is pending.
        crate::unix::write_fd(fd, b"c");
    }
    #[cfg(target_os = "linux")]
    // SAFETY: the pointer still names this thread's errno cell.
    unsafe {
        *errno = saved_errno;
    }
}

pub fn take_child_exit_pending() -> bool {
    CHILD_EXIT_PENDING.swap(false, std::sync::atomic::Ordering::Relaxed)
}

/// uloop's SIGCHLD self-pipe: a child exit wakes the main loop's poll()
/// instead of waiting for its next tick. Returns the read end; the loop
/// drains it after every poll. Installed in both modes, like uloop_init().
pub fn install_sigchld_wakeup() -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    const SIGCHLD: i32 = 17;
    let (r, w) = rustix::pipe::pipe_with(
        rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
    )?;
    SIGCHLD_WAKEUP.store(w.as_raw_fd(), std::sync::atomic::Ordering::SeqCst);
    // The write end lives for the process; the handler owns it from here.
    std::mem::forget(w);
    // SAFETY: this fixed handler only uses atomics and async-signal-safe syscalls.
    let _ = unsafe { crate::unix::set_signal_handler(SIGCHLD, sigchld_signal) };
    Ok(r)
}

/// Empty a wakeup pipe after poll() reported it readable.
/// `procd_signal()` for the PID 1 half: shutdown signals, crash-to-reboot,
/// a dummy HUP, and ctrl-alt-del routed to SIGINT.
pub fn install_pid1_handlers() {
    use crate::unix::set_signal_handler;
    for sig in [2, 15, 10, 12, 30] {
        // SAFETY: this fixed handler only uses atomics and async-signal-safe syscalls.
        let _ = unsafe { set_signal_handler(sig, shutdown_signal) };
    }
    // SIGSEGV and SIGBUS as in the C, plus SIGABRT: a Rust abort (an
    // allocation failure, or a panic whose hook did not get to reboot) must
    // end the same way, not as an init exit and a kernel panic.
    for sig in [11, 7, 6] {
        // SAFETY: this fixed handler only uses atomics and async-signal-safe syscalls.
        let _ = unsafe { set_signal_handler(sig, crash_signal) };
    }
    extern "C" fn dummy(_sig: i32) {}
    // SAFETY: this fixed handler only uses atomics and async-signal-safe syscalls.
    let _ = unsafe { set_signal_handler(1, dummy) };
}

/// Narrow regression hook for the fixed handler's errno preservation.
#[doc(hidden)]
pub fn sigchld_errno_probe(fd: impl std::os::fd::AsFd, value: i32) -> i32 {
    use std::os::fd::AsRawFd;
    let previous = SIGCHLD_WAKEUP.swap(fd.as_fd().as_raw_fd(), std::sync::atomic::Ordering::SeqCst);
    unsafe extern "C" {
        fn __errno_location() -> *mut i32;
    }
    // SAFETY: current-thread errno storage stays live; the fixed handler must
    // leave the injected value alone even when its pipe is full.
    let observed = unsafe {
        let errno = __errno_location();
        let saved = *errno;
        *errno = value;
        sigchld_signal(17);
        let observed = *errno;
        *errno = saved;
        observed
    };
    SIGCHLD_WAKEUP.store(previous, std::sync::atomic::Ordering::SeqCst);
    observed
}
