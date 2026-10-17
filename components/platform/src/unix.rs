//! Numeric descriptor snapshots and fixed libc process/signal contracts.
//! Raw descriptor APIs deliberately accept EBADF/POLLNVAL and never claim
//! ownership or construct BorrowedFd for a possibly stale event-loop slot.
use std::ffi::{c_char, CStr};
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PollFd { pub fd: i32, pub events: i16, pub revents: i16 }

#[cfg(target_os = "macos")]
type Nfds = u32;
#[cfg(not(target_os = "macos"))]
type Nfds = usize;

unsafe extern "C" {
    #[link_name = "poll"]
    fn system_poll(fds: *mut PollFd, count: Nfds, timeout: i32) -> i32;
    fn fcntl(fd: i32, operation: i32, ...) -> i32;
    fn signal(number: i32, handler: usize) -> usize;
    fn setgid(gid: u32) -> i32;
    fn setuid(uid: u32) -> i32;
    fn strerror(error: i32) -> *const c_char;
    fn read(fd: i32, data: *mut u8, length: usize) -> isize;
    fn write(fd: i32, data: *const u8, length: usize) -> isize;
}

pub fn poll_once(fds: &mut [PollFd], timeout: i32) -> io::Result<usize> {
    let count = Nfds::try_from(fds.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: initialized pollfd storage covers count entries exclusively for
    // this call. The kernel defines ignored/invalid FD slots; no FD is owned.
    let result = unsafe { system_poll(fds.as_mut_ptr(), count, timeout) };
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result as usize) }
}

pub fn poll_fds(fds: &mut [PollFd], timeout: i32) -> io::Result<usize> {
    loop {
        match poll_once(fds, timeout) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            result => return result,
        }
    }
}

pub fn set_nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: these fixed fcntl operations only read/set scalar flags. An
    // invalid numeric slot yields EBADF and does not create an FD owner.
    let flags = unsafe { fcntl(fd, 3) };
    if flags < 0 { return Err(io::Error::last_os_error()); }
    // SAFETY: flags came from F_GETFL; the only added bit is O_NONBLOCK.
    if unsafe { fcntl(fd, 4, flags | rustix::fs::OFlags::NONBLOCK.bits() as i32) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opaque disposition returned by libc; callers cannot invent function pointers.
#[derive(Clone, Copy)]
pub struct SignalDisposition(usize);

fn disposition(number: i32, handler: usize) -> io::Result<SignalDisposition> {
    // SAFETY: private callers supply only SIG_IGN, a typed fixed handler, or a
    // prior successful libc disposition. libc validates the scalar signal.
    let old = unsafe { signal(number, handler) };
    if old == usize::MAX { Err(io::Error::last_os_error()) } else { Ok(SignalDisposition(old)) }
}
pub fn ignore_signal(number: i32) -> io::Result<SignalDisposition> { disposition(number, 1) }
pub fn restore_signal(number: i32, previous: SignalDisposition) -> io::Result<()> {
    disposition(number, previous.0).map(|_| ())
}
pub fn observe_signal(number: i32) -> io::Result<SignalDisposition> {
    let previous = ignore_signal(number)?;
    restore_signal(number, previous)?;
    Ok(previous)
}
/// Callers are the existing reviewed atomic/self-pipe handlers. They must keep
/// their bodies async-signal-safe; this boundary does not run arbitrary closures.
pub fn set_signal_handler(number: i32, handler: extern "C" fn(i32)) -> io::Result<()> {
    disposition(number, handler as usize).map(|_| ())
}
/// Keep the original shell/CLI SIGPIPE inheritance across Command's runtime.
pub fn inherit_signal(command: &mut Command, number: i32, previous: SignalDisposition) {
    // SAFETY: the fixed hook only calls signal(2), with a libc-provided
    // disposition. It neither allocates nor invokes business Rust before exec.
    unsafe { command.pre_exec(move || restore_signal(number, previous)); }
}

/// libc changes credentials process-wide, unlike raw per-thread Linux syscalls.
pub fn drop_privileges(uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: scalar IDs, no caller memory; preserve gid-before-uid ordering.
    if unsafe { setgid(gid) } < 0 || unsafe { setuid(uid) } < 0 {
        Err(io::Error::last_os_error())
    } else { Ok(()) }
}
pub fn error_text(code: i32) -> String {
    // SAFETY: target musl returns a static terminated string; supported glibc
    // keeps unknown-error storage thread-local. Copy before the next call.
    let text = unsafe { strerror(code) };
    if text.is_null() { String::new() } else {
        // SAFETY: non-null successful strerror output is terminated libc data.
        unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned()
    }
}
pub fn read_fd(fd: i32, bytes: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the exclusive slice bounds every kernel write, including EBADF.
    let result = unsafe { read(fd, bytes.as_mut_ptr(), bytes.len()) };
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result as usize) }
}
pub fn write_fd(fd: i32, bytes: &[u8]) -> isize {
    // SAFETY: initialized shared bytes remain live throughout write(2); no
    // ownership is inferred from fd. write is also async-signal-safe.
    unsafe { write(fd, bytes.as_ptr(), bytes.len()) }
}

#[cfg(target_os = "linux")]
unsafe extern "C" { fn __errno_location() -> *mut i32; }

#[cfg(target_os = "linux")]
/// Synchronous errno observation used by signal regression tests.
pub fn with_errno<R>(value: i32, action: impl FnOnce() -> R) -> (R, i32) {
    struct Restore(*mut i32, i32);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: the guard never escapes this thread's synchronous call.
            unsafe {
                *self.0 = self.1;
            }
        }
    }
    // SAFETY: Linux exposes this live thread's errno; no pointer escapes.
    let pointer = unsafe { __errno_location() };
    // SAFETY: pointer belongs to the calling thread for the whole operation.
    let restore = unsafe {
        let previous = *pointer;
        *pointer = value;
        Restore(pointer, previous)
    };
    let result = action();
    // SAFETY: callback completed synchronously on the same thread.
    let observed = unsafe { *pointer };
    drop(restore);
    (result, observed)
}

