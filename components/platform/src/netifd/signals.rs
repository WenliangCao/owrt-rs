//! netifd's fixed signal dispositions and async-signal-safe wake pipe.
use std::io;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

static CHILD_PIPE_W: AtomicI32 = AtomicI32::new(-1);
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);
unsafe extern "C" {
    fn signal(number: i32, handler: extern "C" fn(i32)) -> usize;
    fn write(fd: i32, bytes: *const u8, count: usize) -> isize;
    fn __errno_location() -> *mut i32;
}

extern "C" fn on_exit_signal(number: i32) {
    EXIT_REQUESTED.store(true, Ordering::SeqCst);
    on_sigchld(number);
}

extern "C" fn on_sigchld(_number: i32) {
    // SAFETY: Linux errno is live thread-local storage. Preserve it around a
    // single async-signal-safe write; the process-lifetime pipe is nonblocking.
    unsafe {
        let errno = __errno_location();
        let saved = *errno;
        let fd = CHILD_PIPE_W.load(Ordering::Relaxed);
        if fd >= 0 {
            let _ = write(fd, [1u8].as_ptr(), 1);
        }
        *errno = saved;
    }
}

pub struct ChildSignal {
    read: OwnedFd,
}
impl ChildSignal {
    pub fn install() -> io::Result<Self> {
        let (read, write) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )?;
        // As before, the handler's write descriptor lives until process exit.
        CHILD_PIPE_W.store(write.into_raw_fd(), Ordering::Relaxed);
        // SAFETY: startup registers only these static C-ABI handlers. They use
        // lock-free atomics, one bounded write and no allocation or unwinding.
        unsafe {
            signal(17, on_sigchld);
            for number in [2, 15, 10, 12] {
                signal(number, on_exit_signal);
            }
        }
        Ok(Self { read })
    }
    pub fn exit_requested(&self) -> bool {
        EXIT_REQUESTED.load(Ordering::SeqCst)
    }
    pub fn as_raw_fd(&self) -> i32 {
        self.read.as_raw_fd()
    }
    pub fn drain(&self) {
        let mut buffer = [0; 64];
        while matches!(rustix::io::read(&self.read, &mut buffer), Ok(n) if n > 0) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saturated_signal_pipe_preserves_errno() {
        let (_read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::NONBLOCK).unwrap();
        let bytes = [0; 4096];
        while rustix::io::write(&write, &bytes).is_ok() {}
        let previous = CHILD_PIPE_W.swap(write.as_raw_fd(), Ordering::Relaxed);
        // SAFETY: only this thread's errno is read/written, and the fixed
        // handler is called synchronously; no signal disposition is installed.
        let observed = unsafe {
            let errno = __errno_location();
            let saved = *errno;
            *errno = 22;
            on_sigchld(17);
            let observed = *errno;
            *errno = saved;
            observed
        };
        CHILD_PIPE_W.store(previous, Ordering::Relaxed);
        assert_eq!(observed, 22);
    }
}
