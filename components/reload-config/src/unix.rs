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

pub fn try_lock(fd: RawFd) -> io::Result<bool> {
    // SAFETY: fd is owned by a live File and flock does not retain a pointer.
    let result = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error)
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
