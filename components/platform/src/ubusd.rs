//! ubusd's bounded async-signal-safe wake operation.
// This synchronous test helper is shared until the common unix module owns it.
pub use crate::rpcd::with_errno;

unsafe extern "C" {
    fn write(fd: i32, bytes: *const u8, count: usize) -> isize;
    fn __errno_location() -> *mut i32;
}

pub fn wake(fd: i32) {
    // SAFETY: one initialized stack byte remains live across async-signal-safe
    // write. Raw fd is a handler snapshot; errors are ignored without inventing
    // ownership. Linux errno belongs to this calling thread and is restored.
    unsafe {
        let errno = __errno_location();
        let saved = *errno;
        let _ = write(fd, [0u8].as_ptr(), 1);
        *errno = saved;
    }
}
