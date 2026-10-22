//! ubusd's signal wake and integer peer-credential ABI boundaries.
pub use crate::unix::with_errno;

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

/// Linux can return pid=0 for an unavailable/invisible peer. Keep that valid
/// kernel result as integers, like ubusd's original ucred. rustix 1.1.5 UCred
/// embeds a NonZero PID and cannot represent it (upstream rustix#1698).
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct Ucred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

unsafe extern "C" {
    fn getsockopt(fd: i32, level: i32, option: i32, value: *mut Ucred, length: *mut u32) -> i32;
}
pub fn peer_cred(fd: impl std::os::fd::AsFd) -> std::io::Result<Ucred> {
    use std::os::fd::AsRawFd;
    let mut value = Ucred::default();
    let mut length = std::mem::size_of::<Ucred>() as u32;
    // SAFETY: SO_PEERCRED fills exactly the three initialized Linux integer
    // fields; every bit pattern including pid 0 and uid/gid -1 is valid. The
    // socket borrow and output storage live throughout the bounded call.
    if unsafe { getsockopt(fd.as_fd().as_raw_fd(), 1, 17, &mut value, &mut length) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<Ucred>() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(value)
}

#[test]
fn unavailable_peer_credentials_preserve_zero_pid() {
    let socket = std::os::unix::net::UnixDatagram::unbound().unwrap();
    let cred = peer_cred(&socket).unwrap();
    assert_eq!((cred.pid, cred.uid, cred.gid), (0, u32::MAX, u32::MAX));
}
