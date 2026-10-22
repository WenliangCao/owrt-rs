//! Fixed socket options for HTTP's numeric connection snapshots. No File or
//! TcpStream owner is fabricated for these borrowed event-loop slots.
use std::io;
use std::time::Duration;
#[repr(C)]
struct Timeval {
    seconds: i64,
    micros: i64,
}
unsafe extern "C" {
    fn ioctl(fd: i32, request: std::ffi::c_ulong, ...) -> i32;
    fn setsockopt(
        fd: i32,
        level: i32,
        option: i32,
        value: *const std::ffi::c_void,
        size: u32,
    ) -> i32;
}
pub fn set_nonblocking(fd: i32, enabled: bool) -> io::Result<()> {
    if fd < 0 {
        return Ok(());
    }
    let enabled = i32::from(enabled);
    // SAFETY: FIONBIO reads one live i32 and does not take descriptor ownership.
    let rc = unsafe { ioctl(fd, 0x5421, &enabled as *const i32) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub fn set_read_timeout(fd: i32, duration: Duration) -> io::Result<()> {
    if fd < 0 {
        return Ok(());
    }
    if duration.is_zero() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut value = Timeval {
        seconds: duration.as_secs().min(i64::MAX as u64) as i64,
        micros: i64::from(duration.subsec_micros()),
    };
    if value.seconds == 0 && value.micros == 0 {
        value.micros = 1;
    }
    // SAFETY: SO_RCVTIMEO reads the exact Linux64 timeval size from live storage.
    let rc = unsafe { setsockopt(fd, 1, 20, (&value as *const Timeval).cast(), 16) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub fn set_tcp_fastopen(fd: impl std::os::fd::AsFd, queue: i32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: TCP_FASTOPEN reads one bounded scalar from live storage; the
    // borrowed socket remains owned for this call. rustix lacks this option.
    let rc = unsafe {
        setsockopt(
            fd.as_fd().as_raw_fd(),
            6,
            23,
            (&queue as *const i32).cast(),
            4,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
