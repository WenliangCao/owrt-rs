//! Small libc boundaries for rpcd. Request policy and protocol state stay in rpcd.
use std::ffi::{c_char, CStr, CString};
use std::io;
use std::sync::Mutex;

pub mod readiness;

unsafe extern "C" {
    #[link_name = "fnmatch"]
    fn libc_fnmatch(pattern: *const c_char, name: *const c_char, flags: i32) -> i32;
    fn fork() -> i32;
    fn sleep(seconds: u32) -> u32;
    fn execv(path: *const c_char, argv: *const *const c_char) -> i32;
    fn _exit(status: i32) -> !;
    fn sync();
    fn reboot(command: i32) -> i32;
    fn write(fd: i32, bytes: *const u8, count: usize) -> isize;
    fn read(fd: i32, bytes: *mut u8, count: usize) -> isize;
    fn __errno_location() -> *mut i32;
    fn localtime_r(time: *const i64, output: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn time(output: *mut i64) -> i64;
}
#[cfg_attr(target_env = "gnu", link(name = "crypt"))]
unsafe extern "C" {
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

pub fn fnmatch(pattern: &CStr, name: &CStr, flags: i32) -> bool {
    // SAFETY: both terminated strings live across libc's synchronous matcher.
    unsafe { libc_fnmatch(pattern.as_ptr(), name.as_ptr(), flags) == 0 }
}

static CRYPT: Mutex<()> = Mutex::new(());
pub fn crypt_matches(key: &CStr, salt: &CStr, expected: &[u8]) -> bool {
    let _guard = CRYPT.lock().unwrap_or_else(|error| error.into_inner());
    // SAFETY: input strings live across crypt. The mutex protects its static
    // result until comparison is complete; no borrowed result escapes.
    let result = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    if result.is_null() {
        return false;
    }
    // SAFETY: a successful crypt result is terminated and stable under CRYPT.
    unsafe { CStr::from_ptr(result) }.to_bytes() == expected
}

pub fn delayed_exec(arguments: &[CString]) -> i32 {
    if arguments.is_empty() {
        return -1;
    }
    let mut argv: Vec<_> = arguments.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(std::ptr::null());
    // SAFETY: all argv storage exists before libc fork. The child invokes
    // only fixed libc sleep/execv/_exit calls and never returns to Rust or
    // accesses inherited locks, callbacks or parent-owned destructors.
    unsafe {
        let pid = fork();
        if pid == 0 {
            sleep(2);
            execv(argv[0], argv.as_ptr());
            _exit(127);
        }
        pid
    }
}

pub fn delayed_reboot() -> i32 {
    // SAFETY: child-only libc sync/sleep/reboot, with fixed scalar arguments.
    // This matches the existing delayed reboot and never reenters Rust state.
    unsafe {
        let pid = fork();
        if pid == 0 {
            sync();
            sleep(2);
            reboot(0x0123_4567);
            loop {
                sleep(3600);
            }
        }
        pid
    }
}

/// Fixed async-signal-safe operation on a raw wake descriptor snapshot. An
/// invalid or closed descriptor is a syscall error, never a fabricated owner.
pub fn wake(fd: i32) {
    // SAFETY: one stack byte and libc's thread-local errno remain live for the
    // bounded async-signal-safe write. No allocation, lock or Rust callback.
    unsafe {
        let errno = __errno_location();
        let saved = *errno;
        let _ = write(fd, [1u8].as_ptr(), 1);
        *errno = saved;
    }
}

pub fn drain_pipe(fd: i32) {
    let mut buffer = [0; 64];
    loop {
        // SAFETY: writable local buffer has the supplied size. Raw snapshots
        // may already be closed, which read reports without claiming ownership.
        if unsafe { read(fd, buffer.as_mut_ptr(), buffer.len()) } <= 0 {
            break;
        }
    }
}

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

#[repr(C)]
struct Tm {
    sec: i32,
    min: i32,
    hour: i32,
    mday: i32,
    mon: i32,
    year: i32,
    wday: i32,
    yday: i32,
    isdst: i32,
    gmtoff: i64,
    zone: *const c_char,
}

pub struct LocalTime {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,
    pub year: i32,
}

pub fn localtime(provided: Option<i64>) -> Option<LocalTime> {
    // SAFETY: null time output requests the return value only.
    let timestamp = provided.unwrap_or_else(|| unsafe { time(std::ptr::null_mut()) });
    let mut tm = std::mem::MaybeUninit::<Tm>::uninit();
    // SAFETY: Linux64 musl/glibc tm storage has the native size/alignment and
    // remains writable. localtime_r writes it on a non-null successful return.
    if unsafe { localtime_r(&timestamp, tm.as_mut_ptr().cast()) }.is_null() {
        return None;
    }
    // SAFETY: the successful call initialized every calendar field consumed.
    let tm = unsafe { tm.assume_init() };
    Some(LocalTime {
        sec: tm.sec,
        min: tm.min,
        hour: tm.hour,
        mday: tm.mday,
        mon: tm.mon,
        year: tm.year,
    })
}

use std::os::fd::{AsFd, AsRawFd};
unsafe extern "C" {
    fn ioctl(fd: i32, request: std::ffi::c_ulong, ...) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const i32, len: u32) -> i32;
    fn if_nametoindex(name: *const c_char) -> u32;
    fn bind(fd: i32, address: *const u8, length: u32) -> i32;
    fn connect(fd: i32, address: *const u8, length: u32) -> i32;
    fn select(
        nfds: i32,
        read: *mut [u64; 16],
        write: *mut [u64; 16],
        except: *mut [u64; 16],
        timeout: *mut Timeval,
    ) -> i32;
}

pub fn interface_ioctl(
    fd: impl AsFd,
    command: u64,
    name: &[u8; 16],
    data: &mut [u8; 24],
) -> io::Result<()> {
    if !matches!(command, 0x8913 | 0x8914 | 0x8924 | 0x8927) {
        return Err(io::Error::from_raw_os_error(22));
    }
    let mut request = [0u8; 40];
    request[..16].copy_from_slice(name);
    request[16..].copy_from_slice(data);
    // SAFETY: the four fixed flags/MAC requests access only this Linux64
    // ifreq's 40 bytes. No allowed command interprets its union as a pointer.
    if unsafe {
        ioctl(
            fd.as_fd().as_raw_fd(),
            command as std::ffi::c_ulong,
            request.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    data.copy_from_slice(&request[16..]);
    Ok(())
}

pub fn netlink_membership(fd: impl AsFd, group: i32) -> io::Result<()> {
    // SAFETY: fixed SOL_NETLINK/ADD_MEMBERSHIP reads one live integer. rustix
    // 1.1.5 does not expose this socket option.
    if unsafe { setsockopt(fd.as_fd().as_raw_fd(), 270, 1, &group, 4) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn interface_index(name: &CStr) -> u32 {
    // SAFETY: libc receives a live terminated interface name. Its API retains
    // the existing temporary socket behavior and does not expose any pointer.
    unsafe { if_nametoindex(name.as_ptr()) }
}

#[repr(C)]
struct UnixAddress {
    family: u16,
    path: [u8; 108],
}
fn unix_address(path: &[u8]) -> (UnixAddress, u32) {
    let mut address = UnixAddress {
        family: 1,
        path: [0; 108],
    };
    let count = path.len().min(107);
    address.path[..count].copy_from_slice(&path[..count]);
    (address, (2 + count) as u32)
}

pub fn connect_unix_path(fd: impl AsFd, path: &[u8]) -> io::Result<()> {
    let (address, length) = unix_address(path);
    // SAFETY: initialized sockaddr_un storage covers length bytes. Preserve
    // iwinfo's no-terminator address length, unavailable in rustix's path ctor.
    if unsafe {
        connect(
            fd.as_fd().as_raw_fd(),
            (&address as *const UnixAddress).cast(),
            length,
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub fn bind_unix_path(fd: impl AsFd, path: &[u8]) -> io::Result<()> {
    let (address, length) = unix_address(path);
    // SAFETY: same bounded sockaddr_un contract as connect_unix_path.
    if unsafe {
        bind(
            fd.as_fd().as_raw_fd(),
            (&address as *const UnixAddress).cast(),
            length,
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[repr(C)]
struct Timeval {
    seconds: i64,
    micros: i64,
}
pub fn select_readable(fd: impl AsFd, micros: i64) -> io::Result<bool> {
    let fd = fd.as_fd().as_raw_fd();
    if !(0..1024).contains(&fd) || !(0..1_000_000).contains(&micros) {
        return Err(io::Error::from_raw_os_error(22));
    }
    let mut bits = [0u64; 16];
    bits[fd as usize / 64] |= 1 << (fd as usize % 64);
    let mut timeout = Timeval { seconds: 0, micros };
    // SAFETY: checked fd is held live by AsFd; fd_set covers nfds and timeval
    // has the Linux64 ABI. Null write/except sets request no such events.
    if unsafe {
        select(
            fd + 1,
            &mut bits,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut timeout,
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(bits[fd as usize / 64] & (1 << (fd as usize % 64)) != 0)
    }
}
