//! The trusted preinit WDTFD handover and three fixed watchdog ioctl layouts.
use rustix::ioctl::{ioctl, Updater};
use std::io;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};

#[repr(C)]
#[derive(Debug, Default)]
pub struct WatchdogInfo {
    pub options: u32,
    pub firmware_version: u32,
    pub identity: [u8; 32],
}

/// Consume the preinit-to-exec watchdog descriptor named by `WDTFD`.
///
/// Removal precedes validation, as in watchdog_open(), including bad values.
/// Standard descriptors 0..=2 are rejected without closing them: they can have
/// process-global stdio borrowers and cannot become an exclusive watchdog owner.
///
/// # Safety
/// Any accepted descriptor (at least 3) must transfer sole ownership from
/// preinit: it must have no live Rust owner or borrow, and no other thread may
/// close/reuse it. Rejected standard/negative values need no ownership transfer.
/// The environment must be read and changed in a single-threaded startup phase.
/// `F_GETFD` checks validity; it cannot establish exclusive ownership.
pub unsafe fn take_inherited_watchdog(parse: fn(&str) -> u32) -> Option<io::Result<OwnedFd>> {
    let value = std::env::var("WDTFD").ok()?;
    std::env::remove_var("WDTFD");
    let fd = parse(&value) as i32;
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    if fd < 3 {
        return Some(Err(io::Error::from_raw_os_error(9)));
    }
    // SAFETY: F_GETFD validates a scalar fd without claiming ownership.
    if unsafe { fcntl(fd, 1) } < 0 {
        return Some(Err(io::Error::last_os_error()));
    }
    // SAFETY: this application-specific handover transfers the sole close
    // responsibility from preinit into the watchdog owner. Do not duplicate:
    // magic-close depends on closing the last reference to this open file.
    Some(Ok(unsafe { OwnedFd::from_raw_fd(fd) }))
}

pub fn set_timeout(fd: impl AsFd, value: &mut i32) -> io::Result<()> {
    // SAFETY: WDIOC_SETTIMEOUT reads/writes exactly one native int.
    unsafe { ioctl(fd, Updater::<0xc0045706, i32>::new(value)) }.map_err(Into::into)
}
pub fn support(fd: impl AsFd) -> io::Result<WatchdogInfo> {
    let mut value = WatchdogInfo::default();
    // SAFETY: WDIOC_GETSUPPORT writes the target's 40-byte watchdog_info.
    unsafe { ioctl(fd, Updater::<0x80285700, WatchdogInfo>::new(&mut value)) }?;
    Ok(value)
}
pub fn boot_status(fd: impl AsFd) -> io::Result<i32> {
    let mut value = 0;
    // SAFETY: WDIOC_GETBOOTSTATUS writes exactly one native int.
    unsafe { ioctl(fd, Updater::<0x80045702, i32>::new(&mut value)) }?;
    Ok(value)
}
