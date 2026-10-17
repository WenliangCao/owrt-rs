//! The trusted preinit WDTFD handover and three fixed watchdog ioctl layouts.
use rustix::ioctl::{ioctl, Updater};
use std::io;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};

#[repr(C)]
#[derive(Default)]
pub struct WatchdogInfo {
    pub options: u32,
    pub firmware_version: u32,
    pub identity: [u8; 32],
}

/// Consume only procd's preinit-to-exec ownership transfer. The producer has
/// relinquished this fd (tests explicitly use into_raw_fd); it has no existing
/// Rust owner in procd. This is not an arbitrary raw-descriptor adoption API.
/// Removal precedes validation, as in watchdog_open(), including bad values.
pub fn take_inherited_watchdog(parse: fn(&str) -> u32) -> Option<io::Result<OwnedFd>> {
    let value = std::env::var("WDTFD").ok()?;
    std::env::remove_var("WDTFD");
    let fd = parse(&value) as i32;
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    if fd < 0 {
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
