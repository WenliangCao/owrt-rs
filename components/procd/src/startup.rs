//! Owned startup inputs and fixed callbacks for the platform entry adapter.
use owrt_platform::procd::process::{FirmwareRequest, Process};
use std::io;
use std::os::fd::OwnedFd;

/// The platform adapter transfers process operations and watchdog ownership.
pub struct Startup {
    pub process: Process,
    pub inherited_watchdog: Option<io::Result<OwnedFd>>,
}

/// Report the existing cgroup failure through procd's configured logger.
pub fn cgroup_warning(context: &str, error: &io::Error) {
    crate::sys::ulog(crate::sys::LOG_WARNING, &format!("{context}: {error}"));
}

/// Apply one configured rlimit using the established procd conversion rules.
pub fn apply_limit(name: &str, value: &str) -> io::Result<()> {
    crate::sys::apply_limit(name, value)
}

/// Transfer a firmware image using the worker's owned request.
pub fn transfer_firmware(request: FirmwareRequest) {
    crate::hotplug::transfer_firmware(request);
}

/// Preserve procd's atoi conversion for the preinit descriptor field.
pub fn inherited_fd_number(value: &str) -> u32 {
    crate::sys::atoi_u32(value)
}
