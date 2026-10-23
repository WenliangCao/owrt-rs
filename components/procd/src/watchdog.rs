//! `watchdog.c`: /dev/watchdog keep-alive, and the state the
//! `system watchdog` method reads and writes.
//!
//! Defaults are the C's statics: driver timeout 30 s, ping frequency 5 s,
//! magicclose off. `stopped` is defined as "the ping timer is not pending",
//! not as "the fd is closed" -- the method's status string checks the fd
//! first, so a box with no /dev/watchdog is "offline" whatever the timer
//! says. The WDTFD handover (preinit passes an already-open fd in the
//! environment) is honoured because the C unsets the variable either way.

use std::os::fd::OwnedFd;
const WDIOF_CARDRESET: u32 = 0x20;

pub struct Wdt {
    fd: Option<OwnedFd>,
    // Startup adopts the raw handover once. A non-PID1 supervisor keeps it
    // untouched until the first explicit watchdog open from its ubus method.
    inherited: Option<std::io::Result<OwnedFd>>,
    /// `wdt_drv_timeout`.
    timeout: i32,
    /// `wdt_frequency`.
    frequency: i32,
    magicclose: bool,
    /// The uloop timer: `Some(next ping deadline)` while running.
    next_ping: Option<i64>,
}

impl Default for Wdt {
    fn default() -> Self {
        Wdt {
            fd: None,
            inherited: None,
            timeout: 30,
            frequency: 5,
            magicclose: false,
            next_ping: None,
        }
    }
}

impl Wdt {
    /// Keep an already owned startup handover for the first watchdog open.
    pub fn with_inherited(inherited: Option<std::io::Result<OwnedFd>>) -> Self {
        Self {
            inherited,
            ..Self::default()
        }
    }

    /// Borrow the currently open watchdog without transferring its close duty.
    pub fn descriptor(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        self.fd.as_ref().map(AsFd::as_fd)
    }

    fn raw_fd(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.descriptor().map(|fd| fd.as_raw_fd()).unwrap_or(-1)
    }

    /// `watchdog_open()`: an owned startup handover, else /dev/watchdog.
    fn open(&mut self, cloexec: bool, inherited: Option<std::io::Result<OwnedFd>>) -> bool {
        if self.fd.is_some() {
            return true;
        }
        // Startup establishes ownership before handing a descriptor to this
        // safe API. Runtime reopens never adopt a number from the environment.
        let fd = match inherited.or_else(|| self.inherited.take()) {
            Some(result) => result,
            None => rustix::fs::open(
                c"/dev/watchdog",
                rustix::fs::OFlags::WRONLY,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from),
        };
        let Ok(fd) = fd else {
            return false;
        };
        if cloexec {
            if let Ok(flags) = rustix::io::fcntl_getfd(&fd) {
                let _ = rustix::io::fcntl_setfd(&fd, flags | rustix::io::FdFlags::CLOEXEC);
            }
        }
        self.fd = Some(fd);
        true
    }

    /// `watchdog_close()`: magic close writes "V" so the driver disarms.
    fn close(&mut self, with_release: bool) {
        let Some(fd) = self.fd.take() else { return };
        if with_release {
            let _ = rustix::io::write(&fd, b"V");
        }
        // Not with_release: fd drops and closes here.
    }

    fn set_drv_timeout(&mut self) {
        if let Some(fd) = &self.fd {
            // WDIOC_SETTIMEOUT writes back the timeout accepted by the driver.
            let _ = crate::sys::watchdog_set_timeout(fd, &mut self.timeout);
        }
    }

    /// `watchdog_ping()` + re-arm, i.e. `watchdog_timeout_cb`.
    fn ping_and_rearm(&mut self, now: i64) {
        if let Some(fd) = &self.fd {
            if rustix::io::write(fd, b"X").is_err() {
                log!(crate::sys::LOG_ERR, "WDT failed to write");
            }
        }
        self.next_ping = Some(now + self.frequency as i64 * 1000);
    }

    /// Initialize the watchdog, consuming an optional owned preinit descriptor.
    ///
    /// Pass the startup handover only once; later initialization retries pass
    /// `None` and reopen /dev/watchdog if the initial attempt failed.
    pub fn init(&mut self, now: i64, preinit: bool, inherited: Option<std::io::Result<OwnedFd>>) {
        if !self.open(!preinit, inherited) {
            return;
        }
        log!(crate::sys::LOG_INFO, "- watchdog -");
        self.set_drv_timeout();
        self.ping_and_rearm(now);
        self.print_status();
    }

    fn print_status(&self) {
        let Some(fd) = &self.fd else {
            return;
        };
        let Ok(info) = crate::sys::watchdog_support(fd) else {
            debug!(2, "Watchdog GETSUPPORT failed");
            return;
        };
        if info.options & WDIOF_CARDRESET == 0 {
            debug!(2, "Watchdog does not have CARDRESET support");
            return;
        }
        let Ok(status) = crate::sys::watchdog_boot_status(fd) else {
            debug!(2, "Watchdog GETBOOTSTATUS failed");
            return;
        };
        if status as u32 & WDIOF_CARDRESET != 0 {
            log!(
                crate::sys::LOG_INFO,
                "Watchdog has previously reset the system"
            );
        } else {
            debug!(2, "Watchdog did not previously reset the system");
        }
    }

    /// The main loop's timer edge.
    pub fn pump(&mut self, now: i64) {
        if self.next_ping.is_some_and(|at| now >= at) {
            self.ping_and_rearm(now);
        }
    }

    /// `watchdog_set_stopped()`.
    pub fn set_stopped(&mut self, stop: bool, now: i64) {
        if stop {
            self.next_ping = None;
            let release = self.magicclose;
            self.close(release);
        } else {
            self.open(true, None);
            self.set_drv_timeout();
            self.ping_and_rearm(now);
        }
    }

    /// `watchdog_get_stopped()`: the timer, not the fd.
    pub fn stopped(&self) -> bool {
        self.next_ping.is_none()
    }

    /// Milliseconds until the next ping is due (0 when overdue), if armed.
    pub fn next_ping_in(&self, now: i64) -> Option<i64> {
        self.next_ping.map(|at| (at - now).max(0))
    }

    /// `watchdog_timeout(t)`: 0 reads, non-zero writes (and pushes to the
    /// driver when open).
    pub fn timeout(&mut self, t: i32) -> i32 {
        if t != 0 {
            self.timeout = t;
            self.set_drv_timeout();
        }
        self.timeout
    }

    /// `watchdog_frequency(f)`.
    pub fn frequency(&mut self, f: i32) -> i32 {
        if f != 0 {
            self.frequency = f;
        }
        self.frequency
    }

    pub fn magicclose(&self) -> bool {
        self.magicclose
    }

    pub fn set_magicclose(&mut self, v: bool) {
        self.magicclose = v;
    }

    /// `watchdog_fd()`: the status string's "is there a device" test.
    pub fn is_open(&self) -> bool {
        self.fd.is_some()
    }

    /// `watchdog_fd()` proper: the raw fd number for the WDTFD handover.
    pub fn handover_fd(&self) -> Option<i32> {
        self.fd.as_ref().map(|_| self.raw_fd())
    }

    /// `watchdog_set_cloexec()`: upgraded must inherit the fd.
    pub fn set_cloexec(&mut self, val: bool) {
        if let Some(fd) = &self.fd {
            if let Ok(mut flags) = rustix::io::fcntl_getfd(fd) {
                flags.set(rustix::io::FdFlags::CLOEXEC, val);
                let _ = rustix::io::fcntl_setfd(fd, flags);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_method_arithmetic_matches_watchdog_set() {
        let mut w = Wdt::default();
        assert_eq!(w.timeout(0), 30);
        assert_eq!(w.frequency(0), 5);
        // frequency > timeout/2 is clamped BY THE METHOD, not here; the
        // module stores what it is told.
        assert_eq!(w.frequency(10), 10);
        assert_eq!(w.timeout(60), 60);
        assert!(w.stopped(), "no init, no timer");
        assert!(!w.is_open());
    }
}
