//! `watchdog.c`: /dev/watchdog keep-alive, and the state the
//! `system watchdog` method reads and writes.
//!
//! Defaults are the C's statics: driver timeout 30 s, ping frequency 5 s,
//! magicclose off. `stopped` is defined as "the ping timer is not pending",
//! not as "the fd is closed" -- the method's status string checks the fd
//! first, so a box with no /dev/watchdog is "offline" whatever the timer
//! says. The WDTFD handover (preinit passes an already-open fd in the
//! environment) is honoured because the C unsets the variable either way.

use std::ffi::CString;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

extern "C" {
    fn open(path: *const u8, flags: i32, mode: u32) -> i32;
    fn write(fd: i32, buf: *const u8, n: usize) -> isize;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
}

const O_WRONLY: i32 = 1;
const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const FD_CLOEXEC: i32 = 1;
/// `_IOWR('W', 6, int)`.
const WDIOC_SETTIMEOUT: u64 = 0xC004_5706;

pub struct Wdt {
    fd: Option<OwnedFd>,
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
        Wdt { fd: None, timeout: 30, frequency: 5, magicclose: false, next_ping: None }
    }
}

impl Wdt {
    fn raw_fd(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.fd.as_ref().map(|f| f.as_raw_fd()).unwrap_or(-1)
    }

    /// `watchdog_open()`: the WDTFD handover, else /dev/watchdog.
    fn open(&mut self, cloexec: bool) -> bool {
        if self.fd.is_some() {
            return true;
        }
        let fd = match std::env::var("WDTFD") {
            Ok(v) => {
                std::env::remove_var("WDTFD");
                crate::sys::atoi_u32(&v) as i32
            }
            Err(_) => {
                let Ok(c) = CString::new("/dev/watchdog") else { return false };
                // SAFETY: NUL-terminated path.
                unsafe { open(c.as_ptr().cast(), O_WRONLY, 0) }
            }
        };
        if fd < 0 {
            return false;
        }
        if cloexec {
            // SAFETY: fd flag ops on a live fd.
            unsafe { fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC) };
        }
        // SAFETY: `fd` is open and now owned exactly once.
        self.fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
        true
    }

    /// `watchdog_close()`: magic close writes "V" so the driver disarms.
    fn close(&mut self, with_release: bool) {
        let Some(fd) = self.fd.take() else { return };
        if with_release {
            let raw = fd.into_raw_fd();
            // SAFETY: one byte to a live fd, which is then closed once.
            unsafe {
                write(raw, b"V".as_ptr(), 1);
                let _ = crate::sys::close_fd(raw);
            }
        }
        // Not with_release: fd drops and closes here.
    }

    fn set_drv_timeout(&mut self) {
        if self.fd.is_none() {
            return;
        }
        let mut t = self.timeout;
        // SAFETY: WDIOC_SETTIMEOUT reads and writes one int.
        unsafe { crate::sys::ioctl(self.raw_fd(), WDIOC_SETTIMEOUT, &mut t) };
    }

    /// `watchdog_ping()` + re-arm, i.e. `watchdog_timeout_cb`.
    fn ping_and_rearm(&mut self, now: i64) {
        if self.fd.is_some() {
            // SAFETY: one byte to a live fd.
            let r = unsafe { write(self.raw_fd(), b"X".as_ptr(), 1) };
            if r < 0 {
                eprintln!("procd-rs: WDT failed to write");
            }
        }
        self.next_ping = Some(now + self.frequency as i64 * 1000);
    }

    /// `watchdog_init()`.
    pub fn init(&mut self, now: i64, preinit: bool) {
        if !self.open(!preinit) {
            return;
        }
        crate::sys::klog("- watchdog -");
        self.set_drv_timeout();
        self.ping_and_rearm(now);
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
            self.open(true);
            self.set_drv_timeout();
            self.ping_and_rearm(now);
        }
    }

    /// `watchdog_get_stopped()`: the timer, not the fd.
    pub fn stopped(&self) -> bool {
        self.next_ping.is_none()
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
