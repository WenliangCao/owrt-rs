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
            timeout: 30,
            frequency: 5,
            magicclose: false,
            next_ping: None,
        }
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
        // preinit has transferred the inherited descriptor across exec; tests
        // explicitly relinquish it with into_raw_fd. Preserve that exact owner.
        let fd = match crate::sys::take_inherited_watchdog(crate::sys::atoi_u32) {
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

    /// `watchdog_init()`.
    pub fn init(&mut self, now: i64, preinit: bool) {
        if !self.open(!preinit) {
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
            self.open(true);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn inherited_watchdog_exec_flags_and_final_close() {
        use std::os::fd::{AsRawFd, IntoRawFd};
        use std::process::Command;

        // Keep WDTFD mutation and intentional fd inheritance out of the
        // concurrent test process. The child runs only this existing test.
        const CHILD: &str = "OWRT_PROCD_WDT_OWNERSHIP_TEST";
        if std::env::var_os(CHILD).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "watchdog::tests::inherited_watchdog_exec_flags_and_final_close",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .env_remove("WDTFD")
                .status()
                .unwrap();
            assert!(status.success(), "isolated watchdog ownership test failed");
            return;
        }

        let (reader, writer) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )
        .unwrap();
        // A high fd avoids shell startup reusing a descriptor that should
        // have disappeared at exec. Only the transferred writer remains.
        let transferred = rustix::io::fcntl_dupfd_cloexec(&writer, 1000).unwrap();
        drop(writer);
        rustix::io::fcntl_setfd(&transferred, rustix::io::FdFlags::empty()).unwrap();
        let inherited = transferred.into_raw_fd();
        std::env::set_var("WDTFD", inherited.to_string());
        let mut watchdog = Wdt::default();
        watchdog.init(0, false);
        assert!(std::env::var_os("WDTFD").is_none());
        assert_eq!(
            watchdog.handover_fd(),
            Some(inherited),
            "handover must not duplicate"
        );

        assert!(rustix::io::fcntl_getfd(watchdog.fd.as_ref().unwrap())
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));

        for cloexec in [true, false, true] {
            watchdog.set_cloexec(cloexec);
            let flags = rustix::io::fcntl_getfd(watchdog.fd.as_ref().unwrap()).unwrap();
            assert_eq!(flags.contains(rustix::io::FdFlags::CLOEXEC), cloexec);
            let script = if cloexec {
                "test ! -e /proc/self/fd/\"$1\""
            } else {
                "test -e /proc/self/fd/\"$1\""
            };
            assert!(
                Command::new("/bin/sh")
                    .args(["-c", script, "watchdog-exec", &inherited.to_string()])
                    .status()
                    .unwrap()
                    .success(),
                "exec inheritance differs from CLOEXEC"
            );
        }

        watchdog.set_magicclose(true);
        watchdog.set_stopped(true, 0);
        assert!(watchdog.stopped());
        assert_eq!(watchdog.handover_fd(), None);
        let mut bytes = [0; 8];
        let count = rustix::io::read(&reader, &mut bytes).unwrap();
        assert_eq!(&bytes[..count], b"XV", "one init ping then one magic close");
        assert_eq!(
            rustix::io::read(&reader, &mut bytes).unwrap(),
            0,
            "magic close left an extra writer reference alive"
        );

        let reused = rustix::io::fcntl_dupfd_cloexec(&reader, inherited).unwrap();
        assert_eq!(reused.as_raw_fd(), inherited);
        drop(watchdog);
        assert!(
            rustix::io::fcntl_getfd(&reused).is_ok(),
            "drop closed a reused fd"
        );
    }

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
