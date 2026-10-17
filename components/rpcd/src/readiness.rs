//! A fixed pair of readable descriptors, registered once for the daemon loop.

use owrt_ubus::sys::{self, PollFd, POLLIN};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

pub struct Readiness {
    poll: [PollFd; 2],
    epoll: Option<OwnedFd>,
}

impl Readiness {
    pub fn new(fds: [RawFd; 2]) -> Self {
        #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
        let epoll = linux::register(fds).ok();
        #[cfg(not(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64"))))]
        let epoll = None;
        Self { poll: fds.map(|fd| PollFd { fd, events: POLLIN, revents: 0 }), epoll }
    }

    pub fn uses_epoll(&self) -> bool { self.epoll.is_some() }

    pub fn wait(&mut self, timeout: i32) -> io::Result<[bool; 2]> {
        #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
        if let Some(fd) = &self.epoll {
            return linux::wait(fd.as_raw_fd(), timeout);
        }
        for fd in &mut self.poll { fd.revents = 0; }
        sys::poll_fds(&mut self.poll, timeout)?;
        Ok(self.poll.each_ref().map(|fd| fd.revents != 0))
    }
}

#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
use owrt_platform::rpcd::readiness as linux;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn level_readiness_remains_until_consumed_and_reports_closure() {
        let (mut a, mut send_a) = UnixStream::pair().unwrap();
        let (b, mut send_b) = UnixStream::pair().unwrap();
        let mut readiness = Readiness::new([a.as_raw_fd(), b.as_raw_fd()]);
        assert_eq!(readiness.wait(0).unwrap(), [false, false]);
        send_a.write_all(b"x").unwrap();
        assert_eq!(readiness.wait(100).unwrap(), [true, false]);
        assert_eq!(readiness.wait(0).unwrap(), [true, false]);
        a.read_exact(&mut [0]).unwrap();
        assert_eq!(readiness.wait(0).unwrap(), [false, false]);
        send_b.write_all(b"x").unwrap();
        assert_eq!(readiness.wait(100).unwrap(), [false, true]);
        drop(send_a);
        assert_eq!(readiness.wait(100).unwrap(), [true, true]);
    }

    #[test]
    fn failed_registration_keeps_poll_fallback() {
        let (a, mut send) = UnixStream::pair().unwrap();
        let mut readiness = Readiness::new([a.as_raw_fd(), -1]);
        assert!(!readiness.uses_epoll());
        send.write_all(b"x").unwrap();
        assert_eq!(readiness.wait(100).unwrap(), [true, false]);
    }
}
