//! Raw descriptor snapshots may contain -1 for the poll fallback. Do not
//! fabricate BorrowedFd values for epoll registration or waiting.
use crate::unix::PollFd;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

pub struct Readiness {
    poll: [PollFd; 2],
    epoll: Option<OwnedFd>,
}

impl Readiness {
    pub fn new(fds: [RawFd; 2]) -> Self {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        let epoll = register(fds).ok();
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )))]
        let epoll = None;
        Self {
            poll: fds.map(|fd| PollFd {
                fd,
                events: 1,
                revents: 0,
            }),
            epoll,
        }
    }

    pub fn uses_epoll(&self) -> bool {
        self.epoll.is_some()
    }

    pub fn wait(&mut self, timeout: i32) -> io::Result<[bool; 2]> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        if let Some(fd) = &self.epoll {
            return wait(fd.as_raw_fd(), timeout);
        }
        for fd in &mut self.poll {
            fd.revents = 0;
        }
        crate::unix::poll_fds(&mut self.poll, timeout)?;
        Ok(self.poll.each_ref().map(|fd| fd.revents != 0))
    }
}

// The SDK's sys/epoll.h packs this structure only on x86_64.
#[repr(C)]
#[cfg_attr(target_arch = "x86_64", repr(packed))]
#[derive(Clone, Copy, Default)]
struct Event {
    events: u32,
    token: u64,
}

#[test]
fn epoll_event_matches_the_sdk_layout() {
    #[cfg(target_arch = "aarch64")]
    assert_eq!(
        (
            std::mem::size_of::<Event>(),
            std::mem::offset_of!(Event, token)
        ),
        (16, 8)
    );
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        (
            std::mem::size_of::<Event>(),
            std::mem::offset_of!(Event, token)
        ),
        (12, 4)
    );
}

unsafe extern "C" {
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *const std::ffi::c_void) -> i32;
    fn epoll_wait(epfd: i32, events: *mut Event, count: i32, timeout: i32) -> i32;
}

pub fn register(fds: [RawFd; 2]) -> io::Result<OwnedFd> {
    let owned = rustix::event::epoll::create(rustix::event::epoll::CreateFlags::CLOEXEC)?;
    let fd = owned.as_raw_fd();
    for (token, target) in fds.into_iter().enumerate() {
        let event = Event {
            events: 1,
            token: token as u64,
        }; // EPOLLIN, level triggered
           // SAFETY: event is a live SDK-layout epoll_event for this call.
        if unsafe { epoll_ctl(fd, 1, target, (&event as *const Event).cast()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(owned)
}

pub fn wait(fd: RawFd, timeout: i32) -> io::Result<[bool; 2]> {
    let mut events = [Event::default(); 2];
    // SAFETY: events has exactly the two writable entries advertised.
    let n = unsafe { epoll_wait(fd, events.as_mut_ptr(), 2, timeout) };
    // Return EINTR too, so the caller can reconsider signals and timers.
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ready = [false; 2];
    for event in &events[..n as usize] {
        if let Some(slot) = ready.get_mut(event.token as usize) {
            *slot = true;
        }
    }
    Ok(ready)
}

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
