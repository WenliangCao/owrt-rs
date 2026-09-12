//! Readiness notification for single-threaded daemon loops.
//!
//! The interest set is maintained incrementally: a descriptor is registered
//! once and removed once, and a wait hands back only the entries that are
//! ready. ubusd's loop used to rebuild a poll(2) array from the whole client
//! table on every iteration, so each message cost work proportional to the
//! number of connected clients -- a router has twenty or so daemons on the
//! bus, and that overhead showed up as ubusd CPU in every whole-system
//! workload while staying invisible in two-client fixtures. httpd keeps its
//! parked keep-alive sockets in the same kind of set.
//!
//! Linux uses epoll, which is what libubox's uloop gives the C daemons. Other
//! targets keep a poll(2) set in place so the tests build there too.

/// One ready descriptor: the token given at registration and the poll(2)
/// style event bits (`POLLIN`, `POLLOUT`, `POLLERR`, `POLLHUP`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ready {
    pub token: u64,
    pub revents: i16,
}

#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub use linux::Poller;
#[cfg(not(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64"))))]
pub use fallback::Poller;

#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
mod linux {
    use super::Ready;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

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
        assert_eq!((std::mem::size_of::<Event>(), std::mem::offset_of!(Event, token)), (16, 8));
        #[cfg(target_arch = "x86_64")]
        assert_eq!((std::mem::size_of::<Event>(), std::mem::offset_of!(Event, token)), (12, 4));
    }

    extern "C" {
        fn epoll_create1(flags: i32) -> i32;
        fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut Event) -> i32;
        fn epoll_wait(epfd: i32, events: *mut Event, count: i32, timeout: i32) -> i32;
    }

    const EPOLL_CLOEXEC: i32 = 0o2000000;
    const EPOLL_CTL_ADD: i32 = 1;
    const EPOLL_CTL_DEL: i32 = 2;
    const EPOLL_CTL_MOD: i32 = 3;
    const EPOLLIN: u32 = 0x001;
    const EPOLLOUT: u32 = 0x004;
    const EPOLLERR: u32 = 0x008;
    const EPOLLHUP: u32 = 0x010;
    /// The bits that share their value with poll(2); everything a wait
    /// reports is masked to these.
    const POLL_BITS: u32 = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
    /// One wait returns at most this many entries; the rest stay queued in
    /// the kernel for the next call.
    const BATCH: usize = 32;

    pub struct Poller {
        epoll: OwnedFd,
        events: Vec<Event>,
    }

    impl Poller {
        pub fn new() -> io::Result<Self> {
            // SAFETY: no pointers; the flag value is the target's EPOLL_CLOEXEC.
            let fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: epoll_create1 returned a fresh descriptor nobody else owns.
            let epoll = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(Poller { epoll, events: vec![Event::default(); BATCH] })
        }

        fn ctl(&self, op: i32, fd: RawFd, token: u64, write: bool) -> io::Result<()> {
            let mut event = Event { events: EPOLLIN | if write { EPOLLOUT } else { 0 }, token };
            // SAFETY: event is a live, correctly laid out epoll_event for this call.
            if unsafe { epoll_ctl(self.epoll.as_raw_fd(), op, fd, &mut event) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Watch `fd` for input, and for output too when `write` is set.
        pub fn add(&mut self, fd: RawFd, token: u64, write: bool) -> io::Result<()> {
            self.ctl(EPOLL_CTL_ADD, fd, token, write)
        }

        /// Change whether output readiness is wanted for a registered `fd`.
        pub fn set_write(&mut self, fd: RawFd, token: u64, write: bool) -> io::Result<()> {
            self.ctl(EPOLL_CTL_MOD, fd, token, write)
        }

        pub fn remove(&mut self, fd: RawFd) -> io::Result<()> {
            // Closing the last reference drops an fd from the set anyway; an
            // explicit removal keeps the two implementations symmetric.
            // SAFETY: a DEL takes no event structure on this kernel range.
            if unsafe { epoll_ctl(self.epoll.as_raw_fd(), EPOLL_CTL_DEL, fd, std::ptr::null_mut()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Block until something is ready or `timeout_ms` passes (-1 waits
        /// forever), filling `ready` with the ready entries.
        pub fn wait(&mut self, timeout_ms: i32, ready: &mut Vec<Ready>) -> io::Result<()> {
            ready.clear();
            let n = loop {
                // SAFETY: events is a live array of BATCH entries, and BATCH is
                // what the kernel is told it may fill.
                let n = unsafe {
                    epoll_wait(self.epoll.as_raw_fd(), self.events.as_mut_ptr(), BATCH as i32, timeout_ms)
                };
                if n < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                break n as usize;
            };
            for event in &self.events[..n] {
                let bits = event.events;
                let token = event.token;
                ready.push(Ready { token, revents: (bits & POLL_BITS) as i16 });
            }
            Ok(())
        }
    }
}

#[cfg(not(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64"))))]
mod fallback {
    use super::Ready;
    use crate::sys::{self, PollFd, POLLIN, POLLOUT};
    use std::io;
    use std::os::fd::RawFd;

    /// A poll(2) set kept in place between waits.
    pub struct Poller {
        fds: Vec<PollFd>,
        tokens: Vec<u64>,
    }

    impl Poller {
        pub fn new() -> io::Result<Self> {
            Ok(Poller { fds: Vec::new(), tokens: Vec::new() })
        }

        pub fn add(&mut self, fd: RawFd, token: u64, write: bool) -> io::Result<()> {
            let events = POLLIN | if write { POLLOUT } else { 0 };
            self.fds.push(PollFd { fd, events, revents: 0 });
            self.tokens.push(token);
            Ok(())
        }

        pub fn set_write(&mut self, fd: RawFd, _token: u64, write: bool) -> io::Result<()> {
            let Some(entry) = self.fds.iter_mut().find(|p| p.fd == fd) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "descriptor not registered"));
            };
            entry.events = POLLIN | if write { POLLOUT } else { 0 };
            Ok(())
        }

        pub fn remove(&mut self, fd: RawFd) -> io::Result<()> {
            let Some(index) = self.fds.iter().position(|p| p.fd == fd) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "descriptor not registered"));
            };
            self.fds.swap_remove(index);
            self.tokens.swap_remove(index);
            Ok(())
        }

        pub fn wait(&mut self, timeout_ms: i32, ready: &mut Vec<Ready>) -> io::Result<()> {
            ready.clear();
            sys::poll_fds(&mut self.fds, timeout_ms)?;
            for (p, &token) in self.fds.iter().zip(&self.tokens) {
                if p.revents != 0 {
                    ready.push(Ready { token, revents: p.revents });
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{POLLHUP, POLLIN, POLLOUT};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn wait(poller: &mut Poller, timeout_ms: i32) -> Vec<Ready> {
        let mut ready = Vec::new();
        poller.wait(timeout_ms, &mut ready).unwrap();
        ready.sort_by_key(|r| r.token);
        ready
    }

    #[test]
    fn reports_only_ready_entries_with_their_tokens() {
        let (mut a, mut peer_a) = UnixStream::pair().unwrap();
        let (b, mut peer_b) = UnixStream::pair().unwrap();
        let mut poller = Poller::new().unwrap();
        poller.add(a.as_raw_fd(), 7, false).unwrap();
        poller.add(b.as_raw_fd(), 9, false).unwrap();
        assert!(wait(&mut poller, 0).is_empty());

        peer_a.write_all(b"x").unwrap();
        let ready = wait(&mut poller, 1000);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].token, 7);
        assert_ne!(ready[0].revents & POLLIN, 0);
        // Level triggered: still ready until consumed.
        assert_eq!(wait(&mut poller, 0).len(), 1);
        a.read_exact(&mut [0]).unwrap();
        assert!(wait(&mut poller, 0).is_empty());

        peer_b.write_all(b"y").unwrap();
        drop(peer_a);
        let ready = wait(&mut poller, 1000);
        assert_eq!(ready.iter().map(|r| r.token).collect::<Vec<_>>(), vec![7, 9]);
        assert_ne!(ready[0].revents & (POLLIN | POLLHUP), 0);
    }

    #[test]
    fn write_interest_is_toggled_in_place_and_removal_forgets_the_fd() {
        let (a, _peer) = UnixStream::pair().unwrap();
        let mut poller = Poller::new().unwrap();
        poller.add(a.as_raw_fd(), 3, false).unwrap();
        assert!(wait(&mut poller, 0).is_empty());
        poller.set_write(a.as_raw_fd(), 3, true).unwrap();
        let ready = wait(&mut poller, 0);
        assert_eq!(ready.len(), 1);
        assert_ne!(ready[0].revents & POLLOUT, 0);
        poller.set_write(a.as_raw_fd(), 3, false).unwrap();
        assert!(wait(&mut poller, 0).is_empty());
        poller.set_write(a.as_raw_fd(), 3, true).unwrap();
        poller.remove(a.as_raw_fd()).unwrap();
        assert!(wait(&mut poller, 0).is_empty());
        assert!(poller.remove(a.as_raw_fd()).is_err());
    }
}
