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
    use std::os::fd::{OwnedFd, RawFd};
    use rustix::event::{epoll, Timespec};
    use owrt_platform::readiness::{self, Control};

    const BATCH: usize = 32;
    const POLL_BITS: u32 = 0x001 | 0x004 | 0x008 | 0x010;
    pub struct Poller { epoll: OwnedFd, events: Vec<epoll::Event> }

    impl Poller {
        pub fn new() -> io::Result<Self> {
            let epoll = epoll::create(epoll::CreateFlags::CLOEXEC)?;
            let event = epoll::Event { flags: epoll::EventFlags::empty(), data: epoll::EventData::new_u64(0) };
            Ok(Self { epoll, events: vec![event; BATCH] })
        }
        fn ctl(&self, operation: Control, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
            let flags = (if read { epoll::EventFlags::IN } else { epoll::EventFlags::empty() })
                | if write { epoll::EventFlags::OUT } else { epoll::EventFlags::empty() };
            readiness::control(&self.epoll, operation, fd,
                &epoll::Event { flags, data: epoll::EventData::new_u64(token) })
        }
        pub fn add(&mut self, fd: RawFd, token: u64, write: bool) -> io::Result<()> {
            self.ctl(Control::Add, fd, token, true, write)
        }
        pub fn set_write(&mut self, fd: RawFd, token: u64, write: bool) -> io::Result<()> {
            self.set_interest(fd, token, true, write)
        }
        pub fn set_interest(&mut self, fd: RawFd, token: u64, read: bool, write: bool) -> io::Result<()> {
            self.ctl(Control::Modify, fd, token, read, write)
        }
        pub fn remove(&mut self, fd: RawFd) -> io::Result<()> {
            self.ctl(Control::Delete, fd, 0, false, false)
        }
        pub fn wait(&mut self, timeout_ms: i32, ready: &mut Vec<Ready>) -> io::Result<()> {
            ready.clear();
            let timeout = (timeout_ms >= 0).then(|| Timespec {
                tv_sec: (timeout_ms / 1000) as _, tv_nsec: ((timeout_ms % 1000) * 1_000_000) as _,
            });
            let n = loop {
                match epoll::wait(&self.epoll, &mut self.events[..], timeout.as_ref()) {
                    Err(rustix::io::Errno::INTR) => continue,
                    result => break result?,
                }
            };
            for event in &self.events[..n] {
                let flags = event.flags;
                let data = event.data;
                ready.push(Ready { token: data.u64(), revents: (flags.bits() & POLL_BITS) as i16 });
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

        pub fn set_write(&mut self, fd: RawFd, token: u64, write: bool) -> io::Result<()> {
            self.set_interest(fd, token, true, write)
        }

        pub fn set_interest(&mut self, fd: RawFd, _token: u64, read: bool, write: bool) -> io::Result<()> {
            let Some(entry) = self.fds.iter_mut().find(|p| p.fd == fd) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "descriptor not registered"));
            };
            entry.events = (if read { POLLIN } else { 0 }) | if write { POLLOUT } else { 0 };
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

    #[test]
    fn eof_read_interest_can_be_removed_without_losing_write_readiness() {
        let (mut a, peer) = UnixStream::pair().unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let mut poller = Poller::new().unwrap();
        poller.add(a.as_raw_fd(), 4, false).unwrap();
        assert_ne!(wait(&mut poller, 1000)[0].revents & POLLIN, 0);
        assert_eq!(a.read(&mut [0]).unwrap(), 0);
        poller.set_interest(a.as_raw_fd(), 4, false, false).unwrap();
        assert!(wait(&mut poller, 20).is_empty());
        poller.set_interest(a.as_raw_fd(), 4, false, true).unwrap();
        let ready = wait(&mut poller, 1000);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].revents & POLLIN, 0);
        assert_ne!(ready[0].revents & POLLOUT, 0);
    }
}
