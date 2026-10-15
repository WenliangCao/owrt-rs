//! Optional owner-local wait acceleration, never a replacement for global poll.
//!
//! Keys describe live owned descriptors, not object addresses. The single
//! owner must change a key when a descriptor is replaced and must not close or
//! duplicate an eligible descriptor behind this interface. Untagged entries
//! keep the original poll path, including arbitrary files and POLLNVAL.
use owrt_ubus::sys::{self, PollFd, POLLERR, POLLHUP, POLLIN, POLLOUT};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

// Bound the optional linear reconciliation work; this is not a connection
// limit. Larger sets use the original direct poll for that wait.
const MAX_TAGS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Key {
    Signal,
    Route,
    Listener(u64, bool), // token, TCP
    Tcp(u64),
}

#[repr(C)]
#[cfg_attr(target_arch = "x86_64", repr(packed))]
#[derive(Clone, Copy, Default)]
struct Event {
    events: u32,
    token: u64,
}

unsafe extern "C" {
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *const Event) -> i32;
    fn epoll_wait(epfd: i32, events: *mut Event, count: i32, timeout: i32) -> i32;
}

#[derive(Clone, Copy)]
struct Registration {
    key: Key,
    fd: RawFd,
    mask: i16,
    token: u64,
}

pub(super) struct OwnerReadiness {
    epoll: Option<OwnedFd>,
    tags: Vec<(usize, Key)>,
    desired: Vec<Registration>,
    registered: Vec<Registration>,
    direct: Vec<PollFd>,
    events: Vec<Event>,
    next_token: u64,
    oversized: bool,
}

impl OwnerReadiness {
    pub(super) fn new() -> Self {
        // SAFETY: scalar CLOEXEC flag; a successful fresh descriptor is owned once.
        let fd = unsafe { epoll_create1(0o2000000) };
        Self {
            epoll: (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) }),
            tags: Vec::new(), desired: Vec::new(), registered: Vec::new(),
            direct: Vec::new(), events: Vec::new(), next_token: 0, oversized: false,
        }
    }

    fn disable(&mut self) {
        // Closing the optional epoll descriptor removes its registrations;
        // no source fd is closed, duplicated or kept alive by this object.
        self.epoll = None;
        self.tags = Vec::new();
        self.desired = Vec::new();
        self.registered = Vec::new();
        self.direct = Vec::new();
        self.events = Vec::new();
    }

    pub(super) fn begin(&mut self) { self.tags.clear(); self.oversized = false; }

    pub(super) fn watch(&mut self, slot: usize, key: Key) {
        if self.epoll.is_none() || self.oversized { return; }
        if self.tags.len() == MAX_TAGS { self.oversized = true; self.tags.clear(); return; }
        if self.tags.try_reserve(1).is_err() { self.disable(); return; }
        self.tags.push((slot, key));
    }

    fn ctl(&self, operation: i32, row: Registration) -> io::Result<()> {
        let event = Event { events: row.mask as u32, token: row.token };
        // SAFETY: epoll and source descriptors are borrowed; Event matches the
        // Linux ABI and remains initialized and live across this scalar call.
        if unsafe { epoll_ctl(self.epoll.as_ref().unwrap().as_raw_fd(), operation, row.fd, &event) } < 0 {
            Err(io::Error::last_os_error())
        } else { Ok(()) }
    }

    fn prepare(&mut self, fds: &[PollFd]) -> io::Result<()> {
        let allocation = |_| io::Error::from(io::ErrorKind::OutOfMemory);
        self.desired.clear();
        self.direct.clear();
        self.desired.try_reserve(self.tags.len()).map_err(allocation)?;
        self.registered.try_reserve(self.tags.len().saturating_sub(self.registered.len())).map_err(allocation)?;
        self.direct.try_reserve(fds.len().saturating_add(1)).map_err(allocation)?;
        for &(slot, key) in &self.tags {
            let fd = fds.get(slot).ok_or(io::ErrorKind::InvalidInput)?.fd;
            if fd < 0 { continue; }
            if let Some(previous) = self.desired.iter().find(|row| row.fd == fd || row.key == key) {
                if previous.fd != fd || previous.key != key { return Err(io::ErrorKind::InvalidInput.into()); }
                continue;
            }
            self.desired.push(Registration { key, fd, mask: 0, token: 0 });
        }
        // A descriptor can have multiple original slots. Merge requested
        // masks for registration, then expand results to every original slot.
        for fd in fds {
            if let Some(row) = self.desired.iter_mut().find(|row| row.fd == fd.fd) {
                if fd.events & !(POLLIN | POLLOUT) != 0 { return Err(io::ErrorKind::InvalidInput.into()); }
                row.mask |= fd.events;
            } else { self.direct.push(*fd); }
        }
        self.events.clear();
        if self.desired.len() > i32::MAX as usize { return Err(io::ErrorKind::InvalidInput.into()); }
        self.events.try_reserve(self.desired.len().max(1)).map_err(allocation)?;
        self.events.resize(self.desired.len().max(1), Event::default());
        // Retired keys are removed before adding a new lifetime which may
        // reuse the same numeric fd. No descriptor ownership is transferred.
        let mut at = 0;
        while at < self.registered.len() {
            let old = self.registered[at];
            if self.desired.iter().any(|new| new.key == old.key && new.fd == old.fd) { at += 1; continue; }
            match self.ctl(2, old) {
                Ok(()) => {}
                Err(error) if matches!(error.raw_os_error(), Some(2 | 9)) => {}
                Err(error) => return Err(error),
            }
            self.registered.swap_remove(at);
        }
        for index in 0..self.desired.len() {
            let mut new = self.desired[index];
            if let Some(at) = self.registered.iter().position(|old| old.key == new.key && old.fd == new.fd) {
                let old = self.registered[at];
                new.token = old.token;
                if old.mask != new.mask { self.ctl(3, new)?; }
                self.registered[at] = new;
            } else {
                self.next_token = self.next_token.checked_add(1).ok_or(io::ErrorKind::Other)?;
                new.token = self.next_token;
                self.ctl(1, new)?;
                self.registered.push(new);
            }
            self.desired[index] = new;
        }
        Ok(())
    }

    fn collect(&mut self, timeout_ms: i32) -> io::Result<usize> {
        loop {
            // SAFETY: writable Event storage covers the supplied count. EINTR
            // retries the original timeout, matching the existing poll wrapper.
            let result = unsafe { epoll_wait(self.epoll.as_ref().unwrap().as_raw_fd(),
                self.events.as_mut_ptr(), self.events.len() as i32, timeout_ms) };
            if result >= 0 { return Ok(result as usize); }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
        }
    }

    pub(super) fn wait(&mut self, fds: &mut [PollFd], timeout_ms: i32) -> io::Result<usize> {
        if self.epoll.is_none() || self.oversized { return sys::poll_fds(fds, timeout_ms); }
        let started = Instant::now();
        if self.prepare(fds).is_err() {
            self.disable();
            return fallback_wait(fds, timeout_ms, started);
        }
        if self.desired.is_empty() { return sys::poll_fds(fds, timeout_ms); }
        for fd in fds.iter_mut() { fd.revents = 0; }
        let direct_count = self.direct.len();
        let count = if direct_count == 0 {
            match self.collect(timeout_ms) {
                Ok(count) => count,
                Err(_) => { self.disable(); return fallback_wait(fds, timeout_ms, started); }
            }
        } else {
            self.direct.push(PollFd { fd: self.epoll.as_ref().unwrap().as_raw_fd(), events: POLLIN, revents: 0 });
            sys::poll_fds(&mut self.direct, timeout_ms)?;
            let group = self.direct[direct_count].revents;
            if group & !POLLIN != 0 {
                self.disable(); return fallback_wait(fds, timeout_ms, started);
            }
            if group == 0 { 0 } else {
                match self.collect(0) {
                    Ok(count) => count,
                    Err(_) => { self.disable(); return fallback_wait(fds, timeout_ms, started); }
                }
            }
        };
        for event in &self.events[..count] {
            let token = event.token;
            let Some(row) = self.registered.iter().find(|row| row.token == token) else {
                self.disable(); return fallback_wait(fds, timeout_ms, started);
            };
            for fd in fds.iter_mut().filter(|fd| fd.fd == row.fd) {
                fd.revents |= event.events as i16 & (fd.events | POLLERR | POLLHUP);
            }
        }
        let mut direct = 0;
        for fd in fds.iter_mut() {
            if !self.registered.iter().any(|row| row.fd == fd.fd) {
                fd.revents = self.direct[direct].revents;
                direct += 1;
            }
        }
        Ok(fds.iter().filter(|fd| fd.revents != 0).count())
    }
}

fn fallback_wait(fds: &mut [PollFd], timeout_ms: i32, started: Instant) -> io::Result<usize> {
    // An internal wake/error is not a completed caller idle interval. This
    // matters for DHCP probe waits, which count a full quiet quarter-second.
    let remaining = if timeout_ms < 0 { -1 } else {
        Duration::from_millis(timeout_ms as u64).saturating_sub(started.elapsed())
            .as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32
    };
    sys::poll_fds(fds, remaining)
}

#[cfg(test)]
#[path = "owner_readiness_tests.rs"]
mod tests;
