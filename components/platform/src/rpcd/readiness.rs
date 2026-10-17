//! Raw descriptor snapshots may contain -1 for the poll fallback. Do not
//! fabricate BorrowedFd values for epoll registration or waiting.
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
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
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut Event) -> i32;
    fn epoll_wait(epfd: i32, events: *mut Event, count: i32, timeout: i32) -> i32;
}

pub fn register(fds: [RawFd; 2]) -> io::Result<OwnedFd> {
    let owned = rustix::event::epoll::create(rustix::event::epoll::CreateFlags::CLOEXEC)?;
    let fd = owned.as_raw_fd();
    for (token, target) in fds.into_iter().enumerate() {
        let mut event = Event {
            events: 1,
            token: token as u64,
        }; // EPOLLIN, level triggered
           // SAFETY: event is a live SDK-layout epoll_event for this call.
        if unsafe { epoll_ctl(fd, 1, target, &mut event) } < 0 {
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
