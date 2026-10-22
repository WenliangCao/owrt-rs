//! epoll control accepts numeric source slots, including an already-closed
//! slot during teardown. The epoll itself is borrowed from a live owner.
use rustix::event::epoll::Event;
use std::io;
use std::os::fd::{AsFd, AsRawFd};

unsafe extern "C" {
    fn epoll_ctl(epoll: i32, operation: i32, fd: i32, event: *const std::ffi::c_void) -> i32;
}

pub enum Control {
    Add,
    Modify,
    Delete,
}
pub fn control(epoll: impl AsFd, operation: Control, fd: i32, event: &Event) -> io::Result<()> {
    let (op, pointer) = match operation {
        Control::Add => (1, event as *const Event),
        Control::Modify => (3, event as *const Event),
        Control::Delete => (2, std::ptr::null()),
    };
    // SAFETY: rustix Event is the verified target epoll_event ABI. The kernel
    // reads one live record for ADD/MOD and no pointer for DEL. Numeric source
    // validity is checked by the kernel; this call never closes/adopts it.
    let result = unsafe { epoll_ctl(epoll.as_fd().as_raw_fd(), op, fd, pointer.cast()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[test]
fn epoll_event_matches_the_sdk_layout() {
    #[cfg(target_arch = "aarch64")]
    assert_eq!(
        (
            std::mem::size_of::<Event>(),
            std::mem::offset_of!(Event, data)
        ),
        (16, 8)
    );
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        (
            std::mem::size_of::<Event>(),
            std::mem::offset_of!(Event, data)
        ),
        (12, 4)
    );
}
