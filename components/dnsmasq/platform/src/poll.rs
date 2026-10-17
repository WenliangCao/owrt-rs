//! Readiness snapshots may contain ignored or closed numeric descriptors.
//! rustix's PollFd requires a live BorrowedFd, which cannot express those
//! POLLNVAL/negative-slot semantics or live across owner mutations. This one
//! bounded libc boundary never invents a borrowed descriptor or takes ownership.

use std::io;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

pub const POLLIN: i16 = rustix::event::PollFlags::IN.bits() as i16;
pub const POLLOUT: i16 = rustix::event::PollFlags::OUT.bits() as i16;
pub const POLLERR: i16 = rustix::event::PollFlags::ERR.bits() as i16;
pub const POLLHUP: i16 = rustix::event::PollFlags::HUP.bits() as i16;

#[cfg(target_os = "macos")]
type Nfds = u32;
#[cfg(not(target_os = "macos"))]
type Nfds = usize;
unsafe extern "C" {
    #[link_name = "poll"]
    fn system_poll(fds: *mut PollFd, count: Nfds, timeout: i32) -> i32;
}

/// Preserve EINTR so deadline-aware callers can recompute their wait.
pub fn poll_once(fds: &mut [PollFd], timeout: i32) -> io::Result<usize> {
    let count =
        Nfds::try_from(fds.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: PollFd matches Unix pollfd's three scalar fields. The exclusive
    // initialized slice covers exactly count entries and stays live throughout
    // the syscall. poll defines negative/invalid FD behavior and neither closes
    // descriptors nor retains this pointer, so validity is not a precondition.
    let result = unsafe { system_poll(fds.as_mut_ptr(), count, timeout) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

/// Match the existing owner wait: retry EINTR with the original timeout.
pub fn poll_fds(fds: &mut [PollFd], timeout: i32) -> io::Result<usize> {
    loop {
        match poll_once(fds, timeout) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignored_and_invalid_snapshots_do_not_require_live_fd_borrows() {
        assert_eq!(std::mem::size_of::<PollFd>(), 8);
        assert_eq!(std::mem::align_of::<PollFd>(), 4);
        let mut fds = [
            PollFd {
                fd: -1,
                events: POLLIN,
                revents: 0,
            },
            PollFd {
                fd: i32::MAX,
                events: POLLIN,
                revents: 0,
            },
        ];
        assert_eq!(poll_once(&mut fds, 0).unwrap(), 1);
        assert_eq!(fds[0].revents, 0);
        assert_eq!(fds[1].revents, rustix::event::PollFlags::NVAL.bits() as i16);
    }
}
