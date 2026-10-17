//! One bounded Unix-stream send/receive with libubus's exact one-FD ancillary
//! capacity. Numeric sockets are existing event-loop snapshots, not new owners;
//! rustix's AsFd interface cannot represent invalid/stale slots without inventing
//! a borrow. Retry, deadlines, framing and backpressure stay in the ubus crates.
use std::io::{self, IoSlice};
use std::os::fd::{FromRawFd, OwnedFd};

#[repr(C)]
struct IoVec { base: *mut u8, len: usize }
#[repr(C)]
struct MsgHdr {
    name: *mut u8, namelen: u32, iov: *mut IoVec, iovlen: usize,
    control: *mut u8, controllen: usize, flags: i32,
}
#[repr(align(8))]
struct Control([u8; 24]);
unsafe extern "C" {
    fn sendmsg(fd: i32, message: *const MsgHdr, flags: i32) -> isize;
    fn recvmsg(fd: i32, message: *mut MsgHdr, flags: i32) -> isize;
}

pub fn send_slices(fd: i32, slices: &[IoSlice<'_>], passed_fd: Option<i32>, nonblocking: bool) -> io::Result<usize> {
    if slices.len() > i32::MAX as usize { return Err(io::ErrorKind::InvalidInput.into()); }
    let mut control = Control([0; 24]);
    let mut message = MsgHdr {
        name: std::ptr::null_mut(), namelen: 0,
        iov: slices.as_ptr().cast_mut().cast(), iovlen: slices.len(),
        control: std::ptr::null_mut(), controllen: 0, flags: 0,
    };
    if let Some(passed) = passed_fd {
        control.0[..8].copy_from_slice(&20u64.to_ne_bytes());
        control.0[8..12].copy_from_slice(&1i32.to_ne_bytes()); // SOL_SOCKET
        control.0[12..16].copy_from_slice(&1i32.to_ne_bytes()); // SCM_RIGHTS
        control.0[16..20].copy_from_slice(&passed.to_ne_bytes());
        message.control = control.0.as_mut_ptr();
        message.controllen = 20; // CMSG_LEN(int), not SPACE: retain one-FD contract.
    }
    // SAFETY: Unix IoSlice is ABI-compatible with iovec and owns each payload
    // borrow. sendmsg only reads these vectors/bytes. The aligned control and
    // message outlive the call, counts fit target musl's 32-bit fields (upper
    // padding zero); no numeric FD is adopted or assumed valid.
    let n = unsafe { sendmsg(fd, &message, if nonblocking { 0x40 } else { 0 }) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

pub fn recv_into(fd: i32, bytes: &mut [u8], want_fd: bool, nonblocking: bool) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut vector = IoVec { base: bytes.as_mut_ptr(), len: bytes.len() };
    let mut control = Control([0; 24]);
    let mut message = MsgHdr {
        name: std::ptr::null_mut(), namelen: 0, iov: &mut vector, iovlen: 1,
        control: if want_fd { control.0.as_mut_ptr() } else { std::ptr::null_mut() },
        controllen: if want_fd { 20 } else { 0 }, flags: 0,
    };
    // SAFETY: exclusive initialized payload/control storage is bounded by the
    // supplied lengths. Linux closes SCM_RIGHTS exceeding this one-int capacity;
    // without control space every received FD is discarded by the kernel.
    let n = unsafe { recvmsg(fd, &mut message, if nonblocking { 0x40 } else { 0 }) };
    if n < 0 { return Err(io::Error::last_os_error()); }
    let received = if want_fd && message.controllen >= 20
        && i32::from_ne_bytes(control.0[8..12].try_into().unwrap()) == 1
        && i32::from_ne_bytes(control.0[12..16].try_into().unwrap()) == 1 {
        let raw = i32::from_ne_bytes(control.0[16..20].try_into().unwrap());
        if raw >= 0 {
            // SAFETY: only a successful kernel SCM_RIGHTS receive can supply
            // this fresh descriptor. One owner is created; no raw-adopt API.
            Some(unsafe { OwnedFd::from_raw_fd(raw) })
        } else { None }
    } else { None };
    Ok((n as usize, received))
}

#[cfg(test)]
mod tests {
    use super::recv_into;
    use rustix::io::{read, write, Errno};
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use rustix::pipe::{pipe_with, PipeFlags};
    use std::io::IoSlice;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;

    #[test]
    fn two_rights_keep_first_and_close_truncated_descriptor() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let flags = PipeFlags::CLOEXEC | PipeFlags::NONBLOCK;
        let (first_reader, first_writer) = pipe_with(flags).unwrap();
        let (second_reader, second_writer) = pipe_with(flags).unwrap();
        {
            let rights = [first_writer.as_fd(), second_writer.as_fd()];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
            assert_eq!(
                sendmsg(
                    &sender,
                    &[IoSlice::new(b"x")],
                    &mut ancillary,
                    SendFlags::DONTWAIT,
                )
                .unwrap(),
                1
            );
        }
        drop(first_writer);
        drop(second_writer);

        // Only the queued SCM_RIGHTS references now keep these pipes open.
        let mut byte = [0];
        assert_eq!(read(&first_reader, &mut byte), Err(Errno::AGAIN));
        assert_eq!(read(&second_reader, &mut byte), Err(Errno::AGAIN));

        let (count, received) = recv_into(receiver.as_raw_fd(), &mut byte, true, true).unwrap();
        assert_eq!(count, 1);
        assert_eq!(byte, *b"x");
        let received = received.expect("the first descriptor fits the 20-byte control area");
        // A leaked second descriptor would leave this read at EAGAIN, not EOF.
        assert_eq!(read(&second_reader, &mut byte).unwrap(), 0);
        assert_eq!(read(&first_reader, &mut byte), Err(Errno::AGAIN));
        assert_eq!(write(&received, b"y").unwrap(), 1);
        assert_eq!(read(&first_reader, &mut byte).unwrap(), 1);
        assert_eq!(byte, *b"y");

        // The returned OwnedFd holds the first pipe's final writer reference.
        drop(received);
        assert_eq!(read(&first_reader, &mut byte).unwrap(), 0);
    }
}
