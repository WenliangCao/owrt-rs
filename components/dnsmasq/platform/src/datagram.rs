//! Bounded message I/O for the pktinfo ABI not exposed by rustix 1.1.5.
//! Packet policy, ancillary encoding/decoding and retry decisions stay outside.

use std::io;
use std::os::fd::{AsFd, AsRawFd};

/// Linux LP64 sockaddr and cmsghdr storage with explicit alignment.
#[repr(C, align(8))]
#[derive(Debug)]
pub struct AlignedBytes<const N: usize>(pub [u8; N]);

#[derive(Debug)]
pub struct Received {
    pub len: usize,
    pub address_len: u32,
    pub control_len: usize,
    pub flags: i32,
}

pub fn receive(
    fd: impl AsFd,
    packet: &mut [u8],
    address: &mut AlignedBytes<32>,
    control: &mut AlignedBytes<40>,
) -> io::Result<Received> {
    let mut vector = super::IoVec {
        base: packet.as_mut_ptr(),
        len: packet.len(),
    };
    let mut message = super::MsgHdr {
        name: address.0.as_mut_ptr(),
        namelen: address.0.len() as u32,
        iov: &mut vector,
        iovlen: 1,
        control: control.0.as_mut_ptr(),
        controllen: control.0.len(),
        flags: 0,
    };
    // SAFETY: every field points into distinct initialized storage borrowed
    // for this call. Capacities bound kernel writes; no pointer is retained.
    // One iovec and 40 control bytes fit both musl and glibc LP64 count fields.
    let len = unsafe { super::recvmsg(fd.as_fd().as_raw_fd(), &mut message, 0) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Received {
        len: len as usize,
        address_len: message.namelen.min(address.0.len() as u32),
        control_len: message.controllen.min(control.0.len()),
        flags: message.flags,
    })
}

pub fn send(
    fd: impl AsFd,
    packet: &[u8],
    address: &AlignedBytes<32>,
    address_len: u32,
    control: &AlignedBytes<40>,
    control_len: usize,
) -> io::Result<usize> {
    if address_len as usize > address.0.len() || control_len > control.0.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut vector = super::IoVec {
        base: packet.as_ptr().cast_mut(),
        len: packet.len(),
    };
    let message = super::MsgHdr {
        name: address.0.as_ptr().cast_mut(),
        namelen: address_len,
        iov: &mut vector,
        iovlen: 1,
        control: if control_len == 0 {
            std::ptr::null_mut()
        } else {
            control.0.as_ptr().cast_mut()
        },
        controllen: control_len,
        flags: 0,
    };
    // SAFETY: sendmsg only reads these live initialized buffers despite the
    // mutable pointer types in POSIX iovec/msghdr. All lengths are bounded and
    // the descriptor is borrowed; a call performs exactly one send attempt.
    let len = unsafe { super::sendmsg(fd.as_fd().as_raw_fd(), &message, 0) };
    if len < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(len as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_and_control_storage_are_exact_and_aligned() {
        assert_eq!(std::mem::size_of::<AlignedBytes<32>>(), 32);
        assert_eq!(std::mem::size_of::<AlignedBytes<40>>(), 40);
        assert_eq!(std::mem::align_of::<AlignedBytes<40>>(), 8);
    }
}
