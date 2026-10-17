//! Shared socket ABI declarations, temporarily exposed to the existing unsafe
//! callers. The next migration replaces those callers with safe platform APIs.
//! OpenWrt 25.12.5 AArch64 musl: sys/socket.h, sys/uio.h and bits/alltypes.h.

#![cfg_attr(target_os = "linux", deny(warnings))]

use std::ffi::{c_int, c_uint, c_void};

pub type SockLen = c_uint;

#[repr(C)]
pub struct SockAddr {
    #[cfg(target_os = "macos")]
    pub len: u8,
    #[cfg(target_os = "macos")]
    pub family: u8,
    #[cfg(not(target_os = "macos"))]
    pub family: u16,
    pub data: [u8; 14],
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[repr(C)]
pub struct IoVec {
    pub base: *mut u8,
    pub len: usize,
}

/// Linux LP64 message storage. This preserves the original callers' layout.
/// musl uses a 32-bit iovlen/controllen plus a padding word; these callers use
/// one iovec and at most 40 control bytes, so the upper words stay zero. The
/// same storage also matches glibc's size_t fields. Never pass counts above
/// i32::MAX to the musl boundary.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[repr(C)]
pub struct MsgHdr {
    pub name: *mut u8,
    pub namelen: SockLen,
    pub iov: *mut IoVec,
    pub iovlen: usize,
    pub control: *mut u8,
    pub controllen: usize,
    pub flags: c_int,
}

unsafe extern "C" {
    pub fn bind(fd: c_int, address: *const SockAddr, length: SockLen) -> c_int;
    pub fn connect(fd: c_int, address: *const SockAddr, length: SockLen) -> c_int;
    #[cfg(target_os = "linux")]
    pub fn getsockname(fd: c_int, address: *mut SockAddr, length: *mut SockLen) -> c_int;
    pub fn setsockopt(
        fd: c_int,
        level: c_int,
        option: c_int,
        value: *const c_void,
        length: SockLen,
    ) -> c_int;
    #[cfg(target_os = "linux")]
    pub fn getsockopt(
        fd: c_int,
        level: c_int,
        option: c_int,
        value: *mut c_void,
        length: *mut SockLen,
    ) -> c_int;
    #[cfg(target_os = "linux")]
    pub fn sendto(
        fd: c_int,
        bytes: *const c_void,
        length: usize,
        flags: c_int,
        address: *const SockAddr,
        address_length: SockLen,
    ) -> isize;
    #[cfg(target_os = "linux")]
    pub fn recvfrom(
        fd: c_int,
        bytes: *mut c_void,
        length: usize,
        flags: c_int,
        address: *mut SockAddr,
        address_length: *mut SockLen,
    ) -> isize;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn sendmsg(fd: c_int, message: *const MsgHdr, flags: c_int) -> isize;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn recvmsg(fd: c_int, message: *mut MsgHdr, flags: c_int) -> isize;
}

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn message_storage_matches_verified_sdk_lp64_layout() {
        assert_eq!(size_of::<SockLen>(), 4);
        assert_eq!((size_of::<IoVec>(), align_of::<IoVec>()), (16, 8));
        assert_eq!(offset_of!(IoVec, len), 8);
        assert_eq!((size_of::<MsgHdr>(), align_of::<MsgHdr>()), (56, 8));
        assert_eq!(
            [
                offset_of!(MsgHdr, name),
                offset_of!(MsgHdr, namelen),
                offset_of!(MsgHdr, iov),
                offset_of!(MsgHdr, iovlen),
                offset_of!(MsgHdr, control),
                offset_of!(MsgHdr, controllen),
                offset_of!(MsgHdr, flags)
            ],
            [0, 8, 16, 24, 32, 40, 48]
        );
    }
}
