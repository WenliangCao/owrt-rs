//! Small, private implementation boundary for Unix contracts not represented
//! by rustix. Raw ABI declarations stay private; fork entry points expose the
//! process-wide safety requirements their callers must establish.
//! Reference: OpenWrt 25.12.5 AArch64 musl SDK headers and exact runtime behavior.

#![cfg_attr(target_os = "linux", deny(warnings))]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod datagram;
pub mod interfaces;
pub mod libc_format;
pub mod limits;
pub mod poll;
#[cfg(target_os = "linux")]
pub mod process;
pub mod resolver;
pub mod signals;
#[cfg(target_os = "linux")]
pub mod socket_options;

#[cfg(target_os = "linux")]
use std::ffi::{c_int, c_uint, c_void};

#[cfg(target_os = "linux")]
type SockLen = c_uint;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[repr(C)]
struct IoVec {
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
struct MsgHdr {
    pub name: *mut u8,
    pub namelen: SockLen,
    pub iov: *mut IoVec,
    pub iovlen: usize,
    pub control: *mut u8,
    pub controllen: usize,
    pub flags: c_int,
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn setsockopt(
        fd: c_int,
        level: c_int,
        option: c_int,
        value: *const c_void,
        length: SockLen,
    ) -> c_int;
    fn getsockopt(
        fd: c_int,
        level: c_int,
        option: c_int,
        value: *mut c_void,
        length: *mut SockLen,
    ) -> c_int;
    #[cfg(target_pointer_width = "64")]
    fn sendmsg(fd: c_int, message: *const MsgHdr, flags: c_int) -> isize;
    #[cfg(target_pointer_width = "64")]
    fn recvmsg(fd: c_int, message: *mut MsgHdr, flags: c_int) -> isize;
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

#[cfg(all(
    target_os = "linux",
    target_env = "musl",
    target_pointer_width = "64",
    target_feature = "crt-static"
))]
pub mod startup_relro;
