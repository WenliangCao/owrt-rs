//! Hand-written Linux FFI for the iwinfo port (same style as owrt_ubus::sys):
//! raw sockets (netlink, unix datagram, AF_INET ioctl socket), select(2),
//! ioctl(2) and the few process calls the C code makes. 64-bit Linux
//! layouts (aarch64 glibc/musl).

use std::io;
use std::os::fd::RawFd;

pub const AF_UNIX: i32 = 1;
pub const AF_INET: i32 = 2;
pub const AF_NETLINK: i32 = 16;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;
pub const NETLINK_GENERIC: i32 = 16;
pub const SOL_NETLINK: i32 = 270;
pub const NETLINK_ADD_MEMBERSHIP: i32 = 1;

pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const FD_CLOEXEC: i32 = 1;

pub const SIOCGIFFLAGS: u64 = 0x8913;
pub const SIOCSIFFLAGS: u64 = 0x8914;
pub const SIOCSIFHWADDR: u64 = 0x8924;
pub const SIOCGIFHWADDR: u64 = 0x8927;
pub const IFF_UP: i16 = 0x1;
pub const IFF_RUNNING: i16 = 0x40;
pub const IFNAMSIZ: usize = 16;

pub const SIGHUP: i32 = 1;

pub const ENOENT: i32 = 2;
pub const ENOMEM: i32 = 12;
pub const EINVAL: i32 = 22;
pub const ENOLINK: i32 = 67;

/// struct sockaddr_nl
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrNl {
    pub family: u16,
    pub pad: u16,
    pub pid: u32,
    pub groups: u32,
}

/// struct sockaddr_un
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrUn {
    pub family: u16,
    pub path: [u8; 108],
}

impl SockaddrUn {
    pub fn zeroed() -> SockaddrUn {
        SockaddrUn { family: 0, path: [0; 108] }
    }

    /// `sizeof(sun_family) + sprintf(sun_path, ...)`: copies `path` (truncated
    /// to the array like sprintf would overflow — the C paths are short) and
    /// returns the address length the C code passes to connect/bind.
    pub fn set_path(&mut self, path: &[u8]) -> u32 {
        let n = path.len().min(self.path.len() - 1);
        self.path[..n].copy_from_slice(&path[..n]);
        self.path[n] = 0;
        (2 + n) as u32
    }
}

/// struct ifreq: ifr_name followed by the 24-byte union; `ifr_flags` is the
/// short at union offset 0, `ifr_hwaddr.sa_data` starts at union offset 2.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ifreq {
    pub name: [u8; IFNAMSIZ],
    pub data: [u8; 24],
}

impl Ifreq {
    /// `strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1)` on a zeroed struct.
    pub fn new(ifname: &str) -> Ifreq {
        let mut r = Ifreq { name: [0; IFNAMSIZ], data: [0; 24] };
        let b = ifname.as_bytes();
        let n = b.len().min(IFNAMSIZ - 1);
        r.name[..n].copy_from_slice(&b[..n]);
        r
    }

    pub fn flags(&self) -> i16 {
        i16::from_ne_bytes([self.data[0], self.data[1]])
    }

    pub fn set_flags(&mut self, f: i16) {
        self.data[..2].copy_from_slice(&f.to_ne_bytes());
    }
}

/// struct timeval (64-bit)
#[repr(C)]
pub struct Timeval {
    pub sec: i64,
    pub usec: i64,
}

/// fd_set (1024 bits)
#[repr(C)]
pub struct FdSet {
    pub bits: [u64; 16],
}

impl FdSet {
    pub fn zero() -> FdSet {
        FdSet { bits: [0; 16] }
    }

    pub fn set(&mut self, fd: RawFd) {
        if fd >= 0 && (fd as usize) < 1024 {
            self.bits[fd as usize / 64] |= 1u64 << (fd as usize % 64);
        }
    }

    pub fn is_set(&self, fd: RawFd) -> bool {
        fd >= 0 && (fd as usize) < 1024 && self.bits[fd as usize / 64] & (1u64 << (fd as usize % 64)) != 0
    }
}

extern "C" {
    pub fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    // Declared with the sockaddr_nl pointee (as rtnl.rs declares it, so the
    // two extern declarations agree); the unix-socket caller casts.
    pub fn bind(fd: i32, addr: *const SockaddrNl, len: u32) -> i32;
    pub fn connect(fd: i32, addr: *const u8, len: u32) -> i32;
    pub fn send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
    pub fn sendto(fd: i32, buf: *const u8, len: usize, flags: i32, addr: *const u8, alen: u32) -> isize;
    pub fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    pub fn setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32;
    pub fn close(fd: i32) -> i32;
    pub fn ioctl(fd: i32, req: u64, arg: *mut u8) -> i32;
    pub fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    pub fn fchmod(fd: i32, mode: u32) -> i32;
    pub fn lchown(path: *const u8, uid: u32, gid: u32) -> i32;
    pub fn getpid() -> i32;
    pub fn kill(pid: i32, sig: i32) -> i32;
    pub fn select(nfds: i32, r: *mut FdSet, w: *mut FdSet, e: *mut FdSet, tv: *mut Timeval) -> i32;
    pub fn if_nametoindex(name: *const u8) -> u32;
}

/// errno of the last failed call, as a positive number (0 if unknown).
pub fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC)`
pub fn set_cloexec(fd: RawFd) -> i32 {
    // SAFETY: plain fcntl on our own descriptor.
    unsafe { fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC) }
}

/// A NUL-terminated copy of `s` for the few C calls that take a path.
pub fn cpath(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    v.push(0);
    v
}
