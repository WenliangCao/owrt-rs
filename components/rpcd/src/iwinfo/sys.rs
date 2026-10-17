//! Fixed iwinfo constants and owned ifreq bytes; syscalls use rustix or the
//! shared platform boundary. No foreign pointers enter the business layer.


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

/// A NUL-terminated copy of `s` for the few C calls that take a path.
pub fn cpath(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    v.push(0);
    v
}
