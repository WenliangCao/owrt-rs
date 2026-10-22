//! Interface operations not covered by rustix's byte-preserving APIs.
//! Names remain Unix bytes; no raw descriptor or list pointer escapes.

#[cfg(unix)]
use std::ffi::{c_char, CStr, CString};
#[cfg(unix)]
use std::io;

#[cfg(unix)]
unsafe extern "C" {
    fn if_nametoindex(name: *const c_char) -> u32;
    fn if_indextoname(index: u32, name: *mut c_char) -> *mut c_char;
}

/// Preserve libc's zero result for unknown or invalid names, including its
/// support for non-UTF-8 interface names.
#[cfg(unix)]
pub fn interface_index(name: &[u8]) -> u32 {
    CString::new(name).map_or(0, |name| name_index(&name))
}

#[cfg(unix)]
fn name_index(name: &CStr) -> u32 {
    // SAFETY: CStr supplies live terminated storage throughout the call.
    unsafe { if_nametoindex(name.as_ptr()) }
}

/// Lookup for callers which do not already own a control socket. Packet paths
/// use interface_name with their retained socket instead.
#[cfg(unix)]
pub fn index_to_name(index: u32) -> io::Result<[u8; 16]> {
    let mut name = [0u8; 16];
    // SAFETY: Linux and Darwin IF_NAMESIZE are 16. The writable array lives
    // through the call, which either fails or writes a terminated name.
    if unsafe { if_indextoname(index, name.as_mut_ptr().cast()) }.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(name)
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod linux {
    use super::{name_index, CStr};
    use rustix::fd::AsFd;
    use rustix::ioctl::{ioctl, Opcode, Updater};
    use std::ffi::{c_char, c_void};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // The exact AArch64 musl and Linux LP64 ABI, checked by net_abi.c.
    #[repr(C, align(8))]
    struct IfReq {
        name: [u8; 16],
        data: [u8; 24],
    }

    fn query<const OP: Opcode>(fd: impl AsFd, request: &mut IfReq) -> io::Result<()> {
        // SAFETY: the only callers below use SIOCGIFNAME/SIOCGIFFLAGS/
        // SIOCGIFADDR/SIOCGIFMTU with their fully initialized, aligned Linux LP64 ifreq.
        unsafe { ioctl(fd, Updater::<OP, IfReq>::new(request)) }.map_err(Into::into)
    }

    pub fn interface_name(fd: impl AsFd, index: u32) -> io::Result<[u8; 16]> {
        let mut request = IfReq {
            name: [0; 16],
            data: [0; 24],
        };
        request.data[..4].copy_from_slice(&index.to_ne_bytes());
        query::<0x8910>(fd, &mut request)?;
        Ok(request.name)
    }

    pub fn interface_flags(fd: impl AsFd, name: &[u8; 16]) -> io::Result<u16> {
        let mut request = IfReq {
            name: *name,
            data: [0; 24],
        };
        query::<0x8913>(fd, &mut request)?;
        Ok(u16::from_ne_bytes(request.data[..2].try_into().unwrap()))
    }

    pub fn interface_ipv4(fd: impl AsFd, name: &[u8]) -> io::Result<Ipv4Addr> {
        if name.len() >= 16 || name.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }
        let mut request = IfReq {
            name: [0; 16],
            data: [0; 24],
        };
        request.name[..name.len()].copy_from_slice(name);
        query::<0x8915>(fd, &mut request)?;
        if u16::from_ne_bytes(request.data[..2].try_into().unwrap()) != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-IPv4 interface address",
            ));
        }
        Ok(Ipv4Addr::from(
            <[u8; 4]>::try_from(&request.data[4..8]).unwrap(),
        ))
    }

    pub fn interface_mtu(fd: impl AsFd, name: &[u8]) -> io::Result<u32> {
        if name.is_empty() || name.len() >= 16 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut request = IfReq {
            name: [0; 16],
            data: [0; 24],
        };
        request.name[..name.len()].copy_from_slice(name);
        query::<0x8921>(fd, &mut request)?;
        u32::try_from(i32::from_ne_bytes(request.data[..4].try_into().unwrap()))
            .map_err(|_| io::ErrorKind::InvalidData.into())
    }

    /// SIOCSARP copies this exact 68-byte Linux arpreq from user storage.
    /// The kernel validates its address and device fields; no pointer escapes.
    pub fn set_arp(fd: impl AsFd, request: &mut [u8; 68]) -> io::Result<()> {
        // SAFETY: SIOCSARP reads the bounded arpreq bytes. No internal pointer
        // fields exist, and the kernel never reads beyond these 68 bytes.
        unsafe { ioctl(fd, Updater::<0x8955, [u8; 68]>::new(request)) }.map_err(Into::into)
    }

    #[repr(C)]
    struct IfAddrs {
        next: *mut IfAddrs,
        name: *mut c_char,
        flags: u32,
        address: *const u8,
        netmask: *const u8,
        broadcast: *const u8,
        data: *mut c_void,
    }

    unsafe extern "C" {
        fn getifaddrs(addresses: *mut *mut IfAddrs) -> i32;
        fn freeifaddrs(addresses: *mut IfAddrs);
    }

    /// A borrowed row; visit's lifetime prevents names from escaping the list.
    #[derive(Debug)]
    pub struct InterfaceAddress<'a> {
        pub name: &'a CStr,
        pub flags: u32,
        pub address: IpAddr,
        pub netmask: IpAddr,
    }

    impl InterfaceAddress<'_> {
        pub fn index(&self) -> u32 {
            name_index(self.name)
        }
    }

    pub struct InterfaceAddresses(*mut IfAddrs);

    impl InterfaceAddresses {
        pub fn new() -> io::Result<Self> {
            let mut head = std::ptr::null_mut();
            // SAFETY: writable pointer storage; success transfers the list to
            // this one RAII owner, which frees it exactly once.
            if unsafe { getifaddrs(&mut head) } < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(head))
            }
        }

        pub fn visit(&self, mut visitor: impl FnMut(InterfaceAddress<'_>)) {
            let mut current = self.0;
            while !current.is_null() {
                // SAFETY: every node and address belongs to the live libc
                // list. No pointer is mutable or exposed to the visitor.
                let row = unsafe { &*current };
                current = row.next;
                if row.name.is_null() {
                    continue;
                }
                // SAFETY: null or sockaddr storage owned by the list; the
                // decoder checks the family before accessing its layout.
                let (Some(address), Some(netmask)) = (unsafe { decode_ip(row.address) }, unsafe {
                    decode_ip(row.netmask)
                }) else {
                    continue;
                };
                visitor(InterfaceAddress {
                    // SAFETY: non-null ifa_name is a libc-owned C string.
                    name: unsafe { CStr::from_ptr(row.name) },
                    flags: row.flags,
                    address,
                    netmask,
                });
            }
        }
    }

    impl Drop for InterfaceAddresses {
        fn drop(&mut self) {
            // SAFETY: this is precisely the list returned by getifaddrs.
            unsafe { freeifaddrs(self.0) };
        }
    }

    unsafe fn decode_ip(pointer: *const u8) -> Option<IpAddr> {
        if pointer.is_null() {
            return None;
        }
        // SAFETY: the caller supplies a list-owned sockaddr. The family field
        // selects the ABI and therefore the readable address width/offset.
        unsafe {
            match std::ptr::read_unaligned(pointer.cast::<u16>()) {
                2 => Some(IpAddr::V4(Ipv4Addr::from(std::ptr::read_unaligned(
                    pointer.add(4).cast::<[u8; 4]>(),
                )))),
                10 => Some(IpAddr::V6(Ipv6Addr::from(std::ptr::read_unaligned(
                    pointer.add(8).cast::<[u8; 16]>(),
                )))),
                _ => None,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ifreq_matches_verified_sdk_lp64_layout() {
            assert_eq!(std::mem::size_of::<IfReq>(), 40);
            assert_eq!(std::mem::align_of::<IfReq>(), 8);
            assert_eq!(std::mem::offset_of!(IfReq, data), 16);
        }
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use linux::{
    interface_flags, interface_ipv4, interface_mtu, interface_name, set_arp, InterfaceAddress,
    InterfaceAddresses,
};
