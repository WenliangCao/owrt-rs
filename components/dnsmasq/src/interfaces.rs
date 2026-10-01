//! IPv4 interface snapshots for DHCP context selection. No network mutation.

use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Interface {
    pub index: u32,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub loopback: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsInterface {
    pub index: u32,
    pub name: Vec<u8>,
    pub address: IpAddr,
    pub netmask: IpAddr,
    pub loopback: bool,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use linux::{dns_interfaces, ipv4_interfaces, primary_ipv4};

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod linux {
    use super::{DnsInterface, Ipv4Interface};
    use std::ffi::CStr;
    use std::ffi::{c_char, c_void};
    use std::io;
    use std::net::Ipv4Addr;
    use std::net::UdpSocket;
    use std::net::{IpAddr, Ipv6Addr};
    use std::os::fd::AsRawFd;
    const AF_INET: i32 = 2;
    extern "C" {
        fn getifaddrs(addresses: *mut *mut IfAddrs) -> i32;
        fn freeifaddrs(addresses: *mut IfAddrs);
        fn if_nametoindex(name: *const c_char) -> u32;
        fn if_indextoname(index: u32, name: *mut c_char) -> *mut c_char;
        fn ioctl(fd: i32, request: usize, argument: *mut u8) -> i32;
    }

    /// Return SIOCGIFADDR's primary address, not whichever alias received the
    /// datagram. The caller can retain one control socket for every request.
    pub fn primary_ipv4(index: u32, control: &UdpSocket) -> io::Result<Ipv4Addr> {
        let mut request = [0u64; 5];
        // SAFETY: Linux 64-bit ifreq is 40 bytes with an aligned union. Its
        // first 16 bytes are ifr_name; if_indextoname writes at most IFNAMSIZ.
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(request.as_mut_ptr().cast::<u8>(), 40) };
        if unsafe { if_indextoname(index, bytes.as_mut_ptr().cast()) }.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: SIOCGIFADDR writes sockaddr_in at byte 16 of the live ifreq.
        // The UdpSocket owns the descriptor for the entire call.
        if unsafe { ioctl(control.as_raw_fd(), 0x8915, bytes.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ioctl initialized a socket address in the ifreq union.
        unsafe { interface_ipv4(bytes.as_ptr().add(16)) }
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IPv4 interface address"))
    }
    // Linux 64-bit libc ABI, also checked against native and target SDK headers by
    // tools/dnsmasq/net_abi.c. Each address pointer belongs to the getifaddrs list.
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

    /// Snapshot active IPv4 interface addresses. No socket or network state is
    /// changed. Aliases remain distinct, as required by DHCP context selection.
    pub fn ipv4_interfaces() -> io::Result<Vec<Ipv4Interface>> {
        struct Addresses(*mut IfAddrs);
        impl Drop for Addresses {
            fn drop(&mut self) {
                // SAFETY: this is precisely the list returned by getifaddrs; no
                // pointer into it escapes the function and it is freed once.
                unsafe { freeifaddrs(self.0) };
            }
        }
        let mut head = std::ptr::null_mut();
        // SAFETY: head is writable pointer storage; libc initializes it on success.
        if unsafe { getifaddrs(&mut head) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let _addresses = Addresses(head);
        let mut current = head;
        let mut result = Vec::new();
        while !current.is_null() {
            // SAFETY: all nodes and their socket addresses are owned by the live
            // getifaddrs list. A family of AF_INET guarantees sockaddr_in's length.
            let entry = unsafe { &*current };
            current = entry.next;
            if entry.flags & 1 == 0 || entry.name.is_null() {
                continue;
            }
            let address = unsafe { interface_ipv4(entry.address) };
            let netmask = unsafe { interface_ipv4(entry.netmask) };
            let (Some(address), Some(netmask)) = (address, netmask) else {
                continue;
            };
            // SAFETY: ifa_name is NUL terminated and lives until freeifaddrs.
            let index = unsafe { if_nametoindex(entry.name) };
            if index == 0 {
                continue;
            }
            let broadcast = if entry.flags & 2 != 0 {
                // SAFETY: IFF_BROADCAST selects the broadcast arm of ifa_ifu.
                unsafe { interface_ipv4(entry.broadcast) }.unwrap_or(Ipv4Addr::UNSPECIFIED)
            } else {
                Ipv4Addr::UNSPECIFIED
            };
            result.push(Ipv4Interface {
                index,
                address,
                netmask,
                broadcast,
                loopback: entry.flags & 8 != 0,
            });
        }
        Ok(result)
    }

    pub fn dns_interfaces() -> io::Result<Vec<DnsInterface>> {
        let mut head = std::ptr::null_mut();
        // SAFETY: initialized output pointer; free exactly once after copying.
        if unsafe { getifaddrs(&mut head) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut current = head;
        let mut result = Vec::new();
        while !current.is_null() {
            // SAFETY: this node belongs to the live getifaddrs list.
            let entry = unsafe { &*current };
            current = entry.next;
            if entry.flags & 1 == 0 || entry.name.is_null() {
                continue;
            }
            let address = unsafe { interface_ip(entry.address) };
            let netmask = unsafe { interface_ip(entry.netmask) };
            if let (Some(address), Some(netmask)) = (address, netmask) {
                // SAFETY: ifa_name is NUL-terminated storage owned by the list.
                let index = unsafe { if_nametoindex(entry.name) };
                if index != 0 {
                    result.push(DnsInterface {
                        index,
                        name: unsafe { CStr::from_ptr(entry.name) }.to_bytes().to_vec(),
                        address,
                        netmask,
                        loopback: entry.flags & 8 != 0,
                    });
                }
            }
        }
        // SAFETY: all data has been copied and no pointer escapes.
        unsafe { freeifaddrs(head) };
        Ok(result)
    }

    unsafe fn interface_ip(pointer: *const u8) -> Option<IpAddr> {
        if pointer.is_null() {
            return None;
        }
        // SAFETY: family is present in every sockaddr, and selects its layout.
        unsafe {
            match std::ptr::read_unaligned(pointer.cast::<u16>()) {
                2 => interface_ipv4(pointer).map(IpAddr::V4),
                10 => Some(IpAddr::V6(Ipv6Addr::from(std::ptr::read_unaligned(
                    pointer.add(8).cast::<[u8; 16]>(),
                )))),
                _ => None,
            }
        }
    }

    /// `pointer` is null or points into the caller's live getifaddrs list.
    unsafe fn interface_ipv4(pointer: *const u8) -> Option<Ipv4Addr> {
        if pointer.is_null() {
            return None;
        }
        // SAFETY: a non-null list address always contains sa_family_t; AF_INET
        // selects a sockaddr_in with its four network-order address bytes at 4.
        unsafe {
            if std::ptr::read_unaligned(pointer.cast::<u16>()) != AF_INET as u16 {
                return None;
            }
            Some(Ipv4Addr::from(std::ptr::read_unaligned(
                pointer.add(4).cast::<[u8; 4]>(),
            )))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[ignore = "requires a private Linux network namespace"]
        fn isolated_loopback_snapshot_matches_kernel_configuration() {
            assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
            let snapshot = ipv4_interfaces().unwrap();
            assert_eq!(snapshot.len(), 1);
            let interface = snapshot[0];
            assert_eq!(interface.address, Ipv4Addr::LOCALHOST);
            assert_eq!(interface.netmask, Ipv4Addr::new(255, 0, 0, 0));
            assert!(interface.loopback);
            assert_ne!(interface.index, 0);
            let control = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
            assert_eq!(
                primary_ipv4(interface.index, &control).unwrap(),
                interface.address
            );
            assert!(primary_ipv4(u32::MAX, &control).is_err());
        }
    }
}
