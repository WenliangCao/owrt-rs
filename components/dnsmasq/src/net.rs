//! Linux 64-bit datagram boundary. DNS/DHCP/TFTP policy stays in Rust callers.
//! C reference: network.c:936–1009; forward.c:32–119,1635–1796.
//! Reuses the repository's audited iovec/msghdr layout and readiness backend.

use owrt_ubus::sys::{IoVec, MsgHdr};
use std::io;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const SOCK_DGRAM: i32 = 2;
const SOCK_CLOEXEC: i32 = 0o2000000;
const SOCK_NONBLOCK: i32 = 0o4000;
const IPPROTO_IP: i32 = 0;
const IPPROTO_IPV6: i32 = 41;
const IP_PKTINFO: i32 = 8;
const IP_PKTOPTIONS: i32 = 9;
const IPV6_2292PKTINFO: i32 = 2;
const IPV6_2292PKTOPTIONS: i32 = 6;
const IPV6_V6ONLY: i32 = 26;
const IPV6_RECVPKTINFO: i32 = 49;
const IPV6_PKTINFO: i32 = 50;
const MSG_TRUNC: i32 = 32;
const MSG_CTRUNC: i32 = 8;

extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn bind(fd: i32, address: *const u8, len: u32) -> i32;
    fn setsockopt(fd: i32, level: i32, option: i32, value: *const i32, len: u32) -> i32;
    fn getsockopt(fd: i32, level: i32, option: i32, value: *mut i32, len: *mut u32) -> i32;
    fn if_indextoname(index: u32, name: *mut std::ffi::c_char) -> *mut std::ffi::c_char;
    fn recvmsg(fd: i32, message: *mut MsgHdr, flags: i32) -> isize;
    fn sendmsg(fd: i32, message: *const MsgHdr, flags: i32) -> isize;
    fn sendto(
        fd: i32,
        bytes: *const u8,
        len: usize,
        flags: i32,
        address: *const u8,
        address_len: u32,
    ) -> isize;
    fn recvfrom(
        fd: i32,
        bytes: *mut u8,
        len: usize,
        flags: i32,
        address: *mut u8,
        address_len: *mut u32,
    ) -> isize;
    fn poll(fds: *mut owrt_ubus::sys::PollFd, count: usize, timeout: i32) -> i32;
    fn ioctl(fd: i32, request: usize, argument: *mut u8) -> i32;
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug)]
struct UnsupportedSocket(io::Error);
impl std::fmt::Display for UnsupportedSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}
impl std::error::Error for UnsupportedSocket {}

/// C suppresses these errors only when socket() fails. An identical errno
/// returned by bind()/setsockopt() must still reach the caller's error path.
pub(crate) fn socket_creation_error(error: io::Error) -> io::Error {
    if matches!(error.raw_os_error(), Some(93 | 97 | 22)) {
        io::Error::new(error.kind(), UnsupportedSocket(error))
    } else {
        error
    }
}
pub fn is_unsupported_socket_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<UnsupportedSocket>())
}

// sockaddr_in/sockaddr_in6 use native family/scope, network port/address; bytes
// avoid alignment-dependent struct casts. Storage remains aligned for libc.
struct Address {
    storage: [u64; 4],
    len: u32,
}

impl Address {
    fn new(address: SocketAddr) -> Self {
        let mut out = Self {
            storage: [0; 4],
            len: if address.is_ipv4() { 16 } else { 28 },
        };
        let bytes = out.bytes_mut();
        bytes[..2].copy_from_slice(
            &(if address.is_ipv4() {
                AF_INET as u16
            } else {
                AF_INET6 as u16
            })
            .to_ne_bytes(),
        );
        bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
        match address {
            SocketAddr::V4(v) => bytes[4..8].copy_from_slice(&v.ip().octets()),
            SocketAddr::V6(v) => {
                bytes[8..24].copy_from_slice(&v.ip().octets());
                bytes[24..28].copy_from_slice(&v.scope_id().to_ne_bytes());
            }
        }
        out
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: u64 storage is fully initialized; bytes cover precisely it.
        unsafe { std::slice::from_raw_parts_mut(self.storage.as_mut_ptr().cast(), 32) }
    }

    fn decode(&mut self, len: u32) -> io::Result<SocketAddr> {
        let b = self.bytes_mut();
        if len < 4 {
            return Err(invalid("short peer address"));
        }
        let port = u16::from_be_bytes([b[2], b[3]]);
        match i32::from(u16::from_ne_bytes([b[0], b[1]])) {
            AF_INET if len >= 16 => Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(b[4], b[5], b[6], b[7])),
                port,
            )),
            AF_INET6 if len >= 28 => {
                let mut address = [0; 16];
                address.copy_from_slice(&b[8..24]);
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(address),
                    port,
                    0,
                    u32::from_ne_bytes([b[24], b[25], b[26], b[27]]),
                )))
            }
            _ => Err(invalid("unexpected peer address family")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Datagram {
    pub len: usize,
    pub peer: SocketAddr,
    /// Address in the IP header (`ipi_addr`); may be broadcast or multicast.
    pub destination: IpAddr,
    /// Local interface address (`ipi_spec_dst`), suitable as a reply source.
    pub local_address: IpAddr,
    pub interface: u32,
}

pub struct DatagramSocket {
    socket: UdpSocket,
    ipv6: bool,
    bound_dns_ipv4: Option<Ipv4Addr>,
}

impl AsRawFd for DatagramSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

fn set_flag(fd: RawFd, level: i32, flag: i32) -> io::Result<()> {
    let value = 1;
    // SAFETY: the socket option takes one live native int; no ownership transfer.
    if unsafe { setsockopt(fd, level, flag, &value, 4) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// C network.c::tcp_interface reads the SYN's ingress through IP_PKTOPTIONS,
/// including the retained RFC-2292 IPv6 ABI. Missing metadata means fallback;
/// the connection's destination does not identify its arrival interface.
pub(crate) fn tcp_interface(stream: &TcpStream, ipv6: bool) -> Option<(Vec<u8>, bool)> {
    let fd = stream.as_raw_fd();
    let (level, option) = if ipv6 {
        if let Err(error) = set_flag(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO) {
            if error.raw_os_error() != Some(92) // ENOPROTOOPT
                || set_flag(fd, IPPROTO_IPV6, IPV6_2292PKTINFO).is_err()
            {
                return None;
            }
        }
        (IPPROTO_IPV6, IPV6_2292PKTOPTIONS)
    } else {
        set_flag(fd, IPPROTO_IP, IP_PKTINFO).ok()?;
        (IPPROTO_IP, IP_PKTOPTIONS)
    };
    // Only pktinfo is enabled on this stream: CMSG_SPACE is 32 or 40 bytes.
    let mut storage = [0u64; 8];
    let mut length = 64;
    // SAFETY: initialized aligned storage is writable for the supplied length.
    let bytes = unsafe { std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), 64) };
    // SAFETY: the live socket and initialized 64-byte output match length;
    // getsockopt updates the live length scalar before its value is checked.
    if unsafe { getsockopt(fd, level, option, bytes.as_mut_ptr().cast(), &mut length) } < 0 {
        return None;
    }
    let (_, _, index) = packet_info(bytes.get(..length as usize)?, ipv6)?;
    if index == 0 {
        return None;
    }
    let mut request = [0u64; 5];
    // SAFETY: Linux 64-bit ifreq is 40 bytes, with a 16-byte interface name.
    let bytes = unsafe { std::slice::from_raw_parts_mut(request.as_mut_ptr().cast::<u8>(), 40) };
    // SAFETY: Linux writes at most IF_NAMESIZE (16) bytes into this 40-byte buffer.
    if unsafe { if_indextoname(index, bytes.as_mut_ptr().cast()) }.is_null() {
        return None;
    }
    let name = bytes[..16]
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .collect();
    // C's loopback_exception is unavailable when SIOCGIFFLAGS fails.
    // SAFETY: the live socket and aligned 40-byte ifreq contain a terminated
    // interface name; SIOCGIFFLAGS writes only within the ifreq union.
    let loopback = unsafe { ioctl(fd, 0x8913, bytes.as_mut_ptr()) } == 0
        && u16::from_ne_bytes([bytes[16], bytes[17]]) & 8 != 0;
    Some((name, loopback))
}

/// Linux raw ICMP socket used only by the DHCP conflict probe. Every success,
/// error and cancellation path closes its descriptor through OwnedFd.
pub struct IcmpSocket(OwnedFd);

impl IcmpSocket {
    /// Borrow the descriptor for the caller's DNS/TFTP/ICMP poll set.
    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    pub fn open() -> io::Result<Self> {
        // SAFETY: no pointers; successful socket returns unique ownership.
        let fd = unsafe { socket(AF_INET, 3 | SOCK_CLOEXEC | SOCK_NONBLOCK, 1) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is fresh and has exactly one owner.
        let socket = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        let zero = 0;
        // SAFETY: SO_DONTROUTE accepts a live native int of the supplied size.
        if unsafe { setsockopt(fd, 1, 5, &zero, 4) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    pub fn send(&self, bytes: &[u8], target: Ipv4Addr) -> io::Result<()> {
        let mut address = Address::new(SocketAddr::from((target, 0)));
        // SAFETY: both initialized byte buffers outlive this call and the
        // lengths match their allocations; sendto retains neither pointer.
        let sent = unsafe {
            sendto(
                self.0.as_raw_fd(),
                bytes.as_ptr(),
                bytes.len(),
                0,
                address.bytes_mut().as_ptr(),
                16,
            )
        };
        if sent < 0 {
            Err(io::Error::last_os_error())
        } else if sent as usize != bytes.len() {
            Err(io::Error::new(io::ErrorKind::WriteZero, "short ICMP send"))
        } else {
            Ok(())
        }
    }

    pub fn receive(&self, bytes: &mut [u8]) -> io::Result<(usize, Ipv4Addr)> {
        let mut address = Address {
            storage: [0; 4],
            len: 32,
        };
        let mut len = 32;
        // SAFETY: output buffers and address length live through recvfrom;
        // their capacities bound kernel writes. No MSG_TRUNC is requested,
        // matching C's fixed-size ICMP receive (longer datagrams truncate).
        let got = unsafe {
            recvfrom(
                self.0.as_raw_fd(),
                bytes.as_mut_ptr(),
                bytes.len(),
                0,
                address.bytes_mut().as_mut_ptr(),
                &mut len,
            )
        };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        let IpAddr::V4(peer) = address.decode(len)?.ip() else {
            return Err(invalid("unexpected ICMP peer family"));
        };
        Ok((got as usize, peer))
    }

    /// One bounded wait. EINTR is returned to the probe so it can check its
    /// stop flag rather than hiding cancellation inside an unbounded retry.
    pub fn wait(&self, timeout: std::time::Duration) -> io::Result<bool> {
        let mut fd = owrt_ubus::sys::PollFd {
            fd: self.0.as_raw_fd(),
            events: 1,
            revents: 0,
        };
        let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: one initialized pollfd remains live throughout the call.
        let ready = unsafe { poll(&mut fd, 1, millis) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if fd.revents & (8 | 16 | 32) != 0 {
            return Err(io::Error::other("ICMP socket readiness failure"));
        }
        Ok(ready != 0)
    }
}

/// Linux `struct arpreq`: two sockaddrs, flags, netmask sockaddr and device
/// name (68 bytes, four-byte alignment). Unused bytes are zero-initialized;
/// C only initializes the fields required for an ATF_COM neighbour entry.
pub struct ArpEntry([u32; 17]);

impl ArpEntry {
    pub fn new(
        address: SocketAddrV4,
        hardware_type: u8,
        hardware: &[u8],
        interface: &[u8],
    ) -> io::Result<Self> {
        if hardware_type == 0
            || hardware.is_empty()
            || hardware.len() > 14
            || interface.is_empty()
            || interface.len() > 15
            || interface.contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DHCP ARP entry",
            ));
        }
        let mut entry = Self([0; 17]);
        let bytes = entry.bytes_mut();
        bytes[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
        bytes[4..8].copy_from_slice(&address.ip().octets());
        bytes[16..18].copy_from_slice(&u16::from(hardware_type).to_ne_bytes());
        bytes[18..18 + hardware.len()].copy_from_slice(hardware);
        bytes[32..36].copy_from_slice(&2i32.to_ne_bytes()); // ATF_COM, not ATF_PERM.
        bytes[52..52 + interface.len()].copy_from_slice(interface);
        Ok(entry)
    }

    pub fn bytes(&self) -> &[u8; 68] {
        // SAFETY: initialized u32 storage occupies exactly 68 bytes and the
        // shared byte view cannot mutate it or outlive this object.
        unsafe { &*self.0.as_ptr().cast::<[u8; 68]>() }
    }

    fn bytes_mut(&mut self) -> &mut [u8; 68] {
        // SAFETY: exclusive borrow of initialized, four-byte-aligned storage.
        unsafe { &mut *self.0.as_mut_ptr().cast::<[u8; 68]>() }
    }
}

/// Install the DHCP client's dynamic neighbour entry on the original ingress
/// interface. Failure is returned to the runtime, which records it and still
/// attempts the UDP send, as dhcp.c does after a failed SIOCSARP.
pub fn inject_arp(
    socket: &DatagramSocket,
    interface: u32,
    address: SocketAddrV4,
    hardware_type: u8,
    hardware: &[u8],
) -> io::Result<()> {
    let name = interface_name(socket, interface)?;
    inject_arp_with_name(socket, address, hardware_type, hardware, &name)
}

/// Capture the ingress name before DHCP state processing, as dhcp.c does
/// before bridge aliasing and ICMP delays. Interface indexes survive rename.
pub fn interface_name(socket: &impl AsRawFd, interface: u32) -> io::Result<[u8; 16]> {
    if interface == 0 || interface > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ARP requires an ingress interface",
        ));
    }
    let mut request = [0u64; 5];
    // SAFETY: Linux ifreq is 40 bytes aligned to eight, with its union at
    // byte 16. The initialized byte view is exclusively borrowed here.
    let bytes = unsafe { std::slice::from_raw_parts_mut(request.as_mut_ptr().cast::<u8>(), 40) };
    bytes[16..20].copy_from_slice(&interface.to_ne_bytes());
    // SAFETY: SIOCGIFNAME reads the index and writes at most 16 name bytes.
    // Reusing the listener fd matches network.c::indextoname and avoids a
    // transient control socket inside libc if_indextoname.
    if unsafe { ioctl(socket.as_raw_fd(), 0x8910, bytes.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut name = [0; 16];
    name.copy_from_slice(&bytes[..16]);
    Ok(name)
}

/// Query only the ingress needed by C's failed-ACL loopback exception.
pub fn interface_loopback(socket: &impl AsRawFd, name: &[u8; 16]) -> io::Result<bool> {
    let mut request = [0u64; 5];
    // SAFETY: Linux 64-bit ifreq is 40 aligned bytes. The borrowed name is
    // initialized IFNAMSIZ storage returned by SIOCGIFNAME, copied in full.
    let bytes = unsafe { std::slice::from_raw_parts_mut(request.as_mut_ptr().cast::<u8>(), 40) };
    bytes[..16].copy_from_slice(name);
    // SAFETY: the receiving socket owns fd for this call; SIOCGIFFLAGS writes
    // its short flags only inside the live initialized ifreq union.
    if unsafe { ioctl(socket.as_raw_fd(), 0x8913, bytes.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u16::from_ne_bytes([bytes[16], bytes[17]]) & 8 != 0)
}

pub(crate) fn inject_arp_with_name(
    socket: &DatagramSocket,
    address: SocketAddrV4,
    hardware_type: u8,
    hardware: &[u8],
    name: &[u8; 16],
) -> io::Result<()> {
    if socket.ipv6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ARP requires an IPv4 socket",
        ));
    }
    let length = name.iter().position(|byte| *byte == 0).unwrap_or(16);
    let mut entry = ArpEntry::new(address, hardware_type, hardware, &name[..length])?;
    // SAFETY: SIOCSARP reads the complete initialized Linux arpreq. The live
    // socket owns fd and the request is aligned and valid throughout ioctl.
    if unsafe { ioctl(socket.as_raw_fd(), 0x8955, entry.bytes_mut().as_mut_ptr()) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl DatagramSocket {
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::bind_options(address, true, false, None)
    }

    /// Static IPv4 DNS listeners use their bound address instead of IP_PKTINFO,
    /// matching network.c's OPT_NOWILD socket and forward.c's !check_dst path.
    /// Only the DNS factory may select this policy; other protocols need ingress.
    pub(crate) fn bind_dns_static_ipv4(address: SocketAddrV4) -> io::Result<Self> {
        if address.ip().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "static DNS socket requires a bound IPv4 address",
            ));
        }
        Self::bind_options(address.into(), true, false, Some(*address.ip()))
    }

    /// Default DHCP listeners are exclusive; C enables reuse only for the
    /// separately gated bind-interfaces/bind-dynamic modes.
    pub fn bind_exclusive(address: SocketAddr) -> io::Result<Self> {
        Self::bind_options(address, false, false, None)
    }

    /// dhcp.c:70-92 enables both reuse flags only for bind-interfaces or
    /// bind-dynamic. Older kernels may lack SO_REUSEPORT (ENOPROTOOPT).
    pub fn bind_dhcp(address: SocketAddr, reuse: bool) -> io::Result<Self> {
        Self::bind_options(address, reuse, reuse, None)
    }

    /// dhcp-common.c bindtodevice passes the terminated name, capped at IFNAMSIZ.
    /// The caller applies C's EPERM policy and retains any runtime retry state.
    pub fn bind_device(&self, device: &[u8]) -> io::Result<()> {
        let name = std::ffi::CString::new(device).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
        })?;
        let bytes = name.as_bytes_with_nul();
        let length = bytes.len().min(16) as u32;
        // SAFETY: SO_BINDTODEVICE reads at most IFNAMSIZ bytes from the live
        // CString; the socket owns its fd and setsockopt retains no pointer.
        if unsafe { setsockopt(self.as_raw_fd(), 1, 25, bytes.as_ptr().cast(), length) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn bind_options(
        address: SocketAddr,
        reuse_address: bool,
        reuse_port: bool,
        bound_dns_ipv4: Option<Ipv4Addr>,
    ) -> io::Result<Self> {
        let ipv6 = address.is_ipv6();
        // SAFETY: socket has no pointers and returns a new descriptor on success.
        let fd = unsafe {
            socket(
                if ipv6 { AF_INET6 } else { AF_INET },
                SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return Err(socket_creation_error(io::Error::last_os_error()));
        }
        // SAFETY: fd is a fresh UDP socket; UdpSocket now owns every close path.
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        if reuse_port {
            if let Err(error) = set_flag(fd, 1, 15) {
                if error.raw_os_error() != Some(92) {
                    return Err(error);
                }
            }
        }
        if reuse_address {
            set_flag(fd, 1, 2)?; // SOL_SOCKET, SO_REUSEADDR (no SO_REUSEPORT).
        }
        if ipv6 {
            set_flag(fd, IPPROTO_IPV6, IPV6_V6ONLY)?;
        }
        let mut raw = Address::new(address);
        let len = raw.len;
        // SAFETY: initialized sockaddr bytes and matching length outlive bind.
        if unsafe { bind(fd, raw.bytes_mut().as_ptr(), len) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if ipv6 {
            set_flag(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO)?;
        } else if bound_dns_ipv4.is_none() {
            set_flag(fd, IPPROTO_IP, IP_PKTINFO)?;
        }
        Ok(Self {
            socket,
            ipv6,
            bound_dns_ipv4,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn set_broadcast(&self, enabled: bool) -> io::Result<()> {
        self.socket.set_broadcast(enabled)
    }

    /// dhcp_init permits fragmentation, uses the network-control TOS, and
    /// enables broadcast before admitting clients (dhcp.c:40–98).
    pub fn configure_dhcp(&self) -> io::Result<()> {
        if self.ipv6 {
            return Err(invalid("DHCPv4 socket must use AF_INET"));
        }
        for (option, value) in [(10, 0), (1, 0xc0)] {
            // SAFETY: IP_MTU_DISCOVER and IP_TOS both take a native int.
            if unsafe { setsockopt(self.as_raw_fd(), IPPROTO_IP, option, &value, 4) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.set_broadcast(true)
    }

    /// Truncated datagrams/ancillary data and zero source ports are discarded.
    /// Only initialized `buffer[..len]` is returned for protocol processing.
    #[cfg_attr(target_os = "linux", link_section = ".text.dnsmasq_hot")]
    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<Option<Datagram>> {
        let mut peer = Address {
            storage: [0; 4],
            len: 32,
        };
        let mut control = [0u64; 5]; // CMSG_SPACE(in6_pktinfo) == 40.
        let mut iov = IoVec {
            base: buffer.as_mut_ptr(),
            len: buffer.len(),
        };
        let mut msg = MsgHdr {
            name: peer.bytes_mut().as_mut_ptr(),
            namelen: 32,
            iov: &mut iov,
            iovlen: 1,
            control: control.as_mut_ptr().cast(),
            controllen: 40,
            flags: 0,
        };
        // SAFETY: buffers, iovec and header are initialized and live; lengths
        // bound all kernel writes. Socket is nonblocking and remains owned.
        let len = unsafe { recvmsg(self.as_raw_fd(), &mut msg, 0) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        if msg.flags & (MSG_TRUNC | MSG_CTRUNC) != 0 || len as usize > buffer.len() {
            return Ok(None);
        }
        let peer = peer.decode(msg.namelen)?;
        if peer.port() == 0 {
            return Ok(None);
        }
        let (destination, local_address, interface) = if let Some(address) = self.bound_dns_ipv4 {
            (IpAddr::V4(address), IpAddr::V4(address), 0)
        } else {
            // SAFETY: initialized control array, bounded by its actual allocation.
            let bytes = unsafe {
                std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), msg.controllen.min(40))
            };
            let Some(metadata) = packet_info(bytes, self.ipv6) else {
                return Ok(None);
            };
            metadata
        };
        Ok(Some(Datagram {
            len: len as usize,
            peer,
            destination,
            local_address,
            interface,
        }))
    }

    /// None chooses the kernel source for a dedicated bound socket. IPv4 uses
    /// ipi_spec_dst without forcing an interface; IPv6 carries scope/interface.
    pub fn send(
        &self,
        bytes: &[u8],
        peer: SocketAddr,
        source: Option<(IpAddr, u32)>,
    ) -> io::Result<()> {
        self.send_with_interface(bytes, peer, source, None, true)
    }

    /// One owner-scheduled transmission with optional explicit source.
    pub fn send_once(
        &self,
        bytes: &[u8],
        peer: SocketAddr,
        source: Option<(IpAddr, u32)>,
    ) -> io::Result<()> {
        self.send_with_interface(bytes, peer, source, None, false)
    }

    /// DHCP's unconfigured-client branch supplies `ipi_ifindex` and lets the
    /// kernel choose `ipi_spec_dst`. DNS `send` above intentionally keeps its
    /// IPv4 interface at zero, following forward.c::send_from.
    pub fn send_on_interface(
        &self,
        bytes: &[u8],
        peer: SocketAddr,
        interface: u32,
    ) -> io::Result<()> {
        if self.ipv6 || interface == 0 || interface > i32::MAX as u32 {
            return Err(invalid("DHCP send needs a valid IPv4 interface"));
        }
        self.send_with_interface(
            bytes,
            peer,
            Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), interface)),
            Some(interface),
            true,
        )
    }

    /// One DHCP transmission attempt, leaving EINTR/EAGAIN policy to its
    /// runtime. Other protocols retain the existing interrupted-send retry.
    pub fn send_on_interface_once(
        &self,
        bytes: &[u8],
        peer: SocketAddr,
        interface: u32,
    ) -> io::Result<()> {
        if self.ipv6 || interface == 0 || interface > i32::MAX as u32 {
            return Err(invalid("DHCP send needs a valid IPv4 interface"));
        }
        self.send_with_interface(
            bytes,
            peer,
            Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), interface)),
            Some(interface),
            false,
        )
    }

    #[cfg_attr(target_os = "linux", link_section = ".text.dnsmasq_hot")]
    fn send_with_interface(
        &self,
        bytes: &[u8],
        peer: SocketAddr,
        source: Option<(IpAddr, u32)>,
        ipv4_interface: Option<u32>,
        retry_interrupted: bool,
    ) -> io::Result<()> {
        if peer.is_ipv6() != self.ipv6 {
            return Err(invalid("destination family mismatch"));
        }
        let mut address = Address::new(peer);
        let mut control = [0u64; 5];
        let mut iov = IoVec {
            base: bytes.as_ptr() as *mut u8,
            len: bytes.len(),
        };
        let mut msg = MsgHdr {
            name: address.bytes_mut().as_mut_ptr(),
            namelen: address.len,
            iov: &mut iov,
            iovlen: 1,
            control: std::ptr::null_mut(),
            controllen: 0,
            flags: 0,
        };
        if let Some((source, interface)) = source {
            if source.is_ipv6() != self.ipv6 {
                return Err(invalid("source family mismatch"));
            }
            // SAFETY: initialized 40-byte aligned storage, exclusively borrowed.
            let b =
                unsafe { std::slice::from_raw_parts_mut(control.as_mut_ptr().cast::<u8>(), 40) };
            let (len, space, level, kind) = if self.ipv6 {
                (36usize, 40, IPPROTO_IPV6, IPV6_PKTINFO)
            } else {
                (28, 32, IPPROTO_IP, IP_PKTINFO)
            };
            b[..8].copy_from_slice(&len.to_ne_bytes());
            b[8..12].copy_from_slice(&level.to_ne_bytes());
            b[12..16].copy_from_slice(&kind.to_ne_bytes());
            match source {
                IpAddr::V4(v) => {
                    b[16..20].copy_from_slice(&ipv4_interface.unwrap_or(0).to_ne_bytes());
                    b[20..24].copy_from_slice(&v.octets());
                }
                IpAddr::V6(v) => {
                    b[16..32].copy_from_slice(&v.octets());
                    b[32..36].copy_from_slice(&interface.to_ne_bytes());
                }
            }
            msg.control = b.as_mut_ptr();
            msg.controllen = space;
        }
        loop {
            // SAFETY: all iovec/address/control data outlive sendmsg; the kernel
            // only reads the packet despite the POSIX iovec's mutable pointer.
            let sent = unsafe { sendmsg(self.as_raw_fd(), &msg, 0) };
            if sent >= 0 {
                return if sent as usize == bytes.len() {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short datagram send",
                    ))
                };
            }
            let error = io::Error::last_os_error();
            if !retry_interrupted || error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

fn packet_info(mut bytes: &[u8], ipv6: bool) -> Option<(IpAddr, IpAddr, u32)> {
    while bytes.len() >= 16 {
        let len = usize::from_ne_bytes(bytes[..8].try_into().ok()?);
        if len < 16 || len > bytes.len() {
            return None;
        }
        let level = i32::from_ne_bytes(bytes[8..12].try_into().ok()?);
        let kind = i32::from_ne_bytes(bytes[12..16].try_into().ok()?);
        if !ipv6 && level == IPPROTO_IP && kind == IP_PKTINFO && len >= 28 {
            return Some((
                IpAddr::V4(Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27])),
                IpAddr::V4(Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23])),
                u32::from_ne_bytes(bytes[16..20].try_into().ok()?),
            ));
        }
        if ipv6
            && level == IPPROTO_IPV6
            && matches!(kind, IPV6_PKTINFO | IPV6_2292PKTINFO)
            && len >= 36
        {
            return Some((
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[16..32]).ok()?)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[16..32]).ok()?)),
                u32::from_ne_bytes(bytes[32..36].try_into().ok()?),
            ));
        }
        let next = len.checked_add(7)? & !7;
        bytes = bytes.get(next..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn abi_and_sockaddr_bytes() {
        assert_eq!(std::mem::size_of::<IoVec>(), 16);
        assert_eq!(std::mem::size_of::<MsgHdr>(), 56);
        assert_eq!(std::mem::offset_of!(MsgHdr, control), 32);
        for addr in ["192.0.2.1:53", "[2001:db8::1]:53", "[fe80::1%9]:5353"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let mut raw = Address::new(addr);
            let len = raw.len;
            assert_eq!(raw.decode(len).unwrap(), addr);
        }
    }

    #[test]
    fn ipv4_pktinfo_keeps_broadcast_distinct_from_local_source() {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&28usize.to_ne_bytes());
        bytes[8..12].copy_from_slice(&IPPROTO_IP.to_ne_bytes());
        bytes[12..16].copy_from_slice(&IP_PKTINFO.to_ne_bytes());
        bytes[16..20].copy_from_slice(&3u32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&[192, 0, 2, 1]);
        bytes[24..28].copy_from_slice(&[255, 255, 255, 255]);
        assert_eq!(
            packet_info(&bytes, false),
            Some((
                IpAddr::V4(Ipv4Addr::BROADCAST),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                3,
            ))
        );
        for length in 0..28 {
            assert_eq!(packet_info(&bytes[..length], false), None);
        }
    }

    #[test]
    fn ipv6_pktinfo_reads_scope_from_current_and_rfc2292_headers() {
        for kind in [IPV6_PKTINFO, IPV6_2292PKTINFO] {
            let mut bytes = [0; 40];
            bytes[..8].copy_from_slice(&36usize.to_ne_bytes());
            bytes[8..12].copy_from_slice(&IPPROTO_IPV6.to_ne_bytes());
            bytes[12..16].copy_from_slice(&kind.to_ne_bytes());
            let address: Ipv6Addr = "fe80::1".parse().unwrap();
            bytes[16..32].copy_from_slice(&address.octets());
            bytes[32..36].copy_from_slice(&7u32.to_ne_bytes());
            assert_eq!(
                packet_info(&bytes, true),
                Some((address.into(), address.into(), 7))
            );
            for length in 0..36 {
                assert_eq!(packet_info(&bytes[..length], true), None);
            }
        }
    }

    #[test]
    #[ignore = "requires Linux isolated network namespace; run with run_isolated.sh"]
    fn tcp_pktoptions_identifies_loopback_for_both_families() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let listener = std::net::TcpListener::bind(bind).unwrap();
            let address = listener.local_addr().unwrap();
            let _client = TcpStream::connect(address).unwrap();
            let (stream, _) = listener.accept().unwrap();
            assert_eq!(
                tcp_interface(&stream, address.is_ipv6()),
                Some((b"lo".to_vec(), true))
            );
        }
    }

    #[test]
    #[ignore = "requires Linux isolated network namespace; run with run_isolated.sh"]
    fn static_dns_ipv4_preserves_zero_port_and_receive_errors() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        assert_eq!(
            DatagramSocket::bind_dns_static_ipv4("0.0.0.0:0".parse().unwrap()).err().unwrap().kind(),
            io::ErrorKind::InvalidInput,
        );
        for static_dns in [false, true] {
            let server = if static_dns {
                DatagramSocket::bind_dns_static_ipv4("127.0.0.1:0".parse().unwrap()).unwrap()
            } else {
                DatagramSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap()
            };
            // A raw IPv4 UDP socket permits a genuine zero source port. The
            // isolated namespace owns this packet and the kernel adds IPv4.
            // SAFETY: socket has no pointers and returns a new descriptor.
            let fd = unsafe { socket(AF_INET, 3 | SOCK_CLOEXEC, 17) };
            assert!(fd >= 0, "{}", io::Error::last_os_error());
            // SAFETY: a fresh descriptor has exactly this scoped owner.
            let raw = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut target = Address::new(server.local_addr().unwrap());
            let port = server.local_addr().unwrap().port().to_be_bytes();
            let packet = [0, 0, port[0], port[1], 0, 9, 0, 0, 7];
            // SAFETY: all initialized address and datagram bytes outlive sendto.
            assert_eq!(unsafe { sendto(raw.as_raw_fd(), packet.as_ptr(), packet.len(), 0,
                target.bytes_mut().as_ptr(), target.len) }, packet.len() as isize);
            let mut bytes = [0; 32];
            assert_eq!(server.receive(&mut bytes).unwrap(), None);
            assert_eq!(server.receive(&mut bytes).unwrap_err().kind(), io::ErrorKind::WouldBlock);
            let client = UdpSocket::bind("127.0.0.1:0").unwrap();
            client.send_to(b"valid-after-zero-port", server.local_addr().unwrap()).unwrap();
            let incoming = server.receive(&mut bytes).unwrap().unwrap();
            assert_eq!(&bytes[..incoming.len], b"valid-after-zero-port");
        }
    }

    #[test]
    #[ignore = "requires Linux isolated network namespace; run with run_isolated.sh"]
    fn udp_source_and_truncation() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        for (bind, destination, client_bind) in [
            ("0.0.0.0:0", "127.0.0.2", "127.0.0.1:0"),
            ("[::]:0", "::1", "[::1]:0"),
        ] {
            let server = DatagramSocket::bind(bind.parse().unwrap()).unwrap();
            let client = UdpSocket::bind(client_bind).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let destination: IpAddr = destination.parse().unwrap();
            let target = SocketAddr::new(destination, server.local_addr().unwrap().port());
            client.send_to(b"question", target).unwrap();
            let mut bytes = [0; 32];
            let metadata = server.receive(&mut bytes).unwrap().unwrap();
            assert_eq!(metadata.destination, destination);
            assert_ne!(metadata.interface, 0);
            assert_eq!(&bytes[..metadata.len], b"question");
            server
                .send(
                    b"answer",
                    metadata.peer,
                    Some((metadata.destination, metadata.interface)),
                )
                .unwrap();
            let (len, peer) = client.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..len], b"answer");
            assert_eq!(peer.ip(), destination);
            client.send_to(&[7; 100], target).unwrap();
            assert_eq!(server.receive(&mut bytes).unwrap(), None);
        }
    }
}
