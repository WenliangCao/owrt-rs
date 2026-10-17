//! Linux 64-bit datagram boundary. DNS/DHCP/TFTP policy stays in Rust callers.
//! C reference: network.c:936–1009; forward.c:32–119,1635–1796.
//! Reuses the repository's audited iovec/msghdr layout and readiness backend.

use dnsmasq_platform::{
    datagram::{self, AlignedBytes},
    interfaces, socket_options,
};
use rustix::net::{self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use std::io;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket,
};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const IPPROTO_IP: i32 = 0;
const IPPROTO_IPV6: i32 = 41;
const IP_PKTINFO: i32 = 8;
const IPV6_2292PKTINFO: i32 = 2;
const IPV6_PKTINFO: i32 = 50;
const MSG_TRUNC: i32 = 32;
const MSG_CTRUNC: i32 = 8;

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
    storage: AlignedBytes<32>,
    len: u32,
}

impl Address {
    fn new(address: SocketAddr) -> Self {
        let mut out = Self {
            storage: AlignedBytes([0; 32]),
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
        &mut self.storage.0
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

impl AsFd for DatagramSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

/// C network.c::tcp_interface reads the SYN's ingress through IP_PKTOPTIONS,
/// including the retained RFC-2292 IPv6 ABI. Missing metadata means fallback;
/// the connection's destination does not identify its arrival interface.
pub(crate) fn tcp_interface(stream: &TcpStream, ipv6: bool) -> Option<(Vec<u8>, bool)> {
    if ipv6 {
        if let Err(error) = socket_options::enable_packet_info(stream, true, false) {
            if error.raw_os_error() != Some(92)
                || socket_options::enable_packet_info(stream, true, true).is_err()
            {
                return None;
            }
        }
    } else {
        socket_options::enable_packet_info(stream, false, false).ok()?;
    }
    let mut storage = AlignedBytes([0u8; 64]);
    let length = socket_options::packet_options(stream, ipv6, &mut storage.0).ok()?;
    let (_, _, index) = packet_info(&storage.0[..length], ipv6)?;
    if index == 0 {
        return None;
    }
    let name = interfaces::index_to_name(index).ok()?;
    let loopback = interfaces::interface_flags(stream, &name).is_ok_and(|flags| flags & 8 != 0);
    Some((
        name.into_iter().take_while(|&byte| byte != 0).collect(),
        loopback,
    ))
}

/// Linux raw ICMP socket used only by the DHCP conflict probe. Every success,
/// error and cancellation path closes its descriptor through OwnedFd.
pub struct IcmpSocket(OwnedFd);

impl AsFd for IcmpSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl IcmpSocket {
    /// Borrow the descriptor for the caller's DNS/TFTP/ICMP poll set.
    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

    pub fn open() -> io::Result<Self> {
        let socket = Self(net::socket_with(
            AddressFamily::INET,
            SocketType::RAW,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(net::ipproto::ICMP),
        )?);
        socket_options::set_dont_route(&socket.0, false)?;
        Ok(socket)
    }

    pub fn send(&self, bytes: &[u8], target: Ipv4Addr) -> io::Result<()> {
        let sent = net::sendto(
            &self.0,
            bytes,
            SendFlags::empty(),
            &SocketAddrV4::new(target, 0),
        )?;
        if sent != bytes.len() {
            Err(io::Error::new(io::ErrorKind::WriteZero, "short ICMP send"))
        } else {
            Ok(())
        }
    }

    pub fn receive(&self, bytes: &mut [u8]) -> io::Result<(usize, Ipv4Addr)> {
        // No TRUNC flag: preserve C's fixed-buffer truncation behavior.
        let (_, got, address) = net::recvfrom(&self.0, bytes, RecvFlags::empty())?;
        let address = address.ok_or_else(|| invalid("short peer address"))?;
        let peer =
            SocketAddrV4::try_from(address).map_err(|_| invalid("unexpected ICMP peer family"))?;
        Ok((got, *peer.ip()))
    }

    /// One bounded wait. EINTR is returned to the probe so it can check its
    /// stop flag rather than hiding cancellation inside an unbounded retry.
    pub fn wait(&self, timeout: std::time::Duration) -> io::Result<bool> {
        let mut fds = [rustix::event::PollFd::new(
            &self.0,
            rustix::event::PollFlags::IN,
        )];
        let millis = timeout.as_millis().min(i32::MAX as u128) as i64;
        let timeout = rustix::event::Timespec {
            tv_sec: millis / 1000,
            tv_nsec: (millis % 1000) * 1_000_000,
        };
        let ready = rustix::event::poll(&mut fds, Some(&timeout))?;
        if fds[0].revents().intersects(
            rustix::event::PollFlags::ERR
                | rustix::event::PollFlags::HUP
                | rustix::event::PollFlags::NVAL,
        ) {
            return Err(io::Error::other("ICMP socket readiness failure"));
        }
        Ok(ready != 0)
    }
}

/// Linux `struct arpreq`: two sockaddrs, flags, netmask sockaddr and device
/// name (68 bytes, four-byte alignment). Unused bytes are zero-initialized;
/// C only initializes the fields required for an ATF_COM neighbour entry.
#[repr(C, align(4))]
pub struct ArpEntry([u8; 68]);

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
        let mut entry = Self([0; 68]);
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
        &self.0
    }

    fn bytes_mut(&mut self) -> &mut [u8; 68] {
        &mut self.0
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
pub fn interface_name(socket: &impl AsFd, interface: u32) -> io::Result<[u8; 16]> {
    if interface == 0 || interface > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ARP requires an ingress interface",
        ));
    }
    interfaces::interface_name(socket, interface)
}

/// Query only the ingress needed by C's failed-ACL loopback exception.
pub fn interface_loopback(socket: &impl AsFd, name: &[u8; 16]) -> io::Result<bool> {
    Ok(interfaces::interface_flags(socket, name)? & 8 != 0)
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
    interfaces::set_arp(socket, entry.bytes_mut())
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
        socket_options::bind_to_device(self, &bytes[..bytes.len().min(16)])
    }

    fn bind_options(
        address: SocketAddr,
        reuse_address: bool,
        reuse_port: bool,
        bound_dns_ipv4: Option<Ipv4Addr>,
    ) -> io::Result<Self> {
        let ipv6 = address.is_ipv6();
        let fd = net::socket_with(
            if ipv6 {
                AddressFamily::INET6
            } else {
                AddressFamily::INET
            },
            SocketType::DGRAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|error| socket_creation_error(error.into()))?;
        let socket = UdpSocket::from(fd);
        if reuse_port {
            if let Err(error) = net::sockopt::set_socket_reuseport(&socket, true) {
                let error = io::Error::from(error);
                if error.raw_os_error() != Some(92) {
                    return Err(error);
                }
            }
        }
        if reuse_address {
            net::sockopt::set_socket_reuseaddr(&socket, true)?;
        }
        if ipv6 {
            net::sockopt::set_ipv6_v6only(&socket, true)?;
        }
        let mut address = address;
        if let SocketAddr::V6(address) = &mut address {
            address.set_flowinfo(0);
        }
        net::bind(&socket, &address)?;
        if ipv6 || bound_dns_ipv4.is_none() {
            socket_options::enable_packet_info(&socket, ipv6, false)?;
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
        net::sockopt::set_ip_mtu_discover(&self.socket, net::sockopt::Ipv4PathMtuDiscovery::DONT)?;
        net::sockopt::set_ip_tos(&self.socket, 0xc0)?;
        self.set_broadcast(true)
    }

    /// Truncated datagrams/ancillary data and zero source ports are discarded.
    /// Only initialized `buffer[..len]` is returned for protocol processing.
    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<Option<Datagram>> {
        let mut peer = Address {
            storage: AlignedBytes([0; 32]),
            len: 32,
        };
        let mut control = AlignedBytes([0u8; 40]);
        let received = datagram::receive(&self.socket, buffer, &mut peer.storage, &mut control)?;
        if received.flags & (MSG_TRUNC | MSG_CTRUNC) != 0 || received.len > buffer.len() {
            return Ok(None);
        }
        let peer = peer.decode(received.address_len)?;
        if peer.port() == 0 {
            return Ok(None);
        }
        let (destination, local_address, interface) = if let Some(address) = self.bound_dns_ipv4 {
            (IpAddr::V4(address), IpAddr::V4(address), 0)
        } else {
            let bytes = &control.0[..received.control_len];
            let Some(metadata) = packet_info(bytes, self.ipv6) else {
                return Ok(None);
            };
            metadata
        };
        Ok(Some(Datagram {
            len: received.len,
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
        let address = Address::new(peer);
        let mut control = AlignedBytes([0u8; 40]);
        let mut control_len = 0;
        if let Some((source, interface)) = source {
            if source.is_ipv6() != self.ipv6 {
                return Err(invalid("source family mismatch"));
            }
            let b = &mut control.0;
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
            control_len = space;
        }
        loop {
            match datagram::send(
                &self.socket,
                bytes,
                &address.storage,
                address.len,
                &control,
                control_len,
            ) {
                Ok(sent) if sent == bytes.len() => return Ok(()),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short datagram send",
                    ))
                }
                Err(error) if retry_interrupted && error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
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
        assert_eq!(std::mem::align_of::<AlignedBytes<32>>(), 8);
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
            DatagramSocket::bind_dns_static_ipv4("0.0.0.0:0".parse().unwrap())
                .err()
                .unwrap()
                .kind(),
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
            let raw = net::socket_with(
                AddressFamily::INET,
                SocketType::RAW,
                SocketFlags::CLOEXEC,
                Some(net::ipproto::UDP),
            )
            .unwrap();
            let target = server.local_addr().unwrap();
            let port = server.local_addr().unwrap().port().to_be_bytes();
            let packet = [0, 0, port[0], port[1], 0, 9, 0, 0, 7];
            assert_eq!(
                net::sendto(&raw, &packet, SendFlags::empty(), &target).unwrap(),
                packet.len()
            );
            let mut bytes = [0; 32];
            assert_eq!(server.receive(&mut bytes).unwrap(), None);
            assert_eq!(
                server.receive(&mut bytes).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            let client = UdpSocket::bind("127.0.0.1:0").unwrap();
            client
                .send_to(b"valid-after-zero-port", server.local_addr().unwrap())
                .unwrap();
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
