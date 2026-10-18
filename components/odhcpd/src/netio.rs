//! Interface-bound Linux IPv6 sockets. Protocol validation belongs to the
//! router/DHCPv6 modules; this layer rejects incomplete or misdirected datagrams.
use crate::model::Link;
use std::ffi::{c_int, c_void, CString};
use std::io;
use std::mem::{offset_of, size_of};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// These layouts match both glibc and musl on our Linux LP64 little-endian
// targets. In particular musl's 32-bit msg_iovlen/msg_controllen have padding
// in the high half. Do not silently use these definitions on another ABI.
#[cfg(not(all(
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little",
    any(target_arch = "aarch64", target_arch = "x86_64")
)))]
compile_error!("netio requires Linux little-endian aarch64 or x86_64");

const AF_INET6: c_int = 10;
const IPPROTO_IPV6: c_int = 41;
const IPPROTO_ICMPV6: c_int = 58;
const IPV6_PKTINFO: c_int = 50;
const IPV6_HOPLIMIT: c_int = 52;
const MSG_CTRUNC: c_int = 8;
const MSG_TRUNC: c_int = 32;
const MSG_DONTWAIT: c_int = 64;
const CMSG_HEADER: usize = 16;
const PACKET_INFO_SIZE: usize = 20;
const MAX_DATAGRAM: usize = 8192;

#[repr(C)]
#[derive(Default)]
struct SockAddr6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    address: [u8; 16],
    scope: u32,
}

#[repr(C)]
struct IoVec {
    base: *mut c_void,
    len: usize,
}

#[repr(C)]
struct MsgHdr {
    name: *mut c_void,
    name_len: u32,
    iov: *mut IoVec,
    iov_len: usize,
    control: *mut c_void,
    control_len: usize,
    flags: c_int,
}

#[repr(C)]
struct MulticastRequest {
    address: [u8; 16],
    interface: u32,
}

#[repr(align(8))]
struct Control([u8; 64]); // CMSG_SPACE(pktinfo)=40 + CMSG_SPACE(hoplimit)=24.

const _: () = {
    assert!(size_of::<SockAddr6>() == 28);
    assert!(size_of::<IoVec>() == 16);
    assert!(size_of::<MsgHdr>() == 56);
    assert!(offset_of!(MsgHdr, name_len) == 8);
    assert!(offset_of!(MsgHdr, iov) == 16);
    assert!(offset_of!(MsgHdr, iov_len) == 24);
    assert!(offset_of!(MsgHdr, control) == 32);
    assert!(offset_of!(MsgHdr, control_len) == 40);
    assert!(offset_of!(MsgHdr, flags) == 48);
    assert!(size_of::<MulticastRequest>() == PACKET_INFO_SIZE);
};

unsafe extern "C" {
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, len: u32) -> c_int;
    fn bind(fd: c_int, address: *const c_void, len: u32) -> c_int;
    fn recvmsg(fd: c_int, message: *mut MsgHdr, flags: c_int) -> isize;
    fn sendmsg(fd: c_int, message: *const MsgHdr, flags: c_int) -> isize;
    fn if_nametoindex(name: *const std::ffi::c_char) -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Router,
    Dhcp6,
}

#[derive(Debug)]
pub struct Packet {
    pub bytes: Vec<u8>,
    pub source: SocketAddrV6,
    pub destination: Ipv6Addr,
    pub interface: u32,
    pub hop_limit: Option<i32>,
}

pub struct Socket {
    fd: OwnedFd,
    kind: Kind,
    interface: u32,
}

impl Socket {
    pub fn open(kind: Kind, link: &Link) -> io::Result<Self> {
        if link.index == 0 || link.index > i32::MAX as u32 || link.name.len() >= 16 {
            return Err(invalid_input("invalid interface name or index"));
        }
        let name = CString::new(link.name.as_str())
            .map_err(|_| invalid_input("interface name contains NUL"))?;
        // SAFETY: name is a live NUL-terminated string; this only queries the
        // current network namespace and does not retain the pointer.
        let actual_index = unsafe { if_nametoindex(name.as_ptr()) };
        if actual_index == 0 {
            return Err(io::Error::last_os_error());
        }
        if actual_index != link.index {
            return Err(invalid_input("interface index changed before socket open"));
        }
        let (socket_kind, protocol) = match kind {
            Kind::Router => (3, IPPROTO_ICMPV6), // SOCK_RAW
            Kind::Dhcp6 => (2, 17),              // SOCK_DGRAM, IPPROTO_UDP
        };
        // SAFETY: scalar Linux socket constants. A successful fd is immediately
        // transferred to OwnedFd and closed on every subsequent error path.
        let raw = unsafe { socket(AF_INET6, socket_kind | 0x80000 | 0x800, protocol) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket returned a new, valid descriptor owned by this call.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let result = Self {
            fd,
            kind,
            interface: link.index,
        };
        result.set_bytes(1, 25, name.as_bytes_with_nul())?; // SO_BINDTODEVICE
        result.set_int(IPPROTO_IPV6, 49, 1)?; // IPV6_RECVPKTINFO
        result.set_int(IPPROTO_IPV6, 19, 0)?; // IPV6_MULTICAST_LOOP
        match kind {
            Kind::Router => {
                // Linux raw ICMPv6 sockets already are IPv6-only; setting
                // IPV6_V6ONLY on one returns EINVAL. Match the pinned C daemon.
                result.set_int(255, 7, 2)?; // IPPROTO_RAW / IPV6_CHECKSUM
                result.set_int(IPPROTO_IPV6, 18, 255)?; // MULTICAST_HOPS
                result.set_int(IPPROTO_IPV6, 16, 255)?; // UNICAST_HOPS
                result.set_int(IPPROTO_IPV6, 51, 1)?; // RECVHOPLIMIT
                let mut filter = [u32::MAX; 8];
                for message in [133, 134] {
                    filter[message / 32] &= !(1 << (message % 32));
                }
                result.set_value(IPPROTO_ICMPV6, 1, &filter)?; // ICMP6_FILTER
                result.join(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2))?;
            }
            Kind::Dhcp6 => {
                result.set_int(IPPROTO_IPV6, 26, 1)?; // IPV6_V6ONLY
                result.set_int(1, 2, 1)?; // SO_REUSEADDR
                result.set_int(IPPROTO_IPV6, 18, 32)?; // MULTICAST_HOPS
                let address = SockAddr6 {
                    family: AF_INET6 as u16,
                    port: 547u16.to_be(),
                    ..SockAddr6::default()
                };
                // SAFETY: address has the checked Linux sockaddr_in6 layout
                // and remains live throughout bind; its complete size is given.
                if unsafe {
                    bind(
                        result.as_raw_fd(),
                        (&address as *const SockAddr6).cast(),
                        size_of::<SockAddr6>() as u32,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                result.join(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2))?;
                result.join(Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3))?;
            }
        }
        Ok(result)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Consume at most one datagram. None means either no queued packet or a
    /// dropped packet. Remaining packets keep the descriptor readable to poll.
    pub fn recv(&self) -> io::Result<Option<Packet>> {
        let mut bytes = [0u8; MAX_DATAGRAM];
        let mut source = SockAddr6::default();
        let mut control = Control([0; 64]);
        let mut iov = IoVec {
            base: bytes.as_mut_ptr().cast(),
            len: bytes.len(),
        };
        let mut message = MsgHdr {
            name: (&mut source as *mut SockAddr6).cast(),
            name_len: size_of::<SockAddr6>() as u32,
            iov: &mut iov,
            iov_len: 1,
            control: control.0.as_mut_ptr().cast(),
            control_len: control.0.len(),
            flags: 0,
        };
        // SAFETY: all writable message pointers refer to separate, live buffers
        // of the lengths supplied; layouts and ancillary alignment are checked.
        let length = unsafe { recvmsg(self.as_raw_fd(), &mut message, MSG_DONTWAIT) };
        if length < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if message.flags & (MSG_TRUNC | MSG_CTRUNC) != 0
            || length as usize > bytes.len()
            || message.name_len as usize != size_of::<SockAddr6>()
            || source.family != AF_INET6 as u16
            || message.control_len > control.0.len()
        {
            return Ok(None);
        }
        let Some((destination, interface, hop_limit)) =
            parse_control(&control.0[..message.control_len])
        else {
            return Ok(None);
        };
        if interface != self.interface
            || (source.scope != 0 && source.scope != self.interface)
            || (self.kind == Kind::Router && hop_limit != Some(255))
        {
            return Ok(None);
        }
        Ok(Some(Packet {
            bytes: bytes[..length as usize].to_vec(),
            source: SocketAddrV6::new(
                Ipv6Addr::from(source.address),
                u16::from_be(source.port),
                u32::from_be(source.flowinfo),
                source.scope,
            ),
            destination,
            interface,
            hop_limit,
        }))
    }

    pub fn send(
        &self,
        bytes: &[u8],
        destination: SocketAddrV6,
        source: Option<Ipv6Addr>,
    ) -> io::Result<usize> {
        if destination.scope_id() != 0 && destination.scope_id() != self.interface {
            return Err(invalid_input("destination scope disagrees with interface"));
        }
        let scoped = destination.ip().is_unicast_link_local()
            || (destination.ip().is_multicast() && destination.ip().octets()[1] & 0xf == 2);
        let mut address = SockAddr6 {
            family: AF_INET6 as u16,
            port: destination.port().to_be(),
            flowinfo: destination.flowinfo().to_be(),
            address: destination.ip().octets(),
            scope: if scoped {
                self.interface
            } else {
                destination.scope_id()
            },
        };
        let mut control = packet_info(source.unwrap_or(Ipv6Addr::UNSPECIFIED), self.interface);
        let mut iov = IoVec {
            base: bytes.as_ptr().cast_mut().cast(),
            len: bytes.len(),
        };
        let message = MsgHdr {
            name: (&mut address as *mut SockAddr6).cast(),
            name_len: size_of::<SockAddr6>() as u32,
            iov: &mut iov,
            iov_len: 1,
            control: control.0.as_mut_ptr().cast(),
            control_len: 40, // CMSG_SPACE(in6_pktinfo)
            flags: 0,
        };
        // SAFETY: sendmsg only reads the live address, payload, iovec and
        // aligned control buffers. It retains no pointer beyond this call.
        let length = unsafe { sendmsg(self.as_raw_fd(), &message, MSG_DONTWAIT) };
        if length < 0 {
            Err(io::Error::last_os_error())
        } else if length as usize != bytes.len() {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short IPv6 datagram send",
            ))
        } else {
            Ok(length as usize)
        }
    }

    fn join(&self, address: Ipv6Addr) -> io::Result<()> {
        self.set_value(
            IPPROTO_IPV6,
            20, // IPV6_ADD_MEMBERSHIP
            &MulticastRequest {
                address: address.octets(),
                interface: self.interface,
            },
        )
    }

    fn set_int(&self, level: c_int, name: c_int, value: c_int) -> io::Result<()> {
        self.set_value(level, name, &value)
    }

    fn set_value<T>(&self, level: c_int, name: c_int, value: &T) -> io::Result<()> {
        // SAFETY: private callers supply the complete, initialized Linux option
        // type with no padding (i32, [u32;8], or MulticastRequest). setsockopt
        // only reads it synchronously, bounded by its exact size.
        let result = unsafe {
            setsockopt(
                self.as_raw_fd(),
                level,
                name,
                (value as *const T).cast(),
                size_of::<T>() as u32,
            )
        };
        socket_result(result)
    }

    fn set_bytes(&self, level: c_int, name: c_int, value: &[u8]) -> io::Result<()> {
        // SAFETY: value is live for this synchronous call; length is bounded by
        // the already validated interface name, so it fits socklen_t.
        let result = unsafe {
            setsockopt(
                self.as_raw_fd(),
                level,
                name,
                value.as_ptr().cast(),
                value.len() as u32,
            )
        };
        socket_result(result)
    }
}

fn socket_result(result: c_int) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn packet_info(address: Ipv6Addr, interface: u32) -> Control {
    let mut control = Control([0; 64]);
    control.0[..8].copy_from_slice(&(CMSG_HEADER + PACKET_INFO_SIZE).to_ne_bytes());
    control.0[8..12].copy_from_slice(&IPPROTO_IPV6.to_ne_bytes());
    control.0[12..16].copy_from_slice(&IPV6_PKTINFO.to_ne_bytes());
    control.0[16..32].copy_from_slice(&address.octets());
    control.0[32..36].copy_from_slice(&interface.to_ne_bytes());
    control
}

fn parse_control(bytes: &[u8]) -> Option<(Ipv6Addr, u32, Option<i32>)> {
    let mut packet_info = None;
    let mut hop_limit = None;
    let mut offset = 0;
    while offset < bytes.len() {
        let header = bytes.get(offset..offset.checked_add(CMSG_HEADER)?)?;
        let len = usize::from_ne_bytes(header[..8].try_into().ok()?);
        let level = i32::from_ne_bytes(header[8..12].try_into().ok()?);
        let kind = i32::from_ne_bytes(header[12..16].try_into().ok()?);
        if len < CMSG_HEADER {
            return None;
        }
        let data = bytes.get(offset + CMSG_HEADER..offset.checked_add(len)?)?;
        match (level, kind) {
            (IPPROTO_IPV6, IPV6_PKTINFO) => {
                if data.len() != PACKET_INFO_SIZE || packet_info.is_some() {
                    return None;
                }
                packet_info = Some((
                    Ipv6Addr::from(<[u8; 16]>::try_from(&data[..16]).ok()?),
                    u32::from_ne_bytes(data[16..20].try_into().ok()?),
                ));
            }
            (IPPROTO_IPV6, IPV6_HOPLIMIT) => {
                if data.len() != 4 || hop_limit.is_some() {
                    return None;
                }
                let value = i32::from_ne_bytes(data.try_into().ok()?);
                if !(0..=255).contains(&value) {
                    return None;
                }
                hop_limit = Some(value);
            }
            _ => {}
        }
        // The last cmsg may end without its alignment padding.
        let end = offset.checked_add(len)?;
        if end == bytes.len() {
            break;
        }
        offset = end.checked_add(7)? & !7;
    }
    let (destination, interface) = packet_info?;
    (interface != 0).then_some((destination, interface, hop_limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancillary_both_fields_and_packet_info_alone() {
        let address = "ff02::2".parse().unwrap();
        let mut control = packet_info(address, 7);
        assert_eq!(parse_control(&control.0[..40]), Some((address, 7, None)));
        control.0[40..48].copy_from_slice(&20usize.to_ne_bytes());
        control.0[48..52].copy_from_slice(&IPPROTO_IPV6.to_ne_bytes());
        control.0[52..56].copy_from_slice(&IPV6_HOPLIMIT.to_ne_bytes());
        control.0[56..60].copy_from_slice(&255i32.to_ne_bytes());
        assert_eq!(parse_control(&control.0), Some((address, 7, Some(255))));
        assert_eq!(
            parse_control(&control.0[..60]),
            Some((address, 7, Some(255)))
        );
    }

    #[test]
    fn malformed_ancillary_is_not_accepted() {
        let control = packet_info(Ipv6Addr::LOCALHOST, 4);
        for length in 0..36 {
            assert!(parse_control(&control.0[..length]).is_none());
        }
        for declared in [0usize, 15, 16, 35, 37, 65, usize::MAX] {
            let mut invalid = packet_info(Ipv6Addr::LOCALHOST, 4);
            invalid.0[..8].copy_from_slice(&declared.to_ne_bytes());
            assert!(parse_control(&invalid.0).is_none());
        }
        assert!(parse_control(&packet_info(Ipv6Addr::LOCALHOST, 0).0[..40]).is_none());
        let mut duplicate = Vec::from(&control.0[..40]);
        duplicate.extend_from_slice(&control.0[..40]);
        assert!(parse_control(&duplicate).is_none());
    }

    /// Run only under `unshare -n` with loopback up and fe80::1/fe80::2
    /// assigned to it. This is a socket correctness test, not a timing test.
    #[test]
    #[ignore = "requires an explicitly prepared private Linux network namespace"]
    fn private_namespace_socket_io() {
        use std::net::UdpSocket;
        use std::time::{Duration, Instant};

        assert_eq!(
            std::env::var("ODHCPD_NETIO_PRIVATE_TEST").as_deref(),
            Ok("1")
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "refusing to test in the initial network namespace"
        );
        let link = Link {
            name: "lo".into(),
            index: 1,
            flags: 0,
            mtu: 65536,
            mac: [0; 6],
            addresses: Vec::new(),
        };
        let udp = Socket::open(Kind::Dhcp6, &link).unwrap();
        let router = Socket::open(Kind::Router, &link).unwrap();
        let sender = Socket::open(Kind::Router, &link).unwrap();
        let memberships = std::fs::read_to_string("/proc/net/igmp6").unwrap();
        for address in [
            "ff020000000000000000000000000002",
            "ff020000000000000000000000010002",
            "ff050000000000000000000000010003",
        ] {
            assert!(
                memberships.contains(address),
                "missing membership {address}"
            );
        }
        for socket in [&udp, &router] {
            let flags =
                std::fs::read_to_string(format!("/proc/self/fdinfo/{}", socket.as_raw_fd()))
                    .unwrap();
            let flags = flags
                .lines()
                .find_map(|line| line.strip_prefix("flags:\t"))
                .unwrap();
            let flags = u32::from_str_radix(flags, 8).unwrap();
            assert_ne!(flags & 0x800, 0, "missing NONBLOCK");
            assert_ne!(flags & 0x80000, 0, "missing CLOEXEC");
        }
        let client = UdpSocket::bind("[::1]:546").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.send_to(&[1, 2, 3, 4], "[::1]:547").unwrap();
        let packet = receive(&udp);
        assert_eq!(packet.bytes, [1, 2, 3, 4]);
        assert_eq!(packet.destination, Ipv6Addr::LOCALHOST);
        assert_eq!(packet.source.port(), 546);
        assert_eq!(packet.interface, 1);
        assert_eq!(packet.hop_limit, None);
        udp.send(&[7, 8, 9], packet.source, Some(Ipv6Addr::LOCALHOST))
            .unwrap();
        let mut reply = [0; 16];
        let (len, source) = client.recv_from(&mut reply).unwrap();
        assert_eq!(&reply[..len], &[7, 8, 9]);
        assert_eq!(source, "[::1]:547".parse().unwrap());

        // A datagram larger than the C-sized receive buffer must not be parsed
        // as a successful DHCPv6 message. The following complete packet remains.
        client.send_to(&[1; MAX_DATAGRAM + 1], "[::1]:547").unwrap();
        client.send_to(&[9], "[::1]:547").unwrap();
        assert!(udp.recv().unwrap().is_none());
        assert_eq!(receive(&udp).bytes, [9]);

        let from: Ipv6Addr = "fe80::2".parse().unwrap();
        let to: Ipv6Addr = "fe80::1".parse().unwrap();
        let destination = SocketAddrV6::new(to, 0, 0, 0); // scope added by send
        let rs = [133, 0, 0, 0, 0, 0, 0, 0];
        sender.send(&rs, destination, Some(from)).unwrap();
        let packet = receive(&router);
        assert_eq!(packet.source.ip(), &from);
        assert_eq!(packet.destination, to);
        assert_eq!(packet.interface, 1);
        assert_eq!(packet.hop_limit, Some(255));
        assert_eq!(packet.bytes[0], 133);
        assert_eq!(checksum(from, to, &packet.bytes), 0xffff);

        sender.set_int(IPPROTO_IPV6, 16, 64).unwrap();
        sender.send(&rs, destination, Some(from)).unwrap();
        assert!(router.recv().unwrap().is_none(), "accepted RS hoplimit 64");
        sender.set_int(IPPROTO_IPV6, 16, 255).unwrap();
        sender
            .send(&[128, 0, 0, 0, 0, 0, 0, 0], destination, Some(from))
            .unwrap();
        assert!(
            router.recv().unwrap().is_none(),
            "ICMP filter admitted echo"
        );
        let wrong_scope = SocketAddrV6::new(to, 0, 0, 2);
        assert_eq!(
            sender
                .send(&rs, wrong_scope, Some(from))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let mut wrong_index = link;
        wrong_index.index = 2;
        assert!(Socket::open(Kind::Router, &wrong_index).is_err());

        fn receive(socket: &Socket) -> Packet {
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                if let Some(packet) = socket.recv().unwrap() {
                    return packet;
                }
                assert!(Instant::now() < deadline, "packet was not delivered");
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn checksum(source: Ipv6Addr, destination: Ipv6Addr, data: &[u8]) -> u16 {
            let mut bytes = Vec::from(source.octets());
            bytes.extend(destination.octets());
            bytes.extend((data.len() as u32).to_be_bytes());
            bytes.extend([0, 0, 0, 58]);
            bytes.extend(data);
            if bytes.len() % 2 != 0 {
                bytes.push(0);
            }
            let mut sum: u32 = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u16::from_be_bytes([p[0], p[1]]) as u32)
                .sum();
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum as u16
        }
    }
}
