//! Linux 64-bit datagram boundary. DNS/DHCP/TFTP policy stays in Rust callers.
//! C reference: network.c:936–1009; forward.c:32–119,1635–1796.
//! Reuses the repository's audited iovec/msghdr layout and readiness backend.

use owrt_ubus::sys::{IoVec, MsgHdr};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const SOCK_DGRAM: i32 = 2;
const SOCK_CLOEXEC: i32 = 0o2000000;
const SOCK_NONBLOCK: i32 = 0o4000;
const IPPROTO_IP: i32 = 0;
const IPPROTO_IPV6: i32 = 41;
const IP_PKTINFO: i32 = 8;
const IPV6_V6ONLY: i32 = 26;
const IPV6_RECVPKTINFO: i32 = 49;
const IPV6_PKTINFO: i32 = 50;
const MSG_TRUNC: i32 = 32;
const MSG_CTRUNC: i32 = 8;

extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn bind(fd: i32, address: *const u8, len: u32) -> i32;
    fn setsockopt(fd: i32, level: i32, option: i32, value: *const i32, len: u32) -> i32;
    fn recvmsg(fd: i32, message: *mut MsgHdr, flags: i32) -> isize;
    fn sendmsg(fd: i32, message: *const MsgHdr, flags: i32) -> isize;
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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
            AF_INET6 if len >= 28 => Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap()),
                port,
                0,
                u32::from_ne_bytes(b[24..28].try_into().unwrap()),
            ))),
            _ => Err(invalid("unexpected peer address family")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Datagram {
    pub len: usize,
    pub peer: SocketAddr,
    pub destination: IpAddr,
    pub interface: u32,
}

pub struct DatagramSocket {
    socket: UdpSocket,
    ipv6: bool,
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

impl DatagramSocket {
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
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
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh UDP socket; UdpSocket now owns every close path.
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        set_flag(fd, 1, 2)?; // SOL_SOCKET, SO_REUSEADDR (no SO_REUSEPORT).
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
        } else {
            set_flag(fd, IPPROTO_IP, IP_PKTINFO)?;
        }
        Ok(Self { socket, ipv6 })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Truncated datagrams/ancillary data and zero source ports are discarded.
    /// Only initialized `buffer[..len]` is returned for protocol processing.
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
        // SAFETY: initialized control array, bounded by its actual allocation.
        let bytes = unsafe {
            std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), msg.controllen.min(40))
        };
        let Some((destination, interface)) = packet_info(bytes, self.ipv6) else {
            return Ok(None);
        };
        Ok(Some(Datagram {
            len: len as usize,
            peer,
            destination,
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
                IpAddr::V4(v) => b[20..24].copy_from_slice(&v.octets()),
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
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

fn packet_info(mut bytes: &[u8], ipv6: bool) -> Option<(IpAddr, u32)> {
    while bytes.len() >= 16 {
        let len = usize::from_ne_bytes(bytes[..8].try_into().ok()?);
        if len < 16 || len > bytes.len() {
            return None;
        }
        let level = i32::from_ne_bytes(bytes[8..12].try_into().ok()?);
        let kind = i32::from_ne_bytes(bytes[12..16].try_into().ok()?);
        if !ipv6 && level == IPPROTO_IP && kind == IP_PKTINFO && len >= 28 {
            return Some((
                IpAddr::V4(Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23])),
                u32::from_ne_bytes(bytes[16..20].try_into().ok()?),
            ));
        }
        if ipv6 && level == IPPROTO_IPV6 && kind == IPV6_PKTINFO && len >= 36 {
            return Some((
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
