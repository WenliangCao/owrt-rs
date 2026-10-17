//! Nonblocking network.c/netlink.c interface-record enumeration.
//! The parent calls begin only at a C enumeration boundary. A failure opening
//! the control socket precedes clear; later failures publish the received prefix.
use super::interface_records::InterfaceAddress;
use owrt_ubus::sys::{PollFd, POLLIN, POLLOUT};
use rustix::net::{
    self, netlink::SocketAddrNetlink, AddressFamily, RecvAncillaryBuffer, RecvFlags, RecvMsg,
    ReturnFlags, SendFlags, SocketFlags, SocketType,
};
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Idle,
    Send,
    SendBlocked,
    Read,
}

pub struct Enumeration {
    pub addresses: Vec<InterfaceAddress>,
    pub interfaces: Vec<crate::interfaces::DnsInterface>,
    /// None means both family dumps completed. The addresses remain the
    /// observable C prefix when a later failure interrupts enumeration.
    pub error: Option<io::Error>,
}

pub struct InterfaceCollector {
    socket: OwnedFd,
    port: u32,
    sequence: u32,
    family: u8,
    state: State,
    control: Option<OwnedFd>,
    bytes: Vec<u8>,
    addresses: Vec<InterfaceAddress>,
    interfaces: Vec<crate::interfaces::DnsInterface>,
    deadline: Instant,
}

impl InterfaceCollector {
    pub fn new() -> io::Result<Self> {
        let socket = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        net::bind(&socket, &SocketAddrNetlink::new(0, 0))?;
        let endpoint = net::getsockname(&socket)?;
        if endpoint.addr_len() != 12 {
            return Err(malformed());
        }
        let endpoint = SocketAddrNetlink::try_from(endpoint).map_err(|_| malformed())?;
        Ok(Self {
            socket,
            port: endpoint.pid(),
            sequence: 0,
            family: 10,
            state: State::Idle,
            control: None,
            bytes: vec![0; 512],
            addresses: Vec::new(),
            interfaces: Vec::new(),
            deadline: Instant::now(),
        })
    }

    /// An error here occurs before C clears its published interface lists.
    pub fn begin(&mut self) -> io::Result<()> {
        if self.busy() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        self.control = Some(net::socket_with(
            AddressFamily::INET,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )?);
        self.addresses.clear();
        self.interfaces.clear();
        self.deadline = Instant::now() + Duration::from_secs(3);
        self.start_family(10);
        Ok(())
    }

    fn start_family(&mut self, family: u8) {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        self.family = family;
        self.state = State::Send;
    }
    pub fn busy(&self) -> bool {
        self.state != State::Idle
    }
    pub fn runnable(&self) -> bool {
        self.state == State::Send
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.busy().then_some(self.deadline)
    }
    pub fn append_poll_fds(&self, fds: &mut Vec<PollFd>) {
        if self.busy() {
            fds.push(PollFd {
                fd: self.socket.as_raw_fd(),
                events: if self.state == State::Read {
                    POLLIN
                } else {
                    POLLOUT
                },
                revents: 0,
            });
        }
    }

    /// One send or one received datagram; no readiness wait, thread or file I/O.
    pub fn step(&mut self) -> Option<Enumeration> {
        if !self.busy() {
            return None;
        }
        if Instant::now() >= self.deadline {
            return Some(self.finish(Some(io::ErrorKind::TimedOut.into())));
        }
        match self.advance() {
            Ok(true) => Some(self.finish(None)),
            Ok(false) => None,
            Err(error) if error.raw_os_error() == Some(105) => {
                // ENOBUFS makes C restart from a clear IPv6 dump.
                self.addresses.clear();
                self.interfaces.clear();
                self.start_family(10);
                None
            }
            Err(error) => Some(self.finish(Some(error))),
        }
    }
    fn finish(&mut self, error: Option<io::Error>) -> Enumeration {
        self.state = State::Idle;
        self.control = None;
        Enumeration {
            addresses: std::mem::take(&mut self.addresses),
            interfaces: std::mem::take(&mut self.interfaces),
            error,
        }
    }
    fn advance(&mut self) -> io::Result<bool> {
        if self.state != State::Read {
            let mut request = [0u8; 20];
            request[..4].copy_from_slice(&20u32.to_ne_bytes());
            request[4..6].copy_from_slice(&22u16.to_ne_bytes());
            request[6..8].copy_from_slice(&0x305u16.to_ne_bytes());
            request[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
            request[16] = self.family;
            let result = match net::sendto(
                &self.socket,
                &request,
                SendFlags::empty(),
                &SocketAddrNetlink::new(0, 0),
            ) {
                Ok(result) => result,
                Err(error) => {
                    let error = io::Error::from(error);
                    return match error.kind() {
                        io::ErrorKind::WouldBlock => {
                            self.state = State::SendBlocked;
                            Ok(false)
                        }
                        io::ErrorKind::Interrupted => Ok(false),
                        _ => Err(error),
                    };
                }
            };
            if result != request.len() {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.state = State::Read;
            return Ok(false);
        }
        // netlink_recv peeks to size then consumes. A peek error other than
        // EAGAIN/EINTR still reaches the real read, matching C's recovery.
        match self.receive(RecvFlags::PEEK | RecvFlags::TRUNC) {
            Err(error)
                if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::INTR =>
            {
                return Ok(false);
            }
            Ok(message) if message.bytes > self.bytes.len() => {
                self.bytes
                    .try_reserve(message.bytes - self.bytes.len())
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::OutOfMemory, "interface dump buffer")
                    })?;
                self.bytes.resize(message.bytes, 0);
            }
            _ => {} // Other peek errors still reach the consuming read.
        }
        let message = match self.receive(RecvFlags::empty()) {
            Ok(message) => message,
            Err(error) => {
                let error = io::Error::from(error);
                return if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    Ok(false)
                } else {
                    Err(error)
                };
            }
        };
        let kernel = message
            .address
            .filter(|peer| peer.addr_len() >= 12)
            .and_then(|peer| SocketAddrNetlink::try_from(peer).ok())
            .is_some_and(|peer| peer.pid() == 0);
        if !kernel {
            return Ok(false);
        }
        let received = message.bytes;
        if message.flags.contains(ReturnFlags::TRUNC) || received > self.bytes.len() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        let mut at = 0;
        while at + 16 <= received as usize {
            let length = u32::from_ne_bytes(self.bytes[at..at + 4].try_into().unwrap()) as usize;
            if length < 16 || at + length > received as usize {
                return Err(malformed());
            }
            let kind = u16::from_ne_bytes(self.bytes[at + 4..at + 6].try_into().unwrap());
            let sequence = u32::from_ne_bytes(self.bytes[at + 8..at + 12].try_into().unwrap());
            let port = u32::from_ne_bytes(self.bytes[at + 12..at + 16].try_into().unwrap());
            if sequence == self.sequence && port == self.port {
                match kind {
                    3 => {
                        if self.family == 10 {
                            self.start_family(2);
                            return Ok(false);
                        }
                        return Ok(true);
                    }
                    2 => {
                        if length < 20 {
                            return Err(malformed());
                        }
                        let errno =
                            i32::from_ne_bytes(self.bytes[at + 16..at + 20].try_into().unwrap());
                        if errno != 0 {
                            return Err(io::Error::from_raw_os_error(errno.saturating_neg()));
                        }
                    }
                    20 => {
                        if let Some((row, interface)) = decode(
                            &self.bytes[at + 16..at + length],
                            self.family,
                            // Only begin enters active states; finish drops control
                            // after parsing and returns to Idle. Active reads own it.
                            self.control.as_ref().unwrap(),
                        )? {
                            // whine_malloc failure omits this individual C row.
                            if self.addresses.try_reserve(1).is_ok() {
                                self.addresses.push(row);
                            }
                            // Interface-record nodes and listener metadata are
                            // independent C allocations. A record omission must
                            // not remove an existing listener's admission state.
                            if self.interfaces.try_reserve(1).is_ok() {
                                self.interfaces.push(interface);
                            }
                        }
                    }
                    _ => {}
                }
            }
            at += (length + 3) & !3;
        }
        Ok(false)
    }
    fn receive(&mut self, flags: RecvFlags) -> rustix::io::Result<RecvMsg> {
        let mut vectors = [IoSliceMut::new(&mut self.bytes)];
        net::recvmsg(
            &self.socket,
            &mut vectors,
            &mut RecvAncillaryBuffer::default(),
            flags,
        )
    }
}
fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid interface address dump")
}
fn decode(
    bytes: &[u8],
    family: u8,
    control: &OwnedFd,
) -> io::Result<Option<(InterfaceAddress, crate::interfaces::DnsInterface)>> {
    if bytes.len() < 8 {
        return Err(malformed());
    }
    if bytes[0] != family {
        return Ok(None);
    }
    let index = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
    let name = dnsmasq_platform::interfaces::interface_name(control, index)?;
    let mut label = name.split(|&byte| byte == 0).next().unwrap().to_vec();
    let loopback = dnsmasq_platform::interfaces::interface_flags(control, &name)? & 8 != 0;
    let mut local = None;
    let mut fallback = None;
    let mut at = 8;
    while at + 4 <= bytes.len() {
        let length = u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[at + 2..at + 4].try_into().unwrap());
        if length < 4 || at + length > bytes.len() {
            return Err(malformed());
        }
        let value = &bytes[at + 4..at + length];
        let address = match (family, value.len()) {
            (2, 4) => Some(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(value).unwrap(),
            ))),
            (10, 16) => Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(value).unwrap(),
            ))),
            _ => None,
        };
        match kind {
            1 if family == 10 => fallback = address,
            2 => local = address,
            3 if family == 2 => label = value.split(|&byte| byte == 0).next().unwrap().to_vec(),
            _ => {}
        }
        at += (length + 3) & !3;
    }
    let Some(address) = local.or(fallback) else {
        return Ok(None);
    };
    if address.is_unspecified() {
        return Ok(None);
    }
    let netmask = if family == 2 {
        IpAddr::V4(Ipv4Addr::from(
            u32::MAX.wrapping_shl(32u32.wrapping_sub(u32::from(bytes[1]))),
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(
            u128::MAX
                .checked_shl(128u32.wrapping_sub(u32::from(bytes[1])))
                .unwrap_or(0),
        ))
    };
    let interface = crate::interfaces::DnsInterface {
        index,
        name: label.clone(),
        address,
        netmask,
        loopback,
        tentative: bytes[2] & 0x40 != 0,
    };
    Ok(Some((
        InterfaceAddress {
            label,
            address,
            prefix: bytes[1],
            flags: bytes[2],
        },
        interface,
    )))
}
