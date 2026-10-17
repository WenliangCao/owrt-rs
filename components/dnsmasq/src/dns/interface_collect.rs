//! Nonblocking network.c/netlink.c interface-record enumeration.
//! The parent calls begin only at a C enumeration boundary. A failure opening
//! the control socket precedes clear; later failures publish the received prefix.
use dnsmasq_platform::{IoVec, MsgHdr, bind, getsockname, recvmsg, sendto};
use super::interface_records::InterfaceAddress;
use owrt_ubus::sys::{PollFd, POLLIN, POLLOUT};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

#[repr(C)]
#[derive(Default)]
struct Address {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}
extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn ioctl(fd: i32, request: usize, argument: *mut u8) -> i32;
}
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
        // SAFETY: no pointer arguments. Every successful FD has one owner.
        let raw = unsafe { socket(16, 3 | 0o4000 | 0o2000000, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket returned this nonnegative fresh fd; transfer ownership once.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut endpoint = Address {
            family: 16,
            ..Address::default()
        };
        // SAFETY: the initialized repr(C) sockaddr_nl is exactly 12 live bytes.
        if unsafe { bind(raw, (&endpoint as *const Address).cast(), 12) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut length = 12;
        // SAFETY: output sockaddr and its initialized capacity remain writable.
        if unsafe { getsockname(raw, (&mut endpoint as *mut Address).cast(), &mut length) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if length != 12 || endpoint.family != 16 {
            return Err(malformed());
        }
        Ok(Self {
            socket,
            port: endpoint.pid,
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
        // SAFETY: socket has scalar arguments; a successful fd gets one owner below.
        let raw = unsafe { socket(2, 2 | 0o2000000, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this is the fresh successful control fd, never borrowed elsewhere.
        self.control = Some(unsafe { OwnedFd::from_raw_fd(raw) });
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
            let destination = Address {
                family: 16,
                ..Address::default()
            };
            // SAFETY: bounded request and sockaddr storage are live through sendto.
            let result = unsafe {
                sendto(
                    self.socket.as_raw_fd(),
                    request.as_ptr().cast(),
                    request.len(),
                    0,
                    (&destination as *const Address).cast(),
                    12,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                return match error.kind() {
                    io::ErrorKind::WouldBlock => {
                        self.state = State::SendBlocked;
                        Ok(false)
                    }
                    io::ErrorKind::Interrupted => Ok(false),
                    _ => Err(error),
                };
            }
            if result as usize != request.len() {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.state = State::Read;
            return Ok(false);
        }
        // netlink_recv peeks to size then consumes. A peek error other than
        // EAGAIN/EINTR still reaches the real read, matching C's recovery.
        let (needed, _, _) = self.receive(0x22);
        if needed < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Ok(false);
            }
        } else if needed as usize > self.bytes.len() {
            self.bytes
                .try_reserve(needed as usize - self.bytes.len())
                .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "interface dump buffer"))?;
            self.bytes.resize(needed as usize, 0);
        }
        let (received, peer, flags) = self.receive(0);
        if received < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(false)
            } else {
                Err(error)
            };
        }
        if peer.pid != 0 {
            return Ok(false);
        }
        if flags & 0x20 != 0 || received as usize > self.bytes.len() {
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
                            self.control.as_ref().unwrap().as_raw_fd(),
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
    fn receive(&mut self, flags: i32) -> (isize, Address, i32) {
        let mut peer = Address::default();
        let mut vector = IoVec {
            base: self.bytes.as_mut_ptr(),
            len: self.bytes.len(),
        };
        let mut message = MsgHdr {
            name: (&mut peer as *mut Address).cast(),
            namelen: 12,
            iov: &mut vector,
            iovlen: 1,
            control: std::ptr::null_mut(),
            controllen: 0,
            flags: 0,
        };
        // SAFETY: msghdr/iovec/sockaddr and writable byte storage remain live.
        let received = unsafe { recvmsg(self.socket.as_raw_fd(), &mut message, flags) };
        (received, peer, message.flags)
    }
}
fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid interface address dump")
}
fn decode(
    bytes: &[u8],
    family: u8,
    control: i32,
) -> io::Result<Option<(InterfaceAddress, crate::interfaces::DnsInterface)>> {
    if bytes.len() < 8 {
        return Err(malformed());
    }
    if bytes[0] != family {
        return Ok(None);
    }
    let index = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
    let mut request = [0u64; 5];
    // SAFETY: [u64;5] provides all 40 aligned Linux64 ifreq bytes, exclusively borrowed.
    let raw = unsafe { std::slice::from_raw_parts_mut(request.as_mut_ptr().cast::<u8>(), 40) };
    raw[16..20].copy_from_slice(&index.to_ne_bytes());
    // SAFETY: live owned control fd and initialized 40-byte ifreq; SIOCGIFNAME writes within it.
    if unsafe { ioctl(control, 0x8910, raw.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut label = raw[..16].split(|&byte| byte == 0).next().unwrap().to_vec();
    // SAFETY: SIOCGIFFLAGS uses that same live, aligned ifreq after name initialization.
    if unsafe { ioctl(control, 0x8913, raw.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let loopback = u16::from_ne_bytes(raw[16..18].try_into().unwrap()) & 8 != 0;
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
