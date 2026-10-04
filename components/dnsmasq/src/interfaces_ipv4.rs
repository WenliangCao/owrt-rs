//! Owner-driven RTM_GETADDR snapshots. Exact C: netlink.c:173-260.
//! The netlink and ioctl descriptors are retained before privilege drop; a
//! packet lookup never opens a file or socket, including under EMFILE.

use super::Ipv4Interface;
use owrt_ubus::sys::{PollFd, POLLIN, POLLOUT};
use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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
    fn bind(fd: i32, address: *const Address, length: u32) -> i32;
    fn getsockname(fd: i32, address: *mut Address, length: *mut u32) -> i32;
    fn sendto(
        fd: i32,
        bytes: *const u8,
        length: usize,
        flags: i32,
        address: *const Address,
        address_length: u32,
    ) -> isize;
    fn recvfrom(
        fd: i32,
        bytes: *mut u8,
        length: usize,
        flags: i32,
        address: *mut Address,
        address_length: *mut u32,
    ) -> isize;
    fn ioctl(fd: i32, request: usize, argument: *mut u8) -> i32;
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Idle,
    Send,
    SendBlocked,
    Read,
}

/// A fresh, ordered IPv4 address dump for one DHCP packet. Partial dumps never
/// escape. Call begin once, then step from the existing owner until Some(rows).
/// Any hard error discards the partial dump; callers may begin a new request.
pub struct Ipv4Snapshot {
    fd: OwnedFd,
    port: u32,
    sequence: u32,
    state: State,
    bytes: Vec<u8>,
    rows: Vec<Ipv4Interface>,
}

impl Ipv4Snapshot {
    pub fn new() -> io::Result<Self> {
        // SAFETY: no pointers; a successful nonblocking CLOEXEC netlink socket
        // is immediately transferred to one OwnedFd.
        let raw = unsafe { socket(16, 3 | 0o4000 | 0o2000000, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address = Address {
            family: 16,
            ..Address::default()
        };
        // No multicast groups: resolver notifications have a separate owner.
        // SAFETY: sockaddr_nl is initialized and remains live for each call.
        if unsafe { bind(raw, &address, 12) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut length = 12;
        if unsafe { getsockname(raw, &mut address, &mut length) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if length != 12 || address.family != 16 {
            return Err(malformed());
        }
        Ok(Self {
            fd,
            port: address.pid,
            sequence: 0,
            state: State::Idle,
            bytes: vec![0; 512],
            rows: Vec::new(),
        })
    }

    pub fn begin(&mut self) -> io::Result<()> {
        if self.busy() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "IPv4 dump already pending",
            ));
        }
        self.sequence = self.sequence.wrapping_add(1).max(1);
        self.rows.clear();
        self.state = State::Send;
        Ok(())
    }

    pub fn busy(&self) -> bool {
        self.state != State::Idle
    }

    /// Newly queued or interrupted sends get one immediate owner turn. A
    /// socket that returned EAGAIN waits for readiness instead of spinning.
    pub fn runnable(&self) -> bool {
        self.state == State::Send
    }

    pub fn append_poll_fds(&self, fds: &mut Vec<PollFd>) {
        if self.busy() {
            fds.push(PollFd {
                fd: self.fd.as_raw_fd(),
                events: if self.state == State::Read {
                    POLLIN
                } else {
                    POLLOUT
                },
                revents: 0,
            });
        }
    }

    /// At most one send or one received datagram per call. The ioctl control
    /// socket is borrowed, so row decoding needs no spare process descriptor.
    pub fn step(&mut self, control: &UdpSocket) -> io::Result<Option<Vec<Ipv4Interface>>> {
        let result = self.advance(control);
        if result.is_err() {
            self.rows.clear();
            self.state = State::Idle;
        }
        result
    }

    fn advance(&mut self, control: &UdpSocket) -> io::Result<Option<Vec<Ipv4Interface>>> {
        if self.state == State::Idle {
            return Ok(None);
        }
        if self.state != State::Read {
            // C's nlmsghdr + rtgenmsg structure is padded to 20 bytes.
            let mut request = [0u8; 20];
            request[..4].copy_from_slice(&20u32.to_ne_bytes());
            request[4..6].copy_from_slice(&22u16.to_ne_bytes()); // RTM_GETADDR
            request[6..8].copy_from_slice(&0x305u16.to_ne_bytes()); // REQUEST|ACK|DUMP
            request[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
            request[16] = 2; // AF_INET
            let destination = Address {
                family: 16,
                ..Address::default()
            };
            // SAFETY: initialized request and sockaddr remain live for sendto.
            let sent = unsafe {
                sendto(
                    self.fd.as_raw_fd(),
                    request.as_ptr(),
                    request.len(),
                    0,
                    &destination,
                    12,
                )
            };
            if sent < 0 {
                let error = io::Error::last_os_error();
                return match error.kind() {
                    io::ErrorKind::WouldBlock => {
                        self.state = State::SendBlocked;
                        Ok(None)
                    }
                    io::ErrorKind::Interrupted => {
                        self.state = State::Send;
                        Ok(None)
                    }
                    _ => Err(error),
                };
            }
            if sent as usize != request.len() {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.state = State::Read;
            return Ok(None);
        }
        let mut peer = Address::default();
        let mut peer_length = 12;
        // SAFETY: writable buffers and sockaddr lengths are valid; PEEK|TRUNC
        // reports the complete datagram size without consuming it.
        let needed = unsafe {
            recvfrom(
                self.fd.as_raw_fd(),
                self.bytes.as_mut_ptr(),
                self.bytes.len(),
                0x22,
                &mut peer,
                &mut peer_length,
            )
        };
        if needed < 0 {
            return pending_read_error();
        }
        if needed == 0 {
            return Err(malformed());
        }
        let kernel = peer_length == 12 && peer.family == 16 && peer.pid == 0;
        if kernel && needed as usize > self.bytes.len() {
            self.bytes
                .try_reserve(needed as usize - self.bytes.len())
                .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "IPv4 dump buffer"))?;
            self.bytes.resize(needed as usize, 0);
        }
        peer_length = 12;
        // SAFETY: the same buffers are live; MSG_TRUNC explicitly detects a
        // clipped datagram. Consume even non-kernel input, but never trust it.
        let got = unsafe {
            recvfrom(
                self.fd.as_raw_fd(),
                self.bytes.as_mut_ptr(),
                self.bytes.len(),
                0x20,
                &mut peer,
                &mut peer_length,
            )
        };
        if got < 0 {
            return pending_read_error();
        }
        if !kernel || peer_length != 12 || peer.family != 16 || peer.pid != 0 {
            return Ok(None);
        }
        if got != needed || got as usize > self.bytes.len() {
            return Err(malformed());
        }
        let done = decode(
            &self.bytes[..got as usize],
            self.port,
            self.sequence,
            &mut self.rows,
            |index| interface_flags(control, index),
        )?;
        if done {
            self.state = State::Idle;
            return Ok(Some(std::mem::take(&mut self.rows)));
        }
        Ok(None)
    }
}

fn pending_read_error() -> io::Result<Option<Vec<Ipv4Interface>>> {
    let error = io::Error::last_os_error();
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
        _ => Err(error),
    }
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid IPv4 address dump")
}

fn interface_flags(control: &UdpSocket, index: u32) -> io::Result<u16> {
    let name = crate::net::interface_name(control, index)?;
    let mut request = [0u64; 5];
    // SAFETY: aligned 40-byte Linux ifreq, initialized before ioctl.
    let bytes = unsafe { std::slice::from_raw_parts_mut(request.as_mut_ptr().cast::<u8>(), 40) };
    bytes[..16].copy_from_slice(&name);
    if unsafe { ioctl(control.as_raw_fd(), 0x8913, bytes.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u16::from_ne_bytes(bytes[16..18].try_into().unwrap()))
}

fn status(bytes: &[u8], empty_ok: bool) -> io::Result<()> {
    if empty_ok && bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() < 4 {
        return Err(malformed());
    }
    let code = i32::from_ne_bytes(bytes[..4].try_into().unwrap());
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.saturating_neg()))
    }
}

fn decode(
    bytes: &[u8],
    port: u32,
    sequence: u32,
    rows: &mut Vec<Ipv4Interface>,
    mut flags: impl FnMut(u32) -> io::Result<u16>,
) -> io::Result<bool> {
    let mut at = 0;
    while at < bytes.len() {
        if bytes.len() - at < 16 {
            return Err(malformed());
        }
        let length = u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        if length < 16 || length > bytes.len() - at {
            return Err(malformed());
        }
        let header = &bytes[at..at + 16];
        let payload = &bytes[at + 16..at + length];
        let kind = u16::from_ne_bytes(header[4..6].try_into().unwrap());
        let current = u32::from_ne_bytes(header[8..12].try_into().unwrap()) == sequence
            && u32::from_ne_bytes(header[12..16].try_into().unwrap()) == port;
        if current {
            if u16::from_ne_bytes(header[6..8].try_into().unwrap()) & 0x10 != 0 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            match kind {
                2 => status(payload, false)?, // NLMSG_ERROR / ACK
                3 => {
                    status(payload, true)?;
                    return Ok(true);
                }
                20 => {
                    if let Some(row) = address_row(payload, &mut flags)? {
                        rows.push(row);
                    }
                }
                _ => {}
            }
        }
        at += (length + 3) & !3;
        if at > bytes.len() && at - bytes.len() > 3 {
            return Err(malformed());
        }
    }
    Ok(false)
}

fn address_row(
    bytes: &[u8],
    flags: &mut impl FnMut(u32) -> io::Result<u16>,
) -> io::Result<Option<Ipv4Interface>> {
    if bytes.len() < 8 {
        return Err(malformed());
    }
    if bytes[0] != 2 {
        return Ok(None);
    }
    let prefix = bytes[1];
    if prefix > 32 {
        return Err(malformed());
    }
    let index = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
    let mut local = Ipv4Addr::UNSPECIFIED;
    let mut broadcast = Ipv4Addr::UNSPECIFIED;
    let mut at = 8;
    while at < bytes.len() {
        if bytes.len() - at < 4 {
            return Err(malformed());
        }
        let length = usize::from(u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap()));
        let kind = u16::from_ne_bytes(bytes[at + 2..at + 4].try_into().unwrap());
        if length < 4 || length > bytes.len() - at {
            return Err(malformed());
        }
        if matches!(kind, 2 | 4) {
            if length < 8 {
                return Err(malformed());
            }
            let value = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[at + 4..at + 8]).unwrap());
            if kind == 2 {
                local = value;
            } else {
                broadcast = value;
            }
        }
        at += (length + 3) & !3;
    }
    if local.is_unspecified() {
        return Ok(None);
    }
    let flags = flags(index)?;
    if flags & 1 == 0 {
        return Ok(None);
    }
    let netmask = Ipv4Addr::from(if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    });
    Ok(Some(Ipv4Interface {
        index,
        address: local,
        netmask,
        broadcast,
        loopback: flags & 8 != 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(index: u32, prefix: u8, local: Option<[u8; 4]>, broadcast: Option<[u8; 4]>) -> Vec<u8> {
        let mut bytes = vec![2, prefix, 0, 0];
        bytes.extend_from_slice(&index.to_ne_bytes());
        // IFA_ADDRESS is a peer on point-to-point links and is not a local
        // fallback. Include one in every fixture to make that guard observable.
        for (kind, value) in [(1u16, Some([198, 51, 100, 99])), (2, local), (4, broadcast)] {
            if let Some(value) = value {
                bytes.extend_from_slice(&8u16.to_ne_bytes());
                bytes.extend_from_slice(&kind.to_ne_bytes());
                bytes.extend_from_slice(&value);
            }
        }
        bytes
    }

    fn message(kind: u16, flags: u16, seq: u32, port: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(16u32 + payload.len() as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&seq.to_ne_bytes());
        bytes.extend_from_slice(&port.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    #[test]
    fn ordered_local_rows_keep_aliases_prefixes_and_explicit_broadcast() {
        let mut wire = message(20, 2, 4, 7, &row(11, 24, Some([192, 0, 2, 2]), None));
        wire.extend(message(
            20,
            2,
            4,
            7,
            &row(11, 0, Some([192, 0, 2, 1]), Some([192, 0, 2, 1])),
        ));
        wire.extend(message(
            20,
            2,
            4,
            7,
            &row(12, 32, Some([127, 0, 0, 1]), None),
        ));
        wire.extend(message(
            20,
            2,
            4,
            7,
            &row(13, 24, Some([192, 0, 2, 3]), None),
        ));
        wire.extend(message(20, 2, 4, 7, &row(11, 24, None, None)));
        let mut rows = Vec::new();
        assert!(!decode(&wire, 7, 4, &mut rows, |index| Ok(match index {
            12 => 9,
            13 => 0,
            _ => 1,
        }))
        .unwrap());
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows.iter().map(|r| r.address.octets()).collect::<Vec<_>>(),
            [[192, 0, 2, 2], [192, 0, 2, 1], [127, 0, 0, 1]]
        );
        assert_eq!(rows[0].netmask.octets(), [255, 255, 255, 0]);
        assert_eq!(rows[0].broadcast, Ipv4Addr::UNSPECIFIED);
        assert_eq!(rows[1].netmask, Ipv4Addr::UNSPECIFIED);
        assert_eq!(rows[1].broadcast, rows[1].address);
        assert_eq!(rows[2].netmask.octets(), [255; 4]);
        assert!(rows[2].loopback);
        assert!(decode(
            &message(3, 2, 4, 7, &[]),
            7,
            4,
            &mut rows,
            |_| unreachable!()
        )
        .unwrap());
    }

    #[test]
    fn stale_sequences_and_other_recipients_cannot_publish_a_dump() {
        let mut rows = Vec::new();
        for (sequence, port) in [(3, 7), (4, 8)] {
            let mut wire = message(
                20,
                2,
                sequence,
                port,
                &row(11, 24, Some([192, 0, 2, 1]), None),
            );
            wire.extend(message(3, 2, sequence, port, &[]));
            assert!(!decode(&wire, 7, 4, &mut rows, |_| panic!(
                "stale row reached ioctl"
            ))
            .unwrap());
        }
        assert!(rows.is_empty());
        assert!(!decode(
            &message(2, 0, 4, 7, &0i32.to_ne_bytes()),
            7,
            4,
            &mut rows,
            |_| unreachable!()
        )
        .unwrap());
    }

    #[test]
    fn malformed_interrupted_and_kernel_error_dumps_are_not_successes() {
        let mut rows = Vec::new();
        for wire in [
            vec![0; 15],
            message(20, 2, 4, 7, &[2]),
            message(20, 2, 4, 7, &row(11, 33, Some([192, 0, 2, 1]), None)),
            message(2, 0, 4, 7, &[0; 3]),
            message(3, 0, 4, 7, &[0; 3]),
        ] {
            assert_eq!(
                decode(&wire, 7, 4, &mut rows, |_| Ok(1))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            decode(&message(3, 0x10, 4, 7, &[]), 7, 4, &mut rows, |_| Ok(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        for kind in [2, 3] {
            assert_eq!(
                decode(
                    &message(kind, 0, 4, 7, &(-105i32).to_ne_bytes()),
                    7,
                    4,
                    &mut rows,
                    |_| Ok(1)
                )
                .unwrap_err()
                .raw_os_error(),
                Some(105)
            );
        }
        assert_eq!(
            decode(
                &message(20, 2, 4, 7, &row(11, 24, Some([192, 0, 2, 1]), None)),
                7,
                4,
                &mut rows,
                |_| Err(io::Error::from_raw_os_error(19))
            )
            .unwrap_err()
            .raw_os_error(),
            Some(19)
        );
    }

    fn complete(snapshot: &mut Ipv4Snapshot, control: &UdpSocket) -> Vec<Ipv4Interface> {
        extern "C" {
            fn poll(fds: *mut PollFd, count: usize, timeout: i32) -> i32;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        snapshot.begin().unwrap();
        assert!(snapshot.runnable());
        assert!(snapshot.begin().is_err());
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "IPv4 dump completion deadline"
            );
            if !snapshot.runnable() {
                let mut fds = Vec::new();
                snapshot.append_poll_fds(&mut fds);
                assert_eq!(fds.len(), 1);
                // SAFETY: the initialized PollFd stays live through poll.
                assert!(unsafe { poll(fds.as_mut_ptr(), fds.len(), 100) } >= 0);
            }
            if let Some(rows) = snapshot.step(control).unwrap() {
                assert!(!snapshot.busy());
                return rows;
            }
        }
    }

    #[test]
    #[ignore = "requires a private Linux network namespace and process file limit"]
    fn isolated_fresh_snapshot_and_primary_address_need_no_spare_descriptor() {
        assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
        let control = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let mut snapshot = Ipv4Snapshot::new().unwrap();
        let first = complete(&mut snapshot, &control);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].address, Ipv4Addr::LOCALHOST);
        assert!(first[0].loopback);
        assert!(std::process::Command::new("ip")
            .args(["addr", "add", "192.0.2.7/24", "dev", "lo"])
            .status()
            .unwrap()
            .success());
        let expected = super::super::ipv4_interfaces().unwrap();
        assert_eq!(expected.len(), 2);
        extern "C" {
            fn getrlimit(resource: i32, limit: *mut [u64; 2]) -> i32;
            fn setrlimit(resource: i32, limit: *const [u64; 2]) -> i32;
        }
        struct Restore([u64; 2]);
        impl Drop for Restore {
            fn drop(&mut self) {
                assert_eq!(unsafe { setrlimit(7, &self.0) }, 0);
            }
        }
        let mut previous = [0; 2];
        assert_eq!(unsafe { getrlimit(7, &mut previous) }, 0);
        let restore = Restore(previous);
        assert_eq!(unsafe { setrlimit(7, &[64, previous[1]]) }, 0);
        let mut occupied = Vec::new();
        loop {
            match std::fs::File::open("/dev/null") {
                Ok(file) => occupied.push(file),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(24));
                    break;
                }
            }
        }
        let actual = complete(&mut snapshot, &control);
        assert_eq!(actual, expected);
        assert_eq!(
            super::super::primary_ipv4(actual[0].index, &control).unwrap(),
            Ipv4Addr::LOCALHOST
        );
        assert_eq!(
            std::fs::File::open("/dev/null").unwrap_err().raw_os_error(),
            Some(24)
        );
        drop(restore);
        drop(occupied);
        assert!(std::process::Command::new("ip")
            .args(["addr", "del", "192.0.2.7/24", "dev", "lo"])
            .status()
            .unwrap()
            .success());
        assert_eq!(complete(&mut snapshot, &control), first);
    }
}
