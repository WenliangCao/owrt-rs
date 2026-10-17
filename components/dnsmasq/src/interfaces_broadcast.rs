//! Linux address attributes distinguish an absent broadcast from IFA_ADDRESS.
//! getifaddrs uses one union for broadcast/destination and loses that distinction.

use dnsmasq_platform::{bind, sendto, setsockopt};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const AF_NETLINK: i32 = 16;
const SEQUENCE: u32 = 1;

#[repr(C)]
struct Address {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn recv(fd: i32, bytes: *mut u8, length: usize, flags: i32) -> isize;
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid IPv4 address dump")
}

fn dump_end(payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    if payload.len() < 4 {
        return Err(malformed());
    }
    let error = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(error.saturating_neg()))
    }
}

fn align(length: usize) -> usize {
    (length + 3) & !3
}

fn address(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn attributes(bytes: &[u8]) -> io::Result<Option<(u32, Ipv4Addr, Ipv4Addr)>> {
    if bytes.len() < 8 {
        return Err(malformed());
    }
    if bytes[0] != 2 {
        return Ok(None);
    }
    let index = u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let mut local = None;
    let mut broadcast = Ipv4Addr::UNSPECIFIED;
    let mut at = 8;
    while at + 4 <= bytes.len() {
        let length = usize::from(u16::from_ne_bytes([bytes[at], bytes[at + 1]]));
        let kind = u16::from_ne_bytes([bytes[at + 2], bytes[at + 3]]);
        if length < 4 || at + length > bytes.len() {
            return Err(malformed());
        }
        if matches!(kind, 2 | 4) {
            if length < 8 {
                return Err(malformed());
            }
            let value = address(&bytes[at + 4..at + 8]);
            if kind == 2 {
                // IFA_LOCAL; IFA_ADDRESS is deliberately not a fallback.
                local = Some(value);
            } else {
                // IFA_BROADCAST
                broadcast = value;
            }
        }
        at += align(length);
    }
    Ok(local.map(|local| (index, local, broadcast)))
}

/// Read only the kernel's IPv4 local/broadcast pairs, retaining secondary rows.
pub(super) fn snapshot() -> io::Result<Vec<(u32, Ipv4Addr, Ipv4Addr)>> {
    // SAFETY: socket has no pointer arguments; the returned descriptor is owned
    // exactly once and all request/response storage below outlives each syscall.
    let raw = unsafe { socket(AF_NETLINK, 3 | 0x80000, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket creation returned a unique live descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let endpoint = Address {
        family: AF_NETLINK as u16,
        pad: 0,
        pid: 0,
        groups: 0,
    };
    // SAFETY: Address is the initialized repr(C) 12-byte Linux sockaddr_nl;
    // its storage and the socket remain live for this synchronous call.
    if unsafe { bind(socket.as_raw_fd(), (&endpoint as *const Address).cast(), 12) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // Linux 64-bit timeval. A lost/interrupted dump must fail this packet's
    // interface lookup rather than leave the single-threaded daemon blocked.
    let timeout = [2i64, 0];
    // SAFETY: SO_RCVTIMEO reads the live, aligned 16-byte Linux 64-bit timeval.
    if unsafe { setsockopt(socket.as_raw_fd(), 1, 20, timeout.as_ptr().cast(), 16) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut request = [0u8; 24];
    request[..4].copy_from_slice(&24u32.to_ne_bytes());
    request[4..6].copy_from_slice(&22u16.to_ne_bytes()); // RTM_GETADDR
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
    request[16] = 2; // AF_INET
                     // SAFETY: the initialized request and destination outlive sendto and the
                     // passed lengths match their complete storage.
    if unsafe {
        sendto(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&endpoint as *const Address).cast(),
            12,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut rows = Vec::new();
    loop {
        let mut first = 0u8;
        // SAFETY: recv writes at most one byte to first; MSG_TRUNC may return
        // a larger datagram size but does not increase the writable length.
        let length = unsafe { recv(socket.as_raw_fd(), &mut first, 1, 0x22) }; // PEEK | TRUNC
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length == 0 {
            return Err(malformed());
        }
        let mut bytes = vec![0; length as usize];
        // SAFETY: recv is given the full initialized writable buffer length.
        let received = unsafe { recv(socket.as_raw_fd(), bytes.as_mut_ptr(), bytes.len(), 0) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received != length {
            return Err(malformed());
        }
        let mut at = 0;
        while at + 16 <= bytes.len() {
            let length =
                u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
                    as usize;
            if length < 16 || at + length > bytes.len() {
                return Err(malformed());
            }
            let kind = u16::from_ne_bytes([bytes[at + 4], bytes[at + 5]]);
            let flags = u16::from_ne_bytes([bytes[at + 6], bytes[at + 7]]);
            let sequence =
                u32::from_ne_bytes([bytes[at + 8], bytes[at + 9], bytes[at + 10], bytes[at + 11]]);
            if sequence != SEQUENCE {
                return Err(malformed());
            }
            if flags & 0x10 != 0 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let payload = &bytes[at + 16..at + length];
            match kind {
                3 => {
                    // NLMSG_DONE may carry a dump error.
                    dump_end(payload)?;
                    return Ok(rows);
                }
                2 => {
                    if payload.len() < 4 {
                        return Err(malformed());
                    }
                    let error =
                        i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(error.saturating_neg()));
                    }
                }
                20 => {
                    // RTM_NEWADDR
                    if let Some(row) = attributes(payload)? {
                        rows.push(row);
                    }
                }
                _ => {}
            }
            at += align(length);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_end_propagates_kernel_errors_and_rejects_truncated_status() {
        assert!(dump_end(&[]).is_ok());
        assert!(dump_end(&0i32.to_ne_bytes()).is_ok());
        assert_eq!(
            dump_end(&(-4i32).to_ne_bytes()).unwrap_err().raw_os_error(),
            Some(4)
        );
        assert_eq!(
            dump_end(&[0, 0, 0]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn missing_broadcast_is_zero_and_explicit_local_broadcast_is_preserved() {
        let mut row = vec![2, 24, 0, 0];
        row.extend_from_slice(&7u32.to_ne_bytes());
        for kind in [1u16, 2] {
            row.extend_from_slice(&8u16.to_ne_bytes());
            row.extend_from_slice(&kind.to_ne_bytes());
            row.extend_from_slice(&[192, 0, 2, 1]);
        }
        let local = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(
            attributes(&row).unwrap(),
            Some((7, local, Ipv4Addr::UNSPECIFIED))
        );
        row.extend_from_slice(&8u16.to_ne_bytes());
        row.extend_from_slice(&4u16.to_ne_bytes());
        row.extend_from_slice(&local.octets());
        assert_eq!(attributes(&row).unwrap(), Some((7, local, local)));
        row.pop();
        assert!(attributes(&row).is_err());
    }
}
