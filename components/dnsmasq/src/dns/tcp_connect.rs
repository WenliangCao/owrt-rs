//! Audited Linux aarch64/x86_64 nonblocking TCP connect boundary.
//! The descriptor has one OwnedFd owner until successful conversion to a
//! TcpStream. Every address/option buffer lives through the corresponding
//! syscall, uses the Linux sockaddr layout, and has its exact ABI length.

use super::{check_bound, TcpError, CANCEL_INTERVAL};
use owrt_ubus::sys::{poll_fds, PollFd, POLLOUT};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Instant;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const SOCK_STREAM: i32 = 1;
const SOCK_CLOEXEC: i32 = 0o2000000;
const SOCK_NONBLOCK: i32 = 0o4000;
const SOL_SOCKET: i32 = 1;
const SO_ERROR: i32 = 4;
const EINTR: i32 = 4;
const EINPROGRESS: i32 = 115;

#[repr(C)]
struct Inet4 {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
struct Inet6 {
    family: u16,
    port: u16,
    flow: u32,
    address: [u8; 16],
    scope: u32,
}

const _: () = assert!(std::mem::size_of::<Inet4>() == 16);
const _: () = assert!(std::mem::size_of::<Inet6>() == 28);

extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn connect(fd: i32, address: *const u8, length: u32) -> i32;
    fn getsockopt(fd: i32, level: i32, option: i32, value: *mut i32, length: *mut u32) -> i32;
}

pub(super) fn connect_until(
    address: SocketAddr,
    connect_deadline: Instant,
    deadline: Instant,
    stopped: &dyn Fn() -> bool,
) -> Result<TcpStream, TcpError> {
    check_bound(deadline, stopped)?;
    // SAFETY: socket takes scalar arguments and returns a uniquely owned fd.
    // CLOEXEC is atomic, so no concurrent exec can inherit a transient fd.
    let raw = unsafe {
        socket(
            if address.is_ipv4() { AF_INET } else { AF_INET6 },
            SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(TcpError::NoReply);
    }
    // SAFETY: successful socket returned a new fd with no other Rust owner.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let status = match address {
        SocketAddr::V4(address) => {
            let raw_address = Inet4 {
                family: AF_INET as u16,
                port: address.port().to_be(),
                address: address.ip().octets(),
                zero: [0; 8],
            };
            // SAFETY: initialized, correctly aligned sockaddr_in is alive for
            // the call; Linux copies exactly the supplied 16 bytes.
            unsafe { connect(fd.as_raw_fd(), (&raw_address as *const Inet4).cast(), 16) }
        }
        SocketAddr::V6(address) => {
            let raw_address = Inet6 {
                family: AF_INET6 as u16,
                port: address.port().to_be(),
                flow: address.flowinfo().to_be(),
                address: address.ip().octets(),
                scope: address.scope_id(),
            };
            // SAFETY: initialized sockaddr_in6 lives through this call and its
            // supplied length is the asserted Linux 28-byte ABI size.
            unsafe { connect(fd.as_raw_fd(), (&raw_address as *const Inet6).cast(), 28) }
        }
    };
    if status == 0 {
        check_bound(deadline, stopped)?;
        return Ok(TcpStream::from(fd));
    }
    if !matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(EINPROGRESS | EINTR)
    ) {
        return Err(TcpError::NoReply);
    }
    loop {
        check_bound(deadline, stopped)?;
        let remaining = connect_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TcpError::NoReply);
        }
        let wait = remaining
            .min(deadline.saturating_duration_since(Instant::now()))
            .min(CANCEL_INTERVAL);
        let mut poll = [PollFd {
            fd: fd.as_raw_fd(),
            events: POLLOUT,
            revents: 0,
        }];
        let ready =
            poll_fds(&mut poll, wait.as_millis().max(1) as i32).map_err(|_| TcpError::NoReply)?;
        check_bound(deadline, stopped)?;
        if ready == 0 {
            continue;
        }
        let mut error = 0i32;
        let mut length = 4u32;
        // SAFETY: error and length are live, writable native integers. The
        // requested SO_ERROR value is exactly one four-byte Linux int.
        let status = unsafe {
            getsockopt(
                fd.as_raw_fd(),
                SOL_SOCKET,
                SO_ERROR,
                &mut error,
                &mut length,
            )
        };
        if status != 0 || length != 4 || error != 0 {
            return Err(TcpError::NoReply);
        }
        return Ok(TcpStream::from(fd));
    }
}
