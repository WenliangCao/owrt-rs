//! Nonblocking connect boundary for Linux and the macOS test host.
//! The fd has exactly one Rust owner from socket creation onward. Linux uses
//! atomic CLOEXEC/NONBLOCK; macOS sets those flags before issuing connect.

use dnsmasq_platform::connect;
use super::TcpError;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const AF_INET: i32 = 2;
#[cfg(target_os = "linux")]
const AF_INET6: i32 = 10;
#[cfg(target_os = "macos")]
const AF_INET6: i32 = 30;
const SOCK_STREAM: i32 = 1;
const EINTR: i32 = 4;
#[cfg(target_os = "linux")]
const EINPROGRESS: i32 = 115;
#[cfg(target_os = "macos")]
const EINPROGRESS: i32 = 36;

#[repr(C)]
struct Inet4 {
    #[cfg(target_os = "macos")]
    length: u8,
    #[cfg(target_os = "macos")]
    family: u8,
    #[cfg(target_os = "linux")]
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
struct Inet6 {
    #[cfg(target_os = "macos")]
    length: u8,
    #[cfg(target_os = "macos")]
    family: u8,
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "macos")]
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

/// Returns the owned nonblocking stream and whether connect finished already.
/// EINPROGRESS/EINTR returns immediately; the owner polls POLLOUT then calls
/// `connected`. No blocking connect fallback is allowed in the daemon path.
pub(super) fn start(
    address: SocketAddr,
    source: Option<&crate::dns::upstream::source_sockets::SourceSpec>,
) -> Result<(TcpStream, bool), TcpError> {
    #[cfg(target_os = "linux")]
    let kind = SOCK_STREAM | 0o2000000 | 0o4000; // CLOEXEC | NONBLOCK
    #[cfg(target_os = "macos")]
    let kind = SOCK_STREAM;
    // SAFETY: scalar arguments with the native socket constants; success gives
    // a new, uniquely owned fd, wrapped immediately even on later errors.
    let raw = unsafe { socket(if address.is_ipv4() { AF_INET } else { AF_INET6 }, kind, 0) };
    if raw < 0 {
        return Err(TcpError::NoReply);
    }
    // SAFETY: successful socket returned a new descriptor with no other owner.
    let stream = TcpStream::from(unsafe { OwnedFd::from_raw_fd(raw) });
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the stream owns the fd; F_SETFD with FD_CLOEXEC is a scalar
        // fcntl call. The supported production Linux path sets it atomically.
        if unsafe { fcntl(stream.as_raw_fd(), 2, 1) } < 0 {
            return Err(TcpError::NoReply);
        }
        stream
            .set_nonblocking(true)
            .map_err(|_| TcpError::NoReply)?;
    }
    if let Some(source) = source {
        crate::dns::upstream::source_sockets::bind_tcp(stream.as_raw_fd(), source)
            .map_err(|_| TcpError::NoReply)?;
    }
    let status = match address {
        SocketAddr::V4(address) => {
            let raw_address = Inet4 {
                #[cfg(target_os = "macos")]
                length: 16,
                family: AF_INET as _,
                port: address.port().to_be(),
                address: address.ip().octets(),
                zero: [0; 8],
            };
            // SAFETY: initialized native sockaddr_in lives through the call;
            // the supplied size matches its asserted 16-byte ABI layout.
            unsafe {
                connect(
                    stream.as_raw_fd(),
                    (&raw_address as *const Inet4).cast(),
                    16,
                )
            }
        }
        SocketAddr::V6(address) => {
            let raw_address = Inet6 {
                #[cfg(target_os = "macos")]
                length: 28,
                family: AF_INET6 as _,
                port: address.port().to_be(),
                flow: address.flowinfo().to_be(),
                address: address.ip().octets(),
                scope: address.scope_id(),
            };
            // SAFETY: initialized native sockaddr_in6 lives through the call;
            // the supplied size matches its asserted 28-byte ABI layout.
            unsafe {
                connect(
                    stream.as_raw_fd(),
                    (&raw_address as *const Inet6).cast(),
                    28,
                )
            }
        }
    };
    if status == 0 {
        return Ok((stream, true));
    }
    if matches!(
        io::Error::last_os_error().raw_os_error(),
        Some(EINPROGRESS | EINTR)
    ) {
        Ok((stream, false))
    } else {
        Err(TcpError::NoReply)
    }
}

pub(super) fn connected(stream: &TcpStream) -> Result<bool, TcpError> {
    if stream
        .take_error()
        .map_err(|_| TcpError::NoReply)?
        .is_some()
    {
        return Err(TcpError::NoReply);
    }
    match stream.peer_addr() {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(false),
        Err(_) => Err(TcpError::NoReply),
    }
}
