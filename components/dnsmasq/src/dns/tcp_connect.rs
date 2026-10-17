//! Nonblocking connect boundary for Linux and the macOS test host.
//! Owned descriptors move directly from rustix to TcpStream.

use super::TcpError;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use std::io;
use std::net::{SocketAddr, TcpStream};

/// EINPROGRESS/EINTR returns immediately; readiness still belongs to the owner.
pub(super) fn start(
    address: SocketAddr,
    source: Option<&crate::dns::upstream::source_sockets::SourceSpec>,
) -> Result<(TcpStream, bool), TcpError> {
    #[cfg(target_os = "linux")]
    let flags = SocketFlags::CLOEXEC | SocketFlags::NONBLOCK;
    #[cfg(not(target_os = "linux"))]
    let flags = SocketFlags::empty();
    let fd = rustix::net::socket_with(
        if address.is_ipv4() {
            AddressFamily::INET
        } else {
            AddressFamily::INET6
        },
        SocketType::STREAM,
        flags,
        None,
    )
    .map_err(|_| TcpError::NoReply)?;
    let stream = TcpStream::from(fd);
    #[cfg(not(target_os = "linux"))]
    {
        rustix::io::fcntl_setfd(&stream, rustix::io::FdFlags::CLOEXEC)
            .map_err(|_| TcpError::NoReply)?;
        stream
            .set_nonblocking(true)
            .map_err(|_| TcpError::NoReply)?;
    }
    if let Some(source) = source {
        crate::dns::upstream::source_sockets::bind_tcp(&stream, source)
            .map_err(|_| TcpError::NoReply)?;
    }
    match rustix::net::connect(&stream, &address) {
        Ok(()) => Ok((stream, true)),
        Err(rustix::io::Errno::INPROGRESS | rustix::io::Errno::INTR) => Ok((stream, false)),
        Err(_) => Err(TcpError::NoReply),
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
