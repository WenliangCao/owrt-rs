//! network.c::local_bind and the source tuple used by allocate_sfd/allocate_rfd.
use crate::config::dns::{ServerEndpoint, ServerHost};
use crate::config::ScalarConfig;
use crate::dns::forward::Random;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SourceSpec {
    pub address: SocketAddr,
    pub interface: Vec<u8>,
    pub ifindex: u32,
}

impl SourceSpec {
    pub fn wildcard(address: SocketAddr, port: u16) -> Self {
        Self {
            address: SocketAddr::new(
                if address.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                },
                port,
            ),
            interface: Vec::new(),
            ifindex: 0,
        }
    }
    pub fn endpoint(endpoint: &ServerEndpoint, query_port: u16) -> Self {
        let ServerHost::Address(destination) = endpoint.host else {
            unreachable!("routing resolved endpoint")
        };
        let mut source = Self::wildcard(SocketAddr::new(destination, endpoint.port), query_port);
        if let Some(binding) = &endpoint.source {
            if let Some(address) = binding.address {
                source.address.set_ip(address);
            }
            source.address.set_port(binding.port);
            source.interface = binding.interface.clone().unwrap_or_default();
            source.refresh_interface_index();
        }
        source
    }

    /// enumerate_interfaces updates a server's cached index only after a
    /// successful lookup. A missing or cleared name keeps the previous index.
    pub fn refresh_interface_index(&mut self) {
        if self.interface.is_empty() {
            return;
        }
        let index = dnsmasq_platform::interfaces::interface_index(&self.interface);
        if index != 0 {
            self.ifindex = index;
        }
    }
}

#[derive(Debug)]
pub struct SourceBindError {
    pub source: SourceSpec,
    pub error: io::Error,
}
impl std::fmt::Display for SourceBindError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "failed to bind server socket for {}",
            self.source.address.ip()
        )?;
        if !self.source.interface.is_empty() {
            write!(out, " {}", String::from_utf8_lossy(&self.source.interface))?;
        }
        #[cfg(target_os = "linux")]
        {
            write!(out, ": {}", crate::dns::filewatch::os_message(&self.error))
        }
        #[cfg(not(target_os = "linux"))]
        {
            write!(out, ": {}", self.error)
        }
    }
}
impl std::error::Error for SourceBindError {}

#[derive(Clone, Copy, Debug)]
pub struct SocketSettings {
    pub query_port: u16,
    pub os_port: bool,
    pub min_port: u16,
    pub max_port: u16,
    pub port_limit: u32,
    pub pool_slots: usize,
}
impl Default for SocketSettings {
    fn default() -> Self {
        Self {
            query_port: 0,
            os_port: false,
            min_port: 0,
            max_port: 0,
            port_limit: 1,
            pool_slots: 75,
        }
    }
}
impl SocketSettings {
    pub fn from_scalar(scalar: &ScalarConfig) -> Self {
        let open_max = dnsmasq_platform::limits::open_max();
        Self {
            query_port: scalar.query_port,
            os_port: scalar.query_port_os_assigned,
            min_port: scalar.min_port,
            max_port: scalar.max_port,
            port_limit: scalar.port_limit,
            // C truncates -1 / 2 to zero. Smaller negatives fail DNS startup
            // before source sockets are configured; never cast them to usize.
            pool_slots: (scalar.forward_max.max(0) as usize / 2).min(open_max.max(0) as usize / 3),
        }
    }
    pub fn persistent(self, source: &SourceSpec) -> bool {
        self.os_port || source.address.port() != 0
    }
}

fn bind_address(fd: impl AsFd, address: SocketAddr) -> io::Result<()> {
    rustix::net::bind(fd, &address).map_err(Into::into)
}
fn interface(fd: impl AsFd, source: &SourceSpec, tcp: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !tcp && source.ifindex != 0 {
            return dnsmasq_platform::socket_options::set_unicast_interface(
                fd,
                source.address.is_ipv6(),
                source.ifindex,
            );
        }
        if !source.interface.is_empty() {
            let mut name = [0u8; 16];
            let length = source.interface.len().min(15);
            name[..length].copy_from_slice(&source.interface[..length]);
            dnsmasq_platform::socket_options::bind_to_device(fd, &name)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, tcp);
        if !source.interface.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "source interface requires Linux",
            ));
        }
    }
    Ok(())
}

pub fn bind_tcp(fd: impl AsFd, source: &SourceSpec) -> io::Result<()> {
    let mut address = source.address;
    address.set_port(0);
    if !address.ip().is_unspecified() {
        bind_address(fd.as_fd(), address)?;
    }
    interface(fd, source, true)
}

#[derive(Debug)]
pub struct SocketFailure {
    pub error: io::Error,
    /// socket/IPv6 setup errors are silent in random_sock; local_bind errors
    /// have their own C diagnostic boundary.
    pub binding: bool,
}
impl From<io::Error> for SocketFailure {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            binding: false,
        }
    }
}

#[derive(Debug)]
pub struct SourceSocketDiagnostic {
    pub source: SourceSpec,
    pub error: io::Error,
}
impl std::fmt::Display for SourceSocketDiagnostic {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "failed to bind server socket to ")?;
        if self.source.interface.is_empty() {
            write!(out, "{}", self.source.address.ip())?;
        } else {
            write!(out, "{}", String::from_utf8_lossy(&self.source.interface))?;
        }
        #[cfg(target_os = "linux")]
        {
            write!(out, ": {}", crate::dns::filewatch::os_message(&self.error))
        }
        #[cfg(not(target_os = "linux"))]
        {
            write!(out, ": {}", self.error)
        }
    }
}

pub fn udp(
    source: &SourceSpec,
    settings: SocketSettings,
    random: &mut impl Random,
) -> Result<UdpSocket, SocketFailure> {
    #[cfg(target_os = "linux")]
    let flags = SocketFlags::NONBLOCK | SocketFlags::CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = SocketFlags::empty();
    let owned = rustix::net::socket_with(
        if source.address.is_ipv4() {
            AddressFamily::INET
        } else {
            AddressFamily::INET6
        },
        SocketType::DGRAM,
        flags,
        None,
    )
    .map_err(io::Error::from)?;
    if source.address.is_ipv6() {
        rustix::net::sockopt::set_ipv6_v6only(&owned, true).map_err(io::Error::from)?;
    }
    let mut address = source.address;
    let ports = if address.port() == 0 && settings.max_port != 0 {
        u32::from(settings.max_port)
            .checked_sub(u32::from(settings.min_port))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid source port range")
            })?
            + 1
    } else {
        0
    };
    let tries = if ports == 0 {
        1
    } else if ports < 30 {
        ports
    } else {
        100
    };
    if ports != 0 {
        address.set_port(settings.min_port + ((random.next_u32()? as u16 as u32) % ports) as u16);
    }
    for attempt in 0..tries {
        if address.port() == 0 && address.ip().is_unspecified() {
            break;
        }
        match bind_address(&owned, address) {
            Ok(()) => break,
            Err(error) => {
                if !matches!(error.raw_os_error(), Some(13 | 98)) || attempt + 1 == tries {
                    return Err(SocketFailure {
                        error,
                        binding: true,
                    });
                }
                address.set_port(if ports < 30 {
                    if address.port() == settings.max_port {
                        settings.min_port
                    } else {
                        address.port() + 1
                    }
                } else {
                    settings.min_port + ((random.next_u32()? as u16 as u32) % ports) as u16
                });
            }
        }
    }
    interface(&owned, source, false).map_err(|error| SocketFailure {
        error,
        binding: true,
    })?;
    let socket = UdpSocket::from(owned);
    #[cfg(not(target_os = "linux"))]
    socket.set_nonblocking(true)?;
    // Linux installs both flags atomically at creation, as the DNS listener
    // and TCP upstream factories do. Binding/source selection is unchanged.
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_empty_pool_matches_image_boundary() {
        for forward_max in [-1, 0, 1] {
            let mut scalar = ScalarConfig::default();
            scalar.forward_max = forward_max;
            assert_eq!(SocketSettings::from_scalar(&scalar).pool_slots, 0);
        }
    }

    #[test]
    fn inverted_source_port_range_returns_invalid_input() {
        struct NoRandom;
        impl Random for NoRandom {
            fn next_u32(&mut self) -> io::Result<u32> {
                panic!("an invalid range must fail before random port selection")
            }
        }
        let source = SourceSpec::wildcard("192.0.2.53:53".parse().unwrap(), 0);
        let settings = SocketSettings {
            min_port: 60000,
            max_port: 50000,
            ..SocketSettings::default()
        };
        let failure = udp(&source, settings, &mut NoRandom).unwrap_err();
        assert_eq!(failure.error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn udp_factory_returns_nonblocking_close_on_exec_descriptors() {
        struct NoRandom;
        impl Random for NoRandom {
            fn next_u32(&mut self) -> io::Result<u32> {
                panic!("OS-assigned port does not consume random bytes")
            }
        }
        for upstream in ["127.0.0.1:53", "[::1]:53"] {
            let source = SourceSpec::wildcard(upstream.parse().unwrap(), 0);
            let socket = udp(&source, SocketSettings::default(), &mut NoRandom).unwrap();
            let status = rustix::fs::fcntl_getfl(&socket).unwrap();
            let descriptor = rustix::io::fcntl_getfd(&socket).unwrap();
            assert!(status.contains(rustix::fs::OFlags::NONBLOCK));
            assert!(descriptor.contains(rustix::io::FdFlags::CLOEXEC));
            assert_eq!(
                socket.recv_from(&mut [0; 1]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}
