//! network.c::local_bind and the source tuple used by allocate_sfd/allocate_rfd.
use crate::config::dns::{ServerEndpoint, ServerHost};
use crate::config::ScalarConfig;
use crate::dns::forward::Random;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

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
        if let Ok(name) = std::ffi::CString::new(self.interface.as_slice()) {
            // SAFETY: CString owns a NUL-terminated buffer for the whole call;
            // if_nametoindex reads it and does not retain the pointer.
            let index = unsafe { if_nametoindex(name.as_ptr()) };
            if index != 0 {
                self.ifindex = index;
            }
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
        #[cfg(target_os = "linux")]
        // SAFETY: 4 is Linux _SC_OPEN_MAX; sysconf takes no pointer and owns
        // no resource. A negative result is clamped below before conversion.
        let open_max = unsafe { sysconf(4) };
        #[cfg(target_os = "macos")]
        // SAFETY: 5 is Darwin _SC_OPEN_MAX, with the same scalar-only contract.
        let open_max = unsafe { sysconf(5) };
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

#[cfg(target_os = "linux")]
const AF_INET6: i32 = 10;
#[cfg(target_os = "macos")]
const AF_INET6: i32 = 30;
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
unsafe extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn bind(fd: i32, address: *const u8, length: u32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const u8, length: u32) -> i32;
    fn if_nametoindex(name: *const std::ffi::c_char) -> u32;
    fn sysconf(name: i32) -> isize;
}
fn bind_address(fd: RawFd, address: SocketAddr) -> io::Result<()> {
    let result = match address {
        SocketAddr::V4(address) => {
            let native = Inet4 {
                #[cfg(target_os = "macos")]
                length: 16,
                family: 2,
                port: address.port().to_be(),
                address: address.ip().octets(),
                zero: [0; 8],
            };
            // SAFETY: repr(C) Inet4 is the 16-byte sockaddr_in on the supported
            // Linux/Darwin ABIs. The initialized stack value lives through bind.
            unsafe { bind(fd, (&native as *const Inet4).cast(), 16) }
        }
        SocketAddr::V6(address) => {
            let native = Inet6 {
                #[cfg(target_os = "macos")]
                length: 28,
                family: AF_INET6 as _,
                port: address.port().to_be(),
                flow: address.flowinfo().to_be(),
                address: address.ip().octets(),
                scope: address.scope_id(),
            };
            // SAFETY: repr(C) Inet6 matches the 28-byte sockaddr_in6 layout;
            // bind borrows the initialized value only for this call.
            unsafe { bind(fd, (&native as *const Inet6).cast(), 28) }
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn interface(_fd: RawFd, source: &SourceSpec, _tcp: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !_tcp && source.ifindex != 0 {
            let index = source.ifindex.to_be();
            let (level, option) = if source.address.is_ipv4() {
                (0, 50)
            } else {
                (41, 76)
            };
            // SAFETY: this Linux unicast-interface option reads one initialized
            // u32 by value; _fd remains owned by the calling socket operation.
            return if unsafe { setsockopt(_fd, level, option, (&index as *const u32).cast(), 4) }
                == 0
            {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            };
        }
        if !source.interface.is_empty() {
            let mut name = [0u8; 16];
            let length = source.interface.len().min(15);
            name[..length].copy_from_slice(&source.interface[..length]);
            // SAFETY: Linux SO_BINDTODEVICE reads this live 16-byte IFNAMSIZ
            // buffer, initialized and NUL-terminated by the 15-byte limit.
            if unsafe { setsockopt(_fd, 1, 25, name.as_ptr(), 16) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    if !source.interface.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "source interface requires Linux",
        ));
    }
    Ok(())
}

pub fn bind_tcp(fd: RawFd, source: &SourceSpec) -> io::Result<()> {
    let mut address = source.address;
    address.set_port(0);
    if !address.ip().is_unspecified() {
        bind_address(fd, address)?;
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
    let kind = 2 | 0o4000 | 0o2000000; // SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC
    #[cfg(not(target_os = "linux"))]
    let kind = 2;
    // SAFETY: socket has scalar arguments only. The returned descriptor is
    // checked for failure and transferred to a single RAII owner below.
    let fd = unsafe {
        socket(
            if source.address.is_ipv4() {
                2
            } else {
                AF_INET6
            },
            kind,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: fd is newly created, nonnegative and has no other owning wrapper.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if source.address.is_ipv6() {
        let one = 1i32;
        #[cfg(target_os = "linux")]
        let (level, option) = (41, 26);
        #[cfg(target_os = "macos")]
        let (level, option) = (41, 27);
        // SAFETY: IPV6_V6ONLY reads the initialized i32 during this call; owned
        // closes fd on every error path and the pointer is never retained.
        if unsafe { setsockopt(fd, level, option, (&one as *const i32).cast(), 4) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
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
        match bind_address(fd, address) {
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
    interface(fd, source, false).map_err(|error| SocketFailure {
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
    fn native_bind_layouts_and_signed_empty_pool_match_image_boundary() {
        assert_eq!(std::mem::size_of::<Inet4>(), 16);
        assert_eq!(std::mem::size_of::<Inet6>(), 28);
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
        use std::os::fd::AsRawFd;
        unsafe extern "C" { fn fcntl(fd: i32, command: i32, ...) -> i32; }
        struct NoRandom;
        impl Random for NoRandom {
            fn next_u32(&mut self) -> io::Result<u32> {
                panic!("OS-assigned port does not consume random bytes")
            }
        }
        for upstream in ["127.0.0.1:53", "[::1]:53"] {
            let source = SourceSpec::wildcard(upstream.parse().unwrap(), 0);
            let socket = udp(&source, SocketSettings::default(), &mut NoRandom).unwrap();
            // SAFETY: F_GETFL/F_GETFD take no third argument and inspect the
            // live exclusively owned descriptor without changing its flags.
            let status = unsafe { fcntl(socket.as_raw_fd(), 3) };
            let descriptor = unsafe { fcntl(socket.as_raw_fd(), 1) };
            assert!(status >= 0 && status & 0o4000 != 0);
            assert!(descriptor >= 0 && descriptor & 1 != 0);
            assert_eq!(socket.recv_from(&mut [0; 1]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
    }
}
