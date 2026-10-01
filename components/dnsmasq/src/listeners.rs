//! DNS interface selection and the existing Linux pktinfo socket boundary.
use crate::config::dns::DnsConfig;
use crate::interfaces::DnsInterface;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6, TcpListener};

pub fn snapshot() -> io::Result<Vec<DnsInterface>> {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        crate::interfaces::dns_interfaces()
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    {
        Ok(Vec::new())
    }
}
fn name_matches(pattern: &Option<Vec<u8>>, name: &[u8], loopback: bool) -> bool {
    match pattern {
        None => loopback,
        Some(pattern) => match pattern.iter().position(|byte| *byte == b'*') {
            Some(at) => name.starts_with(&pattern[..at]),
            None => pattern == name,
        },
    }
}
pub fn selected(config: &DnsConfig, interface: &DnsInterface) -> bool {
    if config
        .excluded_interfaces
        .iter()
        .any(|name| name_matches(name, &interface.name, interface.loopback))
    {
        return false;
    }
    if config.local_service_host && !config.local_service_net && !explicit_access(config) {
        return interface.loopback;
    }
    config.interfaces.is_empty() && config.listen_addresses.is_empty()
        || config
            .interfaces
            .iter()
            .any(|name| name_matches(name, &interface.name, interface.loopback))
        || !config.interfaces.is_empty() && interface.loopback
        || config.listen_addresses.contains(&interface.address)
}
fn explicit_access(config: &DnsConfig) -> bool {
    !config.interfaces.is_empty()
        || !config.excluded_interfaces.is_empty()
        || !config.listen_addresses.is_empty()
}
pub fn bound_addresses(
    config: &DnsConfig,
    port: u16,
    interfaces: &[DnsInterface],
) -> Vec<SocketAddr> {
    if port == 0 {
        return Vec::new();
    }
    if config.bind_dynamic
        || config.bind_interfaces
        || config.local_service_host && !config.local_service_net && !explicit_access(config)
    {
        let mut result = Vec::new();
        for interface in interfaces
            .iter()
            .filter(|interface| selected(config, interface))
        {
            let address = match interface.address {
                IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    0,
                    if ip.is_unicast_link_local() {
                        interface.index
                    } else {
                        0
                    },
                )),
                ip => SocketAddr::new(ip, port),
            };
            if !result.contains(&address) {
                result.push(address);
            }
        }
        // Explicit addresses can precede interface creation in dynamic mode.
        for address in &config.listen_addresses {
            let address = SocketAddr::new(*address, port);
            if !result.iter().any(|existing| existing.ip() == address.ip()) {
                result.push(address);
            }
        }
        result
    } else if !config.listen_addresses.is_empty() {
        config
            .listen_addresses
            .iter()
            .map(|address| SocketAddr::new(*address, port))
            .collect()
    } else {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            vec![
                SocketAddr::new("0.0.0.0".parse().unwrap(), port),
                SocketAddr::new("::".parse().unwrap(), port),
            ]
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        {
            vec![SocketAddr::new("::".parse().unwrap(), port)]
        }
    }
}
pub fn local_network(
    interfaces: &[DnsInterface],
    destination: IpAddr,
) -> Option<(Ipv4Addr, Ipv4Addr)> {
    interfaces.iter().find_map(|interface| {
        match (interface.address, interface.netmask, destination) {
            (IpAddr::V4(address), IpAddr::V4(mask), IpAddr::V4(destination))
                if address == destination =>
            {
                Some((address, mask))
            }
            _ => None,
        }
    })
}
fn same_network(a: IpAddr, b: IpAddr, mask: IpAddr) -> bool {
    match (a, b, mask) {
        (IpAddr::V4(a), IpAddr::V4(b), IpAddr::V4(mask)) => {
            u32::from(a) & u32::from(mask) == u32::from(b) & u32::from(mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b), IpAddr::V6(mask)) => {
            u128::from(a) & u128::from(mask) == u128::from(b) & u128::from(mask)
        }
        _ => false,
    }
}
pub fn admit(
    config: &DnsConfig,
    interfaces: &[DnsInterface],
    peer: IpAddr,
    destination: IpAddr,
    ingress: u32,
) -> bool {
    if config.local_service_net
        && !explicit_access(config)
        && !interfaces
            .iter()
            .any(|interface| same_network(peer, interface.address, interface.netmask))
    {
        return false;
    }
    if config.bind_dynamic || explicit_access(config) || config.local_service_host {
        interfaces.iter().any(|interface| {
            interface.address == destination
                && (ingress == 0 || ingress == interface.index)
                && selected(config, interface)
        })
    } else {
        true
    }
}

#[derive(Clone, Copy)]
pub struct Incoming {
    pub len: usize,
    pub peer: SocketAddr,
    pub destination: IpAddr,
    pub interface: u32,
}
pub struct DnsSocket {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    socket: crate::net::DatagramSocket,
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    socket: std::net::UdpSocket,
}
impl DnsSocket {
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            Ok(Self {
                socket: crate::net::DatagramSocket::bind(address)?,
            })
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        {
            let socket = std::net::UdpSocket::bind(address)?;
            socket.set_nonblocking(true)?;
            Ok(Self { socket })
        }
    }
    pub fn receive(&self, bytes: &mut [u8]) -> io::Result<Option<Incoming>> {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            Ok(self.socket.receive(bytes)?.map(|data| Incoming {
                len: data.len,
                peer: data.peer,
                destination: data.local_address,
                interface: data.interface,
            }))
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        {
            let (len, peer) = self.socket.recv_from(bytes)?;
            Ok(Some(Incoming {
                len,
                peer,
                destination: self.socket.local_addr()?.ip(),
                interface: 0,
            }))
        }
    }
    pub fn send(
        &self,
        bytes: &[u8],
        peer: SocketAddr,
        source: Option<(IpAddr, u32)>,
    ) -> io::Result<()> {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            self.socket.send(bytes, peer, source)
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        {
            let _ = source;
            self.socket.send_to(bytes, peer).map(|_| ())
        }
    }
}
pub fn tcp_bind(address: SocketAddr) -> io::Result<TcpListener> {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        extern "C" {
            fn socket(family: i32, kind: i32, protocol: i32) -> i32;
            fn setsockopt(fd: i32, level: i32, option: i32, value: *const i32, len: u32) -> i32;
            fn bind(fd: i32, address: *const u8, len: u32) -> i32;
            fn listen(fd: i32, backlog: i32) -> i32;
        }
        // SAFETY: a new socket has unique ownership transferred immediately.
        let fd = unsafe {
            socket(
                if address.is_ipv4() { 2 } else { 10 },
                1 | 0o2000000 | 0o4000,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let listener = unsafe { TcpListener::from_raw_fd(fd) };
        let fd = listener.as_raw_fd();
        let one = 1;
        if unsafe { setsockopt(fd, 1, 2, &one, 4) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if address.is_ipv6() && unsafe { setsockopt(fd, 41, 26, &one, 4) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut storage = [0u64; 4];
        // SAFETY: initialized aligned storage holds either Linux sockaddr layout.
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), 32) };
        bytes[..2].copy_from_slice(&(if address.is_ipv4() { 2u16 } else { 10u16 }).to_ne_bytes());
        bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
        match address {
            SocketAddr::V4(v) => bytes[4..8].copy_from_slice(&v.ip().octets()),
            SocketAddr::V6(v) => {
                bytes[8..24].copy_from_slice(&v.ip().octets());
                bytes[24..28].copy_from_slice(&v.scope_id().to_ne_bytes());
            }
        }
        if unsafe { bind(fd, bytes.as_ptr(), if address.is_ipv4() { 16 } else { 28 }) } < 0
            || unsafe { listen(fd, 32) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(listener)
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    {
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn interface(address: &str, netmask: &str, index: u32) -> DnsInterface {
        DnsInterface {
            index,
            name: b"lan".to_vec(),
            address: address.parse().unwrap(),
            netmask: netmask.parse().unwrap(),
            loopback: false,
        }
    }
    #[test]
    fn local_service_filters_both_families_and_explicit_access_overrides_it() {
        let interfaces = vec![
            interface("192.0.2.1", "255.255.255.0", 3),
            interface("2001:db8::1", "ffff:ffff:ffff:ffff::", 3),
        ];
        let mut config = DnsConfig::default();
        config.local_service_net = true;
        for (peer, allowed) in [
            ("192.0.2.10", true),
            ("198.51.100.1", false),
            ("2001:db8::2", true),
            ("2001:db8:1::1", false),
        ] {
            assert_eq!(
                admit(
                    &config,
                    &interfaces,
                    peer.parse().unwrap(),
                    interfaces[0].address,
                    3
                ),
                allowed
            );
        }
        config.listen_addresses.push(interfaces[0].address);
        assert!(admit(
            &config,
            &interfaces,
            "198.51.100.1".parse().unwrap(),
            interfaces[0].address,
            3
        ));
    }
    #[test]
    fn dynamic_listeners_keep_ipv6_scope_and_enforce_ingress() {
        let interfaces = vec![
            interface("192.0.2.1", "255.255.255.0", 3),
            interface("fe80::1", "ffff:ffff:ffff:ffff::", 3),
        ];
        let mut config = DnsConfig::default();
        config.bind_dynamic = true;
        let addresses = bound_addresses(&config, 53, &interfaces);
        assert_eq!(addresses[1], "[fe80::1%3]:53".parse().unwrap());
        assert!(admit(
            &config,
            &interfaces,
            "192.0.2.2".parse().unwrap(),
            interfaces[0].address,
            3
        ));
        assert!(!admit(
            &config,
            &interfaces,
            "192.0.2.2".parse().unwrap(),
            interfaces[0].address,
            4
        ));
    }
}
