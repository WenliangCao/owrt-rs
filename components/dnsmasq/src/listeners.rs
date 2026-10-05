//! DNS interface selection and the existing Linux pktinfo socket boundary.
use crate::config::dns::DnsConfig;
use crate::interfaces::DnsInterface;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream};

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
fn name_matches(pattern: &Option<Vec<u8>>, name: &[u8], _loopback: bool) -> bool {
    match pattern {
        None => false,
        Some(pattern) => match pattern.iter().position(|byte| *byte == b'*') {
            Some(at) => name.len() > at && name.starts_with(&pattern[..at]),
            None => pattern == name,
        },
    }
}
pub fn selected(config: &DnsConfig, interface: &DnsInterface) -> bool {
    if config.listen_addresses.contains(&interface.address) {
        return true;
    }
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

/// C checks unused interface names after opening static bound listeners.
/// Dynamic binding instead permits interfaces which have not appeared yet.
pub fn validate_bind_interfaces(config: &DnsConfig, interfaces: &[DnsInterface]) -> io::Result<()> {
    if !config.bind_interfaces || config.bind_dynamic {
        return Ok(());
    }
    for pattern in &config.interfaces {
        let Some(name) = pattern else { continue };
        if !interfaces
            .iter()
            .any(|interface| name_matches(pattern, &interface.name, interface.loopback))
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown interface {}", String::from_utf8_lossy(name)),
            ));
        }
    }
    Ok(())
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
            .filter(|interface| selected(config, interface) && !interface.tentative)
        {
            let address = interface_address(interface, port);
            if !result.contains(&address) {
                result.push(address);
            }
        }
        // Explicit addresses can precede interface creation in dynamic mode.
        for address in &config.listen_addresses {
            let address = SocketAddr::new(*address, port);
            // Matching tentative addresses are already INAME_USED in C, so
            // they must not be retried as an unowned explicit address.
            if !interfaces
                .iter()
                .any(|interface| interface.address == address.ip())
                && !result.iter().any(|existing| existing.ip() == address.ip())
            {
                result.push(address);
            }
        }
        result
    } else {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            // C uses wildcard sockets unless a bind mode is selected.
            // Interface and address options are a union enforced by admit().
            vec![
                SocketAddr::new("0.0.0.0".parse().unwrap(), port),
                SocketAddr::new("::".parse().unwrap(), port),
            ]
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        {
            if config.listen_addresses.is_empty() {
                vec![SocketAddr::new("::".parse().unwrap(), port)]
            } else {
                config
                    .listen_addresses
                    .iter()
                    .map(|address| SocketAddr::new(*address, port))
                    .collect()
            }
        }
    }
}

fn interface_address(interface: &DnsInterface, port: u16) -> SocketAddr {
    match interface.address {
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
    }
}

/// Capture at startup for static binding. The poll owner may retry only this
/// set after DAD; later static addresses must not acquire listeners.
pub fn tentative_addresses(
    config: &DnsConfig,
    port: u16,
    interfaces: &[DnsInterface],
) -> Vec<SocketAddr> {
    if port == 0 || !config.bind_interfaces && !config.bind_dynamic {
        return Vec::new();
    }
    let mut addresses = Vec::new();
    for interface in interfaces
        .iter()
        .filter(|interface| interface.tentative && selected(config, interface))
    {
        let address = interface_address(interface, port);
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
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
fn local_source(config: &DnsConfig, interfaces: &[DnsInterface], peer: IpAddr) -> bool {
    !config.local_service_net
        || explicit_access(config)
        || interfaces
            .iter()
            .any(|interface| same_network(peer, interface.address, interface.netmask))
}

pub fn tcp_interface(stream: &TcpStream, ipv6: bool) -> Option<(Vec<u8>, bool)> {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        crate::net::tcp_interface(stream, ipv6)
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    {
        let _ = (stream, ipv6);
        None
    }
}

/// check_dns_listeners checks a wildcard TCP stream's actual arrival name.
/// Unlike UDP, TCP has no label exception. Bound sockets already select their
/// addresses; all modes still enforce the local-service source restriction.
pub fn admit_tcp(
    config: &DnsConfig,
    interfaces: &[DnsInterface],
    peer: IpAddr,
    destination: SocketAddr,
    ingress: Option<(&[u8], bool)>,
) -> bool {
    if !local_source(config, interfaces, peer) {
        return false;
    }
    if config.bind_interfaces || config.bind_dynamic {
        return true;
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    if interfaces.is_empty() {
        return config.listen_addresses.is_empty()
            || config.listen_addresses.contains(&destination.ip());
    }
    let selected_destination = interfaces.iter().any(|interface| {
        interface.address == destination.ip()
            && selected(config, interface)
            && match destination {
                SocketAddr::V6(address) if address.ip().is_unicast_link_local() => {
                    address.scope_id() == interface.index
                }
                _ => true,
            }
    });
    let Some((name, loopback)) = ingress else {
        // C's fallback requires an enumerated, selected destination address.
        return selected_destination;
    };
    let named = config
        .interfaces
        .iter()
        .any(|pattern| name_matches(pattern, name, loopback))
        || !config.interfaces.is_empty() && loopback;
    let excluded = config
        .excluded_interfaces
        .iter()
        .any(|pattern| name_matches(pattern, name, loopback));
    config.listen_addresses.contains(&destination.ip())
        || (config.interfaces.is_empty() && config.listen_addresses.is_empty() || named)
            && !excluded
        || loopback && selected_destination
}

pub fn admit(
    config: &DnsConfig,
    interfaces: &[DnsInterface],
    peer: IpAddr,
    destination: IpAddr,
    ingress: u32,
) -> bool {
    if !local_source(config, interfaces, peer) {
        return false;
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    if interfaces.is_empty()
        && !config.bind_dynamic
        && !config.bind_interfaces
        && !config.local_service_net
        && !config.local_service_host
    {
        return config.listen_addresses.is_empty()
            || config.listen_addresses.contains(&destination);
    }
    if config.local_service_host && !config.local_service_net && !explicit_access(config) {
        return interfaces
            .iter()
            .any(|interface| interface.address == destination && interface.loopback);
    }
    if config.listen_addresses.contains(&destination) {
        return true;
    }
    // C's static IPv4 receive path trusts the bound socket even when it is
    // an unowned loopback alias or an explicitly configured wildcard.
    if config.bind_interfaces && !config.bind_dynamic && destination.is_ipv4() {
        return true;
    }
    if ingress == 0 {
        return !explicit_access(config)
            || interfaces
                .iter()
                .any(|interface| interface.address == destination && selected(config, interface));
    }
    if config.bind_dynamic || explicit_access(config) {
        interfaces
            .iter()
            .filter(|interface| interface.index == ingress)
            .any(|interface| {
                let excluded = config
                    .excluded_interfaces
                    .iter()
                    .any(|name| name_matches(name, interface.link_name(), interface.loopback));
                let allowed = (config.interfaces.is_empty() && config.listen_addresses.is_empty()
                    || config
                        .interfaces
                        .iter()
                        .any(|name| name_matches(name, interface.link_name(), interface.loopback))
                    || !config.interfaces.is_empty() && interface.loopback)
                    && !excluded;
                // C's loopback and label exceptions retain locally originated DNS
                // queries to a configured address even when ingress is loopback.
                allowed
                    || (interface.loopback || destination.is_ipv4())
                        && interfaces.iter().any(|candidate| {
                            candidate.address == destination
                                && selected(config, candidate)
                                && (interface.loopback || candidate.index == ingress)
                        })
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
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.socket.as_raw_fd()
    }

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
            tentative: false,
        }
    }
    #[test]
    fn tentative_explicit_addresses_are_used_but_deferred_with_scope() {
        let mut global = interface("fd42::1", "ffff:ffff:ffff:ffff::", 3);
        let mut local = interface("fe80::1", "ffff:ffff:ffff:ffff::", 3);
        global.tentative = true;
        local.tentative = true;
        let mut config = DnsConfig::default();
        config.bind_interfaces = true;
        config.interfaces.push(Some(b"lan".to_vec()));
        config.listen_addresses.push(global.address);
        config.listen_addresses.push(local.address);
        let mut interfaces = vec![global, local];
        assert!(validate_bind_interfaces(&config, &interfaces).is_ok());
        assert!(bound_addresses(&config, 53, &interfaces).is_empty());
        let expected = vec![
            "[fd42::1]:53".parse().unwrap(),
            "[fe80::1%3]:53".parse().unwrap(),
        ];
        assert_eq!(tentative_addresses(&config, 53, &interfaces), expected);
        for interface in &mut interfaces {
            interface.tentative = false;
        }
        assert!(tentative_addresses(&config, 53, &interfaces).is_empty());
        assert_eq!(bound_addresses(&config, 53, &interfaces), expected);
    }
    #[test]
    fn alias_ingress_exception_requires_its_selected_destination() {
        let primary = interface("192.0.2.1", "255.255.255.0", 3);
        let mut alias = interface("192.0.2.2", "255.255.255.0", 3);
        alias.name = b"lan:0".to_vec();
        let interfaces = [primary, alias];
        let mut config = DnsConfig::default();
        config.interfaces.push(Some(b"lan:0".to_vec()));
        for dynamic in [false, true] {
            config.bind_dynamic = dynamic;
            assert!(!admit(
                &config,
                &interfaces,
                "192.0.2.3".parse().unwrap(),
                "192.0.2.1".parse().unwrap(),
                3
            ));
            assert!(admit(
                &config,
                &interfaces,
                "192.0.2.3".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                3
            ));
        }
    }
    #[test]
    fn wildcard_and_null_names_match_c_string_boundaries() {
        assert!(!name_matches(&Some(b"lan*".to_vec()), b"lan", false));
        assert!(name_matches(&Some(b"lan*ignored".to_vec()), b"lan0", false));
        assert!(!name_matches(&None, b"lo", true));
    }
    #[test]
    fn automatic_loopback_name_admits_unlisted_loopback_destinations() {
        let mut lo = interface("127.0.0.1", "255.0.0.0", 1);
        lo.name = b"lo".to_vec();
        lo.loopback = true;
        let mut config = DnsConfig::default();
        config.interfaces.push(Some(b"lan".to_vec()));
        let peer = "127.0.0.1".parse().unwrap();
        let destination = "127.0.0.2".parse().unwrap();
        assert!(admit(&config, &[lo.clone()], peer, destination, 1));
        config.excluded_interfaces.push(Some(b"lo".to_vec()));
        assert!(!admit(&config, &[lo], peer, destination, 1));
    }
    #[test]
    fn static_binding_rejects_missing_names_but_accepts_matching_patterns() {
        let interfaces = [interface("192.0.2.1", "255.255.255.0", 3)];
        let mut config = DnsConfig::default();
        config.interfaces.push(Some(b"missing123".to_vec()));
        assert!(validate_bind_interfaces(&config, &interfaces).is_ok());
        config.bind_interfaces = true;
        let error = validate_bind_interfaces(&config, &interfaces).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), "unknown interface missing123");
        config.bind_dynamic = true;
        assert!(validate_bind_interfaces(&config, &interfaces).is_ok());
        config.bind_dynamic = false;
        config.interfaces = vec![Some(b"la*".to_vec())];
        assert!(validate_bind_interfaces(&config, &interfaces).is_ok());
        config.interfaces.push(Some(b"missing123".to_vec()));
        assert!(validate_bind_interfaces(&config, &interfaces).is_err());
    }
    #[test]
    fn tcp_checks_arrival_names_and_preserves_bound_and_fallback_rules() {
        let mut lan = interface("192.0.2.1", "255.255.255.0", 3);
        let mut wan = interface("198.51.100.1", "255.255.255.0", 4);
        wan.name = b"wan".to_vec();
        let mut config = DnsConfig::default();
        config.interfaces.push(Some(b"lan".to_vec()));
        config.excluded_interfaces.push(Some(b"wan".to_vec()));
        let peer = "198.51.100.2".parse().unwrap();
        let destination = "192.0.2.1:53".parse().unwrap();
        for (ingress, allowed) in [
            (Some((b"lan".as_slice(), false)), true),
            (Some((b"wan".as_slice(), false)), false),
            (Some((b"lo".as_slice(), true)), true),
            (None, true),
        ] {
            assert_eq!(
                admit_tcp(
                    &config,
                    &[lan.clone(), wan.clone()],
                    peer,
                    destination,
                    ingress
                ),
                allowed
            );
        }
        let unknown = "203.0.113.1:53".parse().unwrap();
        config.listen_addresses.push("203.0.113.1".parse().unwrap());
        assert!(!admit_tcp(&config, &[lan.clone()], peer, unknown, None));
        assert!(admit_tcp(
            &config,
            &[lan.clone()],
            peer,
            unknown,
            Some((b"wan", false))
        ));
        for dynamic in [false, true] {
            config.bind_interfaces = !dynamic;
            config.bind_dynamic = dynamic;
            assert!(admit_tcp(
                &config,
                &[lan.clone()],
                peer,
                destination,
                Some((b"wan", false))
            ));
        }
        config = DnsConfig::default();
        config.bind_dynamic = true;
        config.local_service_net = true;
        assert!(!admit_tcp(&config, &[lan.clone()], peer, destination, None));

        config = DnsConfig::default();
        config.interfaces.push(Some(b"lan:0".to_vec()));
        lan.name = b"lan:0".to_vec();
        assert!(!admit_tcp(
            &config,
            &[lan],
            peer,
            destination,
            Some((b"lan", false))
        ));
    }

    #[test]
    fn tcp_fallback_keeps_link_local_destination_scope() {
        let interfaces = [interface("fe80::1", "ffff:ffff:ffff:ffff::", 3)];
        let config = DnsConfig::default();
        for (destination, allowed) in [("[fe80::1%3]:53", true), ("[fe80::1%4]:53", false)] {
            assert_eq!(
                admit_tcp(
                    &config,
                    &interfaces,
                    "fe80::2".parse().unwrap(),
                    destination.parse().unwrap(),
                    None
                ),
                allowed
            );
        }
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn wildcard_listeners_keep_interface_and_address_access_as_a_union() {
        let mut lan = interface("192.0.2.1", "255.255.255.0", 3);
        lan.name = b"lan".to_vec();
        let mut wan = interface("198.51.100.1", "255.255.255.0", 4);
        wan.name = b"wan".to_vec();
        let interfaces = [lan, wan];
        let mut config = DnsConfig::default();
        config.interfaces.push(Some(b"lan".to_vec()));
        config.listen_addresses.push("203.0.113.1".parse().unwrap());
        assert_eq!(
            bound_addresses(&config, 53, &interfaces),
            ["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()]
        );
        for (destination, ingress, allowed) in [
            ("192.0.2.1", 3, true),
            ("203.0.113.1", 4, true),
            ("203.0.113.1", 0, true),
            ("198.51.100.1", 4, false),
            ("198.51.100.1", 0, false),
        ] {
            assert_eq!(
                admit(
                    &config,
                    &interfaces,
                    "198.51.100.2".parse().unwrap(),
                    destination.parse().unwrap(),
                    ingress,
                ),
                allowed
            );
        }
        config.bind_interfaces = true;
        assert_eq!(
            bound_addresses(&config, 53, &interfaces),
            [
                "192.0.2.1:53".parse().unwrap(),
                "203.0.113.1:53".parse().unwrap()
            ]
        );
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
    fn dynamic_listeners_keep_ipv6_scope_and_require_known_ingress() {
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
