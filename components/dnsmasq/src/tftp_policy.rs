//! TFTP interface, root and startup policy. This has no transfer state.
use crate::config::{dns::DnsConfig, tftp::TftpConfig};
use crate::interfaces::DnsInterface;
use crate::net::Datagram;
use crate::tftp_runtime::{RequestPolicy, RuntimePathPolicy};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt;

pub(super) struct Policy {
    pub config: TftpConfig,
    pub dns: DnsConfig,
    no_dhcp: Vec<Option<Vec<u8>>>,
    pub interfaces: Vec<DnsInterface>,
    tentative: Vec<(Ipv6Addr, u32)>,
}
impl Policy {
    pub fn new(
        config: &TftpConfig,
        dns: &DnsConfig,
        no_dhcp: &[Option<Vec<u8>>],
    ) -> io::Result<Self> {
        // Only interface policy is retained; no DNS records, cache or leases.
        let mut selected_dns = DnsConfig::default();
        selected_dns.interfaces.clone_from(&dns.interfaces);
        selected_dns
            .excluded_interfaces
            .clone_from(&dns.excluded_interfaces);
        selected_dns
            .listen_addresses
            .clone_from(&dns.listen_addresses);
        selected_dns.bind_dynamic = dns.bind_dynamic;
        selected_dns.bind_interfaces = dns.bind_interfaces;
        let dns = selected_dns;
        Ok(Self {
            config: config.clone(),
            dns,
            no_dhcp: no_dhcp.to_vec(),
            interfaces: crate::interfaces::dns_interfaces()?,
            tentative: tentative_addresses()?,
        })
    }
    pub fn refresh(&mut self) -> io::Result<()> {
        self.interfaces = crate::interfaces::dns_interfaces()?;
        self.tentative = tentative_addresses()?;
        Ok(())
    }
    pub fn tentative(&self, address: SocketAddr) -> bool {
        let IpAddr::V6(ip) = address.ip() else {
            return false;
        };
        self.interfaces
            .iter()
            .any(|row| row.address == address.ip() && self.tentative.contains(&(ip, row.index)))
    }
    pub fn addresses(&self) -> Vec<SocketAddr> {
        let mut addresses = crate::listeners::bound_addresses(&self.dns, 69, &self.interfaces);
        if self.dns.bind_interfaces || self.dns.bind_dynamic {
            addresses.retain(|address| {
                self.interfaces
                    .iter()
                    .find(|row| row.address == address.ip())
                    .is_none_or(|row| self.tftp_interface(&row.name))
            });
        }
        addresses
    }
    fn tftp_interface(&self, name: &[u8]) -> bool {
        crate::config::tftp::interface_enabled(
            self.config.enabled,
            &self.config.interfaces,
            &self.no_dhcp,
            name,
        )
    }
    pub fn admitted(&self, datagram: &Datagram, name: &[u8]) -> bool {
        if self.dns.bind_interfaces && !self.dns.bind_dynamic && datagram.destination.is_ipv4() {
            // Static IPv4 sockets select the destination address, while the
            // TFTP interface selector still applies to the owning interface.
            // C rejects an RRQ arriving on an excluded or non-selected
            // interface even though the socket was already bound.
            return self.tftp_interface(name);
        }
        if !self.config.interfaces.is_empty() {
            return self.tftp_interface(name);
        }
        self.tftp_interface(name)
            && crate::listeners::admit(
                &self.dns,
                &self.interfaces,
                datagram.peer.ip(),
                datagram.local_address,
                datagram.interface,
            )
    }
    pub fn request(
        &self,
        datagram: &Datagram,
        name: &[u8],
        interface_mtu: Option<u32>,
        mac: Option<[u8; 6]>,
    ) -> RequestPolicy {
        let prefix = crate::tftp_service::unique_root(
            self.config.root_for_interface(name),
            datagram.peer.ip(),
            mac,
            self.config.unique_root_ip,
            self.config.unique_root_mac,
            |path| {
                std::fs::metadata(std::ffi::OsStr::from_bytes(path))
                    .is_ok_and(|metadata| metadata.is_dir())
            },
        );
        let configured = self.config.mtu.filter(|value| *value != 0);
        let mtu = match (interface_mtu.filter(|value| *value != 0), configured) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        RequestPolicy {
            path: RuntimePathPolicy {
                prefix,
                lowercase: self.config.lowercase,
            },
            mtu,
            ipv6: datagram.peer.is_ipv6(),
        }
    }
    pub fn needs_mac(&self, name: &[u8]) -> bool {
        self.config.unique_root_mac && self.config.root_for_interface(name).is_some()
    }
}

// getifaddrs supplies link flags, not the IPv6 address flags which C obtains
// from netlink. procfs exports those same per-address flags in this namespace.
// Snapshot once per interface refresh, never once per request.
fn tentative_addresses() -> io::Result<Vec<(Ipv6Addr, u32)>> {
    let rows = match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(rows) => rows,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    Ok(rows.lines().filter_map(tentative_address).collect())
}

fn tentative_address(row: &str) -> Option<(Ipv6Addr, u32)> {
    let mut fields = row.split_ascii_whitespace();
    let address = u128::from_str_radix(fields.next()?, 16).ok()?;
    let interface = u32::from_str_radix(fields.next()?, 16).ok()?;
    fields.next()?; // prefix length
    fields.next()?; // scope
    let flags = u32::from_str_radix(fields.next()?, 16).ok()?;
    (flags & 0x40 != 0).then_some((Ipv6Addr::from(address), interface))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tftp::matches_name;
    #[test]
    fn address_flags_distinguish_dad_from_link_flags() {
        let address = "fe80::1".parse().unwrap();
        assert_eq!(
            tentative_address("fe800000000000000000000000000001 02 40 20 40 br-lan"),
            Some((address, 2))
        );
        assert_eq!(
            tentative_address("fe800000000000000000000000000001 02 40 20 80 br-lan"),
            None
        );
        assert_eq!(tentative_address("incomplete row"), None);
    }
    #[test]
    fn dedicated_interfaces_override_dhcp_exclusion_but_require_nonempty_wildcards() {
        let mut policy = Policy {
            config: TftpConfig {
                enabled: true,
                ..TftpConfig::default()
            },
            dns: DnsConfig::default(),
            no_dhcp: vec![Some(b"lan".to_vec())],
            interfaces: vec![],
            tentative: vec![],
        };
        assert!(!policy.tftp_interface(b"lan"));
        policy.config.interfaces.push(Some(b"lan".to_vec()));
        assert!(policy.tftp_interface(b"lan"));
        assert!(!policy.tftp_interface(b"wan"));
        assert!(!matches_name(b"lan*", b"lan"));
        assert!(matches_name(b"lan*", b"lan0"));
    }
    #[test]
    fn request_mtu_is_minimum_and_zero_means_unspecified() {
        let mut policy = Policy {
            config: TftpConfig::default(),
            dns: DnsConfig::default(),
            no_dhcp: vec![],
            interfaces: vec![],
            tentative: vec![],
        };
        let datagram = Datagram {
            len: 0,
            peer: "192.0.2.1:1234".parse().unwrap(),
            destination: "192.0.2.2".parse().unwrap(),
            local_address: "192.0.2.2".parse().unwrap(),
            interface: 2,
        };
        policy.config.mtu = Some(0);
        assert_eq!(
            policy.request(&datagram, b"lan", Some(1400), None).mtu,
            Some(1400)
        );
        policy.config.mtu = Some(1300);
        assert_eq!(
            policy.request(&datagram, b"lan", Some(1400), None).mtu,
            Some(1300)
        );
        assert_eq!(
            policy.request(&datagram, b"lan", None, None).mtu,
            Some(1300)
        );
    }
}
