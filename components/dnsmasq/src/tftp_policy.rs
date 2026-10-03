//! TFTP interface, root and startup policy. This has no transfer state.
use crate::config::{dns::DnsConfig, tftp::TftpConfig};
use crate::interfaces::DnsInterface;
use crate::net::Datagram;
use crate::tftp_runtime::{RequestPolicy, RuntimePathPolicy};
use std::io;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;

pub(super) struct Policy {
    pub config: TftpConfig,
    pub dns: DnsConfig,
    no_dhcp: Vec<Option<Vec<u8>>>,
    pub interfaces: Vec<DnsInterface>,
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
        })
    }
    pub fn refresh(&mut self) -> io::Result<()> {
        self.interfaces = crate::interfaces::dns_interfaces()?;
        Ok(())
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
        if !self.config.interfaces.is_empty() {
            self.config
                .interfaces
                .iter()
                .flatten()
                .any(|pattern| matches_name(pattern, name))
        } else {
            !self
                .no_dhcp
                .iter()
                .flatten()
                .any(|pattern| matches_name(pattern, name))
        }
    }
    pub fn admitted(&self, datagram: &Datagram, name: &[u8]) -> bool {
        if self.dns.bind_interfaces && !self.dns.bind_dynamic && datagram.destination.is_ipv4() {
            return true; // static IPv4 listeners already select the interface
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
fn matches_name(pattern: &[u8], name: &[u8]) -> bool {
    for (pattern, actual) in pattern.iter().zip(name) {
        if *pattern == b'*' {
            return true;
        }
        if pattern != actual {
            return false;
        }
    }
    pattern.len() == name.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dedicated_interfaces_override_dhcp_exclusion_but_require_nonempty_wildcards() {
        let mut policy = Policy {
            config: TftpConfig::default(),
            dns: DnsConfig::default(),
            no_dhcp: vec![Some(b"lan".to_vec())],
            interfaces: vec![],
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
