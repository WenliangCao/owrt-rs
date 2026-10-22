//! TFTP interface, root and startup policy. This has no transfer state.
use crate::config::{dns::DnsConfig, tftp::TftpConfig};
use crate::interfaces::DnsInterface;
use crate::net::Datagram;
use crate::tftp_runtime::{RequestPolicy, RuntimePathPolicy};
use std::io;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;

pub(super) enum Admission {
    Accept,
    Reject,
    Refresh,
}

pub(super) struct Policy {
    pub config: TftpConfig,
    pub dns: DnsConfig,
    no_dhcp: Vec<Option<Vec<u8>>>,
    no_tftp: Vec<Option<Vec<u8>>>,
    pub interfaces: Vec<DnsInterface>,
}
impl Policy {
    pub fn new(
        config: &TftpConfig,
        dns: &DnsConfig,
        no_dhcp: &[Option<Vec<u8>>],
        no_tftp: &[Option<Vec<u8>>],
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
        selected_dns.auth.clone_from(&dns.auth);
        selected_dns.bind_dynamic = dns.bind_dynamic;
        selected_dns.bind_interfaces = dns.bind_interfaces;
        let dns = selected_dns;
        Ok(Self {
            config: config.clone(),
            dns,
            no_dhcp: no_dhcp.to_vec(),
            no_tftp: no_tftp.to_vec(),
            interfaces: crate::interfaces::dns_interfaces()?,
        })
    }
    pub fn refresh(&mut self) -> io::Result<()> {
        self.interfaces = crate::interfaces::dns_interfaces()?;
        Ok(())
    }
    pub fn tentative(&self, address: SocketAddr) -> bool {
        let matching: Vec<_> = self
            .interfaces
            .iter()
            .filter(|row| {
                row.address == address.ip()
                    && match address {
                        SocketAddr::V6(address) if address.ip().is_unicast_link_local() => {
                            address.scope_id() == row.index
                        }
                        _ => true,
                    }
            })
            .collect();
        !matching.is_empty() && matching.iter().all(|row| row.tentative)
    }
    pub fn addresses(&self) -> Vec<SocketAddr> {
        let mut addresses = crate::listeners::bound_addresses(&self.dns, 69, &self.interfaces);
        for address in crate::listeners::tentative_addresses(&self.dns, 69, &self.interfaces) {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        if self.dns.bind_interfaces || self.dns.bind_dynamic {
            addresses.retain(|address| {
                self.interfaces
                    .iter()
                    .find(|row| {
                        row.address == address.ip()
                            && match address {
                                SocketAddr::V6(address) if address.ip().is_unicast_link_local() => {
                                    address.scope_id() == row.index
                                }
                                _ => true,
                            }
                    })
                    .is_none_or(|row| {
                        // network.c disables TFTP on an auth interface unless
                        // a dedicated enable-tftp interface list overrides it.
                        (!self.config.interfaces.is_empty()
                            || !self.dns.auth.selected(row.address, &row.name))
                            && self.tftp_interface(row.link_name())
                    })
            });
        }
        addresses
    }
    fn tftp_interface(&self, name: &[u8]) -> bool {
        crate::config::tftp::interface_enabled(
            self.config.enabled,
            &self.config.interfaces,
            // network.c excludes either family at bound-socket creation.
            // tftp.c's wildcard path excludes only INAME_4|INAME_6 together.
            if self.dns.bind_interfaces || self.dns.bind_dynamic {
                &self.no_dhcp
            } else {
                &self.no_tftp
            },
            name,
        )
    }
    pub fn admission(&self, datagram: &Datagram, name: &[u8], loopback: bool) -> Admission {
        if self.dns.bind_interfaces && !self.dns.bind_dynamic && datagram.destination.is_ipv4() {
            // tftp.c's static IPv4 path trusts socket creation eligibility.
            // It also accepts an unowned explicit listener, whose cached
            // name is NULL, without testing the dedicated interface list.
            return Admission::Accept;
        }
        if !self.config.interfaces.is_empty() {
            return if self.tftp_interface(name) {
                Admission::Accept
            } else {
                Admission::Reject
            };
        }
        if crate::listeners::udp_acl_name(&self.dns, datagram.local_address, name, loopback, false)
        {
            return if self.tftp_interface(name) {
                Admission::Accept
            } else {
                Admission::Reject
            };
        }
        if !self.dns.bind_dynamic {
            return Admission::Refresh;
        }
        if self.admitted_exception(datagram, name, loopback) {
            Admission::Accept
        } else {
            Admission::Reject
        }
    }

    pub fn admitted_exception(&self, datagram: &Datagram, name: &[u8], loopback: bool) -> bool {
        crate::listeners::udp_acl_exception(
            &self.dns,
            &self.interfaces,
            datagram.local_address,
            datagram.interface,
            loopback,
        ) && self.tftp_interface(name)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tftp::matches_name;
    #[test]
    fn link_local_tftp_policy_uses_the_scoped_owner() {
        let mut dns = DnsConfig::default();
        dns.bind_interfaces = true;
        let mut policy = Policy {
            config: TftpConfig {
                enabled: true,
                ..TftpConfig::default()
            },
            dns,
            no_dhcp: vec![Some(b"lan".to_vec())],
            no_tftp: vec![Some(b"lan".to_vec())],
            interfaces: [(2, b"lan".to_vec()), (3, b"wan".to_vec())]
                .into_iter()
                .map(|(index, name)| DnsInterface {
                    index,
                    name,
                    address: "fe80::1".parse().unwrap(),
                    netmask: "ffff:ffff:ffff:ffff::".parse().unwrap(),
                    loopback: false,
                    tentative: false,
                })
                .collect(),
        };
        assert_eq!(policy.addresses(), vec!["[fe80::1%3]:69".parse().unwrap()]);
        policy.dns.bind_interfaces = false;
        policy.dns.bind_dynamic = true;
        assert_eq!(policy.addresses(), vec!["[fe80::1%3]:69".parse().unwrap()]);
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
            no_tftp: vec![Some(b"lan".to_vec())],
            interfaces: vec![],
        };
        assert!(!policy.tftp_interface(b"lan"));
        policy.config.interfaces.push(Some(b"lan".to_vec()));
        assert!(policy.tftp_interface(b"lan"));
        assert!(!policy.tftp_interface(b"wan"));
        assert!(!matches_name(b"lan*", b"lan"));
        assert!(matches_name(b"lan*", b"lan0"));
        policy.config.interfaces.clear();
        policy.no_tftp.clear();
        assert!(policy.tftp_interface(b"lan"));
        policy.dns.bind_interfaces = true;
        assert!(!policy.tftp_interface(b"lan"));
        policy.dns.bind_interfaces = false;
        policy.dns.bind_dynamic = true;
        assert!(!policy.tftp_interface(b"lan"));
    }
    #[test]
    fn request_mtu_is_minimum_and_zero_means_unspecified() {
        let mut policy = Policy {
            config: TftpConfig::default(),
            dns: DnsConfig::default(),
            no_dhcp: vec![],
            no_tftp: vec![],
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
