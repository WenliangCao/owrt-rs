//! IPv4 interface snapshots for DHCP context selection. No network mutation.

use std::net::{IpAddr, Ipv4Addr};

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[path = "interfaces_broadcast.rs"]
mod ipv4_broadcast;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[path = "interfaces_ipv4.rs"]
mod ipv4_snapshot;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use ipv4_snapshot::Ipv4Snapshot;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Interface {
    pub index: u32,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub loopback: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsInterface {
    pub index: u32,
    pub name: Vec<u8>,
    pub address: IpAddr,
    pub netmask: IpAddr,
    pub loopback: bool,
    /// IFA_F_TENTATIVE is an address flag, independent of IFF_UP.
    pub tentative: bool,
}

impl DnsInterface {
    /// IPv4 address labels select addresses; ingress/TFTP uses the real link.
    pub fn link_name(&self) -> &[u8] {
        self.name.split(|byte| *byte == b':').next().unwrap_or(&[])
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use linux::primary_ipv4_with_name;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use linux::{dns_interfaces, ipv4_interfaces, primary_ipv4};

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod linux {
    use super::{DnsInterface, Ipv4Interface};
    use dnsmasq_platform::interfaces::{self as platform, InterfaceAddresses};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};

    /// Return SIOCGIFADDR's primary address using the caller's retained socket.
    pub fn primary_ipv4(index: u32, control: &UdpSocket) -> io::Result<Ipv4Addr> {
        primary_ipv4_with_name(index, None, control)
    }

    pub(crate) fn primary_ipv4_with_name(
        index: u32,
        name: Option<&[u8]>,
        control: &UdpSocket,
    ) -> io::Result<Ipv4Addr> {
        if let Some(name) = name {
            platform::interface_ipv4(control, name)
        } else {
            let name = crate::net::interface_name(control, index)?;
            platform::interface_ipv4(control, name.split(|&b| b == 0).next().unwrap())
        }
    }

    /// Aliases remain distinct, as required by DHCP context selection.
    pub fn ipv4_interfaces() -> io::Result<Vec<Ipv4Interface>> {
        let addresses = InterfaceAddresses::new()?;
        let broadcasts = super::ipv4_broadcast::snapshot()?;
        let mut result = Vec::new();
        addresses.visit(|entry| {
            if entry.flags & 1 == 0 {
                return;
            }
            let (IpAddr::V4(address), IpAddr::V4(netmask)) = (entry.address, entry.netmask) else {
                return;
            };
            let index = entry.index();
            if index == 0 {
                return;
            }
            let broadcast = if entry.flags & 2 != 0 {
                // Only an explicit IFA_BROADCAST is a broadcast address.
                broadcasts
                    .iter()
                    .find_map(|&(id, local, broadcast)| {
                        (id == index && local == address).then_some(broadcast)
                    })
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
            } else {
                Ipv4Addr::UNSPECIFIED
            };
            result.push(Ipv4Interface {
                index,
                address,
                netmask,
                broadcast,
                loopback: entry.flags & 8 != 0,
            });
        });
        Ok(result)
    }

    pub fn dns_interfaces() -> io::Result<Vec<DnsInterface>> {
        let addresses = InterfaceAddresses::new()?;
        let tentative = tentative_addresses()?;
        let mut result = Vec::new();
        addresses.visit(|entry| {
            // DNS enumeration includes down links, as in the original caller.
            let index = entry.index();
            if index != 0 {
                result.push(DnsInterface {
                    index,
                    name: entry.name.to_bytes().to_vec(),
                    address: entry.address,
                    netmask: entry.netmask,
                    loopback: entry.flags & 8 != 0,
                    tentative: match entry.address {
                        IpAddr::V6(ip) => tentative.contains(&(ip, index)),
                        IpAddr::V4(_) => false,
                    },
                });
            }
        });
        Ok(result)
    }

    // getifaddrs exports link flags. procfs exports the same IPv6 address
    // flags which dnsmasq's netlink callback uses, within this namespace.
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

        #[test]
        fn address_flags_distinguish_dad_from_link_flags() {
            assert_eq!(
                tentative_address("fe800000000000000000000000000001 02 40 20 40 br-lan"),
                Some(("fe80::1".parse().unwrap(), 2))
            );
            assert_eq!(
                tentative_address("fe800000000000000000000000000001 02 40 20 80 br-lan"),
                None
            );
            assert_eq!(tentative_address("incomplete row"), None);
        }

        #[test]
        #[ignore = "requires a private Linux network namespace"]
        fn isolated_loopback_snapshot_matches_kernel_configuration() {
            assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
            let snapshot = ipv4_interfaces().unwrap();
            assert_eq!(snapshot.len(), 1);
            let interface = snapshot[0];
            assert_eq!(interface.address, Ipv4Addr::LOCALHOST);
            assert_eq!(interface.netmask, Ipv4Addr::new(255, 0, 0, 0));
            assert!(interface.loopback);
            assert_ne!(interface.index, 0);
            let control = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
            assert_eq!(
                primary_ipv4(interface.index, &control).unwrap(),
                interface.address
            );
            assert!(primary_ipv4(u32::MAX, &control).is_err());
            assert_eq!(
                primary_ipv4_with_name(u32::MAX, Some(b"lo"), &control).unwrap(),
                interface.address
            );
            assert!(primary_ipv4_with_name(interface.index, Some(b"absent"), &control).is_err());
        }
    }
}
