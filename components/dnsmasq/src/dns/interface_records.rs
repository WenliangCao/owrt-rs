//! Pure network.c interface-name snapshots; the parent owner selects when to
//! enumerate. Cloning a snapshot preserves the non-debug TCP fork boundary.
use crate::config::interface_records::InterfaceRule;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct InterfaceAddress {
    pub label: Vec<u8>,
    pub address: IpAddr,
    pub prefix: u8,
    /// Linux ifaddrmsg flags, not link flags. C consumes the three state bits.
    pub flags: u8,
}

#[derive(Clone, Debug)]
pub struct RecordAddress {
    pub address: IpAddr,
    pub reverse_only: bool,
}

#[derive(Clone, Debug)]
struct RuleAddresses {
    rule: InterfaceRule,
    addresses: Vec<RecordAddress>,
}

#[derive(Clone, Debug, Default)]
pub struct InterfaceRecords {
    entries: Vec<RuleAddresses>,
}

/// The owner calls this only at an actual C enumeration boundary. Existing
/// listener/DHCP snapshots stay independent from published interface records.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn read_addresses() -> std::io::Result<Vec<InterfaceAddress>> {
    use std::fs;
    let interfaces = crate::interfaces::dns_interfaces()?;
    let flags = match fs::read_to_string("/proc/net/if_inet6") {
        Ok(text) => text.lines().filter_map(ipv6_flags).collect::<Vec<_>>(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    let mut addresses = Vec::new();
    // Stable family partition matches network.c's IPv6 then IPv4 dumps.
    for ipv6 in [true, false] {
        for interface in interfaces
            .iter()
            .filter(|value| value.address.is_ipv6() == ipv6)
        {
            let prefix = match interface.netmask {
                IpAddr::V4(mask) => u32::from(mask).count_ones(),
                IpAddr::V6(mask) => u128::from(mask).count_ones(),
            } as u8;
            let state = flags
                .iter()
                .find_map(|&(address, index, flags)| {
                    (interface.index == index && interface.address == IpAddr::V6(address))
                        .then_some(flags)
                })
                .unwrap_or(if interface.tentative { 0x40 } else { 0 });
            addresses.push(InterfaceAddress {
                label: interface.name.clone(),
                address: interface.address,
                prefix,
                flags: state,
            });
        }
    }
    Ok(addresses)
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn ipv6_flags(line: &str) -> Option<(Ipv6Addr, u32, u8)> {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 6 || fields[0].len() != 32 || !fields[0].is_ascii() {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&fields[0][index * 2..index * 2 + 2], 16).ok()?;
    }
    Some((
        Ipv6Addr::from(bytes),
        u32::from_str_radix(fields[1], 16).ok()?,
        u32::from_str_radix(fields[4], 16).ok()? as u8,
    ))
}

fn label_matches(label: &[u8], configured: &[u8]) -> bool {
    // strncmp(..., IF_NAMESIZE) compares the terminating zero too. Unlike the
    // server source parser, an overlong configured interface is not truncated.
    label
        .iter()
        .copied()
        .chain([0])
        .take(16)
        .eq(configured.iter().copied().chain([0]).take(16))
}

fn composed(rule: &InterfaceRule, input: &InterfaceAddress) -> Option<RecordAddress> {
    let address = match input.address {
        IpAddr::V4(value) if rule.family4 || rule.prototype4.is_some() => {
            let mask = u32::MAX
                .checked_shl(32u32.checked_sub(u32::from(input.prefix))?)
                .unwrap_or(0);
            IpAddr::V4(rule.prototype4.map_or(value, |prototype| {
                Ipv4Addr::from((u32::from(value) & mask) | (u32::from(prototype) & !mask))
            }))
        }
        IpAddr::V6(value) if rule.family6 || rule.prototype6.is_some() => {
            if value.segments()[0] & 0xffc0 == 0xfe80 {
                return None;
            }
            let mask = u128::MAX
                .checked_shl(128u32.checked_sub(u32::from(input.prefix))?)
                .unwrap_or(0);
            IpAddr::V6(rule.prototype6.map_or(value, |prototype| {
                Ipv6Addr::from((u128::from(value) & mask) | (u128::from(prototype) & !mask))
            }))
        }
        _ => return None,
    };
    Some(RecordAddress {
        address,
        reverse_only: address.is_ipv6() && input.flags & (0x01 | 0x20 | 0x40) != 0,
    })
}

impl InterfaceRecords {
    /// Inputs follow C enumeration order: IPv6 dump, then IPv4 dump. Each rule
    /// prepends new results and keeps the flags of the first duplicate input.
    pub fn from_addresses(rules: &[InterfaceRule], inputs: &[InterfaceAddress]) -> Self {
        let entries = rules
            .iter()
            .map(|rule| {
                let mut addresses: Vec<RecordAddress> = Vec::new();
                for input in inputs {
                    if label_matches(&input.label, &rule.interface) {
                        if let Some(address) = composed(rule, input) {
                            if !addresses.iter().any(|old| old.address == address.address) {
                                addresses.insert(0, address);
                            }
                        }
                    }
                }
                RuleAddresses {
                    rule: rule.clone(),
                    addresses,
                }
            })
            .collect();
        Self { entries }
    }

    pub fn declared(&self, name: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.rule.name.eq_ignore_ascii_case(name))
    }

    /// Some(empty) means an interface declaration intercepts this family but
    /// supplies no eligible answer. The caller must bypass ordinary address
    /// cache/synth lookup and may still forward; it is not an immediate NODATA.
    pub fn forward(
        &self,
        name: &[u8],
        ipv6: bool,
        local_network: Option<(Ipv4Addr, Ipv4Addr)>,
    ) -> Option<Vec<IpAddr>> {
        if !self.declared(name) {
            return None;
        }
        let matching = || {
            self.entries
                .iter()
                .filter(|entry| entry.rule.name.eq_ignore_ascii_case(name))
                .flat_map(|entry| &entry.addresses)
                .filter(|address| address.address.is_ipv6() == ipv6)
        };
        let same_net = |address: IpAddr| match (address, local_network) {
            (IpAddr::V4(value), Some((local, mask))) if !local.is_unspecified() => {
                u32::from(value) & u32::from(mask) == u32::from(local) & u32::from(mask)
            }
            _ => false,
        };
        let localise =
            !ipv6 && local_network.is_some() && matching().any(|address| same_net(address.address));
        Some(
            matching()
                .filter(|address| !address.reverse_only && (!localise || same_net(address.address)))
                .map(|address| address.address)
                .collect(),
        )
    }

    pub fn reverse(&self, address: IpAddr) -> Option<&[u8]> {
        let mut index = 0;
        while let Some(entry) = self.entries.get(index) {
            if entry.addresses.iter().any(|old| old.address == address) {
                return Some(&entry.rule.name);
            }
            let prototype = if address.is_ipv6() {
                entry.rule.prototype6.is_some()
            } else {
                entry.rule.prototype4.is_some()
            };
            if !prototype {
                while index + 1 < self.entries.len()
                    && self.entries[index].rule.interface == self.entries[index + 1].rule.interface
                {
                    index += 1;
                }
            }
            index += 1;
        }
        None
    }

    /// check_for_local_domain tests whether configured names lie below the
    /// question: exact names and ancestors exist, arbitrary descendants do not.
    pub fn name_exists(&self, name: &[u8]) -> bool {
        self.entries.iter().any(|entry| {
            let configured = &entry.rule.name;
            name.is_empty()
                || configured.eq_ignore_ascii_case(name)
                || (configured.len() > name.len()
                    && configured[configured.len() - name.len() - 1] == b'.'
                    && configured[configured.len() - name.len()..].eq_ignore_ascii_case(name))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{interface_records::parse_rule, EncodedArg};
    fn rule(value: &str, dynamic: bool) -> InterfaceRule {
        parse_rule(&EncodedArg::command_line(value.as_bytes()), dynamic).unwrap()
    }
    #[test]
    fn adjacent_family_skip_and_ancestor_existence_match_image() {
        let source = InterfaceAddress {
            label: b"m5ir0".to_vec(),
            address: "198.18.91.9".parse().unwrap(),
            prefix: 24,
            flags: 0,
        };
        let rules = [
            rule("first.records.test,m5ir0/6", false),
            rule("second.records.test,m5ir0/4", false),
        ];
        let records = InterfaceRecords::from_addresses(&rules, &[source]);
        assert!(records.reverse("198.18.91.9".parse().unwrap()).is_none());
        assert!(records.name_exists(b"records.test"));
        assert!(!records.name_exists(b"child.second.records.test"));
        assert_eq!(
            records.forward(b"first.records.test", false, None),
            Some(Vec::new())
        );
    }
    #[test]
    fn prototype_duplicate_retains_first_address_flags() {
        let rules = [rule("proto.test,2001:db8::7,m5ir0", true)];
        let source = InterfaceAddress {
            label: b"m5ir0".to_vec(),
            address: "2001:db8:91::9".parse().unwrap(),
            prefix: 64,
            flags: 1,
        };
        let mut permanent = source.clone();
        permanent.address = "2001:db8:91::10".parse().unwrap();
        permanent.flags = 0x80;
        let records = InterfaceRecords::from_addresses(&rules, &[source, permanent]);
        assert_eq!(records.forward(b"proto.test", true, None), Some(Vec::new()));
        assert_eq!(
            records.reverse("2001:db8:91::7".parse().unwrap()),
            Some(b"proto.test".as_slice())
        );
    }
}
