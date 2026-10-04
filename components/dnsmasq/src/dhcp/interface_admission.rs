//! DHCP interface/address selection from network.c::iface_check and
//! dhcp.c:340-361. No OS access: the caller supplies its fresh IPv4 snapshot.

use crate::config::dns::DnsConfig;
use crate::interfaces::Ipv4Interface;
use std::net::{IpAddr, Ipv4Addr};

pub(super) struct InterfacePolicy {
    names: Vec<Option<Vec<u8>>>,
    excluded: Vec<Option<Vec<u8>>>,
    addresses: Vec<IpAddr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Selection {
    Primary,
    Secondary(Ipv4Interface),
}

impl InterfacePolicy {
    pub(super) fn new(addresses: Vec<IpAddr>) -> Self {
        Self {
            names: Vec::new(),
            excluded: Vec::new(),
            addresses,
        }
    }

    pub(super) fn from_dns(config: &DnsConfig) -> Self {
        Self {
            names: config.interfaces.clone(),
            excluded: config.excluded_interfaces.clone(),
            addresses: config.listen_addresses.clone(),
        }
    }

    /// An explicit interface OR primary listen address admits the primary.
    /// Except-interface vetoes name/default selection, but C lets explicit
    /// listen addresses override it. The caller applies no-dhcp-interface
    /// before this boundary, so an address cannot bypass that DHCP veto.
    pub(super) fn select(
        &self,
        name: Option<&[u8]>,
        index: u32,
        primary: Ipv4Addr,
        snapshot: &[Ipv4Interface],
    ) -> Option<Selection> {
        let loopback = snapshot
            .iter()
            .any(|row| row.index == index && row.loopback);
        if self.selected_address(name, primary, loopback) {
            return Some(Selection::Primary);
        }

        // check_listen_addrs visits every address and retains its last match.
        // Only after primary admission fails does this secondary get the
        // first complete_context pass ahead of the complete enumeration.
        snapshot
            .iter()
            .rev()
            .find(|row| row.index == index && self.addresses.contains(&IpAddr::V4(row.address)))
            .copied()
            .map(Selection::Secondary)
    }

    /// network.c iface_check for one enumerated address, without DHCP's
    /// secondary-address fallback which would admit a different address.
    pub(super) fn selected_address(
        &self,
        name: Option<&[u8]>,
        address: Ipv4Addr,
        loopback: bool,
    ) -> bool {
        let explicit_address = self.addresses.contains(&IpAddr::V4(address));
        let named = name.is_some_and(|name| {
            self.names
                .iter()
                .flatten()
                .any(|pattern| interface_matches(pattern, name))
        });
        // network.c adds discovered loopback names to a nonempty if_names.
        let loopback = !self.names.is_empty() && loopback;
        let excluded = name.is_some_and(|name| {
            self.excluded
                .iter()
                .flatten()
                .any(|pattern| interface_matches(pattern, name))
        });
        explicit_address
            || ((self.names.is_empty() && self.addresses.is_empty()) || named || loopback)
                && !excluded
    }
}

/// util.c wildcard_match accepts any nonempty suffix at the first '*'.
pub(super) fn interface_matches(pattern: &[u8], name: &[u8]) -> bool {
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

    fn policy(lines: &[&[u8]]) -> InterfacePolicy {
        let mut config = DnsConfig::default();
        for line in lines {
            let directive = crate::config::lex_line(line).unwrap().unwrap();
            assert!(config.apply(&directive).unwrap());
        }
        InterfacePolicy::from_dns(&config)
    }

    fn address(index: u32, text: &str) -> Ipv4Interface {
        let address: Ipv4Addr = text.parse().unwrap();
        Ipv4Interface {
            index,
            address,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::from(u32::from(address) | 255),
            loopback: address.is_loopback(),
        }
    }

    #[test]
    fn original_interface_and_loopback_listen_combination_is_a_union() {
        let policy = policy(&[b"interface=br-lan", b"listen-address=127.0.0.1"]);
        let snapshot = [
            address(2, "192.0.2.1"),
            address(1, "127.0.0.1"),
            address(3, "198.51.100.1"),
        ];
        assert_eq!(
            policy.select(Some(b"br-lan"), 2, snapshot[0].address, &snapshot),
            Some(Selection::Primary)
        );
        assert_eq!(
            policy.select(Some(b"lo"), 1, snapshot[1].address, &snapshot),
            Some(Selection::Primary)
        );
        assert_eq!(
            policy.select(Some(b"wan"), 3, snapshot[2].address, &snapshot),
            None
        );
    }

    #[test]
    fn named_interface_keeps_primary_even_when_a_secondary_is_listed() {
        let policy = policy(&[b"interface=br-lan", b"listen-address=192.0.2.2"]);
        let snapshot = [address(2, "192.0.2.1"), address(2, "192.0.2.2")];
        assert_eq!(
            policy.select(Some(b"br-lan"), 2, snapshot[0].address, &snapshot),
            Some(Selection::Primary)
        );
    }

    #[test]
    fn address_only_fallback_uses_last_match_on_received_interface() {
        let policy = InterfacePolicy::new(vec![
            "192.0.2.2".parse().unwrap(),
            "192.0.2.3".parse().unwrap(),
        ]);
        let snapshot = [
            address(2, "192.0.2.1"),
            address(2, "192.0.2.2"),
            address(2, "192.0.2.3"),
            address(3, "192.0.2.2"),
        ];
        assert_eq!(
            policy.select(Some(b"lan"), 2, snapshot[0].address, &snapshot),
            Some(Selection::Secondary(snapshot[2]))
        );
        assert_eq!(
            policy.select(Some(b"other"), 4, "203.0.113.1".parse().unwrap(), &snapshot),
            None
        );
        assert!(!policy.selected_address(Some(b"lan"), snapshot[0].address, false));
        assert!(policy.selected_address(Some(b"lan"), snapshot[1].address, false));
    }

    #[test]
    fn exclusion_vetoes_name_but_explicit_primary_or_secondary_overrides_it() {
        let snapshot = [address(2, "192.0.2.1"), address(2, "192.0.2.2")];
        let excluded = policy(&[b"interface=br-lan", b"except-interface=br-lan"]);
        assert_eq!(
            excluded.select(Some(b"br-lan"), 2, snapshot[0].address, &snapshot),
            None
        );
        let primary = policy(&[b"except-interface=br-lan", b"listen-address=192.0.2.1"]);
        assert_eq!(
            primary.select(Some(b"br-lan"), 2, snapshot[0].address, &snapshot),
            Some(Selection::Primary)
        );
        let secondary = policy(&[b"except-interface=br-lan", b"listen-address=192.0.2.2"]);
        assert_eq!(
            secondary.select(Some(b"br-lan"), 2, snapshot[0].address, &snapshot),
            Some(Selection::Secondary(snapshot[1]))
        );
    }

    #[test]
    fn unrestricted_and_implicit_loopback_selection_keep_exclusions() {
        let snapshot = [address(2, "192.0.2.1"), address(1, "127.0.0.1")];
        let unrestricted = InterfacePolicy::new(Vec::new());
        assert_eq!(
            unrestricted.select(Some(b"wan"), 2, snapshot[0].address, &snapshot),
            Some(Selection::Primary)
        );
        let named = policy(&[b"interface=br-lan"]);
        assert_eq!(
            named.select(Some(b"lo"), 1, snapshot[1].address, &snapshot),
            Some(Selection::Primary)
        );
        let excluded = policy(&[b"interface=br-lan", b"except-interface=lo"]);
        assert_eq!(
            excluded.select(Some(b"lo"), 1, snapshot[1].address, &snapshot),
            None
        );
    }

    #[test]
    fn interface_wildcards_require_a_nonempty_suffix_like_c() {
        assert!(interface_matches(b"br*", b"br-lan"));
        assert!(!interface_matches(b"br*", b"br"));
        assert!(!interface_matches(b"BR*", b"br-lan"));
        assert!(!interface_matches(b"*", b""));
        let policy = policy(&[b"interface=br*"]);
        let snapshot = [address(2, "192.0.2.1")];
        assert_eq!(
            policy.select(Some(b"br-lan"), 2, snapshot[0].address, &snapshot),
            Some(Selection::Primary)
        );
        assert_eq!(
            policy.select(Some(b"br"), 2, snapshot[0].address, &snapshot),
            None
        );
    }
}
