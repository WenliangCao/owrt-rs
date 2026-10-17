//! IPv4 DHCP network policies from exact option.c and their packet selectors.

use super::dhcp::TagPredicate;
use super::{Directive, Error};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyDelay {
    pub tags: TagPredicate,
    pub seconds: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeInterface {
    pub name: Vec<u8>,
    pub aliases: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SharedSelector {
    Address(Ipv4Addr),
    /// C resolves this at option parsing, retaining the index across packets.
    Interface {
        name: Vec<u8>,
        index: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedNetwork {
    pub selector: SharedSelector,
    pub address: Ipv4Addr,
}

impl SharedNetwork {
    pub fn matches_local(&self, address: Ipv4Addr, interface: u32) -> bool {
        match self.selector {
            SharedSelector::Address(expected) => expected == address,
            SharedSelector::Interface { index, .. } => index == interface,
        }
    }

    pub fn matches_relay(&self, relay: Ipv4Addr) -> bool {
        matches!(self.selector, SharedSelector::Address(address) if address == relay)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkConfig {
    /// Lists preserve C's last declaration first order.
    pub delays: Vec<ReplyDelay>,
    pub bridges: Vec<BridgeInterface>,
    pub shared: Vec<SharedNetwork>,
    pub proxy_enabled: bool,
    pub proxy_relays: Vec<Ipv4Addr>,
}

fn address(value: &[u8], error: &'static str) -> Result<Ipv4Addr, Error> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(Error(error))
}

/// Startup/packet interface resolution uses the host namespace, never mutating it.
#[cfg(unix)]
pub fn interface_index(name: &[u8]) -> u32 {
    dnsmasq_platform::interfaces::interface_index(name)
}

#[cfg(not(unix))]
pub fn interface_index(_: &[u8]) -> u32 {
    0
}

impl NetworkConfig {
    /// Only shared-network interface selectors require startup resolution.
    /// Bridge masters resolve at the actual packet caller, as C does.
    pub fn apply(
        &mut self,
        directive: &Directive,
        mut interface_index: impl FnMut(&[u8]) -> u32,
    ) -> Result<bool, Error> {
        let argument = directive.argument.as_ref();
        match directive.name.as_slice() {
            b"dhcp-reply-delay" => {
                let values = argument.ok_or(Error("missing parameter"))?.split(b',');
                let mut tags = Vec::new();
                let mut number = None;
                for value in values {
                    if number.is_none()
                        && (value.encoded().starts_with(b"tag:")
                            || value.encoded().starts_with(b"net:"))
                    {
                        tags.push(value.decoded()[4..].to_vec());
                    } else if number.replace(value.decoded()).is_some() {
                        return Err(Error("error"));
                    }
                }
                let value = number.ok_or(Error("error"))?;
                // option.c:760 accepts decimal digits (including empty) and
                // image musl atoi retains the low signed-int bits.
                let seconds = value.iter().try_fold(0u32, |total, byte| {
                    byte.is_ascii_digit()
                        .then(|| total.wrapping_mul(10).wrapping_add(u32::from(byte - b'0')))
                        .ok_or(Error("error"))
                })? as i32;
                self.delays.insert(
                    0,
                    ReplyDelay {
                        tags: TagPredicate::from_tags(tags),
                        seconds,
                    },
                );
            }
            b"bridge-interface" => {
                let argument = argument.ok_or(Error("missing parameter"))?;
                let (name, aliases) = argument.split_once(b',');
                let name = name.decoded();
                let aliases = aliases.ok_or(Error("bad bridge-interface"))?;
                if name.len() > 15 {
                    return Err(Error("bad bridge-interface"));
                }
                let index =
                    if let Some(index) = self.bridges.iter().position(|entry| entry.name == name) {
                        index
                    } else {
                        self.bridges.insert(
                            0,
                            BridgeInterface {
                                name,
                                aliases: Vec::new(),
                            },
                        );
                        0
                    };
                for alias in aliases.split(b',') {
                    let alias = alias.decoded();
                    if !alias.is_empty() && alias.len() <= 15 {
                        self.bridges[index].aliases.insert(0, alias);
                    }
                }
            }
            b"dhcp-proxy" => {
                self.proxy_enabled = true;
                if let Some(argument) = argument {
                    for value in argument.split(b',') {
                        self.proxy_relays
                            .insert(0, address(&value.decoded(), "bad dhcp-proxy address")?);
                    }
                }
            }
            b"shared-network" => {
                let (selector, shared) =
                    argument.ok_or(Error("missing parameter"))?.split_once(b',');
                let shared = address(
                    &shared.ok_or(Error("bad shared-network"))?.decoded(),
                    "bad shared-network",
                )?;
                let selector = selector.decoded();
                let selector = match address(&selector, "bad shared-network") {
                    Ok(address) => SharedSelector::Address(address),
                    Err(_) => {
                        let index = interface_index(&selector);
                        if index == 0 {
                            return Err(Error("bad shared-network"));
                        }
                        SharedSelector::Interface {
                            name: selector,
                            index,
                        }
                    }
                };
                self.shared.insert(
                    0,
                    SharedNetwork {
                        selector,
                        address: shared,
                    },
                );
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Tagged matches win before any untagged fallback, in linked-list order.
    pub fn reply_delay(&self, tags: &[&[u8]]) -> Option<i32> {
        self.delays
            .iter()
            .find(|rule| rule.tags.matches_with(tags, false))
            .or_else(|| {
                self.delays
                    .iter()
                    .find(|rule| rule.tags.matches_with(tags, true))
            })
            .map(|rule| rule.seconds)
    }

    pub fn bridge_master(&self, received_name: &[u8]) -> Option<&[u8]> {
        self.bridges
            .iter()
            .find(|bridge| {
                bridge
                    .aliases
                    .iter()
                    .any(|pattern| alias_matches(pattern, received_name))
            })
            .map(|bridge| bridge.name.as_slice())
    }

    /// Resolve a bridge master for each packet. The caller keeps the original
    /// ingress index and name for actual reply routing and ARP injection.
    pub fn bridge_ingress(&self, received_name: &[u8]) -> Result<Option<(u32, Vec<u8>)>, Vec<u8>> {
        let Some(master) = self.bridge_master(received_name) else {
            return Ok(None);
        };
        let index = interface_index(master);
        if index == 0 {
            let mut message = b"unknown interface ".to_vec();
            message.extend_from_slice(master);
            message.extend_from_slice(b" in bridge-interface");
            return Err(message);
        }
        Ok(Some((index, master.to_vec())))
    }

    /// Agent suboption11 has priority. No giaddr means no proxy override.
    pub fn server_override(&self, relay: Ipv4Addr, agent: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        agent
            .filter(|address| !address.is_unspecified())
            .or_else(|| {
                (self.proxy_enabled
                    && !relay.is_unspecified()
                    && (self.proxy_relays.is_empty() || self.proxy_relays.contains(&relay)))
                .then_some(relay)
            })
    }
}

fn alias_matches(pattern: &[u8], name: &[u8]) -> bool {
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

    fn apply(config: &mut NetworkConfig, line: &[u8]) {
        let directive = crate::config::lex_line(line).unwrap().unwrap();
        assert!(config
            .apply(&directive, |name| if name == b"uplink" { 7 } else { 0 })
            .unwrap());
    }

    #[test]
    fn tagged_delay_precedes_later_fallback_and_later_tagged_rule_wins() {
        let mut config = NetworkConfig::default();
        for line in [
            b"dhcp-reply-delay=tag:known,2".as_slice(),
            b"dhcp-reply-delay=4",
            b"dhcp-reply-delay=tag:known,tag:!ignore,1",
        ] {
            apply(&mut config, line);
        }
        assert_eq!(config.reply_delay(&[b"known"]), Some(1));
        assert_eq!(config.reply_delay(&[b"known", b"ignore"]), Some(2));
        assert_eq!(config.reply_delay(&[]), Some(4));
    }

    #[test]
    fn bridge_repetitions_merge_without_reordering_existing_masters() {
        let mut config = NetworkConfig::default();
        for line in [
            b"bridge-interface=one,port*".as_slice(),
            b"bridge-interface=two,port2",
            b"bridge-interface=one,port2,,waytoolonginterfacename",
        ] {
            apply(&mut config, line);
        }
        assert_eq!(config.bridge_master(b"port2"), Some(b"two".as_slice()));
        assert_eq!(config.bridge_master(b"port9"), Some(b"one".as_slice()));
        assert_eq!(config.bridges.len(), 2);
        assert_eq!(config.bridges[1].aliases.len(), 2);
    }

    #[test]
    fn proxy_address_list_does_not_become_global_after_bare_repetition() {
        let mut config = NetworkConfig::default();
        apply(&mut config, b"dhcp-proxy=192.0.2.1");
        apply(&mut config, b"dhcp-proxy");
        let relay = "192.0.2.1".parse().unwrap();
        let other = "192.0.2.2".parse().unwrap();
        assert_eq!(config.server_override(relay, None), Some(relay));
        assert_eq!(config.server_override(other, None), None);
        assert_eq!(config.server_override(relay, Some(other)), Some(other));
        assert_eq!(config.server_override(Ipv4Addr::UNSPECIFIED, None), None);
    }

    #[test]
    fn shared_network_interface_index_is_fixed_and_is_not_a_relay_selector() {
        let mut config = NetworkConfig::default();
        apply(&mut config, b"shared-network=uplink,198.51.100.1");
        apply(&mut config, b"shared-network=192.0.2.1,198.51.100.2");
        let local = "192.0.2.1".parse().unwrap();
        assert!(config.shared[1].matches_local(local, 7));
        assert!(!config.shared[1].matches_relay(local));
        assert!(config.shared[0].matches_relay(local));
    }
}
