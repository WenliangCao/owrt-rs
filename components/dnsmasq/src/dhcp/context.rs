//! Dynamic IPv4 context completion from dhcp.c:567–687.
//!
//! The caller supplies interface rows in C callback order, including any
//! preferred secondary address before the full enumeration. Primary-address
//! admission, listen-address/bridge filtering, shared networks and relays are
//! outside this boundary. Guessed fields persist across packets as they do in C.

use super::allocation::{AddressRange, RangeKind};
use crate::config::dhcp::RangeConfig;
use crate::interfaces::Ipv4Interface;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextState {
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub router: Ipv4Addr,
    pub local: Ipv4Addr,
    pub epoch: u32,
}

impl ContextState {
    pub fn new(config: &RangeConfig) -> Self {
        Self {
            netmask: config.netmask.unwrap_or(Ipv4Addr::UNSPECIFIED),
            broadcast: config.broadcast.unwrap_or(Ipv4Addr::UNSPECIFIED),
            router: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            epoch: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SelectedContext {
    pub source_index: usize,
    pub range: AddressRange,
    pub broadcast: Ipv4Addr,
}

fn same_net(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool {
    u32::from(a) & u32::from(mask) == u32::from(b) & u32::from(mask)
}

/// rfc2131.c:280-397 reselects a remote subnet after interface completion.
/// A selector or relay forces replacement; a client address can fall back to
/// the ingress chain so the state machine can issue the appropriate NAK.
#[allow(clippy::too_many_arguments)]
pub fn select_remote_contexts(
    configs: &[RangeConfig],
    states: &mut [ContextState],
    ingress: Vec<SelectedContext>,
    subnet: Ipv4Addr,
    relay: Ipv4Addr,
    client: Ipv4Addr,
    fallback: Ipv4Addr,
    override_server: Option<Ipv4Addr>,
) -> Vec<SelectedContext> {
    let forced = !subnet.is_unspecified() || !relay.is_unspecified();
    let address = if !subnet.is_unspecified() {
        subnet
    } else if !relay.is_unspecified() {
        relay
    } else {
        client
    };
    if address.is_unspecified()
        || (!forced
            && ingress
                .iter()
                .any(|context| context.range.same_subnet(address)))
    {
        return ingress;
    }
    let mut selected = Vec::new();
    for (index, (config, state)) in configs.iter().zip(states).enumerate() {
        let mut mask = state.netmask;
        if config.netmask.is_none() && mask.is_unspecified() {
            let first = config.start.octets()[0];
            let last = config.end.octets()[0];
            mask = match (first, last) {
                (0..=127, 0..=127) => Ipv4Addr::new(255, 0, 0, 0),
                (128..=191, 128..=191) => Ipv4Addr::new(255, 255, 0, 0),
                (192..=223, 192..=223) => Ipv4Addr::new(255, 255, 255, 0),
                _ => Ipv4Addr::UNSPECIFIED,
            };
        }
        if mask.is_unspecified()
            || !same_net(address, config.start, mask)
            || !same_net(address, config.end, mask)
        {
            continue;
        }
        state.netmask = mask;
        if state.local.is_unspecified() {
            state.local = fallback;
        }
        if state.router.is_unspecified() {
            state.router = override_server.unwrap_or(relay);
        }
        if config.broadcast.is_none() && state.broadcast.is_unspecified() {
            state.broadcast = Ipv4Addr::from(u32::from(config.start) | !u32::from(mask));
        }
        selected.push(SelectedContext {
            source_index: index,
            range: AddressRange {
                start: config.start,
                end: config.end,
                netmask: state.netmask,
                router: state.router,
                local: state.local,
                lease_time: config.lease_time,
                kind: RangeKind::Dynamic,
                filter: config.filter.tags().to_vec(),
                epoch: state.epoch,
            },
            broadcast: state.broadcast,
        });
    }
    if selected.is_empty() && !forced {
        ingress
    } else {
        selected.reverse();
        selected
    }
}

/// Complete the current dynamic ranges without reading or changing the OS.
///
/// `states` must have one entry per configured range, in the same order. The
/// caller must recreate that mapping if configuration ranges are replaced.
pub fn select_contexts(
    configs: &[RangeConfig],
    states: &mut [ContextState],
    interfaces: &[Ipv4Interface],
    received_index: u32,
) -> Vec<SelectedContext> {
    assert_eq!(
        configs.len(),
        states.len(),
        "context/config mapping changed"
    );
    let mut linked = vec![false; configs.len()];
    let mut current = Vec::new();
    for interface in interfaces {
        // guess_range_netmask runs for every address, including addresses on
        // interfaces other than the one that received the packet.
        for (config, state) in configs.iter().zip(states.iter_mut()) {
            if config.netmask.is_none()
                && (same_net(interface.address, config.start, interface.netmask)
                    || same_net(interface.address, config.end, interface.netmask))
            {
                state.netmask = interface.netmask;
            }
        }
        for (index, (config, state)) in configs.iter().zip(states.iter_mut()).enumerate() {
            if state.netmask.is_unspecified()
                || !same_net(interface.address, config.start, state.netmask)
                || !same_net(interface.address, config.end, state.netmask)
            {
                continue;
            }
            if interface.index == received_index && !linked[index] {
                state.router = interface.address;
                state.local = interface.address;
                linked[index] = true;
                current.push(index);
            }
            if config.broadcast.is_none() {
                state.broadcast = if same_net(interface.broadcast, config.start, state.netmask) {
                    interface.broadcast
                } else {
                    Ipv4Addr::from(u32::from(config.start) | !u32::from(state.netmask))
                };
            }
        }
    }
    // C prepends each linked context. Build after all callbacks: a later
    // address may change a linked context's mask or broadcast, but cannot
    // replace the first selected local/router address during this packet.
    current
        .into_iter()
        .rev()
        .map(|index| {
            let config = &configs[index];
            let state = &states[index];
            SelectedContext {
                source_index: index,
                range: AddressRange {
                    start: config.start,
                    end: config.end,
                    netmask: state.netmask,
                    router: state.router,
                    local: state.local,
                    lease_time: config.lease_time,
                    kind: RangeKind::Dynamic,
                    filter: config.filter.tags().to_vec(),
                    epoch: state.epoch,
                },
                broadcast: state.broadcast,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn config() -> RangeConfig {
        RangeConfig {
            set_tag: None,
            filter: Default::default(),
            start: address("192.0.2.10"),
            end: address("192.0.2.20"),
            netmask: None,
            broadcast: None,
            lease_time: 3600,
            lease_time_explicit: false,
        }
    }

    fn interface(local: &str) -> Ipv4Interface {
        Ipv4Interface {
            index: 2,
            address: address(local),
            netmask: address("255.255.255.0"),
            broadcast: address("192.0.2.255"),
            loopback: false,
        }
    }

    #[test]
    fn remote_subnet_forces_reselection_but_unknown_client_keeps_ingress() {
        let configs = [config()];
        let mut states = [ContextState::new(&configs[0])];
        let ingress = select_contexts(&configs, &mut states, &[interface("192.0.2.1")], 2);
        let zero = Ipv4Addr::UNSPECIFIED;
        let outside = address("198.51.100.10");
        assert_eq!(
            select_remote_contexts(
                &configs,
                &mut states,
                ingress.clone(),
                zero,
                zero,
                outside,
                address("192.0.2.1"),
                None
            )
            .len(),
            1
        );
        assert!(select_remote_contexts(
            &configs,
            &mut states,
            ingress.clone(),
            outside,
            zero,
            zero,
            address("192.0.2.1"),
            None
        )
        .is_empty());
        assert!(select_remote_contexts(
            &configs,
            &mut states,
            ingress,
            zero,
            outside,
            zero,
            address("192.0.2.1"),
            None
        )
        .is_empty());
    }

    #[test]
    fn relay_guesses_mask_and_retains_config_order_and_override_router() {
        let configs = [config(), config()];
        let mut states = configs.each_ref().map(ContextState::new);
        let zero = Ipv4Addr::UNSPECIFIED;
        let local = address("198.51.100.1");
        let router = address("192.0.2.254");
        let selected = select_remote_contexts(
            &configs,
            &mut states,
            Vec::new(),
            router,
            address("203.0.113.1"),
            zero,
            local,
            Some(router),
        );
        assert_eq!(
            selected
                .iter()
                .map(|row| row.source_index)
                .collect::<Vec<_>>(),
            [1, 0]
        );
        assert_eq!(selected[0].range.netmask, address("255.255.255.0"));
        assert_eq!(selected[0].range.router, router);
        assert_eq!(selected[0].range.local, local);
        assert_eq!(selected[0].broadcast, address("192.0.2.255"));
    }

    // Expected state is retained from the exact C bodies' deterministic
    // dhcp_context_diff.py cases; the Rust implementation is not the oracle.
    #[test]
    fn current_list_reverses_context_order_and_preserves_epoch_mapping() {
        let mut second = config();
        second.start = address("192.0.2.30");
        second.end = address("192.0.2.40");
        let configs = [config(), second];
        let mut states = configs.each_ref().map(ContextState::new);
        states[0].epoch = 8;
        states[1].epoch = 17;
        let selected = select_contexts(&configs, &mut states, &[interface("192.0.2.1")], 2);
        assert_eq!(selected.len(), 2);
        assert_eq!((selected[0].source_index, selected[0].range.epoch), (1, 17));
        assert_eq!((selected[1].source_index, selected[1].range.epoch), (0, 8));
    }

    #[test]
    fn explicit_zero_mask_is_not_an_unspecified_mask() {
        let mut config = config();
        config.netmask = Some(Ipv4Addr::UNSPECIFIED);
        let mut states = [ContextState::new(&config)];
        assert!(select_contexts(&[config], &mut states, &[interface("192.0.2.1")], 2).is_empty());
        assert!(states[0].netmask.is_unspecified());
    }

    #[test]
    fn preferred_alias_keeps_its_local_address_during_full_enumeration() {
        let config = config();
        let mut states = [ContextState::new(&config)];
        let rows = [
            interface("192.0.2.2"),
            interface("192.0.2.1"),
            interface("192.0.2.2"),
        ];
        let selected = select_contexts(&[config], &mut states, &rows, 2);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].range.router, address("192.0.2.2"));
        assert_eq!(selected[0].range.local, address("192.0.2.2"));
    }

    #[test]
    fn later_other_interface_updates_mask_and_broadcast_of_linked_context() {
        let config = config();
        let mut states = [ContextState::new(&config)];
        let mut later = interface("192.0.2.1");
        later.index = 7;
        later.netmask = address("255.255.0.0");
        later.broadcast = address("192.0.255.255");
        let selected = select_contexts(&[config], &mut states, &[interface("192.0.2.1"), later], 2);
        assert_eq!(selected[0].range.netmask, address("255.255.0.0"));
        assert_eq!(selected[0].broadcast, address("192.0.255.255"));
        assert_eq!(selected[0].range.local, address("192.0.2.1"));
    }

    #[test]
    fn guessed_mask_persists_across_interface_change_and_disappearance() {
        let configs = [config()];
        let mut states = [ContextState::new(&configs[0])];
        select_contexts(&configs, &mut states, &[interface("192.0.2.1")], 2);
        let previous = states.clone();
        assert!(select_contexts(&configs, &mut states, &[], 2).is_empty());
        assert_eq!(states, previous);
        let mut changed = interface("192.0.2.5");
        changed.netmask = address("255.255.255.252");
        changed.broadcast = address("192.0.2.7");
        let selected = select_contexts(&configs, &mut states, &[changed], 2);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].range.netmask, address("255.255.255.0"));
        assert_eq!(selected[0].broadcast, address("192.0.2.7"));
        assert_eq!(selected[0].range.local, address("192.0.2.5"));
    }

    #[test]
    fn explicit_broadcast_is_preserved_and_other_interface_does_not_select() {
        let mut config = config();
        config.broadcast = Some(Ipv4Addr::UNSPECIFIED);
        let configs = [config];
        let mut states = [ContextState::new(&configs[0])];
        assert!(select_contexts(&configs, &mut states, &[interface("192.0.2.1")], 7).is_empty());
        assert_eq!(states[0].netmask, address("255.255.255.0"));
        assert!(states[0].router.is_unspecified());
        let selected = select_contexts(&configs, &mut states, &[interface("192.0.2.1")], 2);
        assert!(selected[0].broadcast.is_unspecified());
    }
}
