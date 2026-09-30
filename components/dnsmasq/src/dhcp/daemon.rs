//! Linux local DHCP adapter: interface admission, contexts, state and options.
//! Relay, configured hosts/tags, durable leases and scripts remain separate
//! contracts. Interface snapshots are refreshed for each admitted packet.

use super::allocation::ProbeResult;
use super::context::{select_contexts, ContextState, SelectedContext};
use super::lease::LeaseStore;
use super::probe::IcmpProbe;
use super::runtime::{NetworkOptions, OutcomeProvider, RuntimeError, StateProvider};
use super::service::Dispatch;
use super::state::{Environment, Outcome, Reply};
use crate::config::dhcp::DhcpConfig;
use crate::interfaces::{ipv4_interfaces, primary_ipv4};
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct LocalProvider {
    config: DhcpConfig,
    leases: LeaseStore,
    states: Vec<ContextState>,
    selected: Vec<SelectedContext>,
    listen_addresses: Vec<IpAddr>,
    dns_port: u16,
    control: UdpSocket,
    probe: IcmpProbe,
    probe_error: Option<io::Error>,
    should_stop: fn() -> bool,
}

impl LocalProvider {
    pub fn new(
        config: DhcpConfig,
        listen_addresses: Vec<IpAddr>,
        dns_port: u16,
        should_stop: fn() -> bool,
    ) -> io::Result<Self> {
        Ok(Self {
            leases: LeaseStore::new(config.lease_max),
            states: config.ranges.iter().map(ContextState::new).collect(),
            probe: IcmpProbe::new(config.no_ping)?,
            probe_error: None,
            should_stop,
            config,
            selected: Vec::new(),
            listen_addresses,
            dns_port,
            control: UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
        })
    }

    /// Failed probing suppresses allocation while retaining prune/name side
    /// effects in the Outcome. Report the error after processing that state.
    pub fn take_probe_error(&mut self) -> Option<io::Error> {
        self.probe_error.take()
    }
}

impl OutcomeProvider for LocalProvider {
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
        let interface = dispatch.ingress.interface_index;
        let mut addresses =
            ipv4_interfaces().map_err(|error| RuntimeError::State(error.to_string()))?;
        let mut local = primary_ipv4(interface, &self.control)
            .map_err(|error| RuntimeError::State(error.to_string()))?;
        let loopback = addresses
            .iter()
            .any(|address| address.index == interface && address.loopback);
        self.selected.clear();
        if !self.listen_addresses.is_empty() && !self.listen_addresses.contains(&IpAddr::V4(local))
        {
            // dhcp.c:340-361: an explicitly selected secondary address gets
            // the first complete_context pass, before the full enumeration.
            let secondary = addresses
                .iter()
                .rev()
                .find(|address| {
                    address.index == interface
                        && self.listen_addresses.contains(&IpAddr::V4(address.address))
                })
                .copied();
            let Some(secondary) = secondary else {
                return Ok(Outcome {
                    reply: Reply::Ignore,
                    removed: Vec::new(),
                    lost_names: Vec::new(),
                });
            };
            local = secondary.address;
            addresses.insert(0, secondary);
        }
        self.selected =
            select_contexts(&self.config.ranges, &mut self.states, &addresses, interface);
        let mut ranges: Vec<_> = self
            .selected
            .iter()
            .map(|selected| selected.range.clone())
            .collect();
        let aliases: Vec<_> = addresses
            .iter()
            .filter(|address| address.index == interface)
            .map(|address| address.address)
            .collect();
        let environment = Environment {
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |value| value.as_secs() as i64),
            interface,
            authoritative: self.config.authoritative,
            unicast_destination: dispatch.ingress.unicast_destination,
            ignored: false,
            ignore_client_id: self.config.ignore_client_id,
            fqdn_only: false,
            rapid_commit: false,
            bootp_dynamic: self.config.bootp_dynamic,
            consecutive_addresses: self.config.sequential,
            override_server: None,
            fallback_server: local,
            server_aliases: &aliases,
        };
        let now = environment.now;
        let mut probe_error = None;
        let mut provider = StateProvider::new(
            &mut self.leases,
            &mut ranges,
            &[],
            None,
            &[],
            environment,
            |address, hash| match self.probe.check_with_stop(
                now,
                address,
                hash,
                loopback,
                self.should_stop,
            ) {
                Ok(result) => result,
                Err(error) => {
                    probe_error = Some(error);
                    ProbeResult::Failed
                }
            },
        );
        let result = provider.resolve(dispatch);
        self.probe_error = probe_error;
        for (selected, range) in self.selected.iter().zip(&ranges) {
            self.states[selected.source_index].epoch = range.epoch;
        }
        result
    }

    fn network_options(&self, outcome: &Outcome) -> Option<NetworkOptions> {
        let index = match outcome.reply {
            Reply::Offer { context, .. }
            | Reply::Ack { context, .. }
            | Reply::Bootp { context, .. } => context,
            Reply::Inform {
                context: Some(context),
                ..
            } => context,
            _ => return None,
        };
        let context = self.selected.get(index)?;
        Some(NetworkOptions {
            netmask: context.range.netmask,
            broadcast: (!context.broadcast.is_unspecified()).then_some(context.broadcast),
            router: (!context.range.router.is_unspecified()).then_some(context.range.router),
            dns_server: (self.dns_port == 53).then_some(context.range.local),
        })
    }
}
