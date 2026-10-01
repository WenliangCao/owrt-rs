//! Linux local DHCP adapter: interface admission, contexts, state and options.
//! Relay, configured hosts/tags, durable leases and scripts remain separate
//! contracts. Interface snapshots are refreshed for each admitted packet.

use super::allocation::ProbeResult;
use super::context::{select_contexts, ContextState, SelectedContext};
use super::lease::{Lease, LeaseStore, NameLost};
use super::persistence::{
    self, AlarmAction, DnsPublisher, DnsReport, LeasePersistence, PersistReport,
};
use super::probe::IcmpProbe;
use super::runtime::{NetworkOptions, OutcomeProvider, RuntimeError, StateProvider};
use super::service::Dispatch;
use super::state::{Environment, Outcome, Reply};
use crate::config::dhcp::DhcpConfig;
use crate::interfaces::{ipv4_interfaces, primary_ipv4};
use std::ffi::OsStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct RestoreStats {
    pub invalid_records: usize,
    pub clean_end: bool,
}

#[derive(Debug)]
pub struct MaintenanceReport {
    pub file: PersistReport,
    pub dns: DnsReport,
    pub removed: Vec<Lease>,
    pub lost_names: Vec<NameLost>,
    pub restore: Option<RestoreStats>,
}

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
    persistence: LeasePersistence,
    dns_publisher: Option<Box<dyn DnsPublisher>>,
    startup_removed: Vec<Lease>,
    restore_stats: Option<RestoreStats>,
    initialized: bool,
    alarm_deadline: Option<Instant>,
    pending_alarms: u32,
    maintenance_report: Option<MaintenanceReport>,
}

impl LocalProvider {
    pub fn new(
        config: DhcpConfig,
        listen_addresses: Vec<IpAddr>,
        dns_port: u16,
        should_stop: fn() -> bool,
    ) -> io::Result<Self> {
        let now = epoch_seconds();
        let (persistence, restored) = LeasePersistence::open(
            Path::new(OsStr::from_bytes(config.lease_path())),
            config.lease_read_only,
            config.lease_max,
        )?;
        let mut leases = LeaseStore::new(config.lease_max);
        let (startup_removed, restore_stats) = if let Some(restored) = restored {
            let stats = RestoreStats {
                invalid_records: restored.invalid_records,
                clean_end: restored.clean_end,
            };
            let removed = leases.restore(restored.records, now).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot restore lease database: {error:?}"),
                )
            })?;
            (removed, Some(stats))
        } else {
            (Vec::new(), None)
        };
        Ok(Self {
            leases,
            states: config.ranges.iter().map(ContextState::new).collect(),
            probe: IcmpProbe::new(config.no_ping)?,
            probe_error: None,
            should_stop,
            config,
            selected: Vec::new(),
            listen_addresses,
            dns_port,
            control: UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
            persistence,
            dns_publisher: None,
            startup_removed,
            restore_stats,
            initialized: false,
            alarm_deadline: None,
            pending_alarms: 0,
            maintenance_report: None,
        })
    }

    /// Failed probing suppresses allocation while retaining prune/name side
    /// effects in the Outcome. Report the error after processing that state.
    pub fn take_probe_error(&mut self) -> Option<io::Error> {
        self.probe_error.take()
    }

    /// Attach the dedicated DHCP DNS source. Ordinary Hosts are not a sink.
    /// Startup initialize or the next maintenance publishes the pending state.
    pub fn set_dns_publisher(&mut self, publisher: Box<dyn DnsPublisher>) {
        self.dns_publisher = Some(publisher);
    }

    pub fn take_maintenance_report(&mut self) -> Option<MaintenanceReport> {
        self.maintenance_report.take()
    }

    pub fn next_maintenance(&self) -> Option<Instant> {
        if !self.initialized || self.pending_alarms != 0 {
            Some(Instant::now())
        } else {
            self.alarm_deadline
        }
    }

    fn observe_alarm(&mut self) {
        if self
            .alarm_deadline
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            self.alarm_deadline = None;
            self.pending_alarms = self.pending_alarms.saturating_add(1);
        }
    }

    fn maintain(&mut self, now: i64, removed: Vec<Lease>, force_dns: bool) -> MaintenanceReport {
        let file = self.persistence.update(&mut self.leases, now);
        // A signal which became due during state/file work remains pending
        // even when this update installs a newer relative alarm.
        self.observe_alarm();
        match file.alarm {
            AlarmAction::Keep => {}
            AlarmAction::Immediate => self.pending_alarms = self.pending_alarms.saturating_add(1),
            AlarmAction::At(event) => {
                let seconds = event.saturating_sub(now).max(0) as u64;
                self.alarm_deadline = Instant::now().checked_add(Duration::from_secs(seconds));
            }
        }
        let dns = persistence::update_dns(
            &mut self.leases,
            self.dns_port != 0,
            force_dns,
            false,
            self.dns_publisher.as_deref_mut(),
        );
        let lost_names = LeaseStore::names_lost(&removed);
        MaintenanceReport {
            file,
            dns,
            removed,
            lost_names,
            restore: None,
        }
    }

    /// Complete startup after socket setup and publisher attachment. Calling
    /// it again is harmless and does not replay removed-lease ownership.
    pub fn initialize(&mut self, now: i64) -> MaintenanceReport {
        self.initialized = true;
        let mut removed = std::mem::take(&mut self.startup_removed);
        removed.extend(self.leases.prune(None, now));
        let mut report = self.maintain(now, removed, true);
        report.restore = self.restore_stats.take();
        report
    }

    /// Perform expiry and retry maintenance even when no DHCP packet arrives.
    /// The caller owns returned removals/name losses until cleanup completes.
    pub fn tick(&mut self, now: i64) -> Option<MaintenanceReport> {
        if !self.initialized {
            return Some(self.initialize(now));
        }
        self.observe_alarm();
        if self.pending_alarms == 0 {
            return None;
        }
        self.pending_alarms -= 1;
        let removed = self.leases.prune(None, now);
        Some(self.maintain(now, removed, false))
    }
}

fn epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs() as i64)
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
            now: epoch_seconds(),
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
        // StateProvider's Outcome still owns packet-triggered removals. I/O
        // failure is retained as a report and must not discard that outcome
        // or prevent lease publication / an otherwise valid response.
        self.maintenance_report = Some(self.maintain(now, Vec::new(), false));
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
            next_server: context.range.local,
            netmask: context.range.netmask,
            broadcast: (!context.broadcast.is_unspecified()).then_some(context.broadcast),
            router: (!context.range.router.is_unspecified()).then_some(context.range.router),
            dns_server: (self.dns_port == 53).then_some(context.range.local),
        })
    }
}
