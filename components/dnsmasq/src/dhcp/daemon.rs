//! Linux local DHCP adapter: interface admission, contexts, state and options.
//! Relay, tag selectors and scripts remain separate contracts. Interface
//! snapshots are refreshed for each admitted packet.

use super::allocation::ProbeResult;
use super::context::{select_contexts, ContextState, SelectedContext};
use super::lease::{ClientIdentity, Lease, LeaseError, LeaseStore, NameLost, RestoreError};
use super::persistence::{
    self, AlarmAction, DnsPublisher, DnsReport, LeasePersistence, PersistReport,
};
use super::probe::IcmpProbe;
use super::runtime::{NetworkOptions, OutcomeProvider, ReplyNames, RuntimeError, StateProvider};
use super::service::Dispatch;
use super::state::{Environment, HostPolicy, Outcome, Reply};
use crate::config::dhcp::{DhcpConfig, HostConfig, HostFileError, HostFiles, NameDomains};
use crate::interfaces::{ipv4_interfaces, primary_ipv4};
use std::ffi::OsStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Startup operation determines the C exit class; errno alone does not.
#[derive(Debug)]
pub enum StartupError {
    LeaseFile(io::Error),
    Restore(RestoreError),
    Socket(io::Error),
    Entropy(io::Error),
}

impl StartupError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::LeaseFile(error)
                if error
                    .get_ref()
                    .is_some_and(|cause| cause.is::<super::lease_file::CapacityExceeded>()) =>
            {
                5
            }
            Self::Restore(RestoreError::Lease(LeaseError::Full)) | Self::Entropy(_) => 5,
            Self::LeaseFile(_) | Self::Restore(_) => 3,
            Self::Socket(_) => 2,
        }
    }
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeaseFile(error) => write!(formatter, "cannot open or read lease file: {error}"),
            Self::Restore(error) => write!(formatter, "cannot restore lease database: {error:?}"),
            Self::Socket(error) => write!(formatter, "cannot create DHCP control socket: {error}"),
            Self::Entropy(error) => write!(formatter, "cannot initialize DHCP entropy: {error}"),
        }
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LeaseFile(error) | Self::Socket(error) | Self::Entropy(error) => Some(error),
            Self::Restore(_) => None,
        }
    }
}

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
    pub host_files: Vec<HostFileError>,
}

pub struct LocalProvider {
    config: DhcpConfig,
    leases: LeaseStore,
    states: Vec<ContextState>,
    hosts: Vec<HostPolicy>,
    inline_hosts: Vec<HostConfig>,
    host_files: HostFiles,
    host_files_ready: bool,
    reserved: Vec<Ipv4Addr>,
    domains: NameDomains,
    reply_hostname: Option<Vec<u8>>,
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
    ) -> Result<Self, StartupError> {
        // The C global entropy check precedes lease-file creation. Keep this
        // provider's dependency failures on the same side of that mutation.
        let probe = IcmpProbe::new(config.no_ping).map_err(StartupError::Entropy)?;
        let now = epoch_seconds();
        let (persistence, restored) = LeasePersistence::open(
            Path::new(OsStr::from_bytes(config.lease_path())),
            config.lease_read_only,
            config.lease_max,
        )
        .map_err(StartupError::LeaseFile)?;
        let mut leases = LeaseStore::new(config.lease_max);
        let (startup_removed, restore_stats) = if let Some(restored) = restored {
            let stats = RestoreStats {
                invalid_records: restored.invalid_records,
                clean_end: restored.clean_end,
            };
            let removed = leases
                .restore(restored.records, now)
                .map_err(StartupError::Restore)?;
            (removed, Some(stats))
        } else {
            (Vec::new(), None)
        };
        Ok(Self {
            leases,
            states: config.ranges.iter().map(ContextState::new).collect(),
            hosts: config.hosts.iter().map(host_policy).collect(),
            inline_hosts: config.hosts.clone(),
            host_files: HostFiles::new(&config.host_files),
            host_files_ready: true,
            reserved: config
                .hosts
                .iter()
                .filter_map(|host| host.address)
                .collect(),
            domains: NameDomains::default(),
            reply_hostname: None,
            probe,
            probe_error: None,
            should_stop,
            config,
            selected: Vec::new(),
            listen_addresses,
            dns_port,
            control: UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(StartupError::Socket)?,
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

    /// Install the validated address-to-domain fields before initialize.
    pub fn set_dns_config(&mut self, config: &crate::config::dns::DnsConfig) -> io::Result<()> {
        self.domains = NameDomains::new(config)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(())
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
            host_files: Vec::new(),
        }
    }

    /// Complete startup after socket setup and publisher attachment. Calling
    /// it again is harmless and does not replay removed-lease ownership.
    pub fn initialize(&mut self, now: i64) -> MaintenanceReport {
        let mut host_files = Vec::new();
        if !self.initialized {
            self.leases
                .initialize_fqdns(|address| self.domains.for_address(address));
            host_files = self.reread_host_files();
            if self.host_files_ready {
                self.update_configured_names();
            }
        }
        self.initialized = true;
        let mut removed = std::mem::take(&mut self.startup_removed);
        removed.extend(self.leases.prune(None, now));
        let mut report = self.maintain(now, removed, true);
        report.restore = self.restore_stats.take();
        report.host_files = host_files;
        report
    }

    fn update_configured_names(&mut self) {
        // lease.c lease_update_from_configs runs without a context chain:
        // a configured name is restored only for its own fixed address. Removing
        // a rule does not delete its lease or the lease's previous name.
        let names: Vec<_> = self
            .leases
            .active_newest_first()
            .iter()
            .filter_map(|lease| {
                let index = self.config.find_host(
                    lease.identity.client_id.as_deref(),
                    lease.identity.hardware_type,
                    Some(&lease.identity.hardware_address),
                    |_| true,
                )?;
                let host = &self.config.hosts[index];
                (host.address.is_none_or(|address| address == lease.address))
                    .then(|| {
                        host.hostname
                            .as_ref()
                            .map(|name| (lease.address, name.clone()))
                    })
                    .flatten()
            })
            .collect();
        for (address, name) in names {
            // Addresses were taken from this store and no removal occurs
            // during the loop, so set_hostname cannot fail NotFound.
            self.leases
                .set_hostname(
                    address,
                    Some(&name),
                    true,
                    self.domains.for_address(address),
                    false,
                )
                .expect("restored lease remains present during configured-name update");
        }
    }

    fn reread_host_files(&mut self) -> Vec<HostFileError> {
        let report = self.host_files.reload(&self.inline_hosts);
        self.host_files_ready = report.ready();
        if self.host_files_ready {
            // C frees CONFIG_BANK records and their DECLINE state; unchanged
            // command-line/main records retain theirs across SIGHUP.
            let inline = self
                .hosts
                .split_off(self.hosts.len() - self.inline_hosts.len());
            self.hosts = report.hosts[..report.hosts.len() - self.inline_hosts.len()]
                .iter()
                .map(host_policy)
                .collect();
            self.hosts.extend(inline);
            self.reserved = report
                .hosts
                .iter()
                .filter_map(|host| host.address)
                .collect();
            self.config.hosts = report.hosts;
        }
        report.errors
    }

    /// SIGHUP data-file stage, after the caller reloads DNS hosts and before
    /// acknowledging its reload generation. The main configuration is retained.
    /// Unsupported valid-C selectors pause DHCP admission until a later valid
    /// reload; never serve a partially widened rule set.
    pub fn reload_host_files(&mut self, now: i64) -> MaintenanceReport {
        if !self.initialized {
            return self.initialize(now);
        }
        let host_files = self.reread_host_files();
        if self.host_files_ready {
            self.update_configured_names();
        }
        let mut report = self.maintain(now, Vec::new(), true);
        report.host_files = host_files;
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

fn host_policy(host: &HostConfig) -> HostPolicy {
    HostPolicy {
        address: host.address,
        lease_time: host.lease_time,
        declined_at: None,
        hardware_addresses: host
            .hardware
            .iter()
            .map(|hardware| ClientIdentity {
                hardware_type: hardware.kind,
                hardware_address: hardware.address.clone(),
                client_id: None,
            })
            .collect(),
        ignore_client_id: host.ignore_client_id,
    }
}

fn epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs() as i64)
}

impl OutcomeProvider for LocalProvider {
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
        if !self.host_files_ready {
            return Ok(Outcome {
                reply: Reply::Ignore,
                removed: Vec::new(),
                lost_names: Vec::new(),
            });
        }
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
        let now = epoch_seconds();
        let packet = dispatch.packet;
        let identity = ClientIdentity {
            hardware_type: u32::from(packet.hardware_type()),
            hardware_address: packet.hardware_address().to_vec(),
            client_id: (!self.config.ignore_client_id && packet.message_type() != 0)
                .then(|| packet.client_id().map(<[u8]>::to_vec))
                .flatten(),
        };
        let existing = self
            .leases
            .find_client(&identity)
            .filter(|lease| lease.expires.is_none_or(|expiry| now < expiry));
        let clid = (packet.message_type() != 0)
            .then(|| {
                identity
                    .client_id
                    .as_deref()
                    .or_else(|| existing.and_then(|lease| lease.identity.client_id.as_deref()))
            })
            .flatten();
        let host_index = self.config.find_host(
            clid,
            identity.hardware_type,
            Some(&identity.hardware_address),
            |address| {
                ranges.iter().any(|range| {
                    u32::from(address) & u32::from(range.netmask)
                        == u32::from(range.start) & u32::from(range.netmask)
                })
            },
        );
        let configured = host_index.map(|index| &self.config.hosts[index]);
        let configured_name = configured.and_then(|host| host.hostname.as_deref());
        let client_name = packet.client_hostname();
        self.reply_hostname = configured_name.map(<[u8]>::to_vec).or(client_name);
        if packet.message_type() == 1 && packet.option(81, 3).is_none() {
            // An ordinary client name alone is not echoed in an OFFER. A
            // configured name must match the full provided name, before strip.
            let provided = packet.client_hostname_full();
            if configured_name.is_none()
                || provided
                    .as_deref()
                    .is_some_and(|name| !configured_name.unwrap().eq_ignore_ascii_case(name))
            {
                self.reply_hostname = None;
            }
        }
        if packet.message_type() == 8 && existing.is_none() {
            if let Some(name) = self
                .leases
                .get(packet.effective_ciaddr())
                .and_then(|lease| lease.hostname.as_ref())
            {
                self.reply_hostname = Some(name.clone());
            }
        }
        let environment = Environment {
            now,
            interface,
            authoritative: self.config.authoritative,
            unicast_destination: dispatch.ingress.unicast_destination,
            ignored: configured.is_some_and(|host| host.ignore),
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
            host_index.map(|index| &mut self.hosts[index]),
            &self.reserved,
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
        provider.configured_name = configured_name;
        provider.domains = Some(&self.domains);
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

    fn reply_names(
        &self,
        packet: super::packet::Packet<'_>,
        outcome: &Outcome,
    ) -> Option<ReplyNames<'_>> {
        let address = match outcome.reply {
            Reply::Offer { address, .. }
            | Reply::Ack { address, .. }
            | Reply::Bootp { address, .. } => address,
            Reply::Inform { .. } => packet.effective_ciaddr(),
            _ => return None,
        };
        Some(ReplyNames {
            hostname: self.reply_hostname.as_deref(),
            domain: self.domains.for_address(address),
        })
    }
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    #[test]
    fn startup_class_uses_operation_and_typed_capacity_not_errno_text() {
        let denied = || io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(StartupError::LeaseFile(denied()).exit_code(), 3);
        assert_eq!(StartupError::Socket(denied()).exit_code(), 2);
        assert_eq!(StartupError::Entropy(denied()).exit_code(), 5);
        let file = b"0 02:00:00:00:00:01 192.0.2.10 named *\n";
        let capacity = super::super::lease_file::parse_reader(&file[..], 0).unwrap_err();
        assert_eq!(StartupError::LeaseFile(capacity).exit_code(), 5);
        assert_eq!(
            StartupError::LeaseFile(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many stored leases"
            ))
            .exit_code(),
            3
        );
        assert_eq!(
            StartupError::Restore(RestoreError::Lease(LeaseError::Full)).exit_code(),
            5
        );
    }
}
