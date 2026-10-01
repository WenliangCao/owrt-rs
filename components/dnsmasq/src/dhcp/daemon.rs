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
use crate::ubus_service::{DhcpEventFields, DhcpEventKind, DhcpLogging};
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
    pub address_error: Option<io::Error>,
    pub name_error: Option<io::Error>,
}

type BootHostLookup = Box<dyn FnMut(&[u8]) -> io::Result<Option<Ipv4Addr>> + Send>;
type ReverseHostLookup = Box<dyn FnMut(Ipv4Addr) -> io::Result<Option<Vec<u8>>> + Send>;

pub type DhcpEventSink<'a> =
    dyn for<'event> FnMut(DhcpEventKind, DhcpEventFields<'event>, DhcpLogging) + 'a;

/// Borrowed event owner for one listener operation. The sink does not acquire
/// the provider again, and notification failure cannot undo DHCP state.
pub struct EventProvider<'a> {
    provider: &'a mut LocalProvider,
    sink: &'a mut DhcpEventSink<'a>,
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
    boot_host_lookup: Option<BootHostLookup>,
    config_host_lookup: Option<BootHostLookup>,
    reverse_host_lookup: Option<ReverseHostLookup>,
    startup_removed: Vec<Lease>,
    restore_stats: Option<RestoreStats>,
    initialized: bool,
    alarm_deadline: Option<Instant>,
    pending_alarms: u32,
    maintenance_report: Option<MaintenanceReport>,
    message_counters: super::message_counters::MessageCounters,
}

impl LocalProvider {
    pub fn with_event_sink<'a>(&'a mut self, sink: &'a mut DhcpEventSink<'a>) -> EventProvider<'a> {
        EventProvider {
            provider: self,
            sink,
        }
    }

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
            boot_host_lookup: None,
            config_host_lookup: None,
            reverse_host_lookup: None,
            startup_removed,
            restore_stats,
            initialized: false,
            alarm_deadline: None,
            pending_alarms: 0,
            maintenance_report: None,
            message_counters: super::message_counters::MessageCounters::default(),
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

    /// Lookup only the parent's current static F_HOSTS generation. This hook
    /// must preserve its round-robin mutation; it must not use system DNS,
    /// forwarded cache records or DHCP-derived names.
    pub fn set_boot_host_lookup<F>(&mut self, lookup: F)
    where
        F: FnMut(&[u8]) -> io::Result<Option<Ipv4Addr>> + Send + 'static,
    {
        self.boot_host_lookup = Some(Box::new(lookup));
    }

    /// Resolve a configured short hostname from the current static F_HOSTS
    /// generation. For multiple IPv4 matches, the caller selects the first
    /// reverse-owning record; a sole nonreverse alias is also eligible.
    pub fn set_config_host_lookup<F>(&mut self, lookup: F)
    where
        F: FnMut(&[u8]) -> io::Result<Option<Ipv4Addr>> + Send + 'static,
    {
        self.config_host_lookup = Some(Box::new(lookup));
    }

    /// Return only the current static IPv4 reverse-host name. Domain and
    /// legal-hostname policy is applied here, not by the DNS callback.
    pub fn set_reverse_host_lookup<F>(&mut self, lookup: F)
    where
        F: FnMut(Ipv4Addr) -> io::Result<Option<Vec<u8>>> + Send + 'static,
    {
        self.reverse_host_lookup = Some(Box::new(lookup));
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
            address_error: None,
            name_error: None,
        }
    }

    /// Complete startup after socket setup and publisher attachment. Calling
    /// it again is harmless and does not replay removed-lease ownership.
    pub fn initialize(&mut self, now: i64) -> MaintenanceReport {
        let mut host_files = Vec::new();
        let mut address_error = None;
        let mut name_error = None;
        if !self.initialized {
            self.leases
                .initialize_fqdns(|address| self.domains.for_address(address));
            host_files = self.reread_host_files();
            if self.host_files_ready {
                address_error = self.update_configured_addresses();
            }
            if self.host_files_ready {
                name_error = self.update_configured_names();
            }
        }
        self.initialized = true;
        let mut removed = std::mem::take(&mut self.startup_removed);
        removed.extend(self.leases.prune(None, now));
        let mut report = self.maintain(now, removed, true);
        report.restore = self.restore_stats.take();
        report.host_files = host_files;
        report.address_error = address_error;
        report.name_error = name_error;
        report
    }

    /// Includes startup restoration and all later prune/allocation operations.
    /// Hosts reload and persistence retries preserve this cumulative window.
    pub fn lease_counters(&self) -> super::lease::LeaseCounters {
        self.leases.counters()
    }

    /// Cumulative message events, including valid no-reply branches and
    /// construction before send errors. Reload and maintenance preserve it.
    pub fn message_counters(&self) -> super::message_counters::MessageCounters {
        self.message_counters
    }

    fn update_configured_names(&mut self) -> Option<io::Error> {
        // lease.c lease_update_from_configs runs without a context chain:
        // a configured name is restored only for its own fixed address. Removing
        // a rule does not delete its lease or the lease's previous name.
        // Otherwise try the current static reverse name; no match also keeps
        // the old name. A failed shared lookup is reported separately and
        // does not prevent independent configured-name updates.
        // Keep the C lease traversal order while mutating names. Snapshot
        // addresses only, rather than retaining a cloned name per lease.
        let addresses: Vec<_> = self
            .leases
            .active_newest_first()
            .iter()
            .map(|lease| lease.address)
            .collect();
        let mut name_error = None;
        for address in addresses {
            let lease = self
                .leases
                .get(address)
                .expect("lease remains present during name update");
            let configured = self
                .config
                .find_host(
                    lease.identity.client_id.as_deref(),
                    lease.identity.hardware_type,
                    Some(&lease.identity.hardware_address),
                    |_| true,
                )
                .and_then(|index| {
                    let host = &self.config.hosts[index];
                    host.address
                        .is_none_or(|address| address == lease.address)
                        .then(|| host.hostname.clone())
                        .flatten()
                });
            let name = if configured.is_some() {
                configured
            } else if self.dns_port != 0 && name_error.is_none() {
                match self
                    .reverse_host_lookup
                    .as_mut()
                    .map(|lookup| lookup(lease.address))
                {
                    Some(Ok(Some(name))) => {
                        reverse_hostname(name, self.domains.for_address(lease.address))
                    }
                    Some(Err(error)) => {
                        name_error = Some(error);
                        None
                    }
                    _ => None,
                }
            } else {
                None
            };
            if let Some(name) = name {
                // No address is removed during this loop.
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
        name_error
    }

    fn update_configured_addresses(&mut self) -> Option<io::Error> {
        // dhcp_update_configs walks the newest-first list. Explicit addresses
        // anywhere in it win; the first inferred claim blocks later claims.
        if self.dns_port != 0 {
            if let Some(lookup) = self.config_host_lookup.as_mut() {
                for index in 0..self.config.hosts.len() {
                    let host = &self.config.hosts[index];
                    if host.address.is_some() {
                        continue;
                    }
                    let Some(name) = host.hostname.as_deref() else {
                        continue;
                    };
                    let address = match lookup(name) {
                        Ok(address) => address,
                        Err(error) => {
                            // An internal lookup failure must not turn an
                            // unresolved reservation into dynamic allocation.
                            self.host_files_ready = false;
                            return Some(error);
                        }
                    };
                    if let Some(address) = address {
                        if !self
                            .config
                            .hosts
                            .iter()
                            .any(|host| host.address == Some(address))
                        {
                            self.config.hosts[index].address = Some(address);
                        }
                    }
                }
            }
        }
        self.reserved.clear();
        for (host, policy) in self.config.hosts.iter().zip(&mut self.hosts) {
            // Preserve DECLINE state on surviving inline policies.
            policy.address = host.address;
            self.reserved.extend(host.address);
        }
        None
    }

    fn reread_host_files(&mut self) -> Vec<HostFileError> {
        // C parses new file rules before clearing old inferred inline
        // addresses. Those old addresses still reject duplicate file rows.
        let inline_start = self.config.hosts.len() - self.inline_hosts.len();
        let mut report = self.host_files.reload(&self.config.hosts[inline_start..]);
        self.host_files_ready = report.ready();
        if self.host_files_ready {
            let file_count = report.hosts.len() - self.inline_hosts.len();
            for (host, original) in report.hosts[file_count..]
                .iter_mut()
                .zip(&self.inline_hosts)
            {
                // Rebuild inferred addresses from this DNS generation. The
                // immutable main rules distinguish explicit from inferred.
                host.address = original.address;
            }
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
        let address_error = self
            .host_files_ready
            .then(|| self.update_configured_addresses())
            .flatten();
        let name_error = self
            .host_files_ready
            .then(|| self.update_configured_names())
            .flatten();
        let mut report = self.maintain(now, Vec::new(), true);
        report.host_files = host_files;
        report.address_error = address_error;
        report.name_error = name_error;
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

impl LocalProvider {
    fn resolve_events(
        &mut self,
        dispatch: &Dispatch<'_>,
        interface_name: Option<&[u8]>,
        mut events: Option<&mut DhcpEventSink<'_>>,
    ) -> Result<Outcome, RuntimeError> {
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
        let event_mac = events.as_ref().map(|_| event_mac(packet, clid));
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
        // dhcp.c host_from_dns supplies an authoritative name for ordinary
        // ACK, but only a fallback for INFORM. No lookup is done with DNS
        // disabled. A provider without a static-host source has no match.
        let reverse_address = match packet.message_type() {
            3 if configured_name.is_none() => packet
                .requested_address()
                .or(Some(packet.effective_ciaddr())),
            8 if self.reply_hostname.is_none() => Some(packet.effective_ciaddr()),
            _ => None,
        }
        .filter(|address| !address.is_unspecified());
        let dns_name = if self.dns_port != 0 {
            if let (Some(address), Some(lookup)) =
                (reverse_address, self.reverse_host_lookup.as_mut())
            {
                lookup(address)
                    .map_err(|error| RuntimeError::State(error.to_string()))?
                    .and_then(|name| reverse_hostname(name, self.domains.for_address(address)))
            } else {
                None
            }
        } else {
            None
        };
        if let Some(name) = &dns_name {
            self.reply_hostname = Some(name.clone());
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
        let logging = DhcpLogging {
            quiet_dhcp: self.config.quiet_dhcp,
            log_options: self.config.log_dhcp,
            has_error: false,
        };
        let mut on_event = |event: super::state::LogEvent<'_>| {
            let (kind, address, name, has_error) = match event {
                super::state::LogEvent::Ack { address, name } => {
                    (DhcpEventKind::Ack, address, name, false)
                }
                super::state::LogEvent::Release {
                    address,
                    unknown_lease,
                } => (DhcpEventKind::Release, address, None, unknown_lease),
            };
            let logging = DhcpLogging {
                has_error,
                ..logging
            };
            if logging.suppresses_event() {
                return;
            }
            if let Some(sink) = events.as_deref_mut() {
                let address = address.to_string();
                sink(
                    kind,
                    DhcpEventFields {
                        mac: event_mac.as_deref(),
                        ip: Some(address.as_bytes()),
                        name,
                        interface: interface_name,
                    },
                    logging,
                );
            }
        };
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
        provider.configured_name = dns_name.as_deref().or(configured_name);
        provider.domains = Some(&self.domains);
        provider.quiet_dhcp = self.config.quiet_dhcp;
        provider.message_counters = Some(&mut self.message_counters);
        provider.event_sink = Some(&mut on_event);
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
}

impl OutcomeProvider for LocalProvider {
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
        self.resolve_events(dispatch, None, None)
    }

    fn boot_config(&self) -> Option<&crate::config::dhcp::BootConfig> {
        self.config.boot.as_ref()
    }

    fn configured_options(&self) -> &[crate::config::dhcp::DhcpOption] {
        &self.config.options
    }

    fn boot_next_server(&mut self) -> io::Result<Option<Ipv4Addr>> {
        let Some(boot) = &self.config.boot else {
            return Ok(None);
        };
        if !boot.next_server.is_unspecified() {
            return Ok(Some(boot.next_server));
        }
        let Some(name) = &boot.next_server_name else {
            return Ok(None);
        };
        let address = if self.dns_port == 0 {
            None
        } else {
            let lookup = self
                .boot_host_lookup
                .as_mut()
                .ok_or_else(|| io::Error::other("DHCP boot hosts lookup is not attached"))?;
            lookup(name)?
        };
        if address.is_none() {
            eprintln!(
                "dnsmasq-rs: No IPv4 address found for {}",
                String::from_utf8_lossy(name)
            );
        }
        Ok(Some(address.unwrap_or(Ipv4Addr::UNSPECIFIED)))
    }

    fn allow_override(&self) -> bool {
        !self.config.no_override
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

impl OutcomeProvider for EventProvider<'_> {
    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
        self.provider
            .resolve_events(dispatch, None, Some(self.sink))
    }

    fn resolve_on_interface(
        &mut self,
        dispatch: &Dispatch<'_>,
        interface: Option<&[u8]>,
    ) -> Result<Outcome, RuntimeError> {
        self.provider
            .resolve_events(dispatch, interface, Some(self.sink))
    }

    fn network_options(&self, outcome: &Outcome) -> Option<NetworkOptions> {
        self.provider.network_options(outcome)
    }

    fn configured_options(&self) -> &[crate::config::dhcp::DhcpOption] {
        self.provider.configured_options()
    }

    fn boot_config(&self) -> Option<&crate::config::dhcp::BootConfig> {
        self.provider.boot_config()
    }

    fn boot_next_server(&mut self) -> io::Result<Option<Ipv4Addr>> {
        self.provider.boot_next_server()
    }

    fn allow_override(&self) -> bool {
        self.provider.allow_override()
    }

    fn reply_names(
        &self,
        packet: super::packet::Packet<'_>,
        outcome: &Outcome,
    ) -> Option<ReplyNames<'_>> {
        self.provider.reply_names(packet, outcome)
    }
}

/// dhcp.c:1092 host_from_dns: suffix must match get_domain, then validate the
/// short hostname with legal_hostname and preserve its original letter case.
fn reverse_hostname(mut name: Vec<u8>, domain: Option<&[u8]>) -> Option<Vec<u8>> {
    crate::hosts::canonicalise(&name)?; // check_name's full length/character gate
    let dot = name.iter().position(|byte| *byte == b'.');
    if let Some(dot) = dot {
        let suffix = &name[dot + 1..];
        if !suffix.is_empty() && !domain.is_some_and(|domain| suffix.eq_ignore_ascii_case(domain)) {
            return None;
        }
    }
    let end = dot.unwrap_or(name.len());
    // C can strip a leading-dot record down to a non-NULL empty hostname,
    // which its lease writer serializes as a missing token. Preserve a valid
    // existing/client name instead; empty short names are never DHCP names.
    if end == 0 {
        return None;
    }
    if !name[..end].iter().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphanumeric() || (index != 0 && matches!(byte, b'-' | b'_'))
    }) {
        return None;
    }
    name.truncate(end);
    Some(name)
}

/// rfc2131.c extended_hwaddr followed by util.c print_mac. A zero-length
/// hardware value still has a non-NULL pointer in this path, hence "<null>".
fn event_mac(packet: super::packet::Packet<'_>, client_id: Option<&[u8]>) -> Vec<u8> {
    let hardware = packet.hardware_address();
    let mac = if hardware.is_empty() {
        client_id
            .filter(|clid| clid.len() > 3)
            .map(|clid| {
                if clid[0] == packet.hardware_type()
                    || (clid[0] == 27 && packet.hardware_type() == 24)
                {
                    &clid[1..]
                } else {
                    clid
                }
            })
            .unwrap_or(hardware)
    } else {
        hardware
    };
    if mac.is_empty() {
        return b"<null>".to_vec();
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = Vec::with_capacity(mac.len() * 3 - 1);
    for (index, byte) in mac.iter().copied().enumerate() {
        if index != 0 {
            text.push(b':');
        }
        text.extend_from_slice(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]]);
    }
    text
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    #[test]
    fn address_lookup_error_pauses_admission_until_successful_reload() {
        let mut config = DhcpConfig {
            no_ping: true,
            lease_read_only: true,
            ..DhcpConfig::default()
        };
        for line in [
            b"dhcp-host=02:00:00:00:00:01,older".as_slice(),
            b"dhcp-host=02:00:00:00:00:02,newer",
        ] {
            config
                .apply(&crate::config::lex_line(line).unwrap().unwrap())
                .unwrap();
        }
        let mut provider = LocalProvider::new(config, Vec::new(), 53, || false).unwrap();
        provider.hosts[0].declined_at = Some(50);
        provider.set_config_host_lookup(|name| {
            if name == b"older" {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(Some(Ipv4Addr::new(192, 0, 2, 40)))
            }
        });
        let report = provider.initialize(100);
        assert_eq!(
            report.address_error.unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!provider.host_files_ready);
        assert_eq!(
            provider.lease_counters(),
            super::super::lease::LeaseCounters::default()
        );

        let address = Ipv4Addr::new(192, 0, 2, 41);
        provider.set_config_host_lookup(move |_| Ok(Some(address)));
        assert!(provider.reload_host_files(100).address_error.is_none());
        assert!(provider.host_files_ready);
        assert_eq!(provider.config.hosts[0].address, Some(address));
        assert_eq!(provider.config.hosts[1].address, None);
        assert_eq!(provider.hosts[0].address, Some(address));
        assert_eq!(provider.hosts[0].declined_at, Some(50));
        assert_eq!(provider.reserved, [address]);

        provider.set_config_host_lookup(|_| Ok(None));
        assert!(provider.reload_host_files(100).address_error.is_none());
        assert!(provider.host_files_ready);
        assert!(provider
            .config
            .hosts
            .iter()
            .all(|host| host.address.is_none()));
        assert!(provider.hosts.iter().all(|host| host.address.is_none()));
        assert!(provider.reserved.is_empty());
        assert_eq!(provider.hosts[0].declined_at, Some(50));
        assert_eq!(
            provider.lease_counters(),
            super::super::lease::LeaseCounters::default()
        );
    }

    #[test]
    fn empty_reverse_short_names_keep_a_recoverable_lease_file() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../private/dnsmasq-rewrite/empty-reverse-name-tests");
        std::fs::create_dir_all(&root).unwrap();
        for (index, name) in [b"".as_slice(), b".", b".pool.test"]
            .into_iter()
            .enumerate()
        {
            let folder = root.join(format!("{}-{index}", std::process::id()));
            std::fs::create_dir(&folder).unwrap();
            let path = folder.join("leases");
            let config = DhcpConfig {
                no_ping: true,
                lease_file: Some(path.as_os_str().as_bytes().to_vec()),
                ..DhcpConfig::default()
            };
            let mut provider =
                LocalProvider::new(config.clone(), Vec::new(), 53, || false).unwrap();
            let mut dns = crate::config::dns::DnsConfig::default();
            dns.apply(
                &crate::config::lex_line(b"domain=pool.test")
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            provider.set_dns_config(&dns).unwrap();
            let address = Ipv4Addr::new(192, 0, 2, 10);
            provider
                .leases
                .allocate(
                    address,
                    ClientIdentity {
                        hardware_type: 1,
                        hardware_address: vec![2, 0, 0, 0, 0, 1],
                        client_id: None,
                    },
                )
                .unwrap();
            provider.leases.set_expires(address, u32::MAX, 100).unwrap();
            provider
                .leases
                .set_hostname(address, Some(b"oldname"), false, None, false)
                .unwrap();
            let name = name.to_vec();
            provider.set_reverse_host_lookup(move |_| Ok(Some(name.clone())));
            assert!(provider.initialize(100).name_error.is_none());
            assert_eq!(
                std::fs::read(&path).unwrap(),
                b"0 02:00:00:00:00:01 192.0.2.10 oldname *\n"
            );
            drop(provider);
            let restored = LocalProvider::new(config, Vec::new(), 53, || false).unwrap();
            let lease = restored.leases.get(address).unwrap();
            assert_eq!(lease.hostname.as_deref(), Some(b"oldname".as_slice()));
            assert!(lease.expires.is_none());
            assert_eq!(lease.identity.hardware_address, [2, 0, 0, 0, 0, 1]);
            drop(restored);
            std::fs::remove_dir_all(folder).unwrap();
        }
    }

    #[test]
    fn reverse_reload_error_keeps_old_name_and_reports_independent_config_update() {
        let mut config = DhcpConfig {
            no_ping: true,
            lease_read_only: true,
            ..DhcpConfig::default()
        };
        config
            .apply(
                &crate::config::lex_line(b"dhcp-host=02:00:00:00:00:02,192.0.2.11,configured")
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut provider = LocalProvider::new(config, Vec::new(), 53, || false).unwrap();
        for (last, client, name) in [(10, 1, b"oldname".as_slice()), (11, 2, b"other")] {
            let address = Ipv4Addr::new(192, 0, 2, last);
            provider
                .leases
                .allocate(
                    address,
                    ClientIdentity {
                        hardware_type: 1,
                        hardware_address: vec![2, 0, 0, 0, 0, client],
                        client_id: None,
                    },
                )
                .unwrap();
            provider.leases.set_expires(address, u32::MAX, 100).unwrap();
            provider
                .leases
                .set_hostname(address, Some(name), false, None, false)
                .unwrap();
        }
        provider.set_reverse_host_lookup(|_| Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        let report = provider.initialize(100);
        assert_eq!(
            report.name_error.unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            provider
                .leases
                .get(Ipv4Addr::new(192, 0, 2, 10))
                .unwrap()
                .hostname
                .as_deref(),
            Some(b"oldname".as_slice())
        );
        assert_eq!(
            provider
                .leases
                .get(Ipv4Addr::new(192, 0, 2, 11))
                .unwrap()
                .hostname
                .as_deref(),
            Some(b"configured".as_slice())
        );
        provider.set_reverse_host_lookup(|_| Ok(Some(b"recovered".to_vec())));
        assert!(provider.reload_host_files(100).name_error.is_none());
        assert_eq!(
            provider
                .leases
                .get(Ipv4Addr::new(192, 0, 2, 10))
                .unwrap()
                .hostname
                .as_deref(),
            Some(b"recovered".as_slice())
        );
    }

    #[test]
    fn reverse_host_name_uses_c_domain_and_legal_short_name_rules() {
        for (name, domain, expected) in [
            (b"FromHosts".as_slice(), None, Some(b"FromHosts".as_slice())),
            (
                b"FromHosts.POOL.TEST",
                Some(b"pool.test".as_slice()),
                Some(b"FromHosts".as_slice()),
            ),
            (b"fromhosts.other.test", Some(b"pool.test".as_slice()), None),
            (b"fromhosts.pool.test", None, None),
            (b"_invalid", None, None),
            (b"valid_name", None, Some(b"valid_name".as_slice())),
            (b".pool.test", Some(b"pool.test".as_slice()), None),
        ] {
            assert_eq!(reverse_hostname(name.to_vec(), domain).as_deref(), expected);
        }
    }

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
