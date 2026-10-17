//! Linux local DHCP adapter: interface admission, contexts, state and options.
//! Relay, additional tag selectors and scripts remain separate contracts. Interface
//! snapshots are refreshed for each admitted packet.

use super::allocation::{ProbeResult, RangeKind};
use super::context::{
    select_contexts_with_shared, select_remote_contexts_with_shared, ContextState, SelectedContext,
};
use super::interface_admission::{interface_matches, InterfacePolicy, Selection};
use super::lease::{
    ClientIdentity, Lease, LeaseCounters, LeaseError, LeaseStore, NameLost, RestoreError,
};
use super::lease_query::{self, Query as LeaseQueryInput};
use super::persistence::{
    self, AlarmAction, DnsPublisher, DnsReport, LeasePersistence, PersistReport,
};
use super::probe::IcmpProbe;
use super::pxe;
use super::runtime::{
    NetworkOptions, OutcomeProvider, PxeEncoding, ReplyNames, RuntimeError, StateProvider,
};
use super::service::Dispatch;
use super::state::{Environment, HostPolicy, Outcome, Reply};
use crate::config::dhcp::{
    option_filter, BootConfig, ClassKind, DhcpConfig, FilteredOptions, HostConfig, HostFileError,
    HostFiles, NameDomains, TagIf,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use crate::helper::{LeaseDelivery, LeaseEventContext};
use crate::interfaces::{ipv4_interfaces, primary_ipv4_with_name};
use crate::ubus_service::{DhcpEventFields, DhcpEventKind, DhcpLogging};
use std::cell::RefCell;
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
    pub fn is_lease_capacity(&self) -> bool {
        match self {
            Self::LeaseFile(error) => super::lease_file::capacity_exceeded(error),
            Self::Restore(RestoreError::Lease(LeaseError::Full)) => true,
            _ => false,
        }
    }

    pub fn exit_code(&self) -> i32 {
        if self.is_lease_capacity() {
            return 5;
        }
        match self {
            Self::Entropy(_) => 5,
            Self::LeaseFile(_) | Self::Restore(_) => 3,
            Self::Socket(_) => 2,
        }
    }
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_lease_capacity() {
            return formatter.write_str("too many stored leases");
        }
        match self {
            Self::LeaseFile(error)
                if error
                    .get_ref()
                    .is_some_and(|cause| cause.is::<super::persistence::LeaseFileFailure>()) =>
            {
                write!(formatter, "{error}")
            }
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
    pub warnings: Vec<Vec<u8>>,
    pub diagnostics_logged: bool,
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
    pub file_error_message: Option<Vec<u8>>,
}

impl MaintenanceReport {
    /// A scheduled file generation has not published any state yet.
    fn pending_files() -> Self {
        Self {
            file: PersistReport {
                attempted: false,
                error: None,
                next_event: None,
                retry_in: None,
                alarm: AlarmAction::Keep,
            },
            dns: DnsReport {
                status: persistence::DnsStatus::Pending,
                records: 0,
                error: None,
            },
            removed: Vec::new(),
            lost_names: Vec::new(),
            restore: None,
            host_files: Vec::new(),
            address_error: None,
            name_error: None,
            file_error_message: None,
        }
    }
}

type BootHostLookup = Box<dyn FnMut(&[u8]) -> io::Result<Option<Ipv4Addr>>>;
type ReverseHostLookup = Box<dyn FnMut(Ipv4Addr) -> io::Result<Option<Vec<u8>>>>;

pub type DhcpEventSink<'a> =
    dyn for<'event> FnMut(DhcpEventKind, DhcpEventFields<'event>, DhcpLogging) + 'a;

/// The counters reflect the lease state at this probe, including removals
/// made by this packet. The waiter can publish them without reentering DHCP.
pub type DhcpProbeWait<'a> = dyn FnMut(
        Option<&crate::net::IcmpSocket>,
        Duration,
        LeaseCounters,
        Option<crate::logging::LogEvent>,
    ) -> io::Result<bool>
    + 'a;

/// Borrowed event owner for one listener operation. The sink does not acquire
/// the provider again, and notification failure cannot undo DHCP state.
pub struct EventProvider<'a> {
    provider: &'a mut LocalProvider,
    sink: &'a mut DhcpEventSink<'a>,
    wait: Option<&'a mut DhcpProbeWait<'a>>,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl EventProvider<'_> {
    pub fn take_script_delivery(&mut self) -> Option<LeaseDelivery> {
        self.provider.take_script_delivery()
    }
}

pub struct LocalProvider {
    config: DhcpConfig,
    leases: LeaseStore,
    states: Vec<ContextState>,
    hosts: Vec<HostPolicy>,
    ethers: crate::config::ethers::Ethers,
    host_files: HostFiles,
    host_files_ready: bool,
    file_owner: Option<super::files_runtime::DhcpFiles>,
    ethers_read: Option<crate::config::ethers::EthersRead>,
    inline_options: Vec<crate::config::dhcp::DhcpOption>,
    file_reload_pending: bool,
    file_init_ready: bool,
    file_scripts_pending: bool,
    reserved: Vec<Ipv4Addr>,
    domains: NameDomains,
    reply_hostname: Option<Vec<u8>>,
    force_broadcast: bool,
    /// Boot entry selected after the state outcome identifies its context.
    selected_boot: Option<BootConfig>,
    request_tags: Vec<Vec<u8>>,
    pxe_client: Option<pxe::Client>,
    pxe_generated: Vec<(u8, Vec<u8>)>,
    pxe_menu_failed: bool,
    direct_pxe: Option<DirectPxeReply>,
    selected: Vec<SelectedContext>,
    interface_policy: InterfacePolicy,
    tftp_enabled: bool,
    tftp_interfaces: Vec<Option<Vec<u8>>>,
    dns_port: u16,
    control: UdpSocket,
    interface_owner: Option<crate::interfaces::Ipv4Snapshot>,
    packet_interfaces: Option<Vec<crate::interfaces::Ipv4Interface>>,
    restart_interfaces: bool,
    probe: IcmpProbe,
    probe_error: Option<io::Error>,
    should_stop: fn() -> bool,
    persistence: LeasePersistence,
    dns_publisher: Option<Box<dyn DnsPublisher>>,
    boot_host_lookup: Option<BootHostLookup>,
    config_host_lookup: Option<BootHostLookup>,
    reverse_host_lookup: Option<ReverseHostLookup>,
    startup_removed: Vec<Lease>,
    startup_time: i64,
    startup_script_time: Option<i64>,
    restore_stats: Option<RestoreStats>,
    initialized: bool,
    alarm_deadline: Option<Instant>,
    pending_alarms: u32,
    maintenance_report: Option<MaintenanceReport>,
    message_counters: super::message_counters::MessageCounters,
    scripts: super::lease::ScriptQueue,
    pending_delivery: Option<LeaseDelivery>,
    network_notices: Vec<crate::logging::LogEvent>,
}

struct DirectPxeReply {
    bytes: Vec<u8>,
    encoding: super::reply::ReplyEncoding,
}

impl LocalProvider {
    pub fn with_event_sink<'a>(&'a mut self, sink: &'a mut DhcpEventSink<'a>) -> EventProvider<'a> {
        EventProvider {
            provider: self,
            sink,
            wait: None,
        }
    }

    pub fn with_event_sink_and_wait<'a>(
        &'a mut self,
        sink: &'a mut DhcpEventSink<'a>,
        wait: &'a mut DhcpProbeWait<'a>,
    ) -> EventProvider<'a> {
        EventProvider {
            provider: self,
            sink,
            wait: Some(wait),
        }
    }

    pub fn new(
        config: DhcpConfig,
        listen_addresses: Vec<IpAddr>,
        dns_port: u16,
        should_stop: fn() -> bool,
    ) -> Result<Self, StartupError> {
        Self::new_with_log(config, listen_addresses, dns_port, should_stop, &mut None)
    }

    pub fn new_with_log(
        config: DhcpConfig,
        listen_addresses: Vec<IpAddr>,
        dns_port: u16,
        should_stop: fn() -> bool,
        early_log: &mut Option<crate::logging::Logger>,
    ) -> Result<Self, StartupError> {
        // The C global entropy check precedes lease-file creation. Keep this
        // provider's dependency failures on the same side of that mutation.
        let probe = IcmpProbe::new(config.no_ping).map_err(StartupError::Entropy)?;
        let now = epoch_seconds();
        let (persistence, restored) = LeasePersistence::open_with_warnings(
            Path::new(OsStr::from_bytes(config.lease_path())),
            config.lease_read_only,
            config.lease_max,
            |warning| {
                crate::logging::emit_early(
                    early_log,
                    crate::logging::Priority::Warning,
                    warning.as_slice(),
                );
                Ok(())
            },
        )
        .map_err(|error| {
            let warnings = error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<super::persistence::LeaseFileFailure>())
                .map_or_else(
                    || super::lease_file::warnings(&error),
                    |failure| failure.warnings(),
                );
            for warning in warnings {
                crate::logging::emit_early(
                    early_log,
                    crate::logging::Priority::Warning,
                    warning.as_slice(),
                );
            }
            StartupError::LeaseFile(error)
        })?;
        let mut leases = LeaseStore::new(config.lease_max);
        let (startup_removed, restore_stats) = if let Some(restored) = restored {
            if !restored.clean_end {
                crate::logging::emit_early(
                    early_log,
                    crate::logging::Priority::Error,
                    b"failed to parse lease database cleanly",
                );
            }
            let stats = RestoreStats {
                invalid_records: restored.invalid_records,
                clean_end: restored.clean_end,
                warnings: restored.warnings,
                diagnostics_logged: true,
            };
            let removed = leases
                .restore_with_name_policy(restored.records, now, config.fqdn_only)
                .map_err(StartupError::Restore)?;
            (removed, Some(stats))
        } else {
            (Vec::new(), None)
        };
        Ok(Self {
            leases,
            states: config.ranges.iter().map(ContextState::new).collect(),
            hosts: config.hosts.iter().map(host_policy).collect(),
            ethers: crate::config::ethers::Ethers::new(&config.hosts),
            host_files: HostFiles::new(&config.host_files),
            host_files_ready: true,
            file_owner: None,
            ethers_read: None,
            inline_options: config.options.clone(),
            file_reload_pending: false,
            file_init_ready: true,
            file_scripts_pending: false,
            reserved: config
                .hosts
                .iter()
                .filter_map(|host| host.address)
                .collect(),
            domains: NameDomains::default(),
            reply_hostname: None,
            force_broadcast: false,
            selected_boot: None,
            request_tags: Vec::new(),
            pxe_client: None,
            pxe_generated: Vec::new(),
            pxe_menu_failed: false,
            direct_pxe: None,
            probe,
            probe_error: None,
            should_stop,
            config,
            selected: Vec::new(),
            interface_policy: InterfacePolicy::new(listen_addresses),
            tftp_enabled: false,
            tftp_interfaces: Vec::new(),
            dns_port,
            control: UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(StartupError::Socket)?,
            interface_owner: None,
            packet_interfaces: None,
            restart_interfaces: false,
            persistence,
            dns_publisher: None,
            boot_host_lookup: None,
            config_host_lookup: None,
            reverse_host_lookup: None,
            startup_removed,
            startup_time: now,
            startup_script_time: Some(now),
            restore_stats,
            initialized: false,
            alarm_deadline: None,
            pending_alarms: 0,
            maintenance_report: None,
            message_counters: super::message_counters::MessageCounters::default(),
            scripts: super::lease::ScriptQueue::default(),
            pending_delivery: None,
            network_notices: Vec::new(),
        })
    }

    /// Failed probing suppresses allocation while retaining prune/name side
    /// effects in the Outcome. Report the error after processing that state.
    pub fn take_probe_error(&mut self) -> Option<io::Error> {
        self.probe_error.take()
    }

    pub fn take_network_notices(&mut self) -> Vec<crate::logging::LogEvent> {
        std::mem::take(&mut self.network_notices)
    }

    fn bridge_ingress(&mut self, name: Option<&[u8]>) -> Result<Option<(u32, Vec<u8>)>, ()> {
        let Some(name) = name else { return Ok(None) };
        self.config.network.bridge_ingress(name).map_err(|message| {
            self.network_notices.push(crate::logging::LogEvent::new(
                crate::logging::Service::Dhcp,
                crate::logging::Priority::Warning,
                message,
            ));
        })
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
        F: FnMut(&[u8]) -> io::Result<Option<Ipv4Addr>> + 'static,
    {
        self.boot_host_lookup = Some(Box::new(lookup));
    }

    /// Resolve a configured short hostname from the current static F_HOSTS
    /// generation. For multiple IPv4 matches, the caller selects the first
    /// reverse-owning record; a sole nonreverse alias is also eligible.
    pub fn set_config_host_lookup<F>(&mut self, lookup: F)
    where
        F: FnMut(&[u8]) -> io::Result<Option<Ipv4Addr>> + 'static,
    {
        self.config_host_lookup = Some(Box::new(lookup));
    }

    /// Return only the current static IPv4 reverse-host name. Domain and
    /// legal-hostname policy is applied here, not by the DNS callback.
    pub fn set_reverse_host_lookup<F>(&mut self, lookup: F)
    where
        F: FnMut(Ipv4Addr) -> io::Result<Option<Vec<u8>>> + 'static,
    {
        self.reverse_host_lookup = Some(Box::new(lookup));
    }

    /// Install the validated interface and address-to-domain policy before initialize.
    pub fn set_dns_config(&mut self, config: &crate::config::dns::DnsConfig) -> io::Result<()> {
        self.config
            .validate_dns_config(config)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.domains = NameDomains::new(config)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.interface_policy = InterfacePolicy::from_dns(config);
        Ok(())
    }

    /// DHCP accepts unusual server-ID aliases only on TFTP-eligible interfaces.
    /// Retain only the two selectors needed by network.c's tftp_ok predicate.
    pub fn set_tftp_config(&mut self, config: &crate::config::tftp::TftpConfig) {
        self.tftp_enabled = config.enabled;
        self.tftp_interfaces.clone_from(&config.interfaces);
    }

    pub fn take_maintenance_report(&mut self) -> Option<MaintenanceReport> {
        self.maintenance_report.take()
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn take_script_delivery(&mut self) -> Option<LeaseDelivery> {
        self.queue_script_from_maintenance();
        let delivery = self.pending_delivery.take();
        self.queue_script_from_maintenance();
        delivery
    }

    /// A bounded hosts read has not reached C's next helper queue turn yet.
    /// Transfer an already frozen callback without freezing the following
    /// lease's current name before the new hosts generation is published.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn take_frozen_script_delivery(&mut self) -> Option<LeaseDelivery> {
        self.pending_delivery.take()
    }

    /// Only already frozen work is runnable while a hosts reload is pending.
    /// Checking this must not snapshot the next lease name ahead of publication.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn has_frozen_script_delivery(&self) -> bool {
        self.pending_delivery.is_some()
    }

    /// A dead helper is not respawned by C. Stop retaining undeliverable
    /// callbacks while leaving DHCP, lease persistence and DNS usable.
    pub fn disable_script_delivery(&mut self) {
        self.config.script = None;
        self.scripts = super::lease::ScriptQueue::default();
        self.pending_delivery = None;
        self.leases.clear_helper_contexts();
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn queue_script_from_maintenance(&mut self) {
        if !self.initialized || self.pending_delivery.is_some() || self.config.script.is_none() {
            return;
        }
        if let Some(event) = self.scripts.next(
            &mut self.leases,
            super::lease::ScriptOptions {
                lease_file_read_only: self.config.lease_read_only,
                notify_renewals: self.config.script_on_renewal,
            },
        ) {
            let mut context = event
                .lease
                .helper_context
                .as_deref()
                .cloned()
                .unwrap_or_default();
            context.now = self
                .startup_script_time
                .take()
                .unwrap_or_else(epoch_seconds);
            context.log_dhcp = self.config.log_dhcp;
            self.pending_delivery = Some(LeaseDelivery::new(event, context));
        }
    }

    /// Called only after the helper reports successful read-only initialization,
    /// before admitting DHCP packets. The child already applied leasefile rules.
    pub fn restore_initial_records(
        &mut self,
        restored: super::lease_file::LeaseFile,
        now: i64,
    ) -> Result<(), StartupError> {
        self.restore_stats = Some(RestoreStats {
            invalid_records: restored.invalid_records,
            clean_end: restored.clean_end,
            warnings: restored.warnings,
            diagnostics_logged: true,
        });
        self.startup_removed = self
            .leases
            .restore_with_name_policy(restored.records, now, self.config.fqdn_only)
            .map_err(StartupError::Restore)?;
        self.initialized = false;
        self.startup_time = now;
        self.startup_script_time = Some(now);
        Ok(())
    }

    pub fn restore_script_records(
        &mut self,
        restored: super::lease_file::LeaseFile,
        now: i64,
    ) -> Result<MaintenanceReport, StartupError> {
        self.restore_initial_records(restored, now)?;
        Ok(self.initialize(now))
    }

    fn select_boot(&mut self, outcome: &Outcome) {
        let context = match outcome.reply {
            Reply::Offer { context, .. }
            | Reply::Ack { context, .. }
            | Reply::Bootp { context, .. } => Some(context),
            Reply::Inform {
                context: Some(context),
                ..
            } => Some(context),
            _ => None,
        };
        if context.is_none() {
            return;
        }
        if self.config.boot.is_none() && self.config.boot_entries.is_empty() {
            self.selected_boot = None;
            return;
        }
        let mode = u8::from(
            self.pxe_client
                .as_ref()
                .is_some_and(|client| client.architecture.is_some()),
        );
        let selected = pxe_selection(
            &self.config,
            &self.request_tags,
            &self.selected,
            context,
            mode,
        );
        self.selected_boot = self.config.boot_for(&selected.tags).cloned();
    }

    fn prepare_normal_pxe(&mut self, packet: super::packet::Packet<'_>, outcome: &Outcome) {
        self.pxe_generated.clear();
        let Some(architecture) = self
            .pxe_client
            .as_ref()
            .and_then(|client| client.architecture)
        else {
            return;
        };
        let context = match outcome.reply {
            Reply::Offer { context, .. }
            | Reply::Ack { context, .. }
            | Reply::Bootp { context, .. } => Some(context),
            Reply::Inform { context, .. } => context,
            _ => None,
        };
        let Some(local) = context
            .and_then(|index| self.selected.get(index))
            .map(|selected| selected.range.local)
        else {
            return;
        };
        let selected = pxe_selection(&self.config, &self.request_tags, &self.selected, context, 1);
        if pxe::single_uefi_service(architecture, &self.config.pxe.services, &selected.tags)
            .is_some()
        {
            return;
        }
        let prompt = pxe_custom_prompt(&self.config, packet, &selected.tags);
        self.pxe_generated = pxe::generated_suboptions(
            architecture,
            &self.config.pxe.services,
            &selected.tags,
            local,
            prompt,
            |name| pxe_host(name, self.dns_port, &mut self.boot_host_lookup),
        )
        .unwrap_or_else(|_| {
            self.pxe_menu_failed = true;
            Vec::new()
        });
    }

    /// Direct paths retain only the next reply, never a PXE transaction table.
    /// Packet-triggered expiry still follows the ordinary persistence/helper
    /// maintenance boundary, but no dynamic lease state transition runs.
    fn prepare_direct_pxe(
        &mut self,
        packet: super::packet::Packet<'_>,
        decision: pxe::Decision,
        listener: bool,
        now: i64,
        interface_name: Option<&[u8]>,
        mac: Option<&[u8]>,
    ) -> Result<Outcome, RuntimeError> {
        let logging = DhcpLogging {
            quiet_dhcp: self.config.quiet_dhcp,
            log_options: self.config.log_dhcp,
            has_error: false,
        };
        let xid = packet.transaction_id();
        let mut packet_notices = Vec::new();
        let reply = match decision {
            pxe::Decision::BootItem { client, reply } => {
                let selected =
                    pxe_selection(&self.config, &self.request_tags, &self.selected, None, 1);
                let generated = [(71, reply.boot_item.to_vec())];
                let encoding =
                    PxeEncoding::direct(&client, &self.config.pxe.vendors, &generated, true);
                let options = super::runtime::encode_pxe_vendor_options(
                    packet,
                    &self.config.options,
                    &selected.tags,
                    &encoding,
                );
                self.message_counters.pxe = self.message_counters.pxe.wrapping_add(1);
                if let Some(message) = super::logging::packet(
                    logging,
                    super::logging::PacketLog {
                        kind: b"PXE",
                        address: Some(reply.assigned_address),
                        mac,
                        interface: interface_name,
                        extra: Some(&reply.target.filename[..reply.target.filename.len().min(127)]),
                        error: None,
                        xid,
                    },
                ) {
                    packet_notices.push(crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Info,
                        message,
                    ));
                }
                if logging.log_options {
                    let mut tags = selected.tags.clone();
                    tags.reverse();
                    if let Some(message) = super::logging::tags(xid, &tags) {
                        packet_notices.push(crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Info,
                            message,
                        ));
                    }
                }
                Some((reply.fields(packet), options, true))
            }
            pxe::Decision::Proxy {
                client,
                context,
                ignored,
            } => {
                let selected = pxe_selection(
                    &self.config,
                    &self.request_tags,
                    &self.selected,
                    Some(context),
                    2,
                );
                let boot = self.config.boot_for(&selected.tags).cloned();
                let local = self.selected[context].range.local;
                let Some(architecture) = client.architecture else {
                    self.direct_pxe = None;
                    return Ok(Outcome {
                        reply: Reply::Ignore,
                        removed: Vec::new(),
                        lost_names: Vec::new(),
                        newly_allocated: false,
                    });
                };
                let reply = pxe::proxy_reply(
                    packet,
                    architecture,
                    listener,
                    &self.config.pxe.services,
                    &selected.tags,
                    local,
                    boot.as_ref(),
                    |name| pxe_host(name, self.dns_port, &mut self.boot_host_lookup),
                );
                let generated = if reply.include_menu {
                    let prompt = pxe_custom_prompt(&self.config, packet, &selected.tags);
                    pxe::generated_suboptions(
                        architecture,
                        &self.config.pxe.services,
                        &selected.tags,
                        local,
                        prompt,
                        |name| pxe_host(name, self.dns_port, &mut self.boot_host_lookup),
                    )
                    .unwrap_or_else(|_| {
                        self.network_notices.push(crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Error,
                            b"PXE menu too large".to_vec(),
                        ));
                        Vec::new()
                    })
                } else {
                    Vec::new()
                };
                let encoding = PxeEncoding::direct(
                    &client,
                    &self.config.pxe.vendors,
                    &generated,
                    reply.include_menu,
                );
                let mut option_warnings = Vec::new();
                let options = super::runtime::encode_pxe_options_notices(
                    packet,
                    local,
                    &self.config.options,
                    &selected,
                    &encoding,
                    &mut option_warnings,
                );
                self.network_notices
                    .extend(option_warnings.into_iter().map(|warning| {
                        crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Warning,
                            super::logging::option_warning(warning),
                        )
                    }));
                self.selected_boot = boot;
                self.message_counters.pxe = self.message_counters.pxe.wrapping_add(1);
                if let Some(message) = super::logging::packet(
                    logging,
                    super::logging::PacketLog {
                        kind: b"PXE",
                        address: None,
                        mac,
                        interface: interface_name,
                        extra: Some(if ignored { b"proxy-ignored" } else { b"proxy" }),
                        error: None,
                        xid,
                    },
                ) {
                    packet_notices.push(crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Info,
                        message,
                    ));
                }
                if logging.log_options {
                    let mut tags = selected.tags.clone();
                    tags.reverse();
                    if let Some(message) = super::logging::tags(xid, &tags) {
                        packet_notices.push(crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Info,
                            message,
                        ));
                    }
                }
                Some((reply.fields, options, !ignored))
            }
            pxe::Decision::Ignore => None,
            pxe::Decision::UnsupportedBis => {
                packet_notices.push(crate::logging::LogEvent::new(
                    crate::logging::Service::Dhcp,
                    crate::logging::Priority::Error,
                    b"PXE BIS not supported".to_vec(),
                ));
                None
            }
            pxe::Decision::Continue(_) => unreachable!("ordinary PXE remains in state path"),
        };
        // Serialize once before C's packet/tags/delay sites. This retains
        // actual free_space warnings even for an ignored proxy attempt.
        self.direct_pxe = if let Some((fields, options, send)) = reply {
            let mut bytes = vec![0; packet.response_capacity().max(300)];
            let options: Vec<_> = options
                .iter()
                .map(|(code, value)| super::reply::ReplyOption { code: *code, value })
                .collect();
            let encoding = super::reply::build_pxe_reply(packet, &fields, &options, &mut bytes)
                .map_err(RuntimeError::Reply)?;
            self.network_notices
                .extend(encoding.omitted_options.iter().map(|code| {
                    crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Warning,
                        super::logging::omission(*code),
                    )
                }));
            bytes.truncate(encoding.len);
            send.then_some(DirectPxeReply { bytes, encoding })
        } else {
            None
        };
        self.network_notices.extend(packet_notices);
        let removed = self.leases.prune(None, now);
        self.maintenance_report = Some(self.maintain(now, removed, false));
        self.queue_script_from_maintenance();
        Ok(Outcome {
            reply: Reply::Ignore,
            removed: Vec::new(),
            lost_names: Vec::new(),
            newly_allocated: false,
        })
    }

    pub fn next_maintenance(&self) -> Option<Instant> {
        if !self.initialized || self.pending_alarms != 0 {
            Some(Instant::now())
        } else {
            self.alarm_deadline
        }
    }

    /// Check a caller's single clock sample without turning immediate startup
    /// or external alarm work into a newly sampled, apparently future deadline.
    pub fn maintenance_due(&self, now: Instant) -> bool {
        !self.initialized || self.pending_alarms != 0
            || self.alarm_deadline.is_some_and(|deadline| deadline <= now)
    }

    pub fn script_delivery_enabled(&self) -> bool {
        self.config.script.is_some()
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
        if self.config.script.is_some() {
            self.scripts.add_pruned(removed.clone());
        }
        let file = self.persistence.update(&mut self.leases, now);
        let file_error_message = file.error.as_ref().map(|error| {
            let mut description = error.to_string();
            if let Some(code) = error.raw_os_error() {
                if let Some(text) = description.strip_suffix(&format!(" (os error {code})")) {
                    description = text.to_owned();
                }
            }
            let mut message = b"failed to write ".to_vec();
            message.extend_from_slice(self.config.lease_path());
            message.extend_from_slice(
                format!(
                    ": {description} (retry in {} s)",
                    file.retry_in.unwrap_or(0)
                )
                .as_bytes(),
            );
            message
        });
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
            self.config.fqdn_only,
            self.dns_publisher.as_deref_mut(),
        );
        if matches!(dns.status, persistence::DnsStatus::Failed | persistence::DnsStatus::Pending) {
            // A clean, infinite lease set may have no expiry alarm. Retry a
            // failed forced publication without requiring another packet/HUP,
            // while preserving any earlier lease or file-retry deadline.
            if let Some(retry) = Instant::now().checked_add(Duration::from_secs(
                persistence::LEASE_RETRY_SECONDS as u64,
            )) {
                self.alarm_deadline = Some(self.alarm_deadline.map_or(retry, |due| due.min(retry)));
            }
        }
        let lost_names = LeaseStore::names_lost(&removed);
        MaintenanceReport {
            file,
            file_error_message,
            dns,
            removed,
            lost_names,
            restore: None,
            host_files: Vec::new(),
            address_error: None,
            name_error: None,
        }
    }

    /// Keep the address-dump descriptor for the daemon lifetime, like C's
    /// netlinkfd. No new descriptor is needed when an admitted packet arrives.
    pub fn start_interface_owner(&mut self) -> io::Result<()> {
        self.interface_owner = Some(crate::interfaces::Ipv4Snapshot::new()?);
        Ok(())
    }

    pub fn prepare_packet_interfaces(&mut self) -> io::Result<bool> {
        let Some(owner) = &mut self.interface_owner else {
            return Ok(true);
        };
        if self.packet_interfaces.is_some() {
            return Ok(true);
        }
        if !owner.busy() {
            owner.begin()?;
        }
        if let Some(addresses) = owner.step(&self.control)? {
            if std::mem::take(&mut self.restart_interfaces) {
                return Ok(false);
            }
            self.packet_interfaces = Some(addresses);
            return Ok(true);
        }
        Ok(false)
    }

    pub fn finish_packet_interfaces(&mut self) {
        self.packet_interfaces = None;
    }

    // One admitted packet consumes this generation; probe waits cannot reenter
    // DHCP, and a WouldBlock listener fallback has not reached this method.
    fn packet_addresses(&mut self) -> io::Result<Vec<crate::interfaces::Ipv4Interface>> {
        if self.interface_owner.is_some() {
            self.packet_interfaces
                .take()
                .ok_or_else(|| io::Error::other("DHCP address snapshot is not ready"))
        } else {
            ipv4_interfaces()
        }
    }

    /// Attach file input to the single poll owner after privilege setup.
    /// The initial bank must finish before the normal initialize stage.
    pub fn start_file_owner(&mut self) -> io::Result<()> {
        let mut files = super::files_runtime::DhcpFiles::new(
            &self.config.host_files,
            &self.config.option_files,
            &self.config.dynamic_dirs,
        )?;
        files.begin_reload(&self.ethers.file_bank_base(&self.config.hosts));
        self.file_owner = Some(files);
        self.file_init_ready = false;
        Ok(())
    }

    pub fn files_initializing(&self) -> bool {
        !self.file_init_ready
    }

    pub fn file_work_pending(&self) -> bool {
        self.file_reload_pending
            || self.ethers_read.is_some()
            || self.file_owner.as_ref().is_some_and(|files| files.busy())
    }

    pub fn files_runnable(&self) -> bool {
        // Match step_files priority: active ethers and bank input must finish
        // before a queued reload or buffered directory event can run.
        if let Some(reader) = &self.ethers_read {
            return reader.runnable();
        }
        let Some(files) = &self.file_owner else {
            return false;
        };
        if files.busy() {
            return files.runnable();
        }
        self.file_reload_pending || files.runnable()
    }

    pub fn append_file_fds(&self, fds: &mut Vec<dnsmasq_platform::poll::PollFd>) {
        if let Some(reader) = &self.ethers_read {
            reader.append_poll_fds(fds);
        } else if let Some(files) = &self.file_owner {
            files.append_poll_fds(fds);
        }
    }

    /// An in-progress per-packet dump has its own wait source. The main owner
    /// enables it only when the packet consumer's higher priority gates allow
    /// progress; an unread DHCP socket does not authorize an early receive.
    pub fn packet_interfaces_pending(&self) -> bool {
        self.interface_owner.as_ref().is_some_and(|owner| owner.busy())
    }

    pub fn packet_interfaces_runnable(&self) -> bool {
        !self.file_work_pending()
            && self.interface_owner.as_ref().is_some_and(|owner| owner.runnable())
    }

    pub fn append_packet_interface_fds(&self, fds: &mut Vec<dnsmasq_platform::poll::PollFd>) {
        if !self.file_work_pending() {
            if let Some(owner) = &self.interface_owner {
                owner.append_poll_fds(fds);
            }
        }
    }

    pub fn file_watch_fd(&self) -> Option<std::os::fd::RawFd> {
        self.file_owner.as_ref().and_then(super::files_runtime::DhcpFiles::watch_fd)
    }

    /// At most one file/directory/event turn; packets and helper work run
    /// between these turns. During ICMP waits this method is never entered.
    pub fn step_files(&mut self, now: i64) -> Option<MaintenanceReport> {
        self.step_files_with_watch_readiness(now, true)
    }

    pub fn step_files_with_watch_readiness(&mut self, now: i64, watch_ready: bool) -> Option<MaintenanceReport> {
        if self.file_work_pending()
            && self
                .interface_owner
                .as_ref()
                .is_some_and(|owner| owner.busy())
        {
            // A long bank read may outlive an address change. Drain the old
            // dump, then request a fresh generation before consuming DHCP.
            self.restart_interfaces = true;
        }
        if let Some(reader) = &mut self.ethers_read {
            let done = reader.step();
            if !done {
                return None;
            }
            let reader = self.ethers_read.take()?;
            let (ethers, bad) = reader.into_result();
            self.ethers = ethers;
            let errors = bad
                .into_iter()
                .map(|line| HostFileError {
                    path: "/etc/ethers".into(),
                    line: Some(line),
                    kind: crate::config::dhcp::HostFileErrorKind::Line(crate::config::Error(
                        "bad ethers entry",
                    )),
                })
                .collect();
            return Some(self.finish_file_update(now, true, errors));
        }
        let files = self.file_owner.as_mut()?;
        if self.file_reload_pending && !files.busy() {
            files.begin_reload(&self.ethers.file_bank_base(&self.config.hosts));
            self.file_reload_pending = false;
        }
        let step = files.step_with_watch_readiness(&self.config.hosts, watch_ready);
        for diagnostic in step.diagnostics {
            eprintln!("dnsmasq-rs: {diagnostic}");
        }
        let update = step.update?;
        if update.replacement {
            self.ethers
                .replace_file_bank(update.hosts, &self.config.hosts);
            self.config.options = update.options;
            self.config.options.extend_from_slice(&self.inline_options);
        } else {
            if update.refresh_hosts {
                self.ethers
                    .append_file_bank(update.hosts, &self.config.hosts);
            }
            let mut options = update.options;
            options.append(&mut self.config.options);
            self.config.options = options;
        }
        let mut errors = Vec::new();
        if update.replacement && self.config.read_ethers {
            match self.ethers.begin_read(Path::new("/etc/ethers")) {
                Ok(reader) => {
                    self.ethers_read = Some(reader);
                    return None;
                }
                Err(error) => errors.push(HostFileError {
                    path: "/etc/ethers".into(),
                    line: None,
                    kind: crate::config::dhcp::HostFileErrorKind::Io(error),
                }),
            }
        }
        Some(self.finish_file_update(now, update.refresh_hosts, errors))
    }

    fn finish_file_update(
        &mut self,
        now: i64,
        refresh_hosts: bool,
        errors: Vec<HostFileError>,
    ) -> MaintenanceReport {
        if !refresh_hosts {
            return MaintenanceReport::pending_files();
        }
        // dhcp_update_configs clears CONFIG_ADDR_HOSTS after parsing both
        // full banks and successful live host-file appends.
        self.ethers.clear_inferred_addresses();
        self.hosts = self
            .ethers
            .hosts()
            .iter()
            .zip(self.ethers.previous_indices())
            .map(|(host, previous)| {
                let mut policy = host_policy(host);
                policy.declined_at = previous.and_then(|index| self.hosts[index].declined_at);
                policy
            })
            .collect();
        self.config.hosts = self.ethers.hosts().to_vec();
        self.host_files_ready = true;
        self.file_init_ready = true;
        let mut report = if !self.initialized {
            self.initialize(now)
        } else {
            let address_error = self.update_configured_addresses();
            let name_error = self
                .host_files_ready
                .then(|| self.update_configured_names())
                .flatten();
            let mut report = self.maintain(now, Vec::new(), true);
            report.address_error = address_error;
            report.name_error = name_error;
            self.queue_script_from_maintenance();
            report
        };
        report.host_files.extend(errors);
        if self.file_scripts_pending && !self.file_work_pending() {
            self.file_scripts_pending = false;
            self.rerun_scripts();
        }
        report
    }

    /// Complete startup after socket setup and publisher attachment. Calling
    /// it again is harmless and does not replay removed-lease ownership.
    pub fn initialize(&mut self, now: i64) -> MaintenanceReport {
        if !self.file_init_ready {
            return MaintenanceReport::pending_files();
        }
        let first = !self.initialized;
        let mut host_files = Vec::new();
        let mut address_error = None;
        let mut name_error = None;
        if !self.initialized {
            self.leases
                .initialize_fqdns(|address| self.domains.for_address(address));
            if self.file_owner.is_none() {
                host_files = self.reread_host_files();
            }
            if self.host_files_ready {
                address_error = self.update_configured_addresses();
            }
        }
        if first && self.config.script.is_some() {
            // lease_find_interfaces uses the most specific directly connected
            // subnet before the first script queue turn and EVENT_INIT reload.
            if let Ok(interfaces) = crate::interfaces::dns_interfaces() {
                let addresses: Vec<_> = self
                    .leases
                    .active_newest_first()
                    .iter()
                    .map(|lease| lease.id())
                    .collect();
                for id in addresses {
                    let address = id.address();
                    let selected = interfaces
                        .iter()
                        .filter_map(|interface| {
                            let (IpAddr::V4(local), IpAddr::V4(mask)) =
                                (interface.address, interface.netmask)
                            else {
                                return None;
                            };
                            let mask = u32::from(mask);
                            (mask != 0 && (u32::from(local) & mask) == (u32::from(address) & mask))
                                .then_some((mask.count_ones(), interface))
                        })
                        .reduce(|best, candidate| {
                            if candidate.0 > best.0 {
                                candidate
                            } else {
                                best
                            }
                        });
                    if let Some((_, interface)) = selected {
                        let _ = self.leases.set_interface_by_id(id, interface.index);
                        let _ = self.leases.set_helper_context_by_id(
                            id,
                            LeaseEventContext {
                                interface: interface.name.clone(),
                                ..Default::default()
                            },
                        );
                    }
                }
            }
        }
        // lease_find_interfaces precedes the first helper queue turn. The
        // owner may have polled while file initialization was pending, so no
        // delivery was allowed to consume these records before this point.
        self.initialized = true;
        if first {
            // C freezes one event before processing queued EVENT_INIT. Deleted
            // startup leases take priority during the subsequent maintenance.
            if self.startup_removed.is_empty() {
                self.queue_script_from_maintenance();
                // Only C's pre-EVENT_INIT queue turn sees the original time.
                self.startup_script_time = None;
            }
            if self.host_files_ready {
                name_error = self.update_configured_names();
            }
        }
        let mut removed = std::mem::take(&mut self.startup_removed);
        // lease_init prunes with its pre-read clock. A lease which elapsed
        // during slow input survives through startup OLD callbacks, then the
        // current-time alarm prunes it on the following owner turn.
        removed.extend(
            self.leases
                .prune(None, if first { self.startup_time } else { now }),
        );
        let mut report = self.maintain(now, removed, true);
        report.restore = self.restore_stats.take();
        report.host_files = host_files;
        report.address_error = address_error;
        report.name_error = name_error;
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.queue_script_from_maintenance();
        if first {
            self.startup_script_time = None;
            // C queues one interface-change callback before EVENT_INIT marks
            // every live lease OLD, so that first record is announced twice.
            self.leases.rerun_scripts();
            self.queue_script_from_maintenance();
        }
        report
    }

    /// Includes startup restoration and all later prune/allocation operations.
    /// Hosts reload and persistence retries preserve this cumulative window.
    pub fn lease_counters(&self) -> super::lease::LeaseCounters {
        self.leases.counters()
    }

    /// TFTP uses the stored Ethernet identity before consulting neighbors.
    pub fn tftp_lease_mac(&self, address: Ipv4Addr) -> Option<[u8; 6]> {
        let identity = &self.leases.get(address)?.identity;
        (identity.hardware_type == 1)
            .then(|| identity.hardware_address.as_slice().try_into().ok())
            .flatten()
    }

    /// Only used during an ICMP wait, when the owner cannot reenter DHCP.
    /// Expired leases are excluded as the pending request prunes them first.
    pub fn tftp_lease_snapshot(&self, now: i64) -> Vec<(Ipv4Addr, [u8; 6])> {
        self.leases
            .active_newest_first()
            .into_iter()
            .filter_map(|lease| {
                if lease
                    .expires
                    .is_some_and(|expires| super::lease::lease_expired(expires, now))
                {
                    return None;
                }
                self.tftp_lease_mac(lease.address)
                    .map(|mac| (lease.address, mac))
            })
            .collect()
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
            .map(|lease| lease.id())
            .collect();
        let mut name_error = None;
        for id in addresses {
            let address = id.address();
            let Some(lease) = self.leases.get_by_id(id) else {
                name_error.get_or_insert_with(|| {
                    io::Error::other("lease disappeared during name update")
                });
                continue;
            };
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
                if let Err(error) = self.leases.set_hostname_by_id(
                    id,
                    Some(&name),
                    true,
                    self.domains.for_address(address),
                    self.config.fqdn_only,
                ) {
                    name_error.get_or_insert_with(|| io::Error::other(format!("{error:?}")));
                }
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
        self.reread_host_files_at(Path::new("/etc/ethers"))
    }

    fn reread_host_files_at(&mut self, ethers_path: &Path) -> Vec<HostFileError> {
        // dnsmasq.c clear_cache_and_reload: reread_dhcp, dhcp_read_ethers,
        // then dhcp_update_configs. Ethers merges into the fresh file rows.
        let report = self
            .ethers
            .reload_host_files(&mut self.host_files, &self.config.hosts);
        self.host_files_ready = report.ready();
        let mut errors = report.errors;
        if !self.host_files_ready {
            return errors;
        }
        if self.config.read_ethers {
            match self.ethers.reload(ethers_path) {
                Ok(lines) => {
                    for line in lines {
                        errors.push(HostFileError {
                            path: ethers_path.to_path_buf(),
                            line: Some(line),
                            kind: crate::config::dhcp::HostFileErrorKind::Line(
                                crate::config::Error("bad ethers entry"),
                            ),
                        });
                    }
                }
                Err(error) => errors.push(HostFileError {
                    path: ethers_path.to_path_buf(),
                    line: None,
                    kind: crate::config::dhcp::HostFileErrorKind::Io(error),
                }),
            }
        }
        self.ethers.clear_inferred_addresses();
        self.hosts = self
            .ethers
            .hosts()
            .iter()
            .zip(self.ethers.previous_indices())
            .map(|(host, previous)| {
                let mut policy = host_policy(host);
                policy.declined_at = previous.and_then(|index| self.hosts[index].declined_at);
                policy
            })
            .collect();
        self.config.hosts = self.ethers.hosts().to_vec();
        errors
    }

    /// SIGHUP data-file stage, after the caller reloads DNS hosts and before
    /// acknowledging its reload generation. The main configuration is retained.
    /// Unsupported valid-C selectors pause DHCP admission until a later valid
    /// reload; never serve a partially widened rule set.
    pub fn reload_host_files(&mut self, now: i64) -> MaintenanceReport {
        if !self.initialized {
            return self.initialize(now);
        }
        self.leases.rerun_scripts();
        self.reload_data_files(now)
    }

    /// EVENT_RELOAD reruns unchanged leases after its DNS file reads. A
    /// successful automatic resolver reload only reloads data, without this.
    pub fn rerun_scripts(&mut self) {
        if self.file_work_pending() {
            self.file_scripts_pending = true;
            return;
        }
        self.leases.rerun_scripts();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.queue_script_from_maintenance();
    }

    /// inotify.c hostsdir updates re-evaluate already loaded DHCP rules and
    /// lease names, without rereading unrelated configuration inputs.
    pub fn hosts_changed(&mut self, now: i64) -> MaintenanceReport {
        if !self.initialized {
            return self.initialize(now);
        }
        let address_error = self.update_configured_addresses();
        let name_error = self
            .host_files_ready
            .then(|| self.update_configured_names())
            .flatten();
        let mut report = self.maintain(now, Vec::new(), true);
        report.address_error = address_error;
        report.name_error = name_error;
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.queue_script_from_maintenance();
        report
    }

    pub fn reload_data_files(&mut self, now: i64) -> MaintenanceReport {
        if self.file_owner.is_some() {
            self.file_reload_pending = true;
            return MaintenanceReport::pending_files();
        }
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
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.queue_script_from_maintenance();
        report
    }

    /// Delivered external SIGALRM events use the same maintenance path as
    /// elapsed lease timers, even when the next scheduled timer is later.
    pub fn request_alarms(&mut self, count: usize) {
        self.pending_alarms = self.pending_alarms.saturating_add(
            count.min(u32::MAX as usize) as u32);
    }

    /// Perform expiry and retry maintenance even when no DHCP packet arrives.
    /// The caller owns returned removals/name losses until cleanup completes.
    pub fn tick(&mut self, now: i64) -> Option<MaintenanceReport> {
        if self.file_work_pending() {
            return None;
        }
        if !self.initialized {
            return Some(self.initialize(now));
        }
        self.observe_alarm();
        if self.pending_alarms == 0 {
            return None;
        }
        self.pending_alarms -= 1;
        let removed = self.leases.prune(None, now);
        let report = self.maintain(now, removed, false);
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.queue_script_from_maintenance();
        Some(report)
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

fn pxe_selection<'a>(
    config: &'a DhcpConfig,
    raw_tags: &'a [Vec<u8>],
    selected: &[SelectedContext],
    context: Option<usize>,
    mode: u8,
) -> FilteredOptions<'a> {
    let tags: Vec<_> = raw_tags.iter().map(Vec::as_slice).collect();
    let context_tag = context
        .and_then(|index| selected.get(index))
        .and_then(|selected| config.ranges[selected.source_index].set_tag.as_deref());
    option_filter(
        &config.options,
        &tags,
        &context_tag.into_iter().collect::<Vec<_>>(),
        &config.tag_if,
        mode,
    )
}

fn pxe_custom_prompt(
    config: &DhcpConfig,
    packet: super::packet::Packet<'_>,
    tags: &[&[u8]],
) -> bool {
    use crate::config::dhcp::Encapsulation;
    let Some(vendor) = packet.option(60, 1) else {
        return false;
    };
    let contains = |needle: &[u8]| {
        needle.is_empty() || vendor.windows(needle.len()).any(|part| part == needle)
    };
    config.options.iter().any(|option| {
        option.code == 10
            && option.tags.matches_with(tags, true)
            && match &option.encapsulation {
                Encapsulation::Vendor(needle) => contains(needle),
                Encapsulation::PxeVendor => {
                    config.pxe.vendors.iter().any(|prefix| contains(prefix))
                }
                _ => false,
            }
    })
}

fn pxe_host(name: &[u8], dns_port: u16, lookup: &mut Option<BootHostLookup>) -> Ipv4Addr {
    let address = if dns_port == 0 {
        None
    } else {
        match lookup.as_mut().map(|lookup| lookup(name)) {
            Some(Ok(address)) => address,
            Some(Err(error)) => {
                eprintln!("dnsmasq-rs: PXE hosts lookup: {error}");
                None
            }
            None => None,
        }
    };
    if address.is_none() {
        eprintln!(
            "dnsmasq-rs: No IPv4 address found for {}",
            String::from_utf8_lossy(name)
        );
    }
    address.unwrap_or(Ipv4Addr::UNSPECIFIED)
}

fn apply_reply_delay(
    seconds: Option<i32>,
    received_at: i64,
    xid: u32,
    quiet: bool,
    counters: LeaseCounters,
    wait: &RefCell<Option<&mut DhcpProbeWait<'_>>>,
    notices: &mut Vec<crate::logging::LogEvent>,
) -> io::Result<()> {
    let Some(seconds) = seconds else {
        return Ok(());
    };
    let notice = (!quiet).then(|| {
        crate::logging::LogEvent::new(
            crate::logging::Service::Dhcp,
            crate::logging::Priority::Info,
            format!("{xid} reply delay: {seconds}").into_bytes(),
        )
    });
    let mut borrowed = wait.borrow_mut();
    let Some(owner_wait) = borrowed.as_deref_mut() else {
        if let Some(notice) = notice {
            notices.push(notice);
        }
        return if !super::reply_delay::pending(received_at, epoch_seconds(), seconds, 0) {
            Ok(())
        } else {
            Err(io::Error::other(
                "DHCP reply delay requires its owner waiter",
            ))
        };
    };
    // ZERO transfers the C log write site without servicing network input.
    if notice.is_some() {
        owner_wait(None, Duration::ZERO, counters, notice)?;
    }
    super::reply_delay::wait(received_at, seconds, epoch_seconds, |timeout| {
        owner_wait(None, timeout, counters, None)
    })
}

impl LocalProvider {
    fn resolve_events(
        &mut self,
        dispatch: &Dispatch<'_>,
        interface_name: Option<&[u8]>,
        mut events: Option<&mut DhcpEventSink<'_>>,
        wait: Option<&mut DhcpProbeWait<'_>>,
    ) -> Result<Outcome, RuntimeError> {
        let received_at = epoch_seconds();
        let wait = RefCell::new(wait);
        // Packet::parse has already validated the fixed BOOTP header.
        let bytes = dispatch.packet.bytes();
        let xid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let packet_notices = RefCell::new(Vec::new());
        self.force_broadcast = false;
        self.selected_boot = None;
        self.pxe_client = None;
        self.pxe_generated.clear();
        self.pxe_menu_failed = false;
        self.direct_pxe = None;
        let received_interface = dispatch.ingress.interface_index;
        let bridge = match self.bridge_ingress(interface_name) {
            Ok(bridge) => bridge,
            Err(()) => {
                return Ok(Outcome {
                    reply: Reply::Ignore,
                    removed: Vec::new(),
                    lost_names: Vec::new(),
                    newly_allocated: false,
                })
            }
        };
        let mut effective_dispatch = *dispatch;
        let interface_name = if let Some((index, name)) = &bridge {
            effective_dispatch.ingress.interface_index = *index;
            Some(name.as_slice())
        } else {
            interface_name
        };
        let dispatch = &effective_dispatch;
        if !self.host_files_ready
            || interface_name.is_some_and(|name| {
                self.config
                    .no_dhcp_interfaces
                    .iter()
                    .flatten()
                    .any(|pattern| interface_matches(pattern, name))
            })
        {
            return Ok(Outcome {
                reply: Reply::Ignore,
                removed: Vec::new(),
                lost_names: Vec::new(),
                newly_allocated: false,
            });
        }
        let interface = dispatch.ingress.interface_index;
        let mut addresses = self
            .packet_addresses()
            .map_err(|error| RuntimeError::State(error.to_string()))?;
        let mut local = primary_ipv4_with_name(interface, interface_name, &self.control)
            .map_err(|error| RuntimeError::State(error.to_string()))?;
        let loopback = dispatch.packet.giaddr().is_unspecified()
            && addresses
                .iter()
                .any(|address| address.index == received_interface && address.loopback);
        self.selected.clear();
        match self
            .interface_policy
            .select(interface_name, interface, local, &addresses)
        {
            Some(Selection::Primary) => {}
            Some(Selection::Secondary(secondary)) => {
                local = secondary.address;
                addresses.insert(0, secondary);
            }
            None => {
                return Ok(Outcome {
                    reply: Reply::Ignore,
                    removed: Vec::new(),
                    lost_names: Vec::new(),
                    newly_allocated: false,
                });
            }
        }
        let packet = dispatch.packet;
        let agent_address = |code| {
            relay_suboption(packet, code, 4)
                .and_then(|value| <[u8; 4]>::try_from(value.get(..4)?).ok())
                .map(Ipv4Addr::from)
                .filter(|address| !address.is_unspecified())
        };
        let subnet = packet.subnet_selector().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let override_server = agent_address(11);
        let ingress = select_contexts_with_shared(
            &self.config.ranges,
            &mut self.states,
            &addresses,
            interface,
            &self.config.network.shared,
        );
        self.selected = select_remote_contexts_with_shared(
            &self.config.ranges,
            &mut self.states,
            ingress,
            subnet,
            packet.giaddr(),
            packet.effective_ciaddr(),
            local,
            override_server,
            &self.config.network.shared,
        );
        let override_server = self
            .config
            .network
            .server_override(packet.giaddr(), override_server);
        if self.selected.is_empty() {
            let via = if !subnet.is_unspecified() {
                format!("with subnet selector {subnet}")
            } else if !packet.giaddr().is_unspecified() {
                format!("via {}", packet.giaddr())
            } else {
                format!(
                    "via {}",
                    String::from_utf8_lossy(interface_name.unwrap_or(b"(null)"))
                )
            };
            self.network_notices.push(crate::logging::LogEvent::new(
                crate::logging::Service::Dhcp,
                crate::logging::Priority::Warning,
                format!("no address range available for DHCP request {via}").into_bytes(),
            ));
            return Ok(Outcome {
                reply: Reply::Ignore,
                removed: Vec::new(),
                lost_names: Vec::new(),
                newly_allocated: false,
            });
        }

        let mut ranges: Vec<_> = self
            .selected
            .iter()
            .map(|selected| selected.range.clone())
            .collect();
        let mut alias = None;
        if self.tftp_enabled
            && packet.message_type() == 3
            && override_server.is_none()
            && packet.requested_address().is_some()
        {
            if let Some(server) = packet
                .server_identifier()
                .filter(|server| !ranges.iter().any(|range| range.local == *server))
            {
                for address in addresses.iter().filter(|address| address.address == server) {
                    let Ok(name) = crate::net::interface_name(&self.control, address.index) else {
                        continue;
                    };
                    let name = &name[..name
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(name.len())];
                    if self
                        .interface_policy
                        .selected_address(Some(name), server, address.loopback)
                        && crate::config::tftp::interface_enabled(
                            self.tftp_enabled,
                            &self.tftp_interfaces,
                            &self.config.no_dhcp_interfaces,
                            name,
                        )
                    {
                        alias = Some(server);
                        break;
                    }
                }
            }
        }
        let now = epoch_seconds();
        let packet = dispatch.packet;
        let identity = ClientIdentity {
            hardware_type: u32::from(packet.hardware_type()),
            hardware_address: packet.hardware_address().to_vec(),
            client_id: (!self.config.ignore_client_id && packet.message_type() != 0)
                .then(|| packet.client_id().map(<[u8]>::to_vec))
                .flatten(),
        };
        let existing = self.leases.find_client(&identity).filter(|lease| {
            lease
                .expires
                .is_none_or(|expiry| !super::lease::lease_expired(expiry, now))
        });
        let clid = (packet.message_type() != 0)
            .then(|| {
                identity
                    .client_id
                    .as_deref()
                    .or_else(|| existing.and_then(|lease| lease.identity.client_id.as_deref()))
            })
            .flatten();
        let event_mac = Some(event_mac(packet, clid));
        if self.config.log_dhcp {
            for range in &ranges {
                let value = if range.kind == RangeKind::Dynamic {
                    format!(
                        "{xid} available DHCP range: {} -- {}",
                        range.start, range.end
                    )
                } else {
                    format!(
                        "{xid} available DHCP subnet: {}/{}",
                        range.start, range.netmask
                    )
                };
                packet_notices
                    .borrow_mut()
                    .push(crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Info,
                        value.into_bytes(),
                    ));
            }
            packet_notices.borrow_mut().extend(
                super::logging::request_details(packet)
                    .into_iter()
                    .map(|message| {
                        crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Info,
                            message,
                        )
                    }),
            );
        }
        let mut tags: Vec<&[u8]> = interface_name.into_iter().collect();
        let [oui, serial, _] = crate::helper::cpe_data(packet);
        if oui.is_some() && serial.is_some() {
            tags.push(b"cpewan-id");
        }
        for rule in &self.config.macs {
            if rule.matches(identity.hardware_type, &identity.hardware_address) {
                tags.push(&rule.set_tag);
            }
        }
        for rule in &self.config.matches {
            if rule.matches_packet(packet) {
                tags.push(&rule.set_tag);
            }
        }
        for rule in &self.config.classes {
            let data = match rule.kind {
                ClassKind::Vendor => packet.option(60, 1),
                ClassKind::User => packet.option(77, 1),
                ClassKind::Circuit => relay_suboption(packet, 1, 1),
                ClassKind::Remote => relay_suboption(packet, 2, 1),
                ClassKind::Subscriber => relay_suboption(packet, 6, 1),
            };
            if data.is_some_and(|data| rule.matches(data)) {
                tags.push(&rule.set_tag);
            }
        }

        let in_context = |address| ranges.iter().any(|range| range.same_subnet(address));
        let mut lookup_tags = tags.clone();
        TagIf::apply_all(&self.config.tag_if, &mut lookup_tags);
        let mut host_index = self.config.find_host_tagged(
            clid,
            identity.hardware_type,
            Some(&identity.hardware_address),
            None,
            &lookup_tags,
            in_context,
        );
        if host_index.is_some() {
            tags.push(b"known");
        } else if self
            .config
            .find_host_tagged(
                clid,
                identity.hardware_type,
                Some(&identity.hardware_address),
                None,
                &lookup_tags,
                |_| true,
            )
            .is_some()
        {
            tags.push(b"known-othernet");
        }
        let client_name = packet.client_hostname();
        let full_client_name = packet.client_hostname_full();
        for rule in &self.config.name_matches {
            if full_client_name
                .as_deref()
                .is_some_and(|name| rule.matches(name))
            {
                tags.push(&rule.set_tag);
            }
        }
        let mut configured_by_name = false;
        if host_index.is_none() {
            if let Some(name) = client_name.as_deref() {
                lookup_tags = tags.clone();
                TagIf::apply_all(&self.config.tag_if, &mut lookup_tags);
                if let Some(index) = self.config.find_host_tagged(
                    None,
                    identity.hardware_type,
                    Some(&identity.hardware_address),
                    Some(name),
                    &lookup_tags,
                    in_context,
                ) {
                    let host = &self.config.hosts[index];
                    // rfc2131.c's second lookup cannot authenticate an ID/MAC
                    // rule merely by claiming its configured hostname.
                    if host.client_id.is_none() && host.hardware.is_empty() {
                        host_index = Some(index);
                        configured_by_name = true;
                        tags.push(b"known");
                    }
                }
            }
        }
        let configured = host_index.map(|index| &self.config.hosts[index]);
        let configured_name = configured
            .filter(|_| !configured_by_name)
            .and_then(|host| host.hostname.as_deref());
        if let Some(host) = configured {
            tags.extend(host.set_tags.iter().map(Vec::as_slice));
        }
        if packet.message_type() == 0 && dispatch.ingress.listener == super::service::Listener::Dhcp
        {
            let file = &packet.bytes()[108..236];
            let length = file
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(file.len());
            if length != 0 {
                tags.push(&file[..length]);
            }
            tags.push(b"bootp");
        }
        self.request_tags = tags.iter().map(|tag| tag.to_vec()).collect();
        // do_options checks the original netid head, not tag-if additions.
        self.force_broadcast = self.config.force_broadcast_for(&tags);
        TagIf::apply_all(&self.config.tag_if, &mut tags);
        // PXE checks dhcp-ignore here; CONFIG_DISABLE belongs to the
        // later ordinary DHCP/BOOTP state path in rfc2131.c.
        let ignored = self.config.ignore.iter().any(|rule| rule.matches(&tags));
        let pxe_listener = dispatch.ingress.listener == super::service::Listener::Pxe;
        let decision = if self.config.pxe.enabled || pxe_listener {
            pxe::decide(
                packet,
                pxe_listener,
                self.config.pxe.enabled,
                &self.config.pxe.vendors,
                &self.config.pxe.services,
                &ranges,
                &tags,
                ignored,
                |name| pxe_host(name, self.dns_port, &mut self.boot_host_lookup),
            )
        } else {
            pxe::Decision::Continue(None)
        };
        match decision {
            pxe::Decision::Continue(client) => self.pxe_client = client,
            decision => {
                self.network_notices
                    .extend(packet_notices.borrow_mut().drain(..));
                let delay = if let pxe::Decision::Proxy {
                    context,
                    ignored: false,
                    ..
                } = &decision
                {
                    let selected = pxe_selection(
                        &self.config,
                        &self.request_tags,
                        &self.selected,
                        Some(*context),
                        2,
                    );
                    self.config.network.reply_delay(&selected.tags)
                } else {
                    None
                };
                let outcome = self.prepare_direct_pxe(
                    packet,
                    decision,
                    pxe_listener,
                    now,
                    interface_name,
                    event_mac.as_deref(),
                )?;
                if delay.is_some() {
                    if let Some(owner_wait) = wait.borrow_mut().as_deref_mut() {
                        for notice in self.network_notices.drain(..) {
                            owner_wait(None, Duration::ZERO, self.leases.counters(), Some(notice))
                                .map_err(|error| RuntimeError::State(error.to_string()))?;
                        }
                    }
                }
                apply_reply_delay(
                    delay,
                    received_at,
                    xid,
                    self.config.quiet_dhcp,
                    self.leases.counters(),
                    &wait,
                    &mut self.network_notices,
                )
                .map_err(|error| RuntimeError::State(error.to_string()))?;
                return Ok(outcome);
            }
        }
        let ack = packet.message_type() == 3
            || (packet.message_type() == 1
                && self.config.rapid_commit
                && packet.option(80, 0).is_some());
        self.reply_hostname = configured_name.map(<[u8]>::to_vec).or(client_name);
        if packet.message_type() == 1
            && !ack
            && packet.option(81, 3).is_some()
            && self.reply_hostname.is_none()
            && full_client_name.is_some()
        {
            // A legal FQDN beginning with '.' becomes empty when C strips
            // its domain, while offer_hostname still points at that string.
            self.reply_hostname = Some(Vec::new());
        }
        if packet.message_type() == 1 && !ack && packet.option(81, 3).is_none() {
            // An ordinary client name alone is not echoed in an OFFER. A
            // configured name must match the full provided name, before strip.
            let provided = packet.client_hostname_full();
            if configured_name.is_none_or(|configured| {
                provided
                    .as_deref()
                    .is_some_and(|name| !configured.eq_ignore_ascii_case(name))
            }) {
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
        // INFORM only uses hosts as a fallback; ACK name policy below is
        // shared with rapid commit after DISCOVER has selected its address.
        if packet.message_type() == 8 && self.reply_hostname.is_none() && self.dns_port != 0 {
            let address = packet.effective_ciaddr();
            if !address.is_unspecified() {
                if let Some(lookup) = self.reverse_host_lookup.as_mut() {
                    self.reply_hostname = lookup(address)
                        .map_err(|error| RuntimeError::State(error.to_string()))?
                        .and_then(|name| reverse_hostname(name, self.domains.for_address(address)));
                }
            }
        }
        let generated_name = (!self.config.generate_names.is_empty())
            .then(|| generated_hostname(packet, clid))
            .flatten();
        let mut ack_name = |address: Ipv4Addr, context: Option<usize>| {
            // rfc2131.c:1599,1676-1720: the final context supplies its tag
            // before hosts authority, ignore-names and generated-name policy.
            let mut name_tags: Vec<_> = self.request_tags.iter().map(Vec::as_slice).collect();
            if let Some(tag) = context.and_then(|index| {
                self.config.ranges[self.selected[index].source_index].set_tag.as_deref()
            }) {
                name_tags.push(tag);
            }
            TagIf::apply_all(&self.config.tag_if, &mut name_tags);
            let mut name = configured_name.map(<[u8]>::to_vec);
            let mut authoritative = name.is_some();
            if !authoritative && self.dns_port != 0 && !address.is_unspecified() {
                if let Some(lookup) = self.reverse_host_lookup.as_mut() {
                    name = lookup(address)
                        .map_err(|error| RuntimeError::State(error.to_string()))?
                        .and_then(|name| reverse_hostname(name, self.domains.for_address(address)));
                    authoritative = name.is_some();
                }
            }
            if name.is_none() && !self.config.ignore_client_name(&name_tags) {
                name = packet.client_hostname();
            }
            if name.is_none() && self.config.generate_names.iter().any(|rule| rule.matches(&name_tags)) {
                name = generated_name.clone();
            }
            Ok(name.map(|name| (name, authoritative)))
        };
        let request_name = if packet.message_type() == 3 {
            // SELECTING consumes the server-ID suffix before narrowing.
            let first = if packet.requested_address().is_some() {
                packet.server_identifier()
                    .and_then(|server| ranges.iter().position(|range| range.local == server))
                    .unwrap_or(0)
            } else {
                0
            };
            let address = packet.requested_address().unwrap_or(packet.effective_ciaddr());
            let context = super::allocation::narrow(&ranges[first..], address, &tags)
                .map(|index| first + index);
            let name = ack_name(address, context)?;
            self.reply_hostname = name.as_ref().map(|(name, _)| name.clone());
            name
        } else {
            None
        };
        let bootp_permissions: Vec<bool> = if packet.message_type() == 0
            && !self.config.bootp_dynamic_tags.is_empty()
        {
            self.selected
                .iter()
                .map(|selected| {
                    // run_tag_if starts from raw request tags plus the selected
                    // context, not from a previously expanded request-only list.
                    let mut context_tags: Vec<&[u8]> =
                        self.request_tags.iter().map(Vec::as_slice).collect();
                    if let Some(tag) = self.config.ranges[selected.source_index].set_tag.as_deref()
                    {
                        context_tags.push(tag);
                    }
                    TagIf::apply_all(&self.config.tag_if, &mut context_tags);
                    self.config
                        .bootp_dynamic_tags
                        .iter()
                        .any(|rule| rule.matches(&context_tags))
                })
                .collect()
        } else {
            Vec::new()
        };
        let environment = Environment {
            now,
            interface,
            authoritative: self.config.authoritative,
            unicast_destination: dispatch.ingress.unicast_destination,
            ignored: ignored || configured.is_some_and(|host| host.ignore),
            ignore_client_id: self.config.ignore_client_id,
            fqdn_only: self.config.fqdn_only,
            rapid_commit: self.config.rapid_commit,
            bootp_dynamic: self.config.bootp_dynamic,
            consecutive_addresses: self.config.sequential,
            override_server,
            fallback_server: local,
            server_aliases: alias.as_slice(),
        };
        let now = environment.now;
        let mut probe_error = None;
        let configured_disabled = configured.is_some_and(|host| host.ignore);
        let request_tags = &self.request_tags;
        let ranges_selected = &self.selected;
        let range_config = &self.config.ranges;
        let tag_if = &self.config.tag_if;
        let logging = DhcpLogging {
            quiet_dhcp: self.config.quiet_dhcp,
            log_options: self.config.log_dhcp,
            has_error: false,
        };

        let packet_notice =
            |kind: &[u8], address: Option<Ipv4Addr>, extra: Option<&[u8]>, error: Option<&[u8]>| {
                if let Some(message) = super::logging::packet(
                    logging,
                    super::logging::PacketLog {
                        kind,
                        address,
                        extra,
                        error,
                        mac: event_mac.as_deref(),
                        interface: interface_name,
                        xid,
                    },
                ) {
                    packet_notices
                        .borrow_mut()
                        .push(crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Info,
                            message,
                        ));
                }
            };
        let mut on_event = |event: super::state::LogEvent<'_>| {
            let (kind, address, name, has_error) = match event {
                super::state::LogEvent::Warning { message } => {
                    packet_notices
                        .borrow_mut()
                        .push(crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Warning,
                            message.to_vec(),
                        ));
                    return;
                }

                super::state::LogEvent::Tags { context } => {
                    if logging.log_options {
                        let mut tags: Vec<_> = request_tags.iter().map(Vec::as_slice).collect();
                        if let Some(tag) = context
                            .and_then(|index| ranges_selected.get(index))
                            .and_then(|selected| {
                                range_config[selected.source_index].set_tag.as_deref()
                            })
                        {
                            tags.push(tag);
                        }
                        TagIf::apply_all(tag_if, &mut tags);
                        tags.reverse();
                        if let Some(message) = super::logging::tags(xid, &tags) {
                            packet_notices
                                .borrow_mut()
                                .push(crate::logging::LogEvent::new(
                                    crate::logging::Service::Dhcp,
                                    crate::logging::Priority::Info,
                                    message,
                                ));
                        }
                    }
                    return;
                }
                super::state::LogEvent::Packet {
                    kind,
                    address,
                    extra,
                    error,
                } => {
                    let error = if kind == b"BOOTP"
                        && error == Some(b"ignored".as_slice())
                        && configured_disabled
                    {
                        Some(b"disabled".as_slice())
                    } else {
                        error
                    };
                    packet_notice(kind, address, extra, error);
                    return;
                }
                super::state::LogEvent::Ack { address, name } => {
                    packet_notice(b"DHCPACK", Some(address), name, None);
                    (DhcpEventKind::Ack, address, name, false)
                }
                super::state::LogEvent::Release {
                    address,
                    unknown_lease,
                } => {
                    packet_notice(
                        b"DHCPRELEASE",
                        Some(address),
                        None,
                        unknown_lease.then_some(b"unknown lease".as_slice()),
                    );
                    (DhcpEventKind::Release, address, None, unknown_lease)
                }
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
        let reply_error = RefCell::new(None);
        let mut before_offer = |context: usize, counters: LeaseCounters| {
            // C's DISCOVER record precedes reply-delay and any other service
            // work during that wait. Emit through the existing owner gate.
            for notice in packet_notices.borrow_mut().drain(..) {
                if let Some(owner_wait) = wait.borrow_mut().as_deref_mut() {
                    if let Err(error) = owner_wait(None, Duration::ZERO, counters, Some(notice)) {
                        *reply_error.borrow_mut() = Some(error);
                        return false;
                    }
                } else {
                    self.network_notices.push(notice);
                }
            }
            let mut delay_tags: Vec<_> = self.request_tags.iter().map(Vec::as_slice).collect();
            if let Some(tag) = self.config.ranges[self.selected[context].source_index]
                .set_tag
                .as_deref()
            {
                delay_tags.push(tag);
            }
            TagIf::apply_all(&self.config.tag_if, &mut delay_tags);
            match apply_reply_delay(
                self.config.network.reply_delay(&delay_tags),
                received_at,
                xid,
                self.config.quiet_dhcp,
                counters,
                &wait,
                &mut self.network_notices,
            ) {
                Ok(()) => true,
                Err(error) => {
                    *reply_error.borrow_mut() = Some(error);
                    false
                }
            }
        };
        let mut rapid_name = |address, context| {
            let name = ack_name(address, Some(context))?;
            self.reply_hostname = name.as_ref().map(|(name, _)| name.clone());
            Ok(name)
        };
        let mut provider = StateProvider::new(
            &mut self.leases,
            &mut ranges,
            &tags,
            host_index.map(|index| &mut self.hosts[index]),
            &self.reserved,
            environment,
            |address, hash, counters| {
                let mut owner_wait = wait.borrow_mut();
                let result = if let Some(wait) = owner_wait.as_deref_mut() {
                    self.probe.check_with_wait(
                        now,
                        address,
                        hash,
                        loopback,
                        self.should_stop,
                        &mut |socket, timeout| wait(Some(socket), timeout, counters, None),
                    )
                } else {
                    self.probe
                        .check_with_stop(now, address, hash, loopback, self.should_stop)
                };
                match result {
                    Ok(result) => result,
                    Err(error) => {
                        probe_error = Some(error);
                        ProbeResult::Failed
                    }
                }
            },
        );
        provider.configured_name = request_name.as_ref()
            .filter(|(_, authoritative)| *authoritative)
            .map(|(name, _)| name.as_slice())
            .or(configured_name);
        provider.ignore_client_name = packet.message_type() == 3;
        provider.generated_name = request_name.as_ref()
            .filter(|(_, authoritative)| !authoritative)
            .map(|(name, _)| name.as_slice());
        provider.rapid_name = Some(&mut rapid_name);
        provider.bootp_contexts = &bootp_permissions;
        provider.domains = Some(&self.domains);
        provider.quiet_dhcp = self.config.quiet_dhcp;
        provider.message_counters = Some(&mut self.message_counters);
        provider.event_sink = Some(&mut on_event);
        provider.before_offer = Some(&mut before_offer);
        let result = provider.resolve(dispatch);
        drop(provider);
        drop(rapid_name);
        drop(ack_name);
        drop(before_offer);
        drop(on_event);
        let packet_notices = packet_notices.into_inner();
        if self.network_notices.is_empty() {
            self.network_notices = packet_notices;
        } else {
            self.network_notices.extend(packet_notices);
        }
        if let Some(error) = reply_error.into_inner() {
            return Err(RuntimeError::State(error.to_string()));
        }
        if let Ok(outcome) = &result {
            let lease_id = match outcome.reply {
                Reply::Ack { address, .. } | Reply::Bootp { address, .. } => {
                    let lease_identity = super::state::identity(packet, environment.ignore_client_id);
                    self.leases
                        .find_client(&lease_identity)
                        .filter(|lease| lease.address == address)
                        .or_else(|| self.leases.get(address))
                        .map(|lease| lease.id())
                }
                _ => None,
            };
            if let Some(id) = lease_id.filter(|_| matches!(outcome.reply, Reply::Ack { .. })) {
                if self.config.lease_query.enabled {
                    // C keeps prior metadata when this ACK has no usable
                    // incoming value. Agent retention shares echo reservation.
                    if let Some(agent) = packet.echo_agent_id() {
                        let _ = self.leases.set_agent_id_by_id(id, Some(agent));
                    }
                    if let Some(vendor) = packet.option(60, 1) {
                        let _ = self.leases.set_vendor_class_by_id(id, Some(vendor));
                    }
                } else {
                    let _ = self.leases.set_agent_id_by_id(id, None);
                    let _ = self.leases.set_vendor_class_by_id(id, None);
                }
            }
            if self.config.script.is_some() {
                self.scripts.add_pruned(outcome.removed.clone());
            }
            self.select_boot(outcome);
            self.prepare_normal_pxe(packet, outcome);
            if self.config.script.is_some() {
                if let Reply::Ack {
                    context, ..
                }
                | Reply::Bootp {
                    context, ..
                } = outcome.reply
                {
                    // rfc2131.c refreshes one-shot helper metadata only for
                    // an actual allocation, or REQUEST with option 50. A
                    // multi-MAC handoff reuses the incumbent lease; DISCOVER
                    // with rapid commit skips the REQUEST option-50 branch.
                    let do_classes = packet.message_type() != 0
                        && (outcome.newly_allocated
                            || (packet.message_type() == 3
                                && packet.requested_address().is_some()));
                    let extra = do_classes.then(|| {
                        let mut tags: Vec<_> =
                            self.request_tags.iter().map(Vec::as_slice).collect();
                        if let Some(tag) = self.selected.get(context).and_then(|selected| {
                            self.config.ranges[selected.source_index].set_tag.as_deref()
                        }) {
                            tags.push(tag);
                        }
                        TagIf::apply_all(&self.config.tag_if, &mut tags);
                        crate::helper::extra_data(packet, &tags)
                    });
                    let _ = self.leases.set_helper_context_by_id(
                        lease_id.ok_or_else(|| {
                            RuntimeError::State("committed ACK or BOOTP lease is missing".into())
                        })?,
                        LeaseEventContext {
                            interface: interface_name.unwrap_or_default().to_vec(),
                            now,
                            relay_address: (!packet.giaddr().is_unspecified())
                                .then_some(packet.giaddr()),
                            extra: extra.map(Box::new),
                            log_dhcp: self.config.log_dhcp,
                        },
                    );
                }
            }
        }
        self.probe_error = probe_error;
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.queue_script_from_maintenance();
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
    fn record_reply(
        &mut self,
        request: super::packet::Packet<'_>,
        reply: Reply,
        output: &[u8],
        omitted_options: &[u8],
        option_warnings: &[super::logging::OptionWarning],
    ) {
        // option_filter diagnostics precede do_options' requested list.
        self.network_notices.extend(
            option_warnings
                .iter()
                .copied()
                .filter(|warning| matches!(warning, super::logging::OptionWarning::Duplicate(_)))
                .map(|warning| {
                    crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Warning,
                        super::logging::option_warning(warning),
                    )
                }),
        );
        if self.config.log_dhcp && !matches!(reply, Reply::Nak { .. } | Reply::Bootp { .. }) {
            if let Some(codes) = request.option(55, 0) {
                self.network_notices.extend(
                    super::logging::requested_options(request.transaction_id(), codes)
                        .into_iter()
                        .map(|message| {
                            crate::logging::LogEvent::new(
                                crate::logging::Service::Dhcp,
                                crate::logging::Priority::Info,
                                message,
                            )
                        }),
                );
            }
        }
        self.network_notices.extend(
            option_warnings
                .iter()
                .copied()
                .filter(|warning| !matches!(warning, super::logging::OptionWarning::Duplicate(_)))
                .map(|warning| {
                    crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Warning,
                        super::logging::option_warning(warning),
                    )
                }),
        );
        if self.pxe_menu_failed {
            self.network_notices.push(crate::logging::LogEvent::new(
                crate::logging::Service::Dhcp,
                crate::logging::Priority::Error,
                b"PXE menu too large".to_vec(),
            ));
        }
        self.network_notices
            .extend(omitted_options.iter().map(|code| {
                crate::logging::LogEvent::new(
                    crate::logging::Service::Dhcp,
                    crate::logging::Priority::Warning,
                    super::logging::omission(*code),
                )
            }));
        if self.config.log_dhcp {
            self.network_notices
                .extend(
                    super::logging::reply_details(output)
                        .into_iter()
                        .map(|message| {
                            crate::logging::LogEvent::new(
                                crate::logging::Service::Dhcp,
                                crate::logging::Priority::Info,
                                message,
                            )
                        }),
                );
        }
    }

    fn direct_pxe_reply(
        &mut self,
        _request: super::packet::Packet<'_>,
        output: &mut [u8],
    ) -> Result<Option<super::reply::ReplyEncoding>, RuntimeError> {
        let Some(reply) = self.direct_pxe.take() else {
            return Ok(None);
        };
        if output.len() < reply.bytes.len() {
            return Err(RuntimeError::Reply(
                super::reply::ReplyError::BufferTooSmall {
                    required: reply.bytes.len(),
                    available: output.len(),
                },
            ));
        }
        output[..reply.bytes.len()].copy_from_slice(&reply.bytes);
        let encoded = reply.encoding;
        if self.config.log_dhcp {
            self.network_notices.extend(
                super::logging::reply_details(&output[..encoded.len])
                    .into_iter()
                    .map(|message| {
                        crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Info,
                            message,
                        )
                    }),
            );
        }
        Ok(Some(encoded))
    }

    fn pxe_encoding(&self) -> PxeEncoding<'_> {
        PxeEncoding::ordinary(
            self.pxe_client.as_ref(),
            &self.config.pxe.vendors,
            &self.pxe_generated,
        )
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn lease_query_reply(
        &mut self,
        dispatch: &Dispatch<'_>,
        interface_name: Option<&[u8]>,
        source: Ipv4Addr,
        output: &mut [u8],
    ) -> Result<Option<usize>, RuntimeError> {
        let bridge = match self.bridge_ingress(interface_name) {
            Ok(bridge) => bridge,
            Err(()) => return Ok(None),
        };
        let mut effective_dispatch = *dispatch;
        let interface_name = if let Some((index, name)) = &bridge {
            effective_dispatch.ingress.interface_index = *index;
            Some(name.as_slice())
        } else {
            interface_name
        };
        let dispatch = &effective_dispatch;
        if !self.host_files_ready
            || interface_name.is_some_and(|name| {
                self.config
                    .no_dhcp_interfaces
                    .iter()
                    .flatten()
                    .any(|pattern| interface_matches(pattern, name))
            })
        {
            return Ok(None);
        }
        let interface = dispatch.ingress.interface_index;
        let mut addresses = self
            .packet_addresses()
            .map_err(|error| RuntimeError::State(error.to_string()))?;
        let mut local = primary_ipv4_with_name(interface, interface_name, &self.control)
            .map_err(|error| RuntimeError::State(error.to_string()))?;
        match self
            .interface_policy
            .select(interface_name, interface, local, &addresses)
        {
            Some(Selection::Primary) => {}
            Some(Selection::Secondary(secondary)) => {
                local = secondary.address;
                addresses.insert(0, secondary);
            }
            None => return Ok(None),
        }
        let packet = dispatch.packet;
        // Complete masks from real interface addresses before putting ALL
        // contexts in configuration order on the leasequery chain.
        let ingress_contexts = select_contexts_with_shared(
            &self.config.ranges,
            &mut self.states,
            &addresses,
            interface,
            &self.config.network.shared,
        );
        let relay = packet.giaddr();
        let selector = packet
            .option(118, 4)
            .and_then(|value| <[u8; 4]>::try_from(value.get(..4)?).ok())
            .map(Ipv4Addr::from)
            .filter(|address| !address.is_unspecified())
            .or_else(|| (!relay.is_unspecified() && relay != Ipv4Addr::BROADCAST).then_some(relay))
            .unwrap_or(packet.effective_ciaddr());
        if !selector.is_unspecified() {
            for (range, state) in self.config.ranges.iter().zip(&mut self.states) {
                let mut mask = state.netmask;
                if range.netmask.is_none() && mask.is_unspecified() {
                    let first = range.start.octets()[0];
                    let last = range.end.octets()[0];
                    mask = if first < 128 && last < 128 {
                        Ipv4Addr::new(255, 0, 0, 0)
                    } else if (128..192).contains(&first) && (128..192).contains(&last) {
                        Ipv4Addr::new(255, 255, 0, 0)
                    } else if (192..224).contains(&first) && (192..224).contains(&last) {
                        Ipv4Addr::new(255, 255, 255, 0)
                    } else {
                        Ipv4Addr::UNSPECIFIED
                    };
                }
                let same_net = |address| {
                    u32::from(selector) & u32::from(mask) == u32::from(address) & u32::from(mask)
                };
                if !mask.is_unspecified() && same_net(range.start) && same_net(range.end) {
                    state.netmask = mask;
                    if state.local.is_unspecified() {
                        state.local = local;
                    }
                    if state.router.is_unspecified() && relay != Ipv4Addr::BROADCAST {
                        state.router = relay;
                    }
                    if range.broadcast.is_none() && state.broadcast.is_unspecified() {
                        state.broadcast = Ipv4Addr::from(u32::from(range.start) | !u32::from(mask));
                    }
                }
            }
        }
        let now = epoch_seconds();
        let removed = self.leases.prune(None, now);
        self.maintenance_report = Some(self.maintain(now, removed, false));
        self.queue_script_from_maintenance();
        if self.config.log_dhcp {
            self.network_notices
                .extend(
                    super::logging::request_details(packet)
                        .into_iter()
                        .map(|message| {
                            crate::logging::LogEvent::new(
                                crate::logging::Service::Dhcp,
                                crate::logging::Priority::Info,
                                message,
                            )
                        }),
                );
        }
        if !self.config.lease_query.allows(source) {
            if self.config.lease_query.enabled && !source.is_unspecified() {
                self.network_notices.push(crate::logging::LogEvent::new(
                    crate::logging::Service::Dhcp,
                    crate::logging::Priority::Warning,
                    format!("leasequery from {source} not permitted").into_bytes(),
                ));
            }
            return Ok(None);
        }
        let logging = DhcpLogging {
            quiet_dhcp: self.config.quiet_dhcp,
            log_options: self.config.log_dhcp,
            has_error: false,
        };
        let client_id = (!self.config.ignore_client_id)
            .then(|| packet.client_id())
            .flatten();
        let emac = super::request::extended_hardware_id(
            packet.hardware_type(),
            packet.hardware_address(),
            client_id,
        );
        let mac =
            super::logging::hardware(packet.hardware_type(), packet.hardware_address(), client_id);
        let source_text = source.to_string();
        if let Some(message) = super::logging::packet(
            logging,
            super::logging::PacketLog {
                kind: b"DHCPLEASEQUERY",
                address: (!packet.effective_ciaddr().is_unspecified())
                    .then_some(packet.effective_ciaddr()),
                mac: (!emac.is_empty()).then_some(mac.as_slice()),
                interface: interface_name,
                extra: Some(b"from "),
                error: Some(source_text.as_bytes()),
                xid: packet.transaction_id(),
            },
        ) {
            self.network_notices.push(crate::logging::LogEvent::new(
                crate::logging::Service::Dhcp,
                crate::logging::Priority::Info,
                message,
            ));
        }
        let ranges: Vec<_> = self
            .config
            .ranges
            .iter()
            .zip(&self.states)
            .map(|(range, state)| super::allocation::AddressRange {
                start: range.start,
                end: range.end,
                netmask: state.netmask,
                router: state.router,
                local: state.local,
                lease_time: range.lease_time,
                kind: range.kind,
                filter: range.filter.tags().to_vec(),
                epoch: state.epoch,
            })
            .collect();
        let identity = ClientIdentity {
            hardware_type: u32::from(packet.hardware_type()),
            hardware_address: packet.hardware_address().to_vec(),
            client_id: (!self.config.ignore_client_id)
                .then(|| packet.client_id().map(<[u8]>::to_vec))
                .flatten(),
        };
        let by_client = self.leases.find_client(&identity);
        let lease = if packet.effective_ciaddr().is_unspecified() {
            by_client
        } else {
            self.leases.get(packet.effective_ciaddr())
        };
        let mut tags: Vec<&[u8]> = interface_name.into_iter().collect();
        for rule in &self.config.macs {
            if rule.matches(identity.hardware_type, &identity.hardware_address) {
                tags.push(&rule.set_tag);
            }
        }
        for rule in &self.config.matches {
            if rule.matches_packet(packet) {
                tags.push(&rule.set_tag);
            }
        }
        for rule in &self.config.classes {
            let data = match rule.kind {
                ClassKind::Vendor => packet.option(60, 1),
                ClassKind::User => packet.option(77, 1),
                _ => None, // The query's relay-id must not describe the leased client.
            };
            if data.is_some_and(|data| rule.matches(data)) {
                tags.push(&rule.set_tag);
            }
        }

        let mut lookup_tags = tags.clone();
        TagIf::apply_all(&self.config.tag_if, &mut lookup_tags);
        let clid = identity
            .client_id
            .as_deref()
            .or_else(|| by_client.and_then(|lease| lease.identity.client_id.as_deref()));
        let ingress_host = self.config.find_host_tagged(
            clid,
            identity.hardware_type,
            Some(&identity.hardware_address),
            None,
            &lookup_tags,
            |address| {
                ingress_contexts
                    .iter()
                    .any(|context| context.range.same_subnet(address))
            },
        );
        if ingress_host.is_some() {
            tags.push(b"known");
        } else if self
            .config
            .find_host_tagged(
                clid,
                identity.hardware_type,
                Some(&identity.hardware_address),
                None,
                &lookup_tags,
                |_| true,
            )
            .is_some()
        {
            tags.push(b"known-othernet");
        }
        if let Some(name) = packet.client_hostname_full() {
            for rule in &self.config.name_matches {
                if rule.matches(&name) {
                    tags.push(&rule.set_tag);
                }
            }
        }
        if let Some(agent_id) = lease.and_then(|lease| lease.agent_id.as_deref()) {
            for rule in &self.config.classes {
                let code = match rule.kind {
                    ClassKind::Circuit => 1,
                    ClassKind::Remote => 2,
                    ClassKind::Subscriber => 6,
                    _ => continue,
                };
                if super::packet::find_option(agent_id, code, 1)
                    .is_some_and(|option| rule.matches(option.value))
                {
                    tags.push(&rule.set_tag);
                }
            }
        }
        lookup_tags = tags.clone();
        TagIf::apply_all(&self.config.tag_if, &mut lookup_tags);
        let context =
            lease.and_then(|lease| super::allocation::narrow(&ranges, lease.address, &lookup_tags));
        let host = context
            .and_then(|context| {
                let lease = lease?;
                self.config.find_host_tagged(
                    lease.identity.client_id.as_deref(),
                    lease.identity.hardware_type,
                    Some(&lease.identity.hardware_address),
                    lease.hostname.as_deref(),
                    &lookup_tags,
                    |address| ranges[context].same_subnet(address),
                )
            })
            .map(|index| &self.config.hosts[index]);
        // Context selection precedes host-set tags, exactly as RFC4388's C path.
        let Some(reply) = lease_query::query(
            &self.leases,
            &ranges,
            LeaseQueryInput {
                packet,
                source,
                enabled: self.config.lease_query.enabled,
                allowed_sources: &self.config.lease_query.allowed_sources,
                tags: &lookup_tags,
                now,
                ignore_client_id: self.config.ignore_client_id,
                configured_lease_time: host.and_then(|host| host.lease_time),
            },
        ) else {
            return Ok(None);
        };
        if let Some(host) = host {
            tags.extend(host.set_tags.iter().map(Vec::as_slice));
        }
        let context_tags: Vec<_> = context
            .and_then(|index| self.config.ranges[index].set_tag.as_deref())
            .into_iter()
            .collect();
        let selection = option_filter(
            &self.config.options,
            &tags,
            &context_tags,
            &self.config.tag_if,
            0,
        );
        if self.config.log_dhcp && reply.status == lease_query::Status::Active {
            let mut tags = tags.clone();
            tags.extend(context_tags.iter().copied());
            TagIf::apply_all(&self.config.tag_if, &mut tags);
            tags.reverse();
            if let Some(message) = super::logging::tags(packet.transaction_id(), &tags) {
                self.network_notices.push(crate::logging::LogEvent::new(
                    crate::logging::Service::Dhcp,
                    crate::logging::Priority::Info,
                    message,
                ));
            }
        }
        let reply_mac = if reply.status == lease_query::Status::Active {
            lease.map(|lease| {
                super::logging::hardware(
                    lease.identity.hardware_type as u8,
                    &lease.identity.hardware_address,
                    lease.identity.client_id.as_deref(),
                )
            })
        } else {
            (!emac.is_empty()).then_some(mac)
        };
        if let Some(message) = super::logging::packet(
            logging,
            super::logging::PacketLog {
                kind: match reply.status {
                    lease_query::Status::Active => b"DHCPLEASEACTIVE",
                    lease_query::Status::Unassigned => b"DHCPLEASEUNASSIGNED",
                    lease_query::Status::Unknown => b"DHCPLEASEUNKNOWN",
                },
                address: if reply.status == lease_query::Status::Active {
                    Some(reply.client_address)
                } else {
                    (!packet.effective_ciaddr().is_unspecified())
                        .then_some(packet.effective_ciaddr())
                },
                mac: reply_mac.as_deref(),
                interface: interface_name,
                extra: (reply.status == lease_query::Status::Active)
                    .then(|| lease.and_then(|lease| lease.hostname.as_deref()))
                    .flatten(),
                error: None,
                xid: packet.transaction_id(),
            },
        ) {
            self.network_notices.push(crate::logging::LogEvent::new(
                crate::logging::Service::Dhcp,
                crate::logging::Priority::Info,
                message,
            ));
        }
        let mut option_warnings = Vec::new();
        let mut present = [false; 256];
        let mut values = Vec::new();
        if let Some(context) = reply.context {
            let configured = super::runtime::encode_filtered_options_with_pxe_notices(
                packet,
                Reply::Inform {
                    context: Some(context),
                    server: ranges[context].local,
                    lease_time: None,
                },
                Some(ranges[context].local),
                &self.config.options,
                &selection,
                &mut present,
                true,
                &mut [None, None],
                &mut None,
                &PxeEncoding::ordinary(None, &self.config.pxe.vendors, &[]),
                &mut option_warnings,
            );
            for (code, address) in [
                (1, Some(ranges[context].netmask)),
                (
                    28,
                    (!self.states[context].broadcast.is_unspecified())
                        .then_some(self.states[context].broadcast),
                ),
                (
                    3,
                    (!ranges[context].router.is_unspecified()).then_some(ranges[context].router),
                ),
                (6, (self.dns_port == 53).then_some(ranges[context].local)),
            ] {
                if packet.requests(code) && !present[usize::from(code)] {
                    if let Some(address) = address {
                        values.push((code, address.octets().to_vec()));
                    }
                }
            }
            if let Some(lease) = lease {
                for (code, value) in [
                    (15, self.domains.for_address(lease.address)),
                    (12, lease.hostname.as_deref()),
                ] {
                    if packet.requests(code) && !present[usize::from(code)] {
                        if let Some(value) = value {
                            values.push((code, value.to_vec()));
                        }
                    }
                }
                values.extend(configured);
                let forced_vendor = self.config.options.iter().any(|option| {
                    let crate::config::dhcp::Encapsulation::Vendor(needle) = &option.encapsulation
                    else {
                        return false;
                    };
                    option.force
                        && option.tags.matches_with(&selection.tags, true)
                        && packet.option(60, 1).is_some_and(|vendor| {
                            needle.is_empty()
                                || vendor.windows(needle.len()).any(|part| part == needle)
                        })
                });
                if !values.iter().any(|(code, _)| *code == 60)
                    && (packet.requests(43) || packet.requests(60) || forced_vendor)
                {
                    if let Some(vendor) = lease
                        .vendor_class
                        .as_deref()
                        .or_else(|| packet.option(60, 1))
                    {
                        values.push((60, vendor.to_vec()));
                    }
                }
            }
        }
        self.message_counters.lease_query = self.message_counters.lease_query.wrapping_add(1);
        let counter = match reply.status {
            lease_query::Status::Active => &mut self.message_counters.lease_active,
            lease_query::Status::Unassigned => &mut self.message_counters.lease_unassigned,
            lease_query::Status::Unknown => &mut self.message_counters.lease_unknown,
        };
        *counter = counter.wrapping_add(1);
        let options: Vec<_> = values
            .iter()
            .map(|(code, value)| super::packet::VendorOption { code: *code, value })
            .collect();
        let encoded = lease_query::encode_reply_with_policy(
            packet,
            &reply,
            &options,
            !self.config.no_override,
            output,
        )
        .map_err(|error| RuntimeError::State(format!("leasequery reply: {error:?}")))?;
        self.network_notices.extend(
            option_warnings
                .iter()
                .copied()
                .filter(|warning| matches!(warning, super::logging::OptionWarning::Duplicate(_)))
                .map(|warning| {
                    crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Warning,
                        super::logging::option_warning(warning),
                    )
                }),
        );
        if self.config.log_dhcp {
            let details = if reply.status == lease_query::Status::Active {
                packet.option(55, 0).map_or_else(Vec::new, |codes| {
                    super::logging::requested_options(packet.transaction_id(), codes)
                })
            } else {
                Vec::new()
            };
            self.network_notices
                .extend(details.into_iter().map(|message| {
                    crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Info,
                        message,
                    )
                }));
            self.network_notices.extend(
                option_warnings
                    .iter()
                    .copied()
                    .filter(|warning| {
                        !matches!(warning, super::logging::OptionWarning::Duplicate(_))
                    })
                    .map(|warning| {
                        crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Warning,
                            super::logging::option_warning(warning),
                        )
                    }),
            );
            self.network_notices
                .extend(encoded.omitted_options.iter().map(|code| {
                    crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Warning,
                        super::logging::omission(*code),
                    )
                }));
            let details = super::logging::reply_details(&output[..encoded.len]);
            self.network_notices
                .extend(details.into_iter().map(|message| {
                    crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Info,
                        message,
                    )
                }));
        }
        if !self.config.log_dhcp {
            self.network_notices.extend(
                option_warnings
                    .iter()
                    .copied()
                    .filter(|warning| {
                        !matches!(warning, super::logging::OptionWarning::Duplicate(_))
                    })
                    .map(|warning| {
                        crate::logging::LogEvent::new(
                            crate::logging::Service::Dhcp,
                            crate::logging::Priority::Warning,
                            super::logging::option_warning(warning),
                        )
                    }),
            );

            self.network_notices
                .extend(encoded.omitted_options.iter().map(|code| {
                    crate::logging::LogEvent::new(
                        crate::logging::Service::Dhcp,
                        crate::logging::Priority::Warning,
                        super::logging::omission(*code),
                    )
                }));
        }
        Ok(Some(encoded.len))
    }

    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
        self.resolve_events(dispatch, None, None, None)
    }

    fn resolve_on_interface(
        &mut self,
        dispatch: &Dispatch<'_>,
        interface: Option<&[u8]>,
    ) -> Result<Outcome, RuntimeError> {
        self.resolve_events(dispatch, interface, None, None)
    }

    fn force_broadcast(&self, _: &Outcome) -> bool {
        self.force_broadcast
    }

    fn boot_config(&self) -> Option<&crate::config::dhcp::BootConfig> {
        self.selected_boot.as_ref()
    }

    fn configured_options(&self) -> &[crate::config::dhcp::DhcpOption] {
        &self.config.options
    }

    fn selected_options(&self, outcome: &Outcome) -> FilteredOptions<'_> {
        let context = match outcome.reply {
            Reply::Offer { context, .. }
            | Reply::Ack { context, .. }
            | Reply::Bootp { context, .. } => Some(context),
            Reply::Inform { context, .. } => context,
            _ => None,
        };
        pxe_selection(
            &self.config,
            &self.request_tags,
            &self.selected,
            context,
            self.pxe_encoding().option_mode,
        )
    }

    fn client_update(&self) -> bool {
        self.config.client_update
    }

    fn boot_next_server(&mut self) -> io::Result<Option<Ipv4Addr>> {
        let Some(boot) = self.selected_boot.as_ref() else {
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
    fn record_reply(
        &mut self,
        request: super::packet::Packet<'_>,
        reply: Reply,
        output: &[u8],
        omitted_options: &[u8],
        option_warnings: &[super::logging::OptionWarning],
    ) {
        self.provider
            .record_reply(request, reply, output, omitted_options, option_warnings);
    }

    fn direct_pxe_reply(
        &mut self,
        request: super::packet::Packet<'_>,
        output: &mut [u8],
    ) -> Result<Option<super::reply::ReplyEncoding>, RuntimeError> {
        self.provider.direct_pxe_reply(request, output)
    }

    fn pxe_encoding(&self) -> PxeEncoding<'_> {
        self.provider.pxe_encoding()
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn lease_query_reply(
        &mut self,
        dispatch: &Dispatch<'_>,
        interface_name: Option<&[u8]>,
        source: Ipv4Addr,
        output: &mut [u8],
    ) -> Result<Option<usize>, RuntimeError> {
        self.provider
            .lease_query_reply(dispatch, interface_name, source, output)
    }

    fn resolve(&mut self, dispatch: &Dispatch<'_>) -> Result<Outcome, RuntimeError> {
        self.provider
            .resolve_events(dispatch, None, Some(self.sink), self.wait.as_deref_mut())
    }

    fn resolve_on_interface(
        &mut self,
        dispatch: &Dispatch<'_>,
        interface: Option<&[u8]>,
    ) -> Result<Outcome, RuntimeError> {
        self.provider.resolve_events(
            dispatch,
            interface,
            Some(self.sink),
            self.wait.as_deref_mut(),
        )
    }

    fn network_options(&self, outcome: &Outcome) -> Option<NetworkOptions> {
        self.provider.network_options(outcome)
    }

    fn force_broadcast(&self, outcome: &Outcome) -> bool {
        self.provider.force_broadcast(outcome)
    }

    fn configured_options(&self) -> &[crate::config::dhcp::DhcpOption] {
        self.provider.configured_options()
    }

    fn boot_config(&self) -> Option<&crate::config::dhcp::BootConfig> {
        self.provider.boot_config()
    }

    fn selected_options(&self, outcome: &Outcome) -> FilteredOptions<'_> {
        self.provider.selected_options(outcome)
    }
    fn client_update(&self) -> bool {
        self.provider.client_update()
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
    let mac = super::request::extended_hardware_id(
        packet.hardware_type(),
        packet.hardware_address(),
        client_id,
    );
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

fn relay_suboption(packet: super::packet::Packet<'_>, wanted: u8, min_len: usize) -> Option<&[u8]> {
    if matches!(packet.message_type(), 0 | 10) {
        return None;
    }
    super::packet::find_option(packet.option(82, 1)?, wanted, min_len).map(|option| option.value)
}

fn generated_hostname(
    packet: super::packet::Packet<'_>,
    client_id: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let bytes = super::request::extended_hardware_id(
        packet.hardware_type(),
        packet.hardware_address(),
        client_id,
    );
    if bytes.is_empty() {
        return None;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = Vec::with_capacity(bytes.len().min(80) * 3);
    for (index, byte) in bytes.iter().take(80).enumerate() {
        result.push(HEX[(byte >> 4) as usize]);
        result.push(HEX[(byte & 15) as usize]);
        if index + 1 != bytes.len() {
            result.push(b'-');
        }
    }
    Some(result)
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    #[test]
    fn dispatch_maintenance_uses_the_supplied_clock_and_keeps_immediate_work() {
        let mut provider = LocalProvider::new(DhcpConfig {
            no_ping: true, lease_read_only: true, ..Default::default()
        }, Vec::new(), 53, || false).unwrap();
        let now = Instant::now();
        assert!(provider.maintenance_due(now), "startup is due even if the caller clock is earlier");
        provider.initialize(100);
        let due = now + Duration::from_secs(60);
        provider.alarm_deadline = Some(due);
        provider.pending_alarms = 0;
        assert!(!provider.maintenance_due(now));
        assert!(provider.maintenance_due(due));
        provider.request_alarms(1);
        assert!(provider.maintenance_due(now), "external alarm is not a future deadline");
        assert_eq!(provider.pending_alarms, 1, "eligibility must not consume the alarm");
    }

    #[test]
    fn failed_forced_dns_publication_gets_an_idle_retry_without_delaying_an_alarm() {
        use std::cell::Cell;
        use std::rc::Rc;
        struct RetryPublisher {
            fail: Rc<Cell<bool>>,
            calls: Rc<Cell<usize>>,
        }
        impl DnsPublisher for RetryPublisher {
            fn replace(&mut self, _: &[persistence::DnsLeaseRecord<'_>]) -> io::Result<()> {
                self.calls.set(self.calls.get() + 1);
                if self.fail.get() { Err(io::Error::other("temporary DNS publication failure")) }
                else { Ok(()) }
            }
        }
        for earlier_alarm in [false, true] {
            let mut provider = LocalProvider::new(DhcpConfig {
                no_ping: true, lease_read_only: true, ..Default::default()
            }, Vec::new(), 53, || false).unwrap();
            let fail = Rc::new(Cell::new(false));
            let calls = Rc::new(Cell::new(0));
            provider.set_dns_publisher(Box::new(RetryPublisher {
                fail: Rc::clone(&fail), calls: Rc::clone(&calls),
            }));
            assert_eq!(provider.initialize(100).dns.status, persistence::DnsStatus::Published);
            assert!(!provider.leases.changes().dns);
            let earlier = Instant::now() + Duration::from_secs(5);
            provider.alarm_deadline = earlier_alarm.then_some(earlier);
            fail.set(true);
            let before = Instant::now();
            assert_eq!(provider.hosts_changed(100).dns.status, persistence::DnsStatus::Failed);
            let deadline = provider.alarm_deadline.unwrap();
            if earlier_alarm {
                assert_eq!(deadline, earlier);
            } else {
                assert!(deadline >= before + Duration::from_secs(60));
                assert!(deadline <= Instant::now() + Duration::from_secs(60));
            }
            assert!(provider.leases.changes().dns);
            // Advance only the existing alarm boundary, without a packet or
            // another forced publication. A successful retry consumes it.
            fail.set(false);
            provider.alarm_deadline = Some(Instant::now());
            assert_eq!(provider.tick(160).unwrap().dns.status, persistence::DnsStatus::Published);
            assert_eq!(calls.get(), 3);
            assert!(!provider.leases.changes().dns);
            assert!(provider.alarm_deadline.is_none());
            assert!(provider.tick(160).is_none());
        }
    }

    struct RunnableFilesFixture(std::path::PathBuf);

    impl RunnableFilesFixture {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!("dhcp-runnable-{label}-{}-{}",
                std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn fifo(&self) -> std::path::PathBuf {
            let path = self.0.join("input");
            assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
            path
        }

        fn provider(&self, option_file: Option<&Path>) -> LocalProvider {
            LocalProvider::new(DhcpConfig {
                no_ping: true, lease_read_only: true,
                option_files: option_file.map(|path| vec![path.as_os_str().as_encoded_bytes().to_vec()]).unwrap_or_default(),
                ..Default::default()
            }, Vec::new(), 0, || false).unwrap()
        }
    }

    impl Drop for RunnableFilesFixture {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn queued_reload_waits_behind_active_fifo_then_restarts_after_publication() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let fixture = RunnableFilesFixture::new("bank");
        let fifo = fixture.fifo();
        let mut provider = fixture.provider(Some(&fifo));
        provider.start_file_owner().unwrap();
        for _ in 0..16 {
            if !provider.files_runnable() { break; }
            assert!(provider.step_files_with_watch_readiness(epoch_seconds(), false).is_none());
        }
        assert!(provider.file_work_pending());
        assert!(!provider.files_runnable());
        provider.reload_data_files(epoch_seconds());
        for _ in 0..3 {
            assert!(!provider.files_runnable(), "queued reload cannot run ahead of its FIFO");
            assert!(provider.step_files_with_watch_readiness(epoch_seconds(), false).is_none());
        }
        let mut writer = std::fs::OpenOptions::new().write(true).custom_flags(0o4000).open(&fifo).unwrap();
        writer.write_all(b"option:domain-name,first\n").unwrap();
        provider.step_files_with_watch_readiness(epoch_seconds(), false);
        assert!(!provider.files_runnable(), "a held writer still requires EOF before bank publication");
        drop(writer);
        let first = (0..16).find_map(|_| provider.step_files_with_watch_readiness(epoch_seconds(), false));
        assert!(first.is_some());
        assert!(provider.files_runnable(), "the saved reload now has a real next turn");
        for _ in 0..16 {
            if !provider.files_runnable() { break; }
            provider.step_files_with_watch_readiness(epoch_seconds(), false);
        }
        assert!(!provider.files_runnable());
        let mut writer = std::fs::OpenOptions::new().write(true).custom_flags(0o4000).open(&fifo).unwrap();
        writer.write_all(b"option:domain-name,second\n").unwrap();
        drop(writer);
        assert!((0..16).find_map(|_| provider.step_files_with_watch_readiness(epoch_seconds(), false)).is_some());
        assert!(!provider.file_work_pending());
        assert!(!provider.files_runnable());
        assert_eq!(provider.config.options.len(), 1);
        assert_eq!(provider.config.options[0].value,
            crate::config::dhcp::OptionValue::String(b"second".to_vec()));
    }

    #[test]
    fn active_ethers_fifo_has_priority_over_queued_bank_reload() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let fixture = RunnableFilesFixture::new("ethers");
        let fifo = fixture.fifo();
        let mut provider = fixture.provider(None);
        provider.start_file_owner().unwrap();
        assert!((0..16).find_map(|_| provider.step_files_with_watch_readiness(epoch_seconds(), false)).is_some());
        provider.ethers_read = Some(provider.ethers.begin_read(&fifo).unwrap());
        provider.reload_data_files(epoch_seconds());
        assert!(!provider.files_runnable());
        assert!(provider.step_files_with_watch_readiness(epoch_seconds(), false).is_none());
        let mut writer = std::fs::OpenOptions::new().write(true).custom_flags(0o4000).open(&fifo).unwrap();
        writer.write_all(b"02:00:00:00:00:01 192.0.2.10\n").unwrap();
        drop(writer);
        assert!((0..4).find_map(|_| provider.step_files_with_watch_readiness(epoch_seconds(), false)).is_some());
        assert!(provider.files_runnable(), "ethers published before starting the queued bank");
        assert_eq!(provider.config.hosts[0].address, Some("192.0.2.10".parse().unwrap()));
        assert!((0..16).find_map(|_| provider.step_files_with_watch_readiness(epoch_seconds(), false)).is_some());
        assert!(!provider.files_runnable());
        assert_eq!(provider.config.hosts[0].address, Some("192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn fresh_packet_interface_dump_is_separate_from_file_runnable() {
        let fixture = RunnableFilesFixture::new("interfaces");
        let mut provider = fixture.provider(None);
        provider.start_interface_owner().unwrap();
        provider.interface_owner.as_mut().unwrap().begin().unwrap();
        assert!(provider.packet_interfaces_pending());
        assert!(!provider.files_runnable());
        let mut fds = Vec::new();
        provider.append_file_fds(&mut fds);
        assert!(fds.is_empty());
        provider.append_packet_interface_fds(&mut fds);
        assert_eq!(fds.len(), 1);
        assert!((0..64).any(|_| {
            fds.clear();
            provider.append_packet_interface_fds(&mut fds);
            dnsmasq_platform::poll::poll_fds(&mut fds, 100).unwrap();
            provider.prepare_packet_interfaces().unwrap()
        }));
        assert!(!provider.packet_interfaces_pending());
        assert!(!provider.packet_interfaces_runnable());
        assert!(!provider.packet_addresses().unwrap().is_empty());
        provider.finish_packet_interfaces();
        assert!(provider.packet_addresses().is_err(), "one packet cannot lend its snapshot to the next");
        let ready = provider.prepare_packet_interfaces().unwrap();
        assert_eq!(provider.packet_interfaces_pending(), !ready);
        assert_eq!(provider.packet_addresses().is_ok(), ready);
    }

    #[test]
    fn due_lease_alarm_prunes_without_packet_and_waits_behind_file_work() {
        let fixture = RunnableFilesFixture::new("alarm");
        let mut provider = fixture.provider(None);
        let now = epoch_seconds();
        provider.initialize(now);
        let address = "192.0.2.10".parse().unwrap();
        provider.leases.allocate(address, ClientIdentity {
            hardware_type: 1, hardware_address: vec![2, 0, 0, 0, 0, 1], client_id: None,
        }).unwrap();
        provider.leases.set_expires(address, 1, now).unwrap();
        provider.maintain(now, Vec::new(), false);
        assert!(provider.next_maintenance().is_some());
        provider.alarm_deadline = Some(Instant::now());
        provider.start_file_owner().unwrap();
        assert!(provider.tick(now + 1).is_none(), "expiry cannot pass an unpublished file generation");
        assert!(provider.leases.get(address).is_some());
        assert!((0..16).find_map(|_| provider.step_files_with_watch_readiness(now + 1, false)).is_some());
        let report = provider.tick(now + 1).unwrap();
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.removed[0].address, address);
        assert_eq!(provider.lease_counters().pruned4, 1);
        assert!(provider.leases.get(address).is_none());
        while provider.tick(now + 1).is_some() {}
        assert!(provider.next_maintenance().is_none());
    }

    #[test]
    fn generated_name_uses_extended_hardware_and_c_truncation_separator() {
        let mut bytes = vec![0; 240];
        bytes[..3].copy_from_slice(&[1, 24, 0]);
        bytes[236..240].copy_from_slice(&super::super::packet::COOKIE);
        let packet = super::super::packet::Packet::parse(&bytes).unwrap();
        assert_eq!(generated_hostname(packet, Some(&[27, 1, 2])), None);
        assert_eq!(
            generated_hostname(packet, Some(&[27, 1, 2, 3])),
            Some(b"01-02-03".to_vec())
        );
        assert_eq!(
            generated_hostname(packet, Some(&[1, 1, 2, 3])),
            Some(b"01-01-02-03".to_vec())
        );
        let maximum = generated_hostname(packet, Some(&[1; 81])).unwrap();
        assert_eq!(maximum.len(), 240);
        assert_eq!(maximum.last(), Some(&b'-'));
    }

    #[test]
    fn ethers_merges_after_host_files_at_startup_and_reload() {
        let folder = std::env::var_os("DNSMASQ_REVIEW_EVIDENCE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("hostfile-ethers-unit-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        let bank = folder.join("dhcp-hosts");
        let ethers = folder.join("ethers");
        std::fs::write(&bank, b"02:00:00:00:00:01,192.0.2.10,fixed,1200s\n").unwrap();
        std::fs::write(&ethers, b"02:00:00:00:00:02 192.0.2.10\n").unwrap();
        let config = DhcpConfig {
            no_ping: true,
            lease_read_only: true,
            read_ethers: true,
            host_files: vec![bank.as_os_str().as_encoded_bytes().to_vec()],
            ..DhcpConfig::default()
        };
        let mut provider = LocalProvider::new(config, Vec::new(), 0, || false).unwrap();
        for _ in 0..2 {
            assert!(provider.reread_host_files_at(&ethers).is_empty());
            assert_eq!(provider.config.hosts.len(), 1);
            let host = &provider.config.hosts[0];
            assert_eq!(host.hostname.as_deref(), Some(b"fixed".as_slice()));
            assert_eq!(host.lease_time, Some(1200));
            assert_eq!(host.hardware[0].address, [2, 0, 0, 0, 0, 2]);
        }
        std::fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn host_file_replacement_preserves_only_surviving_ethers_and_main_declines() {
        let folder = std::env::var_os("DNSMASQ_REVIEW_EVIDENCE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "hostfile-ethers-retention-unit-{}",
                std::process::id()
            ));
        std::fs::create_dir_all(&folder).unwrap();
        let bank = folder.join("dhcp-hosts");
        let ethers = folder.join("ethers");
        std::fs::write(&bank, b"02:00:00:00:00:01,192.0.2.10,file,1200s\n").unwrap();
        std::fs::write(
            &ethers,
            b"02:00:00:00:00:02 192.0.2.10\n02:00:00:00:00:03 192.0.2.11\n",
        )
        .unwrap();
        let mut config = DhcpConfig {
            no_ping: true,
            lease_read_only: true,
            read_ethers: true,
            host_files: vec![bank.as_os_str().as_encoded_bytes().to_vec()],
            ..DhcpConfig::default()
        };
        config
            .apply(
                &crate::config::lex_line(b"dhcp-host=02:00:00:00:00:04,192.0.2.20,main")
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut provider = LocalProvider::new(config, Vec::new(), 0, || false).unwrap();
        provider.hosts[0].declined_at = Some(50);
        assert!(provider.reread_host_files_at(&ethers).is_empty());
        assert_eq!(
            provider
                .hosts
                .iter()
                .map(|host| host.address.unwrap().octets()[3])
                .collect::<Vec<_>>(),
            [11, 10, 20]
        );
        provider.hosts[0].declined_at = Some(60);
        provider.hosts[1].declined_at = Some(70);

        std::fs::remove_file(&ethers).unwrap();
        std::fs::write(&bank, b"02:00:00:00:00:05,192.0.2.12,replacement\n").unwrap();
        assert_eq!(provider.reread_host_files_at(&ethers).len(), 1);
        assert_eq!(
            provider
                .hosts
                .iter()
                .map(|host| host.address.unwrap().octets()[3])
                .collect::<Vec<_>>(),
            [12, 11, 20]
        );
        assert_eq!(
            provider
                .hosts
                .iter()
                .map(|host| host.declined_at)
                .collect::<Vec<_>>(),
            [None, Some(60), Some(50)]
        );

        std::fs::write(&ethers, b"").unwrap();
        assert!(provider.reread_host_files_at(&ethers).is_empty());
        assert_eq!(
            provider
                .hosts
                .iter()
                .map(|host| host.address.unwrap().octets()[3])
                .collect::<Vec<_>>(),
            [12, 20]
        );
        assert_eq!(
            provider
                .hosts
                .iter()
                .map(|host| host.declined_at)
                .collect::<Vec<_>>(),
            [None, Some(50)]
        );
        std::fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn ethers_matches_inferred_addresses_before_rebuilding_them() {
        let folder = std::env::var_os("DNSMASQ_REVIEW_EVIDENCE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "hostfile-ethers-inferred-unit-{}",
                std::process::id()
            ));
        std::fs::create_dir_all(&folder).unwrap();
        let bank = folder.join("dhcp-hosts");
        let ethers = folder.join("ethers");
        std::fs::write(&bank, b"").unwrap();
        std::fs::write(&ethers, b"").unwrap();
        let mut config = DhcpConfig {
            no_ping: true,
            lease_read_only: true,
            read_ethers: true,
            host_files: vec![bank.as_os_str().as_encoded_bytes().to_vec()],
            ..DhcpConfig::default()
        };
        config
            .apply(
                &crate::config::lex_line(b"dhcp-host=02:00:00:00:00:01,derived")
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut provider = LocalProvider::new(config, Vec::new(), 53, || false).unwrap();
        provider.set_config_host_lookup(|_| Ok(Some(Ipv4Addr::new(192, 0, 2, 10))));
        assert!(provider.reread_host_files_at(&ethers).is_empty());
        assert!(provider.update_configured_addresses().is_none());

        std::fs::write(&bank, b"02:00:00:00:00:03,192.0.2.10,file\n").unwrap();
        std::fs::write(&ethers, b"02:00:00:00:00:02 192.0.2.10\n").unwrap();
        let errors = provider.reread_host_files_at(&ethers);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, bank);
        assert_eq!(provider.config.hosts.len(), 1);
        assert_eq!(
            provider.config.hosts[0].hostname.as_deref(),
            Some(b"derived".as_slice())
        );
        assert_eq!(
            provider.config.hosts[0].hardware[0].address,
            [2, 0, 0, 0, 0, 2]
        );
        assert_eq!(provider.config.hosts[0].address, None);
        provider.set_config_host_lookup(|_| Ok(Some(Ipv4Addr::new(192, 0, 2, 11))));
        assert!(provider.update_configured_addresses().is_none());
        assert_eq!(
            provider.config.hosts[0].address,
            Some(Ipv4Addr::new(192, 0, 2, 11))
        );
        std::fs::remove_dir_all(folder).unwrap();
    }

    #[test]
    fn ethers_reload_replaces_created_rules_and_preserves_inline_decline() {
        let mut config = DhcpConfig {
            no_ping: true,
            lease_read_only: true,
            read_ethers: true,
            ..DhcpConfig::default()
        };
        config
            .apply(
                &crate::config::lex_line(b"dhcp-host=02:00:00:00:00:01,192.0.2.10,configured")
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        let mut provider = LocalProvider::new(config, Vec::new(), 0, || false).unwrap();
        provider.hosts[0].declined_at = Some(50);
        let path = std::env::temp_dir().join(format!("dnsmasq-ethers-{}", std::process::id()));
        std::fs::write(
            &path,
            b"02:00:00:00:00:02 192.0.2.10\n02:00:00:00:00:03 192.0.2.11\n",
        )
        .unwrap();
        assert!(provider.reread_host_files_at(&path).is_empty());
        assert_eq!(provider.hosts.len(), 2);
        assert_eq!(provider.hosts[1].declined_at, Some(50));
        assert_eq!(
            provider.hosts[1].hardware_addresses[0].hardware_address[5],
            2
        );
        provider.hosts[0].declined_at = Some(60);
        std::fs::write(&path, b"02:00:00:00:00:03 192.0.2.12\n").unwrap();
        assert!(provider.reread_host_files_at(&path).is_empty());
        assert_eq!(
            provider.hosts[0].address,
            Some(Ipv4Addr::new(192, 0, 2, 12))
        );
        assert_eq!(provider.hosts[0].declined_at, None);
        assert_eq!(provider.hosts[1].declined_at, Some(50));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(provider.reread_host_files_at(&path).len(), 1);
        assert_eq!(provider.hosts.len(), 2);
        assert_eq!(
            provider.hosts[0].address,
            Some(Ipv4Addr::new(192, 0, 2, 12))
        );
    }

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
    fn excluded_interface_patterns_follow_c_nonempty_wildcard() {
        assert!(interface_matches(b"wan", b"wan"));
        assert!(!interface_matches(b"wan", b"wan6"));
        assert!(interface_matches(b"wan*", b"wan6"));
        assert!(!interface_matches(b"wan*", b"wan"));
        assert!(!interface_matches(b"WAN", b"wan"));
        assert!(interface_matches(b"*", b"br-lan"));
    }

    #[test]
    fn startup_class_uses_operation_and_typed_capacity_not_errno_text() {
        let denied = || io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(StartupError::LeaseFile(denied()).exit_code(), 3);
        assert_eq!(StartupError::Socket(denied()).exit_code(), 2);
        assert_eq!(StartupError::Entropy(denied()).exit_code(), 5);
        let file = b"0 02:00:00:00:00:01 192.0.2.10 named *\n";
        let capacity = super::super::lease_file::parse_reader(&file[..], 0).unwrap_err();
        let capacity = StartupError::LeaseFile(capacity);
        assert_eq!(capacity.exit_code(), 5);
        assert!(capacity.is_lease_capacity());
        assert_eq!(capacity.to_string(), "too many stored leases");
        let similar_text = StartupError::LeaseFile(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many stored leases",
        ));
        assert!(!similar_text.is_lease_capacity());
        assert_eq!(
            similar_text.to_string(),
            "cannot open or read lease file: too many stored leases"
        );
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
