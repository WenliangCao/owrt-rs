//! Small foreground runner for the implemented DNS UDP/TCP and upstream path.
//!
//! The library remains the compatibility boundary.  This binary intentionally
//! rejects directives whose owning engine is not present yet; silently ignoring
//! a DHCP or TFTP option would make a package appear deployable while
//! dropping configured behavior.

use dnsmasq_rs::config::dhcp::DhcpConfig;
use dnsmasq_rs::config::dns::DnsConfig;
use dnsmasq_rs::config::loader::{self, Action};
use dnsmasq_rs::config::tftp::TftpConfig;
use dnsmasq_rs::config::ubus::UbusConfig;
use dnsmasq_rs::config::{Error, ScalarConfig, StaleCache};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::dhcp::daemon::LocalProvider as DhcpProvider;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::dhcp::service::{
    Listener as DhcpListener, ListenerStep, SocketListener as DhcpSocketListener,
};
use dnsmasq_rs::dns::cache::StalePolicy;
use dnsmasq_rs::dns::daemon::{ClientRequest, DaemonOptions, DnsDaemon, QueryResult};
#[cfg(target_os = "linux")]
use dnsmasq_rs::dns::files::{DnsFiles, ReloadReason};
#[cfg(target_os = "linux")]
use dnsmasq_rs::dns::filewatch::{RouteWatch, WatchError};
use dnsmasq_rs::dns::forward::SocketToken;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::dns::lease_names::{LeasePolicy, PublicationWarning};
use dnsmasq_rs::dns::service::{encode_tcp_frame, LocalDnsService, TcpFramer};
use dnsmasq_rs::dns::tcp_service::{TcpDnsService, TcpServiceProgress, TcpWait};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::helper::{Config as HelperConfig, Helper, LeaseDelivery};
use dnsmasq_rs::hosts::Hosts;
use dnsmasq_rs::interfaces::DnsInterface;
use dnsmasq_rs::listeners::{self, DnsSocket};
use dnsmasq_rs::metrics::{Metric, Metrics};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::neighbors::NeighborCache;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::tftp_listener::TftpListener;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::tftp_runtime::RealFileOpener;
use dnsmasq_rs::ubus_service::{ConnectError, DnsResult, UbusService};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::ubus_service::{DhcpEventFields, DhcpEventKind, DhcpLogging};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(not(target_os = "linux"))]
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static RELOAD_REQUESTED: AtomicUsize = AtomicUsize::new(0);
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);
static LOG_REOPEN_REQUESTED: AtomicUsize = AtomicUsize::new(0);
// SIGHUP is 1 on the supported Linux and Darwin hosts.
const SIGHUP: i32 = 1;

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs() as i64)
}

extern "C" fn request_stop(_signal: i32) {
    STOP_REQUESTED.store(true, Ordering::Release);
}

extern "C" fn request_reload(_signal: i32) {
    // Standard signals coalesce in the kernel. Each delivered handler maps
    // to a distinct C EVENT_RELOAD and must survive an active file read.
    let _ = RELOAD_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
}

extern "C" fn request_log_reopen(_signal: i32) {
    let _ = LOG_REOPEN_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
}

extern "C" fn request_interrupt(_signal: i32) {
    if DEBUG_MODE.load(Ordering::Relaxed) {
        extern "C" {
            fn _exit(status: i32) -> !;
        }
        // SAFETY: _exit is async-signal-safe. C exits debug mode with EC_MISC;
        // PID cleanup is specific to SIGTERM and must not run on this path.
        unsafe { _exit(5) }
    }
    // The nodhcpv6/no-DNSSEC C variant has no EVENT_TIME work in normal mode.
}

fn main() {
    #[cfg(target_os = "linux")]
    {
        unsafe extern "C" {
            fn umask(mask: u32) -> u32;
        }
        unsafe {
            umask(0o022);
        }
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if let Err(error) = run(&args) {
        if error.is::<SilentStartupError>() {
            std::process::exit(startup_status(error.as_ref()));
        }
        // inotify is initialized after PID/privilege setup, when C's ordinary
        // foreground logging no longer uses stderr. Debug mode still does.
        #[cfg(target_os = "linux")]
        if error.is::<WatchError>() && !DEBUG_MODE.load(Ordering::Relaxed) {
            std::process::exit(startup_status(error.as_ref()));
        }
        let blank_line = error.is::<loader::LoadError>()
            || error.is::<Error>()
            || error
                .downcast_ref::<dnsmasq_rs::dns::daemon::DaemonError>()
                .is_some_and(|error| {
                    matches!(error, dnsmasq_rs::dns::daemon::DaemonError::SourceBind(_))
                })
            || error.is::<dnsmasq_rs::startup::StartupError>();
        #[cfg(target_os = "linux")]
        let blank_line = blank_line || error.is::<dnsmasq_rs::logging::LogStartError>();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        let blank_line = blank_line
            || error.is::<dnsmasq_rs::helper::StartError>()
            || error
                .downcast_ref::<dnsmasq_rs::dhcp::daemon::StartupError>()
                .is_some_and(|error| error.is_lease_capacity());
        if blank_line {
            eprintln!();
        }
        #[cfg(target_os = "linux")]
        if let Some(raw) = error.downcast_ref::<dnsmasq_rs::logging::LogStartError>() {
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(b"dnsmasq-rs: ");
            let _ = stderr.write_all(&raw.message_bytes());
            let _ = stderr.write_all(b"\n");
            std::process::exit(startup_status(error.as_ref()));
        }
        eprintln!("dnsmasq-rs: {error}");
        std::process::exit(startup_status(error.as_ref()));
    }
}

#[derive(Debug)]
struct NetworkStartupError(io::Error);

impl std::fmt::Display for NetworkStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}
impl std::error::Error for NetworkStartupError {}

#[derive(Debug)]
struct SilentStartupError(dnsmasq_rs::startup::StartupError);

impl std::fmt::Display for SilentStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for SilentStartupError {}

fn startup_status(error: &(dyn std::error::Error + 'static)) -> i32 {
    // dnsmasq.h: EC_BADCONF=1, EC_BADNET=2. Other initialization boundaries
    // supply their own code rather than guessing from an errno alone.
    if let Some(error) = error.downcast_ref::<loader::LoadError>() {
        return error.exit_code;
    }
    if let Some(error) = error.downcast_ref::<dnsmasq_rs::startup::StartupError>() {
        return error.code;
    }
    #[cfg(target_os = "linux")]
    if let Some(error) = error.downcast_ref::<dnsmasq_rs::logging::LogStartError>() {
        return error.code;
    }
    if let Some(error) = error.downcast_ref::<SilentStartupError>() {
        return error.0.code;
    }
    if error.is::<NetworkStartupError>()
        || matches!(
            error.downcast_ref::<dnsmasq_rs::dns::daemon::DaemonError>(),
            Some(dnsmasq_rs::dns::daemon::DaemonError::SourceBind(_))
        )
    {
        return 2;
    }
    #[cfg(target_os = "linux")]
    if error.is::<WatchError>() {
        return 5;
    }
    if error.is::<ConnectError>() {
        return 5; // dnsmasq.c startup UBus registration failure: EC_MISC.
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(error) = error.downcast_ref::<dnsmasq_rs::helper::StartError>() {
        return error.code;
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(error) = error.downcast_ref::<dnsmasq_rs::dhcp::daemon::StartupError>() {
        return error.exit_code();
    }
    1
}

struct Runtime {
    scalar: ScalarConfig,
    process: dnsmasq_rs::startup::ProcessConfig,
    logging: dnsmasq_rs::config::logging::LoggingConfig,
    dns: DnsConfig,
    tftp: TftpConfig,
    dhcp: DhcpConfig,
    ubus: UbusConfig,
    script_arp: dnsmasq_rs::config::script_arp::ScriptArpConfig,
}

// C's UDP listeners mutate one parent hosts generation. Each accepted TCP
// connection takes its own snapshot; a later reload does not change it.
struct ParentDns {
    local: LocalDnsService,
    daemon: Option<DnsDaemon>,
}

/// One serialized parent event, including synchronous ubus callbacks. These
/// counters belong to the actual UDP send and TCP-session lifetime below;
/// cache/forward/DHCP counters stay with their engines and are only borrowed.
struct ParentEvents {
    ubus_name: Option<Vec<u8>>,
    ubus: Option<UbusService>,
    ubus_error_logged: bool,
    #[cfg(target_os = "linux")]
    ubus_notices: Vec<dnsmasq_rs::logging::LogEvent>,
    local_answered: u32,
    stale_answered: u32,
    tcp_active: usize,
}

impl ParentEvents {
    fn new(config: &UbusConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let name = config.object_name()?.map(<[u8]>::to_vec);
        let ubus = match name.as_deref() {
            None => None,
            Some(name) => match UbusService::connect_bytes(None, name) {
                Ok(service) => Some(service),
                Err(ConnectError::Transport(_)) => None,
                Err(ConnectError::Registration(error)) => {
                    return Err(Box::new(dnsmasq_rs::startup::StartupError {
                        code: 5,
                        message: ConnectError::registration_message(&error),
                    }));
                }
            },
        };
        Ok(Self {
            ubus_name: name,
            ubus,
            ubus_error_logged: false,
            #[cfg(target_os = "linux")]
            ubus_notices: Vec::new(),
            local_answered: 0,
            stale_answered: 0,
            tcp_active: 0,
        })
    }

    fn write_metrics(&self, metrics: &mut Metrics) {
        metrics.set(Metric::LocalAnswered, self.local_answered);
        metrics.set(Metric::StaleAnswered, self.stale_answered);
        metrics.set(Metric::TcpConnections, self.tcp_active as u32);
    }

    fn disconnect(&mut self, _error: &dyn std::fmt::Display) {
        self.ubus = None;
        // libubus reports its failed immediate reconnect before the next
        // set_ubus_listeners emits the once-only missing-connection notice.
        #[cfg(target_os = "linux")]
        self.ubus_notices.push(dnsmasq_rs::logging::LogEvent::new(
            dnsmasq_rs::logging::Service::Dns,
            dnsmasq_rs::logging::Priority::Error,
            b"Cannot reconnect to UBus: Connection failed".to_vec(),
        ));
        self.ubus_error_logged = false;
    }

    #[cfg(target_os = "linux")]
    fn queue_missing_ubus_notice(&mut self) {
        if self.ubus_name.is_some() && self.ubus.is_none() && !self.ubus_error_logged {
            self.ubus_notices.push(dnsmasq_rs::logging::LogEvent::new(
                dnsmasq_rs::logging::Service::Dns,
                dnsmasq_rs::logging::Priority::Error,
                b"Cannot set UBus listeners: no connection".to_vec(),
            ));
            self.ubus_error_logged = true;
        }
    }

    fn process_ubus(&mut self, metrics: &Metrics) {
        if self.ubus_name.is_none() {
            return;
        }
        if self.ubus.is_none() {
            #[cfg(target_os = "linux")]
            self.queue_missing_ubus_notice();
            match UbusService::connect_bytes(None, self.ubus_name.as_deref().unwrap()) {
                Ok(service) => {
                    self.ubus = Some(service);
                    self.ubus_error_logged = false;
                    #[cfg(target_os = "linux")]
                    self.ubus_notices.push(dnsmasq_rs::logging::LogEvent::new(
                        dnsmasq_rs::logging::Service::Dns,
                        dnsmasq_rs::logging::Priority::Info,
                        b"connected to system UBus".to_vec(),
                    ));
                }
                Err(ConnectError::Transport(_)) => return,
                Err(ConnectError::Registration(error)) => {
                    // C treats registration failure during retry as fatal to
                    // UBus only. The DNS/DHCP service keeps running.
                    #[cfg(target_os = "linux")]
                    self.ubus_notices.push(dnsmasq_rs::logging::LogEvent::new(
                        dnsmasq_rs::logging::Service::Dns,
                        dnsmasq_rs::logging::Priority::Error,
                        ConnectError::registration_message(&error).into_bytes(),
                    ));
                    self.ubus_name = None;
                    return;
                }
            }
        }
        while let Some(ubus) = self.ubus.as_mut() {
            match ubus.process_one(metrics) {
                Ok(true) =>
                {
                    #[cfg(target_os = "linux")]
                    for active in ubus.take_subscription_notices() {
                        self.ubus_notices.push(dnsmasq_rs::logging::LogEvent::new(
                            dnsmasq_rs::logging::Service::Dns,
                            dnsmasq_rs::logging::Priority::Debug,
                            format!(
                                "UBus subscription callback: {} subscriber(s)",
                                u8::from(active)
                            )
                            .into_bytes(),
                        ));
                    }
                }
                Ok(false) => break,
                Err(error) => {
                    self.disconnect(&error);
                    break;
                }
            }
        }
    }

    fn doctor(&mut self, result: &DnsResult<'_>, metrics: &Metrics) -> Option<IpAddr> {
        match self.ubus.as_mut()?.doctor_dns(
            result,
            Some(|| STOP_REQUESTED.load(Ordering::Acquire)),
            metrics,
        ) {
            Ok(address) => address,
            Err(error) => {
                self.disconnect(&error);
                None
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn notify_dhcp(
        &mut self,
        kind: DhcpEventKind,
        fields: DhcpEventFields<'_>,
        logging: DhcpLogging,
    ) {
        if let Some(ubus) = &mut self.ubus {
            if let Err(error) = ubus.notify_dhcp(kind, fields, logging) {
                self.disconnect(&error);
            }
        }
    }
}

fn write_dns_metrics(
    metrics: &mut Metrics,
    cache: dnsmasq_rs::dns::cache::CacheCounters,
    forward: dnsmasq_rs::dns::forward::ForwardCounters,
    local_answered: u32,
) {
    metrics.set(Metric::CacheInserted, cache.inserted);
    metrics.set(Metric::CacheLiveFreed, cache.live_freed);
    metrics.set(Metric::QueriesForwarded, forward.queries_forwarded);
    metrics.set(Metric::Unanswered, forward.unanswered);
    metrics.set(
        Metric::LocalAnswered,
        local_answered.wrapping_add(forward.background_local_answered),
    );
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn write_dhcp_metrics(metrics: &mut Metrics, provider: &DhcpProvider) {
    write_lease_metrics(metrics, provider.lease_counters());
    let messages = provider.message_counters();
    for (metric, value) in [
        (Metric::Bootp, messages.bootp),
        (Metric::Pxe, messages.pxe),
        (Metric::DhcpAck, messages.ack),
        (Metric::DhcpDecline, messages.decline),
        (Metric::DhcpDiscover, messages.discover),
        (Metric::DhcpInform, messages.inform),
        (Metric::DhcpNak, messages.nak),
        (Metric::DhcpOffer, messages.offer),
        (Metric::DhcpRelease, messages.release),
        (Metric::DhcpRequest, messages.request),
        (Metric::NoAnswer, messages.no_answer),
        (Metric::DhcpLeaseQuery, messages.lease_query),
        (Metric::DhcpLeaseUnassigned, messages.lease_unassigned),
        (Metric::DhcpLeaseActive, messages.lease_active),
        (Metric::DhcpLeaseUnknown, messages.lease_unknown),
    ] {
        metrics.set(metric, value);
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn write_lease_metrics(metrics: &mut Metrics, leases: dnsmasq_rs::dhcp::lease::LeaseCounters) {
    metrics.set(Metric::LeasesAllocated4, leases.allocated4);
    metrics.set(Metric::LeasesPruned4, leases.pruned4);
    metrics.set(Metric::LeasesPruned6, leases.pruned6);
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
struct LeasePublisher {
    parent: Arc<Mutex<ParentDns>>,
    policy: LeasePolicy,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl dnsmasq_rs::dhcp::persistence::DnsPublisher for LeasePublisher {
    fn replace(
        &mut self,
        records: &[dnsmasq_rs::dhcp::persistence::DnsLeaseRecord<'_>],
    ) -> io::Result<()> {
        let mut parent = self
            .parent
            .lock()
            .map_err(|_| io::Error::other("DNS state lock poisoned"))?;
        let ParentDns { local, daemon } = &mut *parent;
        let daemon = daemon
            .as_mut()
            .ok_or_else(|| io::Error::other("DNS publication is disabled"))?;
        let names = daemon.publish_lease_names(
            records,
            &mut local.hosts,
            &local.config.records.cnames,
            self.policy,
        );
        report_lease_name_warnings(&names);
        local.leases = Arc::new(names);
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn report_lease_name_warnings(names: &dnsmasq_rs::dns::lease_names::LeaseNames) {
    for warning in names.warnings() {
        match warning {
            PublicationWarning::ConfiguredCname { name, address } => {
                eprintln!(
                    "dnsmasq-rs: DHCP name {} conflicts with a configured CNAME for {address}",
                    String::from_utf8_lossy(name)
                );
            }
            PublicationWarning::StaticAddress {
                name,
                address,
                configured_address,
                source,
            } => {
                eprintln!("dnsmasq-rs: DHCP name {} for {address} conflicts with hosts source {source} at {configured_address}", String::from_utf8_lossy(name));
            }
        }
    }
}

fn load(args: &[OsString]) -> Result<(Action, Runtime), loader::LoadError> {
    let mut runtime = Runtime {
        scalar: ScalarConfig::default(),
        process: dnsmasq_rs::startup::ProcessConfig::default(),
        logging: dnsmasq_rs::config::logging::LoggingConfig::default(),
        dns: DnsConfig::default(),
        tftp: TftpConfig::default(),
        dhcp: DhcpConfig::default(),
        ubus: UbusConfig::default(),
        script_arp: Default::default(),
    };
    let action = loader::load(args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        if runtime.logging.apply(directive)?
            || runtime.process.apply(directive)?
            || runtime.scalar.apply(directive)?
            || runtime.dns.apply_resolved(directive)?
            || runtime.tftp.apply(directive)?
            || runtime.dhcp.apply(directive)?
            || runtime.ubus.apply(directive)?
            || runtime.script_arp.apply(directive)?
        {
            Ok(())
        } else {
            Err(Error("option is not implemented by dnsmasq-rs"))
        }
    })?;
    Ok((action, runtime))
}

fn config_diagnostic(error: Error) -> loader::LoadError {
    loader::LoadError {
        location: loader::Location {
            file: None,
            line: None,
            from_script: false,
        },
        exit_code: 1,
        message: error.to_string(),
    }
}

fn finalize_dns_config(config: &mut DnsConfig) -> Result<(), loader::LoadError> {
    config.finalize().map_err(|error| {
        let mut diagnostic = config_diagnostic(error.clone());
        if error == Error("CNAME loop") {
            if let Some(alias) = config.records.cname_loop_alias() {
                diagnostic.message =
                    format!("CNAME loop involving {}", String::from_utf8_lossy(alias));
            }
        }
        diagnostic
    })
}

fn run(args: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    let mut startup = dnsmasq_rs::startup::daemonize::StartupChannel::default();
    let result = run_inner(
        args,
        #[cfg(target_os = "linux")]
        &mut startup,
    );
    #[cfg(target_os = "linux")]
    if startup.active() {
        if let Err(error) = &result {
            if let Some(log) = error.downcast_ref::<dnsmasq_rs::logging::LogStartError>() {
                startup.fail_log(log.errno(), log.argument());
            } else if let Some(tftp) =
                error.downcast_ref::<dnsmasq_rs::config::tftp::RootAccessError>()
            {
                startup.fail_tftp(tftp.error.raw_os_error().unwrap_or(5), &tftp.path);
            } else {
                startup.fail(startup_status(error.as_ref()), &error.to_string());
            }
            return Ok(());
        }
    }
    result
}

fn run_inner(
    args: &[OsString],
    #[cfg(target_os = "linux")] startup: &mut dnsmasq_rs::startup::daemonize::StartupChannel,
) -> Result<(), Box<dyn std::error::Error>> {
    let (action, mut runtime) = load(args)?;
    match action {
        Action::Version => {
            print!("{}", dnsmasq_rs::startup::cli::version_output());
            return Ok(());
        }
        Action::Help | Action::HelpDhcp => {
            print!(
                "{}",
                dnsmasq_rs::startup::cli::help_output(action == Action::HelpDhcp)
            );
            return Ok(());
        }
        Action::Test => {
            // C read_opts performs cross-option checks and CNAME-loop
            // validation before its syntax-check success message.  It does
            // not run the daemon-only EDNS/source-port finalization below.
            if runtime.dns.records.needs_hostname() {
                runtime
                    .dns
                    .finalize_hostname(&dnsmasq_rs::startup::hostname()?)?;
            }
            finalize_dns_config(&mut runtime.dns)?;
            runtime
                .dhcp
                .validate_dns_config(&runtime.dns)
                .map_err(config_diagnostic)?;
            eprintln!("dnsmasq: syntax check OK.");
            return Ok(());
        }
        Action::Run => {}
    }
    #[cfg(target_os = "linux")]
    let identity = dnsmasq_rs::startup::Identity::resolve(&runtime.process)?;
    runtime.scalar.finalize_runtime()?;
    if runtime.dns.records.needs_hostname() {
        runtime
            .dns
            .finalize_hostname(&dnsmasq_rs::startup::hostname()?)?;
    }
    finalize_dns_config(&mut runtime.dns)?;
    runtime
        .dhcp
        .validate_dns_config(&runtime.dns)
        .map_err(config_diagnostic)?;
    runtime.tftp.validate_ready()?;
    runtime.dhcp.validate_ready()?;
    validate_runtime_ready(&runtime.scalar, &runtime.dns)?;
    let dns_enabled = runtime.scalar.dns_port != 0;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let (initial_interface_records, initial_interface_collector) = {
        if runtime.dns.interface_records.rules.is_empty() {
            (
                Arc::new(dnsmasq_rs::dns::interface_records::InterfaceRecords::default()),
                None,
            )
        } else {
            let mut collector = dnsmasq_rs::dns::interface_collect::InterfaceCollector::new()?;
            collector.begin()?;
            let result = loop {
                if let Some(result) = collector.step() {
                    break result;
                }
                let mut fds = Vec::new();
                collector.append_poll_fds(&mut fds);
                let wait = if collector.runnable() {
                    0
                } else {
                    collector
                        .deadline()
                        .unwrap()
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(i32::MAX as u128) as i32
                };
                owrt_ubus::sys::poll_fds(&mut fds, wait)?;
            };
            if let Some(error) = result.error {
                return Err(Box::new(error));
            }
            (
                Arc::new(
                    dnsmasq_rs::dns::interface_records::InterfaceRecords::from_addresses(
                        &runtime.dns.interface_records.rules,
                        &result.addresses,
                    ),
                ),
                Some(collector),
            )
        }
    };
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    let initial_interface_records =
        Arc::new(dnsmasq_rs::dns::interface_records::InterfaceRecords::default());
    let hosts = if dns_enabled {
        read_hosts(&runtime.dns, runtime.scalar.local_ttl)
    } else {
        Hosts::new()
    };
    #[cfg(target_os = "linux")]
    let resolvers = Vec::new();
    #[cfg(not(target_os = "linux"))]
    let resolvers = if dns_enabled {
        read_resolvers(&runtime.dns)?
    } else {
        Vec::new()
    };
    let interface_snapshot = Arc::new(Mutex::new(
        listeners::snapshot().map_err(NetworkStartupError)?,
    ));
    let addresses = listeners::bound_addresses(
        &runtime.dns,
        runtime.scalar.dns_port,
        &interface_snapshot.lock().unwrap(),
    );
    let mut pending_static_dns = listeners::tentative_addresses(
        &runtime.dns,
        runtime.scalar.dns_port,
        &interface_snapshot.lock().unwrap(),
    );
    let tftp_config = runtime.tftp.clone();
    let dhcp_config = runtime.dhcp.clone();
    DEBUG_MODE.store(runtime.process.debug, Ordering::Relaxed);
    owrt_ubus::sys::set_signal_handler(owrt_ubus::sys::SIGINT, request_interrupt);
    owrt_ubus::sys::set_signal_handler(owrt_ubus::sys::SIGTERM, request_stop);
    owrt_ubus::sys::set_signal_handler(SIGHUP, request_reload);
    owrt_ubus::sys::set_signal_handler(12, request_log_reopen);
    // dnsmasq.c allocates `edns_pktsz + MAXDNAME + RRFIXEDSZ` as scratch space.
    // TCP uses this frame limit; UDP admission enforces edns_pktsz itself.
    let packet_limit = usize::from(runtime.scalar.edns_packet_max) + 255 + 10;
    let tcp_limit = usize::try_from(runtime.scalar.max_tcp_connections).unwrap_or(usize::MAX);
    let daemon_config = runtime.dns.clone();
    let daemon_hosts = hosts.clone();
    let daemon_options = DaemonOptions {
        forward_max: runtime.scalar.forward_max.max(0) as usize,
        fast_retry: runtime.scalar.fast_retry,
        edns_packet_max: runtime.scalar.edns_packet_max,
        proxy_dnssec: runtime.dns.proxy_dnssec,
        local_ttl: runtime.scalar.local_ttl,
        max_udp: packet_limit,
        upstream_lifetime: dnsmasq_rs::dns::upstream::Lifetime::ForwardTable,
    };
    // C has one parent forward table and cache across all listener sockets.
    // Capacity and duplicate-query admission must not grow with listen-address.
    let daemon = if dns_enabled {
        let mut daemon = DnsDaemon::new(
            daemon_config.clone(),
            daemon_hosts,
            &resolvers,
            daemon_options,
        )?;
        daemon.configure_source_sockets(
            dnsmasq_rs::dns::upstream::source_sockets::SocketSettings::from_scalar(&runtime.scalar),
            true,
        )?;
        daemon.check_server_addresses(&dns_local_addresses(
            &daemon_config,
            &interface_snapshot.lock().unwrap(),
            runtime.scalar.dns_port,
        ))?;
        daemon.enable_cache(
            usize::try_from(runtime.scalar.cache_size).unwrap_or(usize::MAX),
            runtime.scalar.min_cache_ttl,
            runtime.scalar.max_cache_ttl,
            match runtime.scalar.stale_cache {
                StaleCache::Disabled => StalePolicy::Disabled,
                StaleCache::Until(seconds) => StalePolicy::Seconds(seconds),
                StaleCache::Forever => StalePolicy::Forever,
            },
        );
        daemon.set_max_reply_ttl(runtime.scalar.max_ttl);
        daemon.enable_negative_cache(
            runtime.scalar.negative_ttl,
            !daemon_config.no_negative_cache,
        );
        Some(daemon)
    } else {
        None
    };
    let service = Arc::new(Mutex::new(ParentDns {
        local: LocalDnsService::new_with_limits(
            daemon
                .as_ref()
                .map_or(runtime.dns, |daemon| daemon.local_config().clone()),
            hosts,
            runtime.scalar.local_ttl,
            packet_limit,
            runtime.scalar.edns_packet_max,
        ),
        daemon,
    }));
    {
        let mut parent = service.lock().unwrap();
        parent.local.interfaces = Arc::clone(&initial_interface_records);
        if let Some(daemon) = &mut parent.daemon {
            daemon.publish_interface_records(Arc::clone(&initial_interface_records));
        }
    }
    // C mutates all parent engines in one event loop. Fetch DHCP metrics
    // before locking DNS; synchronous doctor callbacks must never invert it.
    // Socket waits remain outside this gate.
    let parent_events = Arc::new(Mutex::new(ParentEvents::new(&runtime.ubus)?));
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let helper_config = dhcp_config
        .script
        .as_ref()
        .filter(|_| {
            !dhcp_config.ranges.is_empty() || tftp_config.enabled || runtime.script_arp.enabled
        })
        .map(|script| HelperConfig {
            script: PathBuf::from(OsString::from_vec(script.clone())),
            // dnsmasq.c resolves scriptuser only when DHCP is configured.
            // TFTP alone still has a helper, inheriting startup credentials.
            script_user: (!dhcp_config.ranges.is_empty())
                .then(|| dhcp_config.script_user.clone())
                .flatten(),
            debug: runtime.process.debug,
        });
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(config) = &helper_config {
        Helper::validate_startup(
            config,
            (dhcp_config.lease_read_only && !dhcp_config.ranges.is_empty())
                .then_some(dhcp_config.lease_max),
        )?;
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let mut early_logger = None;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let lease_init_now = now_seconds();
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let initial_leases = dnsmasq_rs::startup::lease_init::initialize(
        &dhcp_config,
        runtime.process.debug,
        &mut early_logger,
    )?;
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    if !dhcp_config.ranges.is_empty() || !dhcp_config.relay.is_empty() {
        return Err(Box::new(Error("DHCP listener requires 64-bit Linux")));
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    if tftp_config.enabled && !tftp_config.no_fail {
        return Err(Box::new(Error("TFTP listener requires 64-bit Linux")));
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let provider = if !dhcp_config.ranges.is_empty() {
        let mut provider = DhcpProvider::new_with_log(
            dhcp_config.clone(),
            daemon_config.listen_addresses.clone(),
            runtime.scalar.dns_port,
            // C delay_dhcp finishes the accepted transaction before consuming
            // SIGTERM. The listener still checks STOP before each new packet;
            // DNS/TFTP continue through the borrowed probe wait meanwhile.
            || false,
            &mut early_logger,
        )
        .map_err(|error| {
            use dnsmasq_rs::logging::{emit_early, Priority};
            emit_early(
                &mut early_logger,
                Priority::Critical,
                error.to_string().as_bytes(),
            );
            emit_early(&mut early_logger, Priority::Critical, b"FAILED to start up");
            error
        })?;
        provider
            .start_interface_owner()
            .map_err(|error| dnsmasq_rs::startup::StartupError {
                code: 5,
                message: format!("cannot create DHCP netlink socket: {error}"),
            })?;
        provider.set_dns_config(&daemon_config)?;
        provider.set_tftp_config(&tftp_config);
        if let Some(restored) = initial_leases {
            provider.restore_initial_records(restored, lease_init_now)?;
        }
        if dns_enabled {
            let config_dns = Arc::clone(&service);
            provider.set_config_host_lookup(move |name| {
                let mut parent = config_dns
                    .lock()
                    .map_err(|_| io::Error::other("DNS state lock poisoned"))?;
                let matches = parent.local.hosts.lookup(name, Some(false), false);
                let selected = if matches.len() == 1 {
                    matches.first().copied()
                } else {
                    matches.into_iter().find(|host| host.reverse)
                };
                Ok(selected.and_then(|host| match host.address {
                    IpAddr::V4(address) => Some(address),
                    IpAddr::V6(_) => None,
                }))
            });
            let boot_dns = Arc::clone(&service);
            provider.set_boot_host_lookup(move |name| {
                let mut parent = boot_dns
                    .lock()
                    .map_err(|_| io::Error::other("DNS state lock poisoned"))?;
                Ok(parent
                    .local
                    .hosts
                    .lookup(name, Some(false), false)
                    .first()
                    .and_then(|host| match host.address {
                        IpAddr::V4(address) => Some(address),
                        IpAddr::V6(_) => None,
                    }))
            });
            let reverse_dns = Arc::clone(&service);
            provider.set_reverse_host_lookup(move |address| {
                let parent = reverse_dns
                    .lock()
                    .map_err(|_| io::Error::other("DNS state lock poisoned"))?;
                Ok(parent
                    .local
                    .hosts
                    .reverse(IpAddr::V4(address))
                    .map(|host| host.name.clone()))
            });
            provider.set_dns_publisher(Box::new(LeasePublisher {
                parent: Arc::clone(&service),
                policy: LeasePolicy {
                    local_ttl: runtime.scalar.local_ttl,
                    dhcp_ttl: runtime.scalar.dhcp_ttl,
                    no_round_robin: daemon_config.no_round_robin,
                    stale: match runtime.scalar.stale_cache {
                        StaleCache::Disabled => StalePolicy::Disabled,
                        StaleCache::Until(seconds) => StalePolicy::Seconds(seconds),
                        StaleCache::Forever => StalePolicy::Forever,
                    },
                },
            }));
        }
        let shared_provider = Arc::new(Mutex::new(provider));
        Some(shared_provider)
    } else {
        None
    };
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let dhcp_runtime = if provider.is_some() || !dhcp_config.relay.is_empty() {
        // A relay-only listener must not create or restore a lease file.
        let mut listener = DhcpSocketListener::bind_with_reuse(
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, dhcp_config.ports.server)),
            DhcpListener::Dhcp,
            &[],
            daemon_config.bind_interfaces || daemon_config.bind_dynamic,
        )
        .map_err(NetworkStartupError)?;
        listener.configure_relay(
            &dhcp_config.relay,
            &daemon_config,
            &dhcp_config.no_dhcp_interfaces,
            dhcp_config.ports,
            &dhcp_config.network,
        )?;
        listener
            .configure_pxe(
                dhcp_config.pxe.enabled,
                &dhcp_config.pxe.vendors,
                daemon_config.bind_interfaces || daemon_config.bind_dynamic,
            )
            .map_err(NetworkStartupError)?;
        Some(DhcpService {
            provider,
            listener,
            pxe_next: false,
        })
    } else {
        None
    };
    // C opens/restores the lease file and binds DHCP before its DNS sockets.
    // Open all UDP/TCP listeners before starting workers. A setup error drops
    // every socket without leaving an already-running partial service.
    let mut listeners = Vec::new();
    for address in addresses {
        match open_dns_listener(address, daemon_config.bind_dynamic) {
            Ok((udp, tcp)) if udp.is_some() || tcp.is_some() => listeners.push((address, udp, tcp)),
            Ok(_) => {}
            Err(error) => return Err(Box::new(NetworkStartupError(error))),
        }
    }
    listeners::validate_bind_interfaces(&daemon_config, &interface_snapshot.lock().unwrap())
        .map_err(NetworkStartupError)?;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let mut tftp_listener = if tftp_config.enabled {
        match TftpListener::bind_config(
            &tftp_config,
            &daemon_config,
            &runtime.dhcp.no_dhcp_interfaces,
            &runtime.dhcp.no_tftp_interfaces,
            identity.runtime_uid(&runtime.process),
            if dns_enabled {
                (runtime.scalar.forward_max.max(0) as usize) / 2
            } else {
                0
            },
            packet_limit,
        ) {
            Ok(listener) => Some(listener),
            Err(error) => return Err(Box::new(NetworkStartupError(error))),
        }
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let capabilities = dnsmasq_rs::startup::network_capabilities(
        !runtime.dhcp.ranges.is_empty() || !runtime.dhcp.relay.is_empty(),
        runtime.dhcp.no_ping,
        runtime
            .dhcp
            .force_broadcast
            .first()
            .is_some_and(|rule| rule.is_unconditional()),
        (daemon_config.bind_dynamic
            && (tftp_config.enabled || runtime.scalar.dns_port <= 1024 && dns_enabled))
            || (!pending_static_dns.is_empty() && runtime.scalar.dns_port <= 1024 && dns_enabled)
            || tftp_listener
                .as_ref()
                .is_some_and(TftpListener::needs_privileged_rebind),
        runtime.ubus.object_name()?.is_some(),
    );
    // Fail missing capabilities before touching a pre-existing PID file.
    #[cfg(target_os = "linux")]
    let have_cap_chown = identity.check_capabilities(capabilities)?;
    #[cfg(target_os = "linux")]
    match startup.begin(&runtime.process) {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(error) => {
            if let Some(message) = startup.take_failure_bytes() {
                dnsmasq_rs::logging::report_startup_failure_bytes(
                    &Default::default(),
                    &Default::default(),
                    &message,
                );
                let mut stderr = io::stderr();
                let _ = stderr.write_all(b"\ndnsmasq: ");
                let _ = stderr.write_all(&message);
                let _ = stderr.write_all(b"\n");
                return Err(Box::new(SilentStartupError(error)));
            }
            dnsmasq_rs::logging::report_startup_failure(
                &Default::default(),
                &Default::default(),
                &error.message,
            );
            return Err(Box::new(error));
        }
    }
    #[cfg(target_os = "linux")]
    let pid_file = identity.write_pid(&runtime.process).map_err(|error| {
        if !startup.active() {
            use dnsmasq_rs::logging::{emit_early, Priority};
            emit_early(
                &mut early_logger,
                Priority::Critical,
                error.message.as_bytes(),
            );
            emit_early(&mut early_logger, Priority::Critical, b"FAILED to start up");
        }
        error
    })?;
    #[cfg(target_os = "linux")]
    let (mut logger, log_ownership_warning) = match dnsmasq_rs::logging::Logger::start(
        &runtime.logging,
        &runtime.process,
        identity.log_owner_uid(),
    ) {
        Ok(value) => value,
        Err(error) => {
            if !startup.active() {
                dnsmasq_rs::logging::report_startup_failure_bytes(
                    &runtime.logging,
                    &runtime.process,
                    &error.message_bytes(),
                );
                // C selects log_stderr before dup(), so this failure already
                // has its syslog report and die() does not echo it to stderr.
                if runtime.logging.file.as_deref() == Some(std::path::Path::new("-")) {
                    return Err(Box::new(SilentStartupError(error.into())));
                }
            }
            return Err(Box::new(error));
        }
    };
    #[cfg(target_os = "linux")]
    dnsmasq_rs::startup::redirect_standard_streams(&runtime.process);
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let dhcp_helper = helper_config.map(Helper::start).transpose()?;
    #[cfg(target_os = "linux")]
    identity
        .drop_privileges(&runtime.process, capabilities)
        .map_err(|error| {
            if !startup.active() {
                use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                logger.emit(LogEvent::new(
                    Service::Dns,
                    Priority::Critical,
                    error.message.as_bytes().to_vec(),
                ));
                logger.emit(LogEvent::new(
                    Service::Dns,
                    Priority::Critical,
                    b"FAILED to start up".to_vec(),
                ));
                logger.finish();
            }
            error
        })?;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let tftp_root_warnings = if let Some(listener) = &tftp_listener {
        match listener.root_accesses() {
            Ok(warnings) => warnings,
            Err(error) => {
                if startup.active() {
                    return Err(Box::new(error));
                }
                logger.fatal(&error.message_bytes());
                return Err(Box::new(SilentStartupError(
                    dnsmasq_rs::startup::StartupError {
                        code: 3,
                        message: error.to_string(),
                    },
                )));
            }
        }
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut dns_files = DnsFiles::new(&daemon_config, dns_enabled, daemon_config.clear_on_reload)?;
    #[cfg(target_os = "linux")]
    let route_watch = dns_enabled
        .then(RouteWatch::new)
        .transpose()
        .map_err(|error| dnsmasq_rs::startup::StartupError {
            code: 5,
            message: format!("cannot create netlink socket: {error}"),
        })?;
    #[cfg(target_os = "linux")]
    dns_files.request(ReloadReason::Init);
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(provider) = dhcp_runtime
        .as_ref()
        .and_then(|dhcp| dhcp.provider.as_ref())
    {
        provider
            .lock()
            .map_err(|_| io::Error::other("DHCP state lock poisoned"))?
            .start_file_owner()?;
    }
    // The daemon owns all sockets from the foreground loop.  This keeps the
    // runtime at one service thread and makes ordering explicit across DNS,
    // DHCP, TFTP and UBus.
    let mut poll_listeners = Vec::new();
    let mut bound_listeners = Vec::new();
    let mut next_listener = 0u64;
    for (address, udp, tcp) in listeners {
        let token = SocketToken(next_listener);
        next_listener += 1;
        bound_listeners.push((address, token));
        poll_listeners.push((token, udp, tcp));
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(tftp) = &mut tftp_listener {
        for mut address in tftp.pending_listener_addresses().iter().copied() {
            address.set_port(runtime.scalar.dns_port);
            if !pending_static_dns.contains(&address) {
                pending_static_dns.push(address);
            }
        }
        for mut address in tftp.listener_addresses() {
            if !tftp.has_listener(address) {
                continue;
            }
            address.set_port(runtime.scalar.dns_port);
            if !bound_listeners.iter().any(|(bound, _)| *bound == address) {
                bound_listeners.push((address, SocketToken(next_listener)));
                next_listener += 1;
            }
        }
        tftp.use_shared_listener_owner();
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let neighbor_cache = if tftp_config.unique_root_mac
        || daemon_config.edns.needs_mac()
        || runtime.script_arp.enabled
    {
        let mut cache = NeighborCache::new().ok();
        if let Some(cache) = &mut cache {
            cache.enable_script_arp(runtime.script_arp.enabled);
        }
        cache
    } else {
        None
    };
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let mut poll = SinglePoll::new(
        Arc::clone(&service),
        Arc::clone(&parent_events),
        Arc::clone(&interface_snapshot),
        daemon_config.clone(),
        resolvers.clone(),
        packet_limit,
        tcp_limit,
        daemon_options.edns_packet_max,
        poll_listeners,
        dhcp_runtime,
        dhcp_helper,
        tftp_listener,
        neighbor_cache,
    );
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    let mut poll = SinglePoll::new(
        Arc::clone(&service),
        Arc::clone(&parent_events),
        Arc::clone(&interface_snapshot),
        daemon_config.clone(),
        resolvers.clone(),
        packet_limit,
        tcp_limit,
        daemon_options.edns_packet_max,
        poll_listeners,
    );
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        poll.interface_collector = initial_interface_collector;
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        poll.script_arp = runtime.script_arp.enabled;
    }
    #[cfg(target_os = "linux")]
    {
        poll.dns_files = Some(dns_files);
        poll.route_watch = route_watch;
        poll.dns_port = runtime.scalar.dns_port;
        poll.early_logger = early_logger;
    }
    #[cfg(target_os = "linux")]
    {
        use dnsmasq_rs::logging::{LogEvent, Priority, Service};
        let started = if !dns_enabled {
            "started, version 2.93 DNS disabled".to_owned()
        } else if runtime.scalar.cache_size == 0 {
            "started, version 2.93 cache disabled".to_owned()
        } else {
            format!(
                "started, version 2.93 cachesize {}",
                runtime.scalar.cache_size
            )
        };
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Info,
            started.into_bytes(),
        ));
        if dns_enabled && runtime.scalar.cache_size > 10000 {
            logger.emit(LogEvent::new(Service::Dns, Priority::Warning,
                b"cache size greater than 10000 may cause performance issues, and is unlikely to be useful.".to_vec()));
        }
        if dns_enabled && daemon_config.local_service_net {
            logger.emit(LogEvent::new(
                Service::Dns,
                Priority::Info,
                b"DNS service limited to local subnets".to_vec(),
            ));
        } else if dns_enabled && daemon_config.local_service_host {
            logger.emit(LogEvent::new(
                Service::Dns,
                Priority::Info,
                b"DNS service limited to localhost".to_vec(),
            ));
        }
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Info,
            format!(
                "compile time options: {}",
                dnsmasq_rs::startup::cli::COMPILE_TIME_OPTIONS
            )
            .into_bytes(),
        ));
        if let Some(error) = pid_file.ownership_warning() {
            let path = runtime.process.pid_file.as_ref().unwrap().display();
            let (priority, message) = if error.raw_os_error() == Some(1) && !have_cap_chown {
                (
                    Priority::Info,
                    format!("chown of PID file {path} failed: please add capability CAP_CHOWN"),
                )
            } else {
                (
                    Priority::Warning,
                    format!(
                        "chown of PID file {path} failed: {}",
                        dnsmasq_rs::logging::error_text(error)
                    ),
                )
            };
            logger.emit(LogEvent::new(Service::Dns, priority, message.into_bytes()));
        }
        {
            let event = parent_events.lock().unwrap();
            if event.ubus_name.is_some() {
                logger.emit(LogEvent::new(
                    Service::Dns,
                    Priority::Info,
                    if event.ubus.is_some() {
                        b"UBus support enabled: connected to system bus".to_vec()
                    } else {
                        b"UBus support enabled: bus connection pending".to_vec()
                    },
                ));
            }
        }
        if let Some(error) = log_ownership_warning {
            logger.emit(dnsmasq_rs::logging::ownership_warning(
                runtime.logging.file.as_deref().unwrap(),
                &error,
            ));
        }

        for warning in dnsmasq_rs::logging::startup::missing_interfaces(
            &daemon_config,
            &interface_snapshot.lock().unwrap(),
        ) {
            logger.emit(warning);
        }
        if dns_enabled && daemon_config.no_resolv {
            if daemon_config.has_explicit_resolv_file() {
                logger.emit(LogEvent::new(
                    Service::Dns,
                    Priority::Warning,
                    b"warning: ignoring resolv-file flag because no-resolv is set".to_vec(),
                ));
            }
            if !daemon_config.rules.iter().any(|rule| {
                matches!(
                    rule.target,
                    dnsmasq_rs::config::dns::RuleTarget::Upstream(_)
                )
            }) {
                logger.emit(LogEvent::new(
                    Service::Dns,
                    Priority::Warning,
                    b"warning: no upstream servers configured".to_vec(),
                ));
            }
        }
        let async_limit = logger.async_queue_limit();
        if async_limit != 0 {
            logger.emit(LogEvent::new(
                Service::Dns,
                Priority::Info,
                format!("asynchronous logging enabled, queue limit is {async_limit} messages")
                    .into_bytes(),
            ));
        }
        for range in &runtime.dhcp.ranges {
            logger.emit(dnsmasq_rs::logging::startup::dhcp_range(range));
        }
        if let Some(event) = dnsmasq_rs::logging::startup::tftp(&runtime.tftp) {
            logger.emit(event);
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        for warning in &tftp_root_warnings {
            logger.emit(dnsmasq_rs::logging::startup::tftp_root_warning(warning));
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(limit) = poll
            .tftp
            .as_ref()
            .and_then(TftpListener::restricted_transfer_limit)
        {
            logger.emit(LogEvent::new(
                Service::Tftp,
                Priority::Warning,
                format!("restricting maximum simultaneous TFTP transfers to {limit}").into_bytes(),
            ));
        }
        poll.log_cleared_cache = dns_enabled
            && runtime.scalar.cache_size > 0
            && daemon_config.no_hosts
            && daemon_config.addn_hosts.is_empty();
        poll.logger = Some(logger);
    }
    // `-k` is the normal OpenWrt invocation. Stop handlers let workers leave
    // their bounded receive loops and release sockets before exit.
    #[cfg(target_os = "linux")]
    if poll.helper.as_ref().is_none_or(Helper::ready) {
        startup.complete();
    }
    #[cfg(target_os = "linux")]
    {
        if dns_enabled {
            if let Some(daemon) = &mut service.lock().unwrap().daemon {
                daemon.queue_server_notices();
            }
        }
        poll.log_dns_diagnostics(); // C releases startup errfd before check_servers.
    }
    let mut last_interfaces = Instant::now();
    // C's INAME_USED latch survives interface removal. Once an explicit
    // address belonged to an interface, it cannot become an unowned fallback.
    let mut owned_explicit: Vec<IpAddr> = interface_snapshot
        .lock()
        .unwrap()
        .iter()
        .filter(|interface| daemon_config.listen_addresses.contains(&interface.address))
        .map(|interface| interface.address)
        .collect();
    // A listener created without an interface never acquires ownership when
    // that address later appears. C retains such sockets across removal.
    let mut persistent_unowned: Vec<SocketAddr> = bound_listeners
        .iter()
        .filter(|(address, _)| {
            daemon_config.listen_addresses.contains(&address.ip())
                && !owned_explicit.contains(&address.ip())
        })
        .map(|(address, _)| *address)
        .collect();
    while !STOP_REQUESTED.load(Ordering::Acquire) {
        poll.interfaces_enumerated = false;
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        poll.observe_arp_activity();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        poll.step_dhcp_files();
        #[cfg(target_os = "linux")]
        poll.step_dns_files();
        if std::mem::take(&mut poll.full_reload_pending) {
            poll.reload_data(runtime.scalar.local_ttl)?;
        }
        poll.step();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(error) = poll.helper_init_error.take() {
            if !startup.active() {
                if let Some(logger) = &mut poll.logger {
                    logger.fatal(error.message.as_bytes());
                }
                return Err(Box::new(SilentStartupError(
                    dnsmasq_rs::startup::StartupError {
                        code: error.code,
                        message: error.message,
                    },
                )));
            }
            return Err(Box::new(error));
        }
        #[cfg(target_os = "linux")]
        if startup.active() && poll.helper.as_ref().is_none_or(Helper::ready) {
            startup.complete();
        }
        if last_interfaces.elapsed() >= Duration::from_millis(100) {
            last_interfaces = Instant::now();
            if let Ok(interfaces) = listeners::snapshot() {
                let previous_interfaces = interface_snapshot.lock().unwrap().clone();
                let changed = previous_interfaces != interfaces;
                *interface_snapshot.lock().unwrap() = interfaces.clone();
                #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                if changed {
                    if let Some(dhcp) = &mut poll.dhcp {
                        dhcp.listener.invalidate_relay_interfaces();
                    }
                }
                if changed {
                    if daemon_config.bind_dynamic || daemon_config.local_service_net {
                        poll.enumerate_interface_records();
                    }
                    if poll.interface_work_pending() {
                        poll.pending_interface_server_check = true;
                    } else {
                        let mut parent = service.lock().unwrap();
                        if let Some(daemon) = &mut parent.daemon {
                            daemon.check_server_addresses(&dns_local_addresses(
                                &daemon_config,
                                &interfaces,
                                runtime.scalar.dns_port,
                            ))?;
                            parent.local.config = daemon.local_config().clone();
                        }
                    }
                }
                for interface in &interfaces {
                    if daemon_config.listen_addresses.contains(&interface.address)
                        && !owned_explicit.contains(&interface.address)
                    {
                        owned_explicit.push(interface.address);
                    }
                }
                let mut dns_addresses = listeners::bound_addresses(
                    &daemon_config,
                    runtime.scalar.dns_port,
                    &interfaces,
                );
                if daemon_config.bind_dynamic {
                    dns_addresses.retain(|address| {
                        !owned_explicit.contains(&address.ip())
                            || persistent_unowned.contains(address)
                            || interfaces
                                .iter()
                                .any(|interface| interface.address == address.ip())
                    });
                }
                let mut eligible = dns_addresses.clone();
                #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                if let Some(tftp) = &mut poll.tftp {
                    if daemon_config.bind_dynamic {
                        for (address, _) in &bound_listeners {
                            if !persistent_unowned.contains(address)
                                && !interfaces
                                    .iter()
                                    .any(|interface| interface.address == address.ip())
                            {
                                tftp.retire_listener(*address);
                            }
                        }
                    }
                    tftp.refresh_listener_interfaces(&interfaces);
                    for mut address in tftp.listener_addresses() {
                        address.set_port(runtime.scalar.dns_port);
                        if !eligible.contains(&address) {
                            eligible.push(address);
                        }
                    }
                }
                if daemon_config.bind_dynamic {
                    bound_listeners.retain(|(address, token)| {
                        if eligible.contains(address) {
                            return true;
                        }
                        #[cfg(target_os = "linux")]
                        if let Some(logger) = &mut poll.logger {
                            let interface = previous_interfaces
                                .iter()
                                .find(|interface| interface.address == address.ip());
                            logger.emit(listener_debug_event(
                                "stopped listening",
                                *address,
                                interface,
                            ));
                        }
                        poll.remove_listener(*token);
                        false
                    });
                }
                let attempts = if daemon_config.bind_dynamic {
                    if changed || poll.retry_bound_listeners {
                        eligible.clone()
                    } else {
                        Vec::new()
                    }
                } else {
                    pending_static_dns.clone()
                };
                poll.retry_bound_listeners = false;
                for address in attempts {
                    if !eligible.contains(&address)
                        || bound_listeners.iter().any(|(bound, _)| *bound == address)
                    {
                        continue;
                    }
                    let (udp, tcp, mut bind_errors) = if dns_addresses.contains(&address) {
                        open_late_dns_listener(address, daemon_config.bind_dynamic)
                    } else {
                        (None, None, Vec::new())
                    };
                    let mut opened = udp.is_some() || tcp.is_some();
                    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                    if let Some(tftp) = &mut poll.tftp {
                        match tftp.bind_listener(address) {
                            Ok(bound) => opened |= bound,
                            Err(error)
                                if !suppressed_listener_error(
                                    &error,
                                    daemon_config.bind_dynamic,
                                ) =>
                            {
                                bind_errors.push(error)
                            }
                            Err(_) => {}
                        }
                    }
                    #[cfg(target_os = "linux")]
                    if let Some(logger) = &mut poll.logger {
                        use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                        let mut label = address.ip().to_string();
                        if let SocketAddr::V6(address) = address {
                            if address.scope_id() != 0 {
                                if let Some(interface) = interfaces
                                    .iter()
                                    .find(|interface| interface.index == address.scope_id())
                                {
                                    label.push('%');
                                    label.push_str(&String::from_utf8_lossy(interface.link_name()));
                                }
                            }
                        }
                        for error in bind_errors {
                            logger.emit(LogEvent::new(
                                Service::Dns,
                                Priority::Warning,
                                format!(
                                    "failed to create listening socket for {label}: {}",
                                    dnsmasq_rs::logging::error_text(&error)
                                )
                                .into_bytes(),
                            ));
                        }
                    }
                    if opened {
                        #[cfg(target_os = "linux")]
                        if let Some(logger) = &mut poll.logger {
                            let interface = interfaces
                                .iter()
                                .find(|interface| interface.address == address.ip());
                            logger.emit(listener_debug_event("listening", address, interface));
                        }
                        if daemon_config.listen_addresses.contains(&address.ip())
                            && !interfaces
                                .iter()
                                .any(|interface| interface.address == address.ip())
                        {
                            persistent_unowned.push(address);
                        }
                        let token = SocketToken(next_listener);
                        next_listener += 1;
                        poll.add_listener(token, udp, tcp);
                        bound_listeners.push((address, token));
                        pending_static_dns.retain(|pending| *pending != address);
                    }
                }
            }
        }
        let signaled = !poll.reload_in_progress()
            && RELOAD_REQUESTED
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    count.checked_sub(1)
                })
                .is_ok();
        let file_reload = std::mem::take(&mut poll.full_reload_pending);
        if signaled || file_reload {
            poll.reload_data(runtime.scalar.local_ttl)?;
            #[cfg(target_os = "linux")]
            if signaled {
                if let Some(files) = &mut poll.dns_files {
                    files.request(ReloadReason::Signal);
                }
            }
        }
        {
            let mut event = parent_events
                .lock()
                .map_err(|_| io::Error::other("parent event lock poisoned"))?;
            let metrics = poll.metrics(&event);
            event.process_ubus(&metrics);
        }
        poll.wait_for_files()?;
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(neighbors) = &mut poll.neighbors {
        neighbors.discard_script_changes();
    }
    #[cfg(target_os = "linux")]
    if let Some(files) = &mut poll.dns_files {
        files.begin_shutdown();
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    loop {
        let lookups_drained = poll
            .dns_files
            .as_mut()
            .is_none_or(DnsFiles::lookups_drained);
        let helper_drained = poll.step_helper_shutdown();
        let drained = lookups_drained && helper_drained;
        if let Some(error) = poll.helper_init_error.take() {
            pid_file.cleanup();
            return Err(Box::new(error));
        }
        if drained {
            break;
        }
        // EVENT_TERM drains sources and command bytes, not script execution.
        // Keep IPC and init processing nonblocking in the same poll owner.
        let mut fds = Vec::new();
        if let Some(helper) = &poll.helper {
            for (fd, events) in helper.poll_fds() {
                if fd >= 0 {
                    fds.push(owrt_ubus::sys::PollFd {
                        fd,
                        events,
                        revents: 0,
                    });
                }
            }
        }
        if let Some(files) = &poll.dns_files {
            files.append_poll_fds(&mut fds);
        }
        owrt_ubus::sys::poll_fds(&mut fds, 2)?;
    }
    #[cfg(target_os = "linux")]
    if let Some(logger) = &mut poll.logger {
        use dnsmasq_rs::logging::{LogEvent, Priority, Service};
        logger.emit(LogEvent::new(
            Service::Dns,
            Priority::Info,
            b"exiting on receipt of SIGTERM".to_vec(),
        ));
        let deadline = Instant::now() + Duration::from_millis(100);
        while !logger.finish() && Instant::now() < deadline {
            let mut fds: Vec<_> = logger
                .poll_fds()
                .map(|fd| owrt_ubus::sys::PollFd {
                    fd,
                    events: owrt_ubus::sys::POLLOUT,
                    revents: 0,
                })
                .collect();
            owrt_ubus::sys::poll_fds(&mut fds, 2)?;
        }
    }
    #[cfg(target_os = "linux")]
    pid_file.cleanup();
    Ok(())
}

#[cfg(target_os = "linux")]
fn listener_debug_event(
    action: &str,
    address: SocketAddr,
    interface: Option<&DnsInterface>,
) -> dnsmasq_rs::logging::LogEvent {
    use dnsmasq_rs::logging::{address_text, LogEvent, Priority, Service};
    let mut message = format!("{action} on ").into_bytes();
    if let Some(interface) = interface {
        message.extend_from_slice(&interface.name);
        message.extend_from_slice(format!("(#{}): ", interface.index).as_bytes());
    }
    message.extend_from_slice(&address_text(address));
    message.extend_from_slice(format!(" port {}", address.port()).as_bytes());
    LogEvent::new(Service::Debug, Priority::Debug, message)
}

fn dns_local_addresses(
    config: &DnsConfig,
    interfaces: &[DnsInterface],
    port: u16,
) -> Vec<SocketAddr> {
    interfaces
        .iter()
        .filter(|interface| listeners::selected(config, interface))
        .map(|interface| match interface.address {
            IpAddr::V6(ip) if ip.is_unicast_link_local() => {
                SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, interface.index))
            }
            address => SocketAddr::new(address, port),
        })
        .collect()
}

type DnsListenerPair = (Option<Arc<DnsSocket>>, Option<TcpListener>);

fn suppressed_listener_error(error: &io::Error, dynamic: bool) -> bool {
    listeners::is_unsupported_socket_error(error)
        || dynamic && error.kind() == io::ErrorKind::AddrNotAvailable
}

fn optional_listener<T>(result: io::Result<T>, dynamic: bool) -> io::Result<Option<T>> {
    match result {
        Ok(listener) => Ok(Some(listener)),
        Err(error) if suppressed_listener_error(&error, dynamic) => Ok(None),
        Err(error) => Err(error),
    }
}

fn open_dns_listener(address: SocketAddr, dynamic: bool) -> io::Result<DnsListenerPair> {
    let udp = optional_listener(DnsSocket::bind(address), dynamic)?.map(Arc::new);
    let tcp = optional_listener(listeners::tcp_bind(address), dynamic)?;
    if let Some(tcp) = &tcp {
        tcp.set_nonblocking(true)?;
    }
    Ok((udp, tcp))
}

/// Runtime listener creation preserves independently successful transports.
/// The owner records the address once any DNS/TFTP socket succeeds, like
/// C iface->done, and never fills in a failed half until that address retires.
fn open_late_dns_listener(
    address: SocketAddr,
    dynamic: bool,
) -> (Option<Arc<DnsSocket>>, Option<TcpListener>, Vec<io::Error>) {
    let mut errors = Vec::new();
    let udp = match optional_listener(DnsSocket::bind(address), dynamic) {
        Ok(socket) => socket.map(Arc::new),
        Err(error) => {
            errors.push(error);
            None
        }
    };
    let tcp = match optional_listener(
        listeners::tcp_bind(address).and_then(|tcp| {
            tcp.set_nonblocking(true)?;
            Ok(tcp)
        }),
        dynamic,
    ) {
        Ok(socket) => socket,
        Err(error) => {
            errors.push(error);
            None
        }
    };
    (udp, tcp, errors)
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
struct DhcpService {
    provider: Option<Arc<Mutex<DhcpProvider>>>,
    listener: DhcpSocketListener,
    pxe_next: bool,
}

/// The production event owner. All daemon sockets are advanced from the
/// caller's loop; no listener or TCP connection gets a worker thread.
struct SinglePoll {
    listeners: Vec<PollListener>,
    clients: Vec<PollTcpClient>,
    pending_edns_udp: Vec<PendingEdnsUdp>,
    service: Arc<Mutex<ParentDns>>,
    parent_events: Arc<Mutex<ParentEvents>>,
    interfaces: Arc<Mutex<Vec<DnsInterface>>>,
    config: DnsConfig,
    resolvers: Vec<SocketAddr>,
    packet_limit: usize,
    tcp_limit: usize,
    edns_max: u16,
    probe_metrics: Option<Metrics>,
    full_reload_pending: bool,
    retry_bound_listeners: bool,
    interfaces_enumerated: bool,
    pending_interface_udp: Option<PendingInterfaceUdp>,
    pending_interface_tcp: Option<PendingInterfaceTcp>,
    pending_interface_server_check: bool,
    #[cfg(target_os = "linux")]
    pending_interface_files: Option<(dnsmasq_rs::dns::files::FileStep, bool)>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    interface_collector: Option<dnsmasq_rs::dns::interface_collect::InterfaceCollector>,
    #[cfg(target_os = "linux")]
    logger: Option<dnsmasq_rs::logging::Logger>,
    #[cfg(target_os = "linux")]
    early_logger: Option<dnsmasq_rs::logging::Logger>,
    #[cfg(target_os = "linux")]
    log_cleared_cache: bool,
    #[cfg(target_os = "linux")]
    dns_files: Option<DnsFiles>,
    #[cfg(target_os = "linux")]
    route_watch: Option<RouteWatch>,
    #[cfg(target_os = "linux")]
    files_runnable: bool,
    #[cfg(target_os = "linux")]
    dns_port: u16,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    dhcp: Option<DhcpService>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    helper: Option<Helper>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    helper_init: Option<dnsmasq_rs::dhcp::lease_file::LeaseFile>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    helper_init_end: bool,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    helper_init_error: Option<dnsmasq_rs::helper::StartError>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pending_delivery: Option<LeaseDelivery>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    probe_tftp_macs: Vec<(std::net::Ipv4Addr, [u8; 6])>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    tftp: Option<TftpListener<RealFileOpener>>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    neighbors: Option<NeighborCache>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    script_arp: bool,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    arp_awake: bool,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    tftp_parent_wake: Option<Instant>,
}

struct PollListener {
    token: SocketToken,
    udp: Option<Arc<DnsSocket>>,
    tcp: Option<TcpListener>,
}

// Both EDNS queues are advanced by the existing owner. The UDP queue retains
// the receiving listener token; TCP pending MAC work counts against tcp_limit.
const MAX_EDNS_UDP_WAITERS: usize = 256;
struct PendingEdnsUdp {
    listener: SocketToken,
    client: ClientRequest,
    query: Vec<u8>,
    deadline: Instant,
}
struct PendingInterfaceUdp {
    token: SocketToken,
    udp: Arc<DnsSocket>,
    client: ClientRequest,
    query: Vec<u8>,
    mac: Option<Vec<u8>>,
}
struct PendingInterfaceTcp {
    stream: TcpStream,
    peer: SocketAddr,
    local_network: Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)>,
    mac: Option<Vec<u8>>,
    mac_ready: bool,
    mac_deferred: bool,
    accept_clock: i64,
}

enum ClientMacLookup {
    Ready(Option<Vec<u8>>),
    Pending,
}
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn lookup_edns_mac(
    neighbors: &mut Option<NeighborCache>,
    source: IpAddr,
    lazy: bool,
) -> ClientMacLookup {
    use dnsmasq_rs::neighbors::EdnsMacLookup;
    match neighbors
        .as_mut()
        .map(|neighbors| neighbors.query_edns(source, lazy, now_seconds() as u64))
    {
        Some(EdnsMacLookup::Pending) => ClientMacLookup::Pending,
        Some(EdnsMacLookup::Ready(mac)) => ClientMacLookup::Ready(mac),
        None => ClientMacLookup::Ready(None),
    }
}

struct PollTcpClient {
    #[cfg(target_os = "linux")]
    log_context: Option<dnsmasq_rs::logging::TcpLogContext>,
    network_done: bool,
    stream: Option<TcpStream>,
    service: LocalDnsService,
    forward: TcpDnsService,
    framer: TcpFramer,
    deadline: Instant,
    queries: usize,
    input: Vec<u8>,
    input_offset: usize,
    phase: TcpClientPhase,
    source: IpAddr,
    mac: Option<Vec<u8>>,
    mac_ready: bool,
    mac_deferred: bool,
    mac_deadline: Instant,
    packet_limit: usize,
    parent_cache_activity: bool,
    cache_view: Option<dnsmasq_rs::dns::cache::Cache>,
    cache_counters: dnsmasq_rs::dns::cache::CacheCounters,
    cache_negative: bool,
    cache_negative_ttl: u64,
    cache_debug: bool,
    accept_clock: i64,
    no_cache: bool,
    stale_query: Option<Vec<u8>>,
    refreshing_stale: bool,
}

enum TcpClientPhase {
    Reading,
    WaitingMac { query: Vec<u8> },
    Forwarding { no_cache: bool, wait: TcpWait },
    Writing { frame: Vec<u8>, offset: usize },
}

impl PollTcpClient {
    fn queue_answer(
        &mut self,
        _parent: &Arc<Mutex<ParentDns>>,
        packet: Vec<u8>,
        _insert_cache: bool,
    ) -> Result<(), ()> {
        self.phase = TcpClientPhase::Writing {
            frame: encode_tcp_frame(&packet).map_err(|_| ())?,
            offset: 0,
        };
        Ok(())
    }

    fn run_forward(
        &mut self,
        parent: &Arc<Mutex<ParentDns>>,
        query: Option<&[u8]>,
        no_cache: bool,
    ) -> Result<TcpServiceProgress, ()> {
        let now = self.accept_clock;
        let local = &self.service;
        let debug = self.cache_debug;
        let negative = self.cache_negative;
        let negative_ttl = self.cache_negative_ttl;
        let view = &mut self.cache_view;
        let counters = &mut self.cache_counters;
        let mut transaction = None;
        let mut sink = |packet: &mut Vec<u8>,
                        policy: &dnsmasq_rs::dns::process::AddressPolicy,
                        rcode,
                        mode|
         -> Result<(), dnsmasq_rs::dns::wire::WireError> {
            if debug {
                let mut owner = parent
                    .lock()
                    .map_err(|_| dnsmasq_rs::dns::wire::WireError::InvalidName)?;
                if let Some(daemon) = owner.daemon.as_mut() {
                    daemon.tcp_current_extract(packet, policy, now, rcode, mode)?;
                }
            } else if let Some(cache) = view.as_mut() {
                transaction = dnsmasq_rs::dns::daemon::DnsDaemon::<
                    dnsmasq_rs::dns::upstream::OsRandom,
                >::tcp_view_extract(
                    cache,
                    counters,
                    packet,
                    local,
                    policy,
                    now,
                    rcode,
                    mode,
                    negative,
                    negative_ttl,
                )?;
            }
            Ok(())
        };
        let progress = if let Some(query) = query {
            self.forward.start_with_local_upstream_cache(
                query,
                local,
                self.deadline,
                no_cache,
                now,
                &mut sink,
            )
        } else {
            self.forward
                .step_with_local_upstream_cache(local, no_cache, now, &mut sink)
        }
        .map_err(|_| ())?;
        if let Some(transaction) = transaction {
            self.parent_cache_activity = true;
            let mut owner = parent.lock().map_err(|_| ())?;
            if let Some(daemon) = owner.daemon.as_mut() {
                daemon.import_tcp_cache_transfer(transaction, now_seconds());
            }
        }
        Ok(progress)
    }

    fn answer_query(
        &mut self,
        mut query: Vec<u8>,
        parent: &Arc<Mutex<ParentDns>>,
    ) -> Result<(), ()> {
        let decoration = dnsmasq_rs::dns::edns_policy::decorate(
            &mut query,
            &self.service.config.edns,
            self.source,
            self.mac.as_deref(),
            self.service.edns_packet_max,
            self.packet_limit,
        )
        .map_err(|_| ())?;
        self.no_cache = !decoration.cacheable;
        let now = self.accept_clock;
        let mut stale = false;
        let answered = if self.cache_debug {
            let mut owner = parent.lock().map_err(|_| ())?;
            let daemon = owner.daemon.as_mut().ok_or(())?;
            let cached = if decoration.cacheable {
                Some(daemon.tcp_current_answer(&query, now).map_err(|_| ())?)
            } else {
                None
            };
            stale = cached.as_ref().is_some_and(|answer| answer.stale);
            cached.and_then(|answer| answer.packet).or_else(|| {
                daemon
                    .local_tcp_answer(&query, &mut self.service, now)
                    .ok()
                    .flatten()
            })
        } else {
            let cached = if decoration.cacheable {
                self.cache_view
                    .as_mut()
                    .map(|cache| {
                        dnsmasq_rs::dns::daemon::DnsDaemon::<dnsmasq_rs::dns::upstream::OsRandom>::tcp_view_answer(
                            cache,
                            &query,
                            &mut self.service,
                            now,
                            self.cache_negative,
                            self.cache_negative_ttl,
                        )
                    })
                    .transpose()
                    .map_err(|_| ())?
            } else {
                None
            };
            stale = cached.as_ref().is_some_and(|answer| answer.stale);
            cached.and_then(|answer| answer.packet).or_else(|| {
                dnsmasq_rs::dns::daemon::DnsDaemon::<dnsmasq_rs::dns::upstream::OsRandom>::tcp_view_local_answer(
                    self.cache_view.as_mut(),
                    &query,
                    &mut self.service,
                    now,
                )
                .ok()
                .flatten()
            })
        };
        if let Some(packet) = answered {
            if stale {
                self.stale_query = Some(query);
            }
            self.queue_answer(parent, packet, false)?;
        } else {
            match self.run_forward(parent, Some(&query), self.no_cache)? {
                TcpServiceProgress::Pending(wait) => {
                    self.phase = TcpClientPhase::Forwarding {
                        no_cache: self.no_cache,
                        wait,
                    }
                }
                TcpServiceProgress::Complete(packet, _) => {
                    self.queue_answer(parent, packet, false)?
                }
            }
        }
        Ok(())
    }

    // A small per-turn budget prevents pipelined queries on one connection
    // starving UDP/DHCP. Partial input, upstream I/O and downstream writes
    // retain their offsets; WouldBlock always yields to the service owner.
    fn step(
        &mut self,
        parent: &Arc<Mutex<ParentDns>>,
        lookup: &mut dyn FnMut(IpAddr, bool) -> ClientMacLookup,
    ) -> Result<bool, ()> {
        for _ in 0..8 {
            if Instant::now() >= self.deadline || STOP_REQUESTED.load(Ordering::Acquire) {
                return Ok(false);
            }
            match &mut self.phase {
                TcpClientPhase::WaitingMac { query } => {
                    let mac = if Instant::now() >= self.mac_deadline {
                        None
                    } else {
                        match lookup(self.source, true) {
                            ClientMacLookup::Ready(mac) => mac,
                            ClientMacLookup::Pending => return Ok(true),
                        }
                    };
                    self.mac = mac;
                    self.mac_ready = true;
                    self.mac_deferred = false;
                    let query = std::mem::take(query);
                    self.answer_query(query, parent)?;
                }
                TcpClientPhase::Writing { frame, offset } => {
                    match self.stream.as_mut().ok_or(())?.write(&frame[*offset..]) {
                        Ok(0) => return Ok(false),
                        Ok(count) => *offset += count,
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) =>
                        {
                            return Ok(true)
                        }
                        Err(_) => return Ok(false),
                    }
                    if *offset == frame.len() {
                        if self.queries == 100 {
                            return Ok(false);
                        }
                        if let Some(query) = self.stale_query.take() {
                            if let Some(stream) = self.stream.take() {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                            }
                            self.refreshing_stale = true;
                            match self.run_forward(parent, Some(&query), self.no_cache)? {
                                TcpServiceProgress::Pending(wait) => {
                                    self.phase = TcpClientPhase::Forwarding {
                                        no_cache: self.no_cache,
                                        wait,
                                    };
                                    return Ok(true);
                                }
                                TcpServiceProgress::Complete(_, _) => return Ok(false),
                            }
                        }
                        self.phase = TcpClientPhase::Reading;
                    }
                }
                TcpClientPhase::Forwarding { no_cache, wait } => {
                    if wait.fd >= 0 && Instant::now() < wait.deadline {
                        let mut readiness = [owrt_ubus::sys::PollFd {
                            fd: wait.fd,
                            events: wait.events,
                            revents: 0,
                        }];
                        if owrt_ubus::sys::poll_fds(&mut readiness, 0).map_err(|_| ())? == 0 {
                            return Ok(true);
                        }
                    }
                    let no_cache = *no_cache;
                    match self.run_forward(parent, None, no_cache)? {
                        TcpServiceProgress::Pending(wait) => {
                            self.phase = TcpClientPhase::Forwarding { no_cache, wait };
                            return Ok(true);
                        }
                        TcpServiceProgress::Complete(packet, _) => {
                            if self.refreshing_stale {
                                return Ok(false);
                            }
                            self.queue_answer(parent, packet, false)?;
                        }
                    }
                }
                TcpClientPhase::Reading => {
                    if self.input_offset == self.input.len() {
                        self.input.resize(4096, 0);
                        self.input_offset = 0;
                        match self.stream.as_mut().ok_or(())?.read(&mut self.input) {
                            Ok(0) => return Ok(false),
                            Ok(count) => self.input.truncate(count),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                                ) =>
                            {
                                self.input.clear();
                                return Ok(true);
                            }
                            Err(_) => return Ok(false),
                        }
                    }
                    let (consumed, query) = self
                        .framer
                        .push_frame(&self.input[self.input_offset..])
                        .map_err(|_| ())?;
                    self.input_offset += consumed;
                    let Some(query) = query else { continue };
                    if query.len() < 12 || query[2] & 0x80 != 0 {
                        continue;
                    }
                    self.queries += 1;
                    if !self.mac_ready {
                        match lookup(self.source, true) {
                            ClientMacLookup::Ready(mac) => {
                                self.mac = mac;
                                self.mac_ready = true;
                                self.mac_deferred = false;
                            }
                            ClientMacLookup::Pending => {
                                self.mac_deadline = Instant::now() + Duration::from_secs(3);
                                self.phase = TcpClientPhase::WaitingMac { query };
                                return Ok(true);
                            }
                        }
                    }
                    self.answer_query(query, parent)?;
                }
            }
        }
        Ok(true)
    }
}

impl SinglePoll {
    #[allow(clippy::too_many_arguments)]
    fn new(
        service: Arc<Mutex<ParentDns>>,
        parent_events: Arc<Mutex<ParentEvents>>,
        interfaces: Arc<Mutex<Vec<DnsInterface>>>,
        config: DnsConfig,
        resolvers: Vec<SocketAddr>,
        packet_limit: usize,
        tcp_limit: usize,
        edns_max: u16,
        listeners: Vec<(SocketToken, Option<Arc<DnsSocket>>, Option<TcpListener>)>,
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))] dhcp: Option<DhcpService>,
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))] helper: Option<Helper>,
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))] tftp: Option<
            TftpListener<RealFileOpener>,
        >,
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))] neighbors: Option<
            NeighborCache,
        >,
    ) -> Self {
        Self {
            listeners: listeners
                .into_iter()
                .map(|(token, udp, tcp)| PollListener { token, udp, tcp })
                .collect(),
            clients: Vec::new(),
            pending_edns_udp: Vec::new(),
            service,
            parent_events,
            interfaces,
            config,
            resolvers,
            packet_limit,
            tcp_limit,
            edns_max,
            probe_metrics: None,
            full_reload_pending: false,
            retry_bound_listeners: false,
            interfaces_enumerated: false,
            pending_interface_udp: None,
            pending_interface_tcp: None,
            pending_interface_server_check: false,
            #[cfg(target_os = "linux")]
            pending_interface_files: None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            interface_collector: None,
            #[cfg(target_os = "linux")]
            logger: None,
            #[cfg(target_os = "linux")]
            early_logger: None,
            #[cfg(target_os = "linux")]
            log_cleared_cache: false,
            #[cfg(target_os = "linux")]
            dns_files: None,
            #[cfg(target_os = "linux")]
            route_watch: None,
            #[cfg(target_os = "linux")]
            files_runnable: false,
            #[cfg(target_os = "linux")]
            dns_port: 0,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            dhcp,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            helper_init: helper
                .as_ref()
                .is_some_and(Helper::initializes_leases)
                .then(Default::default),
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            helper_init_end: false,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            helper_init_error: None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            helper,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            pending_delivery: None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            probe_tftp_macs: Vec::new(),
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            tftp,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            neighbors,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            script_arp: false,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            arp_awake: true,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            tftp_parent_wake: None,
        }
    }

    fn reload_data(&mut self, local_ttl: u32) -> io::Result<()> {
        let _event = self
            .parent_events
            .lock()
            .map_err(|_| io::Error::other("parent event lock poisoned"))?;
        let mut parent = self
            .service
            .lock()
            .map_err(|_| io::Error::other("DNS state lock poisoned"))?;
        if parent.daemon.is_some() {
            let hosts = read_hosts(&self.config, local_ttl);
            parent.daemon.as_mut().unwrap().reload_hosts(hosts.clone());
            parent.local.hosts = hosts;
            let ParentDns { local, daemon } = &mut *parent;
            local.leases = Arc::new(daemon.as_mut().unwrap().rebuild_lease_names(
                &local.leases,
                &mut local.hosts,
                &local.config.records.cnames,
            ));
        }
        drop(parent);
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
            let mut provider = provider
                .lock()
                .map_err(|_| io::Error::other("DHCP state lock poisoned"))?;
            report_dhcp_maintenance(
                &provider.reload_data_files(now_seconds()),
                self.logger.as_mut(),
            );
        }
        #[cfg(target_os = "linux")]
        if self.log_cleared_cache {
            if let Some(logger) = &mut self.logger {
                use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                logger.emit(LogEvent::new(
                    Service::Dns,
                    Priority::Info,
                    b"cleared cache".to_vec(),
                ));
            }
        }
        Ok(())
    }

    fn reload_in_progress(&self) -> bool {
        if self.interface_work_pending() {
            return true;
        }
        if self.dhcp_reload_in_progress() {
            return true;
        }
        #[cfg(target_os = "linux")]
        {
            self.dns_files.as_ref().is_some_and(DnsFiles::has_work)
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn dhcp_reload_in_progress(&self) -> bool {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self
            .dhcp
            .as_ref()
            .and_then(|dhcp| dhcp.provider.as_ref())
            .is_some_and(|provider| provider.lock().unwrap().file_work_pending())
        {
            return true;
        }
        false
    }

    fn files_initializing(&self) -> bool {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self
            .dhcp
            .as_ref()
            .and_then(|dhcp| dhcp.provider.as_ref())
            .is_some_and(|provider| provider.lock().unwrap().files_initializing())
        {
            return true;
        }
        #[cfg(target_os = "linux")]
        {
            self.dns_files.as_ref().is_some_and(DnsFiles::initializing)
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    #[cfg(target_os = "linux")]
    fn step_dns_files(&mut self) {
        if self.interface_work_pending() {
            return;
        }
        // inotify_check finishes dynamic DHCP input before poll_resolv applies
        // a resolver-triggered full reload. Yield file work across owner turns
        // while preserving that order; ordinary DNS/TFTP still run each turn.
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self
            .dhcp
            .as_ref()
            .and_then(|dhcp| dhcp.provider.as_ref())
            .is_some_and(|provider| {
                let provider = provider.lock().unwrap();
                provider.file_work_pending() || provider.files_runnable()
            })
        {
            return;
        }
        let Some(files) = &mut self.dns_files else {
            return;
        };
        if self
            .route_watch
            .as_mut()
            .is_some_and(|watch| watch.read_events().unwrap_or(false))
        {
            files.request(ReloadReason::Route);
            self.retry_bound_listeners = true;
        }
        let was_initializing = files.initializing();
        let step = files.step();
        let initial_finished = was_initializing && !files.initializing();
        self.files_runnable = step.runnable;
        let checks_servers = step.update.is_some()
            || ((initial_finished || step.signal_complete)
                && (self.config.servers_file.is_some()
                    || (self.config.no_poll && !self.config.no_resolv)));
        if checks_servers && !self.config.bind_interfaces {
            self.enumerate_interface_records();
            if self.interface_work_pending() {
                self.pending_interface_files = Some((step, initial_finished));
                return;
            }
        }
        self.apply_dns_file_step(step, initial_finished);
    }

    #[cfg(target_os = "linux")]
    fn apply_dns_file_step(
        &mut self,
        step: dnsmasq_rs::dns::files::FileStep,
        initial_finished: bool,
    ) {
        if let Some(logger) = &mut self.logger {
            use dnsmasq_rs::logging::{LogEvent, Priority, Service};
            for diagnostic in step.diagnostics {
                use dnsmasq_rs::dns::files::FileDiagnostic;
                let priority = match &diagnostic {
                    FileDiagnostic::Access { .. } | FileDiagnostic::EmptyResolvers(_) => {
                        Priority::Warning
                    }
                    FileDiagnostic::ReadingResolvers(_) => Priority::Info,
                    _ => Priority::Error,
                };
                logger.emit(LogEvent::new(
                    Service::Dns,
                    priority,
                    diagnostic.to_string().into_bytes(),
                ));
            }
        }
        if let Some(update) = step.update {
            let addresses = dns_local_addresses(
                &self.config,
                &self.interfaces.lock().unwrap(),
                self.dns_port,
            );
            let mut parent = self.service.lock().unwrap();
            if let Some(daemon) = &mut parent.daemon {
                match daemon.replace_server_source(update.source, update.rows, &addresses) {
                    Ok(()) => {
                        parent.local.config = daemon.local_config().clone();
                        self.full_reload_pending |= update.full_reload;
                    }
                    Err(error) => eprintln!("dnsmasq-rs: {error}"),
                }
            }
        }
        self.log_dns_diagnostics();
        if step.initial_cache_reload {
            self.parent_events
                .lock()
                .unwrap()
                .queue_missing_ubus_notice();
            if let Some(logger) = &mut self.logger {
                for notice in self.parent_events.lock().unwrap().ubus_notices.drain(..) {
                    logger.emit(notice);
                }
            }
        }
        if step.initial_cache_reload && self.log_cleared_cache {
            if let Some(logger) = &mut self.logger {
                use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                logger.emit(LogEvent::new(
                    Service::Dns,
                    Priority::Info,
                    b"cleared cache".to_vec(),
                ));
            }
        }
        // read_servers_file checks internally on success; EVENT_INIT/RELOAD
        // also checks once after its no-poll and servers-file calls, even errors.
        if (initial_finished || step.signal_complete)
            && (self.config.servers_file.is_some()
                || (self.config.no_poll
                    && !self.config.no_resolv
                    && !self.config.resolv_files.is_empty()))
        {
            {
                let mut parent = self.service.lock().unwrap();
                if let Some(daemon) = &mut parent.daemon {
                    daemon.queue_server_notices();
                }
            }
            self.log_dns_diagnostics();
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if step.signal_complete {
            if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
                provider.lock().unwrap().rerun_scripts();
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_dhcp_files(&mut self) {
        if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
            if let Some(report) = provider.lock().unwrap().step_files(now_seconds()) {
                report_dhcp_maintenance(&report, self.logger.as_mut());
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn append_file_fds(&self, fds: &mut Vec<owrt_ubus::sys::PollFd>, tcp_logs: bool) {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(collector) = &self.interface_collector {
            collector.append_poll_fds(fds);
        }
        if let Some(logger) = &self.early_logger {
            for fd in logger.poll_fds() {
                fds.push(owrt_ubus::sys::PollFd {
                    fd,
                    events: owrt_ubus::sys::POLLOUT,
                    revents: 0,
                });
            }
        }
        if let Some(logger) = &self.logger {
            for context in self
                .clients
                .iter()
                .filter(|_| tcp_logs)
                .filter_map(|client| client.log_context.as_ref())
            {
                if let Some(fd) = logger.tcp_poll_fd(context) {
                    fds.push(owrt_ubus::sys::PollFd {
                        fd,
                        events: owrt_ubus::sys::POLLOUT,
                        revents: 0,
                    });
                }
            }
            for fd in logger.poll_fds() {
                fds.push(owrt_ubus::sys::PollFd {
                    fd,
                    events: owrt_ubus::sys::POLLOUT,
                    revents: 0,
                });
            }
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
            provider.lock().unwrap().append_file_fds(fds);
        }
        if let Some(files) = &self.dns_files {
            files.append_poll_fds(fds);
        }
        if let Some(watch) = &self.route_watch {
            watch.append_poll_fds(fds);
        }
    }

    fn wait_for_files(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let mut fds = Vec::new();
            self.append_file_fds(&mut fds, true);
            let mut runnable = self.files_runnable;
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
                runnable |= provider.lock().unwrap().files_runnable();
            }
            owrt_ubus::sys::poll_fds(&mut fds, if runnable { 0 } else { 2 })?;
        }
        #[cfg(not(target_os = "linux"))]
        thread::park_timeout(Duration::from_millis(2));
        Ok(())
    }

    fn add_listener(
        &mut self,
        token: SocketToken,
        udp: Option<Arc<DnsSocket>>,
        tcp: Option<TcpListener>,
    ) {
        self.listeners.push(PollListener { token, udp, tcp });
    }

    fn remove_listener(&mut self, token: SocketToken) {
        self.listeners.retain(|listener| listener.token != token);
    }

    // Every UBus entry point uses the same complete snapshot. In particular,
    // idle UDP completion must not answer a metrics call with zero DHCP fields.
    fn metrics(&self, event: &ParentEvents) -> Metrics {
        let mut metrics = self.probe_metrics.unwrap_or_default();
        event.write_metrics(&mut metrics);
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
            write_dhcp_metrics(&mut metrics, &provider.lock().unwrap());
        }
        let parent = self.service.lock().unwrap();
        if let Some(daemon) = &parent.daemon {
            write_dns_metrics(
                &mut metrics,
                daemon.cache_counters(),
                daemon.forward_counters(),
                event.local_answered,
            );
        }
        metrics
    }

    fn step(&mut self) {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.step_interface_collector();
        #[cfg(target_os = "linux")]
        if let Some(logger) = &mut self.early_logger {
            logger.flush_ready();
        }
        #[cfg(target_os = "linux")]
        if let Some(logger) = &mut self.logger {
            if LOG_REOPEN_REQUESTED
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    count.checked_sub(1)
                })
                .is_ok()
            {
                let _ = logger.reopen();
            }
            logger.flush_ready();
        }
        // C drains subscription/metrics requests before processing DHCP.
        // This also applies to port=0, where no DNS listener can drain UBus.
        {
            let mut event = self.parent_events.lock().unwrap();
            let metrics = self.metrics(&event);
            event.process_ubus(&metrics);
        }
        #[cfg(target_os = "linux")]
        if let Some(logger) = &mut self.logger {
            for notice in self.parent_events.lock().unwrap().ubus_notices.drain(..) {
                logger.emit(notice);
            }
        }
        // Bound work per turn.  This keeps a busy UDP socket from starving
        // DHCP, TFTP, reload and TCP admission.
        let listeners = self.listeners.len();
        for index in 0..listeners {
            self.step_udp(index);
            self.step_tcp_accept(index);
        }
        self.poll_udp_completions();
        self.step_tcp_clients();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.step_dhcp();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.step_neighbors();
        self.step_edns_udp();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.step_tftp();
        #[cfg(target_os = "linux")]
        self.log_dns_diagnostics();
    }

    #[cfg(target_os = "linux")]
    fn log_dns_diagnostics(&mut self) {
        use dnsmasq_rs::logging::{LogEvent, Priority, Service};
        let Some(logger) = &mut self.logger else {
            return;
        };
        let mut parent = self.service.lock().unwrap();
        let Some(daemon) = &mut parent.daemon else {
            return;
        };
        for warning in daemon.take_source_warnings() {
            logger.emit(LogEvent::new(
                Service::Dns,
                Priority::Warning,
                warning.into_bytes(),
            ));
        }
        for diagnostic in daemon.take_source_diagnostics() {
            logger.emit(LogEvent::new(
                Service::Dns,
                Priority::Error,
                diagnostic.to_string().into_bytes(),
            ));
        }
        for event in daemon.take_server_notices() {
            logger.emit(event);
        }
    }

    fn enumerate_interface_records(&mut self) {
        if self.interfaces_enumerated {
            return;
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self.interface_work_pending() {
            return;
        }
        self.interfaces_enumerated = true;
        if self.config.interface_records.rules.is_empty() {
            if let Some(daemon) = &mut self.service.lock().unwrap().daemon {
                daemon.refresh_source_interface_indices();
            }
            return;
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            if self.interface_collector.is_none() {
                self.interface_collector =
                    dnsmasq_rs::dns::interface_collect::InterfaceCollector::new().ok();
            }
            let Some(collector) = &mut self.interface_collector else {
                return;
            };
            // A control-socket failure happens before C clears its published
            // lists. Later netlink errors are completed by the owner and
            // publish the received prefix as a new snapshot.
            let _ = collector.begin();
        }
    }

    fn interface_work_pending(&self) -> bool {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            return self
                .interface_collector
                .as_ref()
                .is_some_and(|collector| collector.busy());
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        {
            false
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_interface_collector(&mut self) {
        let Some(collector) = &mut self.interface_collector else {
            return;
        };
        let mut completed = None;
        for _ in 0..4 {
            if let Some(result) = collector.step() {
                completed = Some(result);
                break;
            }
            if !collector.runnable() {
                break;
            }
        }
        let Some(result) = completed else {
            return;
        };
        // This resumed continuation belongs to the enumeration already
        // selected by its original caller, even across owner turns.
        self.interfaces_enumerated = true;
        if result.error.is_none() {
            *self.interfaces.lock().unwrap() = result.interfaces;
        }
        let records = Arc::new(
            dnsmasq_rs::dns::interface_records::InterfaceRecords::from_addresses(
                &self.config.interface_records.rules,
                &result.addresses,
            ),
        );
        {
            let mut parent = self.service.lock().unwrap();
            parent.local.interfaces = Arc::clone(&records);
            if let Some(daemon) = &mut parent.daemon {
                daemon.refresh_source_interface_indices();
                daemon.publish_interface_records(records);
            }
        }
        if std::mem::take(&mut self.pending_interface_server_check) {
            let addresses = dns_local_addresses(
                &self.config,
                &self.interfaces.lock().unwrap(),
                self.dns_port,
            );
            let mut parent = self.service.lock().unwrap();
            if let Some(daemon) = &mut parent.daemon {
                if let Err(error) = daemon.check_server_addresses(&addresses) {
                    eprintln!("dnsmasq-rs: {error}");
                }
                parent.local.config = daemon.local_config().clone();
            }
        }
        #[cfg(target_os = "linux")]
        if let Some((step, initial_finished)) = self.pending_interface_files.take() {
            self.apply_dns_file_step(step, initial_finished);
        }
        if let Some(pending) = self.pending_interface_udp.take() {
            self.process_udp(
                pending.token,
                pending.udp,
                pending.client,
                pending.query,
                pending.mac,
            );
        }
        if let Some(pending) = self.pending_interface_tcp.take() {
            self.finish_tcp_accept(pending);
        }
    }

    fn step_udp(&mut self, index: usize) {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self.interface_work_pending() {
            return;
        }
        if self.files_initializing() {
            return;
        }
        let Some(udp) = self.listeners[index].udp.as_ref().map(Arc::clone) else {
            return;
        };
        let token = self.listeners[index].token;
        let mut query = vec![0; 65_535];
        let incoming = match udp.receive(&mut query) {
            Ok(Some(incoming)) if incoming.len <= usize::from(self.edns_max) => incoming,
            Ok(_) => {
                self.poll_udp_completions();
                return;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                self.poll_udp_completions();
                return;
            }
            Err(_) => return,
        };
        let interfaces = match self.interfaces.lock() {
            Ok(interfaces) => interfaces,
            Err(_) => return,
        };
        let admitted = listeners::admit(
            &self.config,
            &interfaces,
            incoming.peer.ip(),
            incoming.destination,
            incoming.interface,
        );
        drop(interfaces);
        if !admitted {
            self.poll_udp_completions();
            return;
        }
        query.truncate(incoming.len);
        let client = ClientRequest {
            source: incoming.peer,
            destination: incoming.destination,
            interface: incoming.interface,
        };
        let needs_mac = self.config.edns.needs_mac()
            && matches!(
                dnsmasq_rs::dns::udp_query::inspect(&query, self.edns_max),
                dnsmasq_rs::dns::udp_query::Admission::Continue,
            );
        let lookup = if needs_mac {
            self.edns_mac(client.source.ip(), true)
        } else {
            ClientMacLookup::Ready(None)
        };
        match lookup {
            ClientMacLookup::Ready(mac) => self.process_udp(token, udp, client, query, mac),
            ClientMacLookup::Pending if self.pending_edns_udp.len() < MAX_EDNS_UDP_WAITERS => {
                self.pending_edns_udp.push(PendingEdnsUdp {
                    listener: token,
                    client,
                    query,
                    deadline: Instant::now() + Duration::from_secs(3),
                });
            }
            ClientMacLookup::Pending => {} // bounded admission; kernel-style drop
        }
    }

    fn edns_mac(&mut self, source: IpAddr, lazy: bool) -> ClientMacLookup {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            lookup_edns_mac(&mut self.neighbors, source, lazy)
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        {
            let _ = (source, lazy);
            ClientMacLookup::Ready(None)
        }
    }

    fn step_edns_udp(&mut self) {
        let mut index = 0;
        let mut progressed = 0;
        while index < self.pending_edns_udp.len() && progressed < 32 {
            if self.interface_work_pending() {
                break;
            }
            let source = self.pending_edns_udp[index].client.source.ip();
            let lookup = if Instant::now() >= self.pending_edns_udp[index].deadline {
                ClientMacLookup::Ready(None)
            } else {
                self.edns_mac(source, true)
            };
            let ClientMacLookup::Ready(mac) = lookup else {
                index += 1;
                continue;
            };
            let pending = self.pending_edns_udp.remove(index);
            let udp = self
                .listeners
                .iter()
                .find(|listener| listener.token == pending.listener)
                .and_then(|listener| listener.udp.as_ref())
                .map(Arc::clone);
            if let Some(udp) = udp {
                self.process_udp(pending.listener, udp, pending.client, pending.query, mac);
            }
            progressed += 1;
        }
    }

    fn process_udp(
        &mut self,
        token: SocketToken,
        udp: Arc<DnsSocket>,
        client: ClientRequest,
        query: Vec<u8>,
        mac: Option<Vec<u8>>,
    ) {
        let mut event = match self.parent_events.lock() {
            Ok(event) => event,
            Err(_) => return,
        };
        let mut metrics = self.metrics(&event);
        let mut parent = match self.service.lock() {
            Ok(parent) => parent,
            Err(_) => return,
        };
        let ParentDns { local, daemon } = &mut *parent;
        let Some(daemon) = daemon.as_mut() else {
            return;
        };
        write_dns_metrics(
            &mut metrics,
            daemon.cache_counters(),
            daemon.forward_counters(),
            event.local_answered,
        );
        if self.probe_metrics.is_none() {
            event.process_ubus(&metrics);
        }
        if let Ok(interfaces) = self.interfaces.lock() {
            local.local_network = listeners::local_network(&interfaces, client.destination);
        }
        let packet = &query[..];
        let mut decorated = query.clone();
        let mut metadata = None;
        let answer = match dnsmasq_rs::dns::udp_query::inspect(packet, local.edns_packet_max) {
            dnsmasq_rs::dns::udp_query::Admission::Drop => return,
            dnsmasq_rs::dns::udp_query::Admission::Reply(answer) => Some((answer, false)),
            dnsmasq_rs::dns::udp_query::Admission::Continue => {
                let Ok((_, original_metadata)) =
                    dnsmasq_rs::dns::forward_service::prepare_query(packet, self.edns_max)
                else {
                    return;
                };
                let Ok(decoration) = dnsmasq_rs::dns::edns_policy::decorate(
                    &mut decorated,
                    &self.config.edns,
                    client.source.ip(),
                    mac.as_deref(),
                    self.edns_max,
                    usize::from(self.edns_max),
                ) else {
                    return;
                };
                let prepared_metadata = original_metadata.with_cacheable(decoration.cacheable);
                metadata = Some(prepared_metadata);
                let needs_interfaces =
                    dnsmasq_rs::dns::local::interface_forward_name(&self.config, packet).is_some()
                        || (decoration.cacheable
                            && daemon.interface_query_needs_enumeration(packet, now_seconds()));
                if needs_interfaces && !self.interfaces_enumerated {
                    drop(parent);
                    drop(event);
                    self.enumerate_interface_records();
                    if self.interface_work_pending() {
                        self.pending_interface_udp = Some(PendingInterfaceUdp {
                            token,
                            udp,
                            client,
                            query,
                            mac,
                        });
                    } else {
                        // An early control failure keeps the old generation.
                        self.process_udp(token, udp, client, query, mac);
                    }
                    return;
                }

                match daemon.local_udp_answer(packet, local, now_seconds()) {
                    Ok(Some(answer)) => Some((answer, false)),
                    Ok(None) => match daemon.forward_udp_prepared_with_local(
                        packet,
                        &decorated,
                        prepared_metadata,
                        ClientRequest {
                            source: client.source,
                            destination: client.destination,
                            interface: client.interface,
                        },
                        Some(token),
                        local,
                    ) {
                        Ok(QueryResult::Local(answer) | QueryResult::Cached(answer)) => {
                            Some((answer, false))
                        }
                        Ok(QueryResult::Stale(answer)) => Some((answer, true)),
                        _ => None,
                    },
                    Err(_) => None,
                }
            }
        };
        let responses = if event
            .ubus
            .as_ref()
            .is_some_and(UbusService::dns_has_subscribers)
        {
            let mut doctor = |name: &[u8], ttl, address, cache, forward| {
                write_dns_metrics(&mut metrics, cache, forward, event.local_answered);
                event.doctor(&DnsResult { name, ttl, address }, &metrics)
            };
            daemon
                .poll_with_local_doctor(Duration::ZERO, local, &mut doctor)
                .unwrap_or_default()
        } else {
            daemon
                .poll_with_local(Duration::ZERO, local)
                .unwrap_or_default()
        };
        drop(parent);
        if let Some((answer, stale)) = answer {
            let _ = udp.send(
                &answer,
                client.source,
                (!self.config.bind_interfaces && !self.config.bind_dynamic)
                    .then_some((client.destination, client.interface)),
            );
            if stale {
                event.stale_answered = event.stale_answered.wrapping_add(1);
                // Preserve dnsmasq's send-before-refresh ordering.  The
                // refresh may enqueue an upstream response for a later turn;
                // it must not hold the parent lock while that I/O completes.
                if let Ok(mut parent) = self.service.lock() {
                    if let (Some(daemon), Some(metadata)) = (parent.daemon.as_mut(), metadata) {
                        let refresh = daemon.refresh_udp_prepared_on_listener(
                            &query[..],
                            &decorated,
                            metadata,
                            ClientRequest {
                                source: client.source,
                                destination: client.destination,
                                interface: client.interface,
                            },
                            Some(token),
                        );
                        if matches!(refresh, Ok(QueryResult::Local(_))) {
                            event.local_answered = event.local_answered.wrapping_add(1);
                        }
                    }
                }
            } else {
                event.local_answered = event.local_answered.wrapping_add(1);
            }
        }
        // Responses generated by an upstream completion are sent by their
        // owning listener token.  A single owner can dispatch directly.
        for response in responses {
            let Some(token) = response.listener else {
                continue;
            };
            if let Some(target) = self
                .listeners
                .iter()
                .find(|target| target.token == token)
                .and_then(|listener| listener.udp.as_ref())
            {
                let _ = target.send(
                    &response.packet,
                    response.destination,
                    (!self.config.bind_interfaces && !self.config.bind_dynamic)
                        .then_some((response.source, response.interface)),
                );
            }
        }
    }

    fn poll_udp_completions(&mut self) {
        let mut event = match self.parent_events.lock() {
            Ok(event) => event,
            Err(_) => return,
        };
        let mut metrics = self.metrics(&event);
        let mut parent = match self.service.lock() {
            Ok(parent) => parent,
            Err(_) => return,
        };
        let ParentDns { local, daemon } = &mut *parent;
        let Some(daemon) = daemon.as_mut() else {
            return;
        };
        write_dns_metrics(
            &mut metrics,
            daemon.cache_counters(),
            daemon.forward_counters(),
            event.local_answered,
        );
        if self.probe_metrics.is_none() {
            event.process_ubus(&metrics);
        }
        let responses = if event
            .ubus
            .as_ref()
            .is_some_and(UbusService::dns_has_subscribers)
        {
            let mut doctor = |name: &[u8], ttl, address, cache, forward| {
                write_dns_metrics(&mut metrics, cache, forward, event.local_answered);
                event.doctor(&DnsResult { name, ttl, address }, &metrics)
            };
            daemon
                .poll_with_local_doctor(Duration::ZERO, local, &mut doctor)
                .unwrap_or_default()
        } else {
            daemon
                .poll_with_local(Duration::ZERO, local)
                .unwrap_or_default()
        };
        drop(parent);
        for response in responses {
            let Some(response_token) = response.listener else {
                continue;
            };
            if let Some(target) = self
                .listeners
                .iter()
                .find(|target| target.token == response_token)
                .and_then(|target| target.udp.as_ref())
            {
                let _ = target.send(
                    &response.packet,
                    response.destination,
                    (!self.config.bind_interfaces && !self.config.bind_dynamic)
                        .then_some((response.source, response.interface)),
                );
            }
        }
    }

    fn step_tcp_accept(&mut self, index: usize) {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self.interface_work_pending() {
            return;
        }
        if self.files_initializing() {
            return;
        }
        if self.clients.len() >= self.tcp_limit {
            return;
        }
        let listener = &self.listeners[index];
        let Some(tcp) = &listener.tcp else {
            return;
        };
        let Ok((stream, peer)) = tcp.accept() else {
            return;
        };
        let Ok(destination) = stream.local_addr() else {
            return;
        };
        let ingress = if self.config.bind_interfaces || self.config.bind_dynamic {
            None
        } else {
            listeners::tcp_interface(&stream, destination.is_ipv6())
        };
        let interfaces = match self.interfaces.lock() {
            Ok(interfaces) => interfaces,
            Err(_) => return,
        };
        if !listeners::admit_tcp(
            &self.config,
            &interfaces,
            peer.ip(),
            destination,
            ingress
                .as_ref()
                .map(|(name, loopback)| (name.as_slice(), *loopback)),
        ) {
            // C closes a rejected connection directly. Explicit shutdown
            // would turn a close with unread request bytes (RST) into FIN.
            return;
        }
        let local_network = listeners::local_network(&interfaces, destination.ip());
        drop(interfaces);
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let needs_mac = self.config.edns.needs_mac();
        let mac_deferred = needs_mac && DEBUG_MODE.load(Ordering::Relaxed);
        let lookup = if needs_mac && !mac_deferred {
            self.edns_mac(peer.ip(), false)
        } else {
            ClientMacLookup::Ready(None)
        };
        let (mac, mac_ready) = match lookup {
            ClientMacLookup::Ready(mac) => (mac, !mac_deferred),
            ClientMacLookup::Pending => (None, false),
        };
        let pending = PendingInterfaceTcp {
            stream,
            peer,
            local_network,
            mac,
            mac_ready,
            mac_deferred,
            accept_clock: now_seconds(),
        };
        self.enumerate_interface_records();
        if self.interface_work_pending() {
            self.pending_interface_tcp = Some(pending);
            return;
        }
        self.finish_tcp_accept(pending);
    }

    fn finish_tcp_accept(&mut self, pending: PendingInterfaceTcp) {
        let PendingInterfaceTcp {
            stream,
            peer,
            local_network,
            mac,
            mac_ready,
            mac_deferred,
            accept_clock,
        } = pending;
        let mut parent = match self.service.lock() {
            Ok(parent) => parent,
            Err(_) => return,
        };
        let mut snapshot = LocalDnsService::new_with_limits(
            parent.local.config.clone(),
            parent.local.hosts.clone(),
            parent.local.local_ttl,
            parent.local.max_udp,
            parent.local.edns_packet_max,
        );
        snapshot.leases = Arc::clone(&parent.local.leases);
        snapshot.interfaces = Arc::clone(&parent.local.interfaces);
        snapshot.local_network = local_network;
        let cache_debug = DEBUG_MODE.load(Ordering::Relaxed);
        let cache_view = (!cache_debug)
            .then(|| {
                parent
                    .daemon
                    .as_ref()
                    .and_then(|daemon| daemon.tcp_cache_view())
            })
            .flatten();
        let (cache_negative, cache_negative_ttl) = parent
            .daemon
            .as_ref()
            .map_or((true, 0), |daemon| daemon.tcp_cache_parameters());
        let forward = if let Some(daemon) = &mut parent.daemon {
            daemon.tcp_snapshot()
        } else {
            TcpDnsService::new(&self.config, &self.resolvers, self.edns_max)
        };
        drop(parent);
        let Ok(mut forward) = forward else {
            return;
        };
        forward.set_client_source(peer.ip());
        if let Ok(mut event) = self.parent_events.lock() {
            event.tcp_active = event.tcp_active.saturating_add(1);
        }
        self.clients.push(PollTcpClient {
            #[cfg(target_os = "linux")]
            log_context: (!cache_debug)
                .then(|| {
                    self.logger
                        .as_ref()
                        .map(dnsmasq_rs::logging::Logger::tcp_context)
                })
                .flatten(),
            network_done: false,
            stream: Some(stream),
            cache_view,
            cache_negative,
            cache_negative_ttl,
            cache_debug,
            accept_clock,
            cache_counters: Default::default(),
            no_cache: false,
            stale_query: None,
            refreshing_stale: false,
            service: snapshot,
            forward,
            framer: TcpFramer::with_max_frame(self.packet_limit),
            deadline: Instant::now() + Duration::from_secs(150),
            queries: 0,
            input: Vec::new(),
            input_offset: 0,
            phase: TcpClientPhase::Reading,
            source: peer.ip(),
            mac,
            mac_ready,
            mac_deferred,
            mac_deadline: Instant::now() + Duration::from_secs(3),
            packet_limit: self.packet_limit,
            parent_cache_activity: false,
        });
    }

    fn step_tcp_clients(&mut self) {
        let mut index = 0;
        while index < self.clients.len() {
            if !self.clients[index].mac_ready && !self.clients[index].mac_deferred {
                let lookup = if Instant::now() >= self.clients[index].mac_deadline {
                    ClientMacLookup::Ready(None)
                } else {
                    self.edns_mac(self.clients[index].source, true)
                };
                match lookup {
                    ClientMacLookup::Ready(mac) => {
                        self.clients[index].mac = mac;
                        self.clients[index].mac_ready = true;
                    }
                    ClientMacLookup::Pending => {
                        index += 1;
                        continue;
                    }
                }
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            let result = if self.clients[index].network_done {
                Ok(false)
            } else {
                let neighbors = &mut self.neighbors;
                self.clients[index].step(&self.service, &mut |source, lazy| {
                    lookup_edns_mac(neighbors, source, lazy)
                })
            };
            #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
            let result = if self.clients[index].network_done {
                Ok(false)
            } else {
                self.clients[index].step(&self.service, &mut |_, _| ClientMacLookup::Ready(None))
            };
            #[cfg(target_os = "linux")]
            if let Some(logger) = &mut self.logger {
                use dnsmasq_rs::logging::{address_text, LogEvent, Priority, Service};
                for address in self.clients[index].forward.take_connection_failures() {
                    let mut message = b"TCP connection failed to ".to_vec();
                    message.extend_from_slice(&address_text(address));
                    message.extend_from_slice(format!("#{}", address.port()).as_bytes());
                    let event = LogEvent::new(Service::Debug, Priority::Debug, message);
                    if let Some(context) = &mut self.clients[index].log_context {
                        logger.emit_tcp(context, event);
                    } else {
                        logger.emit(event);
                    }
                }
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            {
                self.arp_awake |= std::mem::take(&mut self.clients[index].parent_cache_activity);
            }
            let network_alive = result.unwrap_or(false);
            if !network_alive && !self.clients[index].network_done {
                self.clients[index].network_done = true;
                self.clients[index].stream.take();
            }
            #[cfg(target_os = "linux")]
            let logs_done = if let (Some(logger), Some(context)) =
                (&mut self.logger, &mut self.clients[index].log_context)
            {
                logger.flush_tcp_ready(context);
                network_alive || logger.finish_tcp(context)
            } else {
                true
            };
            #[cfg(not(target_os = "linux"))]
            let logs_done = true;
            if network_alive || !logs_done {
                index += 1;
            } else {
                self.clients.swap_remove(index);
                #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                {
                    self.arp_awake = true;
                } // C parent receives the TCP child's SIGCHLD.
                self.parent_events.lock().unwrap().tcp_active = self.clients.len();
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn wait_during_probe(
        &mut self,
        icmp: &dnsmasq_rs::net::IcmpSocket,
        timeout: Duration,
        leases: dnsmasq_rs::dhcp::lease::LeaseCounters,
    ) -> io::Result<bool> {
        use owrt_ubus::sys::{PollFd, POLLIN, POLLOUT};
        use std::os::fd::AsRawFd;
        // The provider owns its lease transaction. The snapshot is taken at
        // the actual probe call, after packet/BOOTP pruning, not before it.
        if let Some(metrics) = self.probe_metrics.as_mut() {
            write_lease_metrics(metrics, leases);
        }
        if let Some(logger) = &mut self.logger {
            logger.flush_ready();
        }
        self.step_interface_collector();
        let full_deadline = Instant::now() + timeout;
        let mut deadline = full_deadline;
        let mut fds = vec![PollFd {
            fd: icmp.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        }];
        if let Some(logger) = &self.logger {
            for context in self
                .clients
                .iter()
                .filter_map(|client| client.log_context.as_ref())
            {
                if let Some(fd) = logger.tcp_poll_fd(context) {
                    fds.push(PollFd {
                        fd,
                        events: POLLOUT,
                        revents: 0,
                    });
                }
            }
            for fd in logger.poll_fds() {
                fds.push(PollFd {
                    fd,
                    events: POLLOUT,
                    revents: 0,
                });
            }
        }
        for listener in &self.listeners {
            if let Some(udp) = &listener.udp {
                fds.push(PollFd {
                    fd: udp.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                });
            }
            if self.clients.len() < self.tcp_limit {
                if let Some(tcp) = &listener.tcp {
                    fds.push(PollFd {
                        fd: tcp.as_raw_fd(),
                        events: POLLIN,
                        revents: 0,
                    });
                }
            }
        }
        if let Some(daemon) = &self.service.lock().unwrap().daemon {
            deadline = daemon.append_poll_fds(&mut fds, deadline);
        }
        for client in &self.clients {
            if client.network_done {
                continue;
            }
            deadline = deadline.min(client.deadline);
            let (fd, events) = match &client.phase {
                TcpClientPhase::Reading => {
                    if client.input_offset < client.input.len() {
                        deadline = Instant::now();
                    }
                    (
                        client.stream.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                        POLLIN,
                    )
                }
                TcpClientPhase::WaitingMac { .. } => {
                    deadline = deadline.min(client.mac_deadline);
                    (-1, 0)
                }
                TcpClientPhase::Writing { .. } => (
                    client.stream.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                    POLLOUT,
                ),
                TcpClientPhase::Forwarding { wait, .. } => {
                    deadline = deadline.min(wait.deadline);
                    (wait.fd, wait.events)
                }
            };
            fds.push(PollFd {
                fd,
                events,
                revents: 0,
            });
        }
        if let Some(tftp) = &self.tftp {
            tftp.append_poll_fds(&mut fds);
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(neighbors) = &self.neighbors {
            neighbors.append_poll_fds(&mut fds);
        }
        if let Some(collector) = &self.interface_collector {
            collector.append_poll_fds(&mut fds);
            if let Some(limit) = collector.deadline() {
                deadline = deadline.min(limit);
            }
            if collector.runnable() {
                deadline = Instant::now();
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        let ready = owrt_ubus::sys::poll_fds(&mut fds, millis)?;
        self.step_interface_collector();
        // C's delay_dhcp does not consume inotify/route events. They remain
        // queued until the outer owner can apply all reload effects together.
        // Neither signals/reload nor another DHCP packet may reenter the
        // borrowed state. All DNS and TFTP packet buffers are distinct.
        for index in 0..self.listeners.len() {
            self.step_udp(index);
            self.step_tcp_accept(index);
        }
        self.poll_udp_completions();
        self.step_tcp_clients();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.advance_neighbors();
        self.step_edns_udp();
        self.step_tftp();
        // Early DNS/TCP timers or any listener activity must not consume an
        // ICMP quarter-second timeout. Only the full idle poll counts as one.
        self.log_dns_diagnostics();
        Ok(ready != 0 || deadline < full_deadline)
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_helper(&mut self) {
        if self.pending_delivery.is_none() && self.helper_init.is_none() {
            self.pending_delivery = self.dhcp.as_ref().and_then(|dhcp| {
                dhcp.provider
                    .as_ref()?
                    .try_lock()
                    .ok()?
                    .take_script_delivery()
            });
        }
        if let Some(helper) = self.helper.as_mut() {
            if let Some(delivery) = self.pending_delivery.as_ref() {
                match helper.enqueue_delivery(delivery) {
                    Ok(true) => self.pending_delivery = None,
                    Ok(false) => {}
                    Err(error) => eprintln!("dnsmasq-rs: DHCP helper enqueue: {error}"),
                }
            }
            if self.pending_delivery.is_none() && helper.can_enqueue() {
                if let Some(neighbors) = &mut self.neighbors {
                    if let Some(change) = neighbors.front_script_change() {
                        let event = dnsmasq_rs::helper::Event::Arp {
                            added: change.added,
                            address: change.address,
                            hardware_address: change.hardware_address,
                        };
                        match helper.enqueue(&event) {
                            Ok(true) => {
                                neighbors.pop_script_change();
                            }
                            Ok(false) => {}
                            Err(error) => eprintln!("dnsmasq-rs: ARP helper enqueue: {error}"),
                        }
                    }
                }
            }
            if self.pending_delivery.is_none() && helper.can_enqueue() {
                if let Some(listener) = self.tftp.as_mut() {
                    if let Some(done) = listener.front_completion() {
                        let event = dnsmasq_rs::helper::Event::Tftp {
                            size: done.size,
                            address: done.peer.ip(),
                            filename: done.path.clone(),
                        };
                        match helper.enqueue(&event) {
                            Ok(true) => {
                                listener.pop_completion();
                            }
                            Ok(false) => {}
                            Err(error) => eprintln!("dnsmasq-rs: TFTP helper enqueue: {error}"),
                        }
                    }
                }
            }
            match helper.step() {
                Ok(notices) => {
                    for notice in notices {
                        use dnsmasq_rs::helper::{Notice, StartError};
                        match notice {
                            Notice::InitRecord(record) => {
                                if self.helper_init.as_ref().is_some_and(|output| {
                                    output.records.len() >= helper.init_capacity().unwrap_or(0)
                                }) {
                                    self.helper_init.take();
                                    self.helper_init_error = Some(StartError {
                                        code: 5,
                                        message: "too many stored leases".into(),
                                    });
                                } else if let Some(output) = self.helper_init.as_mut() {
                                    output.records.push(record);
                                }
                            }
                            Notice::InitEnd {
                                invalid_records,
                                clean_end,
                            } => {
                                if let Some(output) = self.helper_init.as_mut() {
                                    output.invalid_records = invalid_records;
                                    output.clean_end = clean_end;
                                    self.helper_init_end = true;
                                }
                            }
                            Notice::InitWarning(warning) => {
                                eprintln!("dnsmasq-rs: {}", String::from_utf8_lossy(&warning));
                            }
                            Notice::InitError(code) => {
                                self.helper_init.take();
                                self.helper_init_error = Some(StartError {
                                    code,
                                    message: if code == 5 {
                                        "too many stored leases"
                                    } else {
                                        "cannot parse lease-init database"
                                    }
                                    .into(),
                                });
                            }
                            Notice::InitExit(status) => {
                                if let Some(output) = self.helper_init.take() {
                                    if status != 0 {
                                        self.helper_init_error = Some(StartError {
                                            code: if status == 126 || status == 127 {
                                                3
                                            } else {
                                                status + 10
                                            },
                                            message: format!(
                                                "lease-init script returned exit code {status}"
                                            ),
                                        });
                                    } else if !self.helper_init_end {
                                        self.helper_init_error = Some(StartError {
                                            code: 3,
                                            message: "incomplete lease-init database".into(),
                                        });
                                    } else if let Some(provider) =
                                        self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref())
                                    {
                                        match provider
                                            .lock()
                                            .unwrap()
                                            .restore_script_records(output, now_seconds())
                                        {
                                            Ok(report) => report_dhcp_maintenance(
                                                &report,
                                                self.logger.as_mut(),
                                            ),
                                            Err(error) => {
                                                self.helper_init_error = Some(StartError {
                                                    code: error.exit_code(),
                                                    message: error.to_string(),
                                                })
                                            }
                                        }
                                    }
                                }
                            }
                            Notice::Reaped(_) | Notice::Error(_) if self.helper_init.is_some() => {
                                self.helper_init_error = Some(StartError {
                                    code: 3,
                                    message: "lease-init helper failed".into(),
                                });
                            }
                            Notice::CredentialError(code) => {
                                self.helper_init_error = Some(helper.credential_failure(code));
                            }
                            Notice::Error(code) if !helper.ready() => {
                                self.helper_init_error = Some(StartError {
                                    code: 5,
                                    message: format!(
                                        "failed to initialize helper: {}",
                                        dnsmasq_rs::logging::error_text(
                                            &io::Error::from_raw_os_error(code)
                                        )
                                    ),
                                });
                            }
                            Notice::Ready => {}
                            Notice::Output(bytes) => {
                                if let Some(logger) = &mut self.logger {
                                    use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                                    logger.emit(LogEvent::new(
                                        Service::Script,
                                        Priority::Debug,
                                        bytes,
                                    ));
                                }
                            }
                            Notice::ScriptExit(status) => {
                                if let Some(logger) = &mut self.logger {
                                    use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                                    logger.emit(LogEvent::new(
                                        Service::Dns,
                                        Priority::Warning,
                                        format!("script process exited with status {status}")
                                            .into_bytes(),
                                    ));
                                }
                            }
                            Notice::ScriptSignal(signal) => {
                                if let Some(logger) = &mut self.logger {
                                    use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                                    logger.emit(LogEvent::new(
                                        Service::Dns,
                                        Priority::Warning,
                                        format!("script process killed by signal {signal}")
                                            .into_bytes(),
                                    ));
                                }
                            }
                            Notice::ExecError(code) => {
                                if let Some(logger) = &mut self.logger {
                                    use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                                    logger.emit(LogEvent::new(
                                        Service::Dns,
                                        Priority::Error,
                                        format!(
                                            "failed to execute {}: {}",
                                            helper.script_path().display(),
                                            dnsmasq_rs::logging::error_text(
                                                &io::Error::from_raw_os_error(code)
                                            )
                                        )
                                        .into_bytes(),
                                    ));
                                }
                            }
                            notice => eprintln!("dnsmasq-rs: DHCP helper: {notice:?}"),
                        }
                    }
                }
                Err(error) => eprintln!("dnsmasq-rs: DHCP helper step: {error}"),
            }
            if helper.is_finished() {
                self.pending_delivery = None;
                if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
                    if let Ok(mut provider) = provider.try_lock() {
                        provider.disable_script_delivery();
                    }
                }
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_helper_shutdown(&mut self) -> bool {
        self.step_helper();
        let Some(helper) = self.helper.as_ref() else {
            return true;
        };
        if helper.is_finished() {
            return true;
        }
        // Initialization may still own the child. Its notices must be consumed
        // before closing the command channel or restoring startup callbacks.
        if self.helper_init.is_some() {
            return false;
        }
        if self.pending_delivery.is_none() {
            self.pending_delivery = self
                .dhcp
                .as_ref()
                .and_then(|dhcp| dhcp.provider.as_ref()?.lock().ok()?.take_script_delivery());
        }
        if self.pending_delivery.is_none()
            && self
                .tftp
                .as_ref()
                .is_none_or(|listener| listener.front_completion().is_none())
        {
            let helper = self.helper.as_mut().unwrap();
            helper.begin_shutdown();
            return helper.commands_drained();
        }
        false
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_dhcp(&mut self) {
        self.step_helper();
        if self.interface_work_pending() {
            return;
        }
        if self.helper_init.is_some() || self.helper_init_error.is_some() {
            return;
        }
        // EVENT_RELOAD is consumed before DHCP in C. A completed bank is
        // still intermediate when another delivered SIGHUP waits in the queue.
        if RELOAD_REQUESTED.load(Ordering::Acquire) != 0 || self.dhcp_reload_in_progress() {
            return;
        }
        let Some(mut dhcp) = self.dhcp.take() else {
            return;
        };
        let Some(provider_ref) = dhcp.provider.as_ref().map(Arc::clone) else {
            let _ = dhcp
                .listener
                .process_once_relay_only(|| STOP_REQUESTED.load(Ordering::Acquire));
            if dhcp.listener.has_pxe_listener() {
                let _ = dhcp
                    .listener
                    .process_once_pxe_relay_only(|| STOP_REQUESTED.load(Ordering::Acquire));
            }
            if let Some(logger) = &mut self.logger {
                for notice in dhcp.listener.take_network_notices() {
                    logger.emit(notice);
                }
            }
            self.dhcp = Some(dhcp);
            return;
        };
        let Ok(mut provider) = provider_ref.lock() else {
            self.dhcp = Some(dhcp);
            return;
        };
        if provider.file_work_pending() {
            drop(provider);
            self.dhcp = Some(dhcp);
            return;
        }
        let now = now_seconds();
        if let Some(report) = provider.tick(now) {
            report_dhcp_maintenance(&report, self.logger.as_mut());
        }
        // Leave input in the kernel until a fresh address generation arrives.
        // Each turn advances at most one netlink datagram without a blocking wait.
        if !dhcp.listener.has_input().unwrap_or(false)
            || match provider.prepare_packet_interfaces() {
                Ok(ready) => !ready,
                Err(error) => {
                    eprintln!("dnsmasq-rs: DHCP interface snapshot: {error}");
                    true
                }
            }
        {
            drop(provider);
            self.dhcp = Some(dhcp);
            return;
        }
        if self
            .tftp
            .as_ref()
            .is_some_and(TftpListener::needs_mac_lookup)
        {
            self.probe_tftp_macs = provider.tftp_lease_snapshot(now);
        }
        let mut metrics = Metrics::default();
        write_dhcp_metrics(&mut metrics, &provider);
        self.probe_metrics = Some(metrics);
        let mut output = vec![0; 16_384];
        let events = Arc::clone(&self.parent_events);
        let results = {
            let mut sink = |kind, fields: DhcpEventFields<'_>, logging| {
                events.lock().unwrap().notify_dhcp(kind, fields, logging)
            };
            let mut wait = |socket: &dnsmasq_rs::net::IcmpSocket, duration, leases| {
                self.wait_during_probe(socket, duration, leases)
            };
            let mut provider = provider.with_event_sink_and_wait(&mut sink, &mut wait);
            let has_pxe = dhcp.listener.has_pxe_listener();
            let mut selected = if dhcp.pxe_next && has_pxe {
                DhcpListener::Pxe
            } else {
                DhcpListener::Dhcp
            };
            let first = dhcp.listener.process_once_on_listener(
                selected,
                &mut provider,
                &[],
                &mut output,
                || STOP_REQUESTED.load(Ordering::Acquire),
            );
            // A probe can take several seconds. Never carry its address dump
            // into a second packet; the next owner turn obtains a fresh one.
            let second = if matches!(first, Ok(ListenerStep::WouldBlock)) && has_pxe {
                selected = if selected == DhcpListener::Pxe {
                    DhcpListener::Dhcp
                } else {
                    DhcpListener::Pxe
                };
                dhcp.listener.process_once_on_listener(
                    selected,
                    &mut provider,
                    &[],
                    &mut output,
                    || STOP_REQUESTED.load(Ordering::Acquire),
                )
            } else {
                Ok(ListenerStep::WouldBlock)
            };
            dhcp.pxe_next = has_pxe && selected == DhcpListener::Dhcp;
            [first, second]
        };
        provider.finish_packet_interfaces();
        if self.pending_delivery.is_none() {
            self.pending_delivery = provider.take_script_delivery();
        }
        self.probe_metrics = None;
        self.probe_tftp_macs.clear();
        for result in results {
            if let Ok(ListenerStep::Processed(result)) = result {
                let events = match &result {
                    Ok(report) => &report.events,
                    Err(failure) => &failure.events,
                };
                for event in events {
                    if let dnsmasq_rs::dhcp::runtime::RuntimeEvent::ArpInjectionFailed {
                        kind,
                        raw_os_error,
                    } = event
                    {
                        eprintln!("dnsmasq-rs: DHCP ARP injection: {kind:?} ({raw_os_error:?})");
                    }
                }
            }
        }
        if let Some(error) = provider.take_probe_error() {
            eprintln!("dnsmasq-rs: DHCP conflict probe: {error}");
        }
        if let Some(logger) = &mut self.logger {
            for notice in provider
                .take_network_notices()
                .into_iter()
                .chain(dhcp.listener.take_network_notices())
            {
                logger.emit(notice);
            }
        }
        if let Some(report) = provider.take_maintenance_report() {
            report_dhcp_maintenance(&report, self.logger.as_mut());
        }
        drop(provider);
        self.dhcp = Some(dhcp);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn observe_arp_activity(&mut self) {
        use owrt_ubus::sys::{PollFd, POLLIN};
        use std::os::fd::AsRawFd;
        if !self.script_arp {
            return;
        }
        let now = Instant::now();
        self.arp_awake |= self.full_reload_pending
            || RELOAD_REQUESTED.load(Ordering::Acquire) != 0
            || LOG_REOPEN_REQUESTED.load(Ordering::Acquire) != 0;
        let mut fds = Vec::new();
        // A normal C TCP child owns its logger readiness. It does not wake
        // the parent's ARP loop until cache import or its actual completion.
        self.append_file_fds(&mut fds, false);
        for listener in &self.listeners {
            if let Some(udp) = &listener.udp {
                fds.push(PollFd {
                    fd: udp.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                });
            }
            if let Some(tcp) = &listener.tcp {
                fds.push(PollFd {
                    fd: tcp.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                });
            }
        }
        let parent = self.service.lock().unwrap();
        if let Some(daemon) = &parent.daemon {
            let deadline = daemon.append_poll_fds(&mut fds, now + Duration::from_secs(3600));
            self.arp_awake |= deadline <= now;
        }
        drop(parent);
        if let Some(ubus) = &self.parent_events.lock().unwrap().ubus {
            fds.push(PollFd {
                fd: ubus.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            });
        }
        if let Some(dhcp) = &self.dhcp {
            self.arp_awake |= dhcp.listener.has_input().unwrap_or(false);
            if let Some(provider) = &dhcp.provider {
                self.arp_awake |= provider
                    .lock()
                    .unwrap()
                    .next_maintenance()
                    .is_some_and(|deadline| deadline <= now);
            }
        }
        if let Some(helper) = &self.helper {
            for (fd, events) in helper.poll_fds() {
                if fd >= 0 {
                    fds.push(PollFd {
                        fd,
                        events,
                        revents: 0,
                    });
                }
            }
        }
        if let Some(tftp) = &self.tftp {
            tftp.append_poll_fds(&mut fds);
            if tftp.active_transfers() != 0 {
                // C's existing active-TFTP poll timer is at most 250ms.
                let wake = self
                    .tftp_parent_wake
                    .get_or_insert(now + Duration::from_millis(250));
                if now >= *wake {
                    self.arp_awake = true;
                    *wake = now + Duration::from_millis(250);
                }
            } else {
                self.tftp_parent_wake = None;
            }
        }
        if let Some(neighbors) = &self.neighbors {
            neighbors.append_poll_fds(&mut fds);
        }
        self.arp_awake |= owrt_ubus::sys::poll_fds(&mut fds, 0).is_ok_and(|ready| ready != 0);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_neighbors(&mut self) {
        let awake = std::mem::take(&mut self.arp_awake);
        if let Some(neighbors) = &mut self.neighbors {
            let _ = neighbors.refresh_script_arp(now_seconds() as u64, awake);
            if self.helper.as_ref().is_none_or(Helper::is_finished) {
                neighbors.discard_script_changes();
            }
        }
        self.advance_neighbors();
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn advance_neighbors(&mut self) {
        let Some(neighbors) = self.neighbors.as_mut() else {
            return;
        };
        if let Err(error) = neighbors.step(now_seconds() as u64) {
            if error.kind() != io::ErrorKind::TimedOut {
                eprintln!("dnsmasq-rs: neighbor snapshot: {error}");
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_tftp(&mut self) {
        let Some(listener) = self.tftp.as_mut() else {
            return;
        };
        let now = now_seconds() as u64;
        let provider = self
            .dhcp
            .as_ref()
            .and_then(|dhcp| dhcp.provider.as_ref()?.try_lock().ok());
        let neighbors = &mut self.neighbors;
        let quiet_not_found = listener.quiet_not_found();
        let events = listener.poll_once_with_mac(now, &mut |address, interface, now| {
            if let IpAddr::V4(address) = address {
                let mac = provider
                    .as_ref()
                    .and_then(|provider| provider.tftp_lease_mac(address))
                    .or_else(|| {
                        self.probe_tftp_macs
                            .iter()
                            .find_map(|(ip, mac)| (*ip == address).then_some(*mac))
                    });
                if mac.is_some() {
                    return dnsmasq_rs::neighbors::MacLookup::Ready(mac);
                }
            }
            neighbors
                .as_mut()
                .map_or(dnsmasq_rs::neighbors::MacLookup::Ready(None), |neighbors| {
                    neighbors.query(address, interface, now)
                })
        });
        if let (Ok(events), Some(logger)) = (events, self.logger.as_mut()) {
            for event in events {
                if let Some(event) = event.log_event(quiet_not_found) {
                    logger.emit(event);
                }
            }
        }
        if self.helper.as_ref().is_none_or(Helper::is_finished) {
            while listener.pop_completion().is_some() {}
        }
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn report_dhcp_maintenance(
    report: &dnsmasq_rs::dhcp::daemon::MaintenanceReport,
    mut logger: Option<&mut dnsmasq_rs::logging::Logger>,
) {
    if let Some(error) = &report.address_error {
        eprintln!("dnsmasq-rs: failed to update DHCP host addresses: {error}");
    }
    for error in &report.host_files {
        eprintln!("dnsmasq-rs: DHCP hosts file: {error:?}");
    }
    if let Some(error) = &report.name_error {
        eprintln!("dnsmasq-rs: failed to update lease names from static hosts: {error}");
    }
    if let Some(message) = &report.file_error_message {
        if let Some(logger) = logger.as_deref_mut() {
            use dnsmasq_rs::logging::{LogEvent, Priority, Service};
            logger.emit(LogEvent::new(
                Service::Dhcp,
                Priority::Error,
                message.clone(),
            ));
        }
    }
    if let Some(error) = &report.dns.error {
        eprintln!("dnsmasq-rs: failed to publish lease names: {error}");
    }
    if let Some(restore) = report
        .restore
        .as_ref()
        .filter(|restore| !restore.diagnostics_logged)
    {
        if let Some(logger) = logger {
            use dnsmasq_rs::logging::{LogEvent, Priority, Service};
            for warning in &restore.warnings {
                logger.emit(LogEvent::new(
                    Service::Dhcp,
                    Priority::Warning,
                    warning.clone(),
                ));
            }
            if !restore.clean_end {
                logger.emit(LogEvent::new(
                    Service::Dhcp,
                    Priority::Error,
                    b"failed to parse lease database cleanly".to_vec(),
                ));
            }
        }
    }
}

#[cfg(test)]
fn validate_probe_ready(scalar: &ScalarConfig, dns: &DnsConfig) -> Result<(), Error> {
    if !dns.no_resolv {
        return Err(Error("local probe requires explicit no-resolv"));
    }
    if dns.listen_addresses.is_empty() {
        return Err(Error(
            "local probe requires explicit loopback listen-address",
        ));
    }
    if dns
        .listen_addresses
        .iter()
        .any(|address| !address.is_loopback())
    {
        return Err(Error("local probe only binds loopback addresses"));
    }
    if scalar.dns_port < 1024 {
        return Err(Error("local probe requires an unprivileged DNS port"));
    }
    if !dns.hosts_dirs.is_empty() {
        return Err(Error("hostsdir is not implemented by the local probe"));
    }
    if dns.servers_file.is_some() || dns.domain_from_resolv || !dns.conditional_domains.is_empty() {
        return Err(Error(
            "resolver file/domain discovery is not implemented by the local probe",
        ));
    }
    if dns.resolv_files.len() != 1 || dns.resolv_files[0] != Path::new("/etc/resolv.conf") {
        return Err(Error("resolv-file is not implemented by the local probe"));
    }
    if !dns.interfaces.is_empty() || !dns.excluded_interfaces.is_empty() {
        return Err(Error(
            "interface selection is not implemented by the local probe",
        ));
    }
    if dns.bind_interfaces || dns.bind_dynamic || dns.local_service_net || dns.local_service_host {
        return Err(Error(
            "interface binding is not implemented by the local probe",
        ));
    }
    if dns.domain_needed
        || dns.bogus_priv
        || dns.no_poll
        || dns.strict_order
        || dns.all_servers
        || dns.no_negative_cache
        || dns.stop_rebind
        || dns.rebind_localhost_ok
        || !dns.rebind_domains.is_empty()
        || dns.localise_queries
        || dns.proxy_dnssec
        || dns.no_0x20_encode
        || dns.do_0x20_encode
    {
        return Err(Error(
            "resolver policy is not implemented by the local probe",
        ));
    }
    if dns.records.needs_hostname() {
        return Err(Error(
            "hostname-dependent MX/SRV records are not implemented by the local probe",
        ));
    }
    for rule in &dns.rules {
        if matches!(
            rule.target,
            dnsmasq_rs::config::dns::RuleTarget::Upstream(_)
                | dnsmasq_rs::config::dns::RuleTarget::DefaultResolvers
        ) {
            return Err(Error(
                "upstream forwarding is not implemented by the local probe",
            ));
        }
    }
    // These parser fields have no local-probe effect.  Reject explicit
    // non-default values instead of accepting a configuration that silently
    // loses cache, retry, source-port or TTL policy.
    let defaults = ScalarConfig::default();
    if scalar.cache_size != defaults.cache_size
        || scalar.forward_max != defaults.forward_max
        || scalar.query_port != defaults.query_port
        || scalar.query_port_os_assigned != defaults.query_port_os_assigned
        || scalar.min_port != defaults.min_port
        || scalar.max_port != defaults.max_port
        || scalar.port_limit != defaults.port_limit
        || scalar.max_ttl != defaults.max_ttl
        || scalar.min_cache_ttl != defaults.min_cache_ttl
        || scalar.max_cache_ttl != defaults.max_cache_ttl
        || scalar.dhcp_ttl.is_some()
        || scalar.fast_retry.is_some()
        || scalar.stale_cache != defaults.stale_cache
    {
        return Err(Error("scalar option is not implemented by the local probe"));
    }
    Ok(())
}

/// Validate the subset consumed by `DnsDaemon` before listener threads start.
/// Every rejected field is one whose C behaviour is not represented by the
/// current Rust daemon; accepting it would silently lose configured policy.
fn validate_runtime_ready(scalar: &ScalarConfig, dns: &DnsConfig) -> Result<(), Error> {
    if dns.bind_interfaces && dns.bind_dynamic {
        return Err(Error("cannot set --bind-interfaces and --bind-dynamic"));
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    if dns.bind_interfaces
        || dns.bind_dynamic
        || dns.local_service_net
        || dns.local_service_host
        || !dns.interfaces.is_empty()
        || !dns.excluded_interfaces.is_empty()
    {
        return Err(Error("interface binding requires 64-bit Linux"));
    }
    if dns.records.needs_hostname() {
        return Err(Error(
            "hostname-dependent local records are not implemented",
        ));
    }
    Ok(())
}

fn read_hosts(config: &DnsConfig, local_ttl: u32) -> Hosts {
    let mut hosts = dnsmasq_rs::dns::local::configured_hosts(config, local_ttl);
    let mut read = |path: &Path, source: u32| {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!(
                    "dnsmasq-rs: failed to load names from {}: {error}",
                    path.display()
                );
                return;
            }
        };
        let _ = hosts.read(&bytes, source, local_ttl, config.expand_hosts, |address| {
            config
                .domain_for_address(address)
                .ok()
                .flatten()
                .map(ToOwned::to_owned)
        });
    };
    // `no-hosts` suppresses only the built-in /etc/hosts source. Explicit
    // addn-hosts files remain active in dnsmasq.
    if !config.no_hosts {
        read(Path::new("/etc/hosts"), 0);
    }
    // expand_filelist appends directory members after explicit files. Its
    // alphasort order matters when multiple names compete for PTR ownership.
    let mut directory_files = Vec::new();
    for (index, path) in config.addn_hosts.iter().enumerate() {
        let Some(path) = path else { continue };
        if !path.is_dir() {
            read(path, (index + 1) as u32);
            continue;
        }
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!(
                    "dnsmasq-rs: cannot access directory {}: {error}",
                    path.display()
                );
                continue;
            }
        };
        let mut files = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name();
                let name = name.as_encoded_bytes();
                if name.starts_with(b".")
                    || name.ends_with(b"~")
                    || (name.starts_with(b"#") && name.ends_with(b"#"))
                {
                    return None;
                }
                let path = entry.path();
                path.is_file().then_some(path)
            })
            .collect::<Vec<_>>();
        dnsmasq_rs::sorting::sort_by(&mut files, Ord::cmp);
        directory_files.extend(files);
    }
    for (index, path) in directory_files.iter().enumerate() {
        read(path, (config.addn_hosts.len() + index + 1) as u32);
    }
    hosts
}

#[cfg(any(test, not(target_os = "linux")))]
fn read_resolvers(config: &DnsConfig) -> Result<Vec<SocketAddr>, io::Error> {
    if config.no_resolv {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for path in &config.resolv_files {
        let bytes = std::fs::read(path)?;
        for line in bytes.split(|byte| *byte == b'\n' || *byte == b'\r') {
            let line = line.split(|byte| *byte == b'#').next().unwrap_or_default();
            let fields: Vec<_> = line
                .split(|byte| byte.is_ascii_whitespace())
                .filter(|v| !v.is_empty())
                .collect();
            if fields.len() < 2 || fields.first().is_none_or(|field| *field != b"nameserver") {
                continue;
            }
            if let Ok(address) = std::str::from_utf8(fields[1])
                .unwrap_or_default()
                .parse::<IpAddr>()
            {
                result.push(SocketAddr::new(address, 53));
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnsmasq_rs::config::{lex_line, validate_directive};

    #[test]
    fn startup_status_retains_config_loader_exit_codes() {
        for exit_code in [1, 3, 5, (3 << 8) + 10] {
            let error = loader::LoadError {
                location: loader::Location {
                    file: None,
                    line: None,
                    from_script: false,
                },
                exit_code,
                message: "configuration input failure".into(),
            };
            assert_eq!(startup_status(&error), exit_code);
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn idle_snapshot_includes_restored_dhcp_leases_with_dns_disabled() {
        let path = std::env::temp_dir().join(format!(
            "single-owner-metrics-{}.leases",
            std::process::id()
        ));
        std::fs::write(&path, b"0 02:00:00:00:00:01 192.0.2.10 lease-client *\n").unwrap();
        let config = DhcpConfig {
            no_ping: true,
            lease_file: Some(path.as_os_str().as_encoded_bytes().to_vec()),
            ..DhcpConfig::default()
        };
        let provider = DhcpProvider::new(config, Vec::new(), 0, || false).unwrap();
        let listener =
            DhcpSocketListener::bind("127.0.0.1:0".parse().unwrap(), DhcpListener::Dhcp, &[])
                .unwrap();
        let event = ParentEvents::new(&UbusConfig::default()).unwrap();
        let owner = SinglePoll::new(
            Arc::new(Mutex::new(ParentDns {
                local: LocalDnsService::new_with_limits(
                    DnsConfig::default(),
                    Hosts::new(),
                    0,
                    512,
                    512,
                ),
                daemon: None,
            })),
            Arc::new(Mutex::new(
                ParentEvents::new(&UbusConfig::default()).unwrap(),
            )),
            Arc::new(Mutex::new(Vec::new())),
            DnsConfig::default(),
            Vec::new(),
            512,
            20,
            512,
            Vec::new(),
            Some(DhcpService {
                provider: Some(Arc::new(Mutex::new(provider))),
                listener,
                pxe_next: false,
            }),
            None,
            None,
            None,
        );
        for _ in 0..3 {
            assert_eq!(owner.metrics(&event).get(Metric::LeasesAllocated4), 1);
            assert_eq!(owner.metrics(&event).get(Metric::LocalAnswered), 0);
        }
        drop(owner);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dns_snapshots_add_background_local_answers_once_and_wrap() {
        let mut metrics = Metrics::default();
        let cache = dnsmasq_rs::dns::cache::CacheCounters::default();
        let mut forward = dnsmasq_rs::dns::forward::ForwardCounters {
            background_local_answered: 2,
            ..Default::default()
        };
        write_dns_metrics(&mut metrics, cache, forward, u32::MAX);
        assert_eq!(metrics.get(Metric::LocalAnswered), 1);
        // A repeated snapshot, including the doctor callback, replaces the
        // aggregate from its sources instead of adding the producer twice.
        write_dns_metrics(&mut metrics, cache, forward, u32::MAX);
        assert_eq!(metrics.get(Metric::LocalAnswered), 1);
        forward.background_local_answered += 1;
        write_dns_metrics(&mut metrics, cache, forward, u32::MAX);
        assert_eq!(metrics.get(Metric::LocalAnswered), 2);
    }

    #[test]
    fn no_hosts_keeps_explicit_addn_hosts() {
        let path = std::env::temp_dir().join(format!(
            "dnsmasq-rs-addn-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&path, b"192.0.2.44 addn.test\n").unwrap();
        let mut config = DnsConfig::default();
        let no_hosts = lex_line(b"no-hosts").unwrap().unwrap();
        validate_directive(&no_hosts).unwrap();
        config.apply(&no_hosts).unwrap();
        config.addn_hosts.push(Some(path.clone()));
        let mut hosts = read_hosts(&config, 0);
        assert_eq!(hosts.lookup(b"addn.test", Some(false), true).len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn addn_hosts_directory_uses_sorted_files_and_ignores_backups() {
        let root = std::env::temp_dir().join(format!("dnsmasq-rs-hostdir-{}", std::process::id()));
        std::fs::create_dir_all(root.join("nested")).unwrap();
        for (file, bytes) in [
            ("b", "192.0.2.44 second.test\n"),
            ("a", "192.0.2.44 first.test\n"),
            (".hidden", "192.0.2.45 hidden.test\n"),
            ("backup~", "192.0.2.45 backup.test\n"),
            ("#autosave#", "192.0.2.45 autosave.test\n"),
            ("nested/file", "192.0.2.45 nested.test\n"),
        ] {
            std::fs::write(root.join(file), bytes).unwrap();
        }
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.addn_hosts.push(Some(root.clone()));
        let hosts = read_hosts(&config, 37);
        assert_eq!(hosts.len(), 2);
        let host = hosts.reverse("192.0.2.44".parse().unwrap()).unwrap();
        assert_eq!(host.name, b"first.test");
        assert_eq!(host.ttl, 37);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hosts_receive_the_final_local_ttl() {
        let path = std::env::temp_dir().join(format!("dnsmasq-rs-ttl-{}", std::process::id()));
        std::fs::write(&path, b"192.0.2.44 ttl.test\n").unwrap();
        let mut config = DnsConfig::default();
        config.addn_hosts.push(Some(path.clone()));
        let hosts = read_hosts(&config, 37);
        assert_eq!(hosts.entries()[0].ttl, 37);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn resolver_file_reads_nameserver_addresses_only() {
        let path = std::env::temp_dir().join(format!("dnsmasq-rs-resolv-{}", std::process::id()));
        std::fs::write(
            &path,
            b"# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53 # v6\nsearch test\n",
        )
        .unwrap();
        let mut config = DnsConfig::default();
        config.resolv_files = vec![path.clone()];
        let resolvers = read_resolvers(&config).unwrap();
        assert_eq!(
            resolvers,
            [
                "192.0.2.53:53".parse().unwrap(),
                "[2001:db8::53]:53".parse().unwrap(),
            ]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn probe_requires_explicit_loopback_and_no_resolv() {
        let scalar = ScalarConfig {
            dns_port: 5300,
            ..ScalarConfig::default()
        };
        let dns = DnsConfig::default();
        assert_eq!(
            validate_probe_ready(&scalar, &dns).unwrap_err(),
            Error("local probe requires explicit no-resolv")
        );
        let mut dns = dns;
        dns.no_resolv = true;
        assert_eq!(
            validate_probe_ready(&scalar, &dns).unwrap_err(),
            Error("local probe requires explicit loopback listen-address")
        );
        dns.listen_addresses.push("127.0.0.1".parse().unwrap());
        assert!(validate_probe_ready(&scalar, &dns).is_ok());
    }

    #[test]
    fn test_mode_runs_cname_cross_option_validation() {
        let mut dns = DnsConfig::default();
        for line in [b"cname=a.test,b.test".as_slice(), b"cname=b.test,a.test"] {
            let directive = lex_line(line).unwrap().unwrap();
            validate_directive(&directive).unwrap();
            assert!(dns.apply(&directive).unwrap());
        }
        assert_eq!(dns.finalize().unwrap_err(), Error("CNAME loop"));
    }

    #[test]
    fn runtime_gate_accepts_positive_and_nxdomain_cache_policy() {
        let scalar = ScalarConfig {
            cache_size: ScalarConfig::default().cache_size + 1,
            ..ScalarConfig::default()
        };
        assert!(validate_runtime_ready(&scalar, &DnsConfig::default()).is_ok());

        let scalar = ScalarConfig {
            negative_ttl: 30,
            ..ScalarConfig::default()
        };
        assert!(validate_runtime_ready(&scalar, &DnsConfig::default()).is_ok());
    }
}
