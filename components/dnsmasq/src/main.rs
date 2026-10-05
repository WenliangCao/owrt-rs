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
        // inotify is initialized after PID/privilege setup, when C's ordinary
        // foreground logging no longer uses stderr. Debug mode still does.
        #[cfg(target_os = "linux")]
        if error.is::<WatchError>() && !DEBUG_MODE.load(Ordering::Relaxed) {
            std::process::exit(startup_status(error.as_ref()));
        }
        let blank_line = error.is::<loader::LoadError>() || error.is::<Error>()
            || error
                .downcast_ref::<dnsmasq_rs::dns::daemon::DaemonError>()
                .is_some_and(|error| {
                    matches!(error, dnsmasq_rs::dns::daemon::DaemonError::SourceBind(_))
                })
            || error.is::<dnsmasq_rs::startup::StartupError>();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        let blank_line = blank_line
            || error.is::<dnsmasq_rs::helper::StartError>()
            || error
                .downcast_ref::<dnsmasq_rs::dhcp::daemon::StartupError>()
                .is_some_and(|error| error.is_lease_capacity());
        if blank_line {
            eprintln!();
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

fn startup_status(error: &(dyn std::error::Error + 'static)) -> i32 {
    // dnsmasq.h: EC_BADCONF=1, EC_BADNET=2. Other initialization boundaries
    // supply their own code rather than guessing from an errno alone.
    if let Some(error) = error.downcast_ref::<loader::LoadError>() {
        return error.exit_code;
    }
    if let Some(error) = error.downcast_ref::<dnsmasq_rs::startup::StartupError>() {
        return error.code;
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
                Err(error) => return Err(Box::new(error)),
            },
        };
        Ok(Self {
            ubus_name: name,
            ubus,
            ubus_error_logged: false,
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

    fn disconnect(&mut self, error: &dyn std::fmt::Display) {
        self.ubus = None;
        if !self.ubus_error_logged {
            eprintln!("dnsmasq-rs: UBus: {error}");
            self.ubus_error_logged = true;
        }
    }

    fn process_ubus(&mut self, metrics: &Metrics) {
        let Some(name) = self.ubus_name.as_deref() else {
            return;
        };
        if self.ubus.is_none() {
            match UbusService::connect_bytes(None, name) {
                Ok(service) => {
                    self.ubus = Some(service);
                    self.ubus_error_logged = false;
                }
                Err(error @ ConnectError::Transport(_)) => {
                    self.disconnect(&error);
                    return;
                }
                Err(error @ ConnectError::Registration(_)) => {
                    // C treats registration failure during retry as fatal to
                    // UBus only. The DNS/DHCP service keeps running.
                    self.disconnect(&error);
                    self.ubus_name = None;
                    return;
                }
            }
        }
        while let Some(ubus) = self.ubus.as_mut() {
            match ubus.process_one(metrics) {
                Ok(true) => {}
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
    };
    let action = loader::load(args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        if runtime.logging.apply(directive)?
            || runtime.process.apply(directive)?
            || runtime.scalar.apply(directive)?
            || runtime.dns.apply_resolved(directive)?
            || runtime.tftp.apply(directive)?
            || runtime.dhcp.apply(directive)?
            || runtime.ubus.apply(directive)?
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
            startup.fail(startup_status(error.as_ref()), &error.to_string());
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
            runtime.dns.finalize().map_err(config_diagnostic)?;
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
    runtime.dns.finalize().map_err(config_diagnostic)?;
    runtime
        .dhcp
        .validate_dns_config(&runtime.dns)
        .map_err(config_diagnostic)?;
    runtime.tftp.validate_ready()?;
    runtime.dhcp.validate_ready()?;
    validate_runtime_ready(&runtime.scalar, &runtime.dns)?;
    let dns_enabled = runtime.scalar.dns_port != 0;
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
        forward_max: runtime.scalar.forward_max as usize,
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
    // C mutates all parent engines in one event loop. Fetch DHCP metrics
    // before locking DNS; synchronous doctor callbacks must never invert it.
    // Socket waits remain outside this gate.
    let parent_events = Arc::new(Mutex::new(ParentEvents::new(&runtime.ubus)?));
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let helper_config = dhcp_config
        .script
        .as_ref()
        .filter(|_| !dhcp_config.ranges.is_empty() || tftp_config.enabled)
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
                (runtime.scalar.forward_max as usize) / 2
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
                dnsmasq_rs::logging::report_startup_failure(
                    &runtime.logging,
                    &runtime.process,
                    &error.message,
                );
            }
            return Err(Box::new(error));
        }
    };
    #[cfg(target_os = "linux")]
    dnsmasq_rs::startup::redirect_standard_streams(&runtime.process);
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let dhcp_helper = helper_config.map(Helper::start).transpose()?;
    #[cfg(target_os = "linux")]
    identity.drop_privileges(&runtime.process, capabilities).map_err(|error| {
        if !startup.active() {
            use dnsmasq_rs::logging::{LogEvent, Priority, Service};
            logger.emit(LogEvent::new(Service::Dns, Priority::Critical, error.message.as_bytes().to_vec()));
            logger.emit(LogEvent::new(Service::Dns, Priority::Critical, b"FAILED to start up".to_vec()));
            logger.finish();
        }
        error
    })?;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(listener) = &tftp_listener {
        // C tolerates inaccessible roots with no-fail, never socket errors.
        // Root access failures use EC_FILE, not EC_BADNET.
        let warnings =
            listener
                .validate_roots()
                .map_err(|error| dnsmasq_rs::startup::StartupError {
                    code: 3,
                    message: format!("TFTP root unavailable: {error}"),
                })?;
        for root in warnings {
            eprintln!(
                "dnsmasq-rs: TFTP root unavailable: {}",
                String::from_utf8_lossy(&root)
            );
        }
    }
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
    let neighbor_cache = if tftp_config.unique_root_mac {
        NeighborCache::new().ok()
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
        if let Some(error) = log_ownership_warning {
            logger.emit(LogEvent::new(
                Service::Dns,
                Priority::Warning,
                format!(
                    "warning: failed to change owner of {}: {}",
                    runtime.logging.file.as_deref().unwrap().display(),
                    dnsmasq_rs::logging::error_text(&error)
                )
                .into_bytes(),
            ));
        }
        if dns_enabled && daemon_config.no_resolv && daemon_config.rules.is_empty() {
            logger.emit(LogEvent::new(
                Service::Dns,
                Priority::Warning,
                b"warning: no upstream servers configured".to_vec(),
            ));
        }
        for range in &runtime.dhcp.ranges {
            logger.emit(dnsmasq_rs::logging::startup::dhcp_range(range));
        }
        if let Some(event) = dnsmasq_rs::logging::startup::tftp(&runtime.tftp) {
            logger.emit(event);
        }
        poll.log_cleared_cache = dns_enabled
            && runtime.scalar.cache_size > 0
            && daemon_config.no_hosts
            && daemon_config.addn_hosts.is_empty();
        if poll.log_cleared_cache {
            // The initial host/cache generation above has been constructed.
            logger.emit(LogEvent::new(
                Service::Dns,
                Priority::Info,
                b"cleared cache".to_vec(),
            ));
        }
        poll.logger = Some(logger);
    }
    // `-k` is the normal OpenWrt invocation. Stop handlers let workers leave
    // their bounded receive loops and release sockets before exit.
    #[cfg(target_os = "linux")]
    if poll.helper.as_ref().is_none_or(Helper::ready) {
        startup.complete();
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
            return Err(Box::new(error));
        }
        #[cfg(target_os = "linux")]
        if startup.active() && poll.helper.as_ref().is_none_or(Helper::ready) {
            startup.complete();
        }
        if last_interfaces.elapsed() >= Duration::from_millis(100) {
            last_interfaces = Instant::now();
            if let Ok(interfaces) = listeners::snapshot() {
                let changed = *interface_snapshot.lock().unwrap() != interfaces;
                *interface_snapshot.lock().unwrap() = interfaces.clone();
                #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                if changed {
                    if let Some(dhcp) = &mut poll.dhcp {
                        dhcp.listener.invalidate_relay_interfaces();
                    }
                }
                if changed {
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
}

struct PollListener {
    token: SocketToken,
    udp: Option<Arc<DnsSocket>>,
    tcp: Option<TcpListener>,
}

struct PollTcpClient {
    stream: TcpStream,
    service: LocalDnsService,
    forward: TcpDnsService,
    framer: TcpFramer,
    deadline: Instant,
    queries: usize,
    input: Vec<u8>,
    input_offset: usize,
    phase: TcpClientPhase,
}

enum TcpClientPhase {
    Reading,
    Forwarding { cache_eligible: bool, wait: TcpWait },
    Writing { frame: Vec<u8>, offset: usize },
}

impl PollTcpClient {
    fn queue_answer(
        &mut self,
        parent: &Arc<Mutex<ParentDns>>,
        packet: Vec<u8>,
        insert_cache: bool,
    ) -> Result<(), ()> {
        let bogus = self.forward.take_bogus_cache_entry();
        if insert_cache || bogus.is_some() {
            let mut parent = parent.lock().map_err(|_| ())?;
            if let Some(daemon) = parent.daemon.as_mut() {
                if let Some((name, ttl)) = bogus {
                    daemon.cache_bogus_reply(name, ttl, now_seconds());
                } else {
                    daemon.cache_tcp_reply(&packet, now_seconds());
                }
            }
        }
        self.phase = TcpClientPhase::Writing {
            frame: encode_tcp_frame(&packet).map_err(|_| ())?,
            offset: 0,
        };
        Ok(())
    }

    // A small per-turn budget prevents pipelined queries on one connection
    // starving UDP/DHCP. Partial input, upstream I/O and downstream writes
    // retain their offsets; WouldBlock always yields to the service owner.
    fn step(&mut self, parent: &Arc<Mutex<ParentDns>>) -> Result<bool, ()> {
        for _ in 0..8 {
            if Instant::now() >= self.deadline || STOP_REQUESTED.load(Ordering::Acquire) {
                return Ok(false);
            }
            match &mut self.phase {
                TcpClientPhase::Writing { frame, offset } => {
                    match self.stream.write(&frame[*offset..]) {
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
                        self.phase = TcpClientPhase::Reading;
                    }
                }
                TcpClientPhase::Forwarding {
                    cache_eligible,
                    wait,
                } => {
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
                    let cache_eligible = *cache_eligible;
                    match self
                        .forward
                        .step_with_local_upstream(&self.service)
                        .map_err(|_| ())?
                    {
                        TcpServiceProgress::Pending(wait) => {
                            self.phase = TcpClientPhase::Forwarding {
                                cache_eligible,
                                wait,
                            };
                            return Ok(true);
                        }
                        TcpServiceProgress::Complete(packet, from_upstream) => {
                            self.queue_answer(parent, packet, cache_eligible && from_upstream)?;
                        }
                    }
                }
                TcpClientPhase::Reading => {
                    if self.input_offset == self.input.len() {
                        self.input.resize(4096, 0);
                        self.input_offset = 0;
                        match self.stream.read(&mut self.input) {
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
                    let answered = {
                        let mut parent = parent.lock().map_err(|_| ())?;
                        let daemon = parent.daemon.as_mut().ok_or(())?;
                        let cached = daemon
                            .cached_tcp_answer(&query, &mut self.service, now_seconds())
                            .map_err(|_| ())?;
                        cached.or_else(|| {
                            daemon
                                .local_tcp_answer(&query, &mut self.service, now_seconds())
                                .ok()
                                .flatten()
                        })
                    };
                    if let Some(packet) = answered {
                        self.queue_answer(parent, packet, false)?;
                    } else {
                        let cache_eligible = TcpDnsService::cache_eligible(&query);
                        match self
                            .forward
                            .start_with_local_upstream(&query, &self.service, self.deadline)
                            .map_err(|_| ())?
                        {
                            TcpServiceProgress::Pending(wait) => {
                                self.phase = TcpClientPhase::Forwarding {
                                    cache_eligible,
                                    wait,
                                };
                                return Ok(true);
                            }
                            TcpServiceProgress::Complete(packet, from_upstream) => {
                                self.queue_answer(parent, packet, cache_eligible && from_upstream)?;
                            }
                        }
                    }
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
        let step = files.step();
        self.files_runnable = step.runnable;
        if DEBUG_MODE.load(Ordering::Relaxed) {
            for diagnostic in step.diagnostics {
                eprintln!("dnsmasq-rs: {diagnostic}");
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
    fn append_file_fds(&self, fds: &mut Vec<owrt_ubus::sys::PollFd>) {
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
            self.append_file_fds(&mut fds);
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
    }

    fn step_udp(&mut self, index: usize) {
        if self.files_initializing() {
            return;
        }
        let Some(udp) = self.listeners[index].udp.as_ref().map(Arc::clone) else {
            return;
        };
        let token = self.listeners[index].token;
        let mut query = vec![0; 65_535];
        let incoming = match udp.receive(&mut query) {
            Ok(Some(incoming)) if incoming.len <= self.packet_limit => incoming,
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
            local.local_network = listeners::local_network(&interfaces, incoming.destination);
        }
        let packet = &query[..incoming.len];
        let answer = match dnsmasq_rs::dns::udp_query::inspect(packet, local.edns_packet_max) {
            dnsmasq_rs::dns::udp_query::Admission::Drop => return,
            dnsmasq_rs::dns::udp_query::Admission::Reply(answer) => Some((answer, false)),
            dnsmasq_rs::dns::udp_query::Admission::Continue => {
                match daemon.local_udp_answer(packet, local, now_seconds()) {
                    Ok(Some(answer)) => Some((answer, false)),
                    Ok(None) => match daemon.forward_udp_on_listener_with_local(
                        packet,
                        ClientRequest {
                            source: incoming.peer,
                            destination: incoming.destination,
                            interface: incoming.interface,
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
                incoming.peer,
                (!self.config.bind_interfaces && !self.config.bind_dynamic)
                    .then_some((incoming.destination, incoming.interface)),
            );
            if stale {
                event.stale_answered = event.stale_answered.wrapping_add(1);
                // Preserve dnsmasq's send-before-refresh ordering.  The
                // refresh may enqueue an upstream response for a later turn;
                // it must not hold the parent lock while that I/O completes.
                if let Ok(mut parent) = self.service.lock() {
                    if let Some(daemon) = parent.daemon.as_mut() {
                        let refresh = daemon.refresh_udp_on_listener(
                            &query[..incoming.len],
                            ClientRequest {
                                source: incoming.peer,
                                destination: incoming.destination,
                                interface: incoming.interface,
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
        let parent = match self.service.lock() {
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
        snapshot.local_network = local_network;
        let forward = if let Some(daemon) = &parent.daemon {
            daemon.tcp_snapshot()
        } else {
            TcpDnsService::new(&self.config, &self.resolvers, self.edns_max)
        };
        drop(parent);
        let Ok(forward) = forward else {
            return;
        };
        if let Ok(mut event) = self.parent_events.lock() {
            event.tcp_active = event.tcp_active.saturating_add(1);
        }
        self.clients.push(PollTcpClient {
            stream,
            service: snapshot,
            forward,
            framer: TcpFramer::with_max_frame(self.packet_limit),
            deadline: Instant::now() + Duration::from_secs(150),
            queries: 0,
            input: Vec::new(),
            input_offset: 0,
            phase: TcpClientPhase::Reading,
        });
    }

    fn step_tcp_clients(&mut self) {
        let mut index = 0;
        while index < self.clients.len() {
            let result = self.clients[index].step(&self.service);
            if result.unwrap_or(false) {
                index += 1;
            } else {
                self.clients.swap_remove(index);
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
        let full_deadline = Instant::now() + timeout;
        let mut deadline = full_deadline;
        let mut fds = vec![PollFd {
            fd: icmp.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        }];
        if let Some(logger) = &self.logger {
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
            deadline = deadline.min(client.deadline);
            let (fd, events) = match &client.phase {
                TcpClientPhase::Reading => {
                    if client.input_offset < client.input.len() {
                        deadline = Instant::now();
                    }
                    (client.stream.as_raw_fd(), POLLIN)
                }
                TcpClientPhase::Writing { .. } => (client.stream.as_raw_fd(), POLLOUT),
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
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        let ready = owrt_ubus::sys::poll_fds(&mut fds, millis)?;
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
        self.step_neighbors();
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
        if let Some(report) = provider.take_maintenance_report() {
            report_dhcp_maintenance(&report, self.logger.as_mut());
        }
        drop(provider);
        self.dhcp = Some(dhcp);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_neighbors(&mut self) {
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
            use dnsmasq_rs::logging::{LogEvent, Priority, Service};
            for event in events {
                if let Some((code, message)) = event.error_message() {
                    if code != 1 || !quiet_not_found {
                        logger.emit(LogEvent::new(Service::Tftp, Priority::Error, message.to_vec()));
                    }
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
    let defaults = ScalarConfig::default();
    if scalar.max_ttl != defaults.max_ttl {
        return Err(Error("scalar option is not implemented"));
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
