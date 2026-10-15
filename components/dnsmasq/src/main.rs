//! Small foreground runner for the implemented DNS UDP/TCP and upstream path.
//!
//! The library remains the compatibility boundary.  This binary intentionally
//! rejects directives whose owning engine is not present yet; silently ignoring
//! a DHCP or TFTP option would make a package appear deployable while
//! dropping configured behavior.

// This independent source branch is an excluded allocation diagnostic.
mod udp_allocation_diagnostic;
#[global_allocator]
static DIAGNOSTIC_ALLOCATOR: udp_allocation_diagnostic::Meter = udp_allocation_diagnostic::Meter;

#[cfg(all(
    target_os = "linux",
    target_env = "musl",
    target_pointer_width = "64",
    target_feature = "crt-static"
))]
mod startup_relro;

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
use dnsmasq_rs::dns::filewatch::{NetworkEvents, RouteWatch, WatchError};
use dnsmasq_rs::dns::forward::SocketToken;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::dns::lease_names::{LeasePolicy, PublicationWarning};
use dnsmasq_rs::dns::service::{LocalDnsService, TcpFramer, TcpWriteFrame};
#[cfg(test)]
use dnsmasq_rs::dns::service::encode_tcp_frame;
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
use std::borrow::Cow;
use std::cell::RefCell;
use std::ffi::OsString;
#[cfg(feature = "m6b-diagnostics")]
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(not(target_os = "linux"))]
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static RELOAD_REQUESTED: AtomicUsize = AtomicUsize::new(0);
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);
static LOG_REOPEN_REQUESTED: AtomicUsize = AtomicUsize::new(0);
static CACHE_DUMP_REQUESTED: AtomicUsize = AtomicUsize::new(0);
static ALARM_REQUESTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static SIGNAL_WAKE_WRITE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
// SIGHUP is 1 on the supported Linux and Darwin hosts.
const SIGHUP: i32 = 1;
#[cfg(target_os = "linux")]
const SIGUSR1: i32 = 10;
#[cfg(target_os = "linux")]
const SIGUSR2: i32 = 12;
#[cfg(not(target_os = "linux"))]
const SIGUSR1: i32 = 30;
#[cfg(not(target_os = "linux"))]
const SIGUSR2: i32 = 31;
const SIGALRM: i32 = 14;
const UDP_PACKETS_PER_TURN: usize = 16;
const RELOAD_FILE_TURNS_PER_EVENT: usize = 16;
const UBUS_RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn read(fd: i32, buffer: *mut u8, length: usize) -> isize;
    fn write(fd: i32, buffer: *const u8, length: usize) -> isize;
    fn __errno_location() -> *mut i32;
}

#[cfg(target_os = "linux")]
fn wake_signal_waiter() {
    let fd = SIGNAL_WAKE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = [1u8; 1];
        // SAFETY: the handler writes one byte from a live stack buffer to the
        // process-owned nonblocking pipe; write(2) is async-signal-safe. Linux
        // errno is thread-local; preserve the interrupted caller's value.
        unsafe {
            let errno = __errno_location();
            let saved_errno = *errno;
            let _ = write(fd, byte.as_ptr(), 1);
            *errno = saved_errno;
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn wake_signal_waiter() {}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs() as i64)
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn neighbor_poll_deadline(epoch_seconds: u64, now: Instant, realtime: Duration) -> Instant {
    let remaining = Duration::from_secs(epoch_seconds).saturating_sub(realtime);
    now.checked_add(remaining).unwrap_or(now)
}

#[cfg(target_os = "linux")]
fn owner_poll_timeout(deadline: Option<Instant>, now: Instant, runnable: bool) -> i32 {
    if runnable {
        return 0;
    }
    let Some(deadline) = deadline else {
        return -1;
    };
    deadline.saturating_duration_since(now).as_nanos()
        .div_ceil(1_000_000).min(i32::MAX as u128) as i32
}

extern "C" fn request_stop(_signal: i32) {
    STOP_REQUESTED.store(true, Ordering::Release);
    wake_signal_waiter();
}

extern "C" fn request_reload(_signal: i32) {
    // Standard signals coalesce in the kernel. Each delivered handler maps
    // to a distinct C EVENT_RELOAD and must survive an active file read.
    let _ = RELOAD_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
    wake_signal_waiter();
}

extern "C" fn request_log_reopen(_signal: i32) {
    let _ = LOG_REOPEN_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
    wake_signal_waiter();
}

extern "C" fn request_cache_dump(_signal: i32) {
    let _ = CACHE_DUMP_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
    wake_signal_waiter();
}

extern "C" fn request_alarm(_signal: i32) {
    let _ = ALARM_REQUESTED.fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
    wake_signal_waiter();
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
    wake_signal_waiter();
    // The nodhcpv6/no-DNSSEC C variant has no EVENT_TIME work in normal mode.
}

fn main() {
    #[cfg(all(
        target_os = "linux",
        target_env = "musl",
        target_pointer_width = "64",
        target_feature = "crt-static"
    ))]
    if let Err(error) = startup_relro::protect() {
        eprintln!("dnsmasq: cannot protect GNU_RELRO: {error}");
        std::process::exit(5);
    }
    #[cfg(target_os = "linux")]
    {
        unsafe extern "C" {
            fn umask(mask: u32) -> u32;
        }
        // SAFETY: umask accepts a scalar mode and runs before any service starts.
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
        let blank_line = blank_line
            || error.is::<dnsmasq_rs::logging::LogStartError>()
            || error.is::<dnsmasq_rs::startup::PidStartError>()
            || error.is::<dnsmasq_rs::dump::DumpError>();
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
        #[cfg(target_os = "linux")]
        if let Some(raw) = error.downcast_ref::<dnsmasq_rs::startup::PidStartError>() {
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(b"dnsmasq-rs: ");
            let _ = stderr.write_all(&raw.message_bytes());
            let _ = stderr.write_all(b"\n");
            std::process::exit(startup_status(error.as_ref()));
        }
        #[cfg(target_os = "linux")]
        if let Some(raw) = error.downcast_ref::<dnsmasq_rs::dump::DumpError>() {
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(b"dnsmasq-rs: ");
            let _ = stderr.write_all(&raw.message);
            let _ = stderr.write_all(b"\n");
            std::process::exit(3);
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
    #[cfg(target_os = "linux")]
    if let Some(error) = error.downcast_ref::<dnsmasq_rs::startup::PidStartError>() {
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
    #[cfg(target_os = "linux")]
    if error.is::<dnsmasq_rs::dump::DumpError>() {
        return 3;
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
    dump: dnsmasq_rs::config::dump::DumpConfig,
}

// C's UDP listeners mutate one parent hosts generation. Each accepted TCP
// connection takes its own snapshot; a later reload does not change it.
struct ParentDns {
    query_ids: dnsmasq_rs::query_logging::QueryIds,
    local: LocalDnsService,
    daemon: Option<DnsDaemon>,
    /// New static views awaiting the DHCP provider's configured-name update
    /// and final DNS publication. Queries keep using the published local view.
    pending_hosts: Option<(Hosts, Hosts)>,
    /// Initial admission remains closed across HUP until the initial loading
    /// attempt is published or explicitly abandoned. Runtime HUP is separate.
    hosts_initializing: bool,
}

impl ParentDns {
    fn provider_hosts(&self) -> &Hosts {
        self.pending_hosts.as_ref().map_or(&self.local.hosts, |(hosts, _)| hosts)
    }

    fn provider_hosts_mut(&mut self) -> &mut Hosts {
        self.pending_hosts.as_mut().map_or(&mut self.local.hosts, |(hosts, _)| hosts)
    }

    fn import_tcp_cache_transfer(
        &mut self,
        transaction: dnsmasq_rs::dns::cache::CacheTransaction,
        now: i64,
    ) -> bool {
        self.daemon.as_mut().is_some_and(|daemon| {
            daemon.import_tcp_cache_transfer(transaction, now, &self.local)
        })
    }
}

/// One serialized parent event, including synchronous ubus callbacks. These
/// counters belong to the actual UDP send and TCP-session lifetime below;
/// cache/forward/DHCP counters stay with their engines and are only borrowed.
struct ParentEvents {
    ubus_name: Option<Vec<u8>>,
    ubus: Option<UbusService>,
    ubus_error_logged: bool,
    ubus_registration_error_logged: bool,
    ubus_retry_at: Instant,
    #[cfg(target_os = "linux")]
    ubus_notices: Vec<dnsmasq_rs::logging::LogEvent>,
    local_answered: u32,
    stale_answered: u32,
    tcp_active: usize,
    tcp_high_water: usize,
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
            ubus_registration_error_logged: false,
            ubus_retry_at: Instant::now() + UBUS_RETRY_INTERVAL,
            #[cfg(target_os = "linux")]
            ubus_notices: Vec::new(),
            local_answered: 0,
            stale_answered: 0,
            tcp_active: 0,
            tcp_high_water: 0,
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
        self.ubus_registration_error_logged = false;
        self.ubus_retry_at = Instant::now();
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
            if Instant::now() < self.ubus_retry_at {
                return;
            }
            #[cfg(target_os = "linux")]
            self.queue_missing_ubus_notice();
            let Some(name) = self.ubus_name.as_deref() else {
                return;
            };
            match UbusService::connect_bytes_interruptible(
                None, name, Some(|| STOP_REQUESTED.load(Ordering::Acquire)),
            ) {
                Ok(service) => {
                    self.ubus = Some(service);
                    self.ubus_error_logged = false;
                    self.ubus_registration_error_logged = false;
                    #[cfg(target_os = "linux")]
                    self.ubus_notices.push(dnsmasq_rs::logging::LogEvent::new(
                        dnsmasq_rs::logging::Service::Dns,
                        dnsmasq_rs::logging::Priority::Info,
                        b"connected to system UBus".to_vec(),
                    ));
                }
                Err(ConnectError::Transport(_)) => {
                    self.ubus_retry_at = Instant::now() + UBUS_RETRY_INTERVAL;
                    return;
                }
                Err(ConnectError::Registration(error)) => {
                    // ACLs and object collisions can be temporary. Keep the
                    // configured name and retry, without flooding logs or
                    // depending on a later DNS/DHCP packet to wake the owner.
                    #[cfg(target_os = "linux")]
                    if !self.ubus_registration_error_logged {
                        self.ubus_notices.push(dnsmasq_rs::logging::LogEvent::new(
                            dnsmasq_rs::logging::Service::Dns,
                            dnsmasq_rs::logging::Priority::Error,
                            ConnectError::registration_message(&error).into_bytes(),
                        ));
                    }
                    self.ubus_registration_error_logged = true;
                    self.ubus_retry_at = Instant::now() + UBUS_RETRY_INTERVAL;
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
    parent: Rc<RefCell<ParentDns>>,
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
            .try_borrow_mut()
            .map_err(|_| io::Error::other("DNS state already borrowed"))?;
        let ParentDns { local, daemon, pending_hosts, hosts_initializing, .. } = &mut *parent;
        let daemon = daemon
            .as_mut()
            .ok_or_else(|| io::Error::other("DNS publication is disabled"))?;
        if let Some((hosts, _)) = pending_hosts.as_mut() {
            // Configuration reconciliation needed the retained DHCP entries.
            // lease_update_dns then unhashes that old DHCP source before
            // inserting the new names and performing their static lookups.
            hosts.finish_bulk();
        }
        let hosts = pending_hosts.as_mut().map_or(&mut local.hosts, |(hosts, _)| hosts);
        let names = daemon.publish_lease_names(
            records,
            hosts,
            &local.config.records.cnames,
            self.policy,
        );
        report_lease_name_warnings(&names);
        if let Some((hosts, snapshot)) = pending_hosts.take() {
            daemon.publish_hosts_source(snapshot);
            local.hosts = hosts;
            *hosts_initializing = false;
        }
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
        dump: Default::default(),
    };
    let action = loader::load(args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        // These booleans are accepted by option.c but their consumers are
        // compiled out in the exact NO_DHCP6/NO_DNSSEC image.
        if matches!(directive.name.as_slice(), b"log-malloc" | b"quiet-ra" | b"quiet-dhcp6"
            | b"enable-ra" | b"dnssec-debug" | b"dnssec-no-timecheck") {
            return Ok(());
        }
        if runtime.logging.apply(directive)?
            || runtime.process.apply(directive)?
            || runtime.scalar.apply(directive)?
            || runtime.dns.apply_resolved(directive)?
            || runtime.tftp.apply(directive)?
            || runtime.dhcp.apply(directive)?
            || runtime.ubus.apply(directive)?
            || runtime.script_arp.apply(directive)?
            || runtime.dump.apply(directive)?
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
    // option.c reads domain=# once during read_opts, before --test success
    // and before suffix-dependent SRV, hosts and lease publication.
    if config.domain_from_resolv {
        if !config.no_resolv && config.no_poll && config.resolv_files.len() > 1 {
            return Err(config_diagnostic(Error(
                "only one resolv.conf file allowed in no-poll mode.",
            )));
        }
        if config.no_resolv || config.resolv_files.len() != 1 {
            return Err(config_diagnostic(Error(
                "must have exactly one resolv.conf to read domain from.",
            )));
        }
        let path = &config.resolv_files[0];
        let file = std::fs::File::open(path).map_err(|error| {
            let mut diagnostic = config_diagnostic(Error("resolver domain read failed"));
            diagnostic.exit_code = 3;
            let message = error.to_string();
            let message = message.split(" (os error ").next().unwrap_or(&message);
            diagnostic.message = format!("failed to read {}: {}", path.display(), message);
            diagnostic
        })?;
        config.domain_suffix = dnsmasq_rs::config::domains::resolver_search_domain_reader(
            std::io::BufReader::new(file),
            config.domain_suffix.take(),
        );
        if config.domain_suffix.is_none() {
            let mut diagnostic = config_diagnostic(Error("resolver search directive missing"));
            diagnostic.exit_code = 5;
            diagnostic.message = format!("no search directive found in {}", path.display());
            return Err(diagnostic);
        }
    }
    config.finalize().map_err(|error| {
        let mut diagnostic = config_diagnostic(error.clone());
        if error == Error("CNAME loop") {
            if let Some(alias) = config.records.cname_loop_alias() {
                diagnostic.message =
                    format!("CNAME loop involving {}", String::from_utf8_lossy(alias));
            }
        } else if error == Error("bad SRV name after domain appended") {
            diagnostic.exit_code = 5;
            diagnostic.message =
                "bad srv-host name No error information after domain appended".into();
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
            } else if let Some(pid) = error.downcast_ref::<dnsmasq_rs::startup::PidStartError>() {
                startup.fail_pid(pid.errno(), pid.argument());
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
    #[cfg(target_os = "linux")]
    let dump = dnsmasq_rs::dump::DumpHandle::open(&runtime.dump, runtime.scalar.edns_packet_max)?;
    #[cfg(target_os = "linux")]
    dump.set_query_logging(runtime.logging.queries);
    let dns_enabled = runtime.scalar.dns_port != 0;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let (initial_interface_records, initial_interface_collector) = {
        if runtime.dns.interface_records.rules.is_empty() && !runtime.dns.needs_domain_interfaces()
        {
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
                    collector.deadline().map_or(0, |deadline| {
                        deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis()
                            .min(i32::MAX as u128) as i32
                    })
                };
                owrt_ubus::sys::poll_fds(&mut fds, wait)?;
            };
            if let Some(error) = result.error {
                return Err(Box::new(error));
            }
            runtime.dns.domain_interfaces = domain_interface_snapshot(&result.addresses);
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
    #[cfg(target_os = "linux")]
    let hosts = if dns_enabled {
        // C reads ordinary hosts at EVENT_INIT, after logging is available.
        // This also permits bad-token notices to stream without a startup queue.
        dnsmasq_rs::dns::local::configured_hosts(&runtime.dns, runtime.scalar.local_ttl)
    } else {
        Hosts::new()
    };
    #[cfg(not(target_os = "linux"))]
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
    let interface_snapshot = Rc::new(RefCell::new(
        listeners::snapshot().map_err(NetworkStartupError)?,
    ));
    let addresses = listeners::bound_addresses(
        &runtime.dns,
        runtime.scalar.dns_port,
        &interface_snapshot.borrow_mut(),
    );
    let mut pending_static_dns = listeners::tentative_addresses(
        &runtime.dns,
        runtime.scalar.dns_port,
        &interface_snapshot.borrow_mut(),
    );
    let tftp_config = runtime.tftp.clone();
    let dhcp_config = runtime.dhcp.clone();
    #[cfg(target_os = "linux")]
    let signal_wake = owrt_ubus::sys::nonblocking_pipe().ok();
    #[cfg(target_os = "linux")]
    if let Some((_, write_end)) = &signal_wake {
        SIGNAL_WAKE_WRITE.store(write_end.as_raw_fd(), Ordering::Release);
    }
    DEBUG_MODE.store(runtime.process.debug, Ordering::Relaxed);
    owrt_ubus::sys::set_signal_handler(owrt_ubus::sys::SIGINT, request_interrupt);
    owrt_ubus::sys::set_signal_handler(owrt_ubus::sys::SIGTERM, request_stop);
    owrt_ubus::sys::set_signal_handler(SIGHUP, request_reload);
    owrt_ubus::sys::set_signal_handler(SIGUSR2, request_log_reopen);
    owrt_ubus::sys::set_signal_handler(SIGUSR1, request_cache_dump);
    owrt_ubus::sys::set_signal_handler(SIGALRM, request_alarm);
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
        #[cfg(target_os = "linux")]
        daemon.set_dump(dump.clone());
        daemon.set_query_logging(runtime.logging.queries);
        daemon.enable_negative_cache(
            runtime.scalar.negative_ttl,
            !daemon_config.no_negative_cache,
        );
        Some(daemon)
    } else {
        None
    };
    let service = Rc::new(RefCell::new(ParentDns {
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
        query_ids: Default::default(),
        pending_hosts: None,
        hosts_initializing: false,
    }));
    {
        let mut parent = service.borrow_mut();
        parent.local.query_logging = runtime.logging.queries.enabled;
        parent.local.interfaces = Arc::clone(&initial_interface_records);
        if let Some(daemon) = &mut parent.daemon {
            daemon.publish_interface_records(Arc::clone(&initial_interface_records));
        }
    }
    // C mutates all parent engines in one event loop. Fetch DHCP metrics
    // before borrowing DNS; synchronous doctor callbacks must not reborrow it.
    // Socket waits run after these short-lived borrows are released.
    let parent_events = Rc::new(RefCell::new(ParentEvents::new(&runtime.ubus)?));
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
            let config_dns = Rc::clone(&service);
            provider.set_config_host_lookup(move |name| {
                let mut parent = config_dns
                    .try_borrow_mut()
                    .map_err(|_| io::Error::other("DNS state already borrowed"))?;
                let matches = parent.provider_hosts_mut().lookup(name, Some(false), false);
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
            let boot_dns = Rc::clone(&service);
            provider.set_boot_host_lookup(move |name| {
                let mut parent = boot_dns
                    .try_borrow_mut()
                    .map_err(|_| io::Error::other("DNS state already borrowed"))?;
                Ok(parent
                    .provider_hosts_mut()
                    .lookup(name, Some(false), false)
                    .first()
                    .and_then(|host| match host.address {
                        IpAddr::V4(address) => Some(address),
                        IpAddr::V6(_) => None,
                    }))
            });
            let reverse_dns = Rc::clone(&service);
            provider.set_reverse_host_lookup(move |address| {
                let parent = reverse_dns
                    .try_borrow_mut()
                    .map_err(|_| io::Error::other("DNS state already borrowed"))?;
                Ok(parent
                    .provider_hosts()
                    .provider_reverse(IpAddr::V4(address))
                    .map(|host| host.name.clone()))
            });
            provider.set_dns_publisher(Box::new(LeasePublisher {
                parent: Rc::clone(&service),
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
        let shared_provider = Rc::new(RefCell::new(provider));
        Some(shared_provider)
    } else {
        None
    };
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let mut dhcp_runtime = if provider.is_some() || !dhcp_config.relay.is_empty() {
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
        listener.set_dump(dump.clone());
        listener.set_logging(dhcp_config.log_dhcp);
        Some(DhcpService {
            provider,
            listener,
            pxe_next: false,
            output: vec![0; 16_384],
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
    listeners::validate_bind_interfaces(&daemon_config, &interface_snapshot.borrow_mut())
        .map_err(NetworkStartupError)?;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let mut tftp_listener = if tftp_config.enabled {
        match TftpListener::bind_config(
            &tftp_config,
            &daemon_config,
            &runtime.dhcp.no_dhcp_interfaces.iter()
                .chain(&runtime.dhcp.no_dhcp6_interfaces).cloned().collect::<Vec<_>>(),
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
    if let Some(listener) = &mut tftp_listener {
        listener.set_dump(dump.clone());
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if daemon_config.bind_interfaces || daemon_config.bind_dynamic {
        if let Some(dhcp) = &mut dhcp_runtime {
            let device =
                dhcp_device_name(&daemon_config, &dhcp_config, &interface_snapshot.borrow());
            dhcp.listener
                .configure_device_binding(
                    device,
                    dhcp.provider.is_some() && dhcp_config.relay.is_empty(),
                )
                .map_err(|error| {
                    NetworkStartupError(io::Error::other(format!(
                        "failed to set SO_BINDTODEVICE on DHCP socket: {}",
                        dnsmasq_rs::logging::error_text(&error)
                    )))
                })?;
        }
    }
    // dnsmasq.c:418-422 scales the socket pool by signed ftabsize / 2
    // after binding the listeners. Values below -1 require an impossible
    // size_t allocation. Preserve EC_NOMEM without attempting that allocation.
    if dns_enabled && runtime.scalar.forward_max < -1 {
        return Err(Box::new(dnsmasq_rs::startup::StartupError {
            code: 4,
            message: "could not get memory".into(),
        }));
    }
    // Bind the receiving listeners before sending initial loop probes. A
    // returned startup probe can arrive immediately, including before the
    // owner starts polling. C also binds its listeners before check_servers.
    {
        let mut parent = service.borrow_mut();
        if let Some(daemon) = &mut parent.daemon {
            daemon.check_server_addresses(&dns_local_addresses(
                &daemon_config,
                &interface_snapshot.borrow_mut(),
                runtime.scalar.dns_port,
            ))?;
            parent.local.config = daemon.local_config().clone().into();
        }
    }
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
                &error.message_bytes(),
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
    let route_watch = Some(RouteWatch::new()
        .map_err(|error| dnsmasq_rs::startup::StartupError {
            code: 5,
            message: format!("cannot create netlink socket: {error}"),
        })?);
    #[cfg(target_os = "linux")]
    dns_files.request(ReloadReason::Init);
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(provider) = dhcp_runtime
        .as_ref()
        .and_then(|dhcp| dhcp.provider.as_ref())
    {
        provider
            .try_borrow_mut()
            .map_err(|_| io::Error::other("DHCP state already borrowed"))?
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
        Rc::clone(&service),
        Rc::clone(&parent_events),
        Rc::clone(&interface_snapshot),
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
        Rc::clone(&service),
        Rc::clone(&parent_events),
        Rc::clone(&interface_snapshot),
        daemon_config.clone(),
        resolvers.clone(),
        packet_limit,
        tcp_limit,
        daemon_options.edns_packet_max,
        poll_listeners,
    );
    #[cfg(target_os = "linux")]
    if let Some((read_end, write_end)) = signal_wake {
        poll.signal_wake_read = Some(read_end);
        poll.signal_wake_write = Some(write_end);
    }
    #[cfg(target_os = "linux")]
    {
        poll.dump = dump;
        poll.query_logging = runtime.logging.queries;
    }
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
        if let (Some(error), Some(path)) = (
            pid_file.ownership_warning(),
            runtime.process.pid_file.as_ref(),
        ) {
            let path = path.display();
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
            let event = parent_events.borrow_mut();
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
        if let (Some(error), Some(path)) = (log_ownership_warning, runtime.logging.file.as_deref())
        {
            logger.emit(dnsmasq_rs::logging::ownership_warning(path, &error));
        }

        for warning in dnsmasq_rs::logging::startup::missing_interfaces(
            &daemon_config,
            &interface_snapshot.borrow_mut(),
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
        for relay in &runtime.dhcp.relay {
            logger.emit(dnsmasq_rs::logging::startup::dhcp_relay(relay));
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(device) = poll
            .dhcp
            .as_ref()
            .and_then(|dhcp| dhcp.listener.bound_device_notice())
        {
            let mut message = b"DHCP, sockets bound exclusively to interface ".to_vec();
            message.extend_from_slice(device);
            logger.emit(LogEvent::new(Service::Dhcp, Priority::Info, message));
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
            if let Some(daemon) = &mut service.borrow_mut().daemon {
                daemon.queue_server_notices();
            }
        }
        poll.log_dns_diagnostics(); // C releases startup errfd before check_servers.
    }
    poll.interface_refresh.complete(Instant::now(), pending_listener_retry(&pending_static_dns,
        &interface_snapshot.borrow()) || poll.tftp_pending_interfaces());
    // C's INAME_USED latch survives interface removal. Once an explicit
    // address belonged to an interface, it cannot become an unowned fallback.
    let mut owned_explicit: Vec<IpAddr> = interface_snapshot
        .borrow_mut()
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
        let _allocation_turn = udp_allocation_diagnostic::Turn::new();
        poll.interfaces_enumerated = false;
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        poll.observe_arp_activity();
        #[cfg(target_os = "linux")]
        poll.step_route_events();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        poll.step_dhcp_files();
        #[cfg(target_os = "linux")]
        poll.step_dns_files();
        #[cfg(target_os = "linux")]
        poll.step_hosts_files();
        if poll.interface_refresh.due_now() && !poll.interface_work_pending() {
            poll.interface_refresh.requested = false;
            let mut failed_snapshot = false;
            match listeners::snapshot() {
                Ok(interfaces) => {
                let previous_interfaces = interface_snapshot.borrow_mut().clone();
                let changed = previous_interfaces != interfaces;
                *interface_snapshot.borrow_mut() = interfaces.clone();
                #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                if changed {
                    if let Some(dhcp) = &mut poll.dhcp {
                        dhcp.listener.invalidate_relay_interfaces();
                    }
                }
                if changed && poll.address_refresh_requires_enumeration() {
                    poll.enumerate_interface_records();
                }
                for interface in &interfaces {
                    if daemon_config.listen_addresses.contains(&interface.address)
                        && !owned_explicit.contains(&interface.address)
                    {
                        owned_explicit.push(interface.address);
                    }
                }
                if daemon_config.bind_dynamic {
                    pending_static_dns = listeners::tentative_addresses(&daemon_config,
                        runtime.scalar.dns_port, &interfaces);
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
                        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                        if let Some(tftp) = &mut poll.tftp {
                            tftp.finish_shared_listener_attempt(address);
                        }
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
                Err(error) => {
                    failed_snapshot = true;
                    #[cfg(target_os = "linux")]
                    if let Some(logger) = &mut poll.logger {
                        use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                        logger.emit(LogEvent::new(Service::Dns, Priority::Error,
                            format!("failed to enumerate interfaces: {}", dnsmasq_rs::logging::error_text(&error)).into_bytes()));
                    }
                }
            }
            poll.interface_refresh.complete(Instant::now(), failed_snapshot
                || pending_listener_retry(&pending_static_dns, &interface_snapshot.borrow())
                || poll.tftp_pending_interfaces());
        }
        // Address events and HUP both publish before new DNS admission.
        let signaled = !poll.reload_in_progress()
            && RELOAD_REQUESTED.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                |count| count.checked_sub(1)).is_ok();
        poll.process_reload_before_dns(runtime.scalar.local_ttl, signaled)?;
        poll.step()?;
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
        poll.wait_for_files()?;
    }
    #[cfg(target_os = "linux")]
    SIGNAL_WAKE_WRITE.store(-1, Ordering::Release);
    poll.m6b.write()?;
    udp_allocation_diagnostic::write_report()?;
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
        // C flush_log waits while the destination remains connected. Backpressure
        // alone must not discard the queue; finish also stops on connection failure.
        while !logger.finish() {
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
    // This is the successful daemon-stop return to main, never a reload or
    // library restart. All remaining IO objects still drop normally. Only
    // cache heap storage is left for process exit to reclaim in one pass.
    if let Some(daemon) = service.borrow_mut().daemon.as_mut() {
        daemon.retire_cache_for_process_exit();
    }
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
    provider: Option<Rc<RefCell<DhcpProvider>>>,
    listener: DhcpSocketListener,
    pxe_next: bool,
    output: Vec<u8>,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn dhcp_device_name(
    config: &DnsConfig,
    dhcp: &dnsmasq_rs::config::dhcp::DhcpConfig,
    interfaces: &[DnsInterface],
) -> Option<Vec<u8>> {
    use dnsmasq_rs::config::dhcp_device::{which_device, DeclaredInterface, DeviceInterface};
    let declarations: Vec<_> = config
        .interfaces
        .iter()
        .map(|name| DeclaredInterface {
            name: name.as_deref(),
            // C marks INAME_USED from address labels before exclusion vetoes.
            used: name
                .as_ref()
                .is_some_and(|name| interfaces.iter().any(|interface| interface.name == *name)),
        })
        .collect();
    let excluded = |patterns: &[Option<Vec<u8>>], name: &[u8]| {
        patterns.iter().flatten().any(|pattern| {
            pattern
                .iter()
                .position(|byte| *byte == b'*')
                .map_or(pattern == name, |at| {
                    name.len() > at && name.starts_with(&pattern[..at])
                })
        })
    };
    let candidates: Vec<_> = interfaces
        .iter()
        .filter(|interface| listeners::selected(config, interface))
        .map(|interface| {
            let name = interface.link_name();
            DeviceInterface {
                name,
                dhcp4_ok: !interface.loopback && !config.auth.selected(interface.address, &interface.name)
                    && !excluded(&dhcp.no_dhcp_interfaces, name),
                // whichdevice still sees C's dhcp6_ok in the no-DHCPv6 image.
                dhcp6_ok: !interface.loopback && !config.auth.selected(interface.address, &interface.name)
                    && !excluded(&dhcp.no_dhcp6_interfaces, name),
            }
        })
        .collect();
    which_device(&declarations, &candidates).map(<[u8]>::to_vec)
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn domain_interface_snapshot(
    addresses: &[dnsmasq_rs::dns::interface_records::InterfaceAddress],
) -> Arc<dnsmasq_rs::config::domains::DomainInterfaces> {
    use dnsmasq_rs::config::domains::{DomainAddress, DomainInterfaces};
    Arc::new(DomainInterfaces {
        addresses: addresses
            .iter()
            .map(|entry| DomainAddress {
                label: entry.label.clone(),
                address: entry.address,
                prefix: entry.prefix,
            })
            .collect(),
    })
}

/// The production event owner. All daemon sockets are advanced from the
fn pending_listener_retry(pending: &[SocketAddr], interfaces: &[dnsmasq_rs::interfaces::DnsInterface]) -> bool {
    pending.iter().any(|address| {
        let mut found = false;
        let mut all_tentative = true;
        for interface in interfaces.iter().filter(|row| row.address == address.ip()
            && match address { SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() => v6.scope_id() == row.index, _ => true }) {
            found = true;
            all_tentative &= interface.tentative;
        }
        !found || all_tentative
    })
}

/// C wakes once per second only while an initial tentative listener is
/// unfinished. Ordinary configs refresh on RTM_NEWADDR/DELADDR, not a timer.
#[derive(Default)]
struct InterfaceRefresh {
    requested: bool,
    retry_at: Option<Instant>,
}

impl InterfaceRefresh {
    fn request(&mut self) { self.requested = true; }
    fn due(&self, now: Instant) -> bool {
        self.requested || self.retry_at.is_some_and(|due| due <= now)
    }
    fn due_now(&self) -> bool {
        self.requested || (self.retry_at.is_some() && self.due(Instant::now()))
    }
    fn complete(&mut self, now: Instant, pending: bool) {
        self.requested = false;
        self.retry_at = pending.then_some(now + Duration::from_secs(1));
        // BSD/Darwin has no RouteWatch in this owner; retain its old fallback.
        #[cfg(not(target_os = "linux"))]
        { self.retry_at = Some(now + Duration::from_millis(100)); }
    }
}

/// caller's loop; no listener or TCP connection gets a worker thread.
/// Shared callback state uses Rc/RefCell. Borrows end before socket waits;
/// DHCP probe callbacks use try_borrow_mut when the provider is already active.
struct SinglePoll {
    query_logging: dnsmasq_rs::config::logging::QueryLogging,
    listeners: Vec<PollListener>,
    clients: Vec<PollTcpClient>,
    pending_edns_udp: Vec<PendingEdnsUdp>,
    edns_udp_runnable: bool,
    service: Rc<RefCell<ParentDns>>,
    /// The loading generation, including its temporary reverse hash, is never
    /// visible to parent queries or copied into accepted TCP snapshots.
    hosts_staged: Option<Hosts>,
    hosts_reload_failed: bool,
    parent_events: Rc<RefCell<ParentEvents>>,
    interfaces: Rc<RefCell<Vec<DnsInterface>>>,
    config: DnsConfig,
    resolvers: Vec<SocketAddr>,
    packet_limit: usize,
    tcp_limit: usize,
    edns_max: u16,
    m6b: M6bDiagnostics,
    udp_buffer: Vec<u8>,
    #[cfg(target_os = "linux")]
    signal_wake_read: Option<OwnedFd>,
    #[cfg(target_os = "linux")]
    signal_wake_write: Option<OwnedFd>,
    #[cfg(target_os = "linux")]
    poll_fds: Vec<owrt_ubus::sys::PollFd>,
    ubus_ready: bool,
    #[cfg(target_os = "linux")]
    ready_fds: Vec<owrt_ubus::sys::PollFd>,
    #[cfg(target_os = "linux")]
    upstream_ready: bool,
    #[cfg(target_os = "linux")]
    upstream_next_due: Option<Instant>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    dhcp_ready: bool,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    tftp_ready: bool,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    neighbors_ready: bool,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    tftp_next_due: Option<Instant>,
    probe_metrics: Option<Metrics>,
    full_reload_pending: bool,
    retry_bound_listeners: bool,
    interfaces_enumerated: bool,
    pending_interface_udp: Option<PendingInterfaceUdp>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pending_udp_admission: Option<PendingUdpAdmission>,
    pending_interface_tcp: Option<PendingInterfaceTcp>,
    #[cfg(target_os = "linux")]
    pending_interface_files: Option<(dnsmasq_rs::dns::files::FileStep, bool)>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    interface_collector: Option<dnsmasq_rs::dns::interface_collect::InterfaceCollector>,
    #[cfg(target_os = "linux")]
    logger: Option<dnsmasq_rs::logging::Logger>,
    #[cfg(target_os = "linux")]
    dump: dnsmasq_rs::dump::DumpHandle,
    #[cfg(target_os = "linux")]
    early_logger: Option<dnsmasq_rs::logging::Logger>,
    #[cfg(target_os = "linux")]
    log_cleared_cache: bool,
    #[cfg(target_os = "linux")]
    dns_files: Option<DnsFiles>,
    #[cfg(target_os = "linux")]
    route_watch: Option<RouteWatch>,
    #[cfg(target_os = "linux")]
    route_retry_at: Option<Instant>,
    interface_refresh: InterfaceRefresh,
    #[cfg(target_os = "linux")]
    files_runnable: bool,
    #[cfg(target_os = "linux")]
    hosts_requests: std::collections::VecDeque<dnsmasq_rs::dns::hostsdir::HostChange>,
    #[cfg(target_os = "linux")]
    hosts_deferred: std::collections::VecDeque<dnsmasq_rs::dns::hostsdir::HostChange>,
    #[cfg(target_os = "linux")]
    hosts_read: Option<dnsmasq_rs::dns::hostsdir::HostsRead>,
    #[cfg(target_os = "linux")]
    hosts_bulk: bool,
    #[cfg(target_os = "linux")]
    hosts_full_reload: bool,
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

/// Optional M6b event-loop counters. The sidecar is compiled only with the
/// `m6b-diagnostics` feature and enabled when `DNSMASQ_M6B_WAKE_METRICS` names an output file, so normal service runs do not
/// pay for formatting or file I/O.  Counters are intentionally local to the
/// single poll owner; no mutex or background sampler is needed.
#[derive(Default)]
struct M6bListenerCounters {
    step_calls: u64,
    receive_attempts: u64,
    received_packets: u64,
    would_block: u64,
    receive_errors: u64,
    buffer_alloc_count: u64,
    buffer_alloc_bytes: u64,
    buffer_reuses: u64,
    max_batch: u64,
    budget_yields: u64,
}

#[cfg(feature = "m6b-diagnostics")]
struct M6bDiagnostics {
    path: Option<std::path::PathBuf>,
    origin: Instant,
    last_write: Instant,
    loop_rounds: u64,
    wait_calls: u64,
    poll_calls: u64,
    poll_ready: u64,
    poll_wait_ns: u128,
    wait_timeout_zero: u64,
    wait_timeout_two_ms: u64,
    wait_ready: u64,
    wait_network: u64,
    wait_file: u64,
    wait_timer: u64,
    wait_runnable: u64,
    wait_signal: u64,
    wait_ns: u128,
    wait_durations_ns: Vec<u64>,
    listeners: Vec<M6bListenerCounters>,
}

#[cfg(feature = "m6b-diagnostics")]
impl M6bDiagnostics {
    fn new(listener_count: usize) -> Self {
        let now = Instant::now();
        let path = std::env::var_os("DNSMASQ_M6B_WAKE_METRICS").map(std::path::PathBuf::from);
        Self {
            path,
            origin: now,
            last_write: now,
            loop_rounds: 0,
            wait_calls: 0,
            poll_calls: 0,
            poll_ready: 0,
            poll_wait_ns: 0,
            wait_timeout_zero: 0,
            wait_timeout_two_ms: 0,
            wait_ready: 0,
            wait_network: 0,
            wait_file: 0,
            wait_timer: 0,
            wait_runnable: 0,
            wait_signal: 0,
            wait_ns: 0,
            wait_durations_ns: Vec::new(),
            listeners: (0..listener_count)
                .map(|_| M6bListenerCounters::default())
                .collect(),
        }
    }

    fn enabled(&self) -> bool {
        self.path.is_some()
    }

    fn record_loop(&mut self) { self.loop_rounds += 1; }

    fn listener_mut(&mut self, index: usize) -> &mut M6bListenerCounters {
        if index >= self.listeners.len() {
            self.listeners
                .resize_with(index + 1, M6bListenerCounters::default);
        }
        &mut self.listeners[index]
    }

    fn record_wait(
        &mut self,
        timeout: i32,
        ready: usize,
        elapsed: Duration,
        network_ready: bool,
        file_ready: bool,
        signal_ready: bool,
    ) -> io::Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        let elapsed_ns = elapsed.as_nanos();
        self.wait_calls += 1;
        self.poll_calls += 1;
        self.wait_ns += elapsed_ns;
        self.poll_wait_ns += elapsed_ns;
        self.wait_durations_ns
            .push(elapsed_ns.min(u64::MAX as u128) as u64);
        if ready != 0 {
            self.wait_ready += 1;
            self.poll_ready += 1;
        }
        if timeout == 0 {
            self.wait_timeout_zero += 1;
            self.wait_runnable += 1;
        } else if timeout == 2 {
            self.wait_timeout_two_ms += 1;
        }
        if network_ready {
            self.wait_network += 1;
        }
        if file_ready {
            self.wait_file += 1;
        }
        if ready == 0 && timeout != 0 {
            self.wait_timer += 1;
        }
        if signal_ready {
            self.wait_signal += 1;
        }
        if self.last_write.elapsed() >= Duration::from_millis(500) {
            self.write_snapshot()?;
            self.last_write = Instant::now();
        }
        Ok(())
    }

    fn write_snapshot(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let temporary = path.with_extension("json.tmp");
        let mut output = File::create(&temporary)?;
        write!(
            output,
            "{{\"monotonic_ns\":{},\"loop_rounds\":{},\"poll_calls\":{},\"poll_wait_ns\":{},\"wait_durations_ns\":[",
            self.origin.elapsed().as_nanos(),
            self.loop_rounds,
            self.poll_calls,
            self.poll_wait_ns,
        )?;
        for (index, duration) in self.wait_durations_ns.iter().enumerate() {
            if index != 0 {
                output.write_all(b",")?;
            }
            write!(output, "{duration}")?;
        }
        write!(
            output,
            "],\"wait_reasons\":{{\"files_timeout_0\":{},\"files_timeout_2ms\":{},\"ready\":{},\"poll_ready\":{},\"network\":{},\"file\":{},\"timer\":{},\"runnable\":{},\"signal\":{}}},\"udp_listeners\":[",
            self.wait_timeout_zero,
            self.wait_timeout_two_ms,
            self.wait_ready,
            self.poll_ready,
            self.wait_network,
            self.wait_file,
            self.wait_timer,
            self.wait_runnable,
            self.wait_signal,
        )?;
        for (index, listener) in self.listeners.iter().enumerate() {
            if index != 0 {
                output.write_all(b",")?;
            }
            write!(
                output,
                "{{\"step_udp_calls\":{},\"receive_attempts\":{},\"udp_packets\":{},\"would_block\":{},\"receive_errors\":{},\"alloc_count\":{},\"alloc_bytes\":{},\"reuse_count\":{},\"max_batch\":{},\"budget_yields\":{}}}",
                listener.step_calls,
                listener.receive_attempts,
                listener.received_packets,
                listener.would_block,
                listener.receive_errors,
                listener.buffer_alloc_count,
                listener.buffer_alloc_bytes,
                listener.buffer_reuses,
                listener.max_batch,
                listener.budget_yields,
            )?;
        }
        output.write_all(b"]}\n")?;
        output.sync_all()?;
        std::fs::rename(temporary, path)
    }

    fn write(&mut self) -> io::Result<()> {
        if self.enabled() {
            self.write_snapshot()?;
        }
        Ok(())
    }
}

#[cfg(not(feature = "m6b-diagnostics"))]
struct M6bDiagnostics {
    disabled_listener: M6bListenerCounters,
}

#[cfg(not(feature = "m6b-diagnostics"))]
impl M6bDiagnostics {
    fn new(_listener_count: usize) -> Self {
        Self { disabled_listener: M6bListenerCounters::default() }
    }

    #[inline]
    fn enabled(&self) -> bool { false }

    #[inline]
    fn record_loop(&mut self) {}

    #[inline]
    fn listener_mut(&mut self, _index: usize) -> &mut M6bListenerCounters {
        &mut self.disabled_listener
    }

    #[inline]
    fn record_wait(&mut self, _timeout: i32, _ready: usize, _elapsed: Duration,
                   _network_ready: bool, _file_ready: bool, _signal_ready: bool) -> io::Result<()> {
        Ok(())
    }

    #[inline]
    fn write(&mut self) -> io::Result<()> { Ok(()) }
}

// Both EDNS queues are advanced by the existing owner. The UDP queue retains
// the receiving listener token; TCP pending MAC work counts against tcp_limit.
const MAX_EDNS_UDP_WAITERS: usize = 256;
struct PendingEdnsUdp {
    query_context: dnsmasq_rs::query_logging::QueryContext,
    listener: SocketToken,
    client: ClientRequest,
    query: Vec<u8>,
    deadline: Instant,
}
struct PendingInterfaceUdp {
    query_context: dnsmasq_rs::query_logging::QueryContext,
    token: SocketToken,
    udp: Arc<DnsSocket>,
    client: ClientRequest,
    query: Vec<u8>,
    mac: Option<Vec<u8>>,
}
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
struct PendingUdpAdmission {
    token: SocketToken,
    udp: Arc<DnsSocket>,
    incoming: listeners::Incoming,
    query: Vec<u8>,
    loopback: bool,
}
enum UdpAdmission {
    Accept,
    Reject,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    PendingInterfaces { loopback: bool },
}
struct PendingInterfaceTcp {
    query_ids: dnsmasq_rs::query_logging::QueryIds,
    stream: TcpStream,
    peer: SocketAddr,
    local_network: Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)>,
    mac: Option<Vec<u8>>,
    mac_ready: bool,
    mac_deferred: bool,
    accept_clock: i64,
    auth_query: bool,
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
    // A log-blocked C worker still holds G/the connection limit. Its DNS work
    // has already ended: keep only the accepted log destination and poll slot.
    #[cfg(target_os = "linux")]
    log_context: Option<dnsmasq_rs::logging::TcpLogContext>,
    #[cfg(target_os = "linux")]
    poll_slot: Option<usize>,
    #[cfg(target_os = "linux")]
    ready_events: i16,
    // Inline Option avoids another allocation/indirection on every accept.
    // Taking it drops the complete cache/local/forward/framing ownership set.
    dns_work: Option<TcpDnsWork>,
}

struct TcpDnsWork {
    query_ids: dnsmasq_rs::query_logging::QueryIds,
    query_context: dnsmasq_rs::query_logging::QueryContext,
    query_events: Vec<(
        dnsmasq_rs::query_logging::QueryContext,
        dnsmasq_rs::query_logging::QueryEvent,
    )>,
    peer: SocketAddr,
    auth_query: bool,
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

// Error/hangup interests apply to either operation, but POLLOUT alone
// must never authorize a read after the client completes an answer.
fn poll_events_match(events: i16, wanted: i16) -> bool {
    events & (wanted | owrt_ubus::sys::POLLERR | owrt_ubus::sys::POLLHUP | 0x20) != 0
}

enum TcpClientPhase {
    Reading,
    WaitingMac { query: Vec<u8> },
    Forwarding { no_cache: bool, wait: TcpWait },
    Writing { frame: TcpWriteFrame, offset: usize },
}

impl TcpDnsWork {
    fn start_query(&mut self, query: &[u8], parent: &Rc<RefCell<ParentDns>>) -> Result<(), ()> {
        self.query_context = if self.cache_debug {
            parent
                .try_borrow_mut()
                .map_err(|_| ())?
                .query_ids
                .next(true, Some(self.peer))
        } else {
            self.query_ids.next(true, Some(self.peer))
        };
        if self.service.query_logging {
            if let Some(event) = dnsmasq_rs::query_logging::QueryEvent::request(query, self.peer, self.auth_query) {
                self.query_events.push((self.query_context, event));
            }
        }
        Ok(())
    }

    fn collect_local_query_events(&mut self) {
        self.query_events.extend(
            self.service
                .take_query_events()
                .into_iter()
                .map(|event| (self.query_context, event)),
        );
    }
    fn queue_answer(
        &mut self,
        _parent: &Rc<RefCell<ParentDns>>,
        packet: Vec<u8>,
        _insert_cache: bool,
    ) -> Result<(), ()> {
        self.phase = TcpClientPhase::Writing {
            frame: TcpWriteFrame::new(packet).map_err(|_| ())?,
            offset: 0,
        };
        Ok(())
    }

    fn run_forward(
        &mut self,
        parent: &Rc<RefCell<ParentDns>>,
        query: Option<&[u8]>,
        no_cache: bool,
        forward_name: Option<&dnsmasq_rs::dns::daemon::ForwardName>,
    ) -> Result<TcpServiceProgress, ()> {
        let now = self.accept_clock;
        let local = &self.service;
        let debug = self.cache_debug;
        let negative = self.cache_negative;
        let negative_ttl = self.cache_negative_ttl;
        let cached_name = if debug {
            let owner = parent.try_borrow().map_err(|_| ())?;
            self.forward.cached_query_name(
                query,
                owner.daemon.as_ref().and_then(|daemon| daemon.current_cache()),
                now,
            )
        } else {
            self.forward.cached_query_name(query, self.cache_view.as_ref(), now)
        };
        let view = &mut self.cache_view;
        let counters = &mut self.cache_counters;
        let mut transaction = None;
        let mut extraction_events = Vec::new();
        let mut sink = |packet: &mut Vec<u8>,
                        policy: &dnsmasq_rs::dns::process::AddressPolicy,
                        rcode,
                        mode|
         -> Result<(), dnsmasq_rs::dns::wire::WireError> {
            if debug {
                let mut owner = parent
                    .try_borrow_mut()
                    .map_err(|_| dnsmasq_rs::dns::wire::WireError::InvalidName)?;
                if let Some(daemon) = owner.daemon.as_mut() {
                    daemon.tcp_current_extract(
                        packet,
                        policy,
                        now,
                        rcode,
                        mode,
                        &mut extraction_events,
                    )?;
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
                    &mut extraction_events,
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
                cached_name,
                forward_name,
            )
        } else {
            self.forward
                .step_with_local_upstream_cache(local, no_cache, now, &mut sink, cached_name)
        }
        .map_err(|_| ())?;
        self.query_events.extend(
            self.forward
                .take_query_events()
                .into_iter()
                .map(|event| (self.query_context, event)),
        );
        // Producer warnings survive disabled/only-failed/auth query filters.
        self.query_events.extend(
            extraction_events
                .into_iter()
                .map(|event| (self.query_context, event)),
        );
        if let Some(transaction) = transaction {
            self.parent_cache_activity = true;
            let mut owner = parent.try_borrow_mut().map_err(|_| ())?;
            owner.import_tcp_cache_transfer(transaction, now_seconds());
        }
        Ok(progress)
    }

    fn answer_query(
        &mut self,
        mut query: Vec<u8>,
        parent: &Rc<RefCell<ParentDns>>,
    ) -> Result<(), ()> {
        if self.cache_debug {
            let mut owner = parent.try_borrow_mut().map_err(|_| ())?;
            if let Some(daemon) = owner.daemon.as_mut() {
                daemon.invalidate_udp_resend();
            }
        }
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
        let parsed = dnsmasq_rs::dns::wire::Header::parse(&query).and_then(|header| {
            dnsmasq_rs::dns::forward::Question::parse_with_header(&query, header)
                .map(|question| (header, question))
        });
        // Invalid questions miss both local and cache lookup, then reach the
        // existing TCP forwarder's REFUSED path rather than closing the stream.
        let lookup = match parsed {
            Err(_) => Default::default(),
            Ok((header, question)) if self.cache_debug => {
                let mut owner = parent.try_borrow_mut().map_err(|_| ())?;
                let daemon = owner.daemon.as_mut().ok_or(())?;
                let answer = daemon.current_answer_local_or_cached(
                    &query, header, &question, &mut self.service, now, decoration.cacheable, true,
                ).map_err(|_| ())?;
                for event in daemon.take_local_query_events() {
                    self.service.record_query_event(event);
                }
                answer
            }
            Ok((header, question)) => {
                dnsmasq_rs::dns::daemon::DnsDaemon::<dnsmasq_rs::dns::upstream::OsRandom>::answer_local_or_cached(
                    self.cache_view.as_mut(), &query, header, &question,
                    &mut self.service, now, decoration.cacheable,
                    true,
                ).map_err(|_| ())?
            }
        };
        self.collect_local_query_events();
        let answer = lookup.answer;
        let stale = matches!(answer, Some(QueryResult::Stale(_)));
        if let Some(QueryResult::Local(packet) | QueryResult::Cached(packet) | QueryResult::Stale(packet)) = answer {
            if stale {
                self.stale_query = Some(query);
            }
            self.queue_answer(parent, packet, false)?;
        } else {
            match self.run_forward(parent, Some(&query), self.no_cache, lookup.forward_name.as_ref())? {
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
        parent: &Rc<RefCell<ParentDns>>,
        lookup: &mut dyn FnMut(IpAddr, bool) -> ClientMacLookup,
        mut readable: bool,
        mut writable: bool,
        forward_ready: bool,
    ) -> Result<bool, ()> {
        for _ in 0..8 {
            if Instant::now() >= self.deadline || STOP_REQUESTED.load(Ordering::Acquire) {
                return Ok(false);
            }
            match &mut self.phase {
                TcpClientPhase::WaitingMac { query } => {
                    let mac = if self.mac_ready {
                        // A dump completed in an earlier owner phase. Keep
                        // that captured connection identity instead of doing
                        // a second lookup after its snapshot has advanced.
                        std::mem::take(&mut self.mac)
                    } else if Instant::now() >= self.mac_deadline {
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
                    // A freshly produced answer gets one immediate send turn.
                    writable = true;
                }
                TcpClientPhase::Writing { frame, offset } => {
                    if !writable {
                        return Ok(true);
                    }
                    match frame.write_from(self.stream.as_mut().ok_or(())?, *offset) {
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
                    if *offset == frame.wire_len() {
                        if self.queries == 100 {
                            return Ok(false);
                        }
                        if let Some(query) = self.stale_query.take() {
                            if let Some(stream) = self.stream.take() {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                            }
                            self.refreshing_stale = true;
                            // forward.c:2782-2784: background TCP refresh keeps
                            // its display ID after the client is closed.
                            self.query_context.client = None;
                            match self.run_forward(parent, Some(&query), self.no_cache, None)? {
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
                    if wait.fd >= 0 && Instant::now() < wait.deadline && !forward_ready {
                        return Ok(true);
                    }
                    let no_cache = *no_cache;
                    match self.run_forward(parent, None, no_cache, None)? {
                        TcpServiceProgress::Pending(wait) => {
                            self.phase = TcpClientPhase::Forwarding { no_cache, wait };
                            return Ok(true);
                        }
                        TcpServiceProgress::Complete(packet, _) => {
                            if self.refreshing_stale {
                                return Ok(false);
                            }
                            self.queue_answer(parent, packet, false)?;
                            writable = true;
                        }
                    }
                }
                TcpClientPhase::Reading => {
                    if self.input_offset == self.input.len() && !readable {
                        return Ok(true);
                    }
                    if self.cache_debug {
                        // forward.c:2465: debug TCP uses the parent's packet
                        // scratch, even for ignored or incomplete frames.
                        let mut owner = parent.try_borrow_mut().map_err(|_| ())?;
                        if let Some(daemon) = owner.daemon.as_mut() {
                            daemon.invalidate_udp_resend();
                        }
                    }
                    if self.input_offset == self.input.len() {
                        // Read readiness belongs to this poll, not to a later
                        // phase reached after a POLLOUT-only wake. Buffered
                        // frames still use the existing eight-step budget.
                        readable = false;
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
                    self.start_query(&query, parent)?;
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
                    writable = true;
                }
            }
        }
        Ok(true)
    }
}

impl SinglePoll {
    #[allow(clippy::too_many_arguments)]
    fn new(
        service: Rc<RefCell<ParentDns>>,
        parent_events: Rc<RefCell<ParentEvents>>,
        interfaces: Rc<RefCell<Vec<DnsInterface>>>,
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
        let listener_count = listeners.len();
        Self {
            query_logging: Default::default(),
            listeners: listeners
                .into_iter()
                .map(|(token, udp, tcp)| PollListener { token, udp, tcp })
                .collect(),
            clients: Vec::new(),
            pending_edns_udp: Vec::new(),
            edns_udp_runnable: false,
            service,
            hosts_staged: None,
            hosts_reload_failed: false,
            parent_events,
            interfaces,
            config,
            resolvers,
            packet_limit,
            tcp_limit,
            edns_max,
            m6b: M6bDiagnostics::new(listener_count),
            udp_buffer: vec![0; 65_535],
            #[cfg(target_os = "linux")]
            signal_wake_read: None,
            #[cfg(target_os = "linux")]
            signal_wake_write: None,
            #[cfg(target_os = "linux")]
            poll_fds: Vec::new(),
            ubus_ready: false,
            #[cfg(target_os = "linux")]
            ready_fds: Vec::new(),
            #[cfg(target_os = "linux")]
            upstream_ready: false,
            #[cfg(target_os = "linux")]
            upstream_next_due: None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            dhcp_ready: false,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            tftp_ready: false,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            neighbors_ready: false,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            tftp_next_due: None,
            probe_metrics: None,
            full_reload_pending: false,
            retry_bound_listeners: false,
            interfaces_enumerated: false,
            pending_interface_udp: None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            pending_udp_admission: None,
            pending_interface_tcp: None,
            #[cfg(target_os = "linux")]
            pending_interface_files: None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            interface_collector: None,
            #[cfg(target_os = "linux")]
            logger: None,
            #[cfg(target_os = "linux")]
            dump: dnsmasq_rs::dump::DumpHandle::default(),
            #[cfg(target_os = "linux")]
            early_logger: None,
            #[cfg(target_os = "linux")]
            log_cleared_cache: false,
            #[cfg(target_os = "linux")]
            dns_files: None,
            #[cfg(target_os = "linux")]
            route_watch: None,
            #[cfg(target_os = "linux")]
            route_retry_at: None,
            interface_refresh: InterfaceRefresh::default(),
            #[cfg(target_os = "linux")]
            files_runnable: false,
            #[cfg(target_os = "linux")]
            hosts_requests: Default::default(),
            #[cfg(target_os = "linux")]
            hosts_deferred: Default::default(),
            #[cfg(target_os = "linux")]
            hosts_read: None,
            #[cfg(target_os = "linux")]
            hosts_bulk: false,
            #[cfg(target_os = "linux")]
            hosts_full_reload: false,
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

    fn reload_hosts_data(&mut self, local_ttl: u32) -> io::Result<()> {
        self.hosts_staged = None;
        self.hosts_reload_failed = false;
        let (cache_size, name_hash_capacity, retained_leases) = {
            let mut parent = self.service.try_borrow_mut()
                .map_err(|_| io::Error::other("DNS state already borrowed"))?;
            let previous_capacity = parent.provider_hosts().name_hash_capacity()
                .max(parent.local.hosts.name_hash_capacity());
            // C first publishes DHCP DNS names after EVENT_INIT's hosts scan
            // and lease reconciliation. The provider can initialize earlier
            // here, but its provisional names must not suppress that first
            // reverse-host rename. The latch also covers HUP during init.
            let retained_leases = (!parent.hosts_initializing)
                .then(|| Arc::clone(&parent.local.leases));
            parent.pending_hosts = None;
            let Some(daemon) = parent.daemon.as_mut() else { return Ok(()); };
            daemon.begin_hosts_reload();
            (daemon.cache_capacity(), previous_capacity, retained_leases)
        };
        #[cfg(target_os = "linux")]
        {
            if self.hosts_bulk {
                // A new HUP supersedes an unfinished bulk scan, including a
                // reader that still holds an unlinked inode. Real watch events
                // are in hosts_deferred and must survive this cancellation.
                self.hosts_read = None;
                self.hosts_requests.clear();
            } else {
                let count = self.hosts_requests.len() + usize::from(self.hosts_read.is_some());
                if self.hosts_deferred.try_reserve(count).is_err() {
                    self.hosts_reload_failed = true;
                    return Ok(());
                }
                if let Some(reader) = self.hosts_read.take() {
                    // Restart this incremental read after the bulk scan, using
                    // its path again rather than a stale open file descriptor.
                    self.hosts_deferred.push_back(dnsmasq_rs::dns::hostsdir::HostChange {
                        source: reader.finish().source,
                        deleted: false,
                    });
                }
                self.hosts_deferred.append(&mut self.hosts_requests);
            }
            self.hosts_bulk = false;
        }
        // The same bulk reverse hash continues through config, ordinary files
        // and the initial/HUP hostsdir scan. Keep the published owners intact
        // while asynchronous files finish; allocation failure needs no restore.
        let empty_leases;
        let retained_leases = match retained_leases.as_deref() {
            Some(leases) => leases,
            None => {
                empty_leases = dnsmasq_rs::dns::lease_names::LeaseNames::default();
                &empty_leases
            }
        };
        match read_hosts_with_notices(&self.config, local_ttl, self.packet_limit,
            cache_size, name_hash_capacity, retained_leases, |notice| {
            #[cfg(target_os = "linux")]
            if let Some(logger) = self.logger.as_mut() {
                logger.emit(notice.into_log_event());
            }
            #[cfg(not(target_os = "linux"))]
            let _ = notice;
        }) {
            Ok(hosts) => self.hosts_staged = Some(hosts),
            Err(()) => self.hosts_reload_failed = true,
        }
        #[cfg(not(target_os = "linux"))]
        self.publish_staged_hosts();
        Ok(())
    }

    fn publish_staged_hosts(&mut self) {
        let Some(mut hosts) = self.hosts_staged.take() else {
            self.service.borrow_mut().hosts_initializing = false;
            return;
        };
        hosts.seal_bulk();
        let Ok(mut snapshot) = hosts.try_clone() else {
            self.hosts_reload_failed = true;
            self.service.borrow_mut().hosts_initializing = false;
            return;
        };
        snapshot.finish_bulk();
        let provider_publishes_leases = self.has_dhcp_dns_publisher();
        let mut parent = self.service.borrow_mut();
        if provider_publishes_leases {
            parent.pending_hosts = Some((hosts, snapshot));
            return;
        }
        hosts.finish_bulk();
        parent.hosts_initializing = false;
        let ParentDns { local, daemon, .. } = &mut *parent;
        if let Some(daemon) = daemon {
            daemon.publish_hosts_source(snapshot);
            local.hosts = hosts;
            local.leases = Arc::new(daemon.rebuild_lease_names(
                &local.leases,
                &mut local.hosts,
                &local.config.records.cnames,
            ));
        } else {
            local.hosts = hosts;
        }
    }

    fn has_dhcp_dns_publisher(&self) -> bool {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            self.dhcp.as_ref().is_some_and(|dhcp| dhcp.provider.is_some())
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        { false }
    }

    fn reload_data(&mut self, local_ttl: u32) -> io::Result<()> {
        self.reload_hosts_data(local_ttl)?;
        #[cfg(target_os = "linux")]
        self.scan_hosts_dirs(true);
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if !self.hosts_bulk {
            if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
                let mut provider = provider
                    .try_borrow_mut()
                    .map_err(|_| io::Error::other("DHCP state already borrowed"))?;
                report_dhcp_maintenance(
                    &provider.reload_data_files(now_seconds()),
                    self.logger.as_mut(),
                );
            }
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

    fn process_reload_before_dns(&mut self, local_ttl: u32, signaled: bool) -> io::Result<()> {
        let file_reload = std::mem::take(&mut self.full_reload_pending);
        if !signaled && !file_reload {
            return Ok(());
        }
        self.reload_data(local_ttl)?;
        #[cfg(target_os = "linux")]
        {
            if signaled {
                if let Some(files) = &mut self.dns_files {
                    files.request(ReloadReason::Signal);
                }
            }
            // Finish ordinary small inputs before a same-wake UDP request or
            // TCP snapshot. Each original file step stays bounded to 4096B.
            // FIFO/worker waits and large inputs yield to all service duties.
            for _ in 0..RELOAD_FILE_TURNS_PER_EVENT {
                if !self.reload_file_work_runnable() {
                    break;
                }
                #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                self.step_dhcp_files();
                self.step_dns_files();
                self.step_hosts_files();
                if std::mem::take(&mut self.full_reload_pending) {
                    self.reload_data(local_ttl)?;
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn reload_file_work_runnable(&self) -> bool {
        let mut runnable = self.dns_file_work_runnable()
            || self.hosts_read.as_ref().is_some_and(|reader| reader.runnable())
            || (self.hosts_read.is_none()
                && (!self.hosts_requests.is_empty() || !self.hosts_deferred.is_empty()));
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
            runnable |= provider.try_borrow().is_ok_and(|provider| {
                provider.file_work_pending() && provider.files_runnable()
            });
        }
        runnable
    }

    fn hosts_work_pending(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            return self.hosts_read.is_some() || !self.hosts_requests.is_empty()
                || !self.hosts_deferred.is_empty();
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn reload_in_progress(&self) -> bool {
        if self.hosts_work_pending() {
            return true;
        }
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
            .is_some_and(|provider| provider.borrow_mut().file_work_pending())
        {
            return true;
        }
        false
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn dhcp_packet_work_allowed(&self) -> bool {
        !self.interface_work_pending()
            && !self.files_initializing()
            && self.helper_init.is_none()
            && self.helper_init_error.is_none()
            && RELOAD_REQUESTED.load(Ordering::Acquire) == 0
            && !self.dhcp_reload_in_progress()
    }

    fn files_initializing(&self) -> bool {
        if self.service.borrow().hosts_initializing {
            return true;
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self
            .dhcp
            .as_ref()
            .and_then(|dhcp| dhcp.provider.as_ref())
            .is_some_and(|provider| provider.borrow_mut().files_initializing())
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

    fn tftp_pending_interfaces(&self) -> bool {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        { return self.tftp.as_ref().is_some_and(|listener|
            pending_listener_retry(listener.pending_listener_addresses(), &self.interfaces.borrow())); }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        { false }
    }

    #[cfg(target_os = "linux")]
    fn apply_network_events(&mut self, events: NetworkEvents) {
        if events.address {
            // network.c:newaddress only enumerates for clever binding or
            // effective local-service=net in the NO_DHCP6 reference image.
            // Ordinary interface-name/domain publication stays lazy until
            // its DNS, accept or check_servers caller. An unfinished initial
            // DAD listener also needs an immediate retry on address events.
            if self.address_refresh_requires_enumeration() {
                self.interface_refresh.request();
            }
            #[cfg(target_pointer_width = "64")]
            if let Some(dhcp) = &mut self.dhcp {
                dhcp.listener.invalidate_relay_interfaces();
            }
        }
        if events.route {
            if let Ok(mut parent) = self.service.try_borrow_mut() {
                if let Some(daemon) = parent.daemon.as_mut() {
                    // dnsmasq.c:1694-1698: resend precedes resolver reload,
                    // including no-poll, without admitting another query.
                    daemon.resend_udp_query();
                }
            }
            if let Some(files) = &mut self.dns_files {
                files.request(ReloadReason::Route);
            }
        }
        if let Some(logger) = &mut self.logger {
            use dnsmasq_rs::logging::{LogEvent, Priority, Service};
            for code in events.errors {
                logger.emit(LogEvent::new(Service::Dns, Priority::Error,
                    format!("netlink returns error: {}", dnsmasq_rs::logging::error_text(&io::Error::from_raw_os_error(code))).into_bytes()));
            }
        }
    }

    fn address_refresh_requires_enumeration(&self) -> bool {
        // DnsConfig::finalize has already removed local-service in the
        // presence of an explicit ACL, and host mode is static binding.
        self.config.bind_dynamic
            || self.config.local_service_net
            || self.interface_refresh.retry_at.is_some()
    }

    #[cfg(target_os = "linux")]
    fn step_route_events(&mut self) {
        let ready = self.route_watch.as_ref().is_some_and(|watch| self.fd_ready(watch.raw_fd(), owrt_ubus::sys::POLLIN));
        if !ready && self.route_retry_at.is_none() { return; }
        let now = Instant::now();
        if self.route_retry_at.is_some_and(|due| due > now) { return; }
        self.route_retry_at = None;
        let Some(watch) = &mut self.route_watch else { return; };
        let result = watch.read_events();
        self.finish_route_read(result, now);
    }

    #[cfg(target_os = "linux")]
    fn finish_route_read(&mut self, result: io::Result<NetworkEvents>, now: Instant) {
        self.route_retry_at = None;
        match result {
            Ok(events) => self.apply_network_events(events),
            Err(error) if error.raw_os_error() == Some(105) => {
                // C netlink.c:359–370 continues after ENOBUFS. Yield a bounded
                // owner turn, then read the remaining messages; overflow is not
                // an address event, resolver trigger, or snapshot resync.
                self.route_retry_at = Some(now);
            }
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
            Err(error) => {
                // Other persistent read errors must not spin on POLLERR.
                // This error-only cooldown still needs its actual fault gate.
                self.route_retry_at = Some(now + Duration::from_secs(1));
                if let Some(logger) = &mut self.logger {
                    use dnsmasq_rs::logging::{LogEvent, Priority, Service};
                    logger.emit(LogEvent::new(Service::Dns, Priority::Error,
                        format!("failed to read netlink socket: {}", dnsmasq_rs::logging::error_text(&error)).into_bytes()));
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn dns_file_work_runnable(&self) -> bool {
        // Keep the same publication order as step_dns_files. Queued DNS work
        // cannot run ahead of held hosts/DHCP input or an interface generation.
        if self.hosts_work_pending() || self.interface_work_pending() {
            return false;
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref())
            .is_some_and(|provider| provider.try_borrow().map_or(true, |provider| {
                provider.file_work_pending() || provider.files_runnable()
            }))
        {
            return false;
        }
        self.files_runnable || self.dns_files.as_ref().is_some_and(DnsFiles::runnable)
    }

    #[cfg(target_os = "linux")]
    fn step_dns_files(&mut self) {
        if self.hosts_work_pending() {
            self.files_runnable = false;
            return;
        }
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
                let provider = provider.borrow_mut();
                provider.file_work_pending() || provider.files_runnable()
            })
        {
            return;
        }
        let watch_ready = self.dns_files.as_ref().and_then(DnsFiles::watch_fd)
            .is_some_and(|fd| self.fd_ready(fd, owrt_ubus::sys::POLLIN));
        let Some(files) = &mut self.dns_files else {
            return;
        };
        if !watch_ready && !files.has_work() {
            self.files_runnable = false;
            self.log_dns_diagnostics();
            return;
        }
        let was_initializing = files.initializing();
        let step = files.step_with_watch_readiness(watch_ready);
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
        if self.hosts_bulk {
            self.hosts_deferred.extend(step.hosts_changes);
        } else {
            self.hosts_requests.extend(step.hosts_changes);
        }
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
            let addresses =
                dns_local_addresses(&self.config, &self.interfaces.borrow_mut(), self.dns_port);
            let mut parent = self.service.borrow_mut();
            if let Some(daemon) = &mut parent.daemon {
                match daemon.replace_server_source(update.source, update.rows, &addresses) {
                    Ok(()) => {
                        parent.local.config = daemon.local_config().clone().into();
                        self.full_reload_pending |= update.full_reload;
                    }
                    Err(error) => eprintln!("dnsmasq-rs: {error}"),
                }
            }
        }
        self.log_dns_diagnostics();
        if step.initial_cache_reload {
            self.parent_events.borrow_mut().queue_missing_ubus_notice();
            if let Some(logger) = &mut self.logger {
                for notice in self.parent_events.borrow_mut().ubus_notices.drain(..) {
                    logger.emit(notice);
                }
            }
        }
        if step.initial_cache_reload {
            self.service.borrow_mut().hosts_initializing = true;
            let local_ttl = self.service.borrow().local.local_ttl;
            if let Err(error) = self.reload_hosts_data(local_ttl) {
                self.hosts_notice(dnsmasq_rs::logging::Priority::Error, error.to_string());
            }
            self.scan_hosts_dirs(false);
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if !self.hosts_bulk {
                // EVENT_INIT updates restored lease names after cache_reload,
                // including configurations with no hostsdir work to finish.
                if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
                    report_dhcp_maintenance(
                        &provider.borrow_mut().hosts_changed(now_seconds()),
                        self.logger.as_mut(),
                    );
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
                let mut parent = self.service.borrow_mut();
                if let Some(daemon) = &mut parent.daemon {
                    let _ = daemon.recheck_server_notices();
                }
            }
            self.log_dns_diagnostics();
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if step.signal_complete {
            if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
                provider.borrow_mut().rerun_scripts();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn hosts_notice(&mut self, priority: dnsmasq_rs::logging::Priority, message: String) {
        if let Some(logger) = &mut self.logger {
            logger.emit(dnsmasq_rs::logging::LogEvent::new(
                dnsmasq_rs::logging::Service::Dns,
                priority,
                message.into_bytes(),
            ));
        }
    }

    #[cfg(target_os = "linux")]
    fn scan_hosts_dirs(&mut self, full_reload: bool) {
        if self.hosts_reload_failed {
            self.service.borrow_mut().hosts_initializing = false;
            self.resume_deferred_hosts();
            return;
        }
        let Some(files) = &mut self.dns_files else {
            self.publish_staged_hosts();
            self.resume_deferred_hosts();
            return;
        };
        let (sources, diagnostics) = files.scan_hosts_dirs();
        for diagnostic in diagnostics {
            self.hosts_notice(dnsmasq_rs::logging::Priority::Error, diagnostic.to_string());
        }
        self.hosts_full_reload = full_reload;
        if self.hosts_requests.try_reserve(sources.len()).is_err() {
            self.hosts_staged = None;
            self.hosts_reload_failed = true;
            self.service.borrow_mut().hosts_initializing = false;
            self.resume_deferred_hosts();
            return;
        }
        self.hosts_requests
            .extend(
                sources
                    .into_iter()
                    .map(|source| dnsmasq_rs::dns::hostsdir::HostChange {
                        source,
                        deleted: false,
                    }),
            );
        self.hosts_bulk = !self.hosts_requests.is_empty();
        if !self.hosts_bulk {
            self.publish_staged_hosts();
            self.resume_deferred_hosts();
        }
    }

    #[cfg(target_os = "linux")]
    fn resume_deferred_hosts(&mut self) {
        if !self.hosts_bulk && self.hosts_read.is_none() && self.hosts_requests.is_empty() {
            std::mem::swap(&mut self.hosts_requests, &mut self.hosts_deferred);
        }
    }

    #[cfg(target_os = "linux")]
    fn publish_hosts_source(
        &mut self,
        source: &dnsmasq_rs::dns::hostsdir::HostSource,
        records: Vec<(Vec<u8>, IpAddr)>,
        ttl: u32,
    ) -> usize {
        let count = records.len();
        self.publish_hosts_source_lines(source, records, ttl, 1..=count)
    }

    #[cfg(target_os = "linux")]
    fn publish_hosts_source_lines(
        &mut self,
        source: &dnsmasq_rs::dns::hostsdir::HostSource,
        records: Vec<(Vec<u8>, IpAddr)>,
        ttl: u32,
        line_ends: impl IntoIterator<Item = usize>,
    ) -> usize {
        if self.hosts_bulk {
            if self.hosts_reload_failed {
                return 0;
            }
            let Some(staged) = self.hosts_staged.as_ref() else { return 0; };
            match staged.try_replace_source_with_leases(
                source.uid, source.path.as_os_str().as_encoded_bytes(), records, ttl,
                std::iter::empty::<(&[u8], IpAddr, bool, bool)>(), line_ends,
            ) {
                Ok((hosts, removed)) => {
                    self.hosts_staged = Some(hosts);
                    return removed;
                }
                Err(()) => {
                    self.hosts_staged = None;
                    self.hosts_reload_failed = true;
                    return 0;
                }
            }
        }
        let removed;
        let provider_publishes_leases = self.has_dhcp_dns_publisher();
        {
            let mut parent = self.service.borrow_mut();
            // Keep both published owners intact until assembly and the second
            // publication copy succeed. Failed insertions must abandon the
            // entire replacement, not silently publish its accepted prefix.
            let retained_leases = parent.local.leases.active_entries().map(|lease| (
                lease.name.as_ref(), IpAddr::V4(lease.address),
                lease.reverse, lease.expires.is_none(),
            ));
            let Ok((mut hosts, source_removed)) = parent.provider_hosts().try_replace_source_with_leases(
                source.uid,
                source.path.as_os_str().as_encoded_bytes(),
                records,
                ttl,
                retained_leases,
                line_ends,
            ) else { return 0; };
            removed = source_removed;
            if parent.daemon.is_some() {
                let Ok(mut snapshot) = hosts.try_clone() else { return 0; };
                snapshot.finish_bulk();
                if provider_publishes_leases {
                    parent.pending_hosts = Some((hosts, snapshot));
                } else {
                    let ParentDns { local, daemon, .. } = &mut *parent;
                    let daemon = daemon.as_mut().unwrap();
                    hosts.finish_bulk();
                    daemon.publish_hosts_source(snapshot);
                    local.hosts = hosts;
                    local.leases = Arc::new(daemon.rebuild_lease_names(
                        &local.leases,
                        &mut local.hosts,
                        &local.config.records.cnames,
                    ));
                }
            } else {
                parent.local.hosts = hosts;
            }
        }
        if !self.hosts_bulk {
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(provider) = self
                .dhcp
                .as_ref()
                .and_then(|service| service.provider.as_ref())
            {
                let mut provider = provider.borrow_mut();
                if !provider.file_work_pending() {
                    report_dhcp_maintenance(
                        &provider.hosts_changed(now_seconds()), self.logger.as_mut(),
                    );
                }
            }
        }
        removed
    }

    #[cfg(target_os = "linux")]
    fn step_hosts_files(&mut self) {
        use dnsmasq_rs::logging::Priority;
        self.resume_deferred_hosts();
        if let Some(reader) = &mut self.hosts_read {
            if !reader.step(&self.config).unwrap_or(true) {
                return;
            }
            let Some(reader) = self.hosts_read.take() else {
                return;
            };
            let loaded = reader.finish();
            let removed = if loaded.allocation_failed {
                if self.hosts_bulk {
                    self.hosts_staged = None;
                    self.hosts_reload_failed = true;
                }
                self.hosts_notice(
                    Priority::Error,
                    format!("failed to load names from {}: Cannot allocate memory", loaded.source.path.display()),
                );
                0
            } else {
                self.publish_hosts_source_lines(
                    &loaded.source, loaded.records, loaded.ttl, loaded.line_ends,
                )
            };
            if !self.hosts_bulk && removed != 0 {
                self.hosts_notice(
                    Priority::Info,
                    format!(
                        "inotify: flushed {removed} names read from {}",
                        loaded.source.path.display()
                    ),
                );
            }
            for (line, addresses, names) in loaded.bad_lines {
                for _ in 0..addresses {
                    self.hosts_notice(
                        Priority::Error,
                        format!(
                            "bad address at {} line {line}",
                            loaded.source.path.display()
                        ),
                    );
                }
                for _ in 0..names {
                    self.hosts_notice(
                        Priority::Error,
                        format!("bad name at {} line {line}", loaded.source.path.display()),
                    );
                }
            }
            self.hosts_notice(
                Priority::Info,
                format!(
                    "read {} - {} names",
                    loaded.source.path.display(),
                    loaded.stats.accepted
                ),
            );
        } else if let Some(change) = self.hosts_requests.pop_front() {
            let ttl = self.service.borrow_mut().local.local_ttl;
            if !self.hosts_bulk {
                self.hosts_notice(
                    Priority::Info,
                    format!(
                        "inotify: {} {}",
                        change.source.path.display(),
                        if change.deleted {
                            "removed"
                        } else {
                            "new or modified"
                        }
                    ),
                );
            }
            if change.deleted {
                let removed = self.publish_hosts_source(&change.source, Vec::new(), ttl);
                if removed != 0 {
                    self.hosts_notice(
                        Priority::Info,
                        format!(
                            "inotify: flushed {removed} names read from {}",
                            change.source.path.display()
                        ),
                    );
                }
            } else {
                match dnsmasq_rs::dns::hostsdir::HostsRead::open(
                    change.source.clone(),
                    ttl,
                ) {
                    Ok(reader) => self.hosts_read = Some(reader),
                    Err(error) => {
                        let removed = self.publish_hosts_source(&change.source, Vec::new(), ttl);
                        if !self.hosts_bulk && removed != 0 {
                            self.hosts_notice(
                                Priority::Info,
                                format!(
                                    "inotify: flushed {removed} names read from {}",
                                    change.source.path.display()
                                ),
                            );
                        }
                        let message = error.to_string();
                        let message = message.split(" (os error ").next().unwrap_or(&message);
                        self.hosts_notice(
                            Priority::Error,
                            format!(
                                "failed to load names from {}: {message}",
                                change.source.path.display()
                            ),
                        );
                    }
                }
            }
        }
        if self.hosts_bulk && self.hosts_read.is_none() && self.hosts_requests.is_empty() {
            self.publish_staged_hosts();
            self.hosts_bulk = false;
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(provider) = self
                .dhcp
                .as_ref()
                .and_then(|service| service.provider.as_ref())
            {
                let mut provider = provider.borrow_mut();
                let report = if self.hosts_full_reload {
                    provider.reload_data_files(now_seconds())
                } else {
                    provider.hosts_changed(now_seconds())
                };
                report_dhcp_maintenance(&report, self.logger.as_mut());
            }
            self.resume_deferred_hosts();
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_dhcp_files(&mut self) {
        if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
            let mut provider = provider.borrow_mut();
            let watch_ready = provider.file_watch_fd()
                .is_some_and(|fd| self.fd_ready(fd, owrt_ubus::sys::POLLIN));
            if let Some(report) = provider.step_files_with_watch_readiness(now_seconds(), watch_ready) {
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
        if let Some(fd) = self.dump.poll_fd() {
            fds.push(owrt_ubus::sys::PollFd {
                fd,
                events: owrt_ubus::sys::POLLOUT,
                revents: 0,
            });
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
            provider.borrow_mut().append_file_fds(fds);
        }
        if let Some(files) = &self.dns_files {
            files.append_poll_fds(fds);
        }
        if let Some(reader) = &self.hosts_read {
            reader.append_poll_fds(fds);
        }
        if self.route_retry_at.is_none() {
            if let Some(watch) = &self.route_watch { watch.append_poll_fds(fds); }
        }
    }

    fn wait_for_files(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use owrt_ubus::sys::{PollFd, POLLIN, POLLOUT};
            use std::os::fd::AsRawFd;
            // Keep the descriptor backing allocation across turns.  The set
            // is still rebuilt when topology or readiness changes, but the
            // hot path no longer allocates a fresh Vec every poll.
            let mut fds = std::mem::take(&mut self.poll_fds);
            fds.clear();
            self.append_file_fds(&mut fds, true);
            let file_fd_count = fds.len();
            let mut signal_fd_index = None;
            if let Some(signal) = &self.signal_wake_read {
                signal_fd_index = Some(fds.len());
                fds.push(PollFd {
                    fd: signal.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                });
            }
            let network_fd_start = fds.len();
            let now = Instant::now();
            let mut deadline: Option<Instant> = None;
            let mut wake_at = |due: Instant| {
                deadline = Some(deadline.map_or(due, |current| current.min(due)));
            };
            // Logical work can be queued after its consumer's turn. Do not
            // depend on a pipe byte surviving until the next wait: counters
            // and queues are the authority, fd readiness is only the wakeup.
            let mut runnable = STOP_REQUESTED.load(Ordering::Acquire)
                || LOG_REOPEN_REQUESTED.load(Ordering::Acquire) != 0
                || CACHE_DUMP_REQUESTED.load(Ordering::Acquire) != 0
                || ALARM_REQUESTED.load(Ordering::Acquire) != 0
                || (RELOAD_REQUESTED.load(Ordering::Acquire) != 0
                    && !self.reload_in_progress());
            if !self.interface_work_pending() {
                if let Some(due) = self.interface_refresh.retry_at { wake_at(due); }
                runnable |= self.interface_refresh.requested;
            }
            if let Some(due) = self.route_retry_at { wake_at(due); }

            // The normal owner waits on network and file descriptors in one
            // set.  `step` still performs bounded nonblocking work after the
            // wait returns; readiness is deliberately not consumed here.
            // Pending startup input/interface work cannot consume new DNS requests.
            // Keep their sockets queued until the same admission gate can run.
            let dns_admission_ready = !self.files_initializing() && !self.interface_work_pending();
            for listener in self.listeners.iter().filter(|_| dns_admission_ready) {
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
            for pending in &self.pending_edns_udp {
                wake_at(pending.deadline);
            }
            let upstream_fd_start = fds.len();
            let timer_sentinel = now + Duration::from_secs(3600);
            self.upstream_next_due = self.service.borrow().daemon.as_ref().and_then(|daemon| {
                daemon.append_poll_fds(&mut fds, timer_sentinel)
            });
            if let Some(due) = self.upstream_next_due {
                wake_at(due);
            }
            let upstream_fd_end = fds.len();
            for client in &mut self.clients {
                client.poll_slot = None;
                client.ready_events = 0;
                if let (Some(logger), Some(context)) = (&self.logger, &client.log_context) {
                    if let Some(due) = logger.tcp_retry_deadline(context) {
                        wake_at(due);
                    }
                    if client.dns_work.is_none() && logger.tcp_finished(context) {
                        runnable = true;
                    }
                }
                let Some(work) = &client.dns_work else { continue };
                wake_at(work.deadline);
                if !work.mac_ready && !work.mac_deferred {
                    wake_at(work.mac_deadline);
                    // DNS bytes already queued on the downstream cannot
                    // advance an accept-time MAC lookup. Polling that unread
                    // socket would wake continuously while its dump waits.
                    continue;
                }
                let (fd, events) = match &work.phase {
                    TcpClientPhase::Reading => {
                        if work.input_offset < work.input.len() {
                            runnable = true;
                        }
                        (
                            work.stream.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                            POLLIN,
                        )
                    }
                    TcpClientPhase::WaitingMac { .. } => {
                        wake_at(work.mac_deadline);
                        runnable |= work.mac_ready;
                        (-1, 0)
                    }
                    TcpClientPhase::Writing { .. } => (
                        work.stream.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                        POLLOUT,
                    ),
                    TcpClientPhase::Forwarding { wait, .. } => {
                        wake_at(wait.deadline);
                        (wait.fd, wait.events)
                    }
                };
                client.poll_slot = Some(fds.len());
                fds.push(PollFd {
                    fd,
                    events,
                    revents: 0,
                });
            }
            let mut ubus_fd_index = None;
            if let Some(ubus) = &self.parent_events.borrow().ubus {
                // A synchronous doctor call may have read a complete method
                // into Connection's pending queue while awaiting its reply.
                // The kernel socket can now be empty, but that method is ready.
                runnable |= ubus.has_pending();
                ubus_fd_index = Some(fds.len());
                fds.push(PollFd {
                    fd: ubus.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                });
            } else {
                let event = self.parent_events.borrow();
                if event.ubus_name.is_some() {
                    wake_at(event.ubus_retry_at);
                }
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            let dhcp_fd_start = fds.len();
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(dhcp) = &self.dhcp {
                if self.dhcp_packet_work_allowed() {
                    let interfaces_pending = dhcp.provider.as_ref()
                        .is_some_and(|provider| provider.borrow().packet_interfaces_pending());
                    if !interfaces_pending {
                        dhcp.listener.append_poll_fds(&mut fds);
                    }
                }
                if let Some(provider) = dhcp.provider.as_ref()
                    .filter(|_| self.dhcp_packet_work_allowed()) {
                    let provider = provider.borrow();
                    // Packet interface dumps share the file owner, but their
                    // readiness must also resume the DHCP transaction.
                    provider.append_packet_interface_fds(&mut fds);
                    if provider.packet_interfaces_runnable() {
                        wake_at(now);
                    }
                    if let Some(due) = provider.next_maintenance() {
                        wake_at(due);
                    }
                }
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            let dhcp_fd_end = fds.len();
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
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
                if let Some(due) = self.helper_next_due(now) {
                    runnable |= due <= now;
                    wake_at(due);
                }
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            let tftp_fd_start = fds.len();
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(tftp) = &self.tftp {
                tftp.append_poll_fds(&mut fds);
                if tftp.has_pending_work() {
                    wake_at(self.tftp_next_due.unwrap_or(now));
                }
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            let tftp_fd_end = fds.len();
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            let neighbors_fd_start = fds.len();
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(neighbors) = &self.neighbors {
                neighbors.append_poll_fds(&mut fds);
                if let Some(due) = neighbors.active_dump_deadline() {
                    wake_at(neighbor_poll_deadline(due, now,
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()));
                }
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            let neighbors_fd_end = fds.len();
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(collector) = &self.interface_collector {
                collector.append_poll_fds(&mut fds);
                if let Some(limit) = collector.deadline() {
                    wake_at(limit);
                }
                if collector.runnable() {
                    runnable = true;
                }
            }
            runnable |= self.dns_file_work_runnable()
                || (self.edns_udp_runnable && !self.interface_work_pending())
                || self
                    .hosts_read
                    .as_ref()
                    .is_some_and(|reader| reader.runnable())
                || (self.hosts_read.is_none()
                    && (!self.hosts_requests.is_empty() || !self.hosts_deferred.is_empty()));
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
                runnable |= provider.borrow_mut().files_runnable();
            }
            runnable |= self.full_reload_pending;
            // A failed wake-pipe allocation must not make TERM/HUP sleep
            // indefinitely. This is only an error fallback;
            // the normal path is woken by the pipe and uses the real deadline.
            if self.signal_wake_read.is_none() {
                wake_at(now + Duration::from_millis(100));
            }
            for logger in self.early_logger.iter().chain(self.logger.iter()) {
                if let Some(due) = logger.retry_deadline() {
                    wake_at(due);
                }
            }
            // Active timers retain the existing one-hour recheck cadence.
            // An idle owner has no periodic deadline.
            let deadline = deadline.map(|due| due.min(now + Duration::from_secs(3600)));
            let started = Instant::now();
            let timeout = owner_poll_timeout(deadline, started, runnable);
            debug_assert!(!runnable || timeout == 0);
            let poll_result = owrt_ubus::sys::poll_fds(&mut fds, timeout);
            let ready = match poll_result {
                Ok(ready) => ready,
                Err(error) => {
                    self.poll_fds = fds;
                    return Err(error);
                }
            };
            let waited = started.elapsed();
            let file_ready = fds[..file_fd_count].iter().any(|fd| fd.revents != 0);
            let network_ready = fds[network_fd_start..].iter().any(|fd| fd.revents != 0);
            let signal_ready = signal_fd_index
                .and_then(|index| fds.get(index))
                .is_some_and(|fd| fd.revents != 0);
            self.ubus_ready = ubus_fd_index
                .and_then(|index| fds.get(index))
                .is_some_and(|fd| fd.revents != 0);
            self.ready_fds.clear();
            self.ready_fds.extend(
                fds.iter()
                    .filter(|fd| fd.revents != 0)
                    .copied(),
            );
            // Slots are attached to the actual clients before poll. A newly
            // accepted connection cannot inherit readiness from a reused fd.
            for client in &mut self.clients {
                client.ready_events = client.poll_slot
                    .and_then(|slot| fds.get(slot))
                    .map_or(0, |fd| fd.revents);
            }
            self.upstream_ready = fds[upstream_fd_start..upstream_fd_end]
                .iter()
                .any(|fd| fd.revents != 0);
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            {
                self.dhcp_ready = fds[dhcp_fd_start..dhcp_fd_end]
                    .iter()
                    .any(|fd| fd.revents != 0);
                self.tftp_ready = fds[tftp_fd_start..tftp_fd_end]
                    .iter()
                    .any(|fd| fd.revents != 0);
                self.neighbors_ready = fds[neighbors_fd_start..neighbors_fd_end]
                    .iter()
                    .any(|fd| fd.revents != 0);
            }
            self.poll_fds = fds;
            if signal_ready {
                self.drain_signal_wake();
            }
            self.m6b.record_wait(
                timeout,
                ready,
                waited,
                network_ready,
                file_ready,
                signal_ready,
            )?;
        }
        #[cfg(not(target_os = "linux"))]
        thread::park_timeout(Duration::from_millis(2));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn drain_signal_wake(&self) {
        let Some(signal) = &self.signal_wake_read else {
            return;
        };
        let mut buffer = [0u8; 64];
        loop {
            // SAFETY: the fd is an owned nonblocking pipe read end and the
            // stack buffer bounds the kernel write.
            let read = unsafe { read(signal.as_raw_fd(), buffer.as_mut_ptr(), buffer.len()) };
            if read <= 0 || read < buffer.len() as isize {
                break;
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn fd_ready(&self, fd: i32, wanted: i16) -> bool {
        let events = self.ready_fds.iter().filter(|ready| ready.fd == fd)
            .fold(0, |events, ready| events | ready.revents);
        poll_events_match(events, wanted)
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
            write_dhcp_metrics(&mut metrics, &provider.borrow_mut());
        }
        let parent = self.service.borrow_mut();
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

    fn process_diagnostic_signals(&mut self) {
        // As with EVENT_ALARM, enqueue maintenance even before the relative
        // lease timer is due. The existing owner gates keep it behind reloads.
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(provider) = self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref()) {
            if let Ok(mut provider) = provider.try_borrow_mut() {
                let count = ALARM_REQUESTED.swap(0, Ordering::AcqRel);
                provider.request_alarms(count);
            }
        } else {
            ALARM_REQUESTED.store(0, Ordering::Release);
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        ALARM_REQUESTED.store(0, Ordering::Release);
        if CACHE_DUMP_REQUESTED.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |count| count.checked_sub(1)).is_err() {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            let mut event = self.parent_events.borrow_mut();
            let metrics = self.metrics(&event);
            let parent = self.service.borrow();
            if let (Some(daemon), Some(logger)) = (&parent.daemon, &mut self.logger) {
                daemon.dump_cache(&parent.local, now_seconds(), &metrics, event.tcp_high_water,
                    self.tcp_limit, DEBUG_MODE.load(Ordering::Relaxed), |line| {
                        logger.emit(dnsmasq_rs::logging::LogEvent::new(
                            dnsmasq_rs::logging::Service::Dns,
                            dnsmasq_rs::logging::Priority::Info, line.into_bytes()));
                    });
                event.tcp_high_water = event.tcp_active;
            }
        }
    }

    fn process_ubus_if_ready(&mut self) -> io::Result<()> {
        let pending_or_retry = {
            let event = self.parent_events.borrow();
            if event.ubus_name.is_none() {
                return Ok(());
            }
            event.ubus.as_ref().is_none_or(UbusService::has_pending)
        };
        if !self.ubus_ready && !pending_or_retry {
            return Ok(());
        }
        let mut event = self
            .parent_events
            .try_borrow_mut()
            .map_err(|_| io::Error::other("parent event already borrowed"))?;
        let metrics = self.metrics(&event);
        event.process_ubus(&metrics);
        self.ubus_ready = false;
        Ok(())
    }

    fn step(&mut self) -> io::Result<()> {
        self.m6b.record_loop();
        self.process_ubus_if_ready()?;
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(dhcp) = &mut self.dhcp {
            dhcp.listener.retry_device_binding();
            if let Some(logger) = &mut self.logger {
                for notice in dhcp.listener.take_network_notices() {
                    logger.emit(notice);
                }
            }
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.step_interface_collector();
        #[cfg(target_os = "linux")]
        if let Some(logger) = &mut self.early_logger {
            if logger.has_pending() {
                logger.flush_ready();
            }
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
            if logger.has_pending() {
                logger.flush_ready();
            }
        }
        self.process_diagnostic_signals();
        // C drains subscription/metrics requests before processing DHCP.
        // This also applies to port=0, where no DNS listener can drain UBus.
        #[cfg(target_os = "linux")]
        if let Some(logger) = &mut self.logger {
            for notice in self.parent_events.borrow_mut().ubus_notices.drain(..) {
                logger.emit(notice);
            }
        }
        // A collector may have completed above while an address event was
        // held behind it. Publish that queued generation on the next owner
        // turn before admitting new DNS/DHCP/TFTP work; poll will be runnable.
        if self.interface_refresh.due_now() && !self.interface_work_pending() {
            return Ok(());
        }
        // Bound work per turn.  This keeps a busy UDP socket from starving
        // DHCP, TFTP, reload and TCP admission.
        let listeners = self.listeners.len();
        let mut udp_budget = UDP_PACKETS_PER_TURN;
        for index in 0..listeners {
            if udp_budget != 0 {
                let mut batch = 0;
                while udp_budget != 0 && self.step_udp(index) {
                    udp_budget -= 1;
                    batch += 1;
                }
                if self.m6b.enabled() {
                    let counters = self.m6b.listener_mut(index);
                    counters.max_batch = counters.max_batch.max(batch);
                    if udp_budget == 0 {
                        counters.budget_yields += 1;
                    }
                }
            }
            // TCP admission remains one bounded turn per listener even when
            // a preceding UDP listener consumed the packet budget.
            self.step_tcp_accept(index);
        }
        #[cfg(target_os = "linux")]
        if self.upstream_ready
            || self.upstream_next_due.is_some_and(|due| due <= Instant::now())
        {
            self.poll_udp_completions();
            self.upstream_ready = false;
        }
        #[cfg(not(target_os = "linux"))]
        self.poll_udp_completions();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self.neighbors_ready || self.neighbors.as_ref()
            .and_then(NeighborCache::active_dump_deadline)
            .is_some_and(|due| due <= now_seconds() as u64)
        {
            // MAC waiters consume the completed snapshot in this same wake.
            self.neighbors_ready = true;
            self.advance_neighbors();
        }
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
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn log_dns_diagnostics(&mut self) {
        use dnsmasq_rs::logging::{LogEvent, Priority, Service};
        self.dump.step();
        let Some(logger) = &mut self.logger else {
            return;
        };
        for (error, message) in self.dump.take_notices() {
            logger.emit(LogEvent::new(
                Service::Dns,
                if error {
                    Priority::Error
                } else {
                    Priority::Info
                },
                message,
            ));
        }
        let mut parent = self.service.borrow_mut();
        let Some(daemon) = &mut parent.daemon else {
            return;
        };
        if !daemon.has_pending_notices() {
            return;
        }
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
        self.enumerate_interfaces(false);
    }

    fn enumerate_interfaces(&mut self, needed_for_admission: bool) {
        if self.interfaces_enumerated {
            return;
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self.interface_work_pending() {
            return;
        }
        self.interfaces_enumerated = true;
        if !needed_for_admission && self.config.interface_records.rules.is_empty()
            && !self.config.needs_domain_interfaces()
        {
            if let Some(daemon) = &mut self.service.borrow_mut().daemon {
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
            *self.interfaces.borrow_mut() = result.interfaces;
        }
        let domains = domain_interface_snapshot(&result.addresses);
        self.config.domain_interfaces = Arc::clone(&domains);
        if let Some(provider) = self
            .dhcp
            .as_ref()
            .and_then(|service| service.provider.as_ref())
        {
            if let Err(error) = provider.borrow_mut().set_dns_config(&self.config) {
                eprintln!("dnsmasq-rs: {error}");
            }
        }
        let records = Arc::new(
            dnsmasq_rs::dns::interface_records::InterfaceRecords::from_addresses(
                &self.config.interface_records.rules,
                &result.addresses,
            ),
        );
        {
            let mut parent = self.service.borrow_mut();
            parent.local.interfaces = Arc::clone(&records);
            parent.local.publish_domain_interfaces(Arc::clone(&domains));
            if let Some(daemon) = &mut parent.daemon {
                daemon.publish_domain_interfaces(domains);
                daemon.refresh_source_interface_indices();
                daemon.publish_interface_records(records);
            }
        }
        if let Some(tftp) = self.tftp.as_mut().filter(|tftp| tftp.needs_interface_admission()) {
            tftp.resume_interface_admission(&self.interfaces.borrow(), now_seconds() as u64);
            self.tftp_ready = true;
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
                pending.query.into(),
                pending.mac,
                pending.query_context,
            );
        }
        if let Some(pending) = self.pending_udp_admission.take() {
            let admitted = self.interfaces.try_borrow().is_ok_and(|interfaces| {
                listeners::udp_acl_exception(&self.config, &interfaces, pending.incoming.destination,
                    pending.incoming.interface, pending.loopback)
            });
            if admitted {
                self.process_admitted_udp(pending.token, pending.udp, pending.incoming, pending.query.into());
            }
        }
        if let Some(pending) = self.pending_interface_tcp.take() {
            self.finish_tcp_accept(pending);
        }
    }

    fn invalidate_udp_resend(&mut self) {
        if let Ok(mut parent) = self.service.try_borrow_mut() {
            if let Some(daemon) = parent.daemon.as_mut() {
                daemon.invalidate_udp_resend();
            }
        }
    }

    fn admit_udp(&mut self, udp: &DnsSocket, incoming: listeners::Incoming) -> UdpAdmission {
        let interfaces = match self.interfaces.try_borrow() {
            Ok(interfaces) => interfaces,
            Err(_) => return UdpAdmission::Reject,
        };
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if listeners::udp_needs_ingress_name(&self.config, incoming.destination) {
            if !listeners::udp_source_allowed(&self.config, &interfaces, incoming.peer.ip()) {
                return UdpAdmission::Reject;
            }
            drop(interfaces);
            let Ok(name) = udp.ingress_name(incoming.interface) else {
                return UdpAdmission::Reject;
            };
            let length = name.iter().position(|byte| *byte == 0).unwrap_or(name.len());
            // This is also the implicit loopback name in C's interface list.
            // A failed flags lookup disables only that rule and its exception.
            let loopback = udp.ingress_loopback(&name).is_ok_and(|value| value);
            if listeners::udp_acl_name(&self.config, incoming.destination, &name[..length], loopback, true) {
                return UdpAdmission::Accept;
            }
            // C still checks the IPv4 label exception against the new list.
            if !self.config.bind_dynamic {
                self.enumerate_interfaces(true);
                if self.interface_work_pending() {
                    return UdpAdmission::PendingInterfaces { loopback };
                }
            }
            // A same-turn latch or early control-socket failure keeps the
            // prior generation. Do not retry synchronously via getifaddrs.
            return if self.interfaces.try_borrow().is_ok_and(|interfaces| {
                listeners::udp_acl_exception(&self.config, &interfaces, incoming.destination,
                    incoming.interface, loopback)
            }) {
                UdpAdmission::Accept
            } else {
                UdpAdmission::Reject
            };
        }
        #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
        let _ = udp;
        if listeners::admit(&self.config, &interfaces, incoming.peer.ip(), incoming.destination,
            incoming.interface)
        {
            UdpAdmission::Accept
        } else {
            UdpAdmission::Reject
        }
    }

    fn step_udp(&mut self, index: usize) -> bool {
        let _allocation_step = udp_allocation_diagnostic::Step::new();
        if self.m6b.enabled() {
            self.m6b.listener_mut(index).step_calls += 1;
        }
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if self.interface_work_pending() {
            return false;
        }
        if self.files_initializing() {
            return false;
        }
        let Some(udp) = self.listeners[index].udp.as_ref().map(Arc::clone) else {
            return false;
        };
        #[cfg(target_os = "linux")]
        if !self.fd_ready(udp.as_raw_fd(), owrt_ubus::sys::POLLIN) {
            return false;
        }
        let token = self.listeners[index].token;
        if self.m6b.enabled() {
            let counters = self.m6b.listener_mut(index);
            counters.buffer_reuses += 1;
            if index == 0 && counters.buffer_alloc_count == 0 {
                counters.buffer_alloc_count = 1;
                counters.buffer_alloc_bytes = 65_535;
            }
        }
        if self.m6b.enabled() {
            self.m6b.listener_mut(index).receive_attempts += 1;
        }
        let incoming = match udp.receive(&mut self.udp_buffer) {
            Ok(Some(incoming)) => {
                udp_allocation_diagnostic::classify(udp_allocation_diagnostic::Kind::OtherPacket);
                // forward.c:1628 clears before admission/parsing. Clear every
                // consumed packet, but preserve the newest send across this
                // batch's speculative final WouldBlock receive.
                self.invalidate_udp_resend();
                if incoming.len > usize::from(self.edns_max) {
                    return false;
                }
                if self.m6b.enabled() {
                    self.m6b.listener_mut(index).received_packets += 1;
                }
                incoming
            }
            Ok(None) => {
                udp_allocation_diagnostic::classify(udp_allocation_diagnostic::Kind::OtherPacket);
                // recvmsg succeeded but the datagram/pktinfo was discarded.
                self.invalidate_udp_resend();
                return false;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                if self.m6b.enabled() {
                    self.m6b.listener_mut(index).would_block += 1;
                }
                return false;
            }
            Err(_) => {
                // Includes EINTR: C has already invalidated its scratch at
                // the receive_query entry when this actual read fails.
                self.invalidate_udp_resend();
                if self.m6b.enabled() {
                    self.m6b.listener_mut(index).receive_errors += 1;
                }
                return false;
            }
        };
        if incoming.len < 12 || self.udp_buffer[2] & 0x80 != 0 {
            return true;
        }
        match self.admit_udp(&udp, incoming) {
            UdpAdmission::Reject => return true,
            UdpAdmission::Accept => {}
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            UdpAdmission::PendingInterfaces { loopback } => {
                self.pending_udp_admission = Some(PendingUdpAdmission {
                    token, udp, incoming, query: self.udp_buffer[..incoming.len].to_vec(), loopback,
                });
                return true;
            }
        }
        // The receive scratch is not used again until this synchronous owner
        // turn returns. Only a deferred interface/MAC lookup retains a copy.
        let buffer = std::mem::take(&mut self.udp_buffer);
        let result = self.process_admitted_udp(
            token, udp, incoming, Cow::Borrowed(&buffer[..incoming.len]),
        );
        self.udp_buffer = buffer;
        result
    }

    fn process_admitted_udp(&mut self, token: SocketToken, udp: Arc<DnsSocket>,
                            incoming: listeners::Incoming, query: Cow<'_, [u8]>) -> bool {
        let query_context = match self.service.try_borrow_mut() {
            Ok(mut parent) => parent.query_ids.next(false, Some(incoming.peer)),
            Err(_) => return true,
        };
        #[cfg(target_os = "linux")]
        if self.dump.enabled(dnsmasq_rs::dump::QUERY) {
            if let Ok(destination) = udp.local_addr() {
                self.dump.udp_with_context(
                    dnsmasq_rs::dump::QUERY,
                    &query,
                    incoming.peer,
                    destination,
                    query_context,
                );
            }
        }
        #[cfg(target_os = "linux")]
        if self.query_logging.enabled {
            let mut auth = false;
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if self.config.auth.has_interfaces() {
                auth = if (self.config.bind_interfaces || self.config.bind_dynamic)
                    && incoming.destination.is_ipv4() {
                    self.interfaces.borrow().iter().any(|row| row.address == incoming.destination
                        && self.config.auth.selected(row.address, &row.name))
                } else {
                    udp.ingress_name(incoming.interface).is_ok_and(|name| {
                        let length = name.iter().position(|byte| *byte == 0).unwrap_or(name.len());
                        self.config.auth.selected(incoming.destination, &name[..length])
                    })
                };
            }
            if let (Some(logger), Some(event)) = (
                &mut self.logger,
                dnsmasq_rs::query_logging::QueryEvent::request(&query, incoming.peer, auth),
            ) {
                if let Some(event) =
                    dnsmasq_rs::logging::query::format(self.query_logging, query_context, &event)
                {
                    logger.emit(event);
                }
            }
        }
        if self.config.loop_detect {
            let mut parent = self.service.borrow_mut();
            let ParentDns { local, daemon, .. } = &mut *parent;
            if let Some(daemon) = daemon {
                if daemon.detect_loop(&query).unwrap_or(false) {
                    local.config = daemon.local_config().clone().into();
                    self.config = (*local.config).clone();
                    return true;
                }
            }
        }
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
            ClientMacLookup::Ready(mac) => {
                self.process_udp(token, udp, client, query, mac, query_context)
            }
            ClientMacLookup::Pending if self.pending_edns_udp.len() < MAX_EDNS_UDP_WAITERS => {
                self.pending_edns_udp.push(PendingEdnsUdp {
                    query_context,
                    listener: token,
                    client,
                    query: query.into_owned(),
                    deadline: Instant::now() + Duration::from_secs(3),
                });
            }
            ClientMacLookup::Pending => {} // bounded admission; kernel-style drop
        }
        true
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
        self.step_edns_udp_with_lookup(|owner, source| owner.edns_mac(source, true));
    }

    fn step_edns_udp_with_lookup(
        &mut self,
        mut lookup_mac: impl FnMut(&mut Self, IpAddr) -> ClientMacLookup,
    ) {
        // A previous budget yield requests one new turn. Clear it before
        // scanning so a tail consisting only of unresolved MACs waits on its
        // dump/timeout instead of spinning.
        self.edns_udp_runnable = false;
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
                lookup_mac(self, source)
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
                self.process_udp(
                    pending.listener,
                    udp,
                    pending.client,
                    pending.query.into(),
                    mac,
                    pending.query_context,
                );
            }
            progressed += 1;
        }
        self.edns_udp_runnable = progressed == 32 && !self.pending_edns_udp.is_empty();
    }

    fn process_udp(
        &mut self,
        token: SocketToken,
        udp: Arc<DnsSocket>,
        client: ClientRequest,
        query: Cow<'_, [u8]>,
        mac: Option<Vec<u8>>,
        query_context: dnsmasq_rs::query_logging::QueryContext,
    ) {
        let mut event = match self.parent_events.try_borrow_mut() {
            Ok(event) => event,
            Err(_) => return,
        };
        let mut metrics = self.metrics(&event);
        let mut parent = match self.service.try_borrow_mut() {
            Ok(parent) => parent,
            Err(_) => return,
        };
        let ParentDns { local, daemon, .. } = &mut *parent;
        let Some(daemon) = daemon.as_mut() else {
            return;
        };
        write_dns_metrics(
            &mut metrics,
            daemon.cache_counters(),
            daemon.forward_counters(),
            event.local_answered,
        );
        if let Ok(interfaces) = self.interfaces.try_borrow_mut() {
            local.local_network = listeners::local_network(&interfaces, client.destination);
        }
        daemon.set_query_context(query_context);
        let packet = &query[..];
        let mut decorated = self.config.edns.active().then(|| query.to_vec());
        let mut metadata = None;
        let answer = match dnsmasq_rs::dns::udp_query::inspect(packet, local.edns_packet_max) {
            dnsmasq_rs::dns::udp_query::Admission::Drop => return,
            dnsmasq_rs::dns::udp_query::Admission::Reply(answer) => {
                if self.query_logging.enabled {
                    if let Ok(header) = dnsmasq_rs::dns::wire::Header::parse(packet) {
                        let (flags, name, rcode, ede) = if header.opcode() != 0 {
                            (
                                dnsmasq_rs::query_logging::REPLY,
                                b"opcode".as_slice(),
                                4,
                                None,
                            )
                        } else {
                            (
                                dnsmasq_rs::query_logging::CONFIG,
                                b"error".as_slice(),
                                5,
                                Some(24),
                            )
                        };
                        local.record_query_event(dnsmasq_rs::query_logging::QueryEvent::error(
                            flags, name, rcode, ede,
                        ));
                    }
                }
                Some((answer, false))
            }
            dnsmasq_rs::dns::udp_query::Admission::Continue => {
                let Ok(original_metadata) =
                    dnsmasq_rs::dns::forward_service::query_metadata(packet, self.edns_max)
                else {
                    return;
                };
                let decoration = if let Some(decorated) = &mut decorated {
                    let Ok(decoration) = dnsmasq_rs::dns::edns_policy::decorate(
                        decorated,
                        &self.config.edns,
                        client.source.ip(),
                        mac.as_deref(),
                        self.edns_max,
                        usize::from(self.edns_max),
                    ) else {
                        return;
                    };
                    decoration
                } else {
                    dnsmasq_rs::dns::edns_policy::Decoration {
                        cacheable: dnsmasq_rs::dns::edns_policy::client_subnet_cacheable(packet),
                        padded_subnet: false,
                    }
                };
                let prepared_metadata = original_metadata.with_cacheable(decoration.cacheable);
                metadata = Some(prepared_metadata);
                let needs_interfaces =
                    dnsmasq_rs::dns::local::interface_forward_name(&self.config, packet).is_some()
                        || (decoration.cacheable
                            && !daemon.local_config().interface_records.rules.is_empty()
                            && daemon.interface_query_needs_enumeration(packet, now_seconds()));
                if needs_interfaces && !self.interfaces_enumerated {
                    drop(parent);
                    drop(event);
                    self.enumerate_interface_records();
                    if self.interface_work_pending() {
                        self.pending_interface_udp = Some(PendingInterfaceUdp {
                            query_context,
                            token,
                            udp,
                            client,
                            query: query.into_owned(),
                            mac,
                        });
                    } else {
                        // An early control failure keeps the old generation.
                        self.process_udp(token, udp, client, query, mac, query_context);
                    }
                    return;
                }

                match daemon.answer_udp_prepared_with_local(
                    packet,
                    decorated.as_deref().unwrap_or(packet),
                    prepared_metadata,
                    ClientRequest {
                        source: client.source,
                        destination: client.destination,
                        interface: client.interface,
                    },
                    Some(token),
                    local,
                ) {
                    Ok(QueryResult::Local(answer)) => {
                        udp_allocation_diagnostic::classify(udp_allocation_diagnostic::Kind::Local);
                        Some((answer, false))
                    }
                    Ok(QueryResult::Cached(answer)) => {
                        udp_allocation_diagnostic::classify(udp_allocation_diagnostic::Kind::Cached);
                        Some((answer, false))
                    }
                    Ok(QueryResult::Stale(answer)) => {
                        udp_allocation_diagnostic::classify(udp_allocation_diagnostic::Kind::Stale);
                        Some((answer, true))
                    }
                    _ => None,
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
        let local_query_events = local.take_query_events();
        let daemon_query_events = daemon.take_query_events();
        drop(parent);
        #[cfg(target_os = "linux")]
        if let Some(logger) = &mut self.logger {
            for (context, event) in local_query_events
                .into_iter()
                .map(|event| (query_context, event))
                .chain(daemon_query_events)
            {
                if let Some(event) =
                    dnsmasq_rs::logging::query::format(self.query_logging, context, &event)
                {
                    logger.emit(event);
                }
            }
        }
        if let Some((answer, stale)) = answer {
            #[cfg(target_os = "linux")]
            if self.dump.enabled(dnsmasq_rs::dump::REPLY) {
                if let Ok(source) = udp.local_addr() {
                    self.dump.udp_with_context(
                        dnsmasq_rs::dump::REPLY,
                        &answer,
                        source,
                        client.source,
                        query_context,
                    );
                }
            }
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
                // Release the parent borrow before that I/O completes.
                let mut refresh_query_events = Vec::new();
                if let Ok(mut parent) = self.service.try_borrow_mut() {
                    if let (Some(daemon), Some(metadata)) = (parent.daemon.as_mut(), metadata) {
                        let refresh = daemon.refresh_udp_prepared_on_listener(
                            &query[..],
                            decorated.as_deref().unwrap_or(packet),
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
                        // Forwarded is produced when the refresh is submitted.
                        // Its upstream may never reply, so emit it this turn.
                        refresh_query_events = daemon.take_query_events();
                    }
                }
                #[cfg(target_os = "linux")]
                if let Some(logger) = &mut self.logger {
                    for (context, notice) in refresh_query_events {
                        if let Some(notice) = dnsmasq_rs::logging::query::format(
                            self.query_logging, context, &notice,
                        ) {
                            logger.emit(notice);
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
                #[cfg(target_os = "linux")]
                if self.dump.enabled(dnsmasq_rs::dump::REPLY) {
                    if let Ok(source) = target.local_addr() {
                        self.dump.udp_with_context(
                            dnsmasq_rs::dump::REPLY,
                            &response.packet,
                            source,
                            response.destination,
                            response.query_context,
                        );
                    }
                }
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
        let mut event = match self.parent_events.try_borrow_mut() {
            Ok(event) => event,
            Err(_) => return,
        };
        let mut metrics = self.metrics(&event);
        let mut parent = match self.service.try_borrow_mut() {
            Ok(parent) => parent,
            Err(_) => return,
        };
        let ParentDns { local, daemon, .. } = &mut *parent;
        let Some(daemon) = daemon.as_mut() else {
            return;
        };
        write_dns_metrics(
            &mut metrics,
            daemon.cache_counters(),
            daemon.forward_counters(),
            event.local_answered,
        );
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
        let daemon_query_events = daemon.take_query_events();
        drop(parent);
        #[cfg(target_os = "linux")]
        if let Some(logger) = &mut self.logger {
            for (context, event) in daemon_query_events {
                if let Some(event) =
                    dnsmasq_rs::logging::query::format(self.query_logging, context, &event)
                {
                    logger.emit(event);
                }
            }
        }
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
                #[cfg(target_os = "linux")]
                if self.dump.enabled(dnsmasq_rs::dump::REPLY) {
                    if let Ok(source) = target.local_addr() {
                        self.dump.udp_with_context(
                            dnsmasq_rs::dump::REPLY,
                            &response.packet,
                            source,
                            response.destination,
                            response.query_context,
                        );
                    }
                }
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
        #[cfg(target_os = "linux")]
        if !self.fd_ready(tcp.as_raw_fd(), owrt_ubus::sys::POLLIN) {
            return;
        }
        let Ok((stream, peer)) = tcp.accept() else {
            return;
        };
        let Ok(destination) = stream.local_addr() else {
            return;
        };
        let ingress = if self.config.bind_interfaces || self.config.bind_dynamic {
            None
        } else {
            // network.c:1030: wildcard TCP pktinfo uses parent packet scratch
            // before fork. Bound ordinary children keep their private copy.
            self.invalidate_udp_resend();
            listeners::tcp_interface(&stream, destination.is_ipv6())
        };
        let interfaces = match self.interfaces.try_borrow_mut() {
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
        let auth_query = if let Some((name, _)) = &ingress {
            self.config.auth.selected(destination.ip(), name)
        } else {
            interfaces.iter().any(|row| row.address == destination.ip()
                && match destination {
                    SocketAddr::V6(address) if address.ip().is_unicast_link_local() =>
                        address.scope_id() == row.index,
                    _ => true,
                }
                && self.config.auth.selected(row.address, &row.name))
        };
        drop(interfaces);
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let query_ids = match self.service.try_borrow_mut() {
            Ok(mut parent) => {
                if DEBUG_MODE.load(Ordering::Relaxed) {
                    Default::default()
                } else {
                    parent.query_ids.accept_tcp()
                }
            }
            Err(_) => return,
        };
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
            query_ids,
            stream,
            peer,
            local_network,
            mac,
            mac_ready,
            mac_deferred,
            accept_clock: now_seconds(),
            auth_query,
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
            query_ids,
            stream,
            peer,
            local_network,
            mac,
            mac_ready,
            mac_deferred,
            accept_clock,
            auth_query,
        } = pending;
        let mut parent = match self.service.try_borrow_mut() {
            Ok(parent) => parent,
            Err(_) => return,
        };
        let mut snapshot = LocalDnsService::new_with_limits(
            parent.local.config.clone(),
            parent.local.hosts.tcp_snapshot(),
            parent.local.local_ttl,
            parent.local.max_udp,
            parent.local.edns_packet_max,
        );
        snapshot.leases = Arc::clone(&parent.local.leases);
        snapshot.interfaces = Arc::clone(&parent.local.interfaces);
        snapshot.local_network = local_network;
        snapshot.query_logging = self.query_logging.enabled;
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
        forward.set_query_logging(self.query_logging.enabled);
        if let Ok(mut event) = self.parent_events.try_borrow_mut() {
            event.tcp_active = event.tcp_active.saturating_add(1);
            event.tcp_high_water = event.tcp_high_water.max(event.tcp_active);
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
            #[cfg(target_os = "linux")]
            poll_slot: None,
            #[cfg(target_os = "linux")]
            ready_events: 0,
            dns_work: Some(TcpDnsWork {
                query_ids,
                query_context: Default::default(),
                query_events: Vec::new(),
                peer,
                auth_query,
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
            }),
        });
    }

    #[cfg(target_os = "linux")]
    fn tcp_client_ready(&self, index: usize) -> bool {
        let client = &self.clients[index];
        let now = Instant::now();
        let Some(work) = &client.dns_work else { return true };
        if now >= work.deadline {
            return true;
        }
        #[cfg(target_pointer_width = "64")]
        let neighbor_ready = self.neighbors_ready;
        #[cfg(not(target_pointer_width = "64"))]
        let neighbor_ready = false;
        if !work.mac_ready && !work.mac_deferred {
            return now >= work.mac_deadline || neighbor_ready;
        }
        match &work.phase {
            TcpClientPhase::Reading => work.input_offset < work.input.len()
                || poll_events_match(client.ready_events, owrt_ubus::sys::POLLIN),
            TcpClientPhase::WaitingMac { .. } =>
                work.mac_ready || now >= work.mac_deadline || neighbor_ready,
            TcpClientPhase::Forwarding { wait, .. } => now >= wait.deadline
                || poll_events_match(client.ready_events, wait.events),
            TcpClientPhase::Writing { .. } =>
                poll_events_match(client.ready_events, owrt_ubus::sys::POLLOUT),
        }
    }

    fn step_tcp_clients(&mut self) {
        let mut index = 0;
        while index < self.clients.len() {
            #[cfg(target_os = "linux")]
            if !self.tcp_client_ready(index) {
                index += 1;
                continue;
            }
            if let Some(work) = &self.clients[index].dns_work {
                if Instant::now() < work.deadline && !work.mac_ready && !work.mac_deferred {
                    let lookup = if Instant::now() >= work.mac_deadline {
                        ClientMacLookup::Ready(None)
                    } else {
                        self.edns_mac(work.source, true)
                    };
                    match lookup {
                        ClientMacLookup::Ready(mac) => {
                            if let Some(work) = &mut self.clients[index].dns_work {
                                work.mac = mac;
                                work.mac_ready = true;
                            }
                        }
                        ClientMacLookup::Pending => {
                            index += 1;
                            continue;
                        }
                    }
                }
            }
            #[cfg(target_os = "linux")]
            let (readable, writable, forward_ready) = match &self.clients[index].dns_work {
                Some(TcpDnsWork { phase: TcpClientPhase::Forwarding { wait, .. }, .. }) =>
                    (false, false, poll_events_match(self.clients[index].ready_events, wait.events)),
                _ => (
                    poll_events_match(self.clients[index].ready_events, owrt_ubus::sys::POLLIN),
                    poll_events_match(self.clients[index].ready_events, owrt_ubus::sys::POLLOUT),
                    false,
                ),
            };
            #[cfg(not(target_os = "linux"))]
            let (readable, writable, forward_ready) = (true, true, true);
            #[cfg(target_os = "linux")]
            let was_network_done = self.clients[index].dns_work.is_none();
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            let result = if let Some(work) = &mut self.clients[index].dns_work {
                let neighbors = &mut self.neighbors;
                work.step(&self.service, &mut |source, lazy| {
                    lookup_edns_mac(neighbors, source, lazy)
                }, readable, writable, forward_ready)
            } else {
                Ok(false)
            };
            #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
            let result = if let Some(work) = &mut self.clients[index].dns_work {
                work.step(&self.service, &mut |_, _| ClientMacLookup::Ready(None),
                    readable, writable, forward_ready)
            } else {
                Ok(false)
            };
            #[cfg(target_os = "linux")]
            {
                let client = &mut self.clients[index];
                if let (Some(logger), Some(work)) = (&mut self.logger, &mut client.dns_work) {
                    use dnsmasq_rs::logging::{address_text, LogEvent, Priority, Service};
                    // An error/cancellation can leave producer events behind
                    // before run_forward reaches its normal collection point.
                    // Transfer them too before releasing the producer owners.
                    work.collect_local_query_events();
                    work.query_events.extend(work.forward.take_query_events().into_iter()
                        .map(|event| (work.query_context, event)));
                    for (query_context, event) in std::mem::take(&mut work.query_events)
                    {
                        if let Some(event) = dnsmasq_rs::logging::query::format(
                            self.query_logging,
                            query_context,
                            &event,
                        ) {
                            if let Some(context) = &mut client.log_context {
                                logger.emit_tcp(context, event);
                            } else {
                                logger.emit(event);
                            }
                        }
                    }
                    for address in work.forward.take_connection_failures() {
                        let mut message = b"TCP connection failed to ".to_vec();
                        message.extend_from_slice(&address_text(address));
                        message.extend_from_slice(format!("#{}", address.port()).as_bytes());
                        let event = LogEvent::new(Service::Debug, Priority::Debug, message);
                        if let Some(context) = &mut client.log_context {
                            logger.emit_tcp(context, event);
                        } else {
                            logger.emit(event);
                        }
                    }
                }
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(work) = &mut self.clients[index].dns_work {
                self.arp_awake |= std::mem::take(&mut work.parent_cache_activity);
            }
            let network_alive = result.unwrap_or(false);
            if !network_alive {
                // All producer events/warnings have reached their accepted log
                // context. Normal work, stale refresh, failure or cancellation
                // has now ended; release every DNS-owned field together before
                // waiting for a blocked FIFO to let the client slot/G finish.
                self.clients[index].dns_work.take();
            }
            #[cfg(target_os = "linux")]
            let logs_done = if let (Some(logger), Some(context)) =
                (&mut self.logger, &mut self.clients[index].log_context)
            {
                let log_ready = logger.tcp_poll_fd(context).is_some_and(|fd| {
                    self.ready_fds.iter().any(|ready| ready.fd == fd
                        && poll_events_match(ready.revents, owrt_ubus::sys::POLLOUT))
                }) || logger.tcp_retry_deadline(context).is_some_and(|due| due <= Instant::now());
                // Preserve the first forced finish after network closure.
                // Later turns retry only actual writable/timer work, while an
                // empty or failed queue can release its client immediately.
                if (!was_network_done && !network_alive) || log_ready {
                    logger.flush_tcp_ready(context);
                    network_alive || logger.finish_tcp(context)
                } else {
                    network_alive || logger.tcp_finished(context)
                }
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
                self.parent_events.borrow_mut().tcp_active = self.clients.len();
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn wait_during_probe(
        &mut self,
        icmp: Option<&dnsmasq_rs::net::IcmpSocket>,
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
        if self.edns_udp_runnable && !self.interface_work_pending() {
            deadline = Instant::now();
        }
        let mut fds = vec![PollFd {
            fd: icmp.map_or(-1, |socket| socket.as_raw_fd()),
            events: POLLIN,
            revents: 0,
        }];
        if let Some(fd) = self.dump.poll_fd() {
            fds.push(PollFd {
                fd,
                events: POLLOUT,
                revents: 0,
            });
        }
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
        // Pending startup input/interface work cannot consume new DNS requests.
        // Keep their sockets queued until the same admission gate can run.
        let dns_admission_ready = !self.files_initializing() && !self.interface_work_pending();
        for listener in self.listeners.iter().filter(|_| dns_admission_ready) {
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
        let upstream_fd_start = fds.len();
        let timer_sentinel = Instant::now() + Duration::from_secs(3600);
        self.upstream_next_due = self.service.borrow().daemon.as_ref().and_then(|daemon| {
            daemon.append_poll_fds(&mut fds, timer_sentinel)
        });
        if let Some(due) = self.upstream_next_due {
            deadline = deadline.min(due);
        }
        let upstream_fd_end = fds.len();
        for client in &mut self.clients {
            client.poll_slot = None;
            client.ready_events = 0;
            if let (Some(logger), Some(context)) = (&self.logger, &client.log_context) {
                if let Some(due) = logger.tcp_retry_deadline(context) {
                    deadline = deadline.min(due);
                }
                if client.dns_work.is_none() && logger.tcp_finished(context) {
                    deadline = Instant::now();
                }
            }
            let Some(work) = &client.dns_work else { continue };
            deadline = deadline.min(work.deadline);
            if !work.mac_ready && !work.mac_deferred {
                deadline = deadline.min(work.mac_deadline);
                continue;
            }
            let (fd, events) = match &work.phase {
                TcpClientPhase::Reading => {
                    if work.input_offset < work.input.len() {
                        deadline = Instant::now();
                    }
                    (
                        work.stream.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                        POLLIN,
                    )
                }
                TcpClientPhase::WaitingMac { .. } => {
                    deadline = deadline.min(work.mac_deadline);
                    if work.mac_ready { deadline = Instant::now(); }
                    (-1, 0)
                }
                TcpClientPhase::Writing { .. } => (
                    work.stream.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                    POLLOUT,
                ),
                TcpClientPhase::Forwarding { wait, .. } => {
                    deadline = deadline.min(wait.deadline);
                    (wait.fd, wait.events)
                }
            };
            client.poll_slot = Some(fds.len());
            fds.push(PollFd {
                fd,
                events,
                revents: 0,
            });
        }
        let tftp_fd_start = fds.len();
        if let Some(tftp) = &self.tftp {
            tftp.append_poll_fds(&mut fds);
            if tftp.has_pending_work() {
                deadline = deadline.min(self.tftp_next_due.unwrap_or_else(Instant::now));
            }
        }
        let tftp_fd_end = fds.len();
        let neighbors_fd_start = fds.len();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(neighbors) = &self.neighbors {
            neighbors.append_poll_fds(&mut fds);
            if let Some(due) = neighbors.active_dump_deadline() {
                deadline = deadline.min(neighbor_poll_deadline(due, Instant::now(),
                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()));
            }
        }
        let neighbors_fd_end = fds.len();
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
        self.ready_fds.clear();
        self.ready_fds.extend(fds.iter().filter(|fd| fd.revents != 0).copied());
        for client in &mut self.clients {
            client.ready_events = client.poll_slot.and_then(|slot| fds.get(slot))
                .map_or(0, |fd| fd.revents);
        }
        self.upstream_ready = fds[upstream_fd_start..upstream_fd_end].iter()
            .any(|fd| fd.revents != 0);
        self.tftp_ready = fds[tftp_fd_start..tftp_fd_end].iter()
            .any(|fd| fd.revents != 0);
        self.neighbors_ready = fds[neighbors_fd_start..neighbors_fd_end].iter()
            .any(|fd| fd.revents != 0)
            || self.neighbors.as_ref().and_then(NeighborCache::active_dump_deadline)
                .is_some_and(|due| due <= now_seconds() as u64);
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
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.advance_neighbors();
        self.step_tcp_clients();
        self.step_edns_udp();
        self.step_tftp();
        // Early DNS/TCP timers or any listener activity must not consume an
        // ICMP quarter-second timeout. Only the full idle poll counts as one.
        self.log_dns_diagnostics();
        Ok(ready != 0 || deadline < full_deadline)
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn helper_next_due(&self, now: Instant) -> Option<Instant> {
        let helper = self.helper.as_ref()?;
        // C moves DHCP/ARP/TFTP source work into its bounded helper buffer
        // before poll (dnsmasq.c:1177-1194). Our bounded service turn can create
        // source work after step_helper, so schedule the next turn immediately.
        // A full pipe or unready/stopping helper is driven only by its fd.
        if helper.can_enqueue()
            && (self.pending_delivery.is_some()
                || (self.helper_init.is_none() && !self.files_initializing()
                    && self.dhcp.as_ref().and_then(|dhcp| dhcp.provider.as_ref())
                    .and_then(|provider| provider.try_borrow().ok())
                    .is_some_and(|provider| provider.has_frozen_script_delivery()))
                || self.neighbors.as_ref()
                    .is_some_and(|neighbors| neighbors.front_script_change().is_some())
                || self.tftp.as_ref()
                    .is_some_and(|tftp| tftp.front_completion().is_some()))
        {
            Some(now)
        } else if helper.needs_reap() {
            Some(now + Duration::from_millis(10))
        } else {
            None
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_helper(&mut self) {
        if self.pending_delivery.is_none()
            && self.helper_init.is_none()
            && !self.files_initializing()
        {
            // C completes its initial resolver read before the first helper
            // queue turn. Keep the pre-Init callback frozen until then; helper
            // initialization, pipe progress and reaping still run below.
            let hosts_pending = self.hosts_work_pending();
            self.pending_delivery = self.dhcp.as_ref().and_then(|dhcp| {
                let mut provider = dhcp.provider.as_ref()?.try_borrow_mut().ok()?;
                if hosts_pending {
                    provider.take_frozen_script_delivery()
                } else {
                    provider.take_script_delivery()
                }
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
                                            .borrow_mut()
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
                    if let Ok(mut provider) = provider.try_borrow_mut() {
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
            self.pending_delivery = self.dhcp.as_ref().and_then(|dhcp| {
                dhcp.provider
                    .as_ref()?
                    .try_borrow_mut()
                    .ok()?
                    .take_script_delivery()
            });
        }
        if self.pending_delivery.is_none()
            && self
                .tftp
                .as_ref()
                .is_none_or(|listener| listener.front_completion().is_none())
        {
            let Some(helper) = self.helper.as_mut() else {
                return true;
            };
            helper.begin_shutdown();
            return helper.commands_drained();
        }
        false
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_dhcp(&mut self) {
        self.step_helper();
        // EVENT_RELOAD is consumed before DHCP in C. A completed bank is
        // still intermediate when another delivered SIGHUP waits in the queue.
        if !self.dhcp_packet_work_allowed() {
            return;
        }
        // The main wait already witnessed DHCP/PXE input or the fresh dump's
        // progress. No other owner consumes the queued packet between turns.
        let input_pending = self.dhcp_ready || self
                .dhcp
                .as_ref()
                .is_some_and(|dhcp| dhcp.listener.has_input().unwrap_or(false));
        if !input_pending {
            let maintenance_due = self
                .dhcp
                .as_ref()
                .and_then(|dhcp| dhcp.provider.as_ref())
                .and_then(|provider| provider.try_borrow().ok()?.next_maintenance())
                .is_some_and(|deadline| deadline <= Instant::now());
            if !maintenance_due {
                return;
            }
        }
        self.dhcp_ready = false;
        let Some(mut dhcp) = self.dhcp.take() else {
            return;
        };
        let Some(provider_ref) = dhcp.provider.as_ref().map(Rc::clone) else {
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
        let Ok(mut provider) = provider_ref.try_borrow_mut() else {
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
        // A bounded nonblocking send/data/DONE exchange may finish in this turn.
        if !input_pending
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
        // Each reply serializer initializes the entire transmitted prefix.
        let events = Rc::clone(&self.parent_events);
        let results = {
            let mut sink = |kind, fields: DhcpEventFields<'_>, logging| {
                events.borrow_mut().notify_dhcp(kind, fields, logging)
            };
            let mut wait =
                |socket: Option<&dnsmasq_rs::net::IcmpSocket>, duration, leases, notice| {
                    if let Some(notice) = notice {
                        if let Some(logger) = &mut self.logger {
                            logger.emit(notice);
                        }
                        return Ok(true);
                    }
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
                &mut dhcp.output,
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
                    &mut dhcp.output,
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
            || LOG_REOPEN_REQUESTED.load(Ordering::Acquire) != 0
            || CACHE_DUMP_REQUESTED.load(Ordering::Acquire) != 0
            || ALARM_REQUESTED.load(Ordering::Acquire) != 0;
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
        let parent = self.service.borrow_mut();
        if let Some(daemon) = &parent.daemon {
            let deadline = daemon.append_poll_fds(&mut fds, now + Duration::from_secs(3600));
            self.arp_awake |= deadline.is_some_and(|due| due <= now);
        }
        drop(parent);
        if let Some(ubus) = &self.parent_events.borrow_mut().ubus {
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
                    .borrow_mut()
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
        let was_busy = neighbors.active_dump_deadline().is_some();
        if let Err(error) = neighbors.step(now_seconds() as u64) {
            if error.kind() != io::ErrorKind::TimedOut {
                eprintln!("dnsmasq-rs: neighbor snapshot: {error}");
            }
        }
        if was_busy && neighbors.active_dump_deadline().is_none() {
            // A newly started dump can finish in the tail phase before any
            // owner poll has registered its fd. Capture pending TCP identities
            // now so the next wait registers their real downstream sockets;
            // buffered WaitingMac queries become runnable. UDP's bounded queue
            // runs after this phase; TFTP uses this same completion hint.
            self.neighbors_ready = true;
            self.capture_completed_tcp_macs();
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn capture_completed_tcp_macs(&mut self) {
        for index in 0..self.clients.len() {
            let Some(work) = self.clients[index].dns_work.as_ref() else { continue };
            if work.mac_ready
                || (work.mac_deferred && !matches!(&work.phase, TcpClientPhase::WaitingMac { .. }))
            {
                continue;
            }
            let source = work.source;
            if let ClientMacLookup::Ready(mac) = self.edns_mac(source, true) {
                if let Some(work) = self.clients[index].dns_work.as_mut() {
                    work.mac = mac;
                    work.mac_ready = true;
                    work.mac_deferred = false;
                }
            }
        }
        // Interface collection may still own an admitted connection. Capture
        // its completed identity once as well; finishing that admission later
        // must not park it behind a dump which has already disappeared.
        if let Some(pending) = &mut self.pending_interface_tcp {
            if !pending.mac_ready && !pending.mac_deferred {
                if let ClientMacLookup::Ready(mac) =
                    lookup_edns_mac(&mut self.neighbors, pending.peer.ip(), true)
                {
                    pending.mac = mac;
                    pending.mac_ready = true;
                }
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_tftp(&mut self) {
        let active = self
            .tftp
            .as_ref()
            .is_some_and(TftpListener::has_pending_work);
        if !self.tftp_ready && !active {
            return;
        }
        let now_instant = Instant::now();
        if !self.tftp_ready && !(active && self.neighbors_ready)
            && !(active && self.tftp_next_due.is_some_and(|deadline| deadline <= now_instant))
        {
            return;
        }
        self.tftp_ready = false;
        let Some(listener) = self.tftp.as_mut() else {
            return;
        };
        let now = now_seconds() as u64;
        let provider = self
            .dhcp
            .as_ref()
            .and_then(|dhcp| dhcp.provider.as_ref()?.try_borrow_mut().ok());
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
        drop(provider);
        let packet_overwritten = events.as_ref().is_ok_and(|events| {
            events.iter().any(|event| {
                use dnsmasq_rs::tftp_runtime::RuntimeEvent;
                match event {
                    RuntimeEvent::Send { id: Some(_), packet, .. } => {
                        matches!(packet.get(..2), Some([0, 3] | [0, 5] | [0, 6]))
                    }
                    // tftp.c:679-684 calls get_block without sending. With a
                    // saved UDP query, its scratch cannot still be the TFTP
                    // prefetch; nonfinal/OACK/netascii expiry reconstructs it.
                    // The octet final-ACK no-write branch is Completed here.
                    RuntimeEvent::TimedOut { .. } => true,
                    _ => false,
                }
            })
        });
        if packet_overwritten {
            // tftp.c:925/974: OACK/DATA construction borrows packet scratch.
            // Never reproduce srv_save's unsafe transfer/server pointer alias.
            if let Ok(mut parent) = self.service.try_borrow_mut() {
                if let Some(daemon) = parent.daemon.as_mut() {
                    daemon.invalidate_udp_resend();
                }
            }
        }
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
        self.tftp_next_due = listener.has_pending_work()
            .then_some(now_instant + Duration::from_millis(250));
        let needs_interfaces = listener.needs_interface_admission();
        if needs_interfaces {
            self.enumerate_interfaces(true);
            if !self.interface_work_pending() {
                // The same-turn latch or a failed control socket retains the
                // current published generation, just like UDP admission.
                if let Some(tftp) = &mut self.tftp {
                    tftp.resume_interface_admission(&self.interfaces.borrow(), now);
                }
                self.tftp_ready = true;
            }
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

#[derive(Debug, Eq, PartialEq)]
enum HostsReadNotice {
    Error(Vec<u8>),
    Complete { path: Vec<u8>, names: usize },
}

#[cfg(target_os = "linux")]
impl HostsReadNotice {
    fn into_log_event(self) -> dnsmasq_rs::logging::LogEvent {
        use dnsmasq_rs::logging::{LogEvent, Priority, Service};
        match self {
            Self::Error(message) => LogEvent::new(Service::Dns, Priority::Error, message),
            Self::Complete { path, names } => {
                dnsmasq_rs::logging::startup::hosts_read(&path, names)
            }
        }
    }
}

#[cfg(any(test, not(target_os = "linux")))]
fn read_hosts(config: &DnsConfig, local_ttl: u32) -> Hosts {
    let mut hosts = read_hosts_with_notices(config, local_ttl, 1232 + 255 + 10,
        1000, 1000, &dnsmasq_rs::dns::lease_names::LeaseNames::default(), |_| {})
        .unwrap_or_default();
    hosts.finish_bulk();
    hosts
}

fn read_hosts_with_notices(
    config: &DnsConfig,
    local_ttl: u32,
    packet_limit: usize,
    cache_size: usize,
    name_hash_capacity: usize,
    retained_leases: &dnsmasq_rs::dns::lease_names::LeaseNames,
    mut report: impl FnMut(HostsReadNotice),
) -> Result<Hosts, ()> {
    fn report_error(
        report: &mut impl FnMut(HostsReadNotice),
        action: &[u8],
        path: &Path,
        error: io::Error,
    ) {
        let mut message = action.to_vec();
        message.extend_from_slice(path.as_os_str().as_encoded_bytes());
        message.extend_from_slice(b": ");
        let error = error.to_string();
        message.extend_from_slice(
            error
                .split(" (os error ")
                .next()
                .unwrap_or(&error)
                .as_bytes(),
        );
        report(HostsReadNotice::Error(message));
    }
    fn read(
        hosts: &mut Hosts,
        config: &DnsConfig,
        path: &Path,
        source: u32,
        ttl: u32,
        report: &mut impl FnMut(HostsReadNotice),
    ) -> Result<(), ()> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) => {
                report_error(report, b"failed to load names from ", path, error);
                return Ok(());
            }
        };
        let path_name = dnsmasq_rs::hosts::try_copy(path.as_os_str().as_encoded_bytes())
            .map_err(|_| ())?;
        hosts.set_source_name_checked(source, path_name).map_err(|_| ())?;
        let stats = hosts.read_from_with_diagnostics(
            file,
            source,
            ttl,
            config.expand_hosts,
            |address| {
                config
                    .domain_for_address(address)
                    .ok()
                    .flatten()
                    .and_then(|name| dnsmasq_rs::hosts::try_copy(name).ok())
            },
            |line, address| {
                let prefix: &[u8] = if address { b"bad address at " } else { b"bad name at " };
                let Ok(mut message) = dnsmasq_rs::hosts::try_copy(prefix) else { return; };
                let path = path.as_os_str().as_encoded_bytes();
                if message.try_reserve(path.len() + 32).is_err() { return; }
                message.extend_from_slice(path);
                let _ = write!(message, " line {line}");
                report(HostsReadNotice::Error(message));
            },
        );
        if stats.allocation_failed {
            // Returning releases the entire unpublished replacement before
            // any completion logging or later file/directory allocation.
            return Err(());
        }
        if let Ok(path) = dnsmasq_rs::hosts::try_copy(path.as_os_str().as_encoded_bytes()) {
            report(HostsReadNotice::Complete { path, names: stats.accepted });
        }
        Ok(())
    }
    let mut hosts = dnsmasq_rs::dns::local::configured_hosts_bulk(
        config, local_ttl, packet_limit, cache_size, name_hash_capacity, retained_leases,
    )?;
    // `no-hosts` suppresses only the built-in /etc/hosts source. Explicit
    // addn-hosts files remain active in dnsmasq.
    if !config.no_hosts {
        read(
            &mut hosts,
            config,
            Path::new("/etc/hosts"),
            0,
            local_ttl,
            &mut report,
        )?;
    }
    // expand_filelist appends directory members after explicit files. Its
    // alphasort order matters when multiple names compete for PTR ownership.
    let mut directory_files = Vec::new();
    for (index, path) in config.addn_hosts.iter().enumerate() {
        let Some(path) = path else { continue };
        if !path.is_dir() {
            read(
                &mut hosts,
                config,
                path,
                (index + 1) as u32,
                local_ttl,
                &mut report,
            )?;
            continue;
        }
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) => {
                report_error(&mut report, b"cannot access directory ", path, error);
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
        read(
            &mut hosts,
            config,
            path,
            (config.addn_hosts.len() + index + 1) as u32,
            local_ttl,
            &mut report,
        )?;
    }
    Ok(hosts)
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
#[path = "main_route_resend_tests.rs"]
mod route_resend_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "main_neighbor_tail_tests.rs"]
mod neighbor_tail_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "main_hostsdir_init_tests.rs"]
mod hostsdir_init_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "main_hosts_initial_hup_tests.rs"]
mod hosts_initial_hup_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "main_newaddress_tests.rs"]
mod newaddress_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "main_stale_refresh_log_tests.rs"]
mod stale_refresh_log_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "main_udp_acl_tests.rs"]
mod udp_acl_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "main_tftp_admission_tests.rs"]
mod tftp_admission_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
#[path = "main_tcp_import_local_tests.rs"]
mod tcp_import_local_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use dnsmasq_rs::config::{lex_line, validate_directive};

    pub(super) fn test_owner(config: DnsConfig, daemon: Option<DnsDaemon>) -> SinglePoll {
        let local = LocalDnsService::new_with_limits(
            config.clone(), read_hosts(&config, 37), 37, 1232, 1232,
        );
        SinglePoll::new(
            Rc::new(RefCell::new(ParentDns {
                local, daemon, query_ids: Default::default(),
                pending_hosts: None,
                hosts_initializing: false,
            })),
            Rc::new(RefCell::new(ParentEvents::new(&UbusConfig::default()).unwrap())),
            Rc::new(RefCell::new(Vec::new())), config, Vec::new(), 1232, 20, 1232,
            Vec::new(),
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_runnable_overrides_a_future_timer_and_preserves_timer_rounding() {
        let now = Instant::now();
        assert_eq!(owner_poll_timeout(None, now, false), -1);
        assert_eq!(owner_poll_timeout(None, now, true), 0);
        assert_eq!(owner_poll_timeout(Some(now + Duration::from_secs(3600)), now, true), 0);
        assert_eq!(owner_poll_timeout(Some(now + Duration::from_nanos(1)), now, false), 1);
        assert_eq!(owner_poll_timeout(Some(now), now, false), 0);
        assert_eq!(owner_poll_timeout(Some(now + Duration::from_secs(7200)), now, false), 7_200_000);
        assert_eq!(owner_poll_timeout(Some(now + Duration::from_secs(u32::MAX as u64)), now, false), i32::MAX);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn interface_collector_send_and_completion_progress_without_network_input() {
        use dnsmasq_rs::dns::interface_collect::InterfaceCollector;
        let mut owner = test_owner(DnsConfig::default(), None);
        let mut collector = InterfaceCollector::new().unwrap();
        collector.begin().unwrap();
        assert!(collector.runnable(), "the first dump send has no readable fd yet");
        owner.interface_collector = Some(collector);
        for _ in 0..64 {
            owner.wait_for_files().unwrap();
            owner.step().unwrap();
            if !owner.interface_work_pending() { break; }
        }
        assert!(!owner.interface_work_pending(), "dump fd and deadline must resume its owner");
        assert!(owner.interfaces_enumerated);
        assert!(owner.interfaces.borrow().iter().any(|row| row.loopback));
        let collector = owner.interface_collector.as_ref().unwrap();
        assert!(!collector.runnable());
        assert!(collector.deadline().is_none(), "completed dumps must remove their timer");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dump_backpressure_resumes_on_writable_fd_without_another_packet() {
        use dnsmasq_rs::config::dump::DumpConfig;
        use dnsmasq_rs::dump::{DumpHandle, QUERY};
        use std::io::{Read, Write};
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!("owner-dump-wake-{}", std::process::id()));
        assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
        let mut reader = std::fs::OpenOptions::new().read(true).custom_flags(0o4000).open(&path).unwrap();
        let dump = DumpHandle::open(&DumpConfig { file: Some(path.clone()), mask: QUERY }, 1232).unwrap();
        let mut filler = std::fs::OpenOptions::new().write(true).custom_flags(0o4000).open(&path).unwrap();
        for size in [4096, 1] {
            loop {
                match filler.write(&[0; 4096][..size]) {
                    Ok(count) => assert_ne!(count, 0),
                    Err(error) => { assert_eq!(error.kind(), io::ErrorKind::WouldBlock); break; }
                }
            }
        }
        dump.udp(QUERY, b"queued dump", "192.0.2.1:12345".parse().unwrap(), "192.0.2.2:53".parse().unwrap());
        let fd = dump.poll_fd().expect("the accepted record must retain write interest");
        let mut owner = test_owner(DnsConfig::default(), None);
        owner.dump = dump.clone();
        let mut fds = Vec::new();
        owner.append_file_fds(&mut fds, true);
        assert!(fds.iter().any(|row| row.fd == fd && row.events == owrt_ubus::sys::POLLOUT));
        assert_eq!(owrt_ubus::sys::poll_fds(&mut fds, 0).unwrap(), 0);
        let mut bytes = [0; 8192];
        loop {
            match reader.read(&mut bytes) {
                Ok(count) => assert_ne!(count, 0),
                Err(error) => { assert_eq!(error.kind(), io::ErrorKind::WouldBlock); break; }
            }
        }
        owner.wait_for_files().unwrap();
        owner.step().unwrap();
        assert!(dump.poll_fd().is_none(), "drained dump must remove write interest");
        let count = reader.read(&mut bytes).unwrap();
        assert!(bytes[..count].ends_with(b"queued dump"));
        let notices = dump.take_notices();
        assert_eq!(notices.len(), 1);
        assert!(!notices[0].0);
        assert!(notices[0].1.starts_with(b"dumping packet 1 "));
        drop((owner, dump, reader, filler));
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn delivered_signal_counters_wake_even_without_a_pipe_byte() {
        let mut owner = test_owner(DnsConfig::default(), None);
        assert!(owner.signal_wake_read.is_none());
        for event in 0..5 {
            let before = match event {
                0 => usize::from(STOP_REQUESTED.swap(true, Ordering::AcqRel)),
                1 => LOG_REOPEN_REQUESTED.swap(1, Ordering::AcqRel),
                2 => RELOAD_REQUESTED.swap(1, Ordering::AcqRel),
                3 => CACHE_DUMP_REQUESTED.swap(1, Ordering::AcqRel),
                _ => ALARM_REQUESTED.swap(1, Ordering::AcqRel),
            };
            let started = Instant::now();
            let result = owner.wait_for_files();
            match event {
                0 => STOP_REQUESTED.store(before != 0, Ordering::Release),
                1 => LOG_REOPEN_REQUESTED.store(before, Ordering::Release),
                2 => RELOAD_REQUESTED.store(before, Ordering::Release),
                3 => CACHE_DUMP_REQUESTED.store(before, Ordering::Release),
                _ => ALARM_REQUESTED.store(before, Ordering::Release),
            }
            result.unwrap();
            assert!(started.elapsed() < Duration::from_millis(50),
                "logical signals cannot wait for the 100ms fallback");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signal_wake_drains_a_full_buffer_without_another_write() {
        let mut owner = test_owner(DnsConfig::default(), None);
        let (reader, writer) = owrt_ubus::sys::nonblocking_pipe().unwrap();
        let mut writer = std::fs::File::from(writer);
        writer.write_all(&[1; 64]).unwrap();
        owner.signal_wake_read = Some(reader);
        let started = Instant::now();
        owner.drain_signal_wake();
        assert!(started.elapsed() < Duration::from_millis(50));
        let mut reader = std::fs::File::from(owner.signal_wake_read.take().unwrap());
        assert_eq!(reader.read(&mut [0; 1]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signal_wake_preserves_interrupted_errno_with_or_without_backpressure() {
        for (has_pipe, saturated) in [(false, false), (true, false), (true, true)] {
            let (reader, writer) = owrt_ubus::sys::nonblocking_pipe().unwrap();
            let mut writer = std::fs::File::from(writer);
            if saturated {
                let mut filled = 0;
                loop {
                    match writer.write(&[1; 4096]) {
                        Ok(count) => { assert!(count > 0); filled += count; }
                        Err(error) => { assert_eq!(error.kind(), io::ErrorKind::WouldBlock); break; }
                    }
                    assert!(filled < 2 * 1024 * 1024);
                }
            }
            let previous_fd = SIGNAL_WAKE_WRITE.swap(if has_pipe { writer.as_raw_fd() } else { -1 }, Ordering::AcqRel);
            let previous_stop = STOP_REQUESTED.swap(false, Ordering::AcqRel);
            // SAFETY: Linux returns the current thread's live errno storage.
            let observed_errno = unsafe {
                let errno = __errno_location();
                let saved = *errno;
                *errno = 5; // EIO must survive a successful write or EAGAIN.
                request_stop(15);
                let observed = *errno;
                *errno = saved;
                observed
            };
            let delivered = STOP_REQUESTED.swap(previous_stop, Ordering::AcqRel);
            SIGNAL_WAKE_WRITE.store(previous_fd, Ordering::Release);
            assert!(delivered);
            assert_eq!(observed_errno, 5, "pipe={has_pipe}, saturated={saturated}");
            drop((reader, writer));
        }
    }

    #[test]
    fn pending_listener_retry_requires_unfinished_initial_address() {
        let address: SocketAddr = "[fd42::1]:53".parse().unwrap();
        let mut row = DnsInterface { index: 7, name: b"fixture".to_vec(), address: address.ip(),
            netmask: "ffff:ffff:ffff:ffff::".parse().unwrap(), loopback: false, tentative: true };
        assert!(pending_listener_retry(&[address], &[row.clone()]));
        row.tentative = false;
        assert!(!pending_listener_retry(&[address], &[row.clone()]), "a mature bind error is not a DAD timer");
        assert!(!pending_listener_retry(&[], &[row]), "ordinary configs have no periodic interface scan");
        assert!(pending_listener_retry(&[address], &[]), "a captured DAD address can return later");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interface_dad_deadline_is_one_second_and_removed_when_done() {
        let now = Instant::now();
        let mut refresh = InterfaceRefresh::default();
        assert!(!refresh.due(now + Duration::from_secs(3600)));
        refresh.request(); assert!(refresh.due(now));
        refresh.complete(now, true);
        assert_eq!(refresh.retry_at, Some(now + Duration::from_secs(1)));
        assert!(!refresh.due(now + Duration::from_millis(999)));
        assert!(refresh.due(now + Duration::from_secs(1)));
        refresh.complete(now, false);
        assert!(refresh.retry_at.is_none()); assert!(!refresh.requested);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn multicast_enobufs_continues_without_fabricating_any_event() {
        let mut config = DnsConfig::default(); config.no_hosts = true; config.no_resolv = true;
        let mut owner = test_owner(config.clone(), None);
        owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
        let now = Instant::now();
        owner.finish_route_read(Err(io::Error::from_raw_os_error(105)), now);
        assert_eq!(owner.route_retry_at, Some(now), "next bounded owner turn must continue the drain");
        assert!(!owner.interface_refresh.requested, "overflow is not NEWADDR");
        assert!(owner.interface_refresh.retry_at.is_none(), "overflow does not request snapshot resync");
        assert!(!owner.dns_files.as_ref().unwrap().has_work(), "overflow is not NEWROUTE/full reload");
        owner.finish_route_read(Err(io::Error::from_raw_os_error(11)), now);
        assert!(owner.route_retry_at.is_none(), "EAGAIN returns to the real fd wait");
        owner.finish_route_read(Err(io::Error::from_raw_os_error(5)), now);
        assert_eq!(owner.route_retry_at, Some(now + Duration::from_secs(1)));
        assert!(!owner.interface_refresh.requested);
        assert!(!owner.dns_files.as_ref().unwrap().has_work());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn port_zero_address_actor_does_not_need_a_dns_file_owner() {
        let mut config = DnsConfig::default(); config.bind_dynamic = true;
        let mut owner = test_owner(config, None);
        assert!(owner.dns_files.is_none());
        owner.apply_network_events(NetworkEvents { address: true, ..Default::default() });
        assert!(owner.interface_refresh.requested, "address publication survives DNS disabled");
        assert!(!owner.retry_bound_listeners, "address is not the legacy route-retry flag");
        owner.interface_refresh.complete(Instant::now(), false);
        owner.apply_network_events(NetworkEvents { route: true, ..Default::default() });
        assert!(!owner.interface_refresh.requested, "a route is not a fake address change");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn address_actor_is_independent_of_held_hosts_publication() {
        use dnsmasq_rs::dns::hostsdir::{HostSource, HostsRead};
        let path = std::env::temp_dir().join(format!("address-held-hosts-{}", std::process::id()));
        assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
        let mut config = DnsConfig::default(); config.no_hosts = true; config.no_resolv = true;
        config.bind_dynamic = true;
        let mut owner = test_owner(config.clone(), None);
        owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
        owner.hosts_read = Some(HostsRead::open(HostSource { path: path.clone(), uid: 1 }, 37).unwrap());
        assert!(!owner.dns_file_work_runnable());
        owner.apply_network_events(NetworkEvents { address: true, ..Default::default() });
        assert!(owner.interface_refresh.requested);
        assert!(!owner.dns_files.as_ref().unwrap().has_work(), "address must not queue resolver reload");
        owner.apply_network_events(NetworkEvents { route: true, ..Default::default() });
        assert!(owner.dns_files.as_ref().unwrap().has_work(), "real route is retained until file order allows it");
        assert!(!owner.dns_file_work_runnable(), "a held FIFO does not become busy-runnable");
        drop(owner); std::fs::remove_file(path).unwrap();
    }

    fn add_test_tcp(owner: &mut SinglePoll) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, address) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        owner.finish_tcp_accept(PendingInterfaceTcp {
            query_ids: Default::default(), stream, peer: address, local_network: None,
            mac: None, mac_ready: true, mac_deferred: false, accept_clock: now_seconds(),
            auth_query: false,
        });
        assert_eq!(owner.clients.len(), 1);
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        peer
    }

    fn park_edns_waiters(owner: &mut SinglePoll, count: usize) {
        for index in 0..count {
            owner.pending_edns_udp.push(PendingEdnsUdp {
                query_context: Default::default(), listener: SocketToken(99),
                client: ClientRequest { source: SocketAddr::from(([192, 0, 2, index as u8], 5300)),
                    destination: "192.0.2.1".parse().unwrap(), interface: 0 },
                query: test_dns_query(), deadline: Instant::now() + Duration::from_secs(3),
            });
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn neighbor_deadline_keeps_fractional_epoch_and_expired_dump_immediate() {
        let now = Instant::now();
        // Both normal and probe owners use this same active-dump projection.
        // A coarse two-second epoch bound must not acquire an extra second.
        assert_eq!(neighbor_poll_deadline(102, now, Duration::from_millis(100_750)) - now,
            Duration::from_millis(1250));
        assert_eq!(neighbor_poll_deadline(102, now, Duration::from_millis(102_250)), now);
    }

    #[test]
    fn edns_budget_tail_is_logical_work_without_another_neighbor_event() {
        let mut owner = test_owner(DnsConfig::default(), None);
        park_edns_waiters(&mut owner, 33);
        owner.step_edns_udp_with_lookup(|_, _| ClientMacLookup::Ready(None));
        assert_eq!(owner.pending_edns_udp.len(), 1);
        assert!(owner.edns_udp_runnable);
        #[cfg(target_os = "linux")]
        {
            assert!(owner.ready_fds.is_empty());
            let started = Instant::now();
            owner.wait_for_files().unwrap();
            assert!(started.elapsed() < Duration::from_millis(100),
                "a ready budget tail must not sleep to its three-second fallback");
        }
        owner.step_edns_udp_with_lookup(|_, _| ClientMacLookup::Ready(None));
        assert!(owner.pending_edns_udp.is_empty());
        assert!(!owner.edns_udp_runnable);
    }

    #[test]
    fn edns_mixed_pending_queue_drains_ready_tail_then_stops_spinning() {
        let mut owner = test_owner(DnsConfig::default(), None);
        park_edns_waiters(&mut owner, MAX_EDNS_UDP_WAITERS);
        let ready = |_: &mut SinglePoll, source: IpAddr| {
            if matches!(source, IpAddr::V4(address) if address.octets()[3] % 2 == 0) {
                ClientMacLookup::Ready(None)
            } else {
                ClientMacLookup::Pending
            }
        };
        for remaining in [224, 192, 160, 128] {
            owner.step_edns_udp_with_lookup(ready);
            assert_eq!(owner.pending_edns_udp.len(), remaining);
            assert!(owner.edns_udp_runnable);
        }
        // One bounded recheck establishes that the rest still needs its dump.
        owner.step_edns_udp_with_lookup(ready);
        assert_eq!(owner.pending_edns_udp.len(), 128);
        assert!(!owner.edns_udp_runnable);
        owner.step_edns_udp_with_lookup(|_, _| ClientMacLookup::Pending);
        assert!(!owner.edns_udp_runnable);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn accepted_mac_wait_does_not_busy_poll_queued_dns_before_snapshot_ready() {
        use owrt_ubus::sys::POLLIN;
        use std::os::fd::AsRawFd;
        let mut owner = test_owner(DnsConfig::default(), None);
        let mut peer = add_test_tcp(&mut owner);
        peer.write_all(&encode_tcp_frame(&test_dns_query()).unwrap()).unwrap();
        owner.clients[0].dns_work.as_mut().unwrap().mac_ready = false;
        owner.clients[0].dns_work.as_mut().unwrap().mac_deferred = false;
        owner.clients[0].dns_work.as_mut().unwrap().mac_deadline = Instant::now() + Duration::from_secs(3);
        owner.clients[0].ready_events = POLLIN;
        assert!(!owner.tcp_client_ready(0), "unread DNS cannot resolve a pending MAC");
        let stream_fd = owner.clients[0].dns_work.as_ref().unwrap().stream.as_ref().unwrap().as_raw_fd();
        let started = Instant::now();
        owner.wait_for_files().unwrap();
        assert!(started.elapsed() >= Duration::from_millis(50),
            "without a signal pipe this fixture uses100ms fallback, not the queued socket");
        assert!(!owner.poll_fds.iter().any(|fd| fd.fd == stream_fd));
        assert_eq!(owner.clients[0].ready_events, 0);
        owner.neighbors_ready = true;
        assert!(owner.tcp_client_ready(0), "dump completion authorizes the MAC resume");
        owner.step_tcp_clients();
        assert!(owner.clients[0].dns_work.as_ref().unwrap().mac_ready);
        assert!(owner.clients[0].dns_work.as_ref().unwrap().input.is_empty(), "MAC wake does not invent read readiness");
        owner.neighbors_ready = false;
        owner.wait_for_files().unwrap();
        assert!(owner.tcp_client_ready(0), "now the real queued DNS socket becomes readable");
    }

    fn test_dns_query() -> Vec<u8> {
        use dnsmasq_rs::dns::wire::{Name, PacketWriter};
        let mut writer = PacketWriter::new(7, 0x100, 1232).unwrap();
        writer.question(&Name::from_ascii("ready.test").unwrap(), 1, 1).unwrap();
        writer.finish()
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub(super) fn attach_test_dhcp(owner: &mut SinglePoll, provider: DhcpProvider) -> std::net::UdpSocket {
        let listener = DhcpSocketListener::bind("127.0.0.1:0".parse().unwrap(), DhcpListener::Dhcp, &[]).unwrap();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.connect(listener.local_addr().unwrap()).unwrap();
        owner.dhcp = Some(DhcpService { provider: Some(Rc::new(RefCell::new(provider))), listener,
            pxe_next: false, output: vec![0; 16_384] });
        peer
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn helper_init_keeps_queued_dhcp_and_due_maintenance_off_the_wait_set() {
        for fatal in [false, true] {
            let mut owner = test_owner(DnsConfig::default(), None);
            let provider = DhcpProvider::new(DhcpConfig { no_ping: true, lease_read_only: true,
                ..Default::default() }, Vec::new(), 0, || false).unwrap();
            let peer = attach_test_dhcp(&mut owner, provider);
            peer.send(b"queued-dhcp").unwrap();
            if fatal {
                owner.helper_init_error = Some(dnsmasq_rs::helper::StartError { code: 5, message: "held helper error".into() });
            } else {
                owner.helper_init = Some(Default::default());
            }
            let started = Instant::now();
            owner.wait_for_files().unwrap();
            assert!(started.elapsed() >= Duration::from_millis(25),
                "neither unread DHCP nor an unprocessable alarm may busy-poll");
            owner.step_dhcp();
            assert!(owner.dhcp.as_ref().unwrap().listener.has_input().unwrap());
            let address = owner.dhcp.as_ref().unwrap().listener.local_addr().unwrap();
            assert!(!owner.poll_fds.iter().any(|fd| {
                let mut probe = Vec::new();
                owner.dhcp.as_ref().unwrap().listener.append_poll_fds(&mut probe);
                probe.iter().any(|socket| socket.fd == fd.fd)
            }));
            owner.helper_init = None;
            owner.helper_init_error = None;
            assert!(owner.dhcp_packet_work_allowed());
            owner.wait_for_files().unwrap();
            owner.step_dhcp();
            assert!(!owner.dhcp.as_ref().unwrap().listener.has_input().unwrap(),
                "the original input becomes consumable after the helper gate opens at {address}");
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn held_dhcp_bank_fifo_does_not_spin_on_queued_packet_and_dns_still_replies() {
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!("ready-dhcp-bank-fifo-{}", std::process::id()));
        assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_resolv = true;
        config.bind_interfaces = true;
        config.local_service_net = false;
        config.apply_resolved(&lex_line(b"address=/ready.test/192.0.2.4").unwrap().unwrap()).unwrap();
        let daemon = DnsDaemon::new(config.clone(), Hosts::new(), &[], DaemonOptions::default()).unwrap();
        let mut owner = test_owner(config, Some(daemon));
        let mut provider = DhcpProvider::new(DhcpConfig { no_ping: true, lease_read_only: true,
            option_files: vec![path.as_os_str().as_encoded_bytes().to_vec()], ..Default::default() }, Vec::new(), 0, || false).unwrap();
        provider.start_file_owner().unwrap();
        for _ in 0..16 {
            if !provider.files_runnable() { break; }
            provider.step_files_with_watch_readiness(now_seconds(), false);
        }
        let mut writer = std::fs::OpenOptions::new().write(true).custom_flags(0o4000).open(&path).unwrap();
        writer.write_all(b"option:domain-name,initial\n").unwrap();
        drop(writer);
        assert!((0..16).find_map(|_| provider.step_files_with_watch_readiness(now_seconds(), false)).is_some());
        assert!(!provider.files_initializing());
        let held_writer = std::fs::OpenOptions::new().read(true).write(true).custom_flags(0o4000).open(&path).unwrap();
        provider.reload_data_files(now_seconds());
        for _ in 0..16 {
            if !provider.files_runnable() { break; }
            provider.step_files_with_watch_readiness(now_seconds(), false);
        }
        assert!(provider.file_work_pending() && !provider.files_runnable());
        let peer = attach_test_dhcp(&mut owner, provider);
        peer.send(b"queued-dhcp").unwrap();
        let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let dns_peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        dns_peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        dns_peer.send_to(&test_dns_query(), udp.local_addr().unwrap()).unwrap();
        owner.add_listener(SocketToken(9), Some(udp), None);
        owner.wait_for_files().unwrap();
        owner.step().unwrap();
        let mut answer = [0; 1232];
        let count = dns_peer.recv(&mut answer).unwrap();
        assert_eq!(&answer[count-4..count], &[192, 0, 2, 4], "runtime FIFO cannot block ordinary DNS");
        assert!(owner.dhcp.as_ref().unwrap().listener.has_input().unwrap());
        let started = Instant::now();
        owner.wait_for_files().unwrap();
        assert!(started.elapsed() >= Duration::from_millis(25), "the queued blocked DHCP packet is not readiness");
        let mut socket_fds = Vec::new();
        owner.dhcp.as_ref().unwrap().listener.append_poll_fds(&mut socket_fds);
        assert!(!owner.poll_fds.iter().any(|fd| socket_fds.iter().any(|socket| socket.fd == fd.fd)),
            "blocked input must be absent even if scheduler latency masks a spin");
        drop(held_writer);
        for _ in 0..16 {
            owner.wait_for_files().unwrap();
            owner.step_dhcp_files();
            if !owner.dhcp_reload_in_progress() { break; }
        }
        assert!(!owner.dhcp_reload_in_progress());
        owner.wait_for_files().unwrap();
        owner.step_dhcp();
        assert!(!owner.dhcp.as_ref().unwrap().listener.has_input().unwrap());
        drop(owner);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn packet_snapshot_controls_dhcp_wait_until_publication() {
        let mut owner = test_owner(DnsConfig::default(), None);
        let mut provider = DhcpProvider::new(DhcpConfig { no_ping: true, lease_read_only: true,
            ..Default::default() }, Vec::new(), 0, || false).unwrap();
        provider.initialize(now_seconds());
        provider.start_interface_owner().unwrap();
        let snapshot_ready = provider.prepare_packet_interfaces().unwrap();
        let peer = attach_test_dhcp(&mut owner, provider);
        peer.send(b"queued-dhcp").unwrap();
        let mut socket_fds = Vec::new();
        owner.dhcp.as_ref().unwrap().listener.append_poll_fds(&mut socket_fds);
        owner.wait_for_files().unwrap();
        assert_eq!(owner.poll_fds.iter().any(|fd| socket_fds.iter().any(|socket| socket.fd == fd.fd)),
            snapshot_ready, "only a complete fresh dump enables the packet listener");
        assert!(owner.dhcp.as_ref().unwrap().listener.has_input().unwrap());
        for _ in 0..16 {
            owner.step_dhcp();
            if !owner.dhcp.as_ref().unwrap().listener.has_input().unwrap() { break; }
            owner.wait_for_files().unwrap();
        }
        assert!(!owner.dhcp.as_ref().unwrap().listener.has_input().unwrap());
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn global_interface_generation_keeps_queued_dhcp_until_its_publication() {
        let mut owner = test_owner(DnsConfig::default(), None);
        let provider = DhcpProvider::new(DhcpConfig { no_ping: true, lease_read_only: true,
            ..Default::default() }, Vec::new(), 0, || false).unwrap();
        let peer = attach_test_dhcp(&mut owner, provider);
        peer.send(b"queued-dhcp").unwrap();
        let mut collector = dnsmasq_rs::dns::interface_collect::InterfaceCollector::new().unwrap();
        collector.begin().unwrap();
        owner.interface_collector = Some(collector);
        let mut socket_fds = Vec::new();
        owner.dhcp.as_ref().unwrap().listener.append_poll_fds(&mut socket_fds);
        for _ in 0..32 {
            assert!(!owner.dhcp_packet_work_allowed());
            owner.wait_for_files().unwrap();
            assert!(!owner.poll_fds.iter().any(|fd| socket_fds.iter().any(|socket| socket.fd == fd.fd)));
            owner.step_dhcp();
            assert!(owner.dhcp.as_ref().unwrap().listener.has_input().unwrap());
            owner.step_interface_collector();
            if !owner.interface_work_pending() { break; }
        }
        assert!(!owner.interface_work_pending());
        owner.wait_for_files().unwrap();
        owner.step_dhcp();
        assert!(!owner.dhcp.as_ref().unwrap().listener.has_input().unwrap());
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn lease_alarm_without_network_traffic_expires_and_rewrites_the_lease_file() {
        let path = std::env::temp_dir().join(format!("ready-dhcp-alarm-{}.leases", std::process::id()));
        let now = now_seconds();
        std::fs::write(&path, format!("{} 02:00:00:00:00:01 192.0.2.10 lease-alarm *\n", now+2)).unwrap();
        let mut provider = DhcpProvider::new(DhcpConfig { no_ping: true,
            lease_file: Some(path.as_os_str().as_encoded_bytes().to_vec()), ..Default::default() }, Vec::new(), 0, || false).unwrap();
        provider.initialize(now);
        assert_eq!(provider.lease_counters().pruned4, 0);
        let mut owner = test_owner(DnsConfig::default(), None);
        let _unused_peer = attach_test_dhcp(&mut owner, provider);
        let deadline = Instant::now() + Duration::from_secs(4);
        while owner.dhcp.as_ref().unwrap().provider.as_ref().unwrap().borrow().lease_counters().pruned4 == 0 {
            assert!(Instant::now() < deadline, "expiry must not require a new DHCP request");
            owner.wait_for_files().unwrap();
            owner.step_dhcp();
        }
        assert!(std::fs::read(&path).unwrap().is_empty());
        assert!(!owner.dhcp.as_ref().unwrap().listener.has_input().unwrap());
        assert!(owner.dhcp.as_ref().unwrap().provider.as_ref().unwrap().borrow().next_maintenance().is_none());
        drop(owner);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn finish_test_file_init(owner: &mut SinglePoll) {
        owner.dns_files.as_mut().unwrap().request(ReloadReason::Init);
        for _ in 0..32 {
            if !owner.dns_files.as_ref().unwrap().has_work() { break; }
            owner.step_dns_files();
            owner.step_hosts_files();
        }
        assert!(!owner.dns_files.as_ref().unwrap().has_work());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hup_same_wake_refreshes_hosts_before_udp_and_new_tcp_snapshot() {
        let path = std::env::temp_dir().join(format!("hup-hosts-order-{}", std::process::id()));
        std::fs::write(&path, b"192.0.2.42 ready.test\n").unwrap();
        let mut config = DnsConfig::default();
        config.no_resolv = true;
        config.no_hosts = true;
        config.bind_interfaces = true;
        config.addn_hosts = vec![Some(path.clone())];
        let daemon = DnsDaemon::new(config.clone(), read_hosts(&config, 37), &[],
            DaemonOptions::default()).unwrap();
        let mut owner = test_owner(config.clone(), Some(daemon));
        owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
        let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let tcp = TcpListener::bind(udp.local_addr().unwrap()).unwrap();
        tcp.set_nonblocking(true).unwrap();
        let mut tcp_peer = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
        tcp_peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let udp_peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp_peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let query = test_dns_query();
        udp_peer.send_to(&query, udp.local_addr().unwrap()).unwrap();
        tcp_peer.write_all(&encode_tcp_frame(&query).unwrap()).unwrap();
        owner.add_listener(SocketToken(1), Some(udp), Some(tcp));
        owner.wait_for_files().unwrap();
        std::fs::write(&path, b"192.0.2.43 ready.test\n").unwrap();
        // Model the actual signal-pipe event accepted from this same wake,
        // avoiding test races on the process-global signal counter.
        owner.process_reload_before_dns(37, true).unwrap();
        owner.step().unwrap();
        let mut answer = [0; 1232];
        let length = udp_peer.recv(&mut answer).unwrap();
        assert!(answer[..length].ends_with(&[192, 0, 2, 43]));
        owner.wait_for_files().unwrap();
        owner.step().unwrap();
        let mut size = [0; 2];
        tcp_peer.read_exact(&mut size).unwrap();
        let mut answer = vec![0; usize::from(u16::from_be_bytes(size))];
        tcp_peer.read_exact(&mut answer).unwrap();
        assert!(answer.ends_with(&[192, 0, 2, 43]), "new accept must snapshot the new hosts bank");
        drop(owner);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hup_publishes_small_resolver_and_server_inputs_before_tcp_accept() {
        use dnsmasq_rs::config::dns::{RuleTarget, ServerHost};
        for resolver in [true, false] {
            let path = std::env::temp_dir().join(format!("hup-bank-order-{}-{resolver}", std::process::id()));
            let text = |address| if resolver { format!("nameserver {address}\n") }
                else { format!("server=/ready.test/{address}\n") };
            std::fs::write(&path, text("127.0.0.2")).unwrap();
            let mut config = DnsConfig::default();
            config.no_hosts = true;
            config.bind_interfaces = true;
            config.no_resolv = !resolver;
            config.no_poll = resolver;
            if resolver { config.resolv_files = vec![path.clone()]; }
            else { config.servers_file = Some(path.clone()); }
            let daemon = DnsDaemon::new(config.clone(), Hosts::new(), &[], DaemonOptions::default()).unwrap();
            let mut owner = test_owner(config.clone(), Some(daemon));
            owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
            finish_test_file_init(&mut owner);
            let contains = |config: &DnsConfig, address: &str| config.rules.iter().any(|rule| {
                matches!(&rule.target, RuleTarget::Upstream(endpoint)
                    if endpoint.host == ServerHost::Address(address.parse().unwrap()))
            });
            assert!(contains(&owner.service.borrow().local.config, "127.0.0.2"));
            std::fs::write(&path, text("127.0.0.3")).unwrap();
            owner.process_reload_before_dns(37, true).unwrap();
            assert!(!owner.dns_files.as_ref().unwrap().has_work());
            assert!(contains(&owner.service.borrow().local.config, "127.0.0.3"));
            assert!(!contains(&owner.service.borrow().local.config, "127.0.0.2"));
            let _peer = add_test_tcp(&mut owner);
            assert!(contains(&owner.clients[0].dns_work.as_ref().unwrap().service.config, "127.0.0.3"));
            assert!(!contains(&owner.clients[0].dns_work.as_ref().unwrap().service.config, "127.0.0.2"));
            drop(owner);
            std::fs::remove_file(path).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hup_large_regular_input_yields_before_dns_health_service() {
        let path = std::env::temp_dir().join(format!("hup-large-order-{}", std::process::id()));
        std::fs::write(&path, b"nameserver 127.0.0.2\n").unwrap();
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_poll = true;
        config.bind_interfaces = true;
        config.resolv_files = vec![path.clone()];
        config.apply(&lex_line(b"host-record=ready.test,192.0.2.99").unwrap().unwrap()).unwrap();
        let daemon = DnsDaemon::new(config.clone(), read_hosts(&config, 37), &[],
            DaemonOptions::default()).unwrap();
        let mut owner = test_owner(config.clone(), Some(daemon));
        owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
        finish_test_file_init(&mut owner);
        std::fs::write(&path, format!("{}nameserver 127.0.0.3\n", "# padding\n".repeat(128 * 1024))).unwrap();
        let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        peer.send_to(&test_dns_query(), udp.local_addr().unwrap()).unwrap();
        owner.add_listener(SocketToken(1), Some(udp), None);
        owner.wait_for_files().unwrap();
        owner.process_reload_before_dns(37, true).unwrap();
        assert!(owner.dns_files.as_ref().unwrap().has_work(), "prephase must not drain an unbounded large file");
        owner.step().unwrap();
        let mut answer = [0; 1232];
        let length = peer.recv(&mut answer).unwrap();
        assert!(answer[..length].ends_with(&[192, 0, 2, 99]));
        assert!(owner.dns_files.as_ref().unwrap().has_work(), "DNS remains healthy during the pending file generation");
        drop(owner);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn queued_server_file_reload_publishes_without_another_network_event() {
        use dnsmasq_rs::config::dns::{RuleTarget, ServerHost};
        let path = std::env::temp_dir().join(format!("ready-servers-file-{}", std::process::id()));
        std::fs::write(&path, b"server=/ready.test/127.0.0.2\n").unwrap();
        let mut config = DnsConfig::default();
        config.no_resolv = true;
        config.no_hosts = true;
        config.bind_interfaces = true;
        config.servers_file = Some(path.clone());
        let daemon = DnsDaemon::new(config.clone(), Hosts::new(), &[], DaemonOptions::default()).unwrap();
        let mut owner = test_owner(config.clone(), Some(daemon));
        owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
        for (reason, address) in [(ReloadReason::Init, "127.0.0.2"),
                                   (ReloadReason::Signal, "127.0.0.3")] {
            std::fs::write(&path, format!("server=/ready.test/{address}\n")).unwrap();
            assert!(!owner.files_runnable, "the previous FileStep is idle");
            owner.dns_files.as_mut().unwrap().request(reason);
            assert!(owner.dns_files.as_ref().unwrap().watch_fd().is_none());
            assert!(owner.dns_file_work_runnable(), "a late request must wake the owner");
            for _ in 0..16 {
                if !owner.dns_files.as_ref().unwrap().has_work() { break; }
                assert!(owner.dns_file_work_runnable());
                owner.wait_for_files().unwrap();
                owner.step_dns_files();
            }
            assert!(!owner.dns_files.as_ref().unwrap().has_work());
            assert!(!owner.dns_file_work_runnable(), "idle file sources must not spin");
            assert!(owner.service.borrow().local.config.rules.iter().any(|rule| {
                matches!(&rule.target, RuleTarget::Upstream(endpoint)
                    if endpoint.host == ServerHost::Address(address.parse().unwrap()))
            }));
        }
        drop(owner);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_hosts_fifo_blocks_dns_runnable_without_losing_its_request() {
        use dnsmasq_rs::dns::hostsdir::{HostSource, HostsRead};
        let path = std::env::temp_dir().join(format!("ready-hosts-fifo-{}", std::process::id()));
        assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
        let mut config = DnsConfig::default();
        config.no_resolv = true;
        config.no_hosts = true;
        let mut owner = test_owner(config.clone(), None);
        owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
        owner.dns_files.as_mut().unwrap().request(ReloadReason::Signal);
        owner.files_runnable = true; // stale previous result is also suppressed
        owner.hosts_read = Some(HostsRead::open(HostSource { path: path.clone(), uid: 1 },
            37).unwrap());
        assert!(!owner.hosts_read.as_ref().unwrap().runnable());
        assert!(!owner.dns_file_work_runnable(), "DNS cannot busy-poll ahead of hosts publication");
        owner.step_dns_files();
        assert!(owner.dns_files.as_ref().unwrap().has_work());
        owner.hosts_read.take();
        assert!(owner.dns_file_work_runnable(), "finishing hosts makes the saved request runnable");
        drop(owner);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn startup_fifo_keeps_blocked_dns_off_both_wait_sets_without_dropping_it() {
        use std::os::fd::AsRawFd;
        let path = std::env::temp_dir().join(format!("ready-startup-fifo-{}", std::process::id()));
        assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_poll = true;
        config.bind_interfaces = true;
        config.resolv_files = vec![path.clone()];
        let mut owner = test_owner(config.clone(), None);
        owner.dns_files = Some(DnsFiles::new(&config, true, false).unwrap());
        owner.dns_files.as_mut().unwrap().request(ReloadReason::Init);
        // Init first publishes its cache/hosts barrier, before opening input.
        // Advance only genuinely runnable stages to the actual FIFO wait.
        for _ in 0..16 {
            if !owner.dns_file_work_runnable() { break; }
            owner.step_dns_files();
        }
        assert!(owner.files_initializing());
        assert!(!owner.dns_file_work_runnable(), "the opened FIFO waits for input");
        assert!(!owner.dhcp_packet_work_allowed(), "DHCP must also wait for initial hosts");
        let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let query = test_dns_query();
        peer.send_to(&query, udp.local_addr().unwrap()).unwrap();
        let tcp = TcpListener::bind(udp.local_addr().unwrap()).unwrap();
        tcp.set_nonblocking(true).unwrap();
        let tcp_fd = tcp.as_raw_fd();
        let mut tcp_peer = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
        let frame = encode_tcp_frame(&query).unwrap();
        tcp_peer.write_all(&frame).unwrap();
        owner.add_listener(SocketToken(1), Some(Arc::clone(&udp)), Some(tcp));
        owner.wait_for_files().unwrap();
        assert!(!owner.poll_fds.iter().any(|fd| fd.fd == udp.as_raw_fd()),
            "a queued but unprocessable DNS packet must not spin normal poll");
        assert!(!owner.poll_fds.iter().any(|fd| fd.fd == tcp_fd),
            "a pending but unprocessable TCP accept also cannot spin poll");
        assert!(!owner.wait_during_probe(None, Duration::from_millis(25), Default::default()).unwrap(),
            "blocked DNS readiness must not consume the probe wait");
        let mut packet = [0; 1232];
        let queued = udp.receive(&mut packet).unwrap().unwrap();
        assert_eq!(&packet[..queued.len], query.as_slice(), "the original DNS input stays queued");
        assert!(owner.clients.is_empty(), "probe cannot admit a premature TCP snapshot");
        let (mut queued_tcp, _) = owner.listeners[0].tcp.as_ref().unwrap().accept().unwrap();
        let mut queued_frame = vec![0; frame.len()];
        queued_tcp.read_exact(&mut queued_frame).unwrap();
        assert_eq!(queued_frame, frame, "the original TCP request also stays queued");
        drop(owner);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub(super) fn ready_test_helper() -> Helper {
        let mut helper = Helper::start(HelperConfig {
            script: "/bin/true".into(), script_user: None, debug: false,
        }).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !helper.ready() {
            assert!(Instant::now() < deadline);
            helper.step().unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        helper
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub(super) fn finish_test_helper(helper: &mut Helper) {
        helper.begin_shutdown();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !helper.is_finished() {
            assert!(Instant::now() < deadline);
            helper.step().unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn last_tftp_completion_wakes_helper_without_another_packet() {
        use dnsmasq_rs::tftp_runtime::{RuntimeConfig, RuntimePathPolicy, TransferRuntime};
        use std::os::unix::ffi::OsStrExt;
        let root = std::env::temp_dir().join(format!("ready-tftp-helper-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("boot"), b"last data").unwrap();
        // Both the explicit final ACK and C's final-ACK timeout leave no
        // active transfer fd/timer to wake the owner for its callback.
        for ack in [true, false] {
            let runtime = TransferRuntime::new(RuntimeConfig {
                path: RuntimePathPolicy { prefix: Some(root.as_os_str().as_bytes().to_vec()),
                    lowercase: false }, ..Default::default()
            }, RealFileOpener::new(0, false));
            let mut listener = TftpListener::bind("127.0.0.1:0".parse().unwrap(), runtime).unwrap();
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let now = now_seconds() as u64;
            peer.send_to(b"\0\x01boot\0octet\0", listener.local_addr().unwrap()).unwrap();
            listener.poll_once(now).unwrap();
            let mut packet = [0; 1024];
            let (_, transfer) = peer.recv_from(&mut packet).unwrap();
            if ack {
                peer.send_to(&[0, 4, 0, 1], transfer).unwrap();
                listener.poll_once(now).unwrap();
            } else {
                listener.poll_once(now + 122).unwrap();
            }
            assert!(!listener.has_pending_work());
            assert!(listener.front_completion().is_some());
            let mut owner = test_owner(DnsConfig::default(), None);
            owner.helper = Some(ready_test_helper());
            owner.tftp = Some(listener);
            assert!(owner.ready_fds.is_empty());
            let clock = Instant::now();
            assert_eq!(owner.helper_next_due(clock), Some(clock));
            owner.wait_for_files().unwrap();
            owner.step_helper();
            assert!(owner.tftp.as_ref().unwrap().front_completion().is_none());
            assert_eq!(owner.helper_next_due(clock), None,
                "drained sources and an idle live helper must not spin");
            finish_test_helper(owner.helper.as_mut().unwrap());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn frozen_dhcp_callbacks_resume_after_pipe_capacity_returns() {
        let path = std::env::temp_dir().join(format!("ready-helper-leases-{}", std::process::id()));
        std::fs::write(&path, b"0 02:00:00:00:00:01 192.0.2.10 one *\n0 02:00:00:00:00:02 192.0.2.11 two *\n").unwrap();
        let mut provider = DhcpProvider::new(DhcpConfig {
            no_ping: true, script: Some(b"/bin/true".to_vec()),
            lease_file: Some(path.as_os_str().as_encoded_bytes().to_vec()),
            ..Default::default()
        }, Vec::new(), 0, || false).unwrap();
        provider.tick(now_seconds()).unwrap();
        assert!(provider.has_frozen_script_delivery());
        let mut owner = test_owner(DnsConfig::default(), None);
        owner.pending_delivery = provider.take_script_delivery();
        assert!(owner.pending_delivery.is_some());
        assert!(provider.has_frozen_script_delivery(), "taking one freezes the next callback");
        owner.dhcp = Some(DhcpService {
            provider: Some(Rc::new(RefCell::new(provider))),
            listener: DhcpSocketListener::bind("127.0.0.1:0".parse().unwrap(),
                DhcpListener::Dhcp, &[]).unwrap(), pxe_next: false,
            output: vec![0; 16_384],
        });
        owner.helper = Some(ready_test_helper());
        let now = Instant::now();
        assert_eq!(owner.helper_next_due(now), Some(now));
        assert!(owner.helper.as_mut().unwrap().enqueue(&dnsmasq_rs::helper::Event::Tftp {
            size: 0, address: "127.0.0.1".parse().unwrap(), filename: b"backpressure".to_vec(),
        }).unwrap());
        assert_eq!(owner.helper_next_due(now), None,
            "occupied command slot waits for POLLOUT instead of spinning");
        owner.helper.as_mut().unwrap().step().unwrap();
        owner.step_helper();
        assert!(owner.pending_delivery.is_none());
        assert_eq!(owner.helper_next_due(now), Some(now),
            "the provider's next frozen callback also wakes the owner");
        owner.dns_files = Some(DnsFiles::new(&DnsConfig::default(), true, false).unwrap());
        owner.dns_files.as_mut().unwrap().request(ReloadReason::Init);
        assert!(owner.files_initializing());
        assert_eq!(owner.helper_next_due(now), None,
            "a callback blocked by startup files must not busy-poll");
        owner.step_helper();
        assert!(owner.pending_delivery.is_none());
        assert!(owner.dhcp.as_ref().unwrap().provider.as_ref().unwrap()
            .borrow().has_frozen_script_delivery(), "startup gate retains the callback");
        owner.dns_files = None;
        assert_eq!(owner.helper_next_due(now), Some(now));
        owner.step_helper();
        assert_eq!(owner.helper_next_due(now), None);
        finish_test_helper(owner.helper.as_mut().unwrap());
        drop(owner);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn tcp_polled_write_does_not_consume_unpolled_read() {
        let mut owner = test_owner(DnsConfig::default(), None);
        let mut peer = add_test_tcp(&mut owner);
        peer.write_all(b"not-yet-readable").unwrap();
        let client = owner.clients[0].dns_work.as_mut().unwrap();
        // Model a prefix already sent, leaving the same six answer bytes.
        client.phase = TcpClientPhase::Writing {
            frame: TcpWriteFrame::new(b"answer".to_vec()).unwrap(), offset: 2,
        };
        assert!(client.step(&owner.service, &mut |_, _| ClientMacLookup::Ready(None),
            false, true, false).unwrap());
        let mut answer = [0; 6];
        peer.read_exact(&mut answer).unwrap();
        assert_eq!(&answer, b"answer");
        assert!(matches!(client.phase, TcpClientPhase::Reading));
        assert!(client.input.is_empty());
        let mut pending = [0; 32];
        assert_eq!(client.stream.as_ref().unwrap().peek(&mut pending).unwrap(), 16);
        assert_eq!(&pending[..16], b"not-yet-readable");
    }

    #[test]
    fn tcp_buffered_frame_runs_without_socket_readiness_and_sends_new_answer() {
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.apply(&lex_line(b"host-record=ready.test,192.0.2.7").unwrap().unwrap()).unwrap();
        let mut owner = test_owner(config, None);
        let mut peer = add_test_tcp(&mut owner);
        let query = test_dns_query();
        let client = owner.clients[0].dns_work.as_mut().unwrap();
        client.input = encode_tcp_frame(&query).unwrap();
        assert!(client.step(&owner.service, &mut |_, _| ClientMacLookup::Ready(None),
            false, false, false).unwrap());
        let mut size = [0; 2];
        peer.read_exact(&mut size).unwrap();
        let mut answer = vec![0; usize::from(u16::from_be_bytes(size))];
        peer.read_exact(&mut answer).unwrap();
        assert!(answer.ends_with(&[192, 0, 2, 7]));
        assert_eq!(client.queries, 1);
        assert_eq!(client.input_offset, client.input.len());
    }

    #[test]
    fn tcp_parsed_lookup_keeps_original_invalid_questions_refused() {
        let valid = test_dns_query();
        let mut multi = valid.clone();
        multi[4..6].copy_from_slice(&2u16.to_be_bytes());
        multi.extend_from_slice(&valid[12..]);
        let mut compressed = valid.clone();
        compressed[4..6].copy_from_slice(&2u16.to_be_bytes());
        compressed.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        let mut zero = valid[..12].to_vec();
        zero[4..6].copy_from_slice(&0u16.to_be_bytes());
        let with_tail = |tail: &[u8]| [valid[..12].to_vec(), tail.to_vec()].concat();
        let mut long = valid[..12].to_vec();
        for length in [63, 63, 63, 62] {
            long.push(length);
            long.extend(std::iter::repeat_n(b'a', usize::from(length)));
        }
        long.extend_from_slice(&[0, 0, 1, 0, 1]);
        let cases = [multi, compressed, zero,
            with_tail(&[0xc0, 12, 0, 1, 0, 1]),
            with_tail(&[0xc0, 255, 0, 1, 0, 1]),
            with_tail(&[0x41, 8, b'a', 0, 0, 1, 0, 1]), long];
        for debug in [false, true] {
            let mut config = DnsConfig::default();
            config.no_hosts = true;
            config.no_resolv = true;
            config.apply(&lex_line(b"host-record=ready.test,192.0.2.7").unwrap().unwrap()).unwrap();
            let mut daemon = DnsDaemon::new(config.clone(), read_hosts(&config, 37), &[],
                DaemonOptions::default()).unwrap();
            daemon.enable_cache(32, 0, 0, dnsmasq_rs::dns::cache::StalePolicy::Disabled);
            let mut owner = test_owner(config, Some(daemon));
            let mut peer = add_test_tcp(&mut owner);
            let client = owner.clients[0].dns_work.as_mut().unwrap();
            client.cache_debug = debug;
            for query in cases.iter().chain(std::iter::once(&valid)) {
                client.input = encode_tcp_frame(query).unwrap();
                client.input_offset = 0;
                assert!(client.step(&owner.service, &mut |_, _| ClientMacLookup::Ready(None),
                    false, false, false).unwrap());
                let mut size = [0; 2];
                peer.read_exact(&mut size).unwrap();
                let mut answer = vec![0; usize::from(u16::from_be_bytes(size))];
                peer.read_exact(&mut answer).unwrap();
                let header = dnsmasq_rs::dns::wire::Header::parse(&answer).unwrap();
                let expected = if query == &valid { (0x8580, 1) } else { (0x8185, 0) };
                assert_eq!((header.flags, header.answers), expected);
                assert!(matches!(client.phase, TcpClientPhase::Reading));
            }
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn real_tcp_read_budget_tail_resumes_through_normal_and_probe_owner() {
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.apply(&lex_line(b"host-record=ready.test,192.0.2.7").unwrap().unwrap()).unwrap();
        let mut owner = test_owner(config, None);
        let mut peer = add_test_tcp(&mut owner);
        let frame = encode_tcp_frame(&test_dns_query()).unwrap();
        let pipeline = frame.repeat(9);
        peer.write_all(&pipeline).unwrap();

        owner.wait_for_files().unwrap();
        owner.step_tcp_clients();
        assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().queries, 4, "eight read/write steps serve four frames");
        assert!(matches!(owner.clients[0].dns_work.as_ref().unwrap().phase, TcpClientPhase::Reading));
        assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().input.len(), pipeline.len());
        assert!(owner.clients[0].dns_work.as_ref().unwrap().input_offset < owner.clients[0].dns_work.as_ref().unwrap().input.len());
        let mut byte = [0];
        assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().stream.as_ref().unwrap().peek(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock, "no new kernel read event can authorize the tail");

        let started = Instant::now();
        owner.wait_for_files().unwrap();
        assert!(started.elapsed() < Duration::from_millis(50));
        assert!(owner.ready_fds.is_empty());
        assert_eq!(owner.clients[0].ready_events, 0);
        assert!(owner.tcp_client_ready(0));
        owner.step_tcp_clients();
        assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().queries, 8);

        let started = Instant::now();
        assert!(owner.wait_during_probe(None, Duration::from_millis(200), Default::default()).unwrap());
        assert!(started.elapsed() < Duration::from_millis(50));
        assert_eq!(owner.clients[0].ready_events, 0);
        assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().queries, 9);
        assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().input_offset, owner.clients[0].dns_work.as_ref().unwrap().input.len());
        for _ in 0..9 {
            let mut size = [0; 2];
            peer.read_exact(&mut size).unwrap();
            let mut answer = vec![0; usize::from(u16::from_be_bytes(size))];
            peer.read_exact(&mut answer).unwrap();
            assert!(answer.ends_with(&[192, 0, 2, 7]));
            assert_eq!(dnsmasq_rs::dns::wire::Header::parse(&answer).unwrap().rcode(), 0);
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn real_tcp_transport_budget_tail_resumes_through_normal_and_probe_owner() {
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_resolv = true;
        // Each real source-bind attempt fails before connect. The first client
        // step starts and resumes transport once (128 attempts), leaving a
        // second 64-step tail for normal poll and one attempt for probe poll.
        for port in 10000..10193 {
            let line = format!("server=127.0.0.1#{port}@m6b-no-if-64");
            config.apply(&lex_line(line.as_bytes()).unwrap().unwrap()).unwrap();
        }
        let mut owner = test_owner(config, None);
        let mut peer = add_test_tcp(&mut owner);
        peer.write_all(&encode_tcp_frame(&test_dns_query()).unwrap()).unwrap();
        owner.wait_for_files().unwrap();
        owner.step_tcp_clients();
        let assert_yield = |owner: &SinglePoll| {
            let TcpClientPhase::Forwarding { wait, .. } = &owner.clients[0].dns_work.as_ref().unwrap().phase
                else { panic!("real transport must still have failed servers to visit"); };
            assert_eq!(wait.fd, -1);
            assert_eq!(wait.events, 0);
            assert!(wait.deadline <= Instant::now());
        };
        assert_yield(&owner);
        let started = Instant::now();
        owner.wait_for_files().unwrap();
        assert!(started.elapsed() < Duration::from_millis(50));
        assert!(owner.ready_fds.is_empty());
        assert_eq!(owner.clients[0].ready_events, 0);
        assert!(owner.tcp_client_ready(0));
        owner.step_tcp_clients();
        assert_yield(&owner);
        let started = Instant::now();
        assert!(owner.wait_during_probe(None, Duration::from_millis(200), Default::default()).unwrap());
        assert!(started.elapsed() < Duration::from_millis(50));
        assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().queries, 1);
        assert!(matches!(owner.clients[0].dns_work.as_ref().unwrap().phase, TcpClientPhase::Reading));
        let mut size = [0; 2];
        peer.read_exact(&mut size).unwrap();
        let mut answer = vec![0; usize::from(u16::from_be_bytes(size))];
        peer.read_exact(&mut answer).unwrap();
        // C tcp_talk exhausts failed local_bind attempts, tcp_request sets
        // EDE_NETERR, and make_local_answer(flags=0) uses REFUSED, not
        // SERVFAIL (forward.c:2633/2734; rfc1035.c:1370-1376). No OPT here.
        assert_eq!(dnsmasq_rs::dns::wire::Header::parse(&answer).unwrap().rcode(), 5);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_idle_deadline_and_completed_client_run_without_fd_readiness() {
        let mut owner = test_owner(DnsConfig::default(), None);
        let _peer = add_test_tcp(&mut owner);
        owner.clients[0].dns_work.as_mut().unwrap().deadline = Instant::now();
        owner.step_tcp_clients();
        assert!(owner.clients.is_empty(), "expired idle client must release its slot");
        let _peer = add_test_tcp(&mut owner);
        owner.clients[0].dns_work.take();
        owner.step_tcp_clients();
        assert!(owner.clients.is_empty(), "log-complete client must release its slot");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn duplicate_fd_masks_merge_without_authorizing_read_from_write() {
        use owrt_ubus::sys::{PollFd, POLLIN, POLLOUT};
        let mut owner = test_owner(DnsConfig::default(), None);
        owner.ready_fds = vec![
            PollFd { fd: 42, events: POLLOUT, revents: POLLOUT },
            PollFd { fd: 42, events: POLLIN, revents: 0 },
        ];
        assert!(owner.fd_ready(42, POLLOUT));
        assert!(!owner.fd_ready(42, POLLIN));
        owner.ready_fds[1].revents = POLLIN;
        assert!(owner.fd_ready(42, POLLIN));
        let _peer = add_test_tcp(&mut owner);
        assert_eq!(owner.clients[0].ready_events, 0,
            "accepted client owns no slot from the previous poll");
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn upstream_timeout_wake_advances_without_ready_network_fd() {
        use dnsmasq_rs::dns::upstream::Lifetime;
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut config = DnsConfig::default();
        config.no_resolv = true;
        let line = format!("server=127.0.0.1#{}", server.local_addr().unwrap().port());
        config.apply(&lex_line(line.as_bytes()).unwrap().unwrap()).unwrap();
        let mut daemon = DnsDaemon::new(config.clone(), Hosts::new(), &[], DaemonOptions {
            upstream_lifetime: Lifetime::Fixed(Duration::from_millis(20)),
            ..Default::default()
        }).unwrap();
        assert!(matches!(daemon.forward_udp(&test_dns_query(), ClientRequest {
            source: "127.0.0.1:53000".parse().unwrap(), destination: "127.0.0.1".parse().unwrap(),
            interface: 0,
        }).unwrap(), QueryResult::Forwarded(_)));
        let mut owner = test_owner(config, Some(daemon));
        owner.wait_for_files().unwrap();
        assert!(!owner.upstream_ready);
        assert!(owner.upstream_next_due.unwrap() <= Instant::now());
        owner.step().unwrap();
        assert_eq!(owner.service.borrow().daemon.as_ref().unwrap().pending_count(), 0);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn probe_poll_dispatches_new_udp_using_its_own_readiness() {
        let mut config = DnsConfig::default();
        config.bind_interfaces = true;
        config.no_hosts = true;
        config.no_resolv = true;
        config.apply(&lex_line(b"host-record=ready.test,192.0.2.7").unwrap().unwrap()).unwrap();
        let daemon = DnsDaemon::new(config.clone(), read_hosts(&config, 37), &[],
            DaemonOptions::default()).unwrap();
        let mut owner = test_owner(config, Some(daemon));
        let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = udp.local_addr().unwrap();
        owner.add_listener(SocketToken(1), Some(udp), None);
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        client.send_to(&test_dns_query(), address).unwrap();
        assert!(owner.ready_fds.is_empty());
        assert!(owner.wait_during_probe(None, Duration::from_millis(50), Default::default()).unwrap());
        let mut answer = [0; 1232];
        let (length, _) = client.recv_from(&mut answer).unwrap();
        assert!(answer[..length].ends_with(&[192, 0, 2, 7]));
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn finished_tcp_log_fifo_retries_without_network_events_and_releases_slot() {
        use dnsmasq_rs::config::logging::LoggingConfig;
        use dnsmasq_rs::logging::{LogEvent, Logger, Priority, Service};
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!("dnsmasq-ready-log-{}", std::process::id()));
        assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
        let (logger, _) = Logger::start(&LoggingConfig { file: Some(path.clone()),
            ..Default::default() }, &Default::default(), None).unwrap();
        let mut owner = test_owner(DnsConfig::default(), None);
        owner.logger = Some(logger);
        let _peer = add_test_tcp(&mut owner);
        let context = owner.clients[0].log_context.as_mut().unwrap();
        owner.logger.as_mut().unwrap().emit_tcp(context,
            LogEvent::new(Service::Dns, Priority::Info, b"pending child log".to_vec()));
        let (lease_root, interface_root) = {
            let work = owner.clients[0].dns_work.as_mut().unwrap();
            // Each accepted owner has independent DNS allocations as well as
            // two shared publication roots; none belongs to the log context.
            work.cache_view = Some(dnsmasq_rs::dns::cache::Cache::new(4096,
                Default::default()));
            work.input = vec![0; 65_535];
            // Keep a legal partial 1232-byte frame under this fixture's limit.
            work.framer.push_frame(&[0x04, 0xd0, 1]).unwrap();
            work.mac = Some(vec![7; 1024]);
            work.stale_query = Some(vec![0; 1232]);
            work.deadline = Instant::now();
            (Arc::downgrade(&work.service.leases), Arc::downgrade(&work.service.interfaces))
        };
        owner.step_tcp_clients();
        assert_eq!(owner.clients.len(), 1);
        assert_eq!(owner.parent_events.borrow().tcp_active, 1, "G still holds its slot");
        assert!(owner.clients[0].dns_work.is_none(), "all DNS allocations are released together");
        assert_eq!(lease_root.strong_count(), 1, "only the parent's lease root remains");
        assert_eq!(interface_root.strong_count(), 1, "only the parent's interface root remains");
        assert!(owner.clients[0].log_context.is_some());
        let mut reader = std::fs::OpenOptions::new().read(true).custom_flags(0o4000)
            .open(&path).unwrap();
        owner.wait_for_files().unwrap();
        owner.step_tcp_clients();
        assert!(owner.clients.is_empty(), "FIFO timer must drain log and free TCP slot");
        assert_eq!(owner.parent_events.borrow().tcp_active, 0);
        let mut message = String::new();
        match reader.read_to_string(&mut message) {
            Ok(_) => (),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
        }
        assert!(message.contains("pending child log"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn tcp_closed_downstream_keeps_pending_stale_work_until_refresh_completes() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = upstream.local_addr().unwrap();
        let (query_sender, query_receiver) = std::sync::mpsc::channel();
        let (reply_sender, reply_receiver) = std::sync::mpsc::channel();
        let (closed_sender, closed_receiver) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            upstream.set_nonblocking(true).unwrap();
            let due = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match upstream.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < due);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut length = [0; 2];
            stream.read_exact(&mut length).unwrap();
            let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut query).unwrap();
            query_sender.send(query.clone()).unwrap();
            reply_receiver.recv_timeout(Duration::from_secs(3)).unwrap();
            query[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            stream.write_all(&encode_tcp_frame(&query).unwrap()).unwrap();
            let mut byte = [0];
            closed_sender.send(stream.read(&mut byte).unwrap()).unwrap();
        });
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_resolv = true;
        config.apply(&lex_line(format!("server=127.0.0.1#{}", address.port())
            .as_bytes()).unwrap().unwrap()).unwrap();
        let mut owner = test_owner(config, None);
        #[cfg(target_os = "linux")]
        let log_path = {
            use dnsmasq_rs::config::logging::LoggingConfig;
            use dnsmasq_rs::logging::Logger;
            let path = std::env::temp_dir().join(format!("dnsmasq-stale-log-{}", std::process::id()));
            assert!(std::process::Command::new("mkfifo").arg(&path).status().unwrap().success());
            let (logger, _) = Logger::start(&LoggingConfig { file: Some(path.clone()),
                ..Default::default() }, &Default::default(), None).unwrap();
            owner.logger = Some(logger);
            owner.query_logging.enabled = true;
            path
        };
        let mut peer = add_test_tcp(&mut owner);
        let query = test_dns_query();
        let lease_root = {
            let work = owner.clients[0].dns_work.as_mut().unwrap();
            work.cache_view = Some(dnsmasq_rs::dns::cache::Cache::new(4096, Default::default()));
            work.stale_query = Some(query.clone());
            work.phase = TcpClientPhase::Writing {
                frame: TcpWriteFrame::new(query.clone()).unwrap(), offset: 0,
            };
            work.queries = 1;
            // File/FIFO logging has exactly one buffer, matching C. Keep the
            // first producer warning; later request/forward events must reach
            // the logger and count as overflow while the FIFO has no reader.
            work.query_events.push((work.query_context,
                dnsmasq_rs::query_logging::QueryEvent::warning(b"stale-work warning before release".to_vec())));
            work.query_events.push((work.query_context,
                dnsmasq_rs::query_logging::QueryEvent::request(&query, work.peer, work.auth_query).unwrap()));
            Arc::downgrade(&work.service.leases)
        };
        // Test readiness drives nonblocking I/O. The real owner poll is covered
        // separately; this test controls exactly when the upstream may reply.
        let drive = |owner: &mut SinglePoll| {
            #[cfg(target_os = "linux")]
            for client in &mut owner.clients {
                client.ready_events = owrt_ubus::sys::POLLIN | owrt_ubus::sys::POLLOUT;
            }
            owner.step_tcp_clients();
        };
        let due = Instant::now() + Duration::from_secs(3);
        loop {
            drive(&mut owner);
            match query_receiver.try_recv() {
                Ok(received) => { assert_eq!(received, query); break; }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    assert!(Instant::now() < due);
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("{error}"),
            }
        }
        let mut frame = vec![0; query.len() + 2];
        peer.read_exact(&mut frame).unwrap();
        assert_eq!(frame, encode_tcp_frame(&query).unwrap());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0, "downstream is already closed");
        let work = owner.clients[0].dns_work.as_ref().unwrap();
        assert!(work.stream.is_none());
        assert!(work.refreshing_stale);
        assert!(matches!(work.phase, TcpClientPhase::Forwarding { .. }));
        assert_eq!(lease_root.strong_count(), 2, "pending refresh still pins the accepted view");
        assert_eq!(owner.parent_events.borrow().tcp_active, 1);
        for _ in 0..8 { drive(&mut owner); }
        assert!(owner.clients[0].dns_work.is_some(), "pending upstream must not release early");
        reply_sender.send(()).unwrap();
        while owner.clients.first().is_some_and(|client| client.dns_work.is_some()) {
            assert!(Instant::now() < due);
            drive(&mut owner);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(lease_root.strong_count(), 1);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(owner.parent_events.borrow().tcp_active, 0);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(owner.clients.len(), 1, "G remains held while accepted logs are blocked");
            assert_eq!(owner.parent_events.borrow().tcp_active, 1);
            assert!(owner.clients[0].dns_work.is_none());
            assert!(owner.clients[0].log_context.is_some());
        }
        assert_eq!(closed_receiver.recv_timeout(Duration::from_secs(3)).unwrap(), 0,
            "persistent upstream also closes when DNS work ends");
        server.join().unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut reader = std::fs::OpenOptions::new().read(true).custom_flags(0o4000)
                .open(&log_path).unwrap();
            while !owner.clients.is_empty() {
                assert!(Instant::now() < due);
                owner.wait_for_files().unwrap();
                owner.step_tcp_clients();
            }
            assert_eq!(owner.parent_events.borrow().tcp_active, 0);
            let mut messages = String::new();
            if let Err(error) = reader.read_to_string(&mut messages) {
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            }
            assert!(messages.contains("stale-work warning before release"));
            assert!(messages.contains("overflow:"));
            assert!(messages.contains("log entries lost"));
            std::fs::remove_file(log_path).unwrap();
        }
    }

    #[test]
    fn udp_turn_budget_is_bounded_for_service_fairness() {
        assert!(UDP_PACKETS_PER_TURN > 1);
        assert!(UDP_PACKETS_PER_TURN <= 64);
    }

    #[test]
    fn startup_status_retains_config_loader_exit_codes() {
        for exit_code in [1, 3, 4, 5, (3 << 8) + 10] {
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
            Rc::new(RefCell::new(ParentDns {
                local: LocalDnsService::new_with_limits(
                    DnsConfig::default(),
                    Hosts::new(),
                    0,
                    512,
                    512,
                ),
                daemon: None,
                query_ids: Default::default(),
                pending_hosts: None,
                hosts_initializing: false,
            })),
            Rc::new(RefCell::new(
                ParentEvents::new(&UbusConfig::default()).unwrap(),
            )),
            Rc::new(RefCell::new(Vec::new())),
            DnsConfig::default(),
            Vec::new(),
            512,
            20,
            512,
            Vec::new(),
            Some(DhcpService {
                provider: Some(Rc::new(RefCell::new(provider))),
                listener,
                pxe_next: false,
                output: vec![0; 16_384],
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
    fn ordinary_hosts_diagnostics_include_the_source_and_complete_after_errors() {
        let path = std::env::temp_dir().join(format!("dnsmasq-rs-bad hosts-{}", std::process::id()));
        std::fs::write(&path, b"# comment\n192.0.2.44 \xff good.test \x01\n").unwrap();
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.addn_hosts.push(Some(path.clone()));
        let mut notices = Vec::new();
        let hosts = read_hosts_with_notices(&config, 37, 1232 + 255 + 10, 1000, 1000,
            &dnsmasq_rs::dns::lease_names::LeaseNames::default(),
            |notice| notices.push(notice)).unwrap();
        let message = format!("bad name at {} line 2", path.display()).into_bytes();
        assert_eq!(notices, [
            HostsReadNotice::Error(message.clone()),
            HostsReadNotice::Error(message),
            HostsReadNotice::Complete {
                path: path.as_os_str().as_encoded_bytes().to_vec(),
                names: 1,
            },
        ]);
        assert!(hosts.name_exists(b"good.test"));
        #[cfg(target_os = "linux")]
        for notice in notices {
            let expected = match notice {
                HostsReadNotice::Error(_) => dnsmasq_rs::logging::Priority::Error,
                HostsReadNotice::Complete { .. } => dnsmasq_rs::logging::Priority::Info,
            };
            assert_eq!(notice.into_log_event().priority as i32, expected as i32);
        }
        std::fs::remove_file(path).unwrap();
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
