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
use dnsmasq_rs::tftp_listener::TftpListener;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::tftp_runtime::{RealFileOpener, RuntimeConfig, RuntimePathPolicy, TransferRuntime};
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);
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
    RELOAD_REQUESTED.store(true, Ordering::Release);
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
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if let Err(error) = run(&args) {
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
    if error.is::<NetworkStartupError>() {
        return 2;
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
        dns: DnsConfig::default(),
        tftp: TftpConfig::default(),
        dhcp: DhcpConfig::default(),
        ubus: UbusConfig::default(),
    };
    let action = loader::load(args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        if runtime.process.apply(directive)?
            || runtime.scalar.apply(directive)?
            || runtime.dns.apply(directive)?
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

fn run(args: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
    let (action, mut runtime) = load(args)?;
    match action {
        Action::Version => {
            println!("dnsmasq-rs 0.1.0");
            println!("Compile time options: IPv6 GNU-getopt no-DBus UBus no-i18n no-IDN DHCP no-DHCPv6 no-Lua TFTP no-conntrack no-ipset no-nftset no-auth no-DNSSEC no-ID loop-detect inotify dumpfile");
            println!("Mode: development DNS daemon");
            println!("Implemented: DNS UDP/TCP, cache subsets, DHCPv4 listener boundary and TFTP transfer listener");
            println!("Not implemented: full DNS cache/reload policy and DHCP relay/PXE/leasequery");
            return Ok(());
        }
        Action::Help | Action::HelpDhcp => {
            println!("dnsmasq-rs: use -C FILE and -k to run the implemented DNS service");
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
            runtime.dns.finalize()?;
            runtime.dhcp.validate_dns_config(&runtime.dns)?;
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
    runtime.dns.finalize()?;
    runtime.dhcp.validate_dns_config(&runtime.dns)?;
    runtime.tftp.validate_ready()?;
    runtime.dhcp.validate_ready()?;
    validate_runtime_ready(&runtime.scalar, &runtime.dns)?;
    let dns_enabled = runtime.scalar.dns_port != 0;
    let hosts = if dns_enabled {
        read_hosts(&runtime.dns, runtime.scalar.local_ttl)
    } else {
        Hosts::new()
    };
    let resolvers = if dns_enabled {
        read_resolvers(&runtime.dns)?
    } else {
        Vec::new()
    };
    if dns_enabled && !runtime.dns.no_resolv && resolvers.is_empty() {
        return Err(Box::new(Error("no nameserver in resolver files")));
    }
    let interface_snapshot = Arc::new(Mutex::new(
        listeners::snapshot().map_err(NetworkStartupError)?,
    ));
    let addresses = listeners::bound_addresses(
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
            runtime.dns,
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
    let mut dhcp_provider = None;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let dhcp_helper = if let Some(script) = dhcp_config.script.clone() {
        Some(Helper::start_with_init(
            HelperConfig {
                script: PathBuf::from(OsString::from_vec(script)),
                script_user: dhcp_config.script_user.clone(),
                debug: runtime.process.debug,
            },
            dhcp_config.lease_read_only && !dhcp_config.ranges.is_empty(),
        )?)
    } else {
        None
    };
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    if !dhcp_config.ranges.is_empty() {
        return Err(Box::new(Error("DHCP listener requires 64-bit Linux")));
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    if tftp_config.enabled && !tftp_config.no_fail {
        return Err(Box::new(Error("TFTP listener requires 64-bit Linux")));
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let dhcp_runtime = if !dhcp_config.ranges.is_empty() {
        let mut provider = DhcpProvider::new(
            dhcp_config,
            daemon_config.listen_addresses.clone(),
            runtime.scalar.dns_port,
            || STOP_REQUESTED.load(Ordering::Acquire),
        )?;
        provider.set_dns_config(&daemon_config)?;
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
        dhcp_provider = Some(Arc::clone(&shared_provider));
        // dhcp_init binds INADDR_ANY even with listen-address: initial
        // clients send broadcasts, and interface admission happens later.
        let listener = DhcpSocketListener::bind(
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 67)),
            DhcpListener::Dhcp,
            &[],
        )
        .map_err(NetworkStartupError)?;
        Some((shared_provider, listener))
    } else {
        None
    };
    // C opens/restores the lease file and binds DHCP before its DNS sockets.
    // Open all UDP/TCP listeners before starting workers. A setup error drops
    // every socket without leaving an already-running partial service.
    let mut listeners = Vec::new();
    for address in addresses {
        match open_dns_listener(address) {
            Ok((udp, tcp)) => listeners.push((address, udp, tcp)),
            Err(error) if daemon_config.bind_dynamic => {
                eprintln!("dnsmasq-rs: cannot bind {address}: {error}")
            }
            Err(error) => return Err(Box::new(NetworkStartupError(error))),
        }
    }
    listeners::validate_bind_interfaces(&daemon_config, &interface_snapshot.lock().unwrap())
        .map_err(NetworkStartupError)?;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let tftp_listener = if tftp_config.enabled {
        let bind_ip = daemon_config
            .listen_addresses
            .iter()
            .copied()
            .find(IpAddr::is_ipv4)
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let runtime_config = RuntimeConfig {
            path: RuntimePathPolicy {
                prefix: tftp_config.root.clone(),
                lowercase: tftp_config.lowercase,
            },
            packet_buffer_size: 8192,
            mtu: tftp_config.mtu,
            ipv6: false,
            no_block_size: tftp_config.no_block_size,
            effective_uid: identity.runtime_uid(&runtime.process),
            secure: tftp_config.secure,
            max_transfers: tftp_config.max_transfers,
            single_port: tftp_config.single_port,
        };
        let runtime = TransferRuntime::new(
            runtime_config.clone(),
            RealFileOpener::new(runtime_config.effective_uid, runtime_config.secure),
        );
        match TftpListener::bind_with_port_range(
            SocketAddr::new(bind_ip, 69),
            runtime,
            tftp_config.port_range,
        ) {
            Ok(listener) => Some(listener),
            Err(error) if tftp_config.no_fail => {
                eprintln!("dnsmasq-rs: TFTP disabled: {error}");
                None
            }
            Err(error) => return Err(Box::new(NetworkStartupError(error))),
        }
    } else {
        None
    };
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some((provider, _)) = &dhcp_runtime {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_secs() as i64);
        let mut provider = provider
            .lock()
            .map_err(|_| io::Error::other("DHCP state lock poisoned"))?;
        report_dhcp_maintenance(&provider.initialize(now));
    }
    #[cfg(target_os = "linux")]
    let capabilities = dnsmasq_rs::startup::network_capabilities(
        !runtime.dhcp.ranges.is_empty(),
        runtime.dhcp.no_ping,
        runtime
            .dhcp
            .force_broadcast
            .first()
            .is_some_and(|rule| rule.is_unconditional()),
        daemon_config.bind_dynamic && runtime.scalar.dns_port <= 1024 && dns_enabled,
        runtime.ubus.object_name()?.is_some(),
    );
    // Fail missing capabilities before touching a pre-existing PID file.
    #[cfg(target_os = "linux")]
    identity.check_capabilities(capabilities)?;
    #[cfg(target_os = "linux")]
    let pid_file = identity.write_pid(&runtime.process)?;
    #[cfg(target_os = "linux")]
    identity.drop_privileges(&runtime.process, capabilities)?;
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
    // `-k` is the normal OpenWrt invocation. Stop handlers let workers leave
    // their bounded receive loops and release sockets before exit.
    let mut last_interfaces = Instant::now();
    while !STOP_REQUESTED.load(Ordering::Acquire) {
        poll.step();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(error) = poll.helper_init_error.take() {
            pid_file.cleanup();
            return Err(Box::new(error));
        }
        if last_interfaces.elapsed() >= Duration::from_millis(100) {
            last_interfaces = Instant::now();
            if let Ok(interfaces) = listeners::snapshot() {
                *interface_snapshot.lock().unwrap() = interfaces.clone();
                if daemon_config.bind_dynamic {
                    let addresses = listeners::bound_addresses(
                        &daemon_config,
                        runtime.scalar.dns_port,
                        &interfaces,
                    );
                    bound_listeners.retain(|(address, token)| {
                        if addresses.contains(address) {
                            return true;
                        }
                        poll.remove_listener(*token);
                        false
                    });
                    for address in addresses {
                        if bound_listeners.iter().any(|(bound, _)| *bound == address) {
                            continue;
                        }
                        // An address may still be tentative or not present. Dynamic
                        // mode keeps the remaining service alive and retries later.
                        if let Ok((udp, tcp)) = open_dns_listener(address) {
                            let token = SocketToken(next_listener);
                            next_listener += 1;
                            poll.add_listener(token, udp, tcp);
                            bound_listeners.push((address, token));
                        }
                    }
                }
            }
        }
        if RELOAD_REQUESTED.swap(false, Ordering::AcqRel) {
            let _event = parent_events
                .lock()
                .map_err(|_| io::Error::other("parent event lock poisoned"))?;
            // C SIGHUP rereads data files, not the main configuration. A
            // missing hosts source is logged and its old names disappear.
            if dns_enabled {
                let hosts = read_hosts(&daemon_config, runtime.scalar.local_ttl);
                if let Ok(mut parent) = service.lock() {
                    parent
                        .daemon
                        .as_mut()
                        .expect("DNS enabled")
                        .reload_hosts(hosts.clone());
                    parent.local.hosts = hosts;
                    let ParentDns { local, daemon } = &mut *parent;
                    local.leases =
                        Arc::new(daemon.as_mut().expect("DNS enabled").rebuild_lease_names(
                            &local.leases,
                            &mut local.hosts,
                            &local.config.records.cnames,
                        ));
                }
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(provider) = &dhcp_provider {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |time| time.as_secs() as i64);
                let mut provider = provider
                    .lock()
                    .map_err(|_| io::Error::other("DHCP state lock poisoned"))?;
                report_dhcp_maintenance(&provider.reload_host_files(now));
            }
        }
        {
            let mut event = parent_events
                .lock()
                .map_err(|_| io::Error::other("parent event lock poisoned"))?;
            let metrics = poll.metrics(&event);
            event.process_ubus(&metrics);
        }
        thread::park_timeout(Duration::from_millis(2));
    }
    #[cfg(target_os = "linux")]
    pid_file.cleanup();
    Ok(())
}

fn open_dns_listener(address: SocketAddr) -> io::Result<(Arc<DnsSocket>, TcpListener)> {
    let udp = Arc::new(DnsSocket::bind(address)?);
    let tcp = listeners::tcp_bind(address)?;
    // The single poll owner must never block in accept/read.  The legacy
    // worker path also handles WouldBlock, so this is safe for both modes.
    tcp.set_nonblocking(true)?;
    Ok((udp, tcp))
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
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    dhcp: Option<(Arc<Mutex<DhcpProvider>>, DhcpSocketListener)>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    helper: Option<Helper>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    helper_init: Option<Vec<u8>>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    helper_init_error: Option<dnsmasq_rs::helper::StartError>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pending_delivery: Option<LeaseDelivery>,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    tftp: Option<TftpListener<RealFileOpener>>,
}

struct PollListener {
    token: SocketToken,
    udp: Arc<DnsSocket>,
    tcp: TcpListener,
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
        if insert_cache {
            let mut parent = parent.lock().map_err(|_| ())?;
            if let Some(daemon) = parent.daemon.as_mut() {
                daemon.cache_tcp_reply(&packet, now_seconds());
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
        listeners: Vec<(SocketToken, Arc<DnsSocket>, TcpListener)>,
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))] dhcp: Option<(
            Arc<Mutex<DhcpProvider>>,
            DhcpSocketListener,
        )>,
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))] helper: Option<Helper>,
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))] tftp: Option<
            TftpListener<RealFileOpener>,
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
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            dhcp,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            helper_init: helper
                .as_ref()
                .is_some_and(Helper::initializes_leases)
                .then(Vec::new),
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            helper_init_error: None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            helper,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            pending_delivery: None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            tftp,
        }
    }

    fn add_listener(&mut self, token: SocketToken, udp: Arc<DnsSocket>, tcp: TcpListener) {
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
        if let Some((provider, _)) = &self.dhcp {
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
        self.step_tcp_clients();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.step_dhcp();
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.step_tftp();
    }

    fn step_udp(&mut self, index: usize) {
        let udp = Arc::clone(&self.listeners[index].udp);
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
                Some((incoming.destination, incoming.interface)),
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
            if let Some(target) = self.listeners.iter().find(|target| target.token == token) {
                let _ = target.udp.send(
                    &response.packet,
                    response.destination,
                    Some((response.source, response.interface)),
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
            {
                let _ = target.udp.send(
                    &response.packet,
                    response.destination,
                    Some((response.source, response.interface)),
                );
            }
        }
    }

    fn step_tcp_accept(&mut self, index: usize) {
        if self.clients.len() >= self.tcp_limit {
            return;
        }
        let listener = &self.listeners[index];
        let Ok((stream, peer)) = listener.tcp.accept() else {
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
            let _ = stream.shutdown(std::net::Shutdown::Both);
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
        drop(parent);
        let Ok(forward) = TcpDnsService::new(&self.config, &self.resolvers, self.edns_max) else {
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
        let full_deadline = Instant::now() + timeout;
        let mut deadline = full_deadline;
        let mut fds = vec![PollFd {
            fd: icmp.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        }];
        for listener in &self.listeners {
            fds.push(PollFd {
                fd: listener.udp.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            });
            if self.clients.len() < self.tcp_limit {
                fds.push(PollFd {
                    fd: listener.tcp.as_raw_fd(),
                    events: POLLIN,
                    revents: 0,
                });
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
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        let ready = owrt_ubus::sys::poll_fds(&mut fds, millis)?;
        // Neither signals/reload nor another DHCP packet may reenter the
        // borrowed state. All DNS and TFTP packet buffers are distinct.
        for index in 0..self.listeners.len() {
            self.step_udp(index);
            self.step_tcp_accept(index);
        }
        self.step_tcp_clients();
        self.step_tftp();
        // Early DNS/TCP timers or any listener activity must not consume an
        // ICMP quarter-second timeout. Only the full idle poll counts as one.
        Ok(ready != 0 || deadline < full_deadline)
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_dhcp(&mut self) {
        if let Some(helper) = self.helper.as_mut() {
            if let Some(delivery) = self.pending_delivery.as_ref() {
                match helper.enqueue_delivery(delivery) {
                    Ok(true) => self.pending_delivery = None,
                    Ok(false) => {}
                    Err(error) => eprintln!("dnsmasq-rs: DHCP helper enqueue: {error}"),
                }
            }
            match helper.step() {
                Ok(notices) => {
                    for notice in notices {
                        use dnsmasq_rs::helper::{Notice, StartError};
                        match notice {
                            Notice::InitData(bytes) => {
                                if let Some(output) = self.helper_init.as_mut() {
                                    output.extend(bytes);
                                }
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
                                    } else if let Some((provider, _)) = self.dhcp.as_ref() {
                                        match provider
                                            .lock()
                                            .unwrap()
                                            .restore_script_init(&output, now_seconds())
                                        {
                                            Ok(report) => report_dhcp_maintenance(&report),
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
                            Notice::Ready => {}
                            notice => eprintln!("dnsmasq-rs: DHCP helper: {notice:?}"),
                        }
                    }
                }
                Err(error) => eprintln!("dnsmasq-rs: DHCP helper step: {error}"),
            }
        }
        if self.helper_init.is_some() || self.helper_init_error.is_some() {
            return;
        }
        let Some((shared_provider, mut listener)) = self.dhcp.take() else {
            return;
        };
        let provider_ref = Arc::clone(&shared_provider);
        let Ok(mut provider) = provider_ref.lock() else {
            self.dhcp = Some((shared_provider, listener));
            return;
        };
        let now = now_seconds();
        if let Some(report) = provider.tick(now) {
            report_dhcp_maintenance(&report);
        }
        let mut metrics = Metrics::default();
        write_dhcp_metrics(&mut metrics, &provider);
        self.probe_metrics = Some(metrics);
        let mut output = vec![0; 16_384];
        let events = Arc::clone(&self.parent_events);
        let result = {
            let mut sink = |kind, fields: DhcpEventFields<'_>, logging| {
                events.lock().unwrap().notify_dhcp(kind, fields, logging)
            };
            let mut wait = |socket: &dnsmasq_rs::net::IcmpSocket, duration, leases| {
                self.wait_during_probe(socket, duration, leases)
            };
            let mut provider = provider.with_event_sink_and_wait(&mut sink, &mut wait);
            listener.process_once_local(&mut provider, &[], &mut output, || {
                STOP_REQUESTED.load(Ordering::Acquire)
            })
        };
        if self.pending_delivery.is_none() {
            self.pending_delivery = provider.take_script_delivery();
        }
        self.probe_metrics = None;
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
        if let Some(error) = provider.take_probe_error() {
            eprintln!("dnsmasq-rs: DHCP conflict probe: {error}");
        }
        if let Some(report) = provider.take_maintenance_report() {
            report_dhcp_maintenance(&report);
        }
        drop(provider);
        self.dhcp = Some((shared_provider, listener));
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn step_tftp(&mut self) {
        let Some(listener) = self.tftp.as_mut() else {
            return;
        };
        let _ = listener.poll_once(now_seconds() as u64);
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn report_dhcp_maintenance(report: &dnsmasq_rs::dhcp::daemon::MaintenanceReport) {
    if let Some(error) = &report.address_error {
        eprintln!("dnsmasq-rs: failed to update DHCP host addresses: {error}");
    }
    for error in &report.host_files {
        eprintln!("dnsmasq-rs: DHCP hosts file: {error:?}");
    }
    if let Some(error) = &report.name_error {
        eprintln!("dnsmasq-rs: failed to update lease names from static hosts: {error}");
    }
    if let Some(error) = &report.file.error {
        eprintln!("dnsmasq-rs: failed to update lease file: {error}");
    }
    if let Some(error) = &report.dns.error {
        eprintln!("dnsmasq-rs: failed to publish lease names: {error}");
    }
    if let Some(restore) = &report.restore {
        if restore.invalid_records != 0 || !restore.clean_end {
            eprintln!(
                "dnsmasq-rs: lease file restore: {} invalid records, clean end: {}",
                restore.invalid_records, restore.clean_end
            );
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
    if dns.servers_file.is_some() {
        return Err(Error("servers-file loading is not implemented"));
    }
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
    if dns.no_poll {
        return Err(Error("configured DNS policy is not implemented"));
    }
    if dns.records.needs_hostname() {
        return Err(Error(
            "hostname-dependent local records are not implemented",
        ));
    }
    let defaults = ScalarConfig::default();
    if scalar.query_port != defaults.query_port
        || scalar.query_port_os_assigned != defaults.query_port_os_assigned
        || scalar.min_port != defaults.min_port
        || scalar.max_port != defaults.max_port
        || scalar.port_limit != defaults.port_limit
        || scalar.max_ttl != defaults.max_ttl
    {
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
            Some((Arc::new(Mutex::new(provider)), listener)),
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
