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
use dnsmasq_rs::dns::cache::{CacheImportCursor, StalePolicy};
use dnsmasq_rs::dns::daemon::{ClientRequest, DaemonOptions, DnsDaemon, QueryResult};
use dnsmasq_rs::dns::forward::SocketToken;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::dns::lease_names::{LeasePolicy, PublicationWarning};
use dnsmasq_rs::dns::service::{encode_tcp_frame, LocalDnsService, TcpFramer};
use dnsmasq_rs::dns::tcp_service::TcpDnsService;
use dnsmasq_rs::dns::tcp_transfer::{self, Received, Receiver};
use dnsmasq_rs::hosts::Hosts;
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
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, UdpSocket};

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);
// SIGHUP is 1 on the supported Linux and Darwin hosts.
const SIGHUP: i32 = 1;
const STOP_CHECK_INTERVAL: Duration = Duration::from_millis(100);

extern "C" fn request_stop(_signal: i32) {
    STOP_REQUESTED.store(true, Ordering::Release);
}

extern "C" fn request_reload(_signal: i32) {
    RELOAD_REQUESTED.store(true, Ordering::Release);
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
    if error.is::<NetworkStartupError>() {
        return 2;
    }
    if error.is::<ConnectError>() {
        return 5; // dnsmasq.c startup UBus registration failure: EC_MISC.
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(error) = error.downcast_ref::<dnsmasq_rs::dhcp::daemon::StartupError>() {
        return error.exit_code();
    }
    1
}

struct Runtime {
    scalar: ScalarConfig,
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
    tcp_slots: Vec<Option<TcpSlot>>,
    tcp_pending: Option<(usize, i64)>,
}

impl ParentEvents {
    fn new(config: &UbusConfig, tcp_limit: usize) -> Result<Self, Box<dyn std::error::Error>> {
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
            tcp_slots: (0..tcp_limit).map(|_| None).collect(),
            tcp_pending: None,
        })
    }

    fn tcp_work_ready(&self) -> bool {
        self.tcp_pending.is_some()
            || self
                .tcp_slots
                .iter()
                .flatten()
                .filter_map(|slot| slot.receiver.as_ref())
                .any(|pipe| pipe.ready().unwrap_or(true))
    }

    // A partial byte frame pins the complete parent event and its entry clock.
    // All other parent work/admission waits until this transaction ends. Waits
    // happen only after the containing caller has released every shared lock.
    fn drain_tcp(&mut self, parent: &mut ParentDns) -> bool {
        for index in 0..self.tcp_slots.len() {
            if self
                .tcp_pending
                .is_some_and(|(pending, _)| pending != index)
            {
                continue;
            }
            let Some(slot) = &mut self.tcp_slots[index] else {
                continue;
            };
            if slot.receiver.is_none() && slot.finished.load(Ordering::Acquire) {
                self.tcp_slots[index] = None;
                self.tcp_active -= 1;
                continue;
            }
            let Some(receiver) = &mut slot.receiver else {
                continue;
            };
            if self.tcp_pending.is_none() && !receiver.ready().unwrap_or(true) {
                continue;
            }
            let (_, now) = *self
                .tcp_pending
                .get_or_insert_with(|| (index, unix_seconds()));
            loop {
                match receiver.receive() {
                    Ok(Received::Begin) => {
                        slot.import = Some(
                            parent
                                .daemon
                                .as_mut()
                                .expect("DNS listener owns forwarder")
                                .start_tcp_cache_import(),
                        );
                    }
                    Ok(Received::Record(record)) => {
                        let ParentDns { local, daemon } = parent;
                        daemon
                            .as_mut()
                            .expect("DNS listener owns forwarder")
                            .import_tcp_cache_record(
                                record,
                                now,
                                local,
                                slot.import.as_mut().expect("record follows Begin"),
                            );
                    }
                    Ok(Received::End) => {
                        parent
                            .daemon
                            .as_mut()
                            .expect("DNS listener owns forwarder")
                            .finish_tcp_cache_import();
                        slot.import = None;
                        self.tcp_pending = None;
                        break;
                    }
                    Ok(Received::Pending) => break,
                    Ok(Received::Eof) | Err(_) => {
                        // C leaves complete prefix effects and pending records
                        // until the next Begin. Dropping the cursor is not abort.
                        slot.import = None;
                        slot.receiver = None;
                        self.tcp_pending = None;
                        break;
                    }
                }
            }
            if slot.receiver.is_none() && slot.finished.load(Ordering::Acquire) {
                self.tcp_slots[index] = None;
                self.tcp_active -= 1;
            }
            return true; // one lowest-index complete transaction per event
        }
        false
    }

    // Readiness is only a wake hint. Another owner can close/reuse these raw
    // descriptor numbers after unlock; POLLNVAL or stale readiness is harmless.
    // Every actual read rechecks the current owner under the event lock.
    // Duplicating descriptors here would change EMFILE admission behavior.
    fn wait_fds(&self) -> Vec<owrt_ubus::sys::PollFd> {
        let mut fds = Vec::new();
        let mut add = |fd| {
            fds.push(owrt_ubus::sys::PollFd {
                fd,
                events: owrt_ubus::sys::POLLIN,
                revents: 0,
            })
        };
        if self.tcp_pending.is_none() {
            if let Some(ubus) = &self.ubus {
                add(ubus.as_raw_fd());
            }
        }
        for (index, slot) in self.tcp_slots.iter().enumerate() {
            if self
                .tcp_pending
                .is_some_and(|(pending, _)| pending != index)
            {
                continue;
            }
            if let Some(receiver) = slot.as_ref().and_then(|slot| slot.receiver.as_ref()) {
                add(receiver.as_raw_fd());
            }
        }
        fds
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
        match self
            .ubus
            .as_mut()?
            .doctor_dns(result, Some(stopping), metrics)
        {
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

fn stopping() -> bool {
    STOP_REQUESTED.load(Ordering::Acquire)
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
    let leases = provider.lease_counters();
    metrics.set(Metric::LeasesAllocated4, leases.allocated4);
    metrics.set(Metric::LeasesPruned4, leases.pruned4);
    metrics.set(Metric::LeasesPruned6, leases.pruned6);
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
        dns: DnsConfig::default(),
        tftp: TftpConfig::default(),
        dhcp: DhcpConfig::default(),
        ubus: UbusConfig::default(),
    };
    let action = loader::load(args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        // `-k/--keep-in-foreground` is a process-mode switch consumed by the
        // runner, not a DNS or DHCP configuration directive.
        if matches!(
            directive.name.as_slice(),
            b"keep-in-foreground" | b"no-daemon"
        ) || runtime.scalar.apply(directive)?
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
            runtime.dns.finalize()?;
            return Ok(());
        }
        Action::Run => {}
    }
    runtime.scalar.finalize_runtime()?;
    runtime.dns.finalize()?;
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
    let addresses = bind_addresses(&runtime.dns, runtime.scalar.dns_port);
    let tftp_config = runtime.tftp.clone();
    let dhcp_config = runtime.dhcp.clone();
    owrt_ubus::sys::set_signal_handler(owrt_ubus::sys::SIGINT, request_stop);
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
    let parent_events = Arc::new(Mutex::new(ParentEvents::new(&runtime.ubus, tcp_limit)?));
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let mut dhcp_provider = None;
    let mut workers = Vec::new();
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
        let udp = UdpSocket::bind(address).map_err(NetworkStartupError)?;
        udp.set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(NetworkStartupError)?;
        let tcp = TcpListener::bind(address).map_err(NetworkStartupError)?;
        tcp.set_nonblocking(true).map_err(NetworkStartupError)?;
        listeners.push((address, Arc::new(udp), tcp));
    }
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
            effective_uid: 0,
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
    let udp_sockets: Arc<Vec<_>> = Arc::new(
        listeners
            .iter()
            .map(|(_, socket, _)| Arc::clone(socket))
            .collect(),
    );
    for (listener_index, (address, udp, tcp)) in listeners.into_iter().enumerate() {
        let response_sockets = Arc::clone(&udp_sockets);
        let listener = SocketToken(listener_index as u64);
        let parent_service = Arc::clone(&service);
        let udp_events = Arc::clone(&parent_events);
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        let udp_dhcp = dhcp_provider.clone();
        workers.push(
            thread::Builder::new()
                .name(format!("dns-udp-{address}"))
                .spawn(move || {
                    let mut query = vec![0; 65_535];
                    while !STOP_REQUESTED.load(Ordering::Acquire) {
                        // No shared lock while waiting for client input.
                        let incoming = match udp.recv_from(&mut query) {
                            Ok((length, peer)) if length <= packet_limit => Some((length, peer)),
                            Ok(_) => None,
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock
                                        | io::ErrorKind::TimedOut
                                        | io::ErrorKind::Interrupted
                                ) =>
                            {
                                None
                            }
                            Err(_) => break,
                        };
                        'parent_event: loop {
                            if stopping() {
                                break;
                            }
                            // HUP cannot split one admitted query's answer from
                            // its send/refresh. The receive wait stays outside.
                            let Ok(mut event) = udp_events.lock() else {
                                break;
                            };
                            let mut metrics = Metrics::default();
                            event.write_metrics(&mut metrics);
                            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                            if let Some(provider) = &udp_dhcp {
                                let Ok(provider) = provider.lock() else { break };
                                write_dhcp_metrics(&mut metrics, &provider);
                            }
                            let (answer, responses) = {
                                let Ok(mut parent) = parent_service.lock() else {
                                    break;
                                };
                                let daemon = parent
                                    .daemon
                                    .as_ref()
                                    .expect("DNS listener owns the forwarder");
                                write_dns_metrics(
                                    &mut metrics,
                                    daemon.cache_counters(),
                                    daemon.forward_counters(),
                                    event.local_answered,
                                );
                                if event.tcp_pending.is_none() {
                                    event.process_ubus(&metrics);
                                }
                                if event.drain_tcp(&mut parent) {
                                    drop(parent);
                                    drop(event);
                                    thread::sleep(Duration::from_millis(1));
                                    continue 'parent_event;
                                }
                                let ParentDns { local, daemon } = &mut *parent;
                                let daemon =
                                    daemon.as_mut().expect("DNS listener owns the forwarder");
                                let answer = incoming.and_then(|(length, peer)| {
                                    let packet = &query[..length];
                                    match dnsmasq_rs::dns::udp_query::inspect(
                                        packet,
                                        local.edns_packet_max,
                                    ) {
                                        dnsmasq_rs::dns::udp_query::Admission::Drop => return None,
                                        dnsmasq_rs::dns::udp_query::Admission::Reply(answer) => {
                                            return Some((peer, answer, false))
                                        }
                                        dnsmasq_rs::dns::udp_query::Admission::Continue => {}
                                    }
                                    let answer = match local.handle_udp(packet) {
                                        Ok(Some(answer)) => Some((answer, false)),
                                        Ok(None) => {
                                            match daemon.forward_udp_on_listener_with_local(
                                                packet,
                                                ClientRequest {
                                                    source: peer,
                                                    destination: address.ip(),
                                                    interface: 0,
                                                },
                                                Some(listener),
                                                local,
                                            ) {
                                                Ok(
                                                    QueryResult::Local(answer)
                                                    | QueryResult::Cached(answer),
                                                ) => Some((answer, false)),
                                                Ok(QueryResult::Stale(answer)) => {
                                                    Some((answer, true))
                                                }
                                                _ => None,
                                            }
                                        }
                                        Err(_) => None,
                                    };
                                    answer.map(|(answer, stale)| (peer, answer, stale))
                                });
                                // This poll is nonblocking. Keep local-name policy
                                // and cache updates in the same generation as lookup.
                                let responses = if event
                                    .ubus
                                    .as_ref()
                                    .is_some_and(UbusService::dns_has_subscribers)
                                {
                                    let mut doctor = |name: &[u8], ttl, address, cache, forward| {
                                        write_dns_metrics(
                                            &mut metrics,
                                            cache,
                                            forward,
                                            event.local_answered,
                                        );
                                        event.doctor(&DnsResult { name, ttl, address }, &metrics)
                                    };
                                    daemon.poll_with_local_doctor(
                                        Duration::ZERO,
                                        local,
                                        &mut doctor,
                                    )
                                } else {
                                    daemon.poll_with_local(Duration::ZERO, local)
                                };
                                (answer, responses.unwrap_or_default())
                            };
                            if let Some((peer, answer, stale)) = answer {
                                let _ = udp.send_to(&answer, peer);
                                // C increments after its send attempt, including
                                // a failed send; ordinary TCP answers do not count.
                                if stale {
                                    event.stale_answered = event.stale_answered.wrapping_add(1);
                                } else {
                                    event.local_answered = event.local_answered.wrapping_add(1);
                                }
                                if stale {
                                    // Preserve C's send-before-refresh order even
                                    // when the downstream send itself fails.
                                    let Ok(mut parent) = parent_service.lock() else {
                                        break;
                                    };
                                    let length = incoming.expect("stale reply has a query").0;
                                    let refresh = parent
                                        .daemon
                                        .as_mut()
                                        .expect("DNS listener owns the forwarder")
                                        .refresh_udp_on_listener(
                                            &query[..length],
                                            ClientRequest {
                                                source: peer,
                                                destination: address.ip(),
                                                interface: 0,
                                            },
                                            Some(listener),
                                        );
                                    if matches!(refresh, Ok(QueryResult::Local(_))) {
                                        // forward_query's fallback counts even
                                        // when fd=-1 suppresses a second reply.
                                        event.local_answered = event.local_answered.wrapping_add(1);
                                    }
                                }
                            }
                            for response in responses {
                                let Some(SocketToken(index)) = response.listener else {
                                    continue;
                                };
                                if let Some(socket) = usize::try_from(index)
                                    .ok()
                                    .and_then(|index| response_sockets.get(index))
                                {
                                    let _ = socket.send_to(&response.packet, response.destination);
                                }
                            }
                            break 'parent_event;
                        }
                    }
                })?,
        );
        let tcp_service = Arc::clone(&service);
        let tcp_events = Arc::clone(&parent_events);
        let tcp_resolvers = resolvers.clone();
        let tcp_edns_max = daemon_options.edns_packet_max;
        workers.push(
            thread::Builder::new()
                .name(format!("dns-tcp-{address}"))
                .spawn(move || {
                    let mut clients: Vec<(thread::JoinHandle<()>, Arc<AtomicBool>)> = Vec::new();
                    while !STOP_REQUESTED.load(Ordering::Acquire) {
                        // Reap completed connections during normal operation.
                        // Keeping every historical handle until SIGTERM would
                        // grow memory even with bounded active connections.
                        let mut index = 0;
                        while index < clients.len() {
                            if clients[index].0.is_finished() {
                                let (client, finished) = clients.swap_remove(index);
                                let _ = client.join();
                                finished.store(true, Ordering::Release);
                            } else {
                                index += 1;
                            }
                        }
                        let (stream, mut service, mut cache, mut sender, completion) = {
                            let Ok(mut event) = tcp_events.lock() else {
                                break;
                            };
                            // C leaves clients queued while all TCP slots are
                            // occupied. Serialize admission across listeners
                            // through the existing parent-event owner.
                            if stopping() {
                                break;
                            }
                            if event.tcp_work_ready() {
                                drop(event);
                                thread::sleep(Duration::from_millis(1));
                                continue;
                            }
                            let Some(slot) = event.tcp_slots.iter().rposition(Option::is_none)
                            else {
                                drop(event);
                                thread::sleep(Duration::from_millis(20));
                                continue;
                            };
                            let (stream, _) = match tcp.accept() {
                                Ok(connection) => connection,
                                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                                    continue
                                }
                                Err(_) => {
                                    // C retains the listener after accept
                                    // errors. Release the event gate before
                                    // waiting so other services can progress.
                                    drop(event);
                                    thread::sleep(Duration::from_millis(20));
                                    continue;
                                }
                            };
                            // dnsmasq.c clears inherited O_NONBLOCK after accept.
                            // Darwin inherits it; Linux does not.
                            if stream.set_nonblocking(false).is_err() {
                                continue;
                            }
                            // Snapshot at accept without holding a shared lock
                            // during subsequent client or upstream socket I/O.
                            match tcp_service.lock() {
                                Ok(parent) => {
                                    let mut snapshot = LocalDnsService::new_with_limits(
                                        parent.local.config.clone(),
                                        parent.local.hosts.clone(),
                                        parent.local.local_ttl,
                                        parent.local.max_udp,
                                        parent.local.edns_packet_max,
                                    );
                                    snapshot.leases = Arc::clone(&parent.local.leases);
                                    let accepted_at = unix_seconds();
                                    let cache = parent
                                        .daemon
                                        .as_ref()
                                        .expect("DNS listener owns forwarder")
                                        .snapshot_tcp_cache(accepted_at);
                                    let (receiver, sender) = match tcp_transfer::pipe() {
                                        Ok(pipe) => pipe,
                                        Err(_) => continue,
                                    };
                                    let finished = Arc::new(AtomicBool::new(false));
                                    event.tcp_slots[slot] = Some(TcpSlot {
                                        receiver: Some(receiver),
                                        import: None,
                                        finished: Arc::clone(&finished),
                                    });
                                    event.tcp_active += 1;
                                    (stream, snapshot, cache, sender, finished)
                                }
                                Err(_) => continue,
                            }
                        };
                        let mut forward =
                            match TcpDnsService::new(&service.config, &tcp_resolvers, tcp_edns_max)
                            {
                                Ok(service) => service,
                                Err(_) => {
                                    completion.store(true, Ordering::Release);
                                    continue;
                                }
                            };
                        let client =
                            thread::Builder::new()
                                .name("dns-tcp-client".into())
                                .spawn(move || {
                                    let mut stream = stream;
                                    let deadline = Instant::now() + Duration::from_secs(150);
                                    let mut framer = TcpFramer::with_max_frame(packet_limit);
                                    let mut input = [0u8; 4096];
                                    let mut queries = 0usize;
                                    'connection: while let Some(remaining) =
                                        deadline.checked_duration_since(Instant::now())
                                    {
                                        if remaining.is_zero()
                                            || STOP_REQUESTED.load(Ordering::Acquire)
                                        {
                                            break;
                                        }
                                        if stream
                                            .set_read_timeout(Some(
                                                remaining.min(STOP_CHECK_INTERVAL),
                                            ))
                                            .is_err()
                                        {
                                            break;
                                        }
                                        let count = match stream.read(&mut input) {
                                            Err(error) if retry_tcp_io(&error) => continue,
                                            Ok(0) | Err(_) => break,
                                            Ok(count) => count,
                                        };
                                        let mut offset = 0;
                                        while offset < count {
                                            let (consumed, query) =
                                                match framer.push_frame(&input[offset..count]) {
                                                    Ok(result) => result,
                                                    Err(_) => break 'connection,
                                                };
                                            offset += consumed;
                                            let Some(query) = query else { continue };
                                            // C ignores short headers and QR
                                            // packets before its query counter.
                                            if query.len() < 12 || query[2] & 0x80 != 0 {
                                                continue;
                                            }
                                            queries += 1;
                                            if queries > 100 {
                                                break 'connection;
                                            }
                                            if query.len() > packet_limit {
                                                break 'connection;
                                            }
                                            let local = service
                                                .handle_tcp_payload_at(&query, cache.accepted_at())
                                                .ok()
                                                .flatten();
                                            let cached = if local.is_none() {
                                                cache.answer(&query, &mut service).ok().flatten()
                                            } else {
                                                None
                                            };
                                            let (answer, stale) = if let Some(answer) = local {
                                                (answer, false)
                                            } else if let Some(answer) = cached {
                                                (answer.packet, answer.stale)
                                            } else {
                                                let mut pipe_failed = false;
                                                let mut send = |transaction| {
                                                    if sender
                                                        .send(transaction, deadline, stopping)
                                                        .is_err()
                                                    {
                                                        pipe_failed = true;
                                                    }
                                                };
                                                let answer = forward.handle_with_cache(
                                                    &query, &service, &mut cache, &mut send,
                                                    deadline, &stopping,
                                                );
                                                if pipe_failed {
                                                    break 'connection;
                                                }
                                                match answer {
                                                    Ok(answer) => (answer, false),
                                                    Err(_) => break 'connection,
                                                }
                                            };
                                            let Ok(frame) = encode_tcp_frame(&answer) else {
                                                break 'connection;
                                            };
                                            let Some(remaining) =
                                                deadline.checked_duration_since(Instant::now())
                                            else {
                                                break 'connection;
                                            };
                                            if remaining.is_zero()
                                                || write_frame_until(&mut stream, &frame, deadline)
                                                    .is_err()
                                            {
                                                break 'connection;
                                            }
                                            if stale {
                                                // forward.c::tcp_request closes the downstream
                                                // before its one refresh. The same worker, cache,
                                                // clock and writeback pipe stay alive until then.
                                                let _ = stream.shutdown(Shutdown::Both);
                                                drop(stream);
                                                let mut send = |transaction| {
                                                    let _ = sender.send(
                                                        transaction,
                                                        deadline,
                                                        stopping,
                                                    );
                                                };
                                                let _ = forward.handle_with_cache(
                                                    &query, &service, &mut cache, &mut send,
                                                    deadline, &stopping,
                                                );
                                                break 'connection;
                                            }
                                            if queries == 100 {
                                                break 'connection;
                                            }
                                        }
                                    }
                                });
                        if let Ok(client) = client {
                            clients.push((client, completion));
                        } else {
                            completion.store(true, Ordering::Release);
                        }
                    }
                    for (client, finished) in clients {
                        let _ = client.join();
                        finished.store(true, Ordering::Release);
                    }
                })?,
        );
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some((shared_provider, mut listener)) = dhcp_runtime {
        let dhcp_events = Arc::clone(&parent_events);
        let dhcp_dns = Arc::clone(&service);
        workers.push(
            thread::Builder::new()
                .name("dhcp-listener".into())
                .spawn(move || {
                    let mut output = vec![0; 16_384];
                    while !STOP_REQUESTED.load(Ordering::Acquire) {
                        let Ok(mut event) = dhcp_events.lock() else { break };
                        let Ok(mut provider) = shared_provider.lock() else { break };
                        let mut metrics = Metrics::default();
                        event.write_metrics(&mut metrics);
                        write_dhcp_metrics(&mut metrics, &provider);
                        {
                            let Ok(parent) = dhcp_dns.lock() else { break };
                            if let Some(daemon) = &parent.daemon {
                                write_dns_metrics(&mut metrics, daemon.cache_counters(), daemon.forward_counters(), event.local_answered);
                            }
                        }
                        if event.tcp_pending.is_none() { event.process_ubus(&metrics); }
                        { let Ok(mut parent) = dhcp_dns.lock() else { break };
                          if event.drain_tcp(&mut parent) { drop(parent); drop(provider); drop(event); thread::sleep(Duration::from_millis(1)); continue; } }
                        let now = SystemTime::now().duration_since(UNIX_EPOCH)
                            .map_or(0, |time| time.as_secs() as i64);
                        if let Some(report) = provider.tick(now) {
                            report_dhcp_maintenance(&report);
                        }
                        let mut idle = false;
                        let result = {
                            let mut sink = |kind, fields: DhcpEventFields<'_>, logging| event.notify_dhcp(kind, fields, logging);
                            let mut provider = provider.with_event_sink(&mut sink);
                            listener.process_once_local(&mut provider, &[], &mut output, stopping)
                        };
                        match result {
                            Ok(ListenerStep::WouldBlock) | Ok(ListenerStep::Ignored) => {
                                idle = true;
                            }
                            Ok(ListenerStep::Stopped) => break,
                            Ok(ListenerStep::Malformed(_)) => {}
                            Ok(ListenerStep::Processed(result)) => {
                                let events = match &result {
                                    Ok(report) => &report.events,
                                    Err(failure) => &failure.events,
                                };
                                for event in events {
                                    if let dnsmasq_rs::dhcp::runtime::RuntimeEvent::ArpInjectionFailed { kind, raw_os_error } = event {
                                        eprintln!("dnsmasq-rs: DHCP ARP injection: {kind:?} ({raw_os_error:?})");
                                    }
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => break,
                        }
                        if let Some(error) = provider.take_probe_error() {
                            eprintln!("dnsmasq-rs: DHCP conflict probe: {error}");
                        }
                        if let Some(report) = provider.take_maintenance_report() {
                            report_dhcp_maintenance(&report);
                        }
                        drop(provider);
                        drop(event);
                        if idle { thread::sleep(Duration::from_millis(2)); }
                    }
                })?,
        );
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if let Some(mut listener) = tftp_listener {
        workers.push(
            thread::Builder::new()
                .name("tftp-listener".into())
                .spawn(move || {
                    while !STOP_REQUESTED.load(Ordering::Acquire) {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_or(0, |duration| duration.as_secs());
                        match listener.poll_once(now) {
                            Ok(_) => thread::sleep(Duration::from_millis(1)),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                                ) =>
                            {
                                thread::sleep(Duration::from_millis(2))
                            }
                            Err(_) => break,
                        }
                    }
                })?,
        );
    }
    // `-k` is the normal OpenWrt invocation. Stop handlers let workers leave
    // their bounded receive loops and release sockets before exit.
    while !STOP_REQUESTED.load(Ordering::Acquire) {
        if RELOAD_REQUESTED.load(Ordering::Acquire) {
            let event = parent_events
                .lock()
                .map_err(|_| io::Error::other("parent event lock poisoned"))?;
            if event.tcp_pending.is_none() && RELOAD_REQUESTED.swap(false, Ordering::AcqRel) {
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
        }
        {
            // Metrics still work with port=0 and no incoming DHCP packets.
            // No provider lock is acquired after the DNS parent lock.
            let mut event = parent_events
                .lock()
                .map_err(|_| io::Error::other("parent event lock poisoned"))?;
            let mut metrics = Metrics::default();
            event.write_metrics(&mut metrics);
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            if let Some(provider) = &dhcp_provider {
                let provider = provider
                    .lock()
                    .map_err(|_| io::Error::other("DHCP state lock poisoned"))?;
                write_dhcp_metrics(&mut metrics, &provider);
            }
            let mut parent = service
                .lock()
                .map_err(|_| io::Error::other("DNS state lock poisoned"))?;
            if let Some(daemon) = &parent.daemon {
                write_dns_metrics(
                    &mut metrics,
                    daemon.cache_counters(),
                    daemon.forward_counters(),
                    event.local_answered,
                );
            }
            if event.tcp_pending.is_none() {
                event.process_ubus(&metrics);
            }
            event.drain_tcp(&mut parent);
        }
        let mut fds = parent_events
            .lock()
            .map_err(|_| io::Error::other("parent event lock poisoned"))?
            .wait_fds();
        let _ = owrt_ubus::sys::poll_fds(&mut fds, 100);
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

struct TcpSlot {
    receiver: Option<Receiver>,
    import: Option<CacheImportCursor>,
    finished: Arc<AtomicBool>,
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs() as i64)
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

fn write_frame_until(
    stream: &mut std::net::TcpStream,
    frame: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < frame.len() {
        if STOP_REQUESTED.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "DNS shutdown"));
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS TCP deadline"));
        };
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS TCP deadline"));
        }
        stream.set_write_timeout(Some(remaining.min(STOP_CHECK_INTERVAL)))?;
        let written = match stream.write(&frame[offset..]) {
            Err(error) if retry_tcp_io(&error) => continue,
            result => result?,
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "DNS TCP connection closed",
            ));
        }
        offset += written;
    }
    Ok(())
}

fn retry_tcp_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
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
    if !dns.interfaces.is_empty()
        || !dns.excluded_interfaces.is_empty()
        || dns.bind_interfaces
        || dns.bind_dynamic
        || dns.local_service_net
        || dns.local_service_host
    {
        return Err(Error("interface binding is not implemented"));
    }
    if dns.domain_needed || dns.bogus_priv || dns.no_poll || dns.localise_queries {
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
    for (index, path) in config.addn_hosts.iter().enumerate() {
        let Some(path) = path else { continue };
        read(path, (index + 1) as u32);
    }
    hosts
}

fn bind_addresses(config: &DnsConfig, port: u16) -> Vec<SocketAddr> {
    if port == 0 {
        return Vec::new();
    }
    if config.listen_addresses.is_empty() {
        // OpenWrt's Linux IPv6 wildcard is dual-stack unless the administrator
        // explicitly requests v6-only. One listener therefore covers both
        // families and avoids the EADDRINUSE race from binding two wildcards.
        vec![SocketAddr::new("::".parse().unwrap(), port)]
    } else {
        config
            .listen_addresses
            .iter()
            .copied()
            .map(|address| SocketAddr::new(address, port))
            .collect()
    }
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
