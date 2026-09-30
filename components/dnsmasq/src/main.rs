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
use dnsmasq_rs::config::{Error, ScalarConfig, StaleCache};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::dhcp::daemon::LocalProvider as DhcpProvider;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::dhcp::service::{
    Listener as DhcpListener, ListenerStep, SocketListener as DhcpSocketListener,
};
use dnsmasq_rs::dns::cache::StalePolicy;
use dnsmasq_rs::dns::daemon::{ClientRequest, DaemonOptions, DnsDaemon, QueryResult};
use dnsmasq_rs::dns::service::{encode_tcp_frame, LocalDnsService, TcpFramer};
use dnsmasq_rs::dns::tcp_service::TcpDnsService;
use dnsmasq_rs::hosts::Hosts;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::tftp_listener::TftpListener;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use dnsmasq_rs::tftp_runtime::{RealFileOpener, RuntimeConfig, RuntimePathPolicy, TransferRuntime};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
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
        std::process::exit(1);
    }
}

struct Runtime {
    scalar: ScalarConfig,
    dns: DnsConfig,
    tftp: TftpConfig,
    dhcp: DhcpConfig,
}

fn load(args: &[OsString]) -> Result<(Action, Runtime), loader::LoadError> {
    let mut runtime = Runtime {
        scalar: ScalarConfig::default(),
        dns: DnsConfig::default(),
        tftp: TftpConfig::default(),
        dhcp: DhcpConfig::default(),
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
            println!("Not implemented: full DNS cache/fallback policy, DHCP relay/PXE/leasequery, UBus, full reload and metrics");
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
    if runtime.scalar.dns_port == 0 {
        return Err(Box::new(Error("port=0 is not supported by the listener")));
    }
    let hosts = read_hosts(&runtime.dns, runtime.scalar.local_ttl);
    let resolvers = read_resolvers(&runtime.dns)?;
    if !runtime.dns.no_resolv && resolvers.is_empty() {
        return Err(Box::new(Error("no nameserver in resolver files")));
    }
    let addresses = bind_addresses(&runtime.dns, runtime.scalar.dns_port);
    let tftp_config = runtime.tftp.clone();
    let dhcp_config = runtime.dhcp.clone();
    owrt_ubus::sys::set_signal_handler(owrt_ubus::sys::SIGINT, request_stop);
    owrt_ubus::sys::set_signal_handler(owrt_ubus::sys::SIGTERM, request_stop);
    owrt_ubus::sys::set_signal_handler(SIGHUP, request_reload);
    // dnsmasq.c allocates `edns_pktsz + MAXDNAME + RRFIXEDSZ` for incoming
    // packets and rejects larger UDP/TCP requests before parsing them.
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
        upstream_timeout: Duration::from_secs(10),
    };
    let service = Arc::new(Mutex::new(LocalDnsService::new(
        runtime.dns,
        hosts,
        runtime.scalar.local_ttl,
        usize::from(runtime.scalar.edns_packet_max),
    )));
    let tcp_active = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    let mut reload_senders = Vec::new();
    for address in addresses {
        let udp = UdpSocket::bind(address)?;
        udp.set_read_timeout(Some(Duration::from_millis(50)))?;
        let tcp = TcpListener::bind(address)?;
        tcp.set_nonblocking(true)?;
        let udp_config = daemon_config.clone();
        let udp_hosts = daemon_hosts.clone();
        let udp_resolvers = resolvers.clone();
        let udp_options = daemon_options;
        let mut daemon = DnsDaemon::new(udp_config, udp_hosts, &udp_resolvers, udp_options)?;
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
        // Coalesce repeated signals while a worker is busy: the token refers
        // to the latest hosts snapshot, so reload cannot grow a work queue.
        let (reload_sender, reload_receiver) = mpsc::sync_channel(1);
        let reload_service = Arc::clone(&service);
        reload_senders.push(reload_sender);
        workers.push(
            thread::Builder::new()
                .name(format!("dns-udp-{address}"))
                .spawn(move || {
                    let mut daemon = daemon;
                    let mut query = vec![0; 65_535];
                    while !STOP_REQUESTED.load(Ordering::Acquire) {
                        // Only this worker mutates its cache and local hosts.
                        // Keep upstream transactions alive across SIGHUP as C
                        // clear_cache_and_reload does.
                        if reload_receiver.try_recv().is_ok() {
                            if let Ok(local) = reload_service.lock() {
                                daemon.reload_hosts(local.hosts.clone());
                            }
                        }
                        match udp.recv_from(&mut query) {
                            Ok((length, peer)) if length <= packet_limit => {
                                let request = ClientRequest {
                                    source: peer,
                                    destination: address.ip(),
                                    interface: 0,
                                };
                                if let Ok(
                                    QueryResult::Local(answer) | QueryResult::Cached(answer),
                                ) = daemon.handle_udp(&query[..length], request)
                                {
                                    let _ = udp.send_to(&answer, peer);
                                }
                            }
                            Ok(_) => {}
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock
                                        | io::ErrorKind::TimedOut
                                        | io::ErrorKind::Interrupted
                                ) => {}
                            Err(_) => break,
                        }
                        if let Ok(responses) = daemon.poll(Duration::ZERO) {
                            for response in responses {
                                let _ = udp.send_to(&response.packet, response.destination);
                            }
                        }
                    }
                })?,
        );
        let tcp_service = Arc::clone(&service);
        let tcp_resolvers = resolvers.clone();
        let tcp_edns_max = daemon_options.edns_packet_max;
        let tcp_active_for_listener = Arc::clone(&tcp_active);
        workers.push(
            thread::Builder::new()
                .name(format!("dns-tcp-{address}"))
                .spawn(move || {
                    let mut clients: Vec<thread::JoinHandle<()>> = Vec::new();
                    while !STOP_REQUESTED.load(Ordering::Acquire) {
                        // Reap completed connections during normal operation.
                        // Keeping every historical handle until SIGTERM would
                        // grow memory even with bounded active connections.
                        let mut index = 0;
                        while index < clients.len() {
                            if clients[index].is_finished() {
                                let _ = clients.swap_remove(index).join();
                            } else {
                                index += 1;
                            }
                        }
                        let (stream, _) = match tcp.accept() {
                            Ok(connection) => connection,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(20));
                                continue;
                            }
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => break,
                        };
                        // dnsmasq.c clears inherited O_NONBLOCK after accept.
                        // Darwin inherits it; Linux does not.
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        if !try_acquire_tcp(&tcp_active_for_listener, tcp_limit) {
                            continue;
                        }
                        let permit = TcpPermit(Arc::clone(&tcp_active_for_listener));
                        // C forks one cache/hosts snapshot per accepted TCP
                        // session. Keep that lifetime here without holding a
                        // shared lock during client or upstream socket I/O.
                        let mut service = match tcp_service.lock() {
                            Ok(local) => LocalDnsService::new(
                                local.config.clone(),
                                local.hosts.clone(),
                                local.local_ttl,
                                local.max_udp,
                            ),
                            Err(_) => continue,
                        };
                        let mut forward =
                            match TcpDnsService::new(&service.config, &tcp_resolvers, tcp_edns_max)
                            {
                                Ok(service) => service,
                                Err(_) => continue,
                            };
                        let client =
                            thread::Builder::new()
                                .name("dns-tcp-client".into())
                                .spawn(move || {
                                    let _permit = permit;
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
                                            let answer = match service.handle_tcp_payload(&query) {
                                                Ok(Some(answer)) => answer,
                                                Ok(None) | Err(_) => {
                                                    match forward.handle_with_local(
                                                        &query,
                                                        &service,
                                                        deadline,
                                                        &|| STOP_REQUESTED.load(Ordering::Acquire),
                                                    ) {
                                                        Ok(answer) => answer,
                                                        Err(_) => break 'connection,
                                                    }
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
                                            if queries == 100 {
                                                break 'connection;
                                            }
                                        }
                                    }
                                });
                        if let Ok(client) = client {
                            clients.push(client);
                        }
                    }
                    for client in clients {
                        let _ = client.join();
                    }
                })?,
        );
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if !dhcp_config.ranges.is_empty() {
        // dhcp_init binds INADDR_ANY even with listen-address: initial
        // clients send broadcasts, and interface admission happens later.
        let mut listener = DhcpSocketListener::bind(
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 67)),
            DhcpListener::Dhcp,
            &[],
        )?;
        let mut provider = DhcpProvider::new(
            dhcp_config,
            daemon_config.listen_addresses.clone(),
            runtime.scalar.dns_port,
            || STOP_REQUESTED.load(Ordering::Acquire),
        )?;
        workers.push(
            thread::Builder::new()
                .name("dhcp-listener".into())
                .spawn(move || {
                    let mut output = vec![0; 16_384];
                    while !STOP_REQUESTED.load(Ordering::Acquire) {
                        match listener.process_once_local(&mut provider, &[], &mut output, || {
                            STOP_REQUESTED.load(Ordering::Acquire)
                        }) {
                            Ok(ListenerStep::WouldBlock) | Ok(ListenerStep::Ignored) => {
                                thread::sleep(Duration::from_millis(2));
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
                    }
                })?,
        );
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    if !dhcp_config.ranges.is_empty() {
        return Err(Box::new(Error("DHCP listener requires 64-bit Linux")));
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    if tftp_config.enabled {
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
            Ok(mut listener) => {
                workers.push(thread::Builder::new().name("tftp-listener".into()).spawn(
                    move || {
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
                    },
                )?);
            }
            Err(error) if tftp_config.no_fail => {
                eprintln!("dnsmasq-rs: TFTP disabled: {error}");
            }
            Err(error) => return Err(Box::new(error)),
        }
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    if tftp_config.enabled && !tftp_config.no_fail {
        return Err(Box::new(Error("TFTP listener requires 64-bit Linux")));
    }
    // `-k` is the normal OpenWrt invocation. Stop handlers let workers leave
    // their bounded receive loops and release sockets before exit.
    while !STOP_REQUESTED.load(Ordering::Acquire) {
        if RELOAD_REQUESTED.swap(false, Ordering::AcqRel) {
            // C SIGHUP rereads data files, not the main configuration. A
            // missing hosts source is logged and its old names disappear.
            let hosts = read_hosts(&daemon_config, runtime.scalar.local_ttl);
            if let Ok(mut local) = service.lock() {
                local.hosts = hosts;
            }
            reload_senders.retain(|sender| {
                !matches!(
                    sender.try_send(()),
                    Err(mpsc::TrySendError::Disconnected(()))
                )
            });
        }
        thread::park_timeout(Duration::from_millis(100));
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

struct TcpPermit(Arc<AtomicUsize>);

impl Drop for TcpPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_tcp(active: &AtomicUsize, limit: usize) -> bool {
    let mut current = active.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return false;
        }
        match active.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
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
        || scalar.dhcp_ttl.is_some()
    {
        return Err(Error("scalar option is not implemented"));
    }
    Ok(())
}

fn read_hosts(config: &DnsConfig, local_ttl: u32) -> Hosts {
    let mut hosts = Hosts::new();
    hosts.set_round_robin(!config.no_round_robin);
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
