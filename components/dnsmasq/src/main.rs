//! Small foreground runner for the implemented DNS UDP/TCP and upstream path.
//!
//! The library remains the compatibility boundary.  This binary intentionally
//! rejects directives whose owning engine is not present yet; silently ignoring
//! a DHCP or TFTP option would make a package appear deployable while
//! dropping configured behavior.

use dnsmasq_rs::config::dns::DnsConfig;
use dnsmasq_rs::config::loader::{self, Action};
use dnsmasq_rs::config::{Error, ScalarConfig};
use dnsmasq_rs::dns::daemon::{ClientRequest, DaemonOptions, DnsDaemon, QueryResult};
use dnsmasq_rs::dns::service::{encode_tcp_frame, LocalDnsService, TcpFramer};
use dnsmasq_rs::hosts::Hosts;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
}

fn load(args: &[OsString]) -> Result<(Action, Runtime), loader::LoadError> {
    let mut runtime = Runtime {
        scalar: ScalarConfig::default(),
        dns: DnsConfig::default(),
    };
    let action = loader::load(args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        // `-k/--keep-in-foreground` is a process-mode switch consumed by the
        // runner, not a DNS or DHCP configuration directive.
        if directive.name.as_slice() == b"keep-in-foreground"
            || runtime.scalar.apply(directive)?
            || runtime.dns.apply(directive)?
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
            println!("Implemented: local and configured upstream DNS over UDP and TCP");
            println!("Not implemented: DHCP, TFTP, UBus, reload and metrics");
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
    validate_runtime_ready(&runtime.scalar, &runtime.dns)?;
    if runtime.scalar.dns_port == 0 {
        return Err(Box::new(Error("port=0 is not supported by the listener")));
    }
    let hosts = read_hosts(&runtime.dns, runtime.scalar.local_ttl)?;
    let resolvers = read_resolvers(&runtime.dns)?;
    if !runtime.dns.no_resolv && resolvers.is_empty() {
        return Err(Box::new(Error("no nameserver in resolver files")));
    }
    let addresses = bind_addresses(&runtime.dns, runtime.scalar.dns_port);
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
    for address in addresses {
        let udp = UdpSocket::bind(address)?;
        udp.set_read_timeout(Some(Duration::from_millis(50)))?;
        let tcp = TcpListener::bind(address)?;
        let udp_config = daemon_config.clone();
        let udp_hosts = daemon_hosts.clone();
        let udp_resolvers = resolvers.clone();
        let udp_options = daemon_options;
        let daemon = DnsDaemon::new(udp_config, udp_hosts, &udp_resolvers, udp_options)?;
        workers.push(
            thread::Builder::new()
                .name(format!("dns-udp-{address}"))
                .spawn(move || {
                    let mut daemon = daemon;
                    let mut query = vec![0; 65_535];
                    loop {
                        match udp.recv_from(&mut query) {
                            Ok((length, peer)) if length <= packet_limit => {
                                let request = ClientRequest {
                                    source: peer,
                                    destination: address.ip(),
                                    interface: 0,
                                };
                                if let Ok(QueryResult::Local(answer)) =
                                    daemon.handle_udp(&query[..length], request)
                                {
                                    let _ = udp.send_to(&answer, peer);
                                }
                            }
                            Ok(_) => {}
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
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
        let tcp_active_for_listener = Arc::clone(&tcp_active);
        workers.push(
            thread::Builder::new()
                .name(format!("dns-tcp-{address}"))
                .spawn(move || {
                    for stream in tcp.incoming().flatten() {
                        if !try_acquire_tcp(&tcp_active_for_listener, tcp_limit) {
                            continue;
                        }
                        let service = Arc::clone(&tcp_service);
                        let permit = TcpPermit(Arc::clone(&tcp_active_for_listener));
                        let _ =
                            thread::Builder::new()
                                .name("dns-tcp-client".into())
                                .spawn(move || {
                                    let _permit = permit;
                                    let mut stream = stream;
                                    let deadline = Instant::now() + Duration::from_secs(150);
                                    let mut framer = TcpFramer::new();
                                    let mut input = [0u8; 4096];
                                    let mut queries = 0usize;
                                    'connection: while let Some(remaining) =
                                        deadline.checked_duration_since(Instant::now())
                                    {
                                        if remaining.is_zero() {
                                            break;
                                        }
                                        if stream.set_read_timeout(Some(remaining)).is_err() {
                                            break;
                                        }
                                        let count = match stream.read(&mut input) {
                                            Ok(0) | Err(_) => break,
                                            Ok(count) => count,
                                        };
                                        let Ok(frames) = framer.push(&input[..count]) else {
                                            break;
                                        };
                                        for query in frames {
                                            queries += 1;
                                            if queries > 100 {
                                                break 'connection;
                                            }
                                            if query.len() > packet_limit {
                                                break 'connection;
                                            }
                                            let answer =
                                                service.lock().ok().and_then(|mut guard| {
                                                    guard.handle_tcp_payload(&query).ok().flatten()
                                                });
                                            if let Some(answer) = answer {
                                                let Ok(frame) = encode_tcp_frame(&answer) else {
                                                    break 'connection;
                                                };
                                                let Some(remaining) =
                                                    deadline.checked_duration_since(Instant::now())
                                                else {
                                                    break 'connection;
                                                };
                                                if remaining.is_zero()
                                                    || write_frame_until(
                                                        &mut stream,
                                                        &frame,
                                                        deadline,
                                                    )
                                                    .is_err()
                                                {
                                                    break 'connection;
                                                }
                                            }
                                        }
                                    }
                                });
                    }
                })?,
        );
    }
    // `-k` is the normal OpenWrt invocation.  The runner has no signal module
    // yet; procd owns termination and closes the process on SIGTERM.
    let _ = workers;
    loop {
        thread::park();
    }
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
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS TCP deadline"));
        };
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS TCP deadline"));
        }
        stream.set_write_timeout(Some(remaining))?;
        let written = stream.write(&frame[offset..])?;
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
        || scalar.negative_ttl != defaults.negative_ttl
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
    if dns.domain_needed
        || dns.bogus_priv
        || dns.no_poll
        || dns.no_negative_cache
        || dns.localise_queries
    {
        return Err(Error("configured DNS policy is not implemented"));
    }
    if dns.records.needs_hostname() {
        return Err(Error(
            "hostname-dependent local records are not implemented",
        ));
    }
    let defaults = ScalarConfig::default();
    if scalar.cache_size != defaults.cache_size
        || scalar.query_port != defaults.query_port
        || scalar.query_port_os_assigned != defaults.query_port_os_assigned
        || scalar.min_port != defaults.min_port
        || scalar.max_port != defaults.max_port
        || scalar.port_limit != defaults.port_limit
        || scalar.negative_ttl != defaults.negative_ttl
        || scalar.max_ttl != defaults.max_ttl
        || scalar.min_cache_ttl != defaults.min_cache_ttl
        || scalar.max_cache_ttl != defaults.max_cache_ttl
        || scalar.dhcp_ttl.is_some()
        || scalar.stale_cache != defaults.stale_cache
    {
        return Err(Error("scalar option is not implemented"));
    }
    Ok(())
}

fn read_hosts(config: &DnsConfig, local_ttl: u32) -> Result<Hosts, io::Error> {
    let mut hosts = Hosts::new();
    hosts.set_round_robin(!config.no_round_robin);
    let mut read = |path: &Path, source: u32, required: bool| -> Result<(), io::Error> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if !required && error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let _ = hosts.read(&bytes, source, local_ttl, config.expand_hosts, |address| {
            config
                .domain_for_address(address)
                .ok()
                .flatten()
                .map(ToOwned::to_owned)
        });
        Ok(())
    };
    // `no-hosts` suppresses only the built-in /etc/hosts source. Explicit
    // addn-hosts files remain active in dnsmasq.
    if !config.no_hosts {
        read(Path::new("/etc/hosts"), 0, false)?;
    }
    // `no-hosts` disables the default /etc/hosts source; explicit addn-hosts
    // files remain active in dnsmasq and must still be loaded.
    for (index, path) in config.addn_hosts.iter().enumerate() {
        let Some(path) = path else { continue };
        read(path, (index + 1) as u32, true)?;
    }
    Ok(hosts)
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
        let mut hosts = read_hosts(&config, 0).unwrap();
        assert_eq!(hosts.lookup(b"addn.test", Some(false), true).len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn hosts_receive_the_final_local_ttl() {
        let path = std::env::temp_dir().join(format!("dnsmasq-rs-ttl-{}", std::process::id()));
        std::fs::write(&path, b"192.0.2.44 ttl.test\n").unwrap();
        let mut config = DnsConfig::default();
        config.addn_hosts.push(Some(path.clone()));
        let hosts = read_hosts(&config, 37).unwrap();
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
}
