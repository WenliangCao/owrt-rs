//! SIGUSR1 diagnostics, following cache.c::dump_cache and dump_cache_entry.
//! Internal allocator layout and hash iteration order are implementation details;
//! names, addresses, expiry, provenance and operational counters are not.

use super::*;
use crate::metrics::{Metric, Metrics};
use std::collections::{BTreeMap, HashSet};

impl<R: Random> DnsDaemon<R> {
    #[expect(
        clippy::too_many_arguments,
        reason = "Diagnostic inputs are snapshots of separate owners; the emitter keeps I/O outside the cache."
    )]
    pub fn dump_cache(
        &self,
        local: &LocalDnsService,
        now: i64,
        metrics: &Metrics,
        tcp_high_water: usize,
        tcp_limit: usize,
        debug: bool,
        mut emit: impl FnMut(String),
    ) {
        emit(format!("time {now}"));
        emit(format!(
            "cache size {}, {}/{} cache insertions re-used unexpired cache entries.",
            self.cache.as_ref().map_or(0, Cache::capacity),
            metrics.get(Metric::CacheLiveFreed),
            metrics.get(Metric::CacheInserted)
        ));
        emit(format!(
            "queries forwarded {}, queries answered locally {}",
            metrics.get(Metric::QueriesForwarded),
            metrics.get(Metric::LocalAnswered)
        ));
        if self
            .cache
            .as_ref()
            .is_some_and(|cache| cache.policy().stale != StalePolicy::Disabled)
        {
            emit(format!(
                "queries answered from stale cache {}",
                metrics.get(Metric::StaleAnswered)
            ));
        }
        emit(format!("child processes for TCP requests: in use {}, highest since last SIGUSR1 {}, max allowed {}.",
            metrics.get(Metric::TcpConnections), tcp_high_water, tcp_limit));
        // One live C server record per ID; repeated endpoints sum counters and
        // average their moving latency, including records with no replies yet.
        let mut servers =
            BTreeMap::<SocketAddr, (crate::dns::upstream::ServerCounters, u32)>::new();
        let mut seen = HashSet::new();
        let routed = self
            .routing
            .groups()
            .flat_map(|group| &group.servers)
            .map(|server| (server.id, server.address));
        // Loop-disabled servers remain in C's live list and its diagnostics.
        for (id, address) in routed.chain(self.upstream.retained_servers()) {
            if !seen.insert(id) {
                continue;
            }
            let value = self.upstream.server_counters(id);
            let (total, count) = servers.entry(address).or_default();
            total.queries = total.queries.wrapping_add(value.queries);
            total.retries = total.retries.wrapping_add(value.retries);
            total.failed = total.failed.wrapping_add(value.failed);
            total.nxdomain = total.nxdomain.wrapping_add(value.nxdomain);
            total.latency = total.latency.wrapping_add(value.latency);
            *count += 1;
        }
        for (address, (total, count)) in servers {
            emit(format!("server {}#{}: queries sent {}, retried {}, failed {}, nxdomain replies {}, avg. latency {}ms",
                String::from_utf8_lossy(&crate::address_logging::address_text(address)), address.port(), total.queries, total.retries, total.failed,
                total.nxdomain, total.latency / count));
        }
        if !debug && !self.query_logging.enabled {
            return;
        }
        emit("Host                           Address                                  Flags      Expires                  Source".into());
        emit("------------------------------ ---------------------------------------- ---------- ------------------------ ------------".into());
        for host in local.hosts.entries() {
            // cache.c::cache_reload gives configured host-records both F_HOSTS
            // and F_CONFIG; their positive source UID still names "config".
            let flags = format!(
                "{}F{}I   H{} ",
                if host.address.is_ipv4() { '4' } else { '6' },
                if host.reverse { 'R' } else { ' ' },
                if host.configured { 'C' } else { ' ' }
            );
            let source = if host.configured {
                Some(b"config".as_slice())
            } else {
                local.hosts.source_name(host.source)
            };
            emit(row(
                &host.name,
                &host.address.to_string(),
                &flags,
                None,
                source,
            ));
        }
        for lease in local.leases.active_entries() {
            let flags = format!(
                "4F{}{}D     ",
                if lease.reverse { 'R' } else { ' ' },
                if lease.expires.is_none() { 'I' } else { ' ' }
            );
            emit(row(
                &lease.name,
                &lease.address.to_string(),
                &flags,
                lease.expires,
                None,
            ));
        }
        for cname in &self.local.config.records.cnames {
            // Configured CNAMEs have F_CONFIG but UID zero, so C's dump has no
            // Source column for them (cache.c::dump_cache_entry).
            emit(row(
                &cname.alias,
                &sanitise(&cname.target),
                "CF I    C ",
                None,
                None,
            ));
        }
        if let Some(cache) = &self.cache {
            use crate::dns::cache::{CnameTarget, Kind};
            for entry in cache.entries() {
                let record = &entry.record;
                let reverse = matches!(record.kind, Kind::ReverseIpv4 | Kind::ReverseIpv6);
                let name = if reverse && record.negative {
                    Vec::new()
                } else {
                    record.name.dnsmasq_bytes()
                };
                let kind = match record.kind {
                    Kind::Ipv4 | Kind::ReverseIpv4 => '4',
                    Kind::Ipv6 | Kind::ReverseIpv6 => '6',
                    Kind::Cname => 'C',
                    Kind::Generic(_) => 'T',
                    Kind::NxDomain => ' ',
                };
                let address = match record.kind {
                    Kind::Cname => match entry.cname_target() {
                        Some(CnameTarget::Dynamic(id)) => cache
                            .get(id)
                            .map(|target| sanitise(&target.record.name.dnsmasq_bytes()))
                            .unwrap_or_default(),
                        Some(CnameTarget::Local(target)) => sanitise(&target.name.dnsmasq_bytes()),
                        None => String::new(),
                    },
                    Kind::Generic(kind) => crate::config::rrtypes::name(kind).map_or_else(
                        || format!("<type={kind}>"),
                        |name| format!("<{}>", String::from_utf8_lossy(name)),
                    ),
                    _ if record.negative && !reverse => String::new(),
                    Kind::Ipv4 | Kind::ReverseIpv4 => <[u8; 4]>::try_from(record.data.as_slice())
                        .map(|bytes| std::net::Ipv4Addr::from(bytes).to_string())
                        .unwrap_or_default(),
                    Kind::Ipv6 | Kind::ReverseIpv6 => <[u8; 16]>::try_from(record.data.as_slice())
                        .map(|bytes| std::net::Ipv6Addr::from(bytes).to_string())
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                let flags = format!(
                    "{}{}{}  {}{}   ",
                    kind,
                    if reverse { ' ' } else { 'F' },
                    if reverse { 'R' } else { ' ' },
                    if record.negative { 'N' } else { ' ' },
                    if record.kind == Kind::NxDomain {
                        'X'
                    } else {
                        ' '
                    }
                );
                emit(row(
                    if name.is_empty() && !reverse {
                        b"<Root>"
                    } else {
                        &name
                    },
                    &address,
                    &flags,
                    Some(entry.expires),
                    None,
                ));
            }
        }
    }
}

fn sanitise(name: &[u8]) -> String {
    if name.iter().any(|byte| !(b' '..=b'~').contains(byte)) {
        "<name unprintable>".into()
    } else {
        String::from_utf8_lossy(name).to_ascii_lowercase()
    }
}

fn row(
    name: &[u8],
    address: &str,
    flags: &str,
    expires: Option<i64>,
    source: Option<&[u8]>,
) -> String {
    let name = sanitise(name);
    let mut line = format!(
        "{:<30.30} {:<40.40} {} {:<24.24}",
        name,
        address,
        flags,
        expiry(expires)
    );
    if let Some(source) = source {
        line.push_str(&format!(" {:<40.40}", String::from_utf8_lossy(source)));
    }
    line
}

fn expiry(expires: Option<i64>) -> String {
    let Some(expires) = expires else {
        return String::new();
    };
    #[cfg(target_pointer_width = "64")]
    {
        if let Some(buffer) = dnsmasq_platform::libc_format::local_time(expires) {
            return String::from_utf8_lossy(&buffer[..24]).into_owned();
        }
    }
    expires.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn configured_record_dump_matches_c_flags_and_source() {
        let mut config = DnsConfig::default();
        for line in [
            b"host-record=target.test,192.0.2.42,2001:db8::42".as_slice(),
            b"cname=alias.test,target.test",
            b"cname=orphan.test,missing.test",
        ] {
            config.apply(&lex_line(line).unwrap().unwrap()).unwrap();
        }
        let mut hosts = crate::dns::local::configured_hosts(&config, 0);
        hosts.set_source_name(2, b"/tmp/addn-hosts".to_vec());
        hosts.insert(b"file.test".to_vec(), "192.0.2.43".parse().unwrap(), 0, 2);
        let daemon = DnsDaemon::new(config, hosts, &[], DaemonOptions::default()).unwrap();
        let mut lines = Vec::new();
        daemon.dump_cache(&daemon.local, 0, &Metrics::default(), 0, 30, true, |line| {
            lines.push(line)
        });
        let separator = lines
            .iter()
            .position(|line| line.starts_with("------------------------------ "))
            .unwrap();
        assert_eq!(
            &lines[separator + 1..],
            &[
                format!(
                    "{:<30} {:<40} 4FRI   HC  {:<24} {:<40}",
                    "target.test", "192.0.2.42", "", "config"
                ),
                format!(
                    "{:<30} {:<40} 6FRI   HC  {:<24} {:<40}",
                    "target.test", "2001:db8::42", "", "config"
                ),
                format!(
                    "{:<30} {:<40} 4FRI   H   {:<24} {:<40}",
                    "file.test", "192.0.2.43", "", "/tmp/addn-hosts"
                ),
                format!(
                    "{:<30} {:<40} CF I    C  {:<24}",
                    "alias.test", "target.test", ""
                ),
                format!(
                    "{:<30} {:<40} CF I    C  {:<24}",
                    "orphan.test", "missing.test", ""
                ),
            ]
        );
    }

    #[test]
    fn server_dump_preserves_scope_and_c_fallback() {
        let interface = if cfg!(target_os = "macos") {
            b"lo0".as_slice()
        } else {
            b"lo".as_slice()
        };
        let scope = crate::config::dns::endpoints::scope_index(interface).unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let servers = [
            "127.0.0.1:15354".parse().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
            SocketAddr::V6(SocketAddrV6::new(link_local, 53, 0, scope)),
            // util.c::prettyprint_addr omits a scope whose interface vanished.
            SocketAddr::V6(SocketAddrV6::new(link_local, 53, 0, u32::MAX)),
        ];
        let daemon = DnsDaemon::new(
            DnsConfig::default(),
            Hosts::new(),
            &servers,
            DaemonOptions::default(),
        )
        .unwrap();
        let mut lines = Vec::new();
        daemon.dump_cache(
            &daemon.local,
            0,
            &Metrics::default(),
            0,
            20,
            false,
            |line| lines.push(line),
        );
        let actual: Vec<_> = lines
            .iter()
            .filter(|line| line.starts_with("server "))
            .collect();
        let expected = [
            "127.0.0.1#15354".to_string(),
            "2001:db8::1#53".to_string(),
            format!("fe80::1%{}#53", String::from_utf8_lossy(interface)),
            "fe80::1#53".to_string(),
        ];
        assert_eq!(actual.len(), expected.len());
        for address in expected {
            assert!(actual.iter().any(|line| **line == format!(
                "server {address}: queries sent 0, retried 0, failed 0, nxdomain replies 0, avg. latency 0ms")),
                "missing {address}: {actual:?}");
        }
    }
}
