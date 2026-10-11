//! SIGUSR1 diagnostics, following cache.c::dump_cache and dump_cache_entry.
//! Internal allocator layout and hash iteration order are implementation details;
//! names, addresses, expiry, provenance and operational counters are not.

use super::*;
use crate::metrics::{Metric, Metrics};
use std::collections::{BTreeMap, HashSet};

impl<R: Random> DnsDaemon<R> {
    pub fn dump_cache(
        &self,
        now: i64,
        metrics: &Metrics,
        tcp_high_water: usize,
        tcp_limit: usize,
        debug: bool,
        mut emit: impl FnMut(String),
    ) {
        emit(format!("time {now}"));
        emit(format!("cache size {}, {}/{} cache insertions re-used unexpired cache entries.",
            self.cache.as_ref().map_or(0, Cache::capacity),
            metrics.get(Metric::CacheLiveFreed), metrics.get(Metric::CacheInserted)));
        emit(format!("queries forwarded {}, queries answered locally {}",
            metrics.get(Metric::QueriesForwarded), metrics.get(Metric::LocalAnswered)));
        if self.cache.as_ref().is_some_and(|cache| cache.policy().stale != StalePolicy::Disabled) {
            emit(format!("queries answered from stale cache {}", metrics.get(Metric::StaleAnswered)));
        }
        emit(format!("child processes for TCP requests: in use {}, highest since last SIGUSR1 {}, max allowed {}.",
            metrics.get(Metric::TcpConnections), tcp_high_water, tcp_limit));
        // One live C server record per ID; repeated endpoints sum counters and
        // average their moving latency, including records with no replies yet.
        let mut servers = BTreeMap::<SocketAddr, (crate::dns::upstream::ServerCounters, u32)>::new();
        let mut seen = HashSet::new();
        for server in self.routing.groups().flat_map(|group| &group.servers) {
            if !seen.insert(server.id) { continue; }
            let value = self.upstream.server_counters(server.id);
            let (total, count) = servers.entry(server.address).or_default();
            total.queries = total.queries.wrapping_add(value.queries);
            total.retries = total.retries.wrapping_add(value.retries);
            total.failed = total.failed.wrapping_add(value.failed);
            total.nxdomain = total.nxdomain.wrapping_add(value.nxdomain);
            total.latency = total.latency.wrapping_add(value.latency);
            *count += 1;
        }
        for (address, (total, count)) in servers {
            emit(format!("server {}#{}: queries sent {}, retried {}, failed {}, nxdomain replies {}, avg. latency {}ms",
                address.ip(), address.port(), total.queries, total.retries, total.failed,
                total.nxdomain, total.latency / count));
        }
        if !debug && !self.query_logging.enabled { return; }
        emit("Host                           Address                                  Flags      Expires                  Source".into());
        emit("------------------------------ ---------------------------------------- ---------- ------------------------ ------------".into());
        for host in self.local.hosts.entries() {
            let flags = format!("{}F{}I   {}{} ", if host.address.is_ipv4() { '4' } else { '6' },
                if host.reverse { 'R' } else { ' ' },
                if host.configured { ' ' } else { 'H' }, if host.configured { 'C' } else { ' ' });
            let source = if host.configured { Some(b"config".as_slice()) }
                else { self.local.hosts.source_name(host.source) };
            emit(row(&host.name, &host.address.to_string(), &flags, None, source));
        }
        for lease in self.local.leases.active_entries() {
            let flags = format!("4F{}{}D     ", if lease.reverse { 'R' } else { ' ' },
                if lease.expires.is_none() { 'I' } else { ' ' });
            emit(row(&lease.name, &lease.address.to_string(), &flags, lease.expires, None));
        }
        for cname in &self.local.config.records.cnames {
            emit(row(&cname.alias, &sanitise(&cname.target), "CF I    C ", None, Some(b"config")));
        }
        if let Some(cache) = &self.cache {
            use crate::dns::cache::{CnameTarget, Kind};
            for entry in cache.entries() {
                let record = &entry.record;
                let reverse = matches!(record.kind, Kind::ReverseIpv4 | Kind::ReverseIpv6);
                let name = if reverse && record.negative { Vec::new() } else { record.name.dnsmasq_bytes() };
                let kind = match record.kind {
                    Kind::Ipv4 | Kind::ReverseIpv4 => '4',
                    Kind::Ipv6 | Kind::ReverseIpv6 => '6',
                    Kind::Cname => 'C', Kind::Generic(_) => 'T', Kind::NxDomain => ' ',
                };
                let address = match record.kind {
                    Kind::Cname => match entry.cname_target() {
                        Some(CnameTarget::Dynamic(id)) => cache.get(id)
                            .map(|target| sanitise(&target.record.name.dnsmasq_bytes())).unwrap_or_default(),
                        Some(CnameTarget::Local(target)) => sanitise(&target.name.dnsmasq_bytes()),
                        None => String::new(),
                    },
                    Kind::Generic(kind) => crate::config::rrtypes::name(kind)
                        .map_or_else(|| format!("<type={kind}>"), |name| format!("<{}>", String::from_utf8_lossy(name))),
                    _ if record.negative && !reverse => String::new(),
                    Kind::Ipv4 | Kind::ReverseIpv4 => <[u8; 4]>::try_from(record.data.as_slice())
                        .map(|bytes| std::net::Ipv4Addr::from(bytes).to_string()).unwrap_or_default(),
                    Kind::Ipv6 | Kind::ReverseIpv6 => <[u8; 16]>::try_from(record.data.as_slice())
                        .map(|bytes| std::net::Ipv6Addr::from(bytes).to_string()).unwrap_or_default(),
                    _ => String::new(),
                };
                let flags = format!("{}{}{}  {}{}   ", kind, if reverse { ' ' } else { 'F' },
                    if reverse { 'R' } else { ' ' }, if record.negative { 'N' } else { ' ' },
                    if record.kind == Kind::NxDomain { 'X' } else { ' ' });
                emit(row(if name.is_empty() && !reverse { b"<Root>" } else { &name },
                    &address, &flags, Some(entry.expires), None));
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

fn row(name: &[u8], address: &str, flags: &str, expires: Option<i64>, source: Option<&[u8]>) -> String {
    let name = sanitise(name);
    let mut line = format!("{:<30.30} {:<40.40} {} {:<24.24}", name, address, flags, expiry(expires));
    if let Some(source) = source {
        line.push_str(&format!(" {:<40.40}", String::from_utf8_lossy(source)));
    }
    line
}

fn expiry(expires: Option<i64>) -> String {
    let Some(expires) = expires else { return String::new(); };
    #[cfg(target_pointer_width = "64")]
    {
        unsafe extern "C" { fn ctime_r(time: *const i64, buffer: *mut u8) -> *mut u8; }
        let mut buffer = [0u8; 26];
        // ctime_r writes the fixed 26-byte C representation into caller storage.
        if !unsafe { ctime_r(&expires, buffer.as_mut_ptr()) }.is_null() {
            return String::from_utf8_lossy(&buffer[..24]).into_owned();
        }
    }
    expires.to_string()
}
