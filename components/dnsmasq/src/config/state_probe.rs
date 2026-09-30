// Test driver only; not linked into the dnsmasq-rs library or daemon.
#[path = "mod.rs"]
mod config;
#[path = "../hosts.rs"]
mod hosts;
use config::{dns::DnsConfig, loader, ScalarConfig, StaleCache};
use std::path::Path;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "_".into();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn optional(bytes: Option<&[u8]>) -> String {
    bytes.map(hex).unwrap_or_else(|| "-".into())
}
fn main() {
    let mut scalar = ScalarConfig::default();
    let mut dns = DnsConfig::default();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = loader::load(&args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        if scalar.apply(directive)? || dns.apply(directive)? {
            Ok(())
        } else {
            Err(config::Error("unimplemented probe option"))
        }
    })
    .and_then(|_| {
        dns.finalize().map_err(|error| loader::LoadError {
            location: loader::Location {
                file: None,
                line: None,
                from_script: false,
            },
            exit_code: 1,
            message: error.to_string(),
        })
    });
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(error.exit_code);
    }
    let retry = scalar
        .fast_retry
        .map(|r| (r.interval_ms, r.timeout_seconds))
        .unwrap_or((0, 0));
    let stale = match scalar.stale_cache {
        StaleCache::Disabled => 0,
        StaleCache::Forever => -1,
        StaleCache::Until(t) => i64::from(t),
    };
    println!(
        "scalar {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        scalar.cache_size,
        scalar.dns_port,
        scalar.forward_max,
        scalar.edns_packet_max,
        scalar.query_port,
        u8::from(scalar.query_port_os_assigned),
        scalar.min_port,
        scalar.max_port,
        scalar.port_limit,
        scalar.local_ttl,
        scalar.negative_ttl,
        scalar.max_ttl,
        scalar.min_cache_ttl,
        scalar.max_cache_ttl,
        scalar.dhcp_ttl.unwrap_or(0),
        u8::from(scalar.dhcp_ttl.is_some()),
        retry.0,
        retry.1,
        stale,
        scalar.max_tcp_connections
    );
    for cname in &dns.records.cnames {
        println!(
            "cname {} {} {}",
            hex(&cname.alias),
            hex(&cname.target),
            cname.ttl.unwrap_or(scalar.local_ttl)
        );
    }
    for record in &dns.records.txt {
        println!("txt {} {}", hex(&record.name), hex(&record.data));
    }
    for record in &dns.records.raw {
        println!(
            "raw {} {} {}",
            hex(&record.name),
            record.rr_type,
            hex(&record.data)
        );
    }
    for record in &dns.records.ptr {
        println!(
            "ptr {} {}",
            hex(&record.name),
            optional(record.target.as_deref())
        );
    }
    for record in &dns.records.mx {
        println!(
            "mx {} {} {}",
            hex(&record.name),
            optional(record.target.as_deref()),
            record.preference
        );
    }
    for record in &dns.records.srv {
        println!(
            "srv {} {} {} {} {}",
            hex(&record.name),
            optional(record.target.as_deref()),
            record.port,
            record.priority,
            record.weight
        );
    }
    for record in &dns.records.naptr {
        println!(
            "naptr {} {} {} {} {} {} {}",
            hex(&record.name),
            record.order,
            record.preference,
            optional(record.flags.as_deref()),
            optional(record.services.as_deref()),
            optional(record.regexp.as_deref()),
            optional(record.replacement.as_deref())
        );
    }
    for (index, record) in dns.host_records.iter().enumerate() {
        println!(
            "host {} {} {} {}",
            index,
            record
                .address4
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".into()),
            record
                .address6
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".into()),
            record.ttl.unwrap_or(scalar.local_ttl)
        );
        for (name_index, name) in record.names.iter().enumerate() {
            println!("host-name {index} {name_index} {}", hex(name));
        }
    }
}
