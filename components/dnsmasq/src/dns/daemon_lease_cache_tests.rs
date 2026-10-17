//! Test-only frozen-clock caller for actual C lease/cache differential cases.
use super::*;
use crate::config::loader::{self, Action};
use crate::config::{Error, ScalarConfig, StaleCache};
use crate::dhcp::persistence::DnsLeaseRecord;
use crate::dns::lease_names::{LeaseInput, LeasePolicy};
use std::path::Path;
use std::sync::Arc;

fn publish(daemon: &mut DnsDaemon, inputs: &[LeaseInput], policy: LeasePolicy) {
    let records: Vec<_> = inputs
        .iter()
        .map(|input| DnsLeaseRecord {
            name: &input.name,
            address: input.address,
            expires: input.expires,
        })
        .collect();
    let mut hosts = std::mem::take(&mut daemon.local.hosts);
    let cnames = daemon.local.config.records.cnames.clone();
    let names = daemon.publish_lease_names(&records, &mut hosts, &cnames, policy);
    daemon.local.hosts = hosts;
    daemon.local.leases = Arc::new(names);
}

#[test]
#[ignore = "requires DNSMASQ_LEASE_CACHE_CONFIG and DNSMASQ_LEASE_CACHE_INPUT from lease_insert_diff.py"]
fn exact_c_lease_cache_driver() {
    let path = std::env::var_os("DNSMASQ_LEASE_CACHE_CONFIG").unwrap();
    let mut scalar = ScalarConfig::default();
    let mut config = DnsConfig::default();
    assert_eq!(
        loader::load(
            &["-C".into(), path],
            Path::new("/etc/dnsmasq.conf"),
            |directive, _| {
                if scalar.apply(directive)? || config.apply(directive)? {
                    Ok(())
                } else {
                    Err(Error("unsupported lease/cache probe option"))
                }
            }
        )
        .unwrap(),
        Action::Run
    );
    scalar.finalize_runtime().unwrap();
    config.finalize().unwrap();
    let hosts = super::super::local::configured_hosts(&config, scalar.local_ttl);
    let policy = LeasePolicy {
        local_ttl: scalar.local_ttl,
        dhcp_ttl: scalar.dhcp_ttl,
        no_round_robin: config.no_round_robin,
        stale: match scalar.stale_cache {
            StaleCache::Disabled => StalePolicy::Disabled,
            StaleCache::Until(seconds) => StalePolicy::Seconds(seconds),
            StaleCache::Forever => StalePolicy::Forever,
        },
    };
    let options = DaemonOptions {
        local_ttl: scalar.local_ttl,
        max_udp: 65535,
        ..DaemonOptions::default()
    };
    let mut daemon = DnsDaemon::new(config, hosts, &[], options).unwrap();
    daemon.enable_cache(
        scalar.cache_size as usize,
        scalar.min_cache_ttl,
        scalar.max_cache_ttl,
        policy.stale,
    );
    daemon.enable_negative_cache(scalar.negative_ttl, true);
    let input =
        std::fs::read_to_string(std::env::var_os("DNSMASQ_LEASE_CACHE_INPUT").unwrap()).unwrap();
    let mut inputs = Vec::new();
    let mut pending = false;
    for line in input.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields[0] != "D" && pending {
            publish(&mut daemon, &inputs, policy);
            pending = false;
        }
        match fields[0] {
            "R" => {
                inputs.clear();
                publish(&mut daemon, &inputs, policy);
                println!("LEASE_CACHE_ORACLE R");
            }
            "D" => {
                let expiry = fields[1].parse::<i64>().unwrap();
                inputs.push(LeaseInput {
                    name: fields[3].as_bytes().into(),
                    address: fields[2].parse().unwrap(),
                    expires: (expiry != 0).then_some(expiry),
                });
                pending = true;
                println!("LEASE_CACHE_ORACLE D");
            }
            "S" => {
                let hosts =
                    super::super::local::configured_hosts(&daemon.local.config, scalar.local_ttl);
                daemon.reload_hosts(hosts);
                println!("LEASE_CACHE_ORACLE S");
            }
            "P" | "Q" | "N" | "K" => {
                let now = fields[1].parse().unwrap();
                let packet: Vec<_> = (0..fields[2].len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&fields[2][at..at + 2], 16).unwrap())
                    .collect();
                if fields[0] == "P" {
                    daemon.cache_reply_at(&packet, now);
                    println!("LEASE_CACHE_ORACLE P 0");
                    continue;
                }
                let question = super::super::forward::Question::parse(&packet).unwrap();
                if fields[0] == "N" {
                    let name = question.name.dnsmasq_bytes();
                    if daemon.local.leases.has_expired_name(&name, now) {
                        Arc::make_mut(&mut daemon.local.leases).expire_name(&name, now);
                    }
                    let kind = match question.rrtype {
                        1 => Kind::Ipv4,
                        28 => Kind::Ipv6,
                        5 => Kind::Cname,
                        other => Kind::Generic(other),
                    };
                    let count = daemon
                        .cache
                        .as_mut()
                        .unwrap()
                        .lookup(&question.name, &[kind], now, false)
                        .len();
                    println!("LEASE_CACHE_ORACLE N {count}");
                } else if fields[0] == "K" {
                    let known = super::super::local::known_forwarded_domain_with_leases(
                        &daemon.local.config,
                        &daemon.local.hosts,
                        &question.name,
                        &daemon.local.leases,
                        now,
                    );
                    println!("LEASE_CACHE_ORACLE K {}", u8::from(known));
                } else {
                    let answer = daemon
                        .local
                        .handle_udp_at(&packet, now)
                        .unwrap()
                        .or_else(|| daemon.cached_answer_at(&packet, &question, now).unwrap());
                    println!(
                        "LEASE_CACHE_ORACLE {}",
                        answer.map_or_else(
                            || "NONE".to_owned(),
                            |packet| packet
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>()
                        )
                    );
                }
            }
            operation => panic!("unexpected operation {operation}"),
        }
    }
    if pending {
        publish(&mut daemon, &inputs, policy);
    }
}
