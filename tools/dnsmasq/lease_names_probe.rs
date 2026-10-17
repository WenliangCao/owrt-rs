// Frozen-clock lease publication and local-answer probe. Every expectation
// is produced by the independently executed, exact C oracle.
use dnsmasq_rs::config::dns::DnsConfig;
use dnsmasq_rs::config::loader::{self, Action};
use dnsmasq_rs::config::{Error, ScalarConfig, StaleCache};
use dnsmasq_rs::dhcp::persistence::DnsLeaseRecord;
use dnsmasq_rs::dns::cache::StalePolicy;
use dnsmasq_rs::dns::lease_names::{LeaseInput, LeaseNames, LeasePolicy};
use dnsmasq_rs::dns::local::{configured_hosts, known_forwarded_domain_with_leases, LocalAnswerer};
use dnsmasq_rs::dns::wire::Question;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::Arc;

fn decode(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|at| Ok(u8::from_str_radix(&text[at..at + 2], 16)?))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut scalar = ScalarConfig::default();
    let mut config = DnsConfig::default();
    let action = loader::load(&args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
        if scalar.apply(directive)? || config.apply(directive)? {
            Ok(())
        } else {
            Err(Error("unsupported lease-name probe option"))
        }
    })?;
    if action != Action::Run {
        return Err("probe requires run configuration".into());
    }
    scalar.finalize_runtime()?;
    config.finalize()?;
    config.validate_ready()?;
    let mut hosts = configured_hosts(&config, scalar.local_ttl);
    for path in config.addn_hosts.iter().flatten() {
        hosts.read(
            &std::fs::read(path)?,
            3,
            scalar.local_ttl,
            config.expand_hosts,
            |address| {
                config
                    .domain_for_address(address)
                    .ok()
                    .flatten()
                    .map(ToOwned::to_owned)
            },
        );
    }
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
    let mut inputs: Vec<LeaseInput> = Vec::new();
    let mut leases = Arc::new(LeaseNames::default());
    let mut publication_hosts = hosts.clone();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields[0] {
            "R" => {
                inputs.clear();
                leases = Arc::new(LeaseNames::default());
                publication_hosts = hosts.clone();
                println!("R");
            }
            "D" => {
                let expiry: i64 = fields[1].parse()?;
                inputs.push(LeaseInput {
                    name: fields[3].as_bytes().into(),
                    address: fields[2].parse()?,
                    expires: (expiry != 0).then_some(expiry),
                });
                let records: Vec<_> = inputs
                    .iter()
                    .map(|input| DnsLeaseRecord {
                        name: &input.name,
                        address: input.address,
                        expires: input.expires,
                    })
                    .collect();
                // D commands form one publication batch. Replaying that
                // batch must apply hosts lookup side effects exactly once.
                hosts = publication_hosts.clone();
                leases = Arc::new(LeaseNames::build(
                    &records,
                    &mut hosts,
                    &config.records.cnames,
                    policy,
                    &mut (),
                ));
                println!("D");
            }
            "E" => {
                for entry in leases.active_entries() {
                    println!(
                        "E {} {} 1 0 0 1 0 0 0 0 {} {}",
                        String::from_utf8_lossy(&entry.name),
                        entry.address,
                        u8::from(entry.reverse),
                        entry.expires.unwrap_or(0)
                    );
                }
                for (name, expiry) in leases.non_terminals() {
                    println!(
                        "E {} - 1 0 0 0 0 0 0 0 0 {}",
                        String::from_utf8_lossy(name),
                        expiry.unwrap_or(0)
                    );
                }
                println!("END");
            }
            "Q" | "K" => {
                let now = fields[1].parse()?;
                let query = decode(fields[2])?;
                if fields[0] == "K" {
                    let question = Question::parse(&query, 12)?;
                    println!(
                        "K {}",
                        u8::from(known_forwarded_domain_with_leases(
                            &config,
                            &hosts,
                            &question.name,
                            &leases,
                            now
                        ))
                    );
                } else {
                    let answer = LocalAnswerer {
                        config: &config,
                        hosts: &mut hosts,
                        local_ttl: scalar.local_ttl,
                        max_packet: 65535,
                    }
                    .answer_with_leases(&query, &mut leases, now)
                    .map_err(|error| format!("{error:?}"))?;
                    if let Some(answer) = answer {
                        println!(
                            "{}",
                            answer
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>()
                        );
                    } else {
                        println!("NONE");
                    }
                }
            }
            _ => {
                return Err(
                    "unknown operation; dynamic-cache cases require the daemon probe".into(),
                )
            }
        }
    }
    Ok(())
}
