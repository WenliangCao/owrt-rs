//! Frozen-clock driver for actual cache-answer stale metadata. Expected output
//! is supplied only by the separately recorded full-object C oracle.

use super::*;
use crate::config::{loader, ScalarConfig, StaleCache};
use std::ffi::OsString;
use std::path::Path;

#[test]
#[ignore = "requires DNSMASQ_STALE_CONFIG/INPUT and the exact C baseline"]
fn exact_c_stale_driver() {
    let config_file = std::env::var_os("DNSMASQ_STALE_CONFIG").unwrap();
    let input_file = std::env::var_os("DNSMASQ_STALE_INPUT").unwrap();
    let mut scalar = ScalarConfig::default();
    let mut config = DnsConfig::default();
    let action = loader::load(
        &[OsString::from("-C"), config_file],
        Path::new("/dev/null"),
        |directive, _| {
            // In particular, no filter option is admitted: filtered=0 below
            // is the unfiltered caller contract, not a filter implementation.
            if !matches!(
                directive.name.as_slice(),
                b"no-hosts"
                    | b"no-resolv"
                    | b"cache-size"
                    | b"neg-ttl"
                    | b"min-cache-ttl"
                    | b"max-cache-ttl"
                    | b"max-ttl"
                    | b"use-stale-cache"
            ) {
                return Err(ConfigError(
                    "option outside the frozen stale metadata fixture",
                ));
            }
            if scalar.apply(directive)? || config.apply(directive)? {
                Ok(())
            } else {
                Err(ConfigError("unhandled stale metadata option"))
            }
        },
    )
    .unwrap();
    assert_eq!(action, loader::Action::Run);
    scalar.finalize_runtime().unwrap();
    config.finalize().unwrap();
    config.validate_ready().unwrap();
    assert!(config.no_hosts && config.no_resolv);
    let stale = match scalar.stale_cache {
        StaleCache::Disabled => StalePolicy::Disabled,
        StaleCache::Until(seconds) => StalePolicy::Seconds(seconds),
        StaleCache::Forever => StalePolicy::Forever,
    };
    let options = DaemonOptions {
        local_ttl: scalar.local_ttl,
        max_udp: 65535,
        edns_packet_max: scalar.edns_packet_max,
        ..DaemonOptions::default()
    };
    let mut daemon = DnsDaemon::new(config, Hosts::new(), &[], options).unwrap();
    daemon.enable_cache(
        scalar.cache_size as usize,
        scalar.min_cache_ttl,
        scalar.max_cache_ttl,
        stale,
    );
    daemon.enable_negative_cache(scalar.negative_ttl, true);
    if scalar.max_ttl != 0 {
        // Explicit library-only Policy boundary: the product main still
        // rejects max-ttl, and enable_cache intentionally fixes this to zero.
        daemon.cache = Some(Cache::new(
            scalar.cache_size as usize,
            CachePolicy {
                min_ttl: scalar.min_cache_ttl,
                max_ttl: scalar.max_cache_ttl,
                max_reply_ttl: scalar.max_ttl,
                stale,
            },
        ));
    }
    let input = std::fs::read_to_string(input_file).unwrap();
    for line in input.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        match words[0] {
            "RESET" => {
                assert_eq!(words.len(), 1);
                daemon.reload_hosts(Hosts::new());
                println!("STALE_ORACLE RESET");
            }
            "M" => {
                assert_eq!(words.len(), 1);
                let counters = daemon.cache_counters();
                println!(
                    "STALE_ORACLE M {} {}",
                    counters.inserted, counters.live_freed
                );
            }
            "P" | "T" | "Q" => {
                assert_eq!(words.len(), 4);
                let now = words[1].parse().unwrap();
                let limit: usize = words[2].parse().unwrap();
                assert!(limit <= 65535 && words[3].len().is_multiple_of(2));
                let packet: Vec<_> = words[3]
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|bytes| {
                        u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap()
                    })
                    .collect();
                if words[0] == "P" {
                    daemon.cache_reply_at(&packet, now);
                    println!("STALE_ORACLE P");
                    continue;
                }
                daemon.max_udp = limit;
                let question = super::super::forward::Question::parse(&packet).unwrap();
                let answer = daemon
                    .cached_answer_at_with_local(&packet, &question, now, None)
                    .unwrap();
                let encoded = answer.packet.map_or_else(
                    || "NONE".to_owned(),
                    |packet| {
                        packet
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    },
                );
                if words[0] == "T" {
                    println!("STALE_ORACLE T {} 0 {encoded}", u8::from(answer.stale));
                } else {
                    println!("STALE_ORACLE {encoded}");
                }
            }
            _ => panic!("command outside the frozen stale metadata fixture"),
        }
    }
}
