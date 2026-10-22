//! Offline/cache or explicitly isolated Linux ICMP adapter.
use dnsmasq_rs::dhcp::allocation::ProbeResult;
use dnsmasq_rs::dhcp::probe::{echo_reply_matches, echo_request, wait_pending, PingCache};
use std::io::{self, BufRead};
use std::net::Ipv4Addr;

fn result(value: ProbeResult) {
    match value {
        ProbeResult::Available { offer_hash } => print!("A {offer_hash}"),
        ProbeResult::InUse => print!("I"),
        ProbeResult::Failed => print!("F"),
    }
}

fn main() {
    let mut cache = PingCache::default();
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    let mut network = None;
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let words: Vec<_> = line.split_whitespace().collect();
        match words[0] {
            "R" => {
                cache = PingCache::default();
                println!("R");
            }
            "C" => {
                let mut calls = 0;
                result(
                    cache
                        .check(
                            words[1].parse().unwrap(),
                            words[2].parse().unwrap(),
                            words[3].parse().unwrap(),
                            words[4] == "1",
                            words[5] == "1",
                            |_| {
                                calls += 1;
                                Ok(words[6] == "1")
                            },
                        )
                        .unwrap(),
                );
                print!("|{calls}|");
                for (address, time, hash) in cache.entries() {
                    print!("{address},{time},{hash};");
                }
                println!();
            }
            "W" => {
                for byte in echo_request(words[1].parse().unwrap()) {
                    print!("{byte:02x}");
                }
                println!();
            }
            "T" => println!(
                "{}",
                u8::from(wait_pending(
                    words[1].parse().unwrap(),
                    words[2].parse().unwrap(),
                    words[3].parse().unwrap()
                ))
            ),
            "M" => {
                let data: Vec<u8> = if words[4] == "-" {
                    Vec::new()
                } else {
                    assert!(words[4].len().is_multiple_of(2), "hex fixture has an unmatched nibble");
                    words[4]
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|pair| {
                            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
                        })
                        .collect()
                };
                let peer: Ipv4Addr = words[2].parse().unwrap();
                let target: Ipv4Addr = words[3].parse().unwrap();
                println!(
                    "{}",
                    u8::from(echo_reply_matches(
                        &data[..data.len().min(48)],
                        peer,
                        target,
                        words[1].parse().unwrap()
                    ))
                );
            }
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            "N" | "S" => {
                assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
                use dnsmasq_rs::dhcp::probe::IcmpProbe;
                let probe = network.get_or_insert_with(|| IcmpProbe::new(false).unwrap());
                let start = std::time::Instant::now();
                let stopped = words[0] == "S";
                match probe.check_with_stop(100, words[1].parse().unwrap(), 7, false, || {
                    stopped && start.elapsed() >= std::time::Duration::from_millis(100)
                }) {
                    Ok(value) => result(value),
                    Err(error) => print!("E {:?}", error.kind()),
                }
                println!();
            }
            _ => panic!("bad command"),
        }
    }
}
