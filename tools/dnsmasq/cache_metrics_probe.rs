use dnsmasq_rs::dns::cache::{Cache, CacheCounters, Kind, Policy, Record, StalePolicy};
use dnsmasq_rs::dns::wire::Name;
use dnsmasq_rs::metrics::{Metric, Metrics};
use std::io::{self, BufRead};

fn kind(value: u32) -> Kind {
    match value {
        1 => Kind::Ipv4,
        28 => Kind::Ipv6,
        5 => Kind::Cname,
        65536 => Kind::NxDomain,
        value => Kind::Generic(value as u16),
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args[0] == "--sizes" {
        println!(
            "{} {}",
            std::mem::size_of::<Cache>(),
            std::mem::size_of::<CacheCounters>()
        );
        return;
    }
    let capacity = args[0].parse().unwrap();
    let stale: i32 = args[1].parse().unwrap();
    let policy = Policy {
        stale: match stale {
            -1 => StalePolicy::Forever,
            0 => StalePolicy::Disabled,
            value => StalePolicy::Seconds(value as u32),
        },
        ..Policy::default()
    };
    let mut cache = Cache::new(capacity, policy);
    let mut legacy = Cache::new(capacity, policy);
    let mut counts = CacheCounters::default();
    let mut metrics = Metrics::default();
    metrics.add(Metric::DhcpAck, 7);
    let mut ids = Vec::new();
    let mut legacy_ids = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let words: Vec<_> = line.split_whitespace().collect();
        let number = |index: usize| words[index].parse::<u32>().unwrap();
        match words[0] {
            "B" => {
                cache.start_insert();
                legacy.start_insert();
                print!("B");
            }
            "C" => {
                let result = cache.commit_counted(&mut counts);
                assert_eq!(result, legacy.commit());
                print!("C {}", u8::from(result));
            }
            "S" => {
                cache.clear_counted(&mut counts);
                legacy.clear();
                print!("S");
            }
            "T" => {
                counts.inserted = number(1);
                counts.live_freed = number(2);
                print!("T");
            }
            "I" => {
                let record = || Record {
                    name: Name::from_ascii(words[1]).unwrap(),
                    kind: kind(number(2)),
                    negative: number(5) != 0,
                    data: vec![number(4) as u8],
                };
                let result = cache.insert_counted(
                    record(),
                    words[6].parse().unwrap(),
                    number(3),
                    &mut counts,
                );
                let old = legacy.insert(record(), words[6].parse().unwrap(), number(3));
                assert_eq!(result.is_ok(), old.is_ok());
                print!("I {}", u8::from(result.is_ok()));
                ids.push(result.ok());
                legacy_ids.push(old.ok());
            }
            "L" => {
                let result = match (ids[number(1) as usize], ids[number(2) as usize]) {
                    (Some(a), Some(b)) => cache.set_cname_target(a, b),
                    _ => false,
                };
                let old = match (
                    legacy_ids[number(1) as usize],
                    legacy_ids[number(2) as usize],
                ) {
                    (Some(a), Some(b)) => legacy.set_cname_target(a, b),
                    _ => false,
                };
                assert_eq!(result, old);
                print!("L {}", u8::from(result));
            }
            "Q" => {
                let name = Name::from_ascii(words[1]).unwrap();
                let now = words[3].parse().unwrap();
                let query = |cache: &mut Cache| {
                    cache
                        .lookup(&name, &[kind(number(2))], now, false)
                        .into_iter()
                        .map(|id| {
                            let entry = cache.get(id).unwrap();
                            (
                                if number(2) == 5 {
                                    0
                                } else {
                                    entry.record.data[0]
                                },
                                entry.expires,
                            )
                        })
                        .collect::<Vec<_>>()
                };
                let result = query(&mut cache);
                assert_eq!(result, query(&mut legacy));
                print!("Q");
                for (value, expires) in result {
                    print!(" {value}:{expires}");
                }
            }
            _ => panic!("unknown command"),
        }
        metrics.set(Metric::CacheInserted, counts.inserted);
        metrics.set(Metric::CacheLiveFreed, counts.live_freed);
        assert_eq!(metrics.get(Metric::DhcpAck), 7);
        print!(
            " | {} {}\n",
            metrics.get(Metric::CacheInserted),
            metrics.get(Metric::CacheLiveFreed)
        );
    }
}
