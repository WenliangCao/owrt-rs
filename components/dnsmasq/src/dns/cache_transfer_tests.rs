use super::*;
use crate::dhcp::persistence::DnsLeaseRecord;
use crate::dns::lease_names::{LeaseNames, LeasePolicy};
use crate::hosts::Hosts;
use std::fmt::Write;
use std::net::Ipv4Addr;

fn kind(value: u32) -> Kind {
    match value {
        1 => Kind::Ipv4,
        28 => Kind::Ipv6,
        5 => Kind::Cname,
        65536 => Kind::NxDomain,
        value => Kind::Generic(value.try_into().unwrap()),
    }
}

fn lease_match(leases: &LeaseNames, record: &Record) -> Option<LocalCacheMatch> {
    if !matches!(record.kind, Kind::Ipv4 | Kind::Cname) {
        return None;
    }
    leases
        .active_lookup(&record.name.dnsmasq_bytes())
        .next()
        .map(|entry| LocalCacheMatch {
            same_address: !record.negative
                && record.kind == Kind::Ipv4
                && record.data == entry.address.octets(),
            from_lease: true,
        })
}

struct Fixture {
    cache: Cache,
    counters: CacheCounters,
    leases: LeaseNames,
    ids: Vec<Option<CnameTarget>>,
    capture: bool,
    transactions: Vec<CacheTransaction>,
}

impl Fixture {
    fn new(capacity: usize, policy: Policy) -> Self {
        Self {
            cache: Cache::new(capacity, policy),
            counters: CacheCounters::default(),
            leases: LeaseNames::default(),
            ids: Vec::new(),
            capture: false,
            transactions: Vec::new(),
        }
    }

    fn commands(&mut self, commands: &str, stage: &str) -> Vec<String> {
        let mut output = Vec::new();
        for line in commands.lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            let number = |index: usize| words[index].parse::<u32>().unwrap();
            let time = |index: usize| words[index].parse::<i64>().unwrap();
            let mut row = format!("{stage} ");
            match words[0] {
                "B" => {
                    self.cache.start_insert();
                    row.push('B');
                }
                "C" => {
                    let committed = if self.capture {
                        match self.cache.capture_commit_counted(&mut self.counters) {
                            Some(transaction) => {
                                self.transactions.push(transaction);
                                true
                            }
                            None => false,
                        }
                    } else {
                        self.cache.commit_counted(&mut self.counters)
                    };
                    write!(row, "C {}", u8::from(committed)).unwrap();
                }
                "I" | "G" | "N" => {
                    let name = Name::from_ascii(words[1]).unwrap();
                    let kind = kind(number(2));
                    let ttl = number(3);
                    let negative = words[0] == "N" || number(5) != 0;
                    let now = if words[0] == "N" { time(5) } else { time(6) };
                    let data = if negative || kind == Kind::Cname {
                        Vec::new()
                    } else if words[0] == "G" {
                        vec![number(4) as u8; 24]
                    } else if matches!(kind, Kind::Ipv4 | Kind::Ipv6) {
                        let mut data = number(4).to_ne_bytes().to_vec();
                        data.resize(if kind == Kind::Ipv4 { 4 } else { 16 }, 0);
                        data
                    } else {
                        vec![number(4) as u8]
                    };
                    let record = Record {
                        name,
                        kind,
                        negative,
                        data,
                    };
                    let inserted = if let Some(local) = lease_match(&self.leases, &record) {
                        self.cache
                            .insert_against_local(ttl, local.same_address)
                            .ok()
                            .map(|()| {
                                CnameTarget::Local(self.cache.local_target(record.name, true))
                            })
                    } else {
                        self.cache
                            .insert_counted(record, now, ttl, &mut self.counters)
                            .ok()
                            .map(CnameTarget::Dynamic)
                    };
                    if words[0] == "N" {
                        if let Some(CnameTarget::Dynamic(id)) = &inserted {
                            self.cache
                                .set_negative_authority(*id, Name::from_ascii(words[4]).unwrap());
                        }
                    }
                    write!(row, "{} {}", words[0], u8::from(inserted.is_some())).unwrap();
                    self.ids.push(inserted);
                }
                "L" => {
                    let alias = self.ids[number(1) as usize].clone();
                    let target = self.ids[number(2) as usize].clone();
                    let ok = match (alias, target) {
                        (Some(CnameTarget::Dynamic(alias)), Some(CnameTarget::Dynamic(target))) => {
                            self.cache.set_cname_target(alias, target)
                        }
                        (Some(CnameTarget::Dynamic(alias)), Some(CnameTarget::Local(target))) => {
                            self.cache.set_local_cname_target(alias, target)
                        }
                        _ => false,
                    };
                    write!(row, "L {}", u8::from(ok)).unwrap();
                }
                "H" => {
                    let record = DnsLeaseRecord {
                        name: words[1].as_bytes(),
                        address: Ipv4Addr::from(number(2).to_ne_bytes()),
                        expires: (time(3) != 0).then_some(time(3)),
                    };
                    self.leases = LeaseNames::build(
                        &[record],
                        &mut Hosts::new(),
                        &[],
                        LeasePolicy {
                            stale: self.cache.policy().stale,
                            ..LeasePolicy::default()
                        },
                        &mut self.cache,
                    );
                    row.push('H');
                }
                "Q" => {
                    let name = Name::from_ascii(words[1]).unwrap();
                    let kind = kind(number(2));
                    let now = time(3);
                    row.push('Q');
                    if kind == Kind::Ipv4 {
                        for lease in self.leases.lookup(&name.dnsmasq_bytes(), now) {
                            write!(
                                row,
                                " 0:{}:1:{}",
                                lease.expires.unwrap_or(0),
                                u32::from_ne_bytes(lease.address.octets())
                            )
                            .unwrap();
                        }
                    }
                    for id in self.cache.lookup(&name, &[kind], now, false) {
                        let entry = self.cache.get(id).unwrap();
                        write!(
                            row,
                            " {}:{}:0:",
                            u8::from(entry.record.negative),
                            entry.expires
                        )
                        .unwrap();
                        if entry.record.negative {
                            row.push_str(&entry.negative_authority_name().map_or_else(
                                || "-".into(),
                                |name| String::from_utf8(name.dnsmasq_bytes()).unwrap(),
                            ));
                        } else if entry.record.kind == Kind::Cname {
                            let target = match entry.cname_target().unwrap() {
                                CnameTarget::Dynamic(target) => {
                                    self.cache.get(target).unwrap().record.name.clone()
                                }
                                CnameTarget::Local(target) => target.name.clone(),
                            };
                            row.push_str(&String::from_utf8(target.dnsmasq_bytes()).unwrap());
                        } else if matches!(entry.record.kind, Kind::Ipv4 | Kind::Ipv6) {
                            write!(
                                row,
                                "{}",
                                u32::from_ne_bytes(entry.record.data[..4].try_into().unwrap())
                            )
                            .unwrap();
                        } else if entry.record.data.len() == 24 {
                            for byte in &entry.record.data {
                                write!(row, "{byte:02x}").unwrap();
                            }
                        } else {
                            write!(row, "{}", entry.record.data[0]).unwrap();
                        }
                    }
                }
                _ => panic!("unknown command"),
            }
            write!(
                row,
                " | {} {}",
                self.counters.inserted, self.counters.live_freed
            )
            .unwrap();
            output.push(row);
        }
        output
    }
}

#[test]
fn successful_empty_capture_is_distinct_from_failed_commit() {
    let mut cache = Cache::new(1, Policy::default());
    let mut counters = CacheCounters::default();
    assert!(cache
        .capture_commit_counted(&mut counters)
        .unwrap()
        .records
        .is_empty());
    assert!(cache
        .insert(
            Record {
                name: Name::from_ascii("zero.test").unwrap(),
                kind: Kind::Ipv4,
                negative: false,
                data: vec![0; 4],
            },
            100,
            0
        )
        .is_err());
    assert!(cache.capture_commit_counted(&mut counters).is_none());
    assert_eq!(counters, CacheCounters::default());
}

#[test]
fn capture_preserves_ordinary_commit_effects_and_drops_invalid_cnames() {
    let commands = "B\nI a.test 1 60 7 0 100\nI alias.test 5 60 0 0 100\n\
                    L 1 0\nI dangling.test 5 60 0 0 100\nC\n\
                    Q a.test 1 100\nQ alias.test 5 100\nQ dangling.test 5 100\n";
    let mut ordinary = Fixture::new(8, Policy::default());
    let mut captured = Fixture::new(8, Policy::default());
    captured.capture = true;
    assert_eq!(
        ordinary.commands(commands, "CH"),
        captured.commands(commands, "CH")
    );
    assert_eq!(ordinary.counters, captured.counters);
    assert_eq!(captured.counters.inserted, 2);
    assert_eq!(captured.transactions.len(), 1);
    let records = &captured.transactions[0].records;
    assert_eq!(records.len(), 2);
    assert!(records
        .iter()
        .all(|record| record.record.name != Name::from_ascii("dangling.test").unwrap()));
    assert!(records
        .iter()
        .find(|record| record.record.kind == Kind::Cname)
        .unwrap()
        .record
        .data
        .is_empty());
}

#[test]
fn aborted_capture_preserves_the_same_ordered_removals_as_ordinary_commit() {
    let seed = "B\nI a.test 1 60 7 0 100\nC\n";
    let update =
        "B\nI b.test 1 60 8 0 101\nI zero.test 1 0 9 0 101\nC\nQ a.test 1 101\nQ b.test 1 101\n";
    let mut ordinary = Fixture::new(1, Policy::default());
    let mut captured = Fixture::new(1, Policy::default());
    ordinary.commands(seed, "P0");
    captured.commands(seed, "P0");
    captured.capture = true;
    assert_eq!(
        ordinary.commands(update, "CH"),
        captured.commands(update, "CH")
    );
    assert_eq!(ordinary.counters, captured.counters);
    assert_eq!(
        captured.counters,
        CacheCounters {
            inserted: 1,
            live_freed: 1
        }
    );
    assert!(captured.transactions.is_empty());
}

/// Runs only through the independent-C comparator. Both owners are seeded
/// from the same commands; this driver deliberately chooses no snapshot
/// representation and constructs no UDP resolver or entropy source.
#[test]
#[ignore]
fn exact_c_transfer_probe() {
    use crate::config::{ScalarConfig, StaleCache};
    use std::ffi::OsString;
    let path = std::path::PathBuf::from(std::env::var_os("DNSMASQ_CACHE_TRANSFER_CASE").unwrap());
    assert!(path.components().any(|part| part.as_os_str() == "private"));
    let now = std::env::var("DNSMASQ_CACHE_TRANSFER_NOW")
        .unwrap()
        .parse()
        .unwrap();
    let mut scalar = ScalarConfig::default();
    let mut dns = crate::config::dns::DnsConfig::default();
    let args = [OsString::from("-C"), path.join("config").into_os_string()];
    crate::config::loader::load(
        &args,
        std::path::Path::new("/etc/dnsmasq.conf"),
        |directive, _| {
            assert!(scalar.apply(directive)? || dns.apply(directive)?);
            Ok(())
        },
    )
    .unwrap();
    let policy = Policy {
        min_ttl: scalar.min_cache_ttl,
        max_ttl: scalar.max_cache_ttl,
        max_reply_ttl: 0,
        stale: match scalar.stale_cache {
            StaleCache::Disabled => StalePolicy::Disabled,
            StaleCache::Until(seconds) => StalePolicy::Seconds(seconds),
            StaleCache::Forever => StalePolicy::Forever,
        },
    };
    let read = |name| std::fs::read_to_string(path.join(name)).unwrap();
    let mut parent = Fixture::new(scalar.cache_size as usize, policy);
    let mut child = Fixture::new(scalar.cache_size as usize, policy);
    let mut output = parent.commands(&read("pre"), "P0");
    child.commands(&read("pre"), "P0");
    child.capture = true;
    let child_output = child.commands(&read("child"), "CH");
    output.extend(parent.commands(&read("between"), "P1"));
    for transaction in child.transactions {
        let committed =
            parent
                .cache
                .import_counted(transaction, now, &mut parent.counters, |record| {
                    lease_match(&parent.leases, record)
                });
        output.push(format!(
            "R {} | {} {}",
            u8::from(committed),
            parent.counters.inserted,
            parent.counters.live_freed
        ));
    }
    output.extend(child_output);
    output.extend(parent.commands(&read("after"), "P2"));
    println!("\n{}", output.join("\n"));
}
