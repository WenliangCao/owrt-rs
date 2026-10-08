//! Test-only adapter: actual Cache capture/import, no snapshot representation.
//! The local view follows the existing private TCP caller's forward matcher,
//! including its configured-CNAME predicate. It does not guard reverse records.
use super::*;
use crate::dhcp::persistence::DnsLeaseRecord;
use crate::dns::lease_names::{LeaseNames, LeasePolicy};
use crate::hosts::Hosts;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks_exact(2).map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap()).collect()
}
fn name(name: &Name) -> String { String::from_utf8(name.dnsmasq_bytes()).unwrap() }
fn hex(row: &mut String, bytes: &[u8]) { for byte in bytes { write!(row, "{byte:02x}").unwrap(); } }
fn address(bits: u32, bytes: &[u8]) -> IpAddr {
    match bits {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap())),
        6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())),
        _ => panic!("family"),
    }
}
fn local_match(leases: &LeaseNames, cnames: &[crate::config::records::Cname], record: &Record) -> Option<LocalCacheMatch> {
    let owner = record.name.dnsmasq_bytes();
    let lease = matches!(record.kind, Kind::Ipv4 | Kind::Cname)
        .then(|| leases.active_lookup(&owner).next()).flatten();
    let cname = cnames.iter().any(|cname| cname.alias.eq_ignore_ascii_case(&owner));
    lease.map(|entry| LocalCacheMatch {
        same_address: !record.negative && record.kind == Kind::Ipv4 && record.data == entry.address.octets(),
        from_lease: true,
    }).or_else(|| cname.then_some(LocalCacheMatch { same_address: false, from_lease: false }))
}
struct Fixture {
    cache: Cache,
    counters: CacheCounters,
    leases: LeaseNames,
    capture: bool,
    transactions: Vec<CacheTransaction>,
}
impl Fixture {
    fn new(capacity: usize, policy: Policy) -> Self {
        Self { cache: Cache::new(capacity, policy), counters: CacheCounters::default(), leases: LeaseNames::default(), capture: false, transactions: Vec::new() }
    }
    fn commands(&mut self, commands: &str, stage: &str) -> Vec<String> {
        let mut output = Vec::new();
        for line in commands.lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            let number = |i: usize| words[i].parse::<u32>().unwrap();
            let time = |i: usize| words[i].parse::<i64>().unwrap();
            let mut row = format!("{stage} ");
            match words[0] {
                "B" => { self.cache.start_insert(); row.push('B'); }
                "C" => {
                    let committed = if self.capture {
                        if let Some(transaction) = self.cache.capture_commit_counted(&mut self.counters) {
                            self.transactions.push(transaction); true
                        } else { false }
                    } else { self.cache.commit_counted(&mut self.counters) };
                    write!(row, "C {}", u8::from(committed)).unwrap();
                }
                "V" | "I" => {
                    let kind = match (words[0], number(2)) {
                        ("V", 4) => Kind::ReverseIpv4, ("V", 6) => Kind::ReverseIpv6,
                        ("I", 4) => Kind::Ipv4, ("I", 6) => Kind::Ipv6, _ => panic!("kind"),
                    };
                    let record = Record { name: Name::from_ascii(words[1]).unwrap(), kind, negative: false, data: bytes(words[3]) };
                    let ok = self.cache.insert_counted(record, time(5), number(4), &mut self.counters).is_ok();
                    write!(row, "{} {}", words[0], u8::from(ok)).unwrap();
                }
                "H" => {
                    assert_eq!(number(2), 4);
                    let record = DnsLeaseRecord { name: words[1].as_bytes(), address: Ipv4Addr::from(<[u8; 4]>::try_from(bytes(words[3])).unwrap()), expires: Some(time(4)) };
                    self.leases = LeaseNames::build(&[record], &mut Hosts::new(), &[], LeasePolicy { stale: self.cache.policy().stale, ..LeasePolicy::default() }, &mut self.cache);
                    row.push('H');
                }
                "A" => {
                    let addr = address(number(1), &bytes(words[2])); let now = time(3); row.push('A');
                    if let IpAddr::V4(addr) = addr {
                        if let Some(local) = self.leases.reverse(addr, now) {
                            write!(row, " {}:{}:1", String::from_utf8_lossy(&local.name), local.expires.unwrap_or(0)).unwrap();
                        }
                    }
                    for id in self.cache.lookup_reverse(addr, now) {
                        let entry = self.cache.get(id).unwrap(); write!(row, " {}:{}:0", name(&entry.record.name), entry.expires).unwrap();
                    }
                }
                "Q" => {
                    let owner = Name::from_ascii(words[1]).unwrap(); let now = time(3); row.push('Q');
                    let kind = if number(2) == 4 { Kind::Ipv4 } else { Kind::Ipv6 };
                    if kind == Kind::Ipv4 {
                        for local in self.leases.lookup(&owner.dnsmasq_bytes(), now) {
                            write!(row, " {}:1:", local.expires.unwrap_or(0)).unwrap(); hex(&mut row, &local.address.octets());
                        }
                    }
                    for id in self.cache.lookup(&owner, &[kind], now, false) {
                        let entry = self.cache.get(id).unwrap(); write!(row, " {}:0:", entry.expires).unwrap(); hex(&mut row, &entry.record.data);
                    }
                }
                "T" => {
                    row.push('T'); let mut slot = self.cache.head;
                    while let Some(index) = slot {
                        let node = &self.cache.slots[index];
                        let Some(entry) = self.cache.entry(index) else { slot = slot_index(node.next); continue };
                        assert!(entry.committed);
                        let kind = match entry.record.kind { Kind::Ipv4 => "F4", Kind::Ipv6 => "F6", Kind::ReverseIpv4 => "R4", Kind::ReverseIpv6 => "R6", _ => panic!("LRU kind") };
                        write!(row, " {kind}:{}:{}:", name(&entry.record.name), entry.expires).unwrap(); hex(&mut row, &entry.record.data); slot = slot_index(node.next);
                    }
                }
                _ => panic!("command"),
            }
            write!(row, " | {} {}", self.counters.inserted, self.counters.live_freed).unwrap(); output.push(row);
        }
        output
    }
}
#[test]
#[ignore]
fn exact_c_reverse_transfer_probe() {
    use crate::config::{ScalarConfig, StaleCache};
    use std::ffi::OsString;
    let path = std::path::PathBuf::from(std::env::var_os("DNSMASQ_REVERSE_TRANSFER_CASE").unwrap());
    assert!(path.components().any(|part| part.as_os_str() == "private"));
    let now = std::env::var("DNSMASQ_REVERSE_TRANSFER_NOW").unwrap().parse().unwrap();
    let mut scalar = ScalarConfig::default(); let mut dns = crate::config::dns::DnsConfig::default();
    crate::config::loader::load(&[OsString::from("-C"), path.join("config").into_os_string()], std::path::Path::new("/etc/dnsmasq.conf"), |directive, _| {
        assert!(scalar.apply(directive)? || dns.apply(directive)?); Ok(())
    }).unwrap();
    let policy = Policy { min_ttl: scalar.min_cache_ttl, max_ttl: scalar.max_cache_ttl, max_reply_ttl: 0, stale: match scalar.stale_cache { StaleCache::Disabled => StalePolicy::Disabled, StaleCache::Until(n) => StalePolicy::Seconds(n), StaleCache::Forever => StalePolicy::Forever } };
    let read = |name| std::fs::read_to_string(path.join(name)).unwrap();
    let mut parent = Fixture::new(scalar.cache_size as usize, policy); let mut child = Fixture::new(scalar.cache_size as usize, policy);
    let mut output = parent.commands(&read("pre"), "P0"); child.commands(&read("pre"), "P0");
    child.capture = true; let child_output = child.commands(&read("child"), "CH");
    output.extend(parent.commands(&read("between"), "P1"));
    for transaction in child.transactions {
        let committed = parent.cache.import_counted(transaction, now, &mut parent.counters, |record| local_match(&parent.leases, &dns.records.cnames, record));
        output.push(format!("R {} | {} {}", u8::from(committed), parent.counters.inserted, parent.counters.live_freed));
    }
    output.extend(child_output); output.extend(parent.commands(&read("after"), "P2")); println!("\n{}", output.join("\n"));
}
