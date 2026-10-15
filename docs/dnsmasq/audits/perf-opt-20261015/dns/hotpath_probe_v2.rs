//! Allocation/instruction screen of the public, real local/cache answer path.
//! This is a diagnostic executable, not a product feature or a device workload.
//! Build once with --cfg allocation_tracking for counts and once without for
//! isolated perf/timing. All setup, priming and output are outside the scope.

use dnsmasq_rs::config::dns::DnsConfig;
use dnsmasq_rs::config::records::Cname;
use dnsmasq_rs::dhcp::persistence::DnsLeaseRecord;
use dnsmasq_rs::dns::cache::{Cache, Kind, Policy, Record};
use dnsmasq_rs::dns::daemon::{DnsDaemon, QueryResult};
use dnsmasq_rs::dns::forward::Question;
use dnsmasq_rs::dns::lease_names::{LeaseNames, LeasePolicy};
use dnsmasq_rs::dns::service::LocalDnsService;
use dnsmasq_rs::dns::upstream::OsRandom;
use dnsmasq_rs::dns::wire::{Header, Name, PacketWriter};
use dnsmasq_rs::hosts::Hosts;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

#[cfg(allocation_tracking)]
mod allocation {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
    pub struct Meter;
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static REALLOCS: AtomicU64 = AtomicU64::new(0);
    static BYTES: AtomicU64 = AtomicU64::new(0);
    static LIVE: AtomicI64 = AtomicI64::new(0);
    // Forward the same requests to System; counters themselves never allocate.
    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc(layout) };
            if !ptr.is_null() {
                CALLS.fetch_add(1, Relaxed);
                BYTES.fetch_add(layout.size() as u64, Relaxed);
                LIVE.fetch_add(layout.size() as i64, Relaxed);
            }
            ptr
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            LIVE.fetch_sub(layout.size() as i64, Relaxed);
            unsafe { System.dealloc(ptr, layout) };
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let next = unsafe { System.realloc(ptr, layout, size) };
            if !next.is_null() {
                REALLOCS.fetch_add(1, Relaxed);
                BYTES.fetch_add(size as u64, Relaxed);
                LIVE.fetch_add(size as i64 - layout.size() as i64, Relaxed);
            }
            next
        }
    }
    pub fn snapshot() -> [i64; 4] {
        [CALLS.load(Relaxed) as i64, REALLOCS.load(Relaxed) as i64,
         BYTES.load(Relaxed) as i64, LIVE.load(Relaxed)]
    }
}
#[cfg(allocation_tracking)]
#[global_allocator]
static ALLOCATOR: allocation::Meter = allocation::Meter;

fn counts() -> [i64; 4] {
    #[cfg(allocation_tracking)] { allocation::snapshot() }
    #[cfg(not(allocation_tracking))] { [0; 4] }
}

struct Fixture {
    cache: Cache,
    local: LocalDnsService,
    queries: Vec<Vec<u8>>,
    expected_answers: usize,
}

impl Fixture {
    fn new(scene: &str) -> Self {
        let known = ["hit", "hit-upper", "hit-leases", "miss", "miss-leases", "host", "rrset",
                     "cname", "cname-leases", "cname-config"];
        assert!(known.contains(&scene), "unknown diagnostic scene");
        let rrset = scene == "rrset";
        let chain = scene.starts_with("cname");
        let population = if rrset { 100 } else if chain { 400 } else { 800 };
        let mut cache = Cache::new(1000, Policy::default());
        let mut config = DnsConfig::default();
        let mut hosts = Hosts::new();
        let mut queries = Vec::new();
        for i in 0..population {
            let dotted = format!("name{i:04}.perf.invalid");
            let name = Name::from_ascii(&dotted).unwrap();
            let rrtype = if i % 10 < 7 { 1 } else { 28 };
            let ipv6 = rrtype == 28;
            if chain {
                let target_dotted = format!("target{i:04}.perf.invalid");
                let target_name = Name::from_ascii(&target_dotted).unwrap();
                if scene == "cname-config" {
                    config.records.cnames.push(Cname {
                        alias: dotted.as_bytes().to_vec(), target: target_dotted.as_bytes().to_vec(), ttl: None,
                    });
                    hosts.insert(target_dotted.into_bytes(), if ipv6 {
                        IpAddr::V6("2001:db8::1".parse().unwrap())
                    } else { IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)) }, 120, 2);
                } else {
                    cache.start_insert();
                    let alias = cache.insert(Record { name: name.clone(), kind: Kind::Cname,
                        negative: false, data: target_name.as_wire().to_vec() }, 100, 120).unwrap();
                    let target = cache.insert(Record { name: target_name, kind: if ipv6 { Kind::Ipv6 } else { Kind::Ipv4 },
                        negative: false, data: if ipv6 { vec![1; 16] } else { vec![192, 0, 2, 1] } }, 100, 120).unwrap();
                    assert!(cache.set_cname_target(alias, target));
                    assert!(cache.commit());
                }
            }
            if scene.starts_with("hit") || rrset {
                cache.start_insert();
                for j in 0..if rrset { 8 } else { 1 } {
                    let data = if ipv6 { vec![j; 16] } else { vec![192, 0, 2, j] };
                    cache.insert(Record { name: name.clone(), kind: if ipv6 { Kind::Ipv6 } else { Kind::Ipv4 },
                        negative: false, data }, 100, 120).unwrap();
                }
                assert!(cache.commit());
            }
            if scene == "host" {
                hosts.insert(dotted.as_bytes().to_vec(), if ipv6 {
                    IpAddr::V6("2001:db8::1".parse().unwrap())
                } else { IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)) }, 120, 2);
            }
            let question_name = if scene.ends_with("upper") {
                Name::from_ascii(&dotted.to_ascii_uppercase()).unwrap()
            } else { name };
            let mut writer = PacketWriter::new(0x1234, 0x0100, 1232).unwrap();
            writer.question(&question_name, rrtype, 1).unwrap();
            queries.push(writer.finish());
        }
        let mut local = LocalDnsService::new(config, hosts, 120, 1232);
        if scene.ends_with("leases") {
            let names: Vec<_> = (0..6).map(|i| format!("lease{i}.perf.invalid").into_bytes()).collect();
            let leases: Vec<_> = names.iter().enumerate().map(|(i, name)| DnsLeaseRecord {
                name, address: Ipv4Addr::new(192, 0, 2, i as u8 + 1), expires: Some(600),
            }).collect();
            local.leases = Arc::new(LeaseNames::build(&leases, &mut local.hosts, &[], LeasePolicy::default(), &mut ()));
        }
        Self { cache, local, queries, expected_answers: if scene.starts_with("miss") { 0 } else if rrset { 8 } else if chain { 2 } else { 1 } }
    }

    fn query(&mut self, index: usize, validate: bool) -> u64 {
        let query = black_box(&self.queries[index % self.queries.len()]);
        let header = Header::parse(query).unwrap();
        let question = Question::parse_with_header(query, header).unwrap();
        let result = DnsDaemon::<OsRandom>::answer_local_or_cached(
            Some(&mut self.cache), query, header, &question, &mut self.local, 101, true, false,
        ).unwrap();
        match black_box(result.answer) {
            Some(QueryResult::Local(packet) | QueryResult::Cached(packet)) => {
                if validate {
                    let header = Header::parse(&packet).unwrap();
                    assert_eq!(usize::from(header.answers), self.expected_answers);
                    assert_eq!(header.rcode(), 0);
                    assert_eq!(header.id, 0x1234);
                }
                black_box(packet.len() as u64)
            }
            None => { assert_eq!(self.expected_answers, 0); 0 }
            _ => panic!("unexpected result"),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3, "probe SCENE OPERATIONS");
    let iterations: usize = args[2].parse().unwrap();
    let mut fixture = Fixture::new(&args[1]);
    for i in 0..fixture.queries.len() { fixture.query(i, true); }
    let before = counts();
    let mut checksum = 0u64;
    for i in 0..iterations { checksum = checksum.wrapping_add(fixture.query(i, false)); }
    let after = counts();
    let delta = std::array::from_fn::<_, 4, _>(|i| after[i] - before[i]);
    assert_eq!(delta[3], 0, "steady-state requested allocation balance");
    println!("{{\"scene\":\"{}\",\"operations\":{iterations},\"allocations\":{},\"reallocations\":{},\"requested_bytes\":{},\"live_bytes_delta\":{},\"checksum\":{checksum}}}",
        args[1], delta[0], delta[1], delta[2], delta[3]);
}
