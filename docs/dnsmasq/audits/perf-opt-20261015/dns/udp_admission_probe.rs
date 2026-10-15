//! Public UDP admission/local-cache chain; no transport or owner wait cost.
use dnsmasq_rs::config::{dns::DnsConfig, lex_line};
use dnsmasq_rs::dns::{cache::{Cache, Kind, Policy, Record}, daemon::{DnsDaemon, QueryResult},
    forward::Question, service::LocalDnsService, upstream::OsRandom,
    wire::{Header, Name, PacketWriter}, udp_query::{inspect, Admission}};
use dnsmasq_rs::hosts::Hosts;
use std::hint::black_box;

#[cfg(allocation_tracking)]
mod meter {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static REALLOCS: AtomicU64 = AtomicU64::new(0);
    static REQUESTED: AtomicU64 = AtomicU64::new(0);
    static LIVE: AtomicU64 = AtomicU64::new(0);
    pub struct Meter;
    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let p = unsafe { System.alloc(l) };
            if !p.is_null() { CALLS.fetch_add(1, Relaxed); REQUESTED.fetch_add(l.size() as u64, Relaxed); LIVE.fetch_add(l.size() as u64, Relaxed); }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            LIVE.fetch_sub(l.size() as u64, Relaxed);
            unsafe { System.dealloc(p, l) };
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
            let q = unsafe { System.realloc(p, l, n) };
            if !q.is_null() { REALLOCS.fetch_add(1, Relaxed); REQUESTED.fetch_add(n as u64, Relaxed); LIVE.fetch_add(n as u64, Relaxed); LIVE.fetch_sub(l.size() as u64, Relaxed); }
            q
        }
    }
    pub fn read() -> [u64; 4] { [CALLS.load(Relaxed), REALLOCS.load(Relaxed), REQUESTED.load(Relaxed), LIVE.load(Relaxed)] }
}
#[cfg(allocation_tracking)]
#[global_allocator]
static METER: meter::Meter = meter::Meter;
fn counts() -> [u64; 4] {
    #[cfg(allocation_tracking)] { meter::read() }
    #[cfg(not(allocation_tracking))] { [0; 4] }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    let scene = args[1].as_str();
    assert!(["hit", "hit-upper", "miss", "host", "malformed"].contains(&scene));
    let operations: usize = args[2].parse().unwrap();
    let mut config = DnsConfig::default();
    config.no_hosts = true; config.no_resolv = true; config.bind_interfaces = true;
    config.apply(&lex_line(b"host-record=ready.device-perf.test,192.0.2.1").unwrap().unwrap()).unwrap();
    let mut hosts = Hosts::new();
    hosts.insert(b"ready.device-perf.test".to_vec(), "192.0.2.1".parse().unwrap(), 0, 1);
    let mut local = LocalDnsService::new(config, hosts, 0, 1497);
    let mut cache = Cache::new(1000, Policy::default());
    let mut queries = Vec::new();
    for index in 0..800 {
        let text = format!("q{index:04x}.m6a.test");
        let name = Name::from_ascii(&text).unwrap();
        let ipv6 = index % 10 >= 7;
        let data = if ipv6 { "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec() } else { vec![192, 0, 2, 1] };
        cache.start_insert();
        cache.insert(Record { name: name.clone(), kind: if ipv6 { Kind::Ipv6 } else { Kind::Ipv4 }, negative: false, data }, 100, 120).unwrap();
        assert!(cache.commit());
        let query_name = match scene {
            "host" => Name::from_ascii("ready.device-perf.test").unwrap(),
            "miss" => Name::from_ascii(&format!("z{index:04x}.m6a.test")).unwrap(),
            "hit-upper" => Name::from_ascii(&text.to_ascii_uppercase()).unwrap(),
            _ => name,
        };
        let mut writer = PacketWriter::new(7, 0x100, 1232).unwrap();
        writer.question(&query_name, if scene != "host" && ipv6 { 28 } else { 1 }, 1).unwrap();
        let mut query = writer.finish();
        if scene == "malformed" { query.truncate(12); query.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]); }
        queries.push(query);
    }
    let mut checksum = 0u64;
    let mut before = counts();
    for iteration in 0..operations + 800 {
        if iteration == 800 { before = counts(); checksum = 0; }
        let query = black_box(queries[iteration % 800].as_slice());
        if let Admission::Reply(packet) = inspect(query, 1232) {
            assert_eq!(scene, "malformed"); assert_eq!(Header::parse(&packet).unwrap().rcode(), 5);
            checksum = checksum.wrapping_add(packet.len() as u64); continue;
        }
        assert_ne!(scene, "malformed");
        let metadata = dnsmasq_rs::dns::forward_service::query_metadata(query, 1232).unwrap();
        assert!(!metadata.had_opt);
        assert!(dnsmasq_rs::dns::edns_policy::client_subnet_cacheable(query));
        assert!(dnsmasq_rs::dns::local::interface_forward_name(&local.config, query).is_none());
        let header = Header::parse(query).unwrap();
        let question = Question::parse_with_header(query, header).unwrap();
        let answer = DnsDaemon::<OsRandom>::answer_local_or_cached(Some(&mut cache), query, header, &question, &mut local, 101, true, false).unwrap();
        match answer.answer {
            None => { assert_eq!(scene, "miss"); checksum = checksum.wrapping_add(1); }
            Some(QueryResult::Cached(packet) | QueryResult::Local(packet)) => {
                assert!(matches!(scene, "hit" | "hit-upper" | "host"));
                assert_eq!(Header::parse(&packet).unwrap().answers, 1);
                checksum = checksum.wrapping_add(packet.iter().map(|&b| u64::from(b)).sum::<u64>());
            }
            _ => panic!("unexpected answer"),
        }
    }
    let after = counts();
    let delta = [after[0]-before[0], after[1]-before[1], after[2]-before[2], after[3]-before[3]];
    println!("{{\"scene\":\"{scene}\",\"operations\":{operations},\"checksum\":{checksum},\"allocation_reallocation_requested_live\":{delta:?}}}");
}
