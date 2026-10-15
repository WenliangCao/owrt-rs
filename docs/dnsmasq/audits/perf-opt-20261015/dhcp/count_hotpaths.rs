//! Production-API screening probe; never linked into the product daemon.
//! Build the release library, then rustc -O --edition=2021 with --extern
//! dnsmasq_rs=.../libdnsmasq_rs.rlib and -L dependency=.../release/deps.
use dnsmasq_rs::dhcp::lease::{ClientIdentity, LeaseStore};
use dnsmasq_rs::dhcp::persistence::{self, DnsLeaseRecord, DnsPublisher, DnsStatus};
use dnsmasq_rs::config::dhcp::{DhcpConfig, HardwareAddress, HostConfig};
use dnsmasq_rs::dns::cache::{Cache, Policy as CachePolicy};
use dnsmasq_rs::dns::lease_names::{LeaseNames, LeasePolicy};
use dnsmasq_rs::hosts::Hosts;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;

static ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
struct Meter;
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc(layout) };
        if !result.is_null() && ENABLED.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size(), Relaxed);
        }
        result
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc_zeroed(layout) };
        if !result.is_null() && ENABLED.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size(), Relaxed);
        }
        result
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(ptr, layout, size) };
        if !result.is_null() && ENABLED.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(size, Relaxed);
        }
        result
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
    }
}
// Use --cfg uninstrumented for separate instruction/timing runs. Allocation
// counts and their atomics must not be mistaken for product instruction cost.
#[cfg(not(uninstrumented))]
#[global_allocator]
static ALLOCATOR: Meter = Meter;

#[derive(Default)]
struct Sink { calls: usize, bytes: usize, hash: u64 }
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        self.bytes += bytes.len();
        for &byte in bytes { self.hash = self.hash.wrapping_mul(31).wrapping_add(u64::from(byte)); }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

struct CachedPublisher {
    hosts: Hosts,
    cache: Cache,
    names: Arc<LeaseNames>,
}
impl DnsPublisher for CachedPublisher {
    fn replace(&mut self, records: &[DnsLeaseRecord<'_>]) -> io::Result<()> {
        self.names = Arc::new(LeaseNames::build(records, &mut self.hosts, &[],
            LeasePolicy::default(), &mut self.cache));
        Ok(())
    }
}

fn address(index: usize) -> Ipv4Addr {
    Ipv4Addr::from(0xc000_0201u32 + index as u32)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("serialize");
    let count = args.get(2).map(|v| v.parse().unwrap()).unwrap_or(150usize);
    let iterations = args.get(3).map(|v| v.parse().unwrap()).unwrap_or(1usize);
    let name_style = args.get(4).map(String::as_str).unwrap_or("dotted");
    let names: Vec<Vec<u8>> = (0..count).map(|i| match name_style {
        "dotted" => format!("host{i:04}.screen.test"),
        "short" => format!("host{i:04}"),
        "mixed" => format!("Host{i:04}.Screen.Test"),
        "triples" => format!("host{:04}.screen.test", i / 3),
        "repeated" => "shared.screen.test".to_owned(),
        _ => panic!("unknown name style"),
    }.into_bytes()).collect();
    let mut store = LeaseStore::new(count);
    let mut config = DhcpConfig::default();
    let mut identities = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let address = address(index);
        let identity = ClientIdentity {
            hardware_type: 1,
            hardware_address: vec![2, 0, 0, 0, 0, (index + 1) as u8],
            client_id: None,
        };
        config.hosts.push(HostConfig {
            address: Some(address), hostname: Some(name.clone()),
            hardware: vec![HardwareAddress { kind: 0, address: identity.hardware_address.clone(), wildcard_mask: 0 }],
            ..HostConfig::default()
        });
        identities.push(identity.clone());
        store.allocate(address, identity).unwrap();
        store.set_expires(address, 3600, 100).unwrap();
        if mode == "publication-owner" {
            let short = if name_style == "mixed" { format!("Host{index:04}") } else { format!("host{index:04}") };
            store.set_hostname(address, Some(short.as_bytes()), false, Some(b"screen.test"), false).unwrap();
        } else {
            store.set_hostname(address, Some(name), false, None, false).unwrap();
        }
    }
    let records: Vec<_> = names.iter().enumerate().rev().map(|(i, name)| DnsLeaseRecord {
        name, address: address(i), expires: Some(3700),
    }).collect();
    let short_names: Vec<_> = (0..count).map(|i| format!("host{i:04}").into_bytes()).collect();
    let paired_records: Vec<_> = (0..count).rev().flat_map(|i| [
        DnsLeaseRecord { name: &names[i], address: address(i), expires: Some(3700) },
        DnsLeaseRecord { name: &short_names[i], address: address(i), expires: Some(3700) },
    ]).collect();
    let missing_names: Vec<_> = names.iter().map(|name| {
        let mut missing = name.clone();
        missing.extend_from_slice(b".absent");
        missing
    }).collect();
    let mut input = Vec::new();
    for (index, name) in names.iter().enumerate() {
        writeln!(input, "{} {}", address(index % 250), std::str::from_utf8(name).unwrap()).unwrap();
    }
    let mut hosts = Hosts::new();
    let lease_names = LeaseNames::build(&records, &mut hosts, &[], LeasePolicy::default(), &mut ());
    let mut loaded_hosts = Hosts::new();
    loaded_hosts.begin_bulk(1766, 1000, 1000).unwrap();
    assert!(!loaded_hosts.read(&input, 2, 37, false, |_| None).allocation_failed);
    loaded_hosts.seal_bulk();
    loaded_hosts.finish_bulk();
    let mut removal_hosts = loaded_hosts.try_clone().unwrap();
    for (index, name) in names.iter().enumerate().step_by(2) {
        removal_hosts.insert(name.clone(), Ipv4Addr::from(0xc633_6401u32 + index as u32).into(), 37, 3);
    }
    let mut publisher = CachedPublisher {
        hosts: Hosts::new(), cache: Cache::new(1000, CachePolicy::default()),
        names: Arc::new(LeaseNames::default()),
    };
    publisher.hosts.insert(b"ready.screen.test".to_vec(), "192.0.2.200".parse().unwrap(), 37, 1);
    if mode == "publication-owner" {
        assert_eq!(persistence::update_dns(&mut store, true, true, false, Some(&mut publisher)).status, DnsStatus::Published);
    }
    let mut sink = Sink::default();
    let mut items = 0;
    ENABLED.store(true, Relaxed);
    for _ in 0..iterations {
        match mode {
            "serialize" => store.write_leases(&mut sink).unwrap(),
            "order" => items += black_box(store.active_newest_first()).len(),
            "dhcp-select" => {
                for identity in &identities {
                    items += usize::from(black_box(store.find_client(black_box(identity))).is_some());
                    items += usize::from(black_box(config.find_host(Some(b"unconfigured-client-id"), 1,
                        Some(black_box(&identity.hardware_address)), |_| true)).is_some());
                }
            }
            "publication" | "publication-paired" => {
                let records = if mode == "publication-paired" { &paired_records } else { &records };
                items += black_box(LeaseNames::build(records, &mut hosts, &[], LeasePolicy::default(), &mut ())).entries().len();
            }
            "publication-owner" => {
                // Includes ordering/record-vector construction in update_dns,
                // every LeaseInput allocation, real Hosts/Cache preparation,
                // outer Arc publication and releasing the previous generation.
                let report = persistence::update_dns(&mut store, true, true, false, Some(&mut publisher));
                assert_eq!(report.status, DnsStatus::Published);
                items += black_box(publisher.names.entries().len());
            }
            "lookup" => {
                for name in &names { items += black_box(lease_names.lookup(black_box(name), 100)).count(); }
            }
            "hosts-exists" => {
                for name in &names { items += usize::from(black_box(loaded_hosts.name_exists(black_box(name)))); }
            }
            "hosts-miss" => {
                for name in &missing_names { items += usize::from(black_box(loaded_hosts.name_exists(black_box(name)))); }
            }
            "hosts-ancestor" => {
                for _ in &names { items += usize::from(black_box(loaded_hosts.name_exists(black_box(b"screen.test")))); }
            }
            "hosts-empty" => {
                for name in &names { items += usize::from(black_box(&hosts).name_exists(black_box(name))); }
            }
            "hosts-remove" => {
                let mut next = removal_hosts.try_clone().unwrap();
                assert_eq!(next.try_remove_uid(2).unwrap(), count);
                assert_eq!(next.len(), count.div_ceil(2));
                items += black_box(next).len();
            }
            "hosts" => {
                let mut next = Hosts::new();
                next.begin_bulk(1766, 1000, 1000).unwrap();
                let stats = next.read(black_box(&input), 2, 37, false, |_| None);
                assert!(!stats.allocation_failed && stats.inserted == count);
                next.seal_bulk();
                next.finish_bulk();
                items += black_box(next).len();
            }
            _ => panic!("unknown mode"),
        }
    }
    ENABLED.store(false, Relaxed);
    let allocation_instrumentation = !cfg!(uninstrumented);
    println!("{{\"mode\":\"{mode}\",\"allocation_instrumentation\":{allocation_instrumentation},\"name_style\":\"{name_style}\",\"records\":{count},\"iterations\":{iterations},\"allocations\":{},\"allocated_bytes\":{},\"write_calls\":{},\"output_bytes\":{},\"output_hash\":{},\"items\":{items}}}",
        ALLOCS.load(Relaxed), BYTES.load(Relaxed), sink.calls, sink.bytes, sink.hash);
}
