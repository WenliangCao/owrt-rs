//! Production-API screening probe; never linked into the product daemon.
//! Build the release library, then rustc -O --edition=2021 with --extern
//! dnsmasq_rs=.../libdnsmasq_rs.rlib and -L dependency=.../release/deps.
use dnsmasq_rs::dhcp::lease::{ClientIdentity, LeaseStore};
use dnsmasq_rs::dhcp::persistence::DnsLeaseRecord;
use dnsmasq_rs::dns::lease_names::{LeaseNames, LeasePolicy};
use dnsmasq_rs::hosts::Hosts;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

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

fn address(index: usize) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, (index + 1) as u8)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("serialize");
    let count = args.get(2).map(|v| v.parse().unwrap()).unwrap_or(150usize);
    let iterations = args.get(3).map(|v| v.parse().unwrap()).unwrap_or(1usize);
    let names: Vec<Vec<u8>> = (0..count).map(|i| format!("host{i:04}.screen.test").into_bytes()).collect();
    let mut store = LeaseStore::new(count);
    for (index, name) in names.iter().enumerate() {
        let address = address(index);
        store.allocate(address, ClientIdentity {
            hardware_type: 1,
            hardware_address: vec![2, 0, 0, 0, 0, (index + 1) as u8],
            client_id: None,
        }).unwrap();
        store.set_expires(address, 3600, 100).unwrap();
        store.set_hostname(address, Some(name), false, None, false).unwrap();
    }
    let records: Vec<_> = names.iter().enumerate().rev().map(|(i, name)| DnsLeaseRecord {
        name, address: address(i), expires: Some(3700),
    }).collect();
    let mut input = Vec::new();
    for (index, name) in names.iter().enumerate() {
        writeln!(input, "{} {}", address(index % 250), std::str::from_utf8(name).unwrap()).unwrap();
    }
    let mut hosts = Hosts::new();
    let lease_names = LeaseNames::build(&records, &mut hosts, &[], LeasePolicy::default(), &mut ());
    let mut sink = Sink::default();
    let mut items = 0;
    ENABLED.store(true, Relaxed);
    for _ in 0..iterations {
        match mode {
            "serialize" => store.write_leases(&mut sink).unwrap(),
            "order" => items += black_box(store.active_newest_first()).len(),
            "publication" => {
                items += black_box(LeaseNames::build(&records, &mut hosts, &[], LeasePolicy::default(), &mut ())).entries().len();
            }
            "lookup" => {
                for name in &names { items += black_box(lease_names.lookup(black_box(name), 100)).count(); }
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
    println!("{{\"mode\":\"{mode}\",\"records\":{count},\"iterations\":{iterations},\"allocations\":{},\"allocated_bytes\":{},\"write_calls\":{},\"output_bytes\":{},\"output_hash\":{},\"items\":{items}}}",
        ALLOCS.load(Relaxed), BYTES.load(Relaxed), sink.calls, sink.bytes, sink.hash);
}
