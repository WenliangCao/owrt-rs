//! Native allocation counts through the real daemon publication boundary.
//! Build the release library, then rustc -O -Cpanic=abort -Clto=fat
//! --edition=2021 with --extern
//! dnsmasq_rs=.../libdnsmasq_rs.rlib and -L dependency=.../release/deps.
//! This is not a timing probe and is never linked into the product daemon.
use dnsmasq_rs::config::dns::DnsConfig;
use dnsmasq_rs::dhcp::persistence::DnsLeaseRecord;
use dnsmasq_rs::dns::cache::StalePolicy;
use dnsmasq_rs::dns::daemon::{DaemonOptions, DnsDaemon};
use dnsmasq_rs::dns::lease_names::{LeaseNames, LeasePolicy};
use dnsmasq_rs::hosts::Hosts;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;

static ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCS: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicUsize = AtomicUsize::new(0);
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
            REALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(size, Relaxed);
            RELEASED.fetch_add(layout.size(), Relaxed);
        }
        result
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ENABLED.load(Relaxed) {
            DEALLOCS.fetch_add(1, Relaxed);
            RELEASED.fetch_add(layout.size(), Relaxed);
        }
        unsafe { System.dealloc(ptr, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;

fn totals() -> [usize; 5] {
    [ALLOCS.load(Relaxed), DEALLOCS.load(Relaxed), REALLOCS.load(Relaxed),
     BYTES.load(Relaxed), RELEASED.load(Relaxed)]
}

fn run(leases: usize, reuse: bool, renamed: bool) -> [usize; 5] {
    let mut daemon = DnsDaemon::new(
        DnsConfig::default(), Hosts::new(), &[], DaemonOptions::default(),
    ).unwrap();
    daemon.enable_cache(1000, 0, 0, StalePolicy::Disabled);
    let mut hosts = Hosts::new();
    // Same-length alternate names force every input through the rename fallback.
    let names: Vec<Vec<Vec<u8>>> = ["host", "next"].into_iter().map(|prefix| {
        (0..leases).rev().flat_map(|index| [
            format!("{prefix}{index:04}.screen.test").into_bytes(),
            format!("{prefix}{index:04}").into_bytes(),
        ]).collect()
    }).collect();
    let mut records: Vec<Vec<_>> = names.iter().map(|names| {
        names.iter().enumerate().map(|(index, name)| DnsLeaseRecord {
            name, address: Ipv4Addr::from(0xc000_0201 + (leases - 1 - index / 2) as u32),
            expires: Some(3700),
        }).collect()
    }).collect();
    let mut generation = Arc::new(LeaseNames::default());
    let mut replace = |iteration: usize| {
        let records = &mut records[if renamed { iteration % 2 } else { 0 }];
        for record in records.iter_mut() { record.expires = Some(3700 + iteration as i64); }
        let next = daemon.publish_lease_names(
            black_box(records), &mut hosts, &[], LeasePolicy::default(),
            reuse.then_some(generation.as_ref()),
        );
        assert_eq!(next.inputs().len(), leases * 2);
        assert_eq!(next.entries().len(), leases * 2);
        // As in the owner, allocation of the published Arc and releasing the
        // old generation both remain inside the measured replacement.
        generation = Arc::new(next);
        black_box(&generation);
    };
    for iteration in 0..20 { replace(iteration); }
    let before = totals();
    ENABLED.store(true, Relaxed);
    for iteration in 20..220 { replace(iteration); }
    ENABLED.store(false, Relaxed);
    let after = totals();
    std::array::from_fn(|index| after[index] - before[index])
}

fn main() {
    for (leases, renamed) in [(6, false), (150, false), (6, true)] {
        let ordinary = run(leases, false, renamed);
        let reused = run(leases, true, renamed);
        for (reuse, values) in [(false, ordinary), (true, reused)] {
            println!("LEASE_PUBLICATION leases={leases} inputs={} renamed={renamed} previous={reuse} replacements=200 columns=alloc_including_realloc,dealloc,realloc,requested,released values={values:?}", leases * 2);
        }
        let expected = if renamed { 0 } else { leases * 2 * 200 };
        assert_eq!(ordinary[0] - reused[0], expected);
        assert_eq!(ordinary[1] - reused[1], expected);
        assert_eq!(ordinary[2], reused[2]);
    }
}
