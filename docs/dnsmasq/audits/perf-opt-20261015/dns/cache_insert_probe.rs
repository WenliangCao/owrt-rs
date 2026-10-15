//! Native diagnostic of real cache insertion/removal/commit paths.
//! Counts exclude fixture creation and priming; whole-process PMU/timing include both.
use dnsmasq_rs::dns::cache::{Cache, Entry, Kind, Policy, Record, StalePolicy};
use dnsmasq_rs::dns::wire::{decode_name, Name};
use std::hint::black_box;
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


fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3, "probe SCENE OPERATIONS");
    let scene = &args[1];
    let iterations: usize = args[2].parse().unwrap();
    assert!(["replace", "pressure", "reverse", "long", "expiry", "expiry-stale"].contains(&scene.as_str()));
    let expiry = scene.starts_with("expiry");
    let population = match scene.as_str() { "pressure" | "expiry" | "expiry-stale" => 1200, "long" => 80, _ => 800 };
    let reverse = scene == "reverse";
    let records: Vec<_> = (0..population).map(|i| {
        let name = if scene == "long" {
            let mut wire = vec![38];
            wire.extend(std::iter::repeat_n(0, 36));
            wire.extend_from_slice(&(i as u16).to_be_bytes());
            wire.push(0);
            decode_name(&wire, 0, 0).unwrap().0
        } else { Name::from_ascii(&format!("name{i:04}.perf.invalid")).unwrap() };
        Record { name, kind: if reverse { Kind::ReverseIpv4 } else { Kind::Ipv4 },
            negative: false, data: vec![192, 0, (i / 256) as u8, i as u8] }
    }).collect();
    let policy = Policy { stale: if scene == "expiry-stale" { StalePolicy::Seconds(5) } else { StalePolicy::Disabled }, ..Policy::default() };
    let mut cache = Cache::new(1000, policy);
    let mut clock_index = 0usize;
    let mut insert = |i: usize| {
        cache.start_insert();
        let record = black_box(&records[i % population]).clone();
        let now = if expiry { 100 + (clock_index / 1000) as i64 } else { 100 };
        let ttl = if expiry { [1, 2, 30, 120][i % 4] } else { 120 };
        clock_index += 1;
        let id = cache.insert(record, now, ttl).unwrap();
        assert!(cache.commit());
        black_box(cache.get(id).unwrap().expires as u64)
    };
    for i in 0..population * 4 { insert(i); }
    let before = counts();
    let mut checksum = 0u64;
    for i in 0..iterations { checksum = checksum.wrapping_add(insert(i)); }
    let after = counts();
    let delta = std::array::from_fn::<_, 4, _>(|i| after[i] - before[i]);
    println!("{{\"scene\":\"{}\",\"operations\":{iterations},\"allocations\":{},\"reallocations\":{},\"requested_bytes\":{},\"live_bytes_delta\":{},\"checksum\":{checksum},\"cache_layout\":{},\"entry_layout\":{}}}",
        scene, delta[0], delta[1], delta[2], delta[3], std::mem::size_of::<Cache>(), std::mem::size_of::<Entry>());
}
