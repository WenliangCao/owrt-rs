//! Native diagnostic of the actual Cache constructor/clear/snapshot APIs.
//! No product feature or benchmark-specific branch is introduced.
use dnsmasq_rs::dns::cache::{Cache, Policy};
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
    assert_eq!(args.len(), 3, "probe MODE-CAPACITY OPERATIONS");
    let (mode, capacity) = args[1].rsplit_once('-').unwrap();
    let capacity: usize = capacity.parse().unwrap();
    let iterations: usize = args[2].parse().unwrap();
    assert!(["new", "clear", "snapshot-clear"].contains(&mode));
    let mut cache = Cache::new(capacity, Policy::default());
    cache.clear();
    let before = counts();
    for _ in 0..iterations {
        match mode {
            "new" => { black_box(Cache::new(black_box(capacity), Policy::default())); }
            "clear" => { black_box(&mut cache).clear(); black_box(&cache); }
            "snapshot-clear" => {
                let snapshot = cache.snapshot();
                black_box(&mut cache).clear();
                black_box(snapshot);
            }
            _ => unreachable!(),
        }
    }
    let after = counts();
    let delta = std::array::from_fn::<_, 4, _>(|i| after[i]-before[i]);
    assert_eq!(delta[3], 0, "requested live allocation balance");
    println!("{{\"scene\":\"{}\",\"operations\":{iterations},\"capacity\":{capacity},\"allocations\":{},\"reallocations\":{},\"requested_bytes\":{},\"live_bytes_delta\":{},\"checksum\":0}}",
        args[1], delta[0], delta[1], delta[2], delta[3]);
}
