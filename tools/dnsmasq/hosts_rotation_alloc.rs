//! Standalone allocation regression. Compile with the same rustc as the daemon:
//! rustc --edition=2024 -O tools/dnsmasq/hosts_rotation_alloc.rs -o PRIVATE/probe
//! No allocator instrumentation is linked into the shipped daemon.
#[path = "../../components/dnsmasq/src/hosts.rs"]
mod hosts;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering::Relaxed};
struct Meter;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static FAIL_LARGE: AtomicBool = AtomicBool::new(false);
// SAFETY: successful operations forward System's pointer/layout contract;
// injected failures return null without modifying or freeing the old block.
// Accounting uses only atomics and cannot allocate or unwind.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAIL_LARGE.load(Relaxed) && layout.size() >= 512 {
            return std::ptr::null_mut();
        }
        // SAFETY: forward the caller's valid allocation layout unchanged.
        let result = unsafe { System.alloc(layout) };
        if !result.is_null() {
            LIVE.fetch_add(layout.size() as isize, Relaxed);
            ALLOCATED.fetch_add(layout.size(), Relaxed);
        }
        result
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Relaxed);
        // SAFETY: ptr is the live System allocation matching the caller's layout.
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if FAIL_LARGE.load(Relaxed) && size >= 512 {
            return std::ptr::null_mut();
        }
        // SAFETY: forward the live allocation, matching layout and valid size.
        let result = unsafe { System.realloc(ptr, layout, size) };
        if !result.is_null() {
            LIVE.fetch_add(size as isize - layout.size() as isize, Relaxed);
            ALLOCATED.fetch_add(size, Relaxed);
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;

fn main() {
    let mut parent = hosts::Hosts::new();
    let names: Vec<_> = (0..30000).map(|i| format!("host{i:06}.test")).collect();
    for name in &names {
        for address in ["192.0.2.1", "192.0.2.2"] {
            parent.insert(name.as_bytes().to_vec(), address.parse().unwrap(), 37, 2);
        }
    }
    let seed = parent.tcp_snapshot();
    for name in &names {
        assert_eq!(parent.lookup(name.as_bytes(), Some(false), false).len(), 2);
    }
    let warm_live = LIVE.load(Relaxed);
    let mut children = Vec::with_capacity(20);
    let mut max_query_allocated = 0;
    let mut snapshots_allocated = 0;
    for name in &names[..20] {
        let before = ALLOCATED.load(Relaxed);
        let mut child = parent.tcp_snapshot();
        snapshots_allocated += ALLOCATED.load(Relaxed) - before;
        let before = ALLOCATED.load(Relaxed);
        let answer = child.lookup(name.as_bytes(), Some(false), false);
        assert_eq!(answer.len(), 2);
        let cost = ALLOCATED.load(Relaxed) - before;
        max_query_allocated = max_query_allocated.max(cost);
        drop(answer);
        children.push(child);
    }
    let children_live = LIVE.load(Relaxed) - warm_live;
    // 64-entry pages also cover the worst layout with one entry per name.
    assert!(
        max_query_allocated < 16 * 1024,
        "query copied more than a small page: {max_query_allocated}"
    );
    assert!(
        children_live < 2 * 1024 * 1024,
        "20 children copied the inherited map: {children_live}"
    );
    let mut rolling_peak = children_live;
    for i in 0..2000 {
        parent.lookup(names[i % names.len()].as_bytes(), Some(false), false);
        let mut child = parent.tcp_snapshot();
        child.lookup(
            names[(i + 15000) % names.len()].as_bytes(),
            Some(false),
            false,
        );
        // Accept before closing the old connection; retain exactly 20 clients.
        children[i % 20] = child;
        rolling_peak = rolling_peak.max(LIVE.load(Relaxed) - warm_live);
    }
    assert!(
        rolling_peak < 2 * 1024 * 1024,
        "rolling snapshots retained history: {rolling_peak}"
    );
    drop((children, seed));
    let retained_after_drop = LIVE.load(Relaxed) - warm_live;
    assert!(
        retained_after_drop < 256 * 1024,
        "disconnected clients retained pages: {retained_after_drop}"
    );
    // Reject the shared page's reservation, while the two-address answer and
    // temporary index vectors still fit. The old order must remain usable.
    let mut fault_child = parent.tcp_snapshot();
    FAIL_LARGE.store(true, Relaxed);
    let failed: Vec<_> = fault_child
        .lookup(names[15000].as_bytes(), Some(false), false)
        .into_iter()
        .map(|host| host.address)
        .collect();
    FAIL_LARGE.store(false, Relaxed);
    let recovered: Vec<_> = fault_child
        .lookup(names[15000].as_bytes(), Some(false), false)
        .into_iter()
        .map(|host| host.address)
        .collect();
    assert_eq!(failed, recovered, "failed page copy changed accepted order");
    let rotated: Vec<_> = fault_child
        .lookup(names[15000].as_bytes(), Some(false), false)
        .into_iter()
        .map(|host| host.address)
        .collect();
    assert_ne!(
        recovered, rotated,
        "round robin did not resume after recovery"
    );
    println!(
        "{{\"names\":30000,\"children\":20,\"warm_live\":{warm_live},\"snapshots_allocated\":{snapshots_allocated},\"max_query_allocated\":{max_query_allocated},\"children_live\":{children_live},\"rolling_peak\":{rolling_peak},\"retained_after_drop\":{retained_after_drop}}}"
    );
}
