//! Diagnostic-only requested-live heap accounting; not allocator footprint.
#![allow(dead_code)]
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Heap;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);

fn add(bytes: usize) {
    let now = LIVE.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(now, Relaxed);
}

// SAFETY: every operation forwards the caller's allocation and layout to
// System unchanged. Atomic accounting neither allocates nor dereferences it.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplied a valid layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOCS.fetch_add(1, Relaxed);
            add(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplied a valid layout.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            ALLOCS.fetch_add(1, Relaxed);
            add(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        // SAFETY: forward the original live allocation and its layout.
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: forward the caller's valid allocation, layout and new size.
        let next = unsafe { System.realloc(ptr, layout, size) };
        if !next.is_null() {
            REALLOCS.fetch_add(1, Relaxed);
            if size >= layout.size() {
                add(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Relaxed);
            }
        }
        next
    }
}

#[global_allocator]
static ALLOCATOR: Heap = Heap;

pub fn live() -> usize {
    LIVE.load(Relaxed)
}
pub fn reset_peak() {
    PEAK.store(live(), Relaxed);
}
pub fn peak() -> usize {
    PEAK.load(Relaxed)
}
pub fn reset_calls() {
    ALLOCS.store(0, Relaxed);
    REALLOCS.store(0, Relaxed);
}
pub fn calls() -> (usize, usize) {
    (ALLOCS.load(Relaxed), REALLOCS.load(Relaxed))
}
