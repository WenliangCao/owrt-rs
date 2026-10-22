//! Requested Rust heap retained by the real Registry, not process RSS/PSS.
//! The fixture includes object and path indexes plus one shared empty type.
//! Allocator rounding, libc internals, socket buffers and daemon clients are
//! outside this diagnostic. Do not use this instrumented binary for timing.
#![allow(dead_code)]
#[path = "../src/obj.rs"]
mod obj;
#[path = "../src/sys.rs"]
mod sys;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Heap;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

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
            add(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplied a valid layout.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
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

fn path(index: u32, len: usize) -> Vec<u8> {
    let mut bytes = vec![b'x'; len];
    let number = format!("{index:08}");
    bytes[..8].copy_from_slice(number.as_bytes());
    bytes
}

fn main() {
    println!("objects,path_bytes,retained_requested_bytes,construction_peak_requested_bytes");
    // Warm up formatting/HashMap initialization before measuring the fixture.
    drop(path(0, 16));
    drop(obj::Registry::default());
    for len in [16, 64, 256] {
        for count in [1u32, 64, 128, 512] {
            let baseline = LIVE.load(Relaxed);
            PEAK.store(baseline, Relaxed);
            let mut r = obj::Registry::default();
            r.types.insert(
                2048,
                obj::ObjType {
                    refcount: 0,
                    methods: Vec::new(),
                },
            );
            for i in 0..count {
                r.create(Some(2048), Some(4096 + i)).unwrap();
                assert!(r.set_path(4096 + i, &path(i, len)));
            }
            let retained = LIVE.load(Relaxed) - baseline;
            let peak = PEAK.load(Relaxed) - baseline;
            for i in 0..count {
                assert_eq!(r.by_path(&path(i, len)), Some(4096 + i));
            }
            // A path snapshot must remain valid across deletion and index
            // destruction; releasing all owners must return heap to baseline.
            let held = r.get(4096).unwrap().path.clone().unwrap();
            drop(r.destroy(4096).unwrap());
            assert!(r.by_path(&held).is_none());
            assert_eq!(&held[..], path(0, len).as_slice());
            drop(r);
            assert_eq!(&held[..], path(0, len).as_slice());
            drop(held);
            assert_eq!(
                LIVE.load(Relaxed),
                baseline,
                "registry allocations retained after drop"
            );
            println!("{count},{len},{retained},{peak}");
        }
    }
}
