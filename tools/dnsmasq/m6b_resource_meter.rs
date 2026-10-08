//! Diagnostic companion only. All allocation operations retain System's
//! pointer/layout contract; no allocation header or replacement allocator.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

pub struct Meter;
// The copied lib-test ELF needs the same meter to exercise registry accounting.
// Normal lib compilation does not declare an allocator; the companion binary
// continues to own its one allocator declaration in main.rs.
#[cfg(test)]
#[global_allocator]
static M6B_RESOURCE_TEST_ALLOC: Meter = Meter;
static LIVE: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static OBJECTS: AtomicI64 = AtomicI64::new(0);
static ALLOC: AtomicU64 = AtomicU64::new(0);
static ZEROED: AtomicU64 = AtomicU64::new(0);
static REALLOC: AtomicU64 = AtomicU64::new(0);
static FREE: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);
static BALANCE_ERRORS: AtomicU64 = AtomicU64::new(0);
static OBSERVER_SCOPE: AtomicU64 = AtomicU64::new(0);
static OBSERVER_LIVE: AtomicI64 = AtomicI64::new(0);

/// Only the root registry's own allocations/frees occur in this scope. Its
/// payloads are plain scalars, not product-owned Arc/Vec objects. No scope may
/// cross callbacks, I/O, threads, or return an allocated object to product code.
pub struct ObserverScope;
impl ObserverScope {
    pub fn enter() -> Self { OBSERVER_SCOPE.fetch_add(1, Relaxed); Self }
}
impl Drop for ObserverScope {
    fn drop(&mut self) { OBSERVER_SCOPE.fetch_sub(1, Relaxed); }
}

fn bytes(delta: i64) {
    if OBSERVER_SCOPE.load(Relaxed) != 0 {
        if OBSERVER_LIVE.fetch_add(delta, Relaxed) + delta < 0 { BALANCE_ERRORS.fetch_add(1, Relaxed); }
    }
    let live = LIVE.fetch_add(delta, Relaxed) + delta;
    if live < 0 { BALANCE_ERRORS.fetch_add(1, Relaxed); }
    else { PEAK.fetch_max(live as u64, Relaxed); }
}

// SAFETY: every entry point forwards exactly its original pointer and Layout
// to System. The only extra work is nonallocating atomic accounting; no locks,
// logging, TLS, formatting or fallible container operations run in these hooks.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the GlobalAlloc caller supplies a valid nonzero Layout.
        let result = unsafe { System.alloc(layout) };
        if result.is_null() { FAILED.fetch_add(1, Relaxed); }
        else { bytes(layout.size() as i64); OBJECTS.fetch_add(1, Relaxed); ALLOC.fetch_add(1, Relaxed); }
        result
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: valid nonzero Layout is forwarded unchanged; System retains
        // its zero-initialization guarantee and no bytes are inspected here.
        let result = unsafe { System.alloc_zeroed(layout) };
        if result.is_null() { FAILED.fetch_add(1, Relaxed); }
        else { bytes(layout.size() as i64); OBJECTS.fetch_add(1, Relaxed); ZEROED.fetch_add(1, Relaxed); }
        result
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: the caller's live System allocation, matching old Layout and
        // valid new size are forwarded unchanged. Null retains the old block.
        let result = unsafe { System.realloc(pointer, layout, size) };
        if result.is_null() { FAILED.fetch_add(1, Relaxed); }
        else { bytes(size as i64 - layout.size() as i64); REALLOC.fetch_add(1, Relaxed); }
        result
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: pointer is live and was allocated by the forwarded System
        // implementation with exactly this Layout; it is freed exactly once.
        unsafe { System.dealloc(pointer, layout) };
        bytes(-(layout.size() as i64)); OBJECTS.fetch_sub(1, Relaxed); FREE.fetch_add(1, Relaxed);
    }
}

#[derive(Clone, Copy)]
pub struct Allocation {
    pub live: i64, pub observer_live: i64, pub peak: u64, pub objects: i64,
    pub alloc: u64, pub zeroed: u64, pub realloc: u64, pub free: u64,
    pub failed: u64, pub balance_errors: u64,
}
pub fn allocation() -> Allocation {
    Allocation { live: LIVE.load(Relaxed), observer_live: OBSERVER_LIVE.load(Relaxed),
        peak: PEAK.load(Relaxed), objects: OBJECTS.load(Relaxed),
        alloc: ALLOC.load(Relaxed), zeroed: ZEROED.load(Relaxed), realloc: REALLOC.load(Relaxed),
        free: FREE.load(Relaxed), failed: FAILED.load(Relaxed), balance_errors: BALANCE_ERRORS.load(Relaxed) }
}

const DRAIN_SECONDS: [u64; 5] = [0, 1, 5, 15, 60];
struct Trace {
    file: File, origin: Instant, next: Instant, was_busy: bool,
    drain: Option<Instant>, drain_index: usize, epoch: u64,
}
thread_local! { static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) }; }

/// Set in the companion namespace only, to a fresh regular file in its overlay.
pub fn init() -> io::Result<()> {
    let path = std::env::var_os("DNSMASQ_M6B_RESOURCE_TRACE")
        .ok_or_else(|| io::Error::other("diagnostic trace path is required"))?;
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if !file.metadata()?.is_file() { return Err(io::Error::other("diagnostic trace must be regular")); }
    let now = Instant::now();
    TRACE.with(|trace| {
        *trace.try_borrow_mut().map_err(|_| io::Error::other("diagnostic trace borrowed"))? =
            Some(Trace { file, origin: now, next: now, was_busy: false,
                drain: None, drain_index: 0, epoch: 0 });
        Ok(())
    })
}

pub fn deadline(fallback: Instant) -> Instant {
    TRACE.with(|trace| trace.try_borrow().ok().and_then(|trace| trace.as_ref().map(|trace| {
        let drain = trace.drain.and_then(|start| DRAIN_SECONDS.get(trace.drain_index)
            .map(|seconds| start + Duration::from_secs(*seconds)));
        drain.map_or(trace.next, |due| due.min(trace.next)).min(fallback)
    })).unwrap_or(fallback))
}

#[derive(Clone, Copy)]
pub struct Stamp {
    pub elapsed_ns: u128, pub epoch: u64, pub nominal_drain_second: Option<u64>,
    pub actual_drain_ns: Option<u128>,
}

/// A new workload cancels unfinished drain points. Every row retains actual
/// monotonic elapsed time; a late wake is never relabelled as an exact target.
pub fn sample(drained: bool) -> io::Result<Option<Stamp>> {
    TRACE.with(|trace| {
        let mut trace = trace.try_borrow_mut().map_err(|_| io::Error::other("diagnostic trace borrowed"))?;
        let trace = trace.as_mut().ok_or_else(|| io::Error::other("diagnostic trace not initialized"))?;
        let now = Instant::now();
        if !drained { trace.was_busy = true; trace.drain = None; trace.drain_index = 0; }
        else if trace.was_busy {
            trace.was_busy = false; trace.drain = Some(now); trace.drain_index = 0; trace.epoch += 1;
        }
        let nominal = trace.drain.and_then(|start| DRAIN_SECONDS.get(trace.drain_index)
            .copied().filter(|seconds| now >= start + Duration::from_secs(*seconds)));
        if now < trace.next && nominal.is_none() { return Ok(None); }
        if nominal.is_some() { trace.drain_index += 1; }
        trace.next = now + Duration::from_secs(1);
        Ok(Some(Stamp { elapsed_ns: now.duration_since(trace.origin).as_nanos(), epoch: trace.epoch,
            nominal_drain_second: nominal, actual_drain_ns: trace.drain.map(|start| now.duration_since(start).as_nanos()) }))
    })
}

pub fn emit(arguments: std::fmt::Arguments<'_>) -> io::Result<()> {
    TRACE.with(|trace| {
        let mut trace = trace.try_borrow_mut().map_err(|_| io::Error::other("diagnostic trace borrowed"))?;
        let trace = trace.as_mut().ok_or_else(|| io::Error::other("diagnostic trace not initialized"))?;
        trace.file.write_fmt(arguments)?;
        trace.file.write_all(b"\n")
    })
}

#[cfg(test)]
mod m6b_controls {
    use super::*;

    #[test]
    fn system_operations_and_known_live_object() {
        let baseline = allocation();
        let layout = Layout::from_size_align(64, 8).unwrap();
        // SAFETY: this test uses a valid nonzero Layout, checks the returned
        // pointer, and retains the matching Layout for every operation.
        let pointer = unsafe { Meter.alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        for index in 0..64 {
            // SAFETY: the allocation contains exactly 64 initialized bytes.
            assert_eq!(unsafe { *pointer.add(index) }, 0);
        }
        let held = allocation();
        assert_eq!(held.live - baseline.live, 64, "known undropped object must be visible");
        assert_eq!(held.objects - baseline.objects, 1);
        assert_eq!(held.observer_live, baseline.observer_live, "product object is outside observer scope");
        // SAFETY: pointer is live under layout and 128 is a valid new size.
        let resized = unsafe { Meter.realloc(pointer, layout, 128) };
        assert!(!resized.is_null());
        let expanded = allocation();
        assert_eq!(expanded.live - baseline.live, 128);
        assert_eq!(expanded.objects - baseline.objects, 1);
        // SAFETY: successful realloc now owns 128 bytes with the same alignment.
        unsafe { Meter.dealloc(resized, Layout::from_size_align(128, 8).unwrap()); }
        let released = allocation();
        assert_eq!(released.live, baseline.live);
        assert_eq!(released.objects, baseline.objects);
        assert_eq!(released.balance_errors, baseline.balance_errors);
    }

    #[test]
    fn failed_realloc_retains_old_object_and_balance() {
        let layout = Layout::from_size_align(64, 8).unwrap();
        // SAFETY: valid Layout; the result is checked before accessing it.
        let pointer = unsafe { Meter.alloc(layout) };
        assert!(!pointer.is_null());
        // SAFETY: the first byte belongs to this live 64-byte allocation.
        unsafe { *pointer = 0x5a; }
        let held = allocation();
        // Half isize::MAX is Layout-valid but cannot fit in Linux's user
        // address space on this 64-bit target. Null leaves the old block live.
        // SAFETY: matching live allocation and valid nonzero new size.
        let result = unsafe { Meter.realloc(pointer, layout, isize::MAX as usize / 2) };
        assert!(result.is_null(), "this control requires a genuine failed System realloc");
        let failed = allocation();
        assert_eq!(failed.live, held.live);
        assert_eq!(failed.objects, held.objects);
        assert_eq!(failed.failed, held.failed + 1);
        // SAFETY: failed realloc retained pointer/layout and its contents.
        assert_eq!(unsafe { *pointer }, 0x5a);
        // SAFETY: retained live pointer is freed once under its original Layout.
        unsafe { Meter.dealloc(pointer, layout); }
    }

    #[test]
    fn registry_scope_reserve_grow_and_drop_balance() {
        let before = allocation();
        {
            let _scope = ObserverScope::enter();
            let mut values = std::collections::HashMap::with_capacity(1);
            for key in 0..1024usize { values.insert(key, key); }
            let populated = allocation();
            assert!(populated.observer_live > before.observer_live);
            values.clear();
            values.shrink_to_fit();
        }
        let after = allocation();
        assert_eq!(after.observer_live, before.observer_live);
        assert_eq!(after.live, before.live);
        assert_eq!(after.objects, before.objects);
        assert_eq!(after.balance_errors, before.balance_errors);
        assert_eq!(OBSERVER_SCOPE.load(Relaxed), 0);
    }
}
