//! Diagnostic companion only. All allocation operations retain System's
//! pointer/layout contract; no allocation header or replacement allocator.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

pub struct Meter;
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
