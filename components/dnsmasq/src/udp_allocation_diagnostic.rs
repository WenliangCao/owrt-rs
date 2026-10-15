//! Excluded diagnostic build only: count complete normal-owner UDP steps.
//! Never use this artifact for timing or install it as the production daemon.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

pub struct Meter;
// Successful alloc, standalone dealloc, successful realloc, requested bytes,
// released bytes. Realloc contributes its new/old sizes to the byte counters.
static COUNTS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
static KIND: AtomicUsize = AtomicUsize::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static NESTED: AtomicU64 = AtomicU64::new(0);
static QUERIES: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
static TOTALS: [[AtomicU64; 5]; 5] = [const { [const { AtomicU64::new(0) }; 5] }; 5];
static TURNS: [[AtomicU64; 7]; 3] = [const { [const { AtomicU64::new(0) }; 7] }; 3];
static HIT_ALLOCATION_HISTOGRAM: [AtomicU64; 65] = [const { AtomicU64::new(0) }; 65];

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Kind { Empty = 0, OtherPacket = 1, Local = 2, Cached = 3, Stale = 4 }

unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            COUNTS[0].fetch_add(1, Relaxed);
            COUNTS[3].fetch_add(layout.size() as u64, Relaxed);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        COUNTS[1].fetch_add(1, Relaxed);
        COUNTS[4].fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(pointer, layout, size) };
        if !next.is_null() {
            COUNTS[2].fetch_add(1, Relaxed);
            COUNTS[3].fetch_add(size as u64, Relaxed);
            COUNTS[4].fetch_add(layout.size() as u64, Relaxed);
        }
        next
    }
}

fn snapshot() -> [u64; 5] { std::array::from_fn(|i| COUNTS[i].load(Relaxed)) }

pub fn classify(kind: Kind) { KIND.store(kind as usize, Relaxed); }

pub struct Step {
    before: [u64; 5],
    previous_kind: usize,
}
impl Step {
    pub fn new() -> Self {
        if DEPTH.fetch_add(1, Relaxed) != 0 { NESTED.fetch_add(1, Relaxed); }
        let previous_kind = KIND.swap(Kind::Empty as usize, Relaxed);
        Self { before: snapshot(), previous_kind }
    }
}
impl Drop for Step {
    fn drop(&mut self) {
        let after = snapshot();
        let kind = KIND.swap(self.previous_kind, Relaxed);
        QUERIES[kind].fetch_add(1, Relaxed);
        for i in 0..5 { TOTALS[kind][i].fetch_add(after[i] - self.before[i], Relaxed); }
        if kind == Kind::Cached as usize {
            HIT_ALLOCATION_HISTOGRAM[(after[0] - self.before[0]).min(64) as usize].fetch_add(1, Relaxed);
        }
        DEPTH.fetch_sub(1, Relaxed);
    }
}

// Complement step counts with the whole normal-owner turn, including poll,
// file/control work, and the speculative empty receive. Pure cached turns
// carry a query denominator; mixed/empty turns remain separate.
pub struct Turn {
    before: [u64; 5],
    queries: [u64; 5],
}
impl Turn {
    pub fn new() -> Self {
        Self { before: snapshot(), queries: std::array::from_fn(|i| QUERIES[i].load(Relaxed)) }
    }
}
impl Drop for Turn {
    fn drop(&mut self) {
        let after = snapshot();
        let queries = std::array::from_fn::<_, 5, _>(|i| QUERIES[i].load(Relaxed) - self.queries[i]);
        let cached = queries[Kind::Cached as usize];
        let other = queries[1] + queries[2] + queries[4];
        let kind = if cached != 0 && other == 0 { 1 } else if cached + other == 0 { 0 } else { 2 };
        TURNS[kind][0].fetch_add(1, Relaxed);
        TURNS[kind][1].fetch_add(cached, Relaxed);
        for i in 0..5 { TURNS[kind][i + 2].fetch_add(after[i] - self.before[i], Relaxed); }
    }
}

pub fn write_report() -> std::io::Result<()> {
    use std::io::Write;
    let Some(path) = std::env::var_os("DNSMASQ_UDP_ALLOC_OUT") else { return Ok(()) };
    // Take all values before output allocation/I/O, outside any measured step.
    let queries = std::array::from_fn::<_, 5, _>(|i| QUERIES[i].load(Relaxed));
    let totals = std::array::from_fn::<_, 5, _>(|i| {
        std::array::from_fn::<_, 5, _>(|j| TOTALS[i][j].load(Relaxed))
    });
    let histogram = std::array::from_fn::<_, 65, _>(|i| HIT_ALLOCATION_HISTOGRAM[i].load(Relaxed));
    let nested = NESTED.load(Relaxed);
    let turns = std::array::from_fn::<_, 3, _>(|i| {
        std::array::from_fn::<_, 7, _>(|j| TURNS[i][j].load(Relaxed))
    });
    let mut file = std::fs::File::create(path)?;
    writeln!(file, "{{\"scope\":\"count-only diagnostic, not timing; complete step_udp including receive/admission/process/send and owned drops; single-thread UDP workload required; startup/wait/control work outside step excluded\",\"kinds\":[\"no_packet_or_error\",\"other_packet\",\"local\",\"cached\",\"stale\"],\"columns\":[\"alloc\",\"dealloc\",\"realloc\",\"requested_bytes\",\"released_bytes\"],\"queries\":{queries:?},\"totals\":{totals:?},\"cached_allocation_histogram_64_is_overflow\":{histogram:?},\"nested_steps\":{nested},\"turn_kinds\":[\"no_packet\",\"cached_only\",\"mixed_or_other\"],\"turn_columns\":[\"turns\",\"cached_queries\",\"alloc\",\"dealloc\",\"realloc\",\"requested_bytes\",\"released_bytes\"],\"whole_owner_turns\":{turns:?}}}")
}
