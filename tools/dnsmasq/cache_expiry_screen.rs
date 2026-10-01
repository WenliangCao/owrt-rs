//! Generated module paths select an immutable B0 or EPS1 source snapshot.
//! The driver is Linux/64-bit only; allocation instrumentation is a separate
//! build and never participates in a timed result.
/* CACHE_MODULES */

use cache::{Cache, Kind, Policy, Record};
use std::io::{self, BufRead};
use std::time::Instant;

#[cfg(allocation_tracking)]
mod allocation {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
    pub struct Meter;
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static REALLOCS: AtomicU64 = AtomicU64::new(0);
    static BYTES: AtomicU64 = AtomicU64::new(0);
    static LIVE: AtomicI64 = AtomicI64::new(0);
    static PEAK: AtomicI64 = AtomicI64::new(0);
    fn allocated(size: usize, change: i64) {
        BYTES.fetch_add(size as u64, Relaxed);
        let live = LIVE.fetch_add(change, Relaxed) + change;
        PEAK.fetch_max(live, Relaxed);
    }
    // System receives exactly the allocator's original pointer/layout. Update
    // counters only after a successful allocation; a failed realloc retains
    // ownership and the old live-byte count. Counter operations cannot allocate.
    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                CALLS.fetch_add(1, Relaxed);
                allocated(layout.size(), layout.size() as i64);
            }
            pointer
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            LIVE.fetch_sub(layout.size() as i64, Relaxed);
            unsafe { System.dealloc(pointer, layout) };
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let replacement = unsafe { System.realloc(pointer, layout, size) };
            if !replacement.is_null() {
                REALLOCS.fetch_add(1, Relaxed);
                allocated(size, size as i64 - layout.size() as i64);
            }
            replacement
        }
    }
    pub fn snapshot() -> [i64; 5] {
        [
            CALLS.load(Relaxed) as i64,
            REALLOCS.load(Relaxed) as i64,
            BYTES.load(Relaxed) as i64,
            LIVE.load(Relaxed),
            PEAK.load(Relaxed),
        ]
    }
    pub fn reset_peak() {
        PEAK.store(LIVE.load(Relaxed), Relaxed);
    }
}

#[cfg(allocation_tracking)]
#[global_allocator]
static ALLOCATOR: allocation::Meter = allocation::Meter;

#[repr(C)]
struct Timespec {
    seconds: i64,
    nanos: i64,
}
unsafe extern "C" {
    fn clock_gettime(clock: i32, value: *mut Timespec) -> i32;
}
fn cpu_ns() -> u64 {
    let mut value = Timespec {
        seconds: 0,
        nanos: 0,
    };
    // Linux 64-bit timespec has two signed 64-bit fields. CLOCK_PROCESS_CPUTIME_ID
    // is 2. The pointer is valid/writable for that entire structure and call.
    assert_eq!(unsafe { clock_gettime(2, &mut value) }, 0);
    (value.seconds as u64) * 1_000_000_000 + value.nanos as u64
}

struct Operation {
    phase: u8,
    name: wire::Name,
    kind: Kind,
    ttl: u32,
    data: Vec<u8>,
    negative: bool,
    now: i64,
}

fn parse(line: &str) -> Operation {
    let fields: Vec<_> = line.split_whitespace().collect();
    assert_eq!(fields.len(), 7);
    let kind = match fields[2] {
        "1" => Kind::Ipv4,
        "28" => Kind::Ipv6,
        "65536" => Kind::NxDomain,
        _ => panic!("unexpected vector type"),
    };
    let value: u32 = fields[4].parse().unwrap();
    let mut data = match kind {
        Kind::Ipv4 => vec![0; 4],
        Kind::Ipv6 => vec![0; 16],
        _ => Vec::new(),
    };
    if !data.is_empty() {
        data[..4].copy_from_slice(&value.to_ne_bytes());
    }
    Operation {
        phase: fields[0].as_bytes()[0],
        name: wire::Name::from_ascii(fields[1]).unwrap(),
        kind,
        ttl: fields[3].parse().unwrap(),
        data,
        negative: fields[5] == "1",
        now: fields[6].parse().unwrap(),
    }
}

fn apply(cache: &mut Cache, operation: &Operation) -> [u64; 10] {
    let found = cache.lookup(&operation.name, &[operation.kind], operation.now, false);
    let mut event = [0; 10];
    event[0] = u64::from(!found.is_empty());
    event[3] = found.len() as u64;
    let mut id = found.first().copied();
    drop(found);
    if id.is_none() {
        cache.start_insert();
        id = cache
            .insert(
                Record {
                    name: operation.name.clone(),
                    kind: operation.kind,
                    negative: operation.negative,
                    data: operation.data.clone(),
                },
                operation.now,
                operation.ttl,
            )
            .ok();
        event[1] = u64::from(id.is_some());
        event[2] = u64::from(cache.commit());
        event[3] = u64::from(id.is_some() && event[2] == 1);
    }
    if let Some(entry) = id.and_then(|id| cache.get(id)) {
        event[4] = match entry.record.kind {
            Kind::Ipv4 => 1,
            Kind::Ipv6 => 28,
            Kind::NxDomain => 65536,
            _ => panic!("unexpected returned type"),
        };
        event[5] = if entry.record.data.is_empty() {
            0
        } else {
            u32::from_ne_bytes(entry.record.data[..4].try_into().unwrap()) as u64
        };
        event[6] = u64::from(entry.record.negative);
        event[7] = entry.expires as u64;
        event[8] = entry.reply_ttl(operation.now, cache.policy()) as u64;
        event[9] = u64::from(entry.is_stale(operation.now));
    }
    event
}

struct Stats {
    count: u64,
    hits: u64,
    inserts: u64,
    errors: u64,
    digest: u64,
}
impl Stats {
    fn new() -> Self {
        Self {
            count: 0,
            hits: 0,
            inserts: 0,
            errors: 0,
            digest: 14695981039346656037,
        }
    }
    fn record(&mut self, event: [u64; 10]) {
        self.count += 1;
        self.hits += event[0];
        self.inserts += event[1];
        self.errors +=
            u64::from(event[3] != 1 || (event[0] == 0 && (event[1] != 1 || event[2] != 1)));
        for field in event {
            self.digest = (self.digest ^ field).wrapping_mul(1099511628211);
        }
    }
}

#[cfg(allocation_tracking)]
fn stress() {
    use lease_names::{ForwardPublication, PublicationCache};
    let early = wire::Name::from_ascii("early.test").unwrap();
    let late = wire::Name::from_ascii("late.test").unwrap();
    let pending = wire::Name::from_ascii("pending.test").unwrap();
    let poison = wire::Name::from_ascii("poison.test").unwrap();
    let record = |name: &wire::Name| Record {
        name: name.clone(),
        kind: Kind::Ipv4,
        negative: false,
        data: vec![1, 0, 0, 0],
    };
    let before = allocation::snapshot();
    allocation::reset_peak();
    let mut cache = Cache::new(1000, Policy::default());
    for iteration in 0..2000 {
        let now = 100 + iteration;
        cache.start_insert();
        cache.insert(record(&early), now, 1).unwrap();
        assert!(cache.commit());
        cache.prepare_name(ForwardPublication {
            name: b"early.test",
            no_round_robin: true,
            blockers: &[],
        });
        assert!(cache.lookup(&early, &[Kind::Ipv4], now, false).is_empty());
        cache.start_insert();
        cache.insert(record(&late), now, 120).unwrap();
        assert!(cache.commit());
        cache.start_insert();
        cache.insert(record(&pending), now, 1).unwrap();
        assert!(cache.insert(record(&poison), now, 0).is_err());
        assert!(!cache.commit());
        cache.start_insert();
        assert!(cache.lookup(&pending, &[Kind::Ipv4], now, false).is_empty());
        cache.clear();
        assert!(cache.lookup(&late, &[Kind::Ipv4], now, false).is_empty());
        cache.start_insert();
        let id = cache.insert(record(&early), now, 1).unwrap();
        assert!(cache.commit());
        assert_eq!(cache.get(id).unwrap().expires, now + 1);
        cache.clear();
        assert!(cache.lookup(&early, &[Kind::Ipv4], now, false).is_empty());
    }
    let finished = allocation::snapshot();
    drop(cache);
    let dropped = allocation::snapshot();
    println!("{{\"iterations\":2000,\"absence_checks\":8000,\"expiry_checks\":2000,\"before\":{:?},\"finished\":{:?},\"dropped\":{:?},\"cache_layout\":{},\"entry_layout\":{}}}",
        before,finished,dropped,std::mem::size_of::<Cache>(),std::mem::size_of::<cache::Entry>());
}

fn main() {
    assert!(cfg!(all(target_os = "linux", target_pointer_width = "64")));
    let args: Vec<_> = std::env::args().collect();
    #[cfg(allocation_tracking)]
    if args.get(1).is_some_and(|argument| argument == "stress") {
        stress();
        return;
    }
    let mode = args.get(2).map_or("trace", String::as_str);
    let input = std::fs::File::open(&args[1]).unwrap();
    let operations: Vec<_> = io::BufReader::new(input)
        .lines()
        .map(|line| parse(&line.unwrap()))
        .collect();
    let first_timed = operations
        .iter()
        .position(|operation| operation.phase == b'T')
        .unwrap();
    assert!(operations[first_timed..]
        .iter()
        .all(|operation| operation.phase == b'T'));
    assert_eq!(operations.len() - first_timed, 100_000);
    assert_eq!(mode == "alloc", cfg!(allocation_tracking));
    #[cfg(allocation_tracking)]
    let before = allocation::snapshot();
    #[cfg(allocation_tracking)]
    allocation::reset_peak();
    let mut cache = Cache::new(1000, Policy::default());
    let mut warm = Stats::new();
    for operation in &operations[..first_timed] {
        let event = apply(&mut cache, operation);
        if operation.phase == b'W' {
            warm.record(event);
        }
    }
    assert_eq!(warm.count, 100_000);
    #[cfg(allocation_tracking)]
    let warmed = allocation::snapshot();
    let mut stats = Stats::new();
    let wall_start = (mode == "timing").then(Instant::now);
    let cpu_start = (mode == "timing").then(cpu_ns);
    for operation in &operations[first_timed..] {
        let event = apply(&mut cache, operation);
        stats.record(event);
        if mode == "trace" {
            println!(
                "{} {} {} {} {} {} {} {} {} {}",
                event[0],
                event[1],
                event[2],
                event[3],
                event[4],
                event[5],
                event[6],
                event[7],
                event[8],
                event[9]
            );
        }
    }
    let cpu_elapsed = cpu_start.map_or(0, |start| cpu_ns() - start);
    let wall_elapsed = wall_start.map_or(0, |start| start.elapsed().as_nanos());
    #[cfg(allocation_tracking)]
    let finished = allocation::snapshot();
    drop(cache);
    #[cfg(allocation_tracking)]
    let dropped = allocation::snapshot();
    if mode == "trace" {
        eprintln!("SCREEN_STATS {{\"completed\":{},\"hits\":{},\"inserts\":{},\"errors\":{},\"digest\":{},\"warm_digest\":{}}}",
            stats.count,stats.hits,stats.inserts,stats.errors,stats.digest,warm.digest);
    } else {
        #[cfg(not(allocation_tracking))]
        println!("{{\"completed\":{},\"hits\":{},\"inserts\":{},\"errors\":{},\"digest\":{},\"warm_digest\":{},\"cpu_ns\":{},\"wall_ns\":{},\"cache_layout\":{},\"entry_layout\":{}}}",
            stats.count,stats.hits,stats.inserts,stats.errors,stats.digest,warm.digest,cpu_elapsed,wall_elapsed,
            std::mem::size_of::<Cache>(),std::mem::size_of::<cache::Entry>());
        #[cfg(allocation_tracking)]
        println!("{{\"completed\":{},\"hits\":{},\"inserts\":{},\"errors\":{},\"digest\":{},\"warm_digest\":{},\"before\":{:?},\"warmed\":{:?},\"finished\":{:?},\"dropped\":{:?},\"cache_layout\":{},\"entry_layout\":{}}}",
            stats.count,stats.hits,stats.inserts,stats.errors,stats.digest,warm.digest,before,warmed,finished,dropped,
            std::mem::size_of::<Cache>(),std::mem::size_of::<cache::Entry>());
    }
}
