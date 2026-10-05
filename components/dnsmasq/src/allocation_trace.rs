//! Binary-only diagnostics for actual System allocations. Hooks never allocate.
//!
//! C's allocator wrappers report C call sites and layout; these records report
//! this Rust allocator's actual hook site, layout and pointer identity instead.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

pub const CAPACITY: usize = 4096;
static ENABLED: AtomicBool = AtomicBool::new(false);
static LOST: AtomicU64 = AtomicU64::new(0);
static EVENTS: Mutex<Buffer> = Mutex::new(Buffer {
    entries: [Event::EMPTY; CAPACITY],
    head: 0,
    length: 0,
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Allocate,
    Zeroed,
    Reallocate,
    Free,
}

#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub operation: Operation,
    pub size: usize,
    pub old_pointer: usize,
    pub pointer: usize,
    pub line: u32,
}

impl Event {
    pub const EMPTY: Self = Self {
        operation: Operation::Allocate,
        size: 0,
        old_pointer: 0,
        pointer: 0,
        line: 0,
    };

    pub fn pointer_hash(pointer: usize) -> usize {
        pointer & 0xff_ffff
    }

    /// Formatting belongs to the suspended owner, never to an allocator hook.
    pub fn message(self) -> String {
        let pointer = Self::pointer_hash(self.pointer);
        match self.operation {
            Operation::Allocate | Operation::Zeroed => {
                let function = if self.operation == Operation::Zeroed {
                    "alloc_zeroed"
                } else {
                    "alloc"
                };
                format!(
                    "malloc: allocation_trace::{function}:{} {} bytes at {pointer:x}",
                    self.line, self.size
                )
            }
            Operation::Reallocate => format!(
                "realloc: allocation_trace::realloc:{} {} bytes from {:x} to {pointer:x}",
                self.line,
                self.size,
                Self::pointer_hash(self.old_pointer)
            ),
            Operation::Free => format!(
                "free: allocation_trace::dealloc:{} block at {pointer:x}",
                self.line
            ),
        }
    }
}

struct Buffer {
    entries: [Event; CAPACITY],
    head: usize,
    length: usize,
}

fn record(event: Event) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    // Never wait or call a formatter from GlobalAlloc. The ordinary single
    // owner has no contention; every overflow/contention loss is counted.
    let Ok(mut buffer) = EVENTS.try_lock() else {
        LOST.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if buffer.length == CAPACITY {
        LOST.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let index = (buffer.head + buffer.length) % CAPACITY;
    buffer.entries[index] = event;
    buffer.length += 1;
}

pub fn enable(value: bool) {
    ENABLED.store(value, Ordering::Relaxed);
}

pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// The owner pauses all trace collection while formatting/enqueuing notices,
/// preventing recursive diagnostics about the logger's own allocations.
pub fn suspended<T>(action: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            ENABLED.store(self.0, Ordering::Relaxed);
        }
    }
    let _restore = Restore(ENABLED.swap(false, Ordering::Relaxed));
    action()
}

/// Drain into owner-provided stack storage. No buffer proportional to a heap
/// workload is allocated; the owner can repeat in a bounded service turn.
pub fn drain(output: &mut [Event]) -> (usize, u64) {
    let mut buffer = EVENTS.lock().unwrap_or_else(|error| error.into_inner());
    let count = output.len().min(buffer.length);
    for event in &mut output[..count] {
        *event = buffer.entries[buffer.head];
        buffer.head = (buffer.head + 1) % CAPACITY;
    }
    buffer.length -= count;
    (count, LOST.swap(0, Ordering::Relaxed))
}

struct TraceAllocator;

#[global_allocator]
static ALLOCATOR: TraceAllocator = TraceAllocator;

// SAFETY: every operation preserves System's exact allocator contract. Hooks
// record scalar values in fixed storage and never allocate or block.
unsafe impl GlobalAlloc for TraceAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(Event {
                operation: Operation::Allocate,
                size: layout.size(),
                old_pointer: 0,
                pointer: pointer as usize,
                line: line!(),
            });
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record(Event {
                operation: Operation::Zeroed,
                size: layout.size(),
                old_pointer: 0,
                pointer: pointer as usize,
                line: line!(),
            });
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let replacement = unsafe { System.realloc(pointer, layout, size) };
        if !replacement.is_null() {
            record(Event {
                operation: Operation::Reallocate,
                size,
                old_pointer: pointer as usize,
                pointer: replacement as usize,
                line: line!(),
            });
        }
        replacement
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record(Event {
            operation: Operation::Free,
            size: layout.size(),
            old_pointer: 0,
            pointer: pointer as usize,
            line: line!(),
        });
        unsafe { System.dealloc(pointer, layout) };
    }
}
