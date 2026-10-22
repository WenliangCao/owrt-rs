//! Exercise process setup on main, with no libtest worker or concurrent fixture.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

macro_rules! log {
    ($prio:expr, $($arg:tt)*) => { crate::sys::ulog($prio, &format!($($arg)*)) };
}
macro_rules! debug {
    ($level:expr, $($arg:tt)*) => {
        if crate::sys::debug_level() >= $level {
            crate::sys::ulog(crate::sys::LOG_NOTICE, &format!($($arg)*))
        }
    };
}

// Reuse the production modules. Their unrelated functions and unit-test
// imports are checked under the daemon root, not invoked by this runner.
#[allow(
    dead_code,
    unused_imports,
    reason = "shared production module used by the standalone process fixtures"
)]
#[path = "../src/instance.rs"]
mod instance;
#[allow(
    dead_code,
    unused_imports,
    reason = "shared production module used by the standalone process fixtures"
)]
#[path = "../src/proc.rs"]
mod proc;
#[path = "process/proc.rs"]
mod proc_tests;
#[allow(
    dead_code,
    unused_imports,
    reason = "shared production module used by the standalone process fixtures"
)]
#[path = "../src/sys.rs"]
mod sys;
#[allow(
    dead_code,
    unused_imports,
    reason = "shared production module used by the standalone process fixtures"
)]
#[path = "../src/watchdog.rs"]
mod watchdog;
#[path = "process/watchdog.rs"]
mod watchdog_tests;

fn main() {
    let threads = std::fs::read_dir("/proc/self/task").unwrap().count();
    assert_eq!(
        threads, 1,
        "fork fixtures must run on the sole process thread"
    );
    #[expect(
        unsafe_code,
        reason = "main establishes the single-threaded fork and handover contract"
    )]
    // SAFETY: main starts no threads, holds no application lock and registers
    // no atfork callback. Each fixture owns/reaps its children and descriptors.
    unsafe {
        proc_tests::run();
        watchdog_tests::run();
    }
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    eprintln!("process ownership tests: 5 passed; threads=1");
}
