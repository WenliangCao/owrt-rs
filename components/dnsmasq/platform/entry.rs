//! The executable owns registration of its fixed process workers.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[path = "../src/main.rs"]
mod daemon;
// The libtest build typechecks these fixtures; only the standalone process
// adapter executes them, so no fork is introduced into a libtest worker.
#[cfg(all(test, feature = "process-test-support"))]
#[doc(hidden)]
pub use daemon::run_process_tests;
#[cfg(target_os = "linux")]
mod register;

fn main() {
    #[cfg(target_os = "linux")]
    register::workers();
    daemon::main();
}
