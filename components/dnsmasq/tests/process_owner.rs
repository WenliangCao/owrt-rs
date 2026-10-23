//! Reuse owner fixtures from the platform standalone test entry.
#![forbid(unsafe_code)]
// The included daemon contains other tests and their fixtures. Their #[test]
// entry points are absent in this harness; they remain checked by normal tests.
#[allow(
    dead_code,
    unused_imports,
    reason = "the standalone runner includes the complete daemon and only invokes process fixtures"
)]
#[path = "../src/main.rs"]
mod daemon;

pub fn run() {
    daemon::run_process_tests();
}
