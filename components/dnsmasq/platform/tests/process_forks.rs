//! Standalone platform entry for the fork fixtures, without libtest threads.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[path = "../../tests/process_forks.rs"]
mod fixtures;
mod panic_hook;
#[path = "../register.rs"]
mod register;

fn main() {
    fixtures::unregistered_workers_are_rejected();
    register::workers();
    fixtures::run();
    panic_hook::run();
}
