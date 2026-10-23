//! Standalone platform entry for process-owning event-loop fixtures.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[path = "../../tests/process_owner.rs"]
mod fixtures;
#[path = "../register.rs"]
mod register;

fn main() {
    register::workers();
    fixtures::run();
}
