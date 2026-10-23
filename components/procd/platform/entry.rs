//! Trusted process startup: register fixed child operations and adopt WDTFD.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

fn main() {
    use owrt_platform::procd::{process::Process, watchdog::take_inherited_watchdog};
    use owrt_platform::process_owner::ProcessOwner;
    use owrt_procd::startup::{self, Startup};

    // No business code or descriptor creation runs before the inherited handover.
    // The pinned Rust 1.98.1 Unix runtime initializes standard streams, signals,
    // stack mappings and args, but retains no descriptor >= 3. Re-audit rt.rs,
    // sys/pal/unix/mod.rs and stack_overflow.rs on toolchain changes.
    // The standalone -h mode does not consume the watchdog environment in C.
    let hotplug_only = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .windows(2)
        .any(|args| args[0] == "-h");
    let inherited_watchdog = if hotplug_only {
        None
    } else {
        // SAFETY: this sole startup thread has created no application descriptor
        // owner; the pinned runtime retains no FD >= 3. Preinit transfers its one
        // live reference across exec. Standard slots are rejected by the boundary.
        // Consume once before any application can own or reuse the descriptor.
        unsafe { take_inherited_watchdog(startup::inherited_fd_number) }
    };
    let owner = ProcessOwner::acquire().unwrap_or_else(|error| {
        eprintln!("procd: cannot acquire process ownership: {error}");
        std::process::exit(1);
    });
    // SAFETY: these fixed callbacks only operate on owned strings/scalars and
    // the fixed procd logger/NSS paths. None starts threads, borrows a parent
    // descriptor owner, invokes user callbacks or retains shared mutable data.
    // The platform rechecks exclusivity at every actual spawn/fork operation.
    let process = unsafe {
        Process::new(
            owner,
            startup::cgroup_warning,
            startup::apply_limit,
            startup::transfer_firmware,
        )
    };
    owrt_procd::run(Startup {
        process,
        inherited_watchdog,
    });
}
