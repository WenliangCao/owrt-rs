//! Trusted adapter for process fixtures; assertions stay in safe test modules.
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
#[path = "../tests/process/proc.rs"]
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
#[path = "../tests/process/watchdog.rs"]
mod watchdog_tests;

#[path = "../tests/process_owner.rs"]
mod owner_tests;

fn main() {
    use owrt_platform::process_owner::ProcessOwner;
    use std::os::fd::IntoRawFd;
    let owner = ProcessOwner::acquire().unwrap();
    for raw in 0..=2 {
        let standard = match raw {
            0 => rustix::stdio::stdin(),
            1 => rustix::stdio::stdout(),
            _ => rustix::stdio::stderr(),
        };
        let before = rustix::io::fcntl_getfd(standard).unwrap();
        owner
            .set_var(
                std::ffi::OsStr::new("WDTFD"),
                std::ffi::OsStr::new(&raw.to_string()),
            )
            .unwrap();
        // SAFETY: standard slots are rejected before adoption. This sole thread
        // owns the environment operation and no descriptor ownership is assumed.
        let rejected =
            unsafe { owrt_platform::procd::watchdog::take_inherited_watchdog(sys::atoi_u32) };
        assert_eq!(rejected.unwrap().unwrap_err().raw_os_error(), Some(9));
        assert!(std::env::var_os("WDTFD").is_none());
        assert_eq!(rustix::io::fcntl_getfd(standard).unwrap(), before);
    }
    eprintln!("startup standard descriptor rejection: 3 cases passed");
    let (reader, writer) = rustix::pipe::pipe_with(
        rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
    )
    .unwrap();
    let transferred = rustix::io::fcntl_dupfd_cloexec(&writer, 1000).unwrap();
    drop(writer);
    rustix::io::fcntl_setfd(&transferred, rustix::io::FdFlags::empty()).unwrap();
    let raw = transferred.into_raw_fd();
    owner
        .set_var(
            std::ffi::OsStr::new("WDTFD"),
            std::ffi::OsStr::new(&raw.to_string()),
        )
        .unwrap();
    // SAFETY: into_raw_fd above relinquished the only owner of this high fd.
    // Startup has one thread; consume exactly that handover before fixture code.
    let handover =
        unsafe { owrt_platform::procd::watchdog::take_inherited_watchdog(sys::atoi_u32) }
            .unwrap()
            .unwrap();
    fn warning(context: &str, error: &std::io::Error) {
        sys::ulog(sys::LOG_WARNING, &format!("{context}: {error}"));
    }
    fn firmware(_: owrt_platform::procd::process::FirmwareRequest) {}
    // SAFETY: fixed logger/rlimit callbacks match production and do not create
    // threads or touch abandoned owners. The fixture firmware callback is inert.
    let process = unsafe {
        owrt_platform::procd::process::Process::new(owner, warning, sys::apply_limit, firmware)
    };
    owner_tests::run(&process, reader, handover);
}
