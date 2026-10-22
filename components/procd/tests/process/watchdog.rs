//! Existing watchdog handover assertions run without environment-reading peers.
use crate::watchdog::Wdt;

fn flags(watchdog: &Wdt) -> rustix::io::FdFlags {
    let raw = watchdog
        .handover_fd()
        .expect("watchdog owns its open descriptor");
    #[expect(
        unsafe_code,
        reason = "observe the live watchdog descriptor without duplicating ownership"
    )]
    // SAFETY: the shared owner borrow keeps this descriptor alive throughout
    // the synchronous fcntl call. BorrowedFd does not take ownership or close it.
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw) };
    rustix::io::fcntl_getfd(fd).unwrap()
}

/// # Safety
/// The calling process must have one thread; it must own its WDTFD handover.
#[expect(
    unsafe_code,
    reason = "the runner must establish environment and descriptor ownership"
)]
pub(super) unsafe fn run() {
    inherited_watchdog_exec_flags_and_final_close();
}

fn inherited_watchdog_exec_flags_and_final_close() {
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::process::Command;

    // This runner has no libtest worker; environment and fd ownership are local.
    let (reader, writer) = rustix::pipe::pipe_with(
        rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
    )
    .unwrap();
    // A high fd avoids shell startup reusing a descriptor that should
    // have disappeared at exec. Only the transferred writer remains.
    let transferred = rustix::io::fcntl_dupfd_cloexec(&writer, 1000).unwrap();
    drop(writer);
    rustix::io::fcntl_setfd(&transferred, rustix::io::FdFlags::empty()).unwrap();
    let inherited = transferred.into_raw_fd();
    std::env::set_var("WDTFD", inherited.to_string());
    let mut watchdog = Wdt::default();
    #[expect(
        unsafe_code,
        reason = "exercise explicit ownership transfer from preinit"
    )]
    // SAFETY: into_raw_fd above relinquished the only owner of this live
    // descriptor. This isolated subprocess alone consumes its WDTFD.
    let handover =
        unsafe { owrt_platform::procd::watchdog::take_inherited_watchdog(crate::sys::atoi_u32) };
    watchdog.init(0, false, handover);
    assert!(std::env::var_os("WDTFD").is_none());
    assert_eq!(
        watchdog.handover_fd(),
        Some(inherited),
        "handover must not duplicate"
    );

    assert!(flags(&watchdog).contains(rustix::io::FdFlags::CLOEXEC));

    for cloexec in [true, false, true] {
        watchdog.set_cloexec(cloexec);
        let flags = flags(&watchdog);
        assert_eq!(flags.contains(rustix::io::FdFlags::CLOEXEC), cloexec);
        let script = if cloexec {
            "test ! -e /proc/self/fd/\"$1\""
        } else {
            "test -e /proc/self/fd/\"$1\""
        };
        assert!(
            Command::new("/bin/sh")
                .args(["-c", script, "watchdog-exec", &inherited.to_string()])
                .status()
                .unwrap()
                .success(),
            "exec inheritance differs from CLOEXEC"
        );
    }

    watchdog.set_magicclose(true);
    watchdog.set_stopped(true, 0);
    assert!(watchdog.stopped());
    assert_eq!(watchdog.handover_fd(), None);
    let mut bytes = [0; 8];
    let count = rustix::io::read(&reader, &mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"XV", "one init ping then one magic close");
    assert_eq!(
        rustix::io::read(&reader, &mut bytes).unwrap(),
        0,
        "magic close left an extra writer reference alive"
    );

    let reused = rustix::io::fcntl_dupfd_cloexec(&reader, inherited).unwrap();
    assert_eq!(reused.as_raw_fd(), inherited);
    drop(watchdog);
    assert!(
        rustix::io::fcntl_getfd(&reused).is_ok(),
        "drop closed a reused fd"
    );
}
