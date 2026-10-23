//! Existing watchdog handover assertions run without environment-reading peers.
#![forbid(unsafe_code)]
use crate::watchdog::Wdt;

fn flags(watchdog: &Wdt) -> rustix::io::FdFlags {
    rustix::io::fcntl_getfd(watchdog.descriptor().expect("watchdog owns its descriptor")).unwrap()
}

pub(super) fn run(reader: std::os::fd::OwnedFd, handover: std::os::fd::OwnedFd) {
    inherited_watchdog_exec_flags_and_final_close(reader, handover);
    supervisor_handover_waits_for_the_first_watchdog_method();
}

fn inherited_watchdog_exec_flags_and_final_close(
    reader: std::os::fd::OwnedFd,
    handover: std::os::fd::OwnedFd,
) {
    use std::os::fd::AsRawFd;
    use std::process::Command;

    let inherited = handover.as_raw_fd();
    let mut watchdog = Wdt::default();
    watchdog.init(0, false, Some(Ok(handover)));
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

fn supervisor_handover_waits_for_the_first_watchdog_method() {
    use std::os::fd::AsRawFd;
    let (reader, writer) = rustix::pipe::pipe_with(
        rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
    )
    .unwrap();
    let raw = writer.as_raw_fd();
    let mut watchdog = Wdt::with_inherited(Some(Ok(writer)));
    assert!(!watchdog.is_open());
    assert!(watchdog.stopped());
    let mut byte = [0];
    assert_eq!(
        rustix::io::read(&reader, &mut byte),
        Err(rustix::io::Errno::AGAIN)
    );
    watchdog.set_stopped(false, 0);
    assert_eq!(watchdog.handover_fd(), Some(raw));
    assert_eq!(rustix::io::read(&reader, &mut byte).unwrap(), 1);
    assert_eq!(byte, *b"X");
    watchdog.set_magicclose(true);
    watchdog.set_stopped(true, 0);
    assert_eq!(rustix::io::read(&reader, &mut byte).unwrap(), 1);
    assert_eq!(byte, *b"V");
    assert_eq!(rustix::io::read(&reader, &mut byte).unwrap(), 0);
}
