//! R81: exercise the real process slot with a child that ignores SIGTERM.
//! Run only `r81_termination_is_bounded`; this file also imports upstream tests.
//! No sockets, root privileges, or router access are used. The child exits by
//! itself after two seconds so this regression fails without hanging forever.

#[path = "../../components/netifd/src/process.rs"]
mod netifd_process;

#[test]
fn r81_termination_is_bounded() {
    use std::time::{Duration, Instant};

    let ready = std::env::temp_dir().join(format!("r81-term-ready-{}", std::process::id()));
    let _ = std::fs::remove_file(&ready);
    let mut slot = netifd_process::Slot::default();
    slot.start(
        &[
            "/bin/sh".into(),
            "-c".into(),
            "trap '' TERM; : > \"$1\"; exec /bin/sleep 2".into(),
            "r81-child".into(),
            ready.to_string_lossy().into_owned(),
        ],
        &[],
    )
    .unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while !ready.exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    let child_ready = ready.exists();
    let _ = std::fs::remove_file(&ready);

    let start = Instant::now();
    slot.terminate();
    let elapsed = start.elapsed();
    assert!(child_ready, "child did not install its SIGTERM disposition");
    eprintln!("terminate elapsed={elapsed:?}; child's natural lifetime=2s");
    assert!(
        elapsed < Duration::from_millis(500),
        "netifd's forced cleanup must not wait for a SIGTERM-ignoring child"
    );
}
