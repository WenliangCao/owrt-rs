//! Child panic hooks cannot use or drop the parent's copied resource captures.
use dnsmasq_platform::process::{spawn_lookup, AuditedWorker};
use std::fs::File;
use std::path::PathBuf;

struct HookCapture {
    called: PathBuf,
    dropped: PathBuf,
}

impl Drop for HookCapture {
    fn drop(&mut self) {
        std::fs::write(&self.dropped, std::process::id().to_string()).unwrap();
    }
}

pub(super) fn run() {
    eprintln!("process test: registration::child_hook_is_severed_and_parent_hook_preserved");
    use rustix::process::{waitpid, WaitOptions};
    use std::time::{Duration, Instant};

    fn panic_in_child(_: (), _: File) -> i32 {
        panic!("fixed child panic fixture");
    }

    let directory = std::env::temp_dir().join(format!("dns-fork-hook-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let called = directory.join("called");
    let dropped = directory.join("dropped");
    let capture = HookCapture {
        called: called.clone(),
        dropped: dropped.clone(),
    };
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |_| {
        let _ = &capture;
        // The safe start must reject reentry while this hook is running.
        let result = dnsmasq_rs::helper::Helper::start(dnsmasq_rs::helper::Config {
            script: "/bin/true".into(),
            script_user: None,
            debug: false,
        });
        let message = result.err().map(|error| error.message).unwrap_or_default();
        std::fs::write(&capture.called, message).unwrap();
    }));
    // SAFETY: the only input is unit and the fixed entry immediately panics.
    // It cannot access an inherited descriptor, mapping or application lock.
    // The standalone runner registers no atfork callback and has one thread.
    let worker: AuditedWorker<fn((), File) -> i32> = unsafe { AuditedWorker::new(panic_in_child) };
    let (_, pid, reader) = spawn_lookup((), &worker).unwrap();
    drop(reader);
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some((_, status)) = waitpid(Some(pid), WaitOptions::NOHANG).unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "panicking worker did not exit");
        std::thread::yield_now();
    };
    assert_eq!(status.exit_status(), Some(5));
    assert!(!called.exists(), "the child invoked the inherited hook");
    assert!(
        !dropped.exists(),
        "the child dropped inherited hook captures"
    );

    assert!(std::panic::catch_unwind(|| panic!("parent hook remains installed")).is_err());
    assert!(std::fs::read_to_string(&called)
        .unwrap()
        .contains("cannot fork from a panic handler"));
    let installed = std::panic::take_hook();
    std::panic::set_hook(previous);
    drop(installed);
    assert_eq!(
        std::fs::read_to_string(&dropped).unwrap(),
        std::process::id().to_string()
    );
    std::fs::remove_dir_all(directory).unwrap();
}
