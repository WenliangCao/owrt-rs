//! Process fixtures run on a real sole-thread main, never a libtest worker.
#![forbid(unsafe_code)]

pub(crate) fn run(
    process: &owrt_platform::procd::process::Process,
    reader: std::os::fd::OwnedFd,
    handover: std::os::fd::OwnedFd,
) {
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    crate::proc_tests::run(process);
    crate::watchdog_tests::run(reader, handover);
    rejects_threads_created_after_registration(process);
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    eprintln!("process ownership tests: 7 passed; threads=1");
}

fn rejects_threads_created_after_registration(process: &owrt_platform::procd::process::Process) {
    let (ready, started) = std::sync::mpsc::channel();
    let (finish, release) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        ready.send(()).unwrap();
        release.recv().unwrap();
    });
    started.recv().unwrap();
    let mut instance = crate::instance::Instance::new("thread-control");
    instance.valid = true;
    instance.command = vec!["/bin/true".into()];
    assert!(crate::proc::start(&instance, "fixture", process).is_err());
    assert!(process
        .spawn_firmware(owrt_platform::procd::process::FirmwareRequest {
            directory: String::new(),
            variables: std::collections::BTreeMap::new(),
        })
        .is_err());
    let reaped = rustix::process::wait(rustix::process::WaitOptions::NOHANG);
    assert!(
        matches!(reaped, Err(rustix::io::Errno::CHILD)),
        "rejected operations must not create a child: {reaped:?}"
    );
    finish.send(()).unwrap();
    thread.join().unwrap();
    // pthread_join can return before the kernel releases the exiting task's
    // final address-space reference. Observe the actual guard condition.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while owrt_platform::process_owner::ProcessOwner::acquire().is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "joined thread retained shared address space"
        );
        std::thread::yield_now();
    }
    let (pid, _, _) = crate::proc::start(&instance, "fixture", process).unwrap();
    let child = rustix::process::Pid::from_raw(pid).unwrap();
    let (_, status) = rustix::process::waitpid(Some(child), rustix::process::WaitOptions::empty())
        .unwrap()
        .unwrap();
    assert_eq!(status.exit_status(), Some(0));
    let pid = process
        .spawn_firmware(owrt_platform::procd::process::FirmwareRequest {
            directory: String::new(),
            variables: std::collections::BTreeMap::new(),
        })
        .unwrap();
    let child = rustix::process::Pid::from_raw(pid).unwrap();
    let (_, status) = rustix::process::waitpid(Some(child), rustix::process::WaitOptions::empty())
        .unwrap()
        .unwrap();
    assert_eq!(status.exit_status(), Some(1));
}
