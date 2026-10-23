//! Fork contract fixtures invoked by the platform's standalone test entry.
#![forbid(unsafe_code)]

pub fn unregistered_workers_are_rejected() {
    eprintln!("process test: registration::unregistered_workers_are_rejected");
    use dnsmasq_rs::{
        config::dns::lookup::EndpointLookup,
        helper::{Config, Helper},
    };
    let error = Helper::start(Config {
        script: "/bin/true".into(),
        script_user: None,
        debug: false,
    })
    .err()
    .expect("unregistered helper must be rejected");
    assert!(error.message.contains("helper worker is not installed"));
    let error = EndpointLookup::start(Vec::new(), false)
        .err()
        .expect("unregistered resolver must be rejected");
    assert_eq!(error.to_string(), "resolver worker is not installed");
}

fn live_thread_rejects_fork_then_join_restores_progress() {
    use dnsmasq_rs::{
        config::dns::lookup::EndpointLookup,
        helper::{Config, Helper, Notice},
    };
    use std::time::{Duration, Instant};

    fn process_state() -> (String, Vec<String>, String) {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let mask = status
            .lines()
            .find(|line| line.starts_with("SigBlk:"))
            .unwrap()
            .to_owned();
        let mut descriptors: Vec<_> = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        descriptors.sort();
        let children =
            std::fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))
                .unwrap();
        (mask, descriptors, children)
    }

    let (release, wait) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::spawn(move || wait.recv().unwrap());
    let before = process_state();
    let helper = Helper::start(Config {
        script: "/bin/true".into(),
        script_user: None,
        debug: false,
    });
    assert!(
        helper.is_err(),
        "a previously registered worker must reject a live thread"
    );
    let lookup = EndpointLookup::start(Vec::new(), false);
    assert!(
        lookup.is_err(),
        "a registered resolver must reject a live thread"
    );
    assert_eq!(
        process_state(),
        before,
        "rejection must preserve masks, FDs and children"
    );
    release.send(()).unwrap();
    thread.join().unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    // pthread_join can complete just before the kernel releases the last mm
    // reference. Retry only that transient EINVAL at the actual fork boundary.
    let mut lookup = loop {
        match EndpointLookup::start(Vec::new(), false) {
            Ok(lookup) => break lookup,
            Err(error) if error.raw_os_error() == Some(22) => {
                assert!(
                    Instant::now() < deadline,
                    "joined thread retained its address space"
                );
                std::thread::yield_now();
            }
            Err(error) => panic!("resolver after join: {error}"),
        }
    };
    let result = loop {
        assert!(
            Instant::now() < deadline,
            "resolver did not complete after join"
        );
        if let Some(result) = lookup.step() {
            break result;
        }
        std::thread::yield_now();
    };
    assert!(result.error.is_none(), "{:?}", result.error);
    assert!(result.rules.is_empty());

    let mut helper = Helper::start(Config {
        script: "/bin/true".into(),
        script_user: None,
        debug: false,
    })
    .unwrap();
    let mut ready = false;
    while !helper.ready() {
        assert!(
            Instant::now() < deadline,
            "helper did not become ready after join"
        );
        ready |= helper.step().unwrap().contains(&Notice::Ready);
        std::thread::yield_now();
    }
    assert!(ready);
    helper.begin_shutdown();
    while !helper.is_finished() {
        assert!(Instant::now() < deadline, "helper did not reap after join");
        helper.step().unwrap();
        std::thread::yield_now();
    }
}

pub fn run() {
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    eprintln!("process test: registration::live_thread_rejects_fork_then_join_restores_progress");
    live_thread_rejects_fork_then_join_restores_progress();
    dnsmasq_rs::helper::run_process_tests();
    dnsmasq_rs::config::dns::lookup::run_process_tests();
    dnsmasq_rs::dns::files::run_process_tests();
}
