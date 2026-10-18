use owrt_odhcpd::config::{Config, PoolConfig};
use owrt_odhcpd::dhcpv6::{Dhcpv6, RequestContext};
use owrt_odhcpd::leases::StateFiles;
use owrt_odhcpd::model::{Address, Clock, Link, INFINITE};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    config: Config,
    link: Link,
    engine: Dhcpv6,
    files: StateFiles,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "odhcpd-trigger-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let trigger = directory.join("trigger");
        fs::write(
            &trigger,
            format!(
                "#!/bin/sh\nprintf '%s\\n' $$ >> '{}'\nexec /bin/sleep 30\n",
                directory.join("started").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&trigger, fs::Permissions::from_mode(0o700)).unwrap();
        let mut pool = PoolConfig::new("lan");
        pool.dhcpv6 = true;
        Self {
            config: Config {
                pools: vec![pool],
                lease_trigger: Some(trigger),
                lease_file: Some(directory.join("leases")),
                hosts_dir: Some(directory.join("hosts")),
                ..Config::default()
            },
            link: Link {
                name: "lan".into(),
                index: 7,
                flags: 0x41,
                mtu: 1500,
                mac: [2, 0, 0, 0, 0, 1],
                addresses: vec![Address {
                    address: "fd00::1".parse().unwrap(),
                    length: 64,
                    preferred_until: INFINITE,
                    valid_until: INFINITE,
                    flags: 0,
                    scope: 0,
                }],
            },
            directory,
            engine: Dhcpv6::default(),
            files: StateFiles::default(),
        }
    }

    fn clock(ms: u64) -> Clock {
        Clock {
            monotonic_ms: ms,
            unix_seconds: 2_000_000_000,
        }
    }

    fn update(&mut self, name: &str, ms: u64) {
        fn option(packet: &mut Vec<u8>, code: u16, bytes: &[u8]) {
            packet.extend(code.to_be_bytes());
            packet.extend((bytes.len() as u16).to_be_bytes());
            packet.extend(bytes);
        }
        let mut packet = vec![3, 1, 2, 3];
        option(&mut packet, 1, &[0, 3, 0, 1, 2, 3, 4, 5, 6, 7]);
        let mut ia = 1u32.to_be_bytes().to_vec();
        ia.extend([0; 8]);
        option(&mut packet, 3, &ia);
        let mut fqdn = vec![0, name.len() as u8];
        fqdn.extend(name.as_bytes());
        fqdn.push(0);
        option(&mut packet, 39, &fqdn);
        let clock = Self::clock(ms);
        let result = self.engine.handle(
            &packet,
            RequestContext {
                source: "[fe80::2%7]:546".parse().unwrap(),
                destination: "ff02::1:2".parse().unwrap(),
                link: &self.link,
                pool: &self.config.pools[0],
                config: &self.config,
                clock,
            },
            &mut |_, _| Ok(()),
        );
        assert!(result.reply.is_some());
        assert_eq!(self.engine.leases().len(), 1);
        self.files
            .write(&self.config, self.engine.leases(), clock)
            .unwrap();
    }

    fn started(&self) -> Vec<i32> {
        fs::read_to_string(self.directory.join("started"))
            .unwrap_or_default()
            .lines()
            .map(|line| line.parse().unwrap())
            .collect()
    }

    fn wait_started(&self) {
        self.wait_started_count(1);
    }

    fn wait_started_count(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.started().len() < count {
            assert!(Instant::now() < deadline, "trigger never started");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn script(&self, body: &str) {
        fs::write(
            self.config.lease_trigger.as_ref().unwrap(),
            format!(
                "#!/bin/sh\nprintf '%s\\n' $$ >> '{}'\n{body}\n",
                self.directory.join("started").display()
            ),
        )
        .unwrap();
    }

    fn poll_until(&mut self, ms: u64, done: impl Fn(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !done(self) {
            self.files
                .poll_trigger(&self.config, Self::clock(ms))
                .unwrap();
            assert!(Instant::now() < deadline, "trigger state did not settle");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // StateFiles still owns the child handle. Recorded PIDs may already
        // have been reaped and must never be used as cleanup ownership.
        self.files.stop_trigger().unwrap();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn updates_coalesce_and_the_last_hosts_snapshot_is_delivered() {
    let mut fixture = Fixture::new();
    fixture.script(&format!(
        "while [ ! -f '{0}/release' ]; do sleep 0.01; done\ncat '{0}/hosts/odhcpd.hosts.lan' >> '{0}/observed'",
        fixture.directory.display()
    ));
    fixture.update("first", 100_000);
    fixture.wait_started();
    for value in 0..32 {
        fixture.update(&format!("client{value}"), 100_000);
    }
    fs::write(fixture.directory.join("release"), "").unwrap();
    fixture.poll_until(100_000, |fixture| {
        fixture.started().len() == 2 && fixture.files.trigger_deadline().is_none()
    });
    let observed = fs::read_to_string(fixture.directory.join("observed")).unwrap();
    assert_eq!(observed.lines().count(), 2);
    assert!(observed.lines().all(|line| line.contains("client31")));
    fixture.update("client31", 101_000);
    assert_eq!(
        fixture.started().len(),
        2,
        "renewal must not launch a callback"
    );
    assert_eq!(fixture.files.trigger_deadline(), None);
}

#[test]
fn spawn_failure_retries_without_another_mapping_change() {
    let mut fixture = Fixture::new();
    let trigger = fixture.config.lease_trigger.clone().unwrap();
    fs::remove_file(&trigger).unwrap();
    let error = fixture
        .files
        .write(&fixture.config, &[], Fixture::clock(100_000))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(fixture.files.trigger_deadline(), Some(101_000));
    fixture.script("exit 0");
    fs::set_permissions(&trigger, fs::Permissions::from_mode(0o700)).unwrap();
    fixture
        .files
        .poll_trigger(&fixture.config, Fixture::clock(100_999))
        .unwrap();
    assert!(fixture.started().is_empty());
    fixture.poll_until(101_000, |fixture| {
        fixture.files.trigger_deadline().is_none()
    });
    assert_eq!(fixture.started().len(), 1);
}

#[test]
fn failed_callback_retries_after_one_second() {
    let mut fixture = Fixture::new();
    fixture.script(&format!(
        "if [ ! -f '{0}/failed' ]; then touch '{0}/failed'; exit 1; fi\nexit 0",
        fixture.directory.display()
    ));
    fixture.update("first", 100_000);
    fixture.poll_until(100_000, |fixture| {
        fixture.files.trigger_deadline() == Some(101_000)
    });
    assert_eq!(fixture.started().len(), 1);
    fixture
        .files
        .poll_trigger(&fixture.config, Fixture::clock(100_999))
        .unwrap();
    assert_eq!(fixture.started().len(), 1);
    fixture.poll_until(101_000, |fixture| {
        fixture.files.trigger_deadline().is_none()
    });
    assert_eq!(fixture.started().len(), 2);
}

fn running(pid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|stat| !stat.split_once(") ").unwrap().1.starts_with('Z'))
}

#[test]
fn timeout_kills_the_callback_group_and_schedules_a_retry() {
    let mut fixture = Fixture::new();
    fixture.script(&format!(
        "sleep 30 &\nprintf '%s\\n' $! > '{}/helper'\nwait",
        fixture.directory.display()
    ));
    fixture.update("first", 100_000);
    let helper_file = fixture.directory.join("helper");
    fixture.poll_until(100_000, |_| helper_file.exists());
    let helper = fs::read_to_string(helper_file)
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    let parent = fixture.started()[0];
    assert!(running(parent) && running(helper));
    fixture
        .files
        .poll_trigger(&fixture.config, Fixture::clock(134_999))
        .unwrap();
    assert!(running(parent) && running(helper));
    let error = fixture
        .files
        .poll_trigger(&fixture.config, Fixture::clock(135_000))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    fixture.poll_until(135_000, |_| !running(parent) && !running(helper));
    fixture
        .files
        .poll_trigger(&fixture.config, Fixture::clock(135_000))
        .unwrap();
    assert_eq!(fixture.files.trigger_deadline(), Some(136_000));
    fixture.script("exit 0");
    fixture.poll_until(136_000, |fixture| {
        fixture.files.trigger_deadline().is_none()
    });
    assert_eq!(fixture.started().len(), 2);
}

#[test]
fn disabling_the_trigger_stops_it_and_discards_pending_updates() {
    let mut fixture = Fixture::new();
    fixture.update("first", 100_000);
    fixture.wait_started();
    fixture.update("last", 100_000);
    let parent = fixture.started()[0];
    fixture.config.lease_trigger = None;
    fixture.poll_until(100_000, |fixture| {
        fixture.files.trigger_deadline().is_none()
    });
    assert!(!running(parent));
    fixture
        .files
        .poll_trigger(&fixture.config, Fixture::clock(200_000))
        .unwrap();
    assert_eq!(fixture.started().len(), 1);
}

#[test]
fn changing_the_script_stops_the_old_group_and_runs_the_new_path() {
    let mut fixture = Fixture::new();
    fixture.update("first", 100_000);
    fixture.wait_started();
    let parent = fixture.started()[0];
    fixture.config.lease_trigger = Some(fixture.directory.join("new-trigger"));
    fixture.script("exit 0");
    fs::set_permissions(
        fixture.config.lease_trigger.as_ref().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fixture.poll_until(100_000, |_| !running(parent));
    fixture
        .files
        .poll_trigger(&fixture.config, Fixture::clock(100_000))
        .unwrap();
    assert_eq!(fixture.files.trigger_deadline(), Some(101_000));
    assert!(!running(parent));
    fixture.poll_until(101_000, |fixture| {
        fixture.files.trigger_deadline().is_none()
    });
    assert_eq!(fixture.started().len(), 2);
}

#[test]
fn shutdown_reaps_only_its_callback_and_drop_also_cleans_up() {
    let mut fixture = Fixture::new();
    let mut sibling = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .spawn()
        .unwrap();
    fixture.update("first", 100_000);
    fixture.wait_started();
    let parent = fixture.started()[0];
    let start = Instant::now();
    fixture.files.stop_trigger().unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(!running(parent));
    assert_eq!(fixture.files.trigger_deadline(), None);
    assert_eq!(sibling.wait().unwrap().code(), Some(7));

    fixture.update("last", 100_000);
    fixture.wait_started_count(2);
    let parent = fixture.started()[1];
    drop(std::mem::take(&mut fixture.files));
    assert!(!running(parent));
}

#[test]
fn a_stalled_trigger_does_not_spawn_one_process_per_mapping_change() {
    let mut fixture = Fixture::new();
    for value in 0..32 {
        fixture.update(&format!("client{value}"), 100_000);
    }
    fixture.wait_started();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        fixture.started().len(),
        1,
        "lease-trigger concurrency must be bounded"
    );
    assert!(
        fs::read_to_string(fixture.directory.join("hosts/odhcpd.hosts.lan"))
            .unwrap()
            .contains("client31"),
        "hosts publication must not wait for the trigger"
    );
}
