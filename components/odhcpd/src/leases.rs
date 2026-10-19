//! DHCPv6 lease views and the existing odhcpd consumer interfaces.
use crate::config::{Config, HostConfig};
use crate::model::{remaining, Clock, INFINITE};
use owrt_ubus::blob::BlobBuf;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseKind {
    Na,
    Pd,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseAddress {
    pub address: Ipv6Addr,
    pub length: u8,
    pub preferred_until: u64,
    pub valid_until: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub pool: String,
    pub device: String,
    pub interface_index: u32,
    pub duid: Vec<u8>,
    pub iaid: u32,
    pub kind: LeaseKind,
    pub assigned: u64,
    pub prefix_length: u8,
    pub hostname: Option<Vec<u8>>,
    pub hostname_valid: bool,
    pub bound: bool,
    pub is_static: bool,
    pub(crate) configured_host: Option<HostConfig>,
    pub lease_time: u32,
    pub valid_until: u64,
    pub preferred_until: u64,
    pub peer: SocketAddrV6,
    pub addresses: Vec<LeaseAddress>,
}

impl Lease {
    pub fn valid(&self, now: u64) -> bool {
        self.valid_until == INFINITE || self.valid_until > now
    }
}

pub fn hostname_valid(name: &[u8]) -> bool {
    !name.is_empty()
        && name.split(|b| *b == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label[0].is_ascii_alphanumeric()
                && label[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        })
}

pub fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn escaped_hostname(name: &[u8]) -> String {
    let mut text = String::new();
    for byte in name {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.') {
            text.push(*byte as char);
        } else {
            let _ = write!(text, "\\x{byte:02x}");
        }
    }
    text
}

/// Packed blobmsg fields for `dhcp.ipv6leases`, including empty service devices.
pub fn ubus_leases(leases: &[Lease], devices: &[String], clock: Clock) -> Vec<u8> {
    let mut output = BlobBuf::new();
    let device = output.msg_open_table("device");
    let mut names = devices.to_vec();
    names.extend(leases.iter().map(|lease| lease.device.clone()));
    names.sort();
    names.dedup();
    for name in names {
        let interface = output.msg_open_table(&name);
        let entries = output.msg_open_array("leases");
        for lease in leases
            .iter()
            .filter(|lease| lease.device == name && lease.valid(clock.seconds()))
        {
            let entry = output.msg_open_table("");
            output.msg_string("duid", &hex(&lease.duid));
            output.msg_u32("iaid", lease.iaid);
            output.msg_string_bytes("hostname", lease.hostname.as_deref().unwrap_or_default());
            output.msg_bool("accept-reconf", false);
            if lease.kind == LeaseKind::Na {
                output.msg_u64("assigned", lease.assigned);
            } else {
                output.msg_u32("assigned", lease.assigned as u32);
            }
            let flags = output.msg_open_array("flags");
            if lease.bound {
                output.msg_string("", "bound");
            }
            if lease.is_static {
                output.msg_string("", "static");
            }
            output.msg_close(flags);
            let addresses = output.msg_open_array(if lease.kind == LeaseKind::Na {
                "ipv6-addr"
            } else {
                "ipv6-prefix"
            });
            for address in &lease.addresses {
                if remaining(address.valid_until, clock.seconds()) == 0 {
                    continue;
                }
                let item = output.msg_open_table("");
                output.msg_string("address", &address.address.to_string());
                output.msg_u32(
                    "preferred-lifetime",
                    remaining(
                        address
                            .preferred_until
                            .min(lease.preferred_until)
                            .min(lease.valid_until),
                        clock.seconds(),
                    ),
                );
                output.msg_u32(
                    "valid-lifetime",
                    remaining(address.valid_until.min(lease.valid_until), clock.seconds()),
                );
                if address.length != 128 {
                    output.msg_u32("prefix-length", address.length as u32);
                }
                output.msg_close(item);
            }
            output.msg_close(addresses);
            output.msg_u32("valid", remaining(lease.valid_until, clock.seconds()));
            output.msg_close(entry);
        }
        output.msg_close(entries);
        output.msg_close(interface);
    }
    output.msg_close(device);
    output.into_payload()
}

fn state_text(leases: &[Lease], clock: Clock) -> String {
    let mut text = String::new();
    for lease in leases
        .iter()
        .filter(|lease| lease.bound && lease.valid(clock.seconds()))
    {
        let expiry = if lease.valid_until == INFINITE {
            -1
        } else {
            clock.unix_seconds.saturating_add(
                lease
                    .valid_until
                    .saturating_sub(clock.seconds())
                    .min(i64::MAX as u64) as i64,
            )
        };
        let name = escaped_hostname(lease.hostname.as_deref().unwrap_or(b"-"));
        let broken = if lease.hostname.is_some() && !lease.hostname_valid {
            "broken\\x20"
        } else {
            ""
        };
        let _ = write!(
            text,
            "# {} {} {:x} {}{} {} {:x} {}",
            lease.device,
            hex(&lease.duid),
            lease.iaid,
            broken,
            name,
            expiry,
            lease.assigned,
            lease.prefix_length
        );
        for address in &lease.addresses {
            if remaining(address.valid_until, clock.seconds()) != 0 {
                let _ = write!(text, " {}/{}", address.address, address.length);
            }
        }
        text.push('\n');
    }
    text
}

fn host_text(leases: &[Lease], config: &Config, clock: Clock) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    for pool in config.pools.iter().filter(|pool| pool.dhcpv6) {
        files.insert(pool.name.clone(), String::new());
    }
    for lease in leases.iter().filter(|lease| {
        lease.kind == LeaseKind::Na
            && lease.bound
            && lease.valid(clock.seconds())
            && lease.hostname_valid
    }) {
        let Some(name) = lease
            .hostname
            .as_deref()
            .and_then(|name| std::str::from_utf8(name).ok())
        else {
            continue;
        };
        let Some(pool) = config
            .pools
            .iter()
            .find(|pool| pool.name == lease.pool && pool.dhcpv6)
        else {
            continue;
        };
        let text = files.entry(pool.name.clone()).or_default();
        for address in &lease.addresses {
            if remaining(address.valid_until, clock.seconds()) == 0 {
                continue;
            }
            if let Some(domain) = pool.domains.first() {
                let _ = writeln!(
                    text,
                    "{}\t{}.{}\t{}",
                    address.address,
                    name,
                    domain.trim_end_matches('.'),
                    name
                );
            } else {
                let _ = writeln!(text, "{}\t{}", address.address, name);
            }
        }
    }
    files
}

fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("state path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(".odhcpd.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&temporary)?;
    rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::LockExclusive)?;
    file.set_len(0)?;
    if let Err(error) = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, path))
    {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

#[derive(Default)]
pub struct StateFiles {
    // C hashes just these bytes, excluding deadlines and search domains. Compare
    // directly to preserve that trigger boundary without a crypto dependency.
    published_mapping: Option<Vec<(Ipv6Addr, Vec<u8>)>>,
    published_hosts: Option<BTreeMap<String, String>>,
    trigger: Option<TriggerRun>,
    trigger_path: Option<PathBuf>,
    trigger_pending: bool,
    trigger_retry_at: Option<u64>,
}

const TRIGGER_TIMEOUT_MS: u64 = 35_000;
const TRIGGER_RETRY_MS: u64 = 1_000;

struct TriggerRun {
    child: Child,
    deadline: u64,
    killed: bool,
}

fn kill_trigger(child: &Child) -> io::Result<()> {
    let pid = i32::try_from(child.id())
        .ok()
        .filter(|pid| *pid > 1)
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| io::Error::other("invalid lease trigger process group"))?;
    // Each trigger starts its own process group. Kill its synchronous helpers
    // too, while the unreaped direct child still reserves the group leader PID.
    match rustix::process::kill_process_group(pid, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

impl StateFiles {
    pub fn trigger_deadline(&self) -> Option<u64> {
        self.trigger.as_ref().map(|run| run.deadline).or_else(|| {
            self.trigger_pending
                .then_some(self.trigger_retry_at.unwrap_or(0))
        })
    }

    /// At most one callback runs. Repeated updates request one later callback
    /// against the latest files; the protocol loop never waits for a script.
    pub fn poll_trigger(&mut self, config: &Config, clock: Clock) -> io::Result<()> {
        let now = clock.monotonic_ms;
        if self.trigger_path != config.lease_trigger {
            self.trigger_pending =
                config.lease_trigger.is_some() && (self.trigger_pending || self.trigger.is_some());
            self.trigger_path.clone_from(&config.lease_trigger);
            self.trigger_retry_at = None;
            if let Some(run) = &mut self.trigger {
                kill_trigger(&run.child)?;
                run.killed = true;
                run.deadline = now.saturating_add(TRIGGER_RETRY_MS);
            }
        }
        if let Some(run) = &mut self.trigger {
            match run.child.try_wait() {
                Ok(Some(status)) => {
                    self.trigger = None;
                    if !status.success() && self.trigger_path.is_some() {
                        self.trigger_pending = true;
                        self.trigger_retry_at = Some(now.saturating_add(TRIGGER_RETRY_MS));
                    }
                }
                Ok(None) => {
                    if now >= run.deadline {
                        run.deadline = now.saturating_add(TRIGGER_RETRY_MS);
                        if !run.killed {
                            kill_trigger(&run.child)?;
                            run.killed = true;
                            self.trigger_pending = self.trigger_path.is_some();
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "lease trigger exceeded 35 seconds; killed its process group",
                            ));
                        }
                    }
                    return Ok(());
                }
                Err(error) => {
                    run.deadline = now.saturating_add(TRIGGER_RETRY_MS);
                    return Err(error);
                }
            }
        }
        if !self.trigger_pending || self.trigger_retry_at.is_some_and(|at| now < at) {
            return Ok(());
        }
        let Some(path) = &self.trigger_path else {
            self.trigger_pending = false;
            self.trigger_retry_at = None;
            return Ok(());
        };
        match Command::new(path).process_group(0).spawn() {
            Ok(child) => {
                self.trigger = Some(TriggerRun {
                    child,
                    deadline: now.saturating_add(TRIGGER_TIMEOUT_MS),
                    killed: false,
                });
                self.trigger_pending = false;
                self.trigger_retry_at = None;
                Ok(())
            }
            Err(error) => {
                self.trigger_retry_at = Some(now.saturating_add(TRIGGER_RETRY_MS));
                Err(error)
            }
        }
    }

    /// Shutdown only: bounded reaping after killing our own callback group.
    pub fn stop_trigger(&mut self) -> io::Result<()> {
        self.trigger_pending = false;
        self.trigger_retry_at = None;
        self.trigger_path = None;
        let Some(mut run) = self.trigger.take() else {
            return Ok(());
        };
        if run.child.try_wait()?.is_some() {
            return Ok(());
        }
        kill_trigger(&run.child)?;
        let until = Instant::now() + Duration::from_secs(1);
        loop {
            if run.child.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "lease trigger did not exit after SIGKILL",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Returns whether the host mapping changed. Lease deadlines alone do not run the trigger.
    pub fn write(&mut self, config: &Config, leases: &[Lease], clock: Clock) -> io::Result<bool> {
        if let Some(path) = &config.lease_file {
            atomic_write(path, state_text(leases, clock).as_bytes())?;
        }
        let hosts = host_text(leases, config, clock);
        let mapping: Vec<_> = leases
            .iter()
            .filter(|lease| {
                lease.kind == LeaseKind::Na
                    && lease.bound
                    && lease.valid(clock.seconds())
                    && lease.hostname_valid
            })
            .flat_map(|lease| {
                lease
                    .addresses
                    .iter()
                    .filter(|address| remaining(address.valid_until, clock.seconds()) != 0)
                    .filter_map(|address| {
                        lease
                            .hostname
                            .as_ref()
                            .map(|name| (address.address, name.clone()))
                    })
            })
            .collect();
        if self.published_mapping.as_ref() == Some(&mapping) {
            self.poll_trigger(config, clock)?;
            return Ok(false);
        }
        if let Some(directory) = &config.hosts_dir {
            for (name, text) in &hosts {
                if name.is_empty()
                    || name.contains('/')
                    || name.contains('\0')
                    || name == "."
                    || name == ".."
                {
                    return Err(io::Error::other("invalid host-file interface name"));
                }
                atomic_write(
                    &directory.join(format!("odhcpd.hosts.{name}")),
                    text.as_bytes(),
                )?;
            }
            if let Some(previous) = &self.published_hosts {
                for name in previous.keys().filter(|name| !hosts.contains_key(*name)) {
                    match fs::remove_file(directory.join(format!("odhcpd.hosts.{name}"))) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        self.published_mapping = Some(mapping);
        self.published_hosts = Some(hosts);
        self.trigger_pending = config.lease_trigger.is_some();
        self.poll_trigger(config, clock)?;
        Ok(true)
    }
}

impl Drop for StateFiles {
    fn drop(&mut self) {
        let _ = self.stop_trigger();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PoolConfig;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn state_hostname_cannot_inject_a_second_record() {
        assert_eq!(
            escaped_hostname(b"x\n# forged name\xff"),
            "x\\x0a\\x23\\x20forged\\x20name\\xff"
        );
        assert!(!hostname_valid(b"x\n# forged"));
        assert!(hostname_valid(b"my_host-2"));
        assert!(!hostname_valid(b"-host"));
        assert!(!hostname_valid(&[b'x'; 64]));
    }

    #[test]
    fn lifetime_renewal_does_not_republish_hosts_or_spawn_trigger() {
        let directory =
            std::env::temp_dir().join(format!("odhcpd-statefile-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let result = std::panic::catch_unwind(|| {
            let trigger = directory.join("trigger");
            let count = directory.join("count");
            fs::write(
                &trigger,
                format!("#!/bin/sh\nprintf x >> '{}'\n", count.display()),
            )
            .unwrap();
            fs::set_permissions(&trigger, fs::Permissions::from_mode(0o700)).unwrap();
            let mut pool = PoolConfig::new("lan");
            pool.dhcpv6 = true;
            let config = Config {
                pools: vec![pool],
                lease_file: Some(directory.join("leases")),
                hosts_dir: Some(directory.join("hosts")),
                lease_trigger: Some(trigger),
                ..Config::default()
            };
            let clock = Clock {
                monotonic_ms: 100_000,
                unix_seconds: 2_000_000_000,
            };
            let mut lease = Lease {
                pool: "lan".into(),
                device: "br-lan".into(),
                interface_index: 7,
                duid: vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 2],
                iaid: 0x123,
                kind: LeaseKind::Na,
                assigned: 0x9ed,
                prefix_length: 128,
                hostname: Some(b"client".to_vec()),
                hostname_valid: true,
                bound: true,
                is_static: false,
                configured_host: None,
                lease_time: 43200,
                valid_until: 5500,
                preferred_until: 2800,
                peer: "[fe80::2]:546".parse().unwrap(),
                addresses: vec![LeaseAddress {
                    address: "2001:db8::9ed".parse().unwrap(),
                    length: 128,
                    preferred_until: 2800,
                    valid_until: 5500,
                }],
            };
            let mut files = StateFiles::default();
            assert!(files.write(&config, &[lease.clone()], clock).unwrap());
            if let Some(run) = &mut files.trigger {
                run.child.wait().unwrap();
            }
            let first_hosts = fs::read(directory.join("hosts/odhcpd.hosts.lan")).unwrap();
            lease.valid_until += 100;
            lease.preferred_until += 100;
            lease.addresses[0].valid_until += 100;
            assert!(!files.write(&config, &[lease.clone()], clock).unwrap());
            assert_eq!(fs::read(&count).unwrap(), b"x");
            assert_eq!(
                fs::read(directory.join("hosts/odhcpd.hosts.lan")).unwrap(),
                first_hosts
            );
            assert!(fs::read_to_string(directory.join("leases"))
                .unwrap()
                .contains("2000005500"));
            lease.addresses.clear();
            assert!(files.write(&config, &[lease], clock).unwrap());
            if let Some(run) = &mut files.trigger {
                run.child.wait().unwrap();
            }
            assert_eq!(fs::read(&count).unwrap(), b"xx");
            assert!(fs::read(directory.join("hosts/odhcpd.hosts.lan"))
                .unwrap()
                .is_empty());
        });
        fs::remove_dir_all(directory).unwrap();
        result.unwrap();
    }
}
