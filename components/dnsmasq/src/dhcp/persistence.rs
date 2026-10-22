//! Lease-file durability and DNS publication handoff, after state commit.
//! References: lease.c:174-254,286-453,564-620; dnsmasq.c:1420-1431.

use super::lease::LeaseStore;
use super::lease_file::{parse_reader, LeaseFile};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Seek, Write};
use std::net::Ipv4Addr;
use std::path::Path;

pub const LEASE_RETRY_SECONDS: i64 = 60;

/// The standard Write boundary plus the two file operations needed to make
/// an update durable. Fault adapters can retain exact operation/byte traces.
pub trait LeaseIo: Write {
    fn rewind(&mut self) -> io::Result<()>;
    fn truncate(&mut self) -> io::Result<()>;
    fn sync(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlarmAction {
    /// C send_alarm(0, now!=0) does not cancel an already scheduled alarm.
    Keep,
    Immediate,
    At(i64),
}

#[derive(Debug)]
pub struct PersistReport {
    pub attempted: bool,
    pub error: Option<io::Error>,
    pub next_event: Option<i64>,
    /// C's exact relative deadline printed with a write failure.
    pub retry_in: Option<u32>,
    pub alarm: AlarmAction,
}

/// File failure is a report, never a rollback of a committed DHCP outcome.
/// Flush is attempted even after an earlier failure; fsync follows only a
/// successful flush. A later flush/fsync failure replaces the earlier error.
pub fn update_file(
    store: &mut LeaseStore,
    stream: Option<&mut dyn LeaseIo>,
    now: i64,
) -> PersistReport {
    let mut error = None;
    let mut attempted = false;
    if store.changes().file {
        if let Some(stream) = stream {
            attempted = true;
            if let Err(failed) = stream.rewind().and_then(|_| stream.truncate()) {
                error = Some(failed);
            } else if let Err(failed) = store.write_leases(&mut *stream) {
                error = Some(failed);
            }
            if let Err(failed) = stream.flush().and_then(|_| stream.sync()) {
                error = Some(failed);
            }
            if error.is_none() {
                store.file_written();
            }
        }
    }
    let mut next_event = store.next_expiry();
    if error.is_some() {
        let retry = now.saturating_add(LEASE_RETRY_SECONDS);
        next_event = Some(next_event.map_or(retry, |expiry| {
            if expiry.wrapping_sub(retry) > 0 {
                retry
            } else {
                expiry
            }
        }));
    }
    let alarm = if now == 0 || next_event.is_some_and(|event| event.wrapping_sub(now) <= 0) {
        AlarmAction::Immediate
    } else if let Some(event) = next_event {
        // AArch64 conversion to the unsigned alarm argument saturates at
        // UINT_MAX. Keep that actual relative deadline representable for poll.
        AlarmAction::At(now.saturating_add(event.wrapping_sub(now).min(i64::from(u32::MAX))))
    } else {
        AlarmAction::Keep
    };
    let retry_in = error
        .as_ref()
        .and_then(|_| next_event.map(|event| super::lease::remaining_seconds(event, now)));
    PersistReport {
        attempted,
        error,
        next_event,
        retry_in,
        alarm,
    }
}

/// The caller reports this diagnostic unchanged: lease_init distinguishes
/// open/create from read failures, both with EC_FILE and the configured path.
#[derive(Debug)]
pub struct LeaseFileFailure {
    action: &'static str,
    path: std::path::PathBuf,
    source: io::Error,
}

impl LeaseFileFailure {
    pub fn warnings(&self) -> &[Vec<u8>] {
        super::lease_file::warnings(&self.source)
    }
}

impl std::fmt::Display for LeaseFileFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut description = self.source.to_string();
        if let Some(code) = self.source.raw_os_error() {
            if let Some(text) = description.strip_suffix(&format!(" (os error {code})")) {
                description = text.to_owned();
            }
        }
        write!(
            formatter,
            "{} {}: {}",
            self.action,
            self.path.display(),
            description
        )
    }
}

impl std::error::Error for LeaseFileFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn file_failure(action: &'static str, path: &Path, source: io::Error) -> io::Error {
    io::Error::new(
        source.kind(),
        LeaseFileFailure {
            action,
            path: path.to_owned(),
            source,
        },
    )
}

struct FileStream(BufWriter<File>);

impl Write for FileStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl LeaseIo for FileStream {
    fn rewind(&mut self) -> io::Result<()> {
        self.0.rewind()
    }
    fn truncate(&mut self) -> io::Result<()> {
        self.0.get_ref().set_len(0)
    }
    fn sync(&mut self) -> io::Result<()> {
        self.0.get_ref().sync_all()
    }
}

/// Holds one inode for the lifetime of the daemon, matching fopen("a+").
/// It does not reopen or atomically replace a pathname on each update.
pub struct LeasePersistence {
    stream: Option<FileStream>,
}

impl LeasePersistence {
    pub fn open(
        path: &Path,
        read_only: bool,
        maximum_records: usize,
    ) -> io::Result<(Self, Option<LeaseFile>)> {
        Self::open_inner(path, read_only, maximum_records, None)
    }

    pub fn open_with_warnings(
        path: &Path,
        read_only: bool,
        maximum_records: usize,
        mut emit: impl FnMut(Vec<u8>) -> io::Result<()>,
    ) -> io::Result<(Self, Option<LeaseFile>)> {
        Self::open_inner(path, read_only, maximum_records, Some(&mut emit))
    }

    fn open_inner(
        path: &Path,
        read_only: bool,
        maximum_records: usize,
        emit: Option<&mut dyn FnMut(Vec<u8>) -> io::Result<()>>,
    ) -> io::Result<(Self, Option<LeaseFile>)> {
        if read_only {
            // leasefile-ro without a script uses an empty DB, even if the
            // configured pathname contains valid leases or cannot be opened.
            return Ok((Self { stream: None }, None));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(|error| file_failure("cannot open or create lease file", path, error))?;
        // C's startup rewind does not inspect errno; read errors remain fatal.
        let _ = file.rewind();
        let reader = BufReader::with_capacity(1024, &mut file);
        let parsed = if let Some(emit) = emit {
            super::lease_file::parse_reader_with_warnings(reader, maximum_records, emit)
        } else {
            parse_reader(reader, maximum_records)
        };
        let restored = parsed.map_err(|error| {
            if super::lease_file::capacity_exceeded(&error) {
                error
            } else {
                file_failure("failed to read lease file", path, error)
            }
        })?;
        Ok((
            Self {
                stream: Some(FileStream(BufWriter::with_capacity(1024, file))),
            },
            Some(restored),
        ))
    }

    pub fn update(&mut self, store: &mut LeaseStore, now: i64) -> PersistReport {
        update_file(
            store,
            self.stream
                .as_mut()
                .map(|stream| stream as &mut dyn LeaseIo),
            now,
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DnsLeaseRecord<'a> {
    pub name: &'a [u8],
    pub address: Ipv4Addr,
    pub expires: Option<i64>,
}

/// Replace only DHCP-derived DNS entries. Success means the new source is
/// visible to DNS readers before the caller can transmit its DHCP response.
/// The DNS implementation owns hosts/config precedence, PTR and TTL policy.
// Publications run synchronously on the single poll owner.
pub trait DnsPublisher {
    fn replace(&mut self, records: &[DnsLeaseRecord<'_>]) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsStatus {
    NotNeeded,
    Pending,
    Published,
    Failed,
}

#[derive(Debug)]
pub struct DnsReport {
    pub status: DnsStatus,
    pub records: usize,
    pub error: Option<io::Error>,
}

/// Preserve dirty state while DNS is disabled or its dedicated lease source
/// is not attached. Ordinary Hosts data is not used as a substitute.
pub fn update_dns(
    store: &mut LeaseStore,
    dns_enabled: bool,
    force: bool,
    fqdn_only: bool,
    publisher: Option<&mut (dyn DnsPublisher + '_)>,
) -> DnsReport {
    if !dns_enabled || (!force && !store.changes().dns) {
        return DnsReport {
            status: DnsStatus::NotNeeded,
            records: 0,
            error: None,
        };
    }
    // A forced hosts/config reconciliation may start from clean lease state.
    // Keep that request pending until the replacement is actually published.
    store.dns_update_pending();
    let Some(publisher) = publisher else {
        return DnsReport {
            status: DnsStatus::Pending,
            records: 0,
            error: None,
        };
    };
    let mut records = Vec::new();
    for lease in store.active_newest_first() {
        if let Some(name) = &lease.fqdn {
            records.push(DnsLeaseRecord {
                name,
                address: lease.address,
                expires: lease.expires,
            });
        }
        if !fqdn_only {
            if let Some(name) = &lease.hostname {
                records.push(DnsLeaseRecord {
                    name,
                    address: lease.address,
                    expires: lease.expires,
                });
            }
        }
    }
    let count = records.len();
    if let Err(error) = publisher.replace(&records) {
        return DnsReport {
            status: DnsStatus::Failed,
            records: count,
            error: Some(error),
        };
    }
    store.dns_updated();
    DnsReport {
        status: DnsStatus::Published,
        records: count,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::lease::ClientIdentity;
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn directory() -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../private/dnsmasq-rewrite/persistence-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn real_file_restores_and_keeps_the_open_inode() {
        let directory = directory();
        let path = directory.join("leases");
        std::fs::write(&path, b"200 02:00:00:00:00:01 192.0.2.10 host *\n").unwrap();
        let (mut persistence, records) = LeasePersistence::open(&path, false, 2).unwrap();
        let mut store = LeaseStore::new(2);
        assert!(store
            .restore(records.unwrap().records, 100)
            .unwrap()
            .is_empty());
        let held = directory.join("held-inode");
        std::fs::rename(&path, &held).unwrap();
        std::fs::write(&path, b"other inode\n").unwrap();
        store
            .set_expires(Ipv4Addr::new(192, 0, 2, 10), 300, 0)
            .unwrap();
        let report = persistence.update(&mut store, 100);
        assert!(report.attempted && report.error.is_none());
        assert!(!store.changes().file);
        assert_eq!(
            std::fs::read(&held).unwrap(),
            b"300 02:00:00:00:00:01 192.0.2.10 host *\n"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"other inode\n");
        drop(persistence);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn readonly_without_script_ignores_even_an_unopenable_path() {
        let directory = directory();
        let path = directory.join("missing-parent/leases");
        let (mut persistence, records) = LeasePersistence::open(&path, true, 0).unwrap();
        assert!(records.is_none());
        let mut store = LeaseStore::new(1);
        let address = Ipv4Addr::new(192, 0, 2, 10);
        store
            .allocate(
                address,
                ClientIdentity {
                    hardware_type: 1,
                    hardware_address: vec![2; 6],
                    client_id: None,
                },
            )
            .unwrap();
        store.set_expires(address, 600, 100).unwrap();
        let report = persistence.update(&mut store, 100);
        assert!(!report.attempted && report.error.is_none());
        assert_eq!(report.next_event, Some(700));
        assert!(store.changes().file && !path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_or_failed_dns_publisher_does_not_claim_publication() {
        struct Failed;
        impl DnsPublisher for Failed {
            fn replace(&mut self, _: &[DnsLeaseRecord<'_>]) -> io::Result<()> {
                Err(io::Error::other("DNS source unavailable"))
            }
        }
        let mut store = LeaseStore::new(1);
        store.restore(Vec::new(), 100).unwrap();
        assert_eq!(
            update_dns(&mut store, true, false, false, None).status,
            DnsStatus::Pending
        );
        assert!(store.changes().dns);
        assert_eq!(
            update_dns(&mut store, true, false, false, Some(&mut Failed)).status,
            DnsStatus::Failed
        );
        assert!(store.changes().dns);
        assert_eq!(
            update_dns(&mut store, false, true, false, None).status,
            DnsStatus::NotNeeded
        );
        assert!(store.changes().dns);
    }

    #[test]
    fn failed_forced_dns_publication_retries_without_another_force() {
        struct Retry {
            fail: bool,
            calls: usize,
        }
        impl DnsPublisher for Retry {
            fn replace(&mut self, _: &[DnsLeaseRecord<'_>]) -> io::Result<()> {
                self.calls += 1;
                if self.fail {
                    Err(io::Error::other("publication temporarily unavailable"))
                } else {
                    Ok(())
                }
            }
        }
        let mut store = LeaseStore::new(1);
        let mut publisher = Retry {
            fail: false,
            calls: 0,
        };
        assert_eq!(
            update_dns(&mut store, true, true, false, Some(&mut publisher)).status,
            DnsStatus::Published
        );
        assert!(!store.changes().dns);
        publisher.fail = true;
        assert_eq!(
            update_dns(&mut store, true, true, false, Some(&mut publisher)).status,
            DnsStatus::Failed
        );
        assert!(
            store.changes().dns,
            "a forced replacement remains pending after failure"
        );
        publisher.fail = false;
        assert_eq!(
            update_dns(&mut store, true, false, false, Some(&mut publisher)).status,
            DnsStatus::Published
        );
        assert_eq!(publisher.calls, 3);
        assert!(!store.changes().dns);
    }
}
