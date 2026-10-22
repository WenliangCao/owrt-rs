//! Inject single and sustained allocation failures on the hosts read/copy path.
//! This separate test binary cannot affect other unit tests' allocations.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use dnsmasq_rs::hosts::Hosts;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
    static FAIL_REPEAT: Cell<usize> = const { Cell::new(1) };
    static FAIL_MIN_BYTES: Cell<usize> = const { Cell::new(0) };
}
struct FailOne;
fn fail_now(bytes: usize) -> bool {
    if FAIL_MIN_BYTES
        .try_with(|minimum| bytes < minimum.get())
        .unwrap_or(false)
    {
        return false;
    }
    FAIL_AFTER
        .try_with(|remaining| match remaining.get() {
            Some(0) => {
                FAIL_REPEAT.with(|count| {
                    if count.get() <= 1 {
                        remaining.set(None);
                    } else {
                        count.set(count.get() - 1);
                    }
                });
                true
            }
            Some(n) => {
                remaining.set(Some(n - 1));
                false
            }
            None => false,
        })
        .unwrap_or(false)
}
// SAFETY: successful operations delegate the unchanged pointer/layout contract
// to System. Injection returns null only for allocation/reallocation failure;
// it never changes a live allocation, and deallocation is always forwarded.
unsafe impl GlobalAlloc for FailOne {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if fail_now(layout.size()) {
            std::ptr::null_mut()
        } else {
            // SAFETY: the caller supplied a valid allocation layout.
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if fail_now(layout.size()) {
            std::ptr::null_mut()
        } else {
            // SAFETY: System initializes the complete allocation for the caller-provided layout.
            unsafe { System.alloc_zeroed(layout) }
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if fail_now(size) {
            std::ptr::null_mut()
        } else {
            // SAFETY: the caller supplied the live System allocation, its layout and valid new size.
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller supplied a live System allocation with its original layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: FailOne = FailOne;

fn with_failure<T>(after: usize, action: impl FnOnce() -> T) -> (T, bool) {
    FAIL_AFTER.with(|remaining| remaining.set(Some(after)));
    let result = action();
    let failed = FAIL_AFTER.with(|remaining| remaining.replace(None).is_none());
    (result, failed)
}

fn with_persistent_failure<T>(after: usize, action: impl FnOnce() -> T) -> (T, bool) {
    FAIL_REPEAT.with(|count| count.set(usize::MAX));
    FAIL_AFTER.with(|remaining| remaining.set(Some(after)));
    let result = action();
    FAIL_AFTER.with(|remaining| remaining.set(None));
    let failed = FAIL_REPEAT.with(|count| count.replace(1) != usize::MAX);
    (result, failed)
}

#[test]
fn persistent_hosts_failure_stops_reading_and_allows_a_later_generation() {
    struct CountedRead<'a> {
        remaining: &'a [u8],
        reads_after_failure: usize,
    }
    impl std::io::Read for CountedRead<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if FAIL_REPEAT.with(|count| count.get() != usize::MAX) {
                self.reads_after_failure += 1;
            }
            let length = self.remaining.len().min(output.len()).min(64);
            output[..length].copy_from_slice(&self.remaining[..length]);
            self.remaining = &self.remaining[length..];
            Ok(length)
        }
    }
    let mut input = Vec::new();
    for index in 0..512 {
        use std::io::Write;
        writeln!(input, "192.0.2.2 name{index}.branch{index}.test").unwrap();
    }
    for failure in 0..200 {
        let mut hosts = Hosts::new();
        hosts.insert(b"ready.test".to_vec(), "192.0.2.41".parse().unwrap(), 10, 1);
        let mut reader = CountedRead {
            remaining: &input,
            reads_after_failure: 0,
        };
        let (stats, failed) = with_persistent_failure(failure, || {
            hosts.read_from(&mut reader, 2, 20, false, |_| None)
        });
        assert!(failed, "allocation {failure} must be exercised");
        assert!(
            stats.allocation_failed,
            "allocation {failure} must be reported"
        );
        assert_eq!(reader.reads_after_failure, 0);
        assert!(
            !reader.remaining.is_empty(),
            "do not consume the rest of the file"
        );
        assert_eq!(stats.bad_addresses, 0);
        assert_eq!(stats.bad_names, 0);
        assert_eq!(hosts.addresses(b"ready.test").count(), 1);
        for host in hosts.entries() {
            assert!(hosts.addresses(&host.name).any(|found| found == host));
            if host.reverse {
                assert!(hosts.reverse_all(host.address).any(|owner| owner == host));
            }
        }
        hosts.remove_uid(2);
        let recovered = hosts.read(&input, 2, 20, false, |_| None);
        assert!(!recovered.allocation_failed);
        assert_eq!(recovered.inserted, 512);
        assert_eq!(hosts.len(), 513);
    }
}

#[test]
fn duplicate_and_read_error_are_not_allocation_failures() {
    struct FailsAfterPrefix<'a>(Option<&'a [u8]>);
    impl std::io::Read for FailsAfterPrefix<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let Some(prefix) = self.0.take() else {
                return Err(std::io::ErrorKind::Other.into());
            };
            output[..prefix.len()].copy_from_slice(prefix);
            Ok(prefix.len())
        }
    }
    let input = b"192.0.2.1 same.test\n192.0.2.1 same.test";
    for read_error in [false, true] {
        let mut hosts = Hosts::new();
        let stats = if read_error {
            hosts.read_from(FailsAfterPrefix(Some(input)), 2, 20, false, |_| None)
        } else {
            hosts.read(input, 2, 20, false, |_| None)
        };
        assert!(!stats.allocation_failed);
        assert_eq!(stats.accepted, 2);
        assert_eq!(stats.inserted, 1);
        assert_eq!(hosts.len(), 1);
    }
}

#[test]
fn removing_uppercase_name_records_is_atomic_under_allocation_failure() {
    for shared in [false, true] {
        for persistent in [false, true] {
            let mut completed = false;
            let mut failures = 0;
            for failure in 0..128 {
                let mut local = Hosts::new();
                local.insert(
                    b"Representative.Test".to_vec(),
                    "192.0.2.1".parse().unwrap(),
                    37,
                    2,
                );
                local.insert(
                    b"REPRESENTATIVE.TEST".to_vec(),
                    "192.0.2.2".parse().unwrap(),
                    37,
                    3,
                );
                let held = shared.then(|| local.tcp_snapshot());
                let expected = local.entries().to_vec();
                let action = || local.try_remove_uid(2);
                let (result, failed) = if persistent {
                    with_persistent_failure(failure, action)
                } else {
                    with_failure(failure, action)
                };
                assert_eq!(result.is_err(), failed);
                if let Some(held) = &held {
                    assert_eq!(held.entries(), expected);
                    assert!(held.name_exists(b"representative.test"));
                }
                if let Ok(removed) = result {
                    assert_eq!(removed, 1);
                    assert_eq!(local.addresses(b"representative.test").count(), 1);
                    assert!(local.name_exists(b"representative.test"));
                    assert!(local.name_exists(b"REPRESENTATIVE.TEST"));
                    assert_eq!(local.try_remove_uid(3).unwrap(), 1);
                    assert!(!local.name_exists(b"representative.test"));
                    completed = true;
                    break;
                }
                assert_eq!(local.entries(), expected);
                assert_eq!(local.addresses(b"representative.test").count(), 2);
                assert!(local.name_exists(b"REPRESENTATIVE.TEST"));
                failures += 1;
            }
            assert!(completed && failures > 0);
        }
    }
}

#[test]
fn failed_hosts_allocations_keep_indexes_valid_and_allow_later_reload() {
    let input = b"192.0.2.1 One.Sub.Test alias.test\n192.0.2.2 One.Sub.Test\n192.0.2.1 One.Sub.Test\n2001:db8::1 v6.test\n";
    let mut exercised = 0;
    for failure in 0..200 {
        let mut hosts = Hosts::new();
        hosts.insert(b"ready.test".to_vec(), "192.0.2.41".parse().unwrap(), 10, 1);
        let (stats, failed) = with_failure(failure, || hosts.read(input, 2, 20, false, |_| None));
        assert_eq!(stats.allocation_failed, failed);
        if !failed {
            break;
        }
        exercised += 1;
        assert_eq!(hosts.addresses(b"ready.test").count(), 1);
        for host in hosts.entries() {
            assert!(hosts.addresses(&host.name).any(|found| found == host));
            if host.reverse {
                assert!(hosts.reverse_all(host.address).any(|owner| owner == host));
            }
        }
        let (_, failed) = with_failure(0, || hosts.remove_uid(2));
        assert!(failed, "exercise the no-change removal fallback");
        hosts.remove_uid(2);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts.read(input, 2, 20, false, |_| None).inserted, 4);
        assert_eq!(hosts.len(), 5);
    }
    assert!(exercised > 10);
}

#[test]
fn failed_snapshot_copy_leaves_original_order_and_sources_intact() {
    let mut hosts = Hosts::new();
    hosts.set_source_name(2, b"/hosts".to_vec());
    hosts.read(
        b"192.0.2.1 one.test\n192.0.2.2 one.test\n",
        2,
        20,
        false,
        |_| None,
    );
    hosts.lookup(b"one.test", Some(false), false);
    let mut exercised = 0;
    let mut completed = false;
    for failure in 0..100 {
        let (copy, failed) = with_failure(failure, || hosts.try_clone());
        assert_eq!(
            hosts
                .addresses(b"one.test")
                .next()
                .unwrap()
                .address
                .to_string(),
            "192.0.2.2"
        );
        assert_eq!(hosts.source_name(2), Some(b"/hosts".as_slice()));
        if !failed {
            let copy = copy.unwrap();
            assert_eq!(copy.entries(), hosts.entries());
            assert_eq!(
                copy.addresses(b"one.test").next(),
                hosts.addresses(b"one.test").next()
            );
            completed = true;
            break;
        }
        exercised += 1;
        assert!(copy.is_err());
    }
    assert!(exercised > 5);
    assert!(completed, "snapshot copy must reach a successful control");
}

#[test]
fn expanded_names_skip_failed_allocations_without_becoming_bad_names() {
    let mut completed = false;
    for failure in 0..80 {
        let mut hosts = Hosts::new();
        let (stats, failed) = with_failure(failure, || {
            hosts.read(b"192.0.2.1 short alias\n", 2, 20, true, |_| {
                dnsmasq_rs::hosts::try_copy(b"example.test").ok()
            })
        });
        assert_eq!(stats.bad_names, 0);
        assert_eq!(stats.bad_addresses, 0);
        if !failed {
            assert_eq!(hosts.len(), 4);
            completed = true;
            break;
        }
    }
    assert!(completed, "expanded names must reach a successful control");
}

#[cfg(target_os = "linux")]
#[test]
fn staged_hosts_records_and_diagnostics_tolerate_failed_growth() {
    use dnsmasq_rs::config::dns::DnsConfig;
    use dnsmasq_rs::dns::hostsdir::{HostSource, HostsRead};
    let path = std::env::temp_dir().join(format!("hosts-fallible-{}", std::process::id()));
    std::fs::write(
        &path,
        b"192.0.2.1 first.test second.test\nbad ignored\n192.0.2.2 \xff third.test\n",
    )
    .unwrap();
    let config = DnsConfig::default();
    let mut exercised = 0;
    let mut completed = false;
    for failure in 0..100 {
        let source = HostSource {
            path: path.clone(),
            uid: 2,
        };
        let mut reader = HostsRead::open(source, 20).unwrap();
        let (_, failed) = with_failure(failure, || while !reader.step(&config).unwrap() {});
        let loaded = reader.finish();
        let incomplete = loaded.allocation_failed;
        if incomplete {
            assert!(loaded.records.is_empty());
            assert!(loaded.bad_lines.is_empty());
            assert!(loaded.line_ends.is_empty());
        }
        let mut hosts = Hosts::new();
        hosts.insert(
            b"preserved.test".to_vec(),
            "192.0.2.41".parse().unwrap(),
            20,
            2,
        );
        loaded.apply(&mut hosts);
        if incomplete {
            assert_eq!(hosts.len(), 1);
            assert!(hosts.addresses(b"preserved.test").next().is_some());
        } else {
            assert_eq!(hosts.len(), 3);
        }
        if !failed {
            completed = true;
            break;
        }
        exercised += 1;
    }
    assert!(exercised > 3);
    assert!(completed, "staged input must reach a successful control");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn consecutive_publication_and_restore_failures_leave_last_daemon_snapshot_intact() {
    let mut daemon = Hosts::new();
    daemon.read(
        b"192.0.2.41 retained.test\n192.0.2.42 old.test\n",
        2,
        37,
        false,
        |_| None,
    );
    let mut replacement = Hosts::new();
    replacement.read(b"192.0.2.43 new.test\n", 3, 37, false, |_| None);
    FAIL_REPEAT.with(|count| count.set(2));
    FAIL_AFTER.with(|remaining| remaining.set(Some(0)));
    let publication = replacement.try_clone();
    drop(replacement);
    let restoration = daemon.try_clone();
    FAIL_AFTER.with(|remaining| remaining.set(None));
    FAIL_REPEAT.with(|count| count.set(1));
    assert!(publication.is_err());
    assert!(restoration.is_err());
    assert_eq!(daemon.len(), 2);
    let restored = daemon.try_clone().unwrap();
    assert_eq!(restored.entries(), daemon.entries());
}

#[test]
fn retained_hosts_restore_without_allocating_after_failed_publication() {
    for (incremental, shared) in [(false, false), (false, true), (true, true)] {
        let mut local = Hosts::new();
        local.insert(b"ready.test".to_vec(), "192.0.2.41".parse().unwrap(), 37, 1);
        local.read(
            b"192.0.2.42 old.test\n192.0.2.43 old.test\n",
            2,
            37,
            false,
            |_| None,
        );
        local.set_source_name(2, b"/old-hosts".to_vec());
        assert!(!local.has_shared_records());
        let held = shared.then(|| local.tcp_snapshot());
        assert_eq!(local.has_shared_records(), shared);
        // The parent has private query order as well as shared records.
        local.lookup(b"old.test", Some(false), false);
        let expected = local.try_clone().unwrap();
        let original_records = local.entries().as_ptr();
        let previous = if incremental {
            let working = local.try_clone().unwrap();
            std::mem::replace(&mut local, working)
        } else {
            std::mem::take(&mut local)
        };
        if incremental {
            assert_eq!(local.try_remove_uid(2).unwrap(), 2);
        }
        local.read(b"192.0.2.44 new.test\n", 2, 37, false, |_| None);
        let ((failed_publication, restore_attempts), failed) = with_persistent_failure(0, || {
            let failed_publication = local.try_clone().is_err();
            let before = FAIL_REPEAT.with(Cell::get);
            local = previous;
            let after = FAIL_REPEAT.with(Cell::get);
            (failed_publication, before - after)
        });
        assert!(failed && failed_publication);
        assert_eq!(
            restore_attempts, 0,
            "restoring a retained owner cannot allocate"
        );
        assert_eq!(local.entries().as_ptr(), original_records);
        assert_eq!(local.entries(), expected.entries());
        assert_eq!(local.source_name(2), Some(b"/old-hosts".as_slice()));
        assert_eq!(
            local.addresses(b"old.test").collect::<Vec<_>>(),
            expected.addresses(b"old.test").collect::<Vec<_>>()
        );
        assert_eq!(local.addresses(b"ready.test").count(), 1);
        assert_eq!(local.addresses(b"new.test").count(), 0);
        let later = local.tcp_snapshot();
        assert_eq!(later.entries().as_ptr(), original_records);
        if let Some(held) = &held {
            assert_eq!(held.addresses(b"old.test").count(), 2);
        }
        drop((held, later));
        assert!(!local.has_shared_records(), "a sole Arc owner is exclusive");
        // A later successful update publishes new data without altering the
        // retained connection's accepted generation.
        let held = local.tcp_snapshot();
        local.try_remove_uid(2).unwrap();
        local.read(b"192.0.2.44 new.test\n", 2, 37, false, |_| None);
        assert_eq!(local.addresses(b"ready.test").count(), 1);
        assert_eq!(local.addresses(b"new.test").count(), 1);
        assert_eq!(local.addresses(b"old.test").count(), 0);
        assert_eq!(held.addresses(b"old.test").count(), 2);
    }
}

#[test]
fn incremental_transaction_preserves_owners_at_every_allocation_failure() {
    for shared in [false, true] {
        for deleted in [false, true] {
            for persistent in [false, true] {
                let mut local = Hosts::new();
                local.insert(b"ready.test".to_vec(), "192.0.2.41".parse().unwrap(), 37, 1);
                local.read(
                    b"192.0.2.42 old.test\n192.0.2.43 old.test\n",
                    2,
                    37,
                    false,
                    |_| None,
                );
                local.set_source_name(2, b"/old-hosts".to_vec());
                // Removing source 2 must not promote another source's
                // previously suppressed PTR ownership.
                local.insert(
                    b"retained.test".to_vec(),
                    "192.0.2.42".parse().unwrap(),
                    37,
                    3,
                );
                let daemon = local.try_clone().unwrap();
                let held = shared.then(|| local.tcp_snapshot());
                local.lookup(b"old.test", Some(false), false);
                let expected = local.try_clone().unwrap();
                let original_records = local.entries().as_ptr();
                let mut exercised = 0;
                let mut completed = false;
                for failure in 0..256 {
                    let records = if deleted {
                        Vec::new()
                    } else {
                        [
                            (b"new.test".as_slice(), "192.0.2.44"),
                            (b"new.test".as_slice(), "192.0.2.44"),
                            (b"new.test".as_slice(), "192.0.2.45"),
                            (b"leaf.deep.branch.test".as_slice(), "192.0.2.46"),
                        ]
                        .into_iter()
                        .map(|(name, address)| (name.to_vec(), address.parse().unwrap()))
                        .collect()
                    };
                    let action = || {
                        // This is the same assembler and publication copy
                        // used by the owner loop before either owner changes.
                        let (replacement, removed) =
                            local.try_replace_source(2, b"/new-hosts", records, 37)?;
                        let published = replacement.try_clone()?;
                        Ok::<_, dnsmasq_rs::hosts::IngestionError>((
                            replacement,
                            published,
                            removed,
                        ))
                    };
                    let (result, failed) = if persistent {
                        with_persistent_failure(failure, action)
                    } else {
                        with_failure(failure, action)
                    };
                    assert_eq!(result.is_err(), failed,
                        "allocation {failure}, shared={shared}, deleted={deleted}, persistent={persistent}");
                    assert_eq!(local.entries().as_ptr(), original_records);
                    assert_eq!(local.entries(), expected.entries());
                    assert_eq!(local.source_name(2), Some(b"/old-hosts".as_slice()));
                    assert_eq!(
                        local.addresses(b"old.test").collect::<Vec<_>>(),
                        expected.addresses(b"old.test").collect::<Vec<_>>()
                    );
                    assert_eq!(daemon.addresses(b"old.test").count(), 2);
                    if let Some(held) = &held {
                        assert_eq!(held.addresses(b"old.test").count(), 2);
                    }
                    if let Ok((replacement, published, removed)) = result {
                        assert_eq!(removed, 2);
                        assert_eq!(replacement.entries(), published.entries());
                        assert_eq!(replacement.source_name(2), Some(b"/new-hosts".as_slice()));
                        assert_eq!(replacement.addresses(b"ready.test").count(), 1);
                        assert_eq!(replacement.addresses(b"retained.test").count(), 1);
                        assert_eq!(replacement.addresses(b"old.test").count(), 0);
                        assert!(replacement.reverse("192.0.2.42".parse().unwrap()).is_none());
                        assert_eq!(replacement.len(), if deleted { 2 } else { 5 });
                        assert_eq!(
                            replacement.addresses(b"new.test").count(),
                            if deleted { 0 } else { 2 }
                        );
                        if !deleted {
                            assert!(replacement.name_exists(b"deep.branch.test"));
                        }
                        completed = true;
                        break;
                    }
                    exercised += 1;
                }
                assert!(completed && exercised > 20);
            }
        }
    }
}

// Exact C fixture: its temporary reverse hash and name lookup share `next`.
// With EDNS 1232, the packet buffer is 1232 + MAXDNAME(255) + RRFIXEDSZ(10).
const BULK_PACKET_BYTES: usize = 1497;
const BULK_PREFIX: &[u8] =
    b"192.0.2.2 old.test\n192.0.2.1 x.test\n192.0.3.186 a.test\n192.0.3.185 a.test\n";
const BULK_SUFFIX: &[u8] = b"192.0.2.1 y.test\n192.0.2.2 y.test\n";

fn ptr_names(hosts: &Hosts, address: &str) -> Vec<Vec<u8>> {
    let mut names: Vec<_> = hosts
        .reverse_all(address.parse().unwrap())
        .map(|host| host.name.clone())
        .collect();
    names.sort();
    names
}

fn bulk_hosts() -> Hosts {
    let mut hosts = Hosts::new();
    hosts.begin_bulk(BULK_PACKET_BYTES, 1000, 1000).unwrap();
    assert!(
        !hosts
            .read(BULK_PREFIX, 2, 37, false, |_| None)
            .allocation_failed
    );
    assert!(
        !hosts
            .read(BULK_SUFFIX, 3, 37, false, |_| None)
            .allocation_failed
    );
    hosts.finish_bulk();
    assert_eq!(
        ptr_names(&hosts, "192.0.2.1"),
        [b"x.test".to_vec(), b"y.test".to_vec()]
    );
    hosts
}

#[test]
fn completed_generation_snapshots_do_not_keep_bulk_ingestion_links() {
    for no_round_robin in [false, true] {
        let mut parent = Hosts::new();
        parent.set_round_robin(!no_round_robin);
        parent.begin_bulk(BULK_PACKET_BYTES, 1000, 1000).unwrap();
        assert!(
            !parent
                .read(BULK_PREFIX, 2, 37, false, |_| None)
                .allocation_failed
        );
        // Only completed generations may reach a TCP reader. Publishing a
        // completed copy must not destroy the separate loader's cross-source
        // history, or retain that history in the published copy's snapshots.
        let mut published = parent.try_clone().unwrap();
        published.finish_bulk();
        let mut child = published.tcp_snapshot();
        assert_eq!(published.entries().as_ptr(), child.entries().as_ptr());
        assert!(
            !parent
                .read(BULK_SUFFIX, 3, 37, false, |_| None)
                .allocation_failed
        );
        assert!(
            !child
                .read(BULK_SUFFIX, 3, 37, false, |_| None)
                .allocation_failed
        );
        assert_eq!(
            ptr_names(&parent, "192.0.2.1"),
            [b"x.test".to_vec(), b"y.test".to_vec()]
        );
        assert_eq!(
            ptr_names(&child, "192.0.2.1"),
            [b"x.test".to_vec()],
            "the TCP reader must use incremental ownership, with no ingestion sidecar"
        );
        parent.finish_bulk();
        parent.read(b"192.0.2.1 later.test\n", 4, 37, false, |_| None);
        assert_eq!(
            ptr_names(&parent, "192.0.2.1"),
            [b"x.test".to_vec(), b"y.test".to_vec()]
        );
    }
}

#[test]
fn fallible_bulk_copy_preserves_the_loading_owners_links() {
    for retained_lease in [false, true] {
        for persistent in [false, true] {
            let mut loading = Hosts::new();
            loading.begin_bulk(BULK_PACKET_BYTES, 1000, 1000).unwrap();
            if retained_lease {
                loading
                    .add_bulk_lease(b"a.test", "192.0.2.1".parse().unwrap(), true, false)
                    .unwrap();
            }
            let expected = if retained_lease {
                vec![b"x.test".to_vec()]
            } else {
                vec![b"x.test".to_vec(), b"y.test".to_vec()]
            };
            loading.read(BULK_PREFIX, 2, 37, false, |_| None);
            let pointer = loading.entries().as_ptr();
            let mut completed = false;
            for failure in 0..256 {
                let (result, failed) = if persistent {
                    with_persistent_failure(failure, || loading.try_clone())
                } else {
                    with_failure(failure, || loading.try_clone())
                };
                assert_eq!(result.is_err(), failed);
                assert_eq!(loading.entries().as_ptr(), pointer);
                assert_eq!(loading.len(), 4);
                if let Ok(mut copy) = result {
                    assert!(
                        !copy
                            .read(BULK_SUFFIX, 3, 37, false, |_| None)
                            .allocation_failed
                    );
                    copy.finish_bulk();
                    assert_eq!(ptr_names(&copy, "192.0.2.1"), expected);
                    completed = true;
                    break;
                }
            }
            assert!(completed);
            assert!(
                !loading
                    .read(BULK_SUFFIX, 3, 37, false, |_| None)
                    .allocation_failed
            );
            loading.finish_bulk();
            assert_eq!(ptr_names(&loading, "192.0.2.1"), expected);
        }
    }
}

#[test]
fn bulk_generation_failures_never_replace_existing_multiple_ptr_owners() {
    for shared in [false, true] {
        for persistent in [false, true] {
            let mut local = bulk_hosts();
            let daemon = local.try_clone().unwrap();
            let held = shared.then(|| local.tcp_snapshot());
            let old_pointer = local.entries().as_ptr();
            let mut completed = false;
            let mut exercised = 0;
            for failure in 0..512 {
                let action = || {
                    let mut replacement = Hosts::new();
                    replacement.begin_bulk(BULK_PACKET_BYTES, 1000, 1000)?;
                    for (source, input) in [(2, BULK_PREFIX), (3, BULK_SUFFIX)] {
                        if replacement
                            .read(input, source, 37, false, |_| None)
                            .allocation_failed
                        {
                            return Err(dnsmasq_rs::hosts::IngestionError);
                        }
                    }
                    replacement.finish_bulk();
                    let published = replacement.try_clone()?;
                    Ok((replacement, published))
                };
                let (result, failed) = if persistent {
                    with_persistent_failure(failure, action)
                } else {
                    with_failure(failure, action)
                };
                assert_eq!(
                    result.is_err(),
                    failed,
                    "allocation {failure}, shared={shared}, persistent={persistent}"
                );
                assert_eq!(local.entries().as_ptr(), old_pointer);
                for old in [&local, &daemon].into_iter().chain(held.iter()) {
                    assert_eq!(
                        ptr_names(old, "192.0.2.1"),
                        [b"x.test".to_vec(), b"y.test".to_vec()]
                    );
                }
                if let Ok((replacement, published)) = result {
                    assert_eq!(replacement.entries(), published.entries());
                    assert_eq!(
                        ptr_names(&replacement, "192.0.2.1"),
                        [b"x.test".to_vec(), b"y.test".to_vec()]
                    );
                    completed = true;
                    break;
                }
                exercised += 1;
            }
            assert!(completed && exercised > 30);
        }
    }
}

#[test]
fn deleting_either_multiple_ptr_source_is_atomic_under_allocation_failure() {
    for shared in [false, true] {
        for source in [2, 3] {
            for persistent in [false, true] {
                let mut local = bulk_hosts();
                let daemon = local.try_clone().unwrap();
                let held = shared.then(|| local.tcp_snapshot());
                let old_pointer = local.entries().as_ptr();
                let expected = if source == 2 {
                    b"y.test".as_slice()
                } else {
                    b"x.test".as_slice()
                };
                let mut completed = false;
                for failure in 0..512 {
                    let action = || {
                        let (replacement, removed) =
                            local.try_replace_source(source, b"/deleted", Vec::new(), 37)?;
                        let published = replacement.try_clone()?;
                        Ok::<_, dnsmasq_rs::hosts::IngestionError>((
                            replacement,
                            published,
                            removed,
                        ))
                    };
                    let (result, failed) = if persistent {
                        with_persistent_failure(failure, action)
                    } else {
                        with_failure(failure, action)
                    };
                    assert_eq!(result.is_err(), failed, "allocation {failure}, source={source}, shared={shared}, persistent={persistent}");
                    assert_eq!(local.entries().as_ptr(), old_pointer);
                    for old in [&local, &daemon].into_iter().chain(held.iter()) {
                        assert_eq!(
                            ptr_names(old, "192.0.2.1"),
                            [b"x.test".to_vec(), b"y.test".to_vec()]
                        );
                    }
                    if let Ok((replacement, published, removed)) = result {
                        assert_eq!(removed, if source == 2 { 4 } else { 2 });
                        assert_eq!(replacement.entries(), published.entries());
                        assert_eq!(ptr_names(&replacement, "192.0.2.1"), [expected.to_vec()]);
                        assert!(!replacement
                            .entries()
                            .iter()
                            .any(|host| host.source == source));
                        completed = true;
                        break;
                    }
                }
                assert!(completed);
            }
        }
    }
}

#[test]
fn retained_dhcp_bulk_links_match_finite_and_infinite_c_lease_controls() {
    use dnsmasq_rs::config::{dns::DnsConfig, lex_line};
    use dnsmasq_rs::dhcp::persistence::DnsLeaseRecord;
    use dnsmasq_rs::dns::lease_names::{LeaseNames, LeasePolicy};
    use dnsmasq_rs::dns::local::{configured_hosts, configured_hosts_bulk};

    // As in hosts.rs's finite/immortal C counterexample, earlier names must
    // not split the retained lease's name-hash chain. The hash includes process
    // pointers, so fixed "a.test" can collide under a different executable/ASLR.
    // Observe bucket topology through independent three-address insertion,
    // outside fault injection; never choose a fixture by its final PTR answer.
    fn shares_bucket(name: &[u8], blocker: &[u8]) -> bool {
        let mut hosts = Hosts::new();
        hosts.begin_bulk(BULK_PACKET_BYTES, 1000, 1000).unwrap();
        let first = "192.0.2.10".parse().unwrap();
        let middle = "192.0.2.11".parse().unwrap();
        let last = "192.0.2.12".parse().unwrap();
        for (name, address) in [(name, first), (blocker, middle), (name, last)] {
            assert!(hosts.insert_checked(name.to_vec(), address, 37, 2).unwrap());
        }
        let addresses: Vec<_> = hosts.addresses(name).map(|host| host.address).collect();
        assert!(addresses == [first, last] || addresses == [last, first]);
        addresses == [last, first]
    }
    let lease = (0..10000)
        .map(|id| format!("a{id}.test"))
        .find(|name| {
            [b"ready.test".as_slice(), b"old.test", b"x.test"]
                .into_iter()
                .all(|blocker| !shares_bucket(name.as_bytes(), blocker))
        })
        .expect("bounded name pool has a separate bucket");
    let prefix = std::str::from_utf8(BULK_PREFIX)
        .unwrap()
        .replace("a.test", &lease);

    let mut config = DnsConfig::default();
    config
        .apply(
            &lex_line(b"host-record=ready.test,192.0.2.41")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    for expires in [None, Some(3600)] {
        for shared in [false, true] {
            for persistent in [false, true] {
                let mut old = configured_hosts(&config, 37);
                let retained = LeaseNames::build(
                    &[DnsLeaseRecord {
                        name: lease.as_bytes(),
                        address: "192.0.2.1".parse().unwrap(),
                        expires,
                    }],
                    &mut old,
                    &[],
                    LeasePolicy::default(),
                    &mut (),
                );
                assert_eq!(retained.active_entries().count(), 1);
                assert!(retained.entries()[0].reverse);
                let old_input = retained.entries()[0].clone();
                let held = shared.then(|| old.tcp_snapshot());
                let pointer = old.entries().as_ptr();
                let mut completed = false;
                for failure in 0..512 {
                    let action = || {
                        let mut replacement = configured_hosts_bulk(
                            &config,
                            37,
                            BULK_PACKET_BYTES,
                            1000,
                            1000,
                            &retained,
                        )?;
                        for (source, input) in [(2, prefix.as_bytes()), (3, BULK_SUFFIX)] {
                            if replacement
                                .read(input, source, 37, false, |_| None)
                                .allocation_failed
                            {
                                return Err(dnsmasq_rs::hosts::IngestionError);
                            }
                        }
                        replacement.finish_bulk();
                        let published = replacement.try_clone()?;
                        Ok((replacement, published))
                    };
                    let (result, failed) = if persistent {
                        with_persistent_failure(failure, action)
                    } else {
                        with_failure(failure, action)
                    };
                    assert_eq!(result.is_err(), failed,
                        "allocation {failure}, expires={expires:?}, shared={shared}, persistent={persistent}");
                    assert_eq!(old.entries().as_ptr(), pointer);
                    assert_eq!(old.len(), 1);
                    assert_eq!(retained.entries(), std::slice::from_ref(&old_input));
                    if let Some(held) = &held {
                        assert_eq!(held.entries(), old.entries());
                    }
                    if let Ok((mut replacement, published)) = result {
                        let expected = if expires.is_some() {
                            vec![b"x.test".to_vec()]
                        } else {
                            vec![b"x.test".to_vec(), b"y.test".to_vec()]
                        };
                        assert_eq!(
                            ptr_names(&replacement, "192.0.2.1"),
                            expected,
                            "fixture lease={lease}"
                        );
                        assert_eq!(ptr_names(&published, "192.0.2.1"), expected);
                        assert_eq!(replacement.len(), 7, "DHCP shadows are not published hosts");
                        let leases = retained.rebuild(&mut replacement, &[], &mut ());
                        assert_eq!(
                            leases.lookup(lease.as_bytes(), 0).count(),
                            0,
                            "same-name static host suppresses the old lease after bulk loading"
                        );
                        assert_eq!(
                            ptr_names(&replacement, "192.0.2.1"),
                            expected,
                            "post-HUP lease removal must not rewrite bulk PTR ownership"
                        );
                        completed = true;
                        break;
                    }
                }
                assert!(completed);
            }
        }
    }
}

#[test]
fn failed_query_page_copy_keeps_the_shared_chain_and_complete_answer() {
    fn answer(hosts: &mut Hosts) -> [std::net::IpAddr; 3] {
        let rows = hosts.lookup(b"many.test", Some(false), false);
        assert_eq!(rows.len(), 3);
        [rows[0].address, rows[1].address, rows[2].address]
    }
    for persistent in [false, true] {
        let mut parent = Hosts::new();
        parent.read(
            b"192.0.2.1 many.test\n192.0.2.2 many.test\n192.0.2.3 many.test\n",
            2,
            37,
            false,
            |_| None,
        );
        let mut reference = parent.try_clone().unwrap();
        let expected = answer(&mut reference);
        let mut child = parent.tcp_snapshot();
        // Three-answer scratch allocations are small; fail only the 512-byte
        // copy-on-write link/head pages, after the answer has been selected.
        FAIL_MIN_BYTES.with(|minimum| minimum.set(128));
        let (actual, failed) = if persistent {
            with_persistent_failure(0, || [answer(&mut child), answer(&mut child)])
        } else {
            let (first, failed) = with_failure(0, || answer(&mut child));
            ([first, expected], failed)
        };
        FAIL_MIN_BYTES.with(|minimum| minimum.set(0));
        assert!(
            failed,
            "a shared global chain page must exercise the copy failure"
        );
        assert_eq!(actual, [expected, expected]);
        assert_eq!(
            answer(&mut child),
            expected,
            "a failed page copy must not publish part of a rotation"
        );
        assert_eq!(answer(&mut child), answer(&mut reference));
        assert_eq!(
            answer(&mut parent),
            expected,
            "the TCP child cannot change its parent's chain"
        );
    }
}

#[test]
fn incremental_retained_lease_ownership_is_atomic_at_every_allocation_failure() {
    use dnsmasq_rs::dhcp::persistence::DnsLeaseRecord;
    use dnsmasq_rs::dns::lease_names::{LeaseNames, LeasePolicy};
    use std::net::IpAddr;
    for expires in [None, Some(3600)] {
        for shared in [false, true] {
            for persistent in [false, true] {
                let mut local = Hosts::new();
                local.insert(b"ready.test".to_vec(), "192.0.2.41".parse().unwrap(), 37, 1);
                let leases = LeaseNames::build(
                    &[DnsLeaseRecord {
                        name: b"lease.test",
                        address: "192.0.2.1".parse().unwrap(),
                        expires,
                    }],
                    &mut local,
                    &[],
                    LeasePolicy::default(),
                    &mut (),
                );
                let held = shared.then(|| local.tcp_snapshot());
                let pointer = local.entries().as_ptr();
                let mut completed = false;
                for failure in 0..512 {
                    let records = vec![
                        (b"lease.test".to_vec(), "192.0.2.1".parse().unwrap()),
                        (b"alias.test".to_vec(), "192.0.2.1".parse().unwrap()),
                    ];
                    let action = || {
                        let (mut replacement, removed) = local.try_replace_source_with_leases(
                            2,
                            b"/hostsdir/hosts",
                            records,
                            37,
                            leases.active_entries().map(|lease| {
                                (
                                    lease.name.as_ref(),
                                    IpAddr::V4(lease.address),
                                    lease.reverse,
                                    lease.expires.is_none(),
                                )
                            }),
                            [2],
                        )?;
                        replacement.finish_bulk();
                        let published = replacement.try_clone()?;
                        Ok::<_, dnsmasq_rs::hosts::IngestionError>((
                            replacement,
                            published,
                            removed,
                        ))
                    };
                    let (result, failed) = if persistent {
                        with_persistent_failure(failure, action)
                    } else {
                        with_failure(failure, action)
                    };
                    assert_eq!(result.is_err(), failed,
                        "allocation {failure}, expires={expires:?}, shared={shared}, persistent={persistent}");
                    assert_eq!(local.entries().as_ptr(), pointer);
                    assert_eq!(local.len(), 1);
                    assert_eq!(leases.lookup(b"lease.test", 0).count(), 1);
                    if let Some(held) = &held {
                        assert_eq!(held.entries(), local.entries());
                    }
                    if let Ok((replacement, published, removed)) = result {
                        assert_eq!(removed, 0);
                        let expected = if expires.is_none() {
                            vec![b"alias.test".to_vec(), b"lease.test".to_vec()]
                        } else {
                            vec![b"lease.test".to_vec()]
                        };
                        assert_eq!(ptr_names(&replacement, "192.0.2.1"), expected);
                        assert_eq!(ptr_names(&published, "192.0.2.1"), expected);
                        assert_eq!(replacement.len(), 3);
                        completed = true;
                        break;
                    }
                }
                assert!(completed);
            }
        }
    }
}
