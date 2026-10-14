//! Inject single and sustained allocation failures on the hosts read/copy path.
//! This separate test binary cannot affect other unit tests' allocations.
use dnsmasq_rs::hosts::Hosts;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
    static FAIL_REPEAT: Cell<usize> = const { Cell::new(1) };
}
struct FailOne;
fn fail_now() -> bool {
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
unsafe impl GlobalAlloc for FailOne {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if fail_now() {
            std::ptr::null_mut()
        } else {
            System.alloc(layout)
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if fail_now() {
            std::ptr::null_mut()
        } else {
            System.alloc_zeroed(layout)
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if fail_now() {
            std::ptr::null_mut()
        } else {
            System.realloc(ptr, layout, size)
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
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
                assert_eq!(hosts.reverse(host.address), Some(host));
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
                assert_eq!(hosts.reverse(host.address), Some(host));
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
            break;
        }
        exercised += 1;
        assert!(copy.is_err());
    }
    assert!(exercised > 5);
}

#[test]
fn expanded_names_skip_failed_allocations_without_becoming_bad_names() {
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
            break;
        }
    }
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
            break;
        }
        exercised += 1;
    }
    assert!(exercised > 3);
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
        local.read(b"192.0.2.42 old.test\n192.0.2.43 old.test\n", 2, 37, false, |_| None);
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
        assert_eq!(restore_attempts, 0, "restoring a retained owner cannot allocate");
        assert_eq!(local.entries().as_ptr(), original_records);
        assert_eq!(local.entries(), expected.entries());
        assert_eq!(local.source_name(2), Some(b"/old-hosts".as_slice()));
        assert_eq!(local.addresses(b"old.test").collect::<Vec<_>>(),
            expected.addresses(b"old.test").collect::<Vec<_>>());
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
                local.read(b"192.0.2.42 old.test\n192.0.2.43 old.test\n", 2, 37, false, |_| None);
                local.set_source_name(2, b"/old-hosts".to_vec());
                // Removing source 2 must not promote another source's
                // previously suppressed PTR ownership.
                local.insert(b"retained.test".to_vec(), "192.0.2.42".parse().unwrap(), 37, 3);
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
                        ].into_iter().map(|(name, address)|
                            (name.to_vec(), address.parse().unwrap())
                        ).collect()
                    };
                    let action = || {
                        // This is the same assembler and publication copy
                        // used by the owner loop before either owner changes.
                        let (replacement, removed) =
                            local.try_replace_source(2, b"/new-hosts", records, 37)?;
                        let published = replacement.try_clone().map_err(|_| ())?;
                        Ok::<_, ()>((replacement, published, removed))
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
                    assert_eq!(local.addresses(b"old.test").collect::<Vec<_>>(),
                        expected.addresses(b"old.test").collect::<Vec<_>>());
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
                        assert_eq!(replacement.addresses(b"new.test").count(), if deleted { 0 } else { 2 });
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
