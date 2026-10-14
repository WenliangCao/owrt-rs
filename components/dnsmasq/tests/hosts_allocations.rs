//! Every allocation on the hosts read/copy path is allowed to fail once. This
//! is a separate test binary so the allocator cannot affect other unit tests.
use dnsmasq_rs::hosts::Hosts;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
}
struct FailOne;
fn fail_now() -> bool {
    FAIL_AFTER
        .try_with(|remaining| match remaining.get() {
            Some(0) => {
                remaining.set(None);
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

#[test]
fn failed_hosts_allocations_keep_indexes_valid_and_allow_later_reload() {
    let input = b"192.0.2.1 One.Sub.Test alias.test\n192.0.2.2 One.Sub.Test\n192.0.2.1 One.Sub.Test\n2001:db8::1 v6.test\n";
    let mut exercised = 0;
    for failure in 0..200 {
        let mut hosts = Hosts::new();
        hosts.insert(b"ready.test".to_vec(), "192.0.2.41".parse().unwrap(), 10, 1);
        let (_, failed) = with_failure(failure, || hosts.read(input, 2, 20, false, |_| None));
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
    let mut exercised = 0;
    for failure in 0..100 {
        let source = HostSource {
            path: path.clone(),
            uid: 2,
        };
        let mut reader = HostsRead::open(source, &DnsConfig::default(), 20).unwrap();
        let (_, failed) = with_failure(failure, || while !reader.step().unwrap() {});
        let loaded = reader.finish();
        let mut hosts = Hosts::new();
        loaded.apply(&mut hosts);
        assert!(hosts.len() <= 3);
        if !failed {
            assert_eq!(hosts.len(), 3);
            break;
        }
        exercised += 1;
    }
    assert!(exercised > 3);
    std::fs::remove_file(path).unwrap();
}
