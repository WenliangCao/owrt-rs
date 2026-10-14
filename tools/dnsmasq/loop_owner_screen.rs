// Append to a private copy of main.rs. Measures actual step_udp allocations;
// the allocator is never linked into a release artifact.
#[cfg(test)]
mod loop_allocation_screen {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    static REALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    static BYTES: AtomicU64 = AtomicU64::new(0);
    static DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    static FREED_BYTES: AtomicU64 = AtomicU64::new(0);
    struct Meter;
    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCATIONS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size() as u64, Relaxed);
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            DEALLOCATIONS.fetch_add(1, Relaxed);
            FREED_BYTES.fetch_add(layout.size() as u64, Relaxed);
            unsafe { System.dealloc(pointer, layout) };
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            REALLOCATIONS.fetch_add(1, Relaxed);
            BYTES.fetch_add(size as u64, Relaxed);
            unsafe { System.realloc(pointer, layout, size) }
        }
    }
    #[global_allocator]
    static METER: Meter = Meter;
    fn snapshot() -> [u64; 3] {
        [ALLOCATIONS.load(Relaxed), REALLOCATIONS.load(Relaxed), BYTES.load(Relaxed)]
    }

    #[test]
    fn udp_owner_counts() {
        use dnsmasq_rs::config::lex_line;
        use dnsmasq_rs::dns::wire::{Name, PacketWriter};
        let mut config = DnsConfig::default();
        config.bind_interfaces = true;
        config.no_hosts = true;
        config.no_resolv = true;
        config.apply(&lex_line(b"host-record=ready.test,192.0.2.7").unwrap().unwrap()).unwrap();
        let daemon = DnsDaemon::new(config.clone(), read_hosts(&config, 37), &[],
            DaemonOptions::default()).unwrap();
        let mut owner = tests::test_owner(config, Some(daemon));
        let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = udp.local_addr().unwrap();
        owner.ready_fds.push(owrt_ubus::sys::PollFd {
            fd: udp.as_raw_fd(), events: owrt_ubus::sys::POLLIN,
            revents: owrt_ubus::sys::POLLIN,
        });
        owner.add_listener(SocketToken(1), Some(udp), None);
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut writer = PacketWriter::new(7, 0x100, 1232).unwrap();
        writer.question(&Name::from_ascii("ready.test").unwrap(), 1, 1).unwrap();
        let query = writer.finish();
        let mut answer = [0; 1232];
        let mut counts = [0; 3];
        let iterations = 1000;
        for index in 0..=iterations {
            peer.send_to(&query, address).unwrap();
            let before = snapshot();
            assert!(owner.step_udp(0));
            let after = snapshot();
            let (length, _) = peer.recv_from(&mut answer).unwrap();
            assert!(answer[..length].ends_with(&[192, 0, 2, 7]));
            assert_eq!(owner.udp_buffer.len(), 65535);
            if index != 0 {
                for field in 0..3 { counts[field] += after[field] - before[field]; }
            }
        }
        println!("OWNER_ALLOCATION {{\"iterations\":{iterations},\"query_bytes\":{},\"alloc_realloc_bytes\":{counts:?}}}", query.len());
    }

    #[test]
    fn upstream_poll_counts() {
        use dnsmasq_rs::config::lex_line;
        use dnsmasq_rs::dns::wire::{Name, PacketWriter};
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_resolv = true;
        let setting = format!("server=127.0.0.1#{}", server.local_addr().unwrap().port());
        config.apply(&lex_line(setting.as_bytes()).unwrap().unwrap()).unwrap();
        let mut daemon = DnsDaemon::new(config, Hosts::new(), &[], DaemonOptions {
            upstream_lifetime: dnsmasq_rs::dns::upstream::Lifetime::Fixed(Duration::from_secs(60)),
            ..Default::default()
        }).unwrap();
        let mut writer = PacketWriter::new(7, 0x100, 1232).unwrap();
        writer.question(&Name::from_ascii("ready.test").unwrap(), 1, 1).unwrap();
        assert!(matches!(daemon.forward_udp(&writer.finish(), ClientRequest {
            source: "127.0.0.1:53000".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(), interface: 0,
        }).unwrap(), QueryResult::Forwarded(_)));
        assert!(daemon.poll(Duration::ZERO).unwrap().is_empty());
        let before = snapshot();
        let iterations = 1000;
        for _ in 0..iterations {
            assert!(daemon.poll(Duration::ZERO).unwrap().is_empty());
        }
        let after = snapshot();
        let counts: Vec<_> = before.iter().zip(after).map(|(a, b)| b - a).collect();
        assert_eq!(daemon.pending_count(), 1);
        println!("UPSTREAM_ALLOCATION {{\"iterations\":{iterations},\"alloc_realloc_bytes\":{counts:?}}}");
    }

    #[test]
    fn terminal_cache_retirement_counts() {
        let descriptors_before = std::fs::read_dir("/proc/self/fd").unwrap().count();
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_resolv = true;
        let mut daemon = DnsDaemon::new(config, Hosts::new(), &[], DaemonOptions::default()).unwrap();
        daemon.enable_cache(1000, 0, 0, dnsmasq_rs::dns::cache::StalePolicy::Disabled);
        assert!(daemon.current_cache().is_some());
        let before_calls = DEALLOCATIONS.load(Relaxed);
        let before_bytes = FREED_BYTES.load(Relaxed);
        /* RETIRE_CACHE */
        drop(daemon);
        let deallocations = DEALLOCATIONS.load(Relaxed) - before_calls;
        let freed_bytes = FREED_BYTES.load(Relaxed) - before_bytes;
        let descriptors_after = std::fs::read_dir("/proc/self/fd").unwrap().count();
        assert_eq!(descriptors_after, descriptors_before);
        println!("TERMINAL_CACHE {{\"cache_records\":1000,\"deallocations\":{deallocations},\"freed_bytes\":{freed_bytes},\"fds_before\":{descriptors_before},\"fds_after\":{descriptors_after}}}");
        // Invoke only this test in its own process. Retired memory is reclaimed
        // by test process exit; this is not a long-lived test-service pattern.
    }
}
