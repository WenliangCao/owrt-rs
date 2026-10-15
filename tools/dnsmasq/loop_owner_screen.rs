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
    static REALLOCATED_OLD_BYTES: AtomicU64 = AtomicU64::new(0);
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
            REALLOCATED_OLD_BYTES.fetch_add(layout.size() as u64, Relaxed);
            unsafe { System.realloc(pointer, layout, size) }
        }
    }
    #[global_allocator]
    static METER: Meter = Meter;
    fn snapshot() -> [u64; 3] {
        [ALLOCATIONS.load(Relaxed), REALLOCATIONS.load(Relaxed), BYTES.load(Relaxed)]
    }

    /* READINESS_RESOURCES */

    fn all_counts() -> [u64; 6] {
        [ALLOCATIONS.load(Relaxed), REALLOCATIONS.load(Relaxed), BYTES.load(Relaxed),
         DEALLOCATIONS.load(Relaxed), FREED_BYTES.load(Relaxed),
         REALLOCATED_OLD_BYTES.load(Relaxed)]
    }

    fn measured<T>(label: &str, iterations: usize, operation: impl FnOnce() -> T) -> T {
        // Markers are outside the allocation interval and can delimit a
        // separate syscall trace. No elapsed time is reported by this harness.
        eprintln!("OWNER_STAGE_BEGIN {label}");
        let before = all_counts();
        let result = operation();
        let after = all_counts();
        let delta: [u64; 6] = std::array::from_fn(|i| after[i] - before[i]);
        println!("OWNER_COUNTS {{\"stage\":\"{label}\",\"iterations\":{iterations},\"alloc_realloc_bytes_dealloc_freed_realloc_old_bytes\":{delta:?}}}");
        eprintln!("OWNER_STAGE_END {label}");
        result
    }

    fn report_resources(label: &str, owner: &SinglePoll) {
        let resources = readiness_resources(owner);
        let state = readiness_state(owner);
        println!("OWNER_RESOURCES {{\"stage\":\"{label}\",\"backend_key_registration_event_sizes_and_five_capacity_bytes\":{resources:?},\"active_registered_oversized\":{state:?},\"poll_capacity\":{},\"ready_capacity\":{},\"client_capacity\":{},\"fds\":{}}}",
            owner.poll_fds.capacity(), owner.ready_fds.capacity(), owner.clients.capacity(),
            std::fs::read_dir("/proc/self/fd").unwrap().count());
    }

    fn prepared_owner() -> impl FnOnce() -> SinglePoll {
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_resolv = true;
        config.bind_interfaces = true;
        config.apply(&dnsmasq_rs::config::lex_line(
            b"host-record=ready.test,192.0.2.7").unwrap().unwrap()).unwrap();
        let daemon = DnsDaemon::new(config.clone(), read_hosts(&config, 37), &[],
            DaemonOptions::default()).unwrap();
        let local = LocalDnsService::new_with_limits(
            config.clone(), read_hosts(&config, 37), 37, 1232, 1232);
        let service = Rc::new(RefCell::new(ParentDns {
            local, daemon: Some(daemon), query_ids: Default::default(),
            pending_hosts: None, hosts_initializing: false,
        }));
        let events = Rc::new(RefCell::new(ParentEvents::new(&UbusConfig::default()).unwrap()));
        let interfaces = Rc::new(RefCell::new(Vec::new()));
        move || SinglePoll::new(service, events, interfaces, config, Vec::new(),
            1232, 128, 1232, Vec::new(), None, None, None, None)
    }

    fn prepared_client() -> (PendingInterfaceTcp, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, address) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        (PendingInterfaceTcp {
            query_ids: Default::default(), stream, peer: address, local_network: None,
            mac: None, mac_ready: true, mac_deferred: false, accept_clock: now_seconds(),
            auth_query: false,
        }, peer)
    }

    #[test]
    fn readiness_owner_counts() {
        use dnsmasq_rs::dns::wire::{Name, PacketWriter};
        use std::mem::{align_of, size_of};
        let initial_fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
        println!("OWNER_LAYOUT {{\"single_poll_size_align\":[{},{}],\"tcp_client_size_align\":[{},{}],\"tcp_work_size_align\":[{},{}],\"optional_generation_size_align\":[{},{}]}}",
            size_of::<SinglePoll>(), align_of::<SinglePoll>(),
            size_of::<PollTcpClient>(), align_of::<PollTcpClient>(),
            size_of::<TcpDnsWork>(), align_of::<TcpDnsWork>(),
            size_of::<Option<u64>>(), align_of::<Option<u64>>());
        let constructor = prepared_owner();
        let mut owner = measured("owner_init_prepared_inputs", 1, constructor);
        report_resources("owner_init", &owner);
        owner.full_reload_pending = true;
        owner.route_watch = Some(RouteWatch::new().unwrap());
        let (read_end, write_end) = owrt_ubus::sys::nonblocking_pipe().unwrap();
        owner.signal_wake_read = Some(read_end);
        owner.signal_wake_write = Some(write_end);
        let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let udp6 = Arc::new(DnsSocket::bind("[::1]:0".parse().unwrap()).unwrap());
        owner.add_listener(SocketToken(1), Some(Arc::clone(&udp)),
            Some(TcpListener::bind("127.0.0.1:0").unwrap()));
        owner.add_listener(SocketToken(2), Some(udp6),
            Some(TcpListener::bind("[::1]:0").unwrap()));
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut writer = PacketWriter::new(7, 0x100, 1232).unwrap();
        writer.question(&Name::from_ascii("ready.test").unwrap(), 1, 1).unwrap();
        let query = writer.finish();
        peer.send_to(&query, udp.local_addr().unwrap()).unwrap();
        measured("first_normal_six", 1, || owner.wait_for_files().unwrap());
        assert_eq!(owner.poll_fds.len(), 6);
        report_resources("first_normal_six", &owner);
        measured("steady_normal_ready_six", 1000, || {
            for _ in 0..1000 { owner.wait_for_files().unwrap(); }
        });
        let mut peers = Vec::with_capacity(64);
        for _ in 0..8 {
            let (pending, peer) = prepared_client();
            owner.finish_tcp_accept(pending);
            peers.push(peer);
        }
        measured("first_normal_fourteen", 1, || owner.wait_for_files().unwrap());
        assert_eq!(owner.poll_fds.len(), 14);
        report_resources("first_normal_fourteen", &owner);
        measured("steady_normal_ready_fourteen", 1000, || {
            for _ in 0..1000 { owner.wait_for_files().unwrap(); }
        });
        let frame = TcpWriteFrame::new(vec![0; 12]).unwrap();
        owner.clients[0].dns_work.as_mut().unwrap().phase =
            TcpClientPhase::Writing { frame, offset: 0 };
        measured("reading_to_writing", 1, || owner.wait_for_files().unwrap());
        owner.clients[0].dns_work.as_mut().unwrap().phase = TcpClientPhase::Reading;
        measured("writing_to_reading", 1, || owner.wait_for_files().unwrap());
        let (pending, replacement_peer) = prepared_client();
        measured("client_retirement", 1, || drop(owner.clients.remove(0)));
        drop(peers.remove(0));
        measured("client_accept", 1, || owner.finish_tcp_accept(pending));
        peers.push(replacement_peer);
        measured("lifetime_reconcile", 1, || owner.wait_for_files().unwrap());
        assert!(owner.step_udp(0));
        let mut answer = [0; 1232];
        let (size, _) = peer.recv_from(&mut answer).unwrap();
        assert!(answer[..size].ends_with(&[192, 0, 2, 7]));
        measured("first_probe_subset", 1, || {
            owner.wait_during_probe(None, Duration::ZERO, Default::default()).unwrap();
        });
        report_resources("first_probe_subset", &owner);
        measured("normal_probe_transitions", 1000, || {
            for _ in 0..1000 {
                owner.wait_for_files().unwrap();
                owner.wait_during_probe(None, Duration::ZERO, Default::default()).unwrap();
            }
        });
        // Six normal fixed/listener slots plus 58 real accepted connections.
        for _ in 8..58 {
            let (pending, peer) = prepared_client();
            owner.finish_tcp_accept(pending);
            peers.push(peer);
        }
        measured("first_normal_sixty_four", 1, || owner.wait_for_files().unwrap());
        assert_eq!(owner.poll_fds.len(), 64);
        report_resources("first_normal_sixty_four", &owner);
        measured("steady_normal_sixty_four", 1000, || {
            for _ in 0..1000 { owner.wait_for_files().unwrap(); }
        });
        let (pending, peer65) = prepared_client();
        owner.finish_tcp_accept(pending);
        measured("first_oversized_sixty_five", 1, || owner.wait_for_files().unwrap());
        assert_eq!(owner.poll_fds.len(), 65);
        report_resources("first_oversized_sixty_five", &owner);
        measured("steady_oversized_sixty_five", 1000, || {
            for _ in 0..1000 { owner.wait_for_files().unwrap(); }
        });
        drop(owner.clients.pop());
        drop(peer65);
        measured("return_to_sixty_four", 1, || owner.wait_for_files().unwrap());
        report_resources("return_to_sixty_four", &owner);
        owner.clients.truncate(8);
        peers.truncate(8);
        measured("return_to_fourteen", 1, || owner.wait_for_files().unwrap());
        report_resources("return_to_fourteen", &owner);
        // Ready downstream clients remain unread by the normal wait alone.
        for peer in &mut peers { peer.write_all(b"x").unwrap(); }
        measured("all_downstream_ready_fourteen", 1000, || {
            for _ in 0..1000 { owner.wait_for_files().unwrap(); }
        });
        measured("owner_drop_with_inputs", 1, || drop(owner));
        drop(peers);
        drop(udp);
        drop(peer);
        let final_fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
        assert_eq!(final_fds, initial_fds);
        println!("OWNER_FD_CLEANUP {{\"initial\":{initial_fds},\"final\":{final_fds}}}");
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
