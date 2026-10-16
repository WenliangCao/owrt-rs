use super::*;
use dnsmasq_rs::config::lex_line;
use dnsmasq_rs::dns::wire::{Header, Name, PacketWriter, Question as WireQuestion, Section};
use std::net::UdpSocket;

fn query(name: &str, id: u16) -> Vec<u8> {
    let mut writer = PacketWriter::new(id, 0x100, 1232).unwrap();
    writer
        .question(&Name::from_ascii(name).unwrap(), 1, 1)
        .unwrap();
    writer.finish()
}

struct PendingCaller {
    owner: SinglePoll,
    upstream: UdpSocket,
    client: UdpSocket,
    dns: SocketAddr,
    packet: Vec<u8>,
    peer: SocketAddr,
}

impl PendingCaller {
    fn new(no_poll: bool, cached: bool) -> Self {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_resolv = true;
        config.no_poll = no_poll;
        config.bind_interfaces = true;
        config.listen_addresses = vec!["127.0.0.1".parse().unwrap()];
        for line in [
            format!("server=127.0.0.1#{}", upstream.local_addr().unwrap().port()),
            "host-record=ready.test,192.0.2.7".to_owned(),
        ] {
            config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .unwrap();
        }
        // Diagnostic fixture only: model the one local rule already known to
        // exist in OpenWrt without importing any private production names.
        if let Ok(mode) = std::env::var("D1_DIAGNOSTIC_LOCAL_RULE") {
            config.apply(&lex_line(b"local=/lan/").unwrap().unwrap()).unwrap();
            if mode == "rfc6761" {
                for line in ["server=/bind/", "server=/invalid/", "server=/local/",
                    "server=/localhost/", "server=/onion/", "server=/test/"] {
                    config.apply(&lex_line(line.as_bytes()).unwrap().unwrap()).unwrap();
                }
            }
        }
        let mut daemon = DnsDaemon::new(
            config.clone(),
            read_hosts(&config, 37),
            &[],
            DaemonOptions::default(),
        )
        .unwrap();
        daemon.enable_cache(8, 0, 0, StalePolicy::Disabled);
        let mut owner = super::tests::test_owner(config, Some(daemon));
        let dns = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = dns.local_addr().unwrap();
        owner.add_listener(SocketToken(1), Some(dns), None);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut fixture = Self {
            owner,
            upstream,
            client,
            dns: address,
            packet: Vec::new(),
            peer: "127.0.0.1:0".parse().unwrap(),
        };
        if cached {
            fixture.send_client(&query("cached.route.example", 8));
            fixture.read_upstream();
            let question = WireQuestion::parse(&fixture.packet, 12).unwrap();
            let mut writer =
                PacketWriter::new(Header::parse(&fixture.packet).unwrap().id, 0x8180, 1232)
                    .unwrap();
            writer.question(&question.name, 1, 1).unwrap();
            writer
                .record_at(Section::Answer, 12, 1, 1, 600, &[192, 0, 2, 55])
                .unwrap();
            fixture
                .upstream
                .send_to(&writer.finish(), fixture.peer)
                .unwrap();
            fixture.owner.wait_for_files().unwrap();
            fixture.owner.poll_udp_completions();
            let mut answer = [0; 1232];
            fixture.client.recv_from(&mut answer).unwrap();
            assert_eq!(
                fixture
                    .owner
                    .service
                    .borrow()
                    .daemon
                    .as_ref()
                    .unwrap()
                    .cache_counters()
                    .inserted,
                1
            );
            if std::env::var_os("D1_DIAGNOSTIC_DUAL_FAMILY").is_some() {
                let mut packet = query("cached.route.example", 9);
                let end = packet.len();
                packet[end - 4..end - 2].copy_from_slice(&28u16.to_be_bytes());
                assert!(fixture.send_client(&packet));
                fixture.read_upstream();
                let question = WireQuestion::parse(&fixture.packet, 12).unwrap();
                let mut writer = PacketWriter::new(
                    Header::parse(&fixture.packet).unwrap().id, 0x8180, 1232,
                ).unwrap();
                writer.question(&question.name, 28, 1).unwrap();
                writer.record_at(Section::Answer, 12, 28, 1, 600, &[7; 16]).unwrap();
                fixture.upstream.send_to(&writer.finish(), fixture.peer).unwrap();
                fixture.owner.wait_for_files().unwrap();
                fixture.owner.poll_udp_completions();
                fixture.client.recv_from(&mut answer).unwrap();
                assert_eq!(fixture.owner.service.borrow().daemon.as_ref().unwrap()
                    .cache_counters().inserted, 2);
            }
        }
        fixture.prime();
        fixture
    }

    fn send_client(&mut self, packet: &[u8]) -> bool {
        self.client.send_to(packet, self.dns).unwrap();
        self.owner.wait_for_files().unwrap();
        self.owner.step_udp(0)
    }

    fn read_upstream(&mut self) {
        let mut packet = [0; 2048];
        let (length, peer) = self.upstream.recv_from(&mut packet).unwrap();
        self.packet = packet[..length].to_vec();
        self.peer = peer;
    }

    fn prime(&mut self) {
        assert!(self.send_client(&query("pending.route.example", 7)));
        self.read_upstream();
        assert_eq!(
            self.owner
                .service
                .borrow()
                .daemon
                .as_ref()
                .unwrap()
                .pending_count(),
            1
        );
    }

    fn route(&mut self) {
        #[cfg(target_os = "linux")]
        self.owner.apply_network_events(NetworkEvents {
            route: true,
            ..Default::default()
        });
        // Darwin has no route owner. Still run real owner ingress and TCP/HUP
        // consumers, then observe their library send state over real UDP.
        #[cfg(not(target_os = "linux"))]
        self.owner
            .service
            .borrow_mut()
            .daemon
            .as_mut()
            .unwrap()
            .resend_udp_query();
    }

    fn assert_resend(&mut self) {
        let forwarded = self
            .owner
            .service
            .borrow()
            .daemon
            .as_ref()
            .unwrap()
            .forward_counters()
            .queries_forwarded;
        self.route();
        let mut packet = [0; 2048];
        let (length, peer) = self.upstream.recv_from(&mut packet).unwrap();
        assert_eq!(peer, self.peer);
        assert_eq!(&packet[..length], self.packet);
        assert_eq!(
            self.owner
                .service
                .borrow()
                .daemon
                .as_ref()
                .unwrap()
                .forward_counters()
                .queries_forwarded,
            forwarded
        );
    }

    fn assert_no_resend(&mut self) {
        self.route();
        self.upstream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let error = self.upstream.recv_from(&mut [0; 2048]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert_eq!(
            self.owner
                .service
                .borrow()
                .daemon
                .as_ref()
                .unwrap()
                .pending_count(),
            1,
            "invalidation does not cancel an admitted query"
        );
    }

    fn accept_tcp(&mut self) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        self.owner
            .add_listener(SocketToken(2), None, Some(listener));
        self.owner.wait_for_files().unwrap();
        self.owner.step_tcp_accept(1);
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        for _ in 0..32 {
            if !self.owner.clients.is_empty() {
                break;
            }
            self.owner.wait_for_files().unwrap();
            self.owner.step_interface_collector();
        }
        assert_eq!(self.owner.clients.len(), 1);
        peer
    }
}

#[test]
fn route_resend_owner_keeps_the_actual_forward_across_a_batch_empty_read() {
    for no_poll in [false, true] {
        let mut fixture = PendingCaller::new(no_poll, false);
        // The prior poll's POLLIN remains available for the bounded batch;
        // this final real receive returns WouldBlock rather than a datagram.
        assert!(!fixture.owner.step_udp(0));
        #[cfg(target_os = "linux")]
        {
            fixture.owner.dns_files =
                Some(DnsFiles::new(&fixture.owner.config, true, false).unwrap());
            assert!(!fixture.owner.dns_files.as_ref().unwrap().has_work());
        }
        fixture.assert_resend();
        #[cfg(target_os = "linux")]
        assert!(
            fixture.owner.dns_files.as_ref().unwrap().has_work(),
            "route resend and resolver work share the same actor invocation"
        );
    }
}

#[test]
fn route_resend_owner_clears_on_local_cached_invalid_oversize_and_rejected_udp() {
    for case in ["local", "cached", "short", "qr", "oversize", "rejected"] {
        let mut fixture = PendingCaller::new(false, case == "cached");
        let packet = match case {
            "local" => query("ready.test", 9),
            "cached" => query("cached.route.example", 9),
            "short" => b"bad".to_vec(),
            "qr" => {
                let mut packet = query("ready.test", 9);
                packet[2] |= 0x80;
                packet
            }
            "oversize" => vec![0; 1233],
            _ => {
                // Select a destination absent from this listener generation;
                // the already-received real datagram is rejected by admit.
                fixture.owner.config.bind_interfaces = false;
                fixture.owner.config.listen_addresses = vec!["192.0.2.99".parse().unwrap()];
                query("ready.test", 9)
            }
        };
        fixture.send_client(&packet);
        if matches!(case, "local" | "cached") {
            let mut answer = [0; 1232];
            let (length, _) = fixture.client.recv_from(&mut answer).unwrap();
            assert_eq!(Header::parse(&answer[..length]).unwrap().id, 9);
        }
        fixture.assert_no_resend();
    }
}

#[test]
fn route_resend_owner_preserves_bound_private_tcp_and_clears_wildcard_accept() {
    let mut fixture = PendingCaller::new(false, false);
    let mut peer = fixture.accept_tcp();
    peer.write_all(&encode_tcp_frame(&query("ready.test", 10)).unwrap())
        .unwrap();
    fixture.owner.wait_for_files().unwrap();
    fixture.owner.step_tcp_clients();
    let mut size = [0; 2];
    peer.read_exact(&mut size).unwrap();
    let mut answer = vec![0; usize::from(u16::from_be_bytes(size))];
    peer.read_exact(&mut answer).unwrap();
    assert_eq!(Header::parse(&answer).unwrap().id, 10);
    fixture.assert_resend();

    let mut fixture = PendingCaller::new(false, false);
    fixture.owner.config.bind_interfaces = false;
    let _peer = fixture.accept_tcp();
    fixture.assert_no_resend();
}

#[test]
fn route_resend_owner_debug_shared_partial_frame_clears_before_validation() {
    let mut fixture = PendingCaller::new(false, false);
    let mut peer = fixture.accept_tcp();
    // Select the debug consumer without changing the process-global mode used
    // by unrelated parallel tests. Save itself is produced only by real UDP.
    fixture.owner.clients[0].dns_work.as_mut().unwrap().cache_debug = true;
    peer.write_all(&[0]).unwrap();
    fixture.owner.wait_for_files().unwrap();
    fixture.owner.step_tcp_clients();
    assert_eq!(fixture.owner.clients.len(), 1);
    fixture.assert_no_resend();
}

#[test]
fn route_resend_owner_full_reload_clears_without_releasing_its_pending_query() {
    let mut fixture = PendingCaller::new(false, false);
    fixture.owner.process_reload_before_dns(37, true).unwrap();
    fixture.assert_no_resend();
}


#[test]
fn plain_udp_owner_reuses_receive_bytes_and_sends_existing_completion_after_hit() {
    let mut fixture = PendingCaller::new(true, true);
    let question = WireQuestion::parse(&fixture.packet, 12).unwrap();
    let mut writer = PacketWriter::new(Header::parse(&fixture.packet).unwrap().id, 0x8180, 1232).unwrap();
    writer.question(&question.name, 1, 1).unwrap();
    writer.record_at(Section::Answer, 12, 1, 1, 600, &[192, 0, 2, 88]).unwrap();
    fixture.upstream.send_to(&writer.finish(), fixture.peer).unwrap();
    let before_count = fixture.owner.parent_events.borrow().local_answered;
    let packet = query("cached.route.example", 0x1234);
    assert!(fixture.send_client(&packet));
    assert_eq!(Header::parse(&fixture.owner.udp_buffer).unwrap().flags, 0x8180,
        "the direct hit must use the receive buffer rather than a copied reply");
    assert_eq!(&fixture.owner.udp_buffer[12..packet.len()], &packet[12..]);
    let mut response = [0; 1232];
    let (length, _) = fixture.client.recv_from(&mut response).unwrap();
    assert_eq!(Header::parse(&response[..length]).unwrap().id, 0x1234);
    assert_eq!(&response[length - 4..length], &[192, 0, 2, 55]);
    let (length, _) = fixture.client.recv_from(&mut response).unwrap();
    assert_eq!(Header::parse(&response[..length]).unwrap().id, 7,
        "an already completed upstream reply follows the current cached answer");
    assert_eq!(&response[length - 4..length], &[192, 0, 2, 88]);
    assert_eq!(fixture.owner.parent_events.borrow().local_answered, before_count + 1);
    assert_eq!(fixture.owner.service.borrow().daemon.as_ref().unwrap().pending_count(), 0);
}

#[test]
fn plain_udp_owner_feature_rejection_keeps_packet_and_counters() {
    for excluded in ["logging", "edns", "loop"] {
        let mut fixture = PendingCaller::new(true, true);
        match excluded {
            "logging" => fixture.owner.query_logging.enabled = true,
            "edns" => { fixture.owner.config.apply(&lex_line(b"add-mac").unwrap().unwrap()).unwrap(); },
            "loop" => fixture.owner.config.loop_detect = true,
            _ => unreachable!(),
        }
        let query = query("cached.route.example", 0x1234);
        let mut packet = vec![0xa5; 512];
        packet[..query.len()].copy_from_slice(&query);
        let before = packet.clone();
        let before_count = fixture.owner.parent_events.borrow().local_answered;
        let udp = Arc::clone(fixture.owner.listeners[0].udp.as_ref().unwrap());
        let incoming = listeners::Incoming { len: query.len(), peer: fixture.client.local_addr().unwrap(),
            destination: fixture.dns.ip(), interface: 0 };
        assert!(!fixture.owner.try_plain_udp_hit(&udp, incoming, &mut packet));
        assert_eq!(packet, before);
        assert_eq!(fixture.owner.parent_events.borrow().local_answered, before_count);
        assert_eq!(fixture.owner.service.borrow().daemon.as_ref().unwrap().pending_count(), 1);
    }
}


#[test]
fn plain_udp_owner_allocation_count_comparison() {
    let mut fixture = PendingCaller::new(true, true);
    let query = query("cached.route.example", 0x2345);
    let mut response = [0; 512];
    for enabled in [false, true] {
        D1_FAST_ENABLED.store(enabled, Ordering::Relaxed);
        for _ in 0..20 {
            assert!(fixture.send_client(&query));
            fixture.client.recv_from(&mut response).unwrap();
        }
        let before = udp_allocation_diagnostic::cached_totals();
        let before_names = dnsmasq_rs::dns::wire::diagnostic_name_visits();
        for _ in 0..2000 {
            assert!(fixture.send_client(&query));
            let (length, _) = fixture.client.recv_from(&mut response).unwrap();
            assert_eq!(Header::parse(&response[..length]).unwrap().id, 0x2345);
            assert_eq!(&response[length - 4..length], &[192, 0, 2, 55]);
        }
        let after = udp_allocation_diagnostic::cached_totals();
        let after_names = dnsmasq_rs::dns::wire::diagnostic_name_visits();
        let names: [u64; 3] = std::array::from_fn(|i| after_names[i] - before_names[i]);
        println!("D1_NAME_VISITS fast={enabled} columns=general_walk,encoded_skip,plain_scan values={names:?}");
        let delta: [u64; 6] = std::array::from_fn(|i| after[i] - before[i]);
        assert_eq!(delta[0], 2000);
        println!("D1_ALLOCATION fast={enabled} columns=query,alloc,dealloc,realloc,requested,released values={delta:?}");
    }
    D1_FAST_ENABLED.store(true, Ordering::Relaxed);
}

#[test]
fn plain_udp_owner_flag_shape_counts() {
    // Count work only; elapsed time in this instrumented native test is not
    // device performance. This fixture keeps one fresh A and public rules.
    assert_eq!(std::env::var("D1_DIAGNOSTIC_LOCAL_RULE").as_deref(), Ok("rfc6761"));
    assert!(std::env::var_os("D1_DIAGNOSTIC_DUAL_FAMILY").is_none());
    let mut fixture = PendingCaller::new(true, true);
    let mut response = [0; 1232];
    for (shape, flags, opt) in [
        ("plain", 0x0100u16, false), ("ad", 0x0120, false),
        ("cd", 0x0110, false), ("ad_cd", 0x0130, false),
        ("empty_opt", 0x0100, true), ("ad_cd_empty_opt", 0x0130, true),
    ] {
        let mut packet = query("cached.route.example", 0x2345);
        packet[2..4].copy_from_slice(&flags.to_be_bytes());
        if opt {
            packet[10..12].copy_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        }
        for enabled in [false, true] {
            D1_FAST_ENABLED.store(enabled, Ordering::Relaxed);
            for _ in 0..20 {
                assert!(fixture.send_client(&packet));
                fixture.client.recv_from(&mut response).unwrap();
            }
            let before = udp_allocation_diagnostic::cached_totals();
            let before_names = dnsmasq_rs::dns::wire::diagnostic_name_visits();
            for _ in 0..200 {
                assert!(fixture.send_client(&packet));
                let (length, _) = fixture.client.recv_from(&mut response).unwrap();
                let header = Header::parse(&response[..length]).unwrap();
                assert_eq!(header.id, 0x2345);
                assert_eq!(header.answers, 1);
                assert_eq!(header.flags & 0x0030, flags & 0x0010);
                assert_eq!(header.additionals, u16::from(opt));
            }
            let after = udp_allocation_diagnostic::cached_totals();
            let after_names = dnsmasq_rs::dns::wire::diagnostic_name_visits();
            let delta: [u64; 6] = std::array::from_fn(|i| after[i] - before[i]);
            let names: [u64; 3] = std::array::from_fn(|i| after_names[i] - before_names[i]);
            assert_eq!(delta[0], 200);
            println!("D1_FLAG_SHAPE shape={shape} fast={enabled} allocation_columns=query,alloc,dealloc,realloc,requested,released values={delta:?} name_columns=general_walk,encoded_skip,plain_scan names={names:?}");
        }
    }
    D1_FAST_ENABLED.store(true, Ordering::Relaxed);
}
