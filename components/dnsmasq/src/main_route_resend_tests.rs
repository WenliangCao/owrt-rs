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
        let mut daemon = DnsDaemon::new(
            config.clone(),
            read_hosts(&config, 37),
            &[],
            DaemonOptions::default(),
        )
        .unwrap();
        daemon.enable_cache(8, 0, 0, StalePolicy::Disabled);
        let mut owner = super::tests::test_owner(config, Some(daemon));
        let dns = Rc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
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
            fixture.send_client(&query("cached.route.test", 8));
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
        assert!(self.send_client(&query("pending.route.test", 7)));
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
            "cached" => query("cached.route.test", 9),
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
