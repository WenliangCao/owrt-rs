//! Exercise the original UDP owner through both dispatch choices over real sockets.
use super::*;
use dnsmasq_rs::config::lex_line;
use dnsmasq_rs::dns::wire::{Header, Name, PacketWriter, Question, Section};
use std::net::UdpSocket;

struct Fixture {
    owner: SinglePoll,
    peer: UdpSocket,
    upstream: UdpSocket,
    address: SocketAddr,
}

fn query(name: &str, id: u16) -> Vec<u8> {
    let mut writer = PacketWriter::new(id, 0x100, 512).unwrap();
    writer.question(&Name::from_ascii(name).unwrap(), 1, 1).unwrap();
    writer.finish()
}

fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut packet = [0; 2048];
    let (len, peer) = socket.recv_from(&mut packet).unwrap();
    (packet[..len].to_vec(), peer)
}

impl Fixture {
    fn new() -> Self {
        let mut fixture = Self::unstarted();
        // Linux starts with ARP maintenance pending even without a neighbor
        // service. Exercise the original startup turn before claiming idle.
        fixture.owner.step().unwrap();
        fixture
    }

    fn unstarted() -> Self {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        upstream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut config = DnsConfig::default();
        config.no_hosts = true;
        config.no_resolv = true;
        config.no_poll = true;
        config.bind_interfaces = true;
        for line in ["host-record=local.dispatch.test,192.0.2.7".to_owned(),
            format!("server=127.0.0.1#{}", upstream.local_addr().unwrap().port())] {
            config.apply(&lex_line(line.as_bytes()).unwrap().unwrap()).unwrap();
        }
        let mut daemon = DnsDaemon::new(config.clone(), read_hosts(&config, 37), &[],
            DaemonOptions::default()).unwrap();
        daemon.enable_cache(8, 0, 0, StalePolicy::Disabled);
        let mut owner = tests::test_owner(config, Some(daemon));
        #[cfg(target_os = "linux")]
        {
            let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::NONBLOCK | rustix::pipe::PipeFlags::CLOEXEC).unwrap();
            owner.signal_wake_read = Some(read);
            owner.signal_wake_write = Some(write);
        }
        let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = udp.local_addr().unwrap();
        owner.add_listener(SocketToken(1), Some(udp), None);
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        Self { owner, peer, upstream, address }
    }

    fn ready(&mut self, packet: &[u8]) {
        self.peer.send_to(packet, self.address).unwrap();
        self.owner.wait_for_files().unwrap();
        // Darwin has no production poll witness. Exercise the same private
        // dispatch/state checks locally; Linux tests use the real poll latch.
        #[cfg(not(target_os = "linux"))]
        { self.owner.udp_only_wake = Some((SocketToken(1), None)); }
    }

    fn answer_upstream(&self) {
        let (packet, source) = receive(&self.upstream);
        let question = Question::parse(&packet, 12).unwrap();
        let mut writer = PacketWriter::new(Header::parse(&packet).unwrap().id, 0x8180, 512).unwrap();
        writer.question(&question.name, 1, 1).unwrap();
        // A fixed max-reply TTL keeps the wire comparison independent of a
        // wall-clock second boundary while both entries remain fresh.
        writer.record_at(Section::Answer, 12, 1, 1, 600, &[192, 0, 2, 55]).unwrap();
        self.upstream.send_to(&writer.finish(), source).unwrap();
    }

    fn fill_cache(&mut self) {
        self.owner.service.borrow_mut().daemon.as_mut().unwrap().set_max_reply_ttl(30);
        self.ready(&query("cached.dispatch.test", 10));
        self.owner.udp_only_wake = None;
        self.owner.step().unwrap();
        self.answer_upstream();
        self.owner.wait_for_files().unwrap();
        self.owner.poll_udp_completions();
        receive(&self.peer);
        #[cfg(target_os = "linux")]
        { self.owner.upstream_ready = false; }
    }
}

#[test]
fn udp_dispatch_cached_and_local_answers_match_full_turn() {
    let mut fast = Fixture::new();
    let mut full = Fixture::new();
    fast.fill_cache();
    full.fill_cache();
    for name in ["cached.dispatch.test", "local.dispatch.test", "cached.dispatch.test"] {
        let packet = query(name, 21);
        fast.ready(&packet);
        full.ready(&packet);
        assert_eq!(fast.owner.udp_only_wake, Some((SocketToken(1), None)));
        assert!(fast.owner.udp_dispatch_idle(Instant::now()));
        full.owner.udp_only_wake = None;
        fast.owner.step().unwrap();
        full.owner.step().unwrap();
        assert_eq!(receive(&fast.peer).0, receive(&full.peer).0);
        assert_eq!(fast.owner.parent_events.borrow().local_answered,
                   full.owner.parent_events.borrow().local_answered);
        let fast_parent = fast.owner.service.borrow();
        let full_parent = full.owner.service.borrow();
        assert_eq!(fast_parent.daemon.as_ref().unwrap().cache_counters(),
                   full_parent.daemon.as_ref().unwrap().cache_counters());
        assert_eq!(fast_parent.daemon.as_ref().unwrap().forward_counters(),
                   full_parent.daemon.as_ref().unwrap().forward_counters());
        assert!(fast.owner.udp_only_wake.is_none(), "one wait authorizes one turn only");
    }
}

#[test]
fn udp_dispatch_keeps_the_original_budget_then_repolls() {
    let mut fixture = Fixture::new();
    for id in 0..=UDP_PACKETS_PER_TURN {
        fixture.peer.send_to(&query("local.dispatch.test", id as u16), fixture.address).unwrap();
    }
    fixture.owner.wait_for_files().unwrap();
    #[cfg(not(target_os = "linux"))]
    { fixture.owner.udp_only_wake = Some((SocketToken(1), None)); }
    fixture.owner.step().unwrap();
    assert_eq!(fixture.owner.parent_events.borrow().local_answered as usize, UDP_PACKETS_PER_TURN);
    for _ in 0..UDP_PACKETS_PER_TURN { receive(&fixture.peer); }
    assert!(fixture.peer.recv(&mut [0; 2048]).is_err(), "the last packet must await another owner turn");
    fixture.owner.wait_for_files().unwrap();
    #[cfg(not(target_os = "linux"))]
    { fixture.owner.udp_only_wake = Some((SocketToken(1), None)); }
    fixture.owner.step().unwrap();
    assert_eq!(Header::parse(&receive(&fixture.peer).0).unwrap().id, UDP_PACKETS_PER_TURN as u16);
}

#[test]
fn udp_dispatch_new_forwarding_work_completes_on_original_owner() {
    let mut fixture = Fixture::new();
    fixture.ready(&query("miss.dispatch.test", 44));
    assert!(fixture.owner.udp_dispatch_idle(Instant::now()));
    fixture.owner.step().unwrap();
    assert_eq!(fixture.owner.service.borrow().daemon.as_ref().unwrap().pending_count(), 1);
    assert!(!fixture.owner.udp_dispatch_idle(Instant::now()), "a newly submitted transaction is not idle");
    fixture.answer_upstream();
    fixture.owner.wait_for_files().unwrap();
    assert!(fixture.owner.udp_only_wake.is_none());
    fixture.owner.step().unwrap();
    let answer = receive(&fixture.peer).0;
    assert_eq!(Header::parse(&answer).unwrap().id, 44);
    assert!(answer.ends_with(&[192, 0, 2, 55]));
    assert_eq!(fixture.owner.service.borrow().daemon.as_ref().unwrap().pending_count(), 0);
}

#[test]
fn udp_dispatch_rechecks_work_queued_after_poll_without_consuming_it() {
    let mut fixture = Fixture::new();
    fixture.ready(&query("local.dispatch.test", 7));
    fixture.owner.full_reload_pending = true;
    assert_eq!(fixture.owner.take_udp_only_listener(Instant::now()), None);
    assert!(fixture.owner.full_reload_pending);
    fixture.owner.full_reload_pending = false;
    assert_eq!(fixture.owner.take_udp_only_listener(Instant::now()), None, "rejected witness cannot be reused");
    fixture.owner.udp_only_wake = Some((SocketToken(1), None));
    fixture.owner.pending_edns_udp.push(PendingEdnsUdp {
        query_context: Default::default(), listener: SocketToken(1),
        client: ClientRequest { source: fixture.peer.local_addr().unwrap(),
            destination: fixture.address.ip(), interface: 0 },
        query: query("local.dispatch.test", 8), deadline: Instant::now() + Duration::from_secs(3),
    });
    assert_eq!(fixture.owner.take_udp_only_listener(Instant::now()), None);
    assert_eq!(fixture.owner.pending_edns_udp.len(), 1);
    fixture.owner.pending_edns_udp.clear();
    for signal in [&RELOAD_REQUESTED, &LOG_REOPEN_REQUESTED, &CACHE_DUMP_REQUESTED, &ALARM_REQUESTED] {
        fixture.owner.udp_only_wake = Some((SocketToken(1), None));
        let old = signal.swap(1, Ordering::AcqRel);
        let result = fixture.owner.take_udp_only_listener(Instant::now());
        signal.store(old, Ordering::Release);
        assert_eq!(result, None);
    }
    fixture.owner.udp_only_wake = Some((SocketToken(1), None));
    fixture.owner.interface_refresh.retry_at = Some(Instant::now());
    assert_eq!(fixture.owner.take_udp_only_listener(Instant::now()), None);
    fixture.owner.interface_refresh.retry_at = None;
    fixture.owner.udp_only_wake = Some((SocketToken(1), None));
    fixture.owner.remove_listener(SocketToken(1));
    assert!(fixture.owner.udp_only_wake.is_none());
}

#[test]
fn udp_dispatch_does_not_starve_a_tcp_frame_already_in_memory() {
    let mut fixture = Fixture::new();
    fixture.ready(&query("local.dispatch.test", 51));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, address) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    fixture.owner.finish_tcp_accept(PendingInterfaceTcp {
        query_ids: Default::default(), stream, peer: address, local_network: None,
        mac: None, mac_ready: true, mac_deferred: false,
        accept_clock: now_seconds(), auth_query: false,
    });
    let work = fixture.owner.clients[0].dns_work.as_mut().unwrap();
    work.input = encode_tcp_frame(&query("local.dispatch.test", 52)).unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(fixture.owner.clients[0].ready_events, 0);
    assert!(!fixture.owner.udp_dispatch_idle(Instant::now()));
    fixture.owner.step().unwrap();
    assert_eq!(Header::parse(&receive(&fixture.peer).0).unwrap().id, 51);
    let mut length = [0; 2];
    peer.read_exact(&mut length).unwrap();
    let mut answer = vec![0; u16::from_be_bytes(length) as usize];
    peer.read_exact(&mut answer).unwrap();
    assert_eq!(Header::parse(&answer).unwrap().id, 52);
    assert!(answer.ends_with(&[192, 0, 2, 7]));
}

#[test]
fn udp_dispatch_rechecks_the_poll_deadline_at_step_time() {
    let mut fixture = Fixture::new();
    let returned = Instant::now();
    let due = returned + Duration::from_secs(60);
    fixture.owner.udp_only_wake = Some((SocketToken(1), Some(due)));
    assert_eq!(fixture.owner.take_udp_only_listener(returned), Some((0, Some(due))),
        "a future deadline permits the bounded UDP turn");
    fixture.owner.udp_only_wake = Some((SocketToken(1), Some(due)));
    assert_eq!(fixture.owner.take_udp_only_listener(due), None,
        "the timer may become due after poll returns, without another fd event");
    assert!(fixture.owner.udp_only_wake.is_none());
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[test]
fn udp_dispatch_allows_idle_dhcp_but_rejects_a_queued_alarm() {
    let mut fixture = Fixture::new();
    let mut provider = DhcpProvider::new(DhcpConfig {
        no_ping: true, lease_read_only: true, ..Default::default()
    }, Vec::new(), 53, || false).unwrap();
    provider.initialize(now_seconds());
    let provider = Rc::new(RefCell::new(provider));
    let mut listener = DhcpSocketListener::bind("127.0.0.1:0".parse().unwrap(),
        DhcpListener::Dhcp, &[]).unwrap();
    assert!(listener.configure_device_binding(Some(b"lo".to_vec()), true).unwrap());
    fixture.owner.dhcp = Some(DhcpService {
        provider: Some(Rc::clone(&provider)), listener, pxe_next: false,
        output: vec![0; 16_384],
    });
    fixture.ready(&query("local.dispatch.test", 61));
    assert!(fixture.owner.udp_dispatch_idle(Instant::now()));
    assert!(fixture.owner.udp_only_wake.is_some());
    fixture.owner.step().unwrap();
    assert_eq!(Header::parse(&receive(&fixture.peer).0).unwrap().id, 61);
    fixture.ready(&query("local.dispatch.test", 62));
    provider.borrow_mut().request_alarms(1);
    assert_eq!(fixture.owner.take_udp_only_listener(Instant::now()), None);
    assert!(provider.borrow().maintenance_due(Instant::now()), "gate leaves queued work intact");
    fixture.owner.step().unwrap();
    assert!(!provider.borrow().maintenance_due(Instant::now()));
    assert_eq!(Header::parse(&receive(&fixture.peer).0).unwrap().id, 62);
}

#[cfg(target_os = "linux")]
#[test]
fn udp_dispatch_real_wait_rejects_other_readiness_and_queued_work() {
    let mut fixture = Fixture::new();
    let second = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    fixture.peer.send_to(&query("local.dispatch.test", 2), second.local_addr().unwrap()).unwrap();
    fixture.owner.add_listener(SocketToken(2), Some(second), None);
    fixture.ready(&query("local.dispatch.test", 1));
    assert!(fixture.owner.udp_only_wake.is_none(), "two ready listeners require original fairness loop");
    fixture.owner.step().unwrap();
    let mut ids = [Header::parse(&receive(&fixture.peer).0).unwrap().id,
                   Header::parse(&receive(&fixture.peer).0).unwrap().id];
    ids.sort();
    assert_eq!(ids, [1, 2]);
    fixture.owner.full_reload_pending = true;
    fixture.ready(&query("local.dispatch.test", 3));
    assert!(fixture.owner.udp_only_wake.is_none(), "runnable state outranks a lone ready UDP fd");
    fixture.owner.full_reload_pending = false;
    fixture.owner.route_retry_at = Some(Instant::now() + Duration::from_secs(1));
    fixture.owner.wait_for_files().unwrap();
    assert!(fixture.owner.udp_only_wake.is_some(), "a future timer does not prevent UDP work");
    assert!(fixture.owner.take_udp_only_listener(Instant::now()).is_some());
}


#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[test]
fn udp_dispatch_startup_wakeup_requires_the_original_full_turn() {
    let mut fixture = Fixture::unstarted();
    assert!(fixture.owner.arp_awake);
    assert!(!fixture.owner.udp_dispatch_idle(Instant::now()));
    fixture.owner.udp_only_wake = Some((SocketToken(1), None));
    assert_eq!(fixture.owner.take_udp_only_listener(Instant::now()), None,
        "an injected readiness witness must not bypass pending startup work");
    fixture.owner.step().unwrap();
    assert!(!fixture.owner.arp_awake, "the normal neighbor step drains startup work");
    assert!(fixture.owner.udp_dispatch_idle(Instant::now()));
    fixture.ready(&query("local.dispatch.test", 71));
    assert!(fixture.owner.udp_only_wake.is_some());
    fixture.owner.step().unwrap();
    assert_eq!(Header::parse(&receive(&fixture.peer).0).unwrap().id, 71);
}
