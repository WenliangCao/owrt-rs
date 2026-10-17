//! Dump completion in the same turn as admission must not lose its continuation.
use super::*;
use std::os::fd::AsRawFd;

fn queued_client(config: DnsConfig) -> (SinglePoll, TcpStream) {
    let mut owner = tests::test_owner(config, None);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, address) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    owner.finish_tcp_accept(PendingInterfaceTcp {
        auth_query: false,
        query_ids: Default::default(), stream, peer: address, local_network: None,
        mac: None, mac_ready: false, mac_deferred: false, accept_clock: now_seconds(),
    });
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    peer.write_all(&encode_tcp_frame(&query()).unwrap()).unwrap();
    owner.neighbors = Some(NeighborCache::new().unwrap());
    (owner, peer)
}

fn query() -> Vec<u8> {
    use dnsmasq_rs::dns::wire::{Name, PacketWriter};
    let mut writer = PacketWriter::new(7, 0x100, 1232).unwrap();
    writer.question(&Name::from_ascii("ready.test").unwrap(), 1, 1).unwrap();
    writer.finish()
}

fn await_dump_datagram(owner: &SinglePoll) {
    // Deliberately observe only the real kernel dump socket here. The owner
    // has not polled it and must not inherit this test's revents or wake flag.
    let mut fds = Vec::new();
    owner.neighbors.as_ref().unwrap().append_poll_fds(&mut fds);
    assert_eq!(fds.len(), 1);
    assert!(dnsmasq_platform::poll::poll_fds(&mut fds, 1000).unwrap() > 0);
    assert!(!owner.neighbors_ready);
}

#[test]
fn tail_dump_completion_captures_accept_mac_then_registers_real_downstream() {
    let (mut owner, _peer) = queued_client(DnsConfig::default());
    let source = owner.clients[0].dns_work.as_ref().unwrap().source;
    assert!(matches!(owner.edns_mac(source, false), ClientMacLookup::Pending));
    assert!(!owner.tcp_client_ready(0));
    assert_eq!(owner.clients[0].ready_events, 0);
    await_dump_datagram(&owner);
    owner.advance_neighbors();
    assert_eq!(owner.neighbors.as_ref().unwrap().active_dump_deadline(), None);
    assert!(owner.clients[0].dns_work.as_ref().unwrap().mac_ready, "tail publication must resume the accepted MAC lookup");
    assert_eq!(owner.clients[0].ready_events, 0, "completion is not a synthetic POLLIN");
    assert!(owner.clients[0].dns_work.as_ref().unwrap().input.is_empty());
    let fd = owner.clients[0].dns_work.as_ref().unwrap().stream.as_ref().unwrap().as_raw_fd();
    owner.wait_for_files().unwrap();
    assert!(owner.poll_fds.iter().any(|item| item.fd == fd && item.events == dnsmasq_platform::poll::POLLIN));
    assert!(poll_events_match(owner.clients[0].ready_events, dnsmasq_platform::poll::POLLIN),
        "only the actual queued downstream socket supplies read readiness");
}

#[test]
fn captured_buffered_mac_query_is_runnable_and_does_not_lookup_again() {
    let mut config = DnsConfig::default();
    config.apply(&dnsmasq_rs::config::lex_line(b"host-record=ready.test,192.0.2.99").unwrap().unwrap()).unwrap();
    let (mut owner, mut peer) = queued_client(config);
    // The separate queued bytes are not needed by this already-framed query.
    // A captured MAC must authorize its phase without declaring them readable.
    let client = owner.clients[0].dns_work.as_mut().unwrap();
    client.queries = 1;
    client.phase = TcpClientPhase::WaitingMac { query: query() };
    client.mac = Some(vec![2, 0, 0, 0, 0, 1]);
    client.mac_ready = true;
    assert!(owner.tcp_client_ready(0));
    owner.wait_for_files().unwrap();
    assert_eq!(owner.clients[0].ready_events, 0);
    assert!(owner.clients[0].dns_work.as_mut().unwrap().step(&owner.service,
        &mut |_, _| panic!("captured connection MAC must not be looked up again"),
        false, false, false).unwrap());
    assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().mac, Some(vec![2, 0, 0, 0, 0, 1]));
    let mut length = [0; 2];
    peer.read_exact(&mut length).unwrap();
    let mut packet = vec![0; u16::from_be_bytes(length) as usize];
    peer.read_exact(&mut packet).unwrap();
    assert_eq!(&packet[..2], &query()[..2]);
    assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().queries, 1, "the separate queued frame was not read without POLLIN");
}

#[test]
fn tail_dump_completion_resumes_udp_and_interface_held_accept() {
    let mut owner = tests::test_owner(DnsConfig::default(), None);
    owner.neighbors = Some(NeighborCache::new().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, address) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    owner.pending_interface_tcp = Some(PendingInterfaceTcp {
        auth_query: false,
        query_ids: Default::default(), stream, peer: address, local_network: None,
        mac: None, mac_ready: false, mac_deferred: false, accept_clock: now_seconds(),
    });
    assert!(matches!(owner.edns_mac(address.ip(), false), ClientMacLookup::Pending));
    owner.pending_edns_udp.push(PendingEdnsUdp {
        query_context: Default::default(), listener: SocketToken(99),
        client: ClientRequest { source: address, destination: "127.0.0.1".parse().unwrap(), interface: 1 },
        query: query(), deadline: Instant::now() + Duration::from_secs(3),
    });
    await_dump_datagram(&owner);
    owner.advance_neighbors();
    assert!(owner.pending_interface_tcp.as_ref().unwrap().mac_ready,
        "interface publication cannot recreate a wait on an already completed dump");
    owner.step_edns_udp();
    assert!(owner.pending_edns_udp.is_empty());
    let pending = owner.pending_interface_tcp.take().unwrap();
    owner.finish_tcp_accept(pending);
    assert!(owner.clients[0].dns_work.as_ref().unwrap().mac_ready);
}

#[test]
fn tail_dump_completion_resumes_tftp_mac_waiter_without_socket_ready_hint() {
    use dnsmasq_rs::config::tftp::TftpConfig;
    use std::net::UdpSocket;
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
    assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
    let root = std::env::temp_dir().join(format!("neighbor-tail-tftp-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("boot.bin"), b"tail-completion").unwrap();
    std::fs::set_permissions(root.join("boot.bin"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut dns = DnsConfig::default();
    dns.bind_interfaces = true;
    dns.listen_addresses.push("127.0.0.1".parse().unwrap());
    let config = TftpConfig { enabled: true, root: Some(root.as_os_str().as_bytes().to_vec()),
        unique_root_mac: true, max_transfers: 0, ..Default::default() };
    let listener = TftpListener::bind_config(&config, &dns, &[], &[], 0, 0, 1497).unwrap();
    let destination = listener.local_addr().unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    peer.send_to(b"\0\x01boot.bin\0octet\0", destination).unwrap();
    let mut owner = tests::test_owner(DnsConfig::default(), None);
    owner.neighbors = Some(NeighborCache::new().unwrap());
    owner.tftp = Some(listener);
    let now = now_seconds() as u64;
    let neighbors = owner.neighbors.as_mut().unwrap();
    assert!(owner.tftp.as_mut().unwrap().poll_once_with_mac(now,
        &mut |address, interface, now| neighbors.query(address, interface, now)).unwrap().is_empty());
    assert!(owner.tftp.as_ref().unwrap().has_pending_work());
    assert_eq!(owner.tftp.as_ref().unwrap().active_transfers(), 0);
    owner.tftp_next_due = Some(Instant::now() + Duration::from_secs(60));
    owner.step_tftp();
    assert_eq!(owner.tftp.as_ref().unwrap().active_transfers(), 0);
    await_dump_datagram(&owner);
    owner.advance_neighbors();
    assert!(!owner.tftp_ready && owner.ready_fds.is_empty(), "no TFTP socket readiness was invented");
    owner.step_tftp();
    let mut packet = [0; 512];
    let (length, _) = peer.recv_from(&mut packet).unwrap();
    assert_eq!(&packet[..length], b"\0\x03\0\x01tail-completion");
    assert_eq!(owner.neighbors.as_ref().unwrap().active_dump_deadline(), None);
    drop(owner);
    std::fs::remove_dir_all(root).unwrap();
}
