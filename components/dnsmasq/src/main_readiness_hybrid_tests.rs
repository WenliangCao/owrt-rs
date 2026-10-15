//! Caller-level readiness controls across real normal/probe owner turns.

use super::*;
use super::tests::test_owner;
use dnsmasq_rs::dns::wire::{Name, PacketWriter};
use std::os::fd::AsRawFd;

fn owner() -> SinglePoll {
    let mut config = DnsConfig::default();
    config.no_hosts = true;
    config.no_resolv = true;
    config.bind_interfaces = true;
    config.apply(&dnsmasq_rs::config::lex_line(
        b"host-record=ready.test,192.0.2.7").unwrap().unwrap()).unwrap();
    test_owner(config, None)
}

fn query() -> Vec<u8> {
    let mut writer = PacketWriter::new(19, 0x100, 1232).unwrap();
    writer.question(&Name::from_ascii("ready.test").unwrap(), 1, 1).unwrap();
    writer.finish()
}

fn accept(owner: &mut SinglePoll) -> TcpStream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, address) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    owner.finish_tcp_accept(PendingInterfaceTcp {
        query_ids: Default::default(), stream, peer: address, local_network: None,
        mac: None, mac_ready: true, mac_deferred: false, accept_clock: now_seconds(),
        auth_query: false,
    });
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    peer
}

#[test]
fn normal_signal_registration_does_not_shorten_a_later_probe_idle_interval() {
    let mut owner = owner();
    let (read_end, write_end) = owrt_ubus::sys::nonblocking_pipe().unwrap();
    let signal_fd = read_end.as_raw_fd();
    owner.signal_wake_read = Some(read_end);
    let mut writer = std::fs::File::from(write_end);
    let udp = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    owner.add_listener(SocketToken(11), Some(Arc::clone(&udp)), None);

    // First install the normal wait set without blocking or consuming data.
    owner.full_reload_pending = true;
    owner.wait_for_files().unwrap();
    owner.full_reload_pending = false;
    writer.write_all(b"x").unwrap();

    let started = Instant::now();
    assert!(!owner.wait_during_probe(None, Duration::from_millis(25), Default::default()).unwrap());
    assert!(started.elapsed() >= Duration::from_millis(20),
        "normal-only signal readiness must not consume a probe idle interval");
    let mut signal = [owrt_ubus::sys::PollFd {
        fd: signal_fd, events: owrt_ubus::sys::POLLIN, revents: 0,
    }];
    assert_eq!(owrt_ubus::sys::poll_fds(&mut signal, 0).unwrap(), 1,
        "the probe must leave the signal byte queued");

    owner.wait_for_files().unwrap();
    assert!(owner.fd_ready(signal_fd, owrt_ubus::sys::POLLIN));
    assert_eq!(owrt_ubus::sys::poll_fds(&mut signal, 0).unwrap(), 0,
        "the normal owner still drains its own signal source");
    peer.send_to(&query(), udp.local_addr().unwrap()).unwrap();
    assert!(owner.wait_during_probe(None, Duration::from_millis(100), Default::default()).unwrap());
    let mut answer = [0; 1232];
    let size = peer.recv(&mut answer).unwrap();
    assert_eq!(&answer[..2], &[0, 19]);
    assert!(answer[..size].ends_with(&[192, 0, 2, 7]),
        "normal/probe set changes must retain real UDP progress");
}

#[test]
fn expired_ready_tcp_client_does_not_wake_its_new_owner_slot() {
    let mut owner = owner();
    let mut previous = accept(&mut owner);
    previous.write_all(&encode_tcp_frame(&query()).unwrap()).unwrap();
    owner.wait_for_files().unwrap();
    assert_ne!(owner.clients[0].ready_events & owrt_ubus::sys::POLLIN, 0);
    owner.clients[0].dns_work.as_mut().unwrap().deadline = Instant::now();
    owner.step_tcp_clients();
    assert!(owner.clients.is_empty());

    let mut current = accept(&mut owner);
    assert_eq!(owner.clients[0].ready_events, 0,
        "a newly accepted client cannot inherit the retired client's readiness");
    let started = Instant::now();
    assert!(!owner.wait_during_probe(None, Duration::from_millis(25), Default::default()).unwrap());
    assert!(started.elapsed() >= Duration::from_millis(20));
    assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().queries, 0);

    current.write_all(&encode_tcp_frame(&query()).unwrap()).unwrap();
    assert!(owner.wait_during_probe(None, Duration::from_millis(100), Default::default()).unwrap());
    let mut length = [0; 2];
    current.read_exact(&mut length).unwrap();
    let mut answer = vec![0; usize::from(u16::from_be_bytes(length))];
    current.read_exact(&mut answer).unwrap();
    assert_eq!(&answer[..2], &[0, 19]);
    assert!(answer.ends_with(&[192, 0, 2, 7]));
    assert_eq!(owner.clients[0].dns_work.as_ref().unwrap().queries, 1);
}
