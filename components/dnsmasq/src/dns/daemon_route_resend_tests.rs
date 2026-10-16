use super::*;
use crate::config::lex_line;
use std::net::UdpSocket;

fn packet(host: &str) -> Vec<u8> {
    packet_kind(host, 1)
}

fn packet_kind(host: &str, kind: u16) -> Vec<u8> {
    let mut writer = PacketWriter::new(0x7331, 0x100, 512).unwrap();
    writer
        .question(&Name::from_ascii(host).unwrap(), kind, 1)
        .unwrap();
    writer.finish()
}

fn client() -> ClientRequest {
    ClientRequest {
        source: "127.0.0.1:39001".parse().unwrap(),
        destination: "127.0.0.1".parse().unwrap(),
        interface: 1,
    }
}

fn daemon() -> (DnsDaemon, UdpSocket) {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut config = DnsConfig::default();
    for line in [
        "no-resolv".to_string(),
        "no-hosts".to_string(),
        "txt-record=local.route.test,local".to_string(),
        format!("server=127.0.0.1#{}", server.local_addr().unwrap().port()),
    ] {
        config
            .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
            .unwrap();
    }
    let mut daemon = DnsDaemon::new(config, Hosts::new(), &[], DaemonOptions::default()).unwrap();
    daemon.enable_cache(4, 0, 0, StalePolicy::Disabled);
    (daemon, server)
}

fn received(server: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut bytes = [0; 2048];
    let (length, peer) = server.recv_from(&mut bytes).unwrap();
    (bytes[..length].to_vec(), peer)
}

fn quiet(server: &UdpSocket) {
    server.set_nonblocking(true).unwrap();
    assert_eq!(
        server.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    server.set_nonblocking(false).unwrap();
}

fn pending(daemon: &mut DnsDaemon, server: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    assert!(matches!(
        daemon
            .handle_udp(&packet("pending.route.test"), client())
            .unwrap(),
        QueryResult::Forwarded(_)
    ));
    received(server)
}

#[test]
fn direct_local_invalid_and_reload_callers_clear_only_resend_not_pending_udp() {
    for operation in ["local", "invalid", "invalid-forward", "reload"] {
        let (mut daemon, server) = daemon();
        pending(&mut daemon, &server);
        let counts = daemon.forward_counters();
        match operation {
            "local" => assert!(matches!(
                daemon
                    .handle_udp(&packet_kind("local.route.test", 16), client())
                    .unwrap(),
                QueryResult::Local(_)
            )),
            "invalid" => assert!(matches!(
                daemon.handle_udp(b"bad", client()).unwrap(),
                QueryResult::Dropped
            )),
            "invalid-forward" => assert!(daemon.forward_udp(b"bad", client()).is_err()),
            "reload" => daemon.reload_hosts(Hosts::new()),
            _ => unreachable!(),
        }
        daemon.resend_udp_query();
        quiet(&server);
        assert_eq!(
            daemon.pending_count(),
            1,
            "a scratch clear is not cancellation: {operation}"
        );
        assert_eq!(daemon.forward_counters(), counts);
    }
}

#[test]
fn cache_hit_clears_parent_udp_save_but_plain_tcp_snapshot_keeps_it() {
    let (mut daemon, server) = daemon();
    let seed = packet("cached.route.test");
    assert!(matches!(
        daemon.handle_udp(&seed, client()).unwrap(),
        QueryResult::Forwarded(_)
    ));
    let (wire, peer) = received(&server);
    let question = WireQuestion::parse(&wire, 12).unwrap();
    let mut writer = PacketWriter::new(Header::parse(&wire).unwrap().id, 0x8180, 512).unwrap();
    writer.question(&question.name, 1, 1).unwrap();
    writer
        .record_at(Section::Answer, 12, 1, 1, 60, &[192, 0, 2, 55])
        .unwrap();
    server.send_to(&writer.finish(), peer).unwrap();
    assert_eq!(daemon.poll(Duration::from_secs(1)).unwrap().len(), 1);
    let saved = pending(&mut daemon, &server);
    let _private_snapshot = daemon.tcp_snapshot().unwrap();
    daemon.resend_udp_query();
    assert_eq!(received(&server), saved);
    assert!(matches!(
        daemon.handle_udp(&seed, client()).unwrap(),
        QueryResult::Cached(_)
    ));
    daemon.resend_udp_query();
    quiet(&server);
    assert_eq!(daemon.pending_count(), 1);
    assert_eq!(daemon.forward_counters().queries_forwarded, 2);
}

#[test]
fn plain_cached_udp_clears_deferred_resend_without_cancelling_pending() {
    let (mut daemon, server) = daemon();
    let seed = packet("cached.route.test");
    assert!(matches!(daemon.handle_udp(&seed, client()).unwrap(), QueryResult::Forwarded(_)));
    let (wire, peer) = received(&server);
    let question = WireQuestion::parse(&wire, 12).unwrap();
    let mut writer = PacketWriter::new(Header::parse(&wire).unwrap().id, 0x8180, 512).unwrap();
    writer.question(&question.name, 1, 1).unwrap();
    writer.record_at(Section::Answer, 12, 1, 1, 60, &[192, 0, 2, 55]).unwrap();
    server.send_to(&writer.finish(), peer).unwrap();
    assert_eq!(daemon.poll(Duration::from_secs(1)).unwrap().len(), 1);

    let mut local = LocalDnsService::new(DnsConfig::default(), Hosts::new(), 60, 1232);
    let metadata = super::super::forward_service::query_metadata(&seed, 1232).unwrap();
    let QueryResult::Cached(answer) = daemon.answer_udp_prepared_with_local(
        &seed, &seed, metadata, client(), None, &mut local,
    ).unwrap() else { panic!("expected warm cache hit"); };
    local.recycle_cached_reply(answer);
    assert!(daemon.udp_name_buffer.capacity() > 0);

    // The received hit cleared scratch before an asynchronous admission wait.
    // A later upstream send during that wait can repopulate the saved packet.
    daemon.invalidate_udp_resend();
    let saved = pending(&mut daemon, &server);
    let counts = daemon.forward_counters();
    daemon.resend_udp_query();
    assert_eq!(received(&server), saved, "the deferred interval must leave a live resend");

    let answer = daemon.try_plain_cached_udp(&seed, &mut local)
        .expect("warm plain address hit must select the shortcut").unwrap();
    assert_eq!(&answer[answer.len() - 4..], &[192, 0, 2, 55]);
    assert_eq!(daemon.pending_count(), 1, "scratch invalidation is not cancellation");
    assert_eq!(daemon.forward_counters(), counts);
    daemon.resend_udp_query();
    // A nonblocking read can race local UDP delivery on macOS.
    server.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let received = server.recv_from(&mut [0; 2048]);
    assert!(received.is_err(), "cached hit retained the deferred resend: {received:?}");
    assert!(matches!(received.unwrap_err().kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut));
    assert_eq!(daemon.pending_count(), 1);
    assert_eq!(daemon.forward_counters(), counts);
}
