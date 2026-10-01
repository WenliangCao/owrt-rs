//! Regression inputs mirror the exact C process_reply known-local cases.
use super::*;
use crate::config::lex_line;
use std::net::UdpSocket;

fn configuration(upstream: &UdpSocket) -> DnsConfig {
    let mut config = DnsConfig::default();
    for line in [
        "no-resolv".to_string(),
        format!("server=127.0.0.1#{}", upstream.local_addr().unwrap().port()),
    ] {
        config
            .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
            .unwrap();
    }
    config
}

fn request(name: &str, qtype: u16) -> Vec<u8> {
    let mut writer = PacketWriter::new(0x2930, 0x100, 1232).unwrap();
    writer
        .question(&Name::from_ascii(name).unwrap(), qtype, 1)
        .unwrap();
    writer.finish()
}

fn negative_reply(upstream: &UdpSocket) {
    let mut query = [0; 4096];
    let (length, peer) = upstream.recv_from(&mut query).unwrap();
    let mut header = Header::parse(&query[..length]).unwrap();
    header.flags = 0x8183;
    header.write(&mut query[..length]).unwrap();
    upstream.send_to(&query[..length], peer).unwrap();
}

fn admit(daemon: &mut DnsDaemon, name: &str, qtype: u16) {
    let outcome = daemon
        .handle_udp(
            &request(name, qtype),
            ClientRequest {
                source: "127.0.0.1:39001".parse().unwrap(),
                destination: "127.0.0.1".parse().unwrap(),
                interface: 1,
            },
        )
        .unwrap();
    assert!(matches!(outcome, QueryResult::Forwarded(_)));
}

#[test]
fn pending_udp_reply_uses_current_local_generation() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let config = configuration(&upstream);
    let mut daemon =
        DnsDaemon::new(config.clone(), Hosts::new(), &[], DaemonOptions::default()).unwrap();
    admit(&mut daemon, "changed.test", 28);
    negative_reply(&upstream);
    // The daemon's original private hosts table stays empty. Publication or
    // reload can add this A owner while its AAAA query is pending upstream.
    let mut hosts = Hosts::new();
    hosts.insert(
        b"changed.test".to_vec(),
        "192.0.2.7".parse().unwrap(),
        37,
        1,
    );
    let current = LocalDnsService::new(config, hosts, 37, 1232);
    let responses = daemon
        .poll_with_local(Duration::from_millis(250), &current)
        .unwrap();
    assert_eq!(responses.len(), 1);
    let header = Header::parse(&responses[0].packet).unwrap();
    assert_eq!(header.id, 0x2930);
    assert_eq!(header.flags, 0x8580); // C: NOERROR, AA, RA, RD.
    assert_eq!(
        (header.answers, header.authorities, header.additionals),
        (0, 0, 0)
    );
    assert!(daemon.local.hosts.is_empty());
}

#[test]
fn pending_udp_address_reply_cannot_cache_over_the_current_local_generation() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let config = configuration(&upstream);
    let mut daemon =
        DnsDaemon::new(config.clone(), Hosts::new(), &[], DaemonOptions::default()).unwrap();
    daemon.enable_cache(4, 0, 0, StalePolicy::Disabled);
    admit(&mut daemon, "changed.test", 1);
    let mut query = [0; 4096];
    let (length, peer) = upstream.recv_from(&mut query).unwrap();
    let end = super::super::wire::skip_questions(&query[..length]).unwrap();
    let mut reply = query[..end].to_vec();
    let mut header = Header::parse(&reply).unwrap();
    header.flags = 0x8180;
    header.answers = 1;
    header.additionals = 0;
    header.write(&mut reply).unwrap();
    reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 99]);
    upstream.send_to(&reply, peer).unwrap();
    let mut hosts = Hosts::new();
    hosts.insert(
        b"changed.test".to_vec(),
        "192.0.2.7".parse().unwrap(),
        37,
        1,
    );
    let current = LocalDnsService::new(config, hosts, 37, 1232);
    let responses = daemon
        .poll_with_local(Duration::from_millis(250), &current)
        .unwrap();
    assert_eq!(responses.len(), 1);
    assert!(responses[0].packet.ends_with(&[192, 0, 2, 99]));
    assert!(daemon.local.hosts.is_empty());
    // The containing process has now removed that local source. The rejected
    // dynamic answer must not become visible after the source disappears.
    admit(&mut daemon, "changed.test", 1);
    assert_eq!(daemon.pending_count(), 1);
}

#[test]
fn udp_address_rule_is_known_but_upstream_rule_is_not() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut config = configuration(&upstream);
    config
        .apply(&lex_line(b"address=/known.test/192.0.2.7").unwrap().unwrap())
        .unwrap();
    let current = LocalDnsService::new(config.clone(), Hosts::new(), 0, 1232);
    let mut daemon = DnsDaemon::new(config, Hosts::new(), &[], DaemonOptions::default()).unwrap();
    for (name, flags) in [("known.test", 0x8580), ("unknown.test", 0x8183)] {
        admit(&mut daemon, name, 65400);
        negative_reply(&upstream);
        let responses = daemon
            .poll_with_local(Duration::from_millis(250), &current)
            .unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(Header::parse(&responses[0].packet).unwrap().flags, flags);
    }
}

#[test]
fn coalesced_replies_retain_each_receiving_listener() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut daemon = DnsDaemon::new(
        configuration(&upstream),
        Hosts::new(),
        &[],
        DaemonOptions::default(),
    )
    .unwrap();
    for (listener, port) in [(10, 39001), (20, 39002)] {
        let result = daemon
            .forward_udp_on_listener(
                &request("shared.test", 1),
                ClientRequest {
                    source: SocketAddr::from(([127, 0, 0, 1], port)),
                    destination: "127.0.0.1".parse().unwrap(),
                    interface: 1,
                },
                Some(crate::dns::forward::SocketToken(listener)),
            )
            .unwrap();
        assert!(matches!(result, QueryResult::Forwarded(_)));
    }
    assert_eq!(daemon.pending_count(), 1);
    negative_reply(&upstream);
    let responses = daemon.poll(Duration::from_millis(250)).unwrap();
    assert_eq!(responses.len(), 2);
    for (listener, port) in [(10, 39001), (20, 39002)] {
        assert!(responses.iter().any(|response| {
            response.listener == Some(crate::dns::forward::SocketToken(listener))
                && response.destination.port() == port
        }));
    }
}
