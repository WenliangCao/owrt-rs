//! Regression inputs mirror the exact C process_reply known-local cases.
use super::*;
use crate::config::lex_line;
use std::net::UdpSocket;

#[test]
fn invalid_programmatic_address_prefixes_fail_before_starting_dns() {
    for (address, prefix) in [("192.0.2.1", 33), ("2001:db8::1", 129)] {
        let invalid = crate::config::dns::PrefixConfig {
            address: address.parse().unwrap(),
            prefix,
        };
        let mut config = DnsConfig::default();
        config.bogus_addresses.push(invalid);
        assert!(matches!(
            address_policy(&config),
            Err(DaemonError::Config(ConfigError(
                "bad bogus-nxdomain prefix"
            )))
        ));
        config.bogus_addresses.clear();
        config.ignore_addresses.push(invalid);
        assert!(matches!(
            address_policy(&config),
            Err(DaemonError::Config(ConfigError(
                "bad ignore-address prefix"
            )))
        ));
    }
}

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
fn coalesced_replies_retain_each_receiving_listener_and_source() {
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
    let clients = [
        (10, "127.0.0.1:39001", "127.0.0.2", 1),
        (20, "[fe80::2%7]:39002", "fe80::1", 7),
    ];
    for (listener, source, destination, interface) in clients {
        let result = daemon
            .forward_udp_on_listener(
                &request("shared.test", 1),
                ClientRequest {
                    source: source.parse().unwrap(),
                    destination: destination.parse().unwrap(),
                    interface,
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
    for (listener, source, destination, interface) in clients {
        assert!(responses.iter().any(|response| {
            response.listener == Some(crate::dns::forward::SocketToken(listener))
                && response.destination == source.parse::<SocketAddr>().unwrap()
                && response.source == destination.parse::<IpAddr>().unwrap()
                && response.interface == interface
        }));
    }
}

#[test]
fn duplicate_pool_refusal_keeps_current_client_id_and_accepted_recipients() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut daemon = DnsDaemon::new(
        configuration(&upstream),
        Hosts::new(),
        &[],
        DaemonOptions {
            forward_max: 1,
            ..DaemonOptions::default()
        },
    )
    .unwrap();
    let make_query = |host: &str, id: u16, maximum: u16| {
        let mut packet = request(host, 1);
        let mut header = Header::parse(&packet).unwrap();
        header.id = id;
        header.flags = 0x130;
        header.additionals = 1;
        header.write(&mut packet).unwrap();
        packet.extend_from_slice(&[0, 0, 41]);
        packet.extend_from_slice(&maximum.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0x80, 0, 0, 0]);
        packet
    };
    let client = |port| ClientRequest {
        source: SocketAddr::from(([127, 0, 0, 1], port)),
        destination: "127.0.0.1".parse().unwrap(),
        interface: 1,
    };
    let first = make_query("hold.test", 0x7101, 512);
    assert!(matches!(
        daemon.handle_udp(&first, client(39001)).unwrap(),
        QueryResult::Forwarded(_)
    ));
    let mut input = [0; 4096];
    let (length, peer) = upstream.recv_from(&mut input).unwrap();
    let upstream_id = Header::parse(&input[..length]).unwrap().id;
    let second = make_query("hold.test", 0x7102, 512);
    assert!(matches!(
        daemon.handle_udp(&second, client(39002)).unwrap(),
        QueryResult::Forwarded(_)
    ));
    let rejected_id = if upstream_id == 0x7103 {
        0x7104
    } else {
        0x7103
    };
    let rejected = make_query("HOLD.test", rejected_id, 1232);
    let QueryResult::Local(reply) = daemon.handle_udp(&rejected, client(39003)).unwrap() else {
        panic!("duplicate pool exhaustion must refuse this client");
    };
    let header = Header::parse(&reply).unwrap();
    assert_eq!(header.id, rejected_id);
    assert_ne!(header.id, upstream_id);
    assert_eq!(header.flags, 0x8195);
    let end = super::super::wire::skip_questions(&rejected).unwrap();
    assert_eq!(&reply[12..end], &rejected[12..end]);
    let opt = find_pseudoheader(&reply, false).unwrap().opt.unwrap();
    assert_eq!(opt.record.class, 1232);
    assert_eq!(opt.record.ttl, 0);
    assert!(opt.record.rdata.is_empty());
    assert_eq!(daemon.pending_count(), 1);

    let end = super::super::wire::skip_questions(&input[..length]).unwrap();
    let mut response = input[..end].to_vec();
    let mut header = Header::parse(&response).unwrap();
    header.flags = 0x8180;
    header.answers = 1;
    header.additionals = 0;
    header.write(&mut response).unwrap();
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
    upstream.send_to(&response, peer).unwrap();
    let responses = daemon.poll(Duration::from_millis(250)).unwrap();
    assert_eq!(
        responses
            .iter()
            .map(|response| Header::parse(&response.packet).unwrap().id)
            .collect::<Vec<_>>(),
        [0x7101, 0x7102]
    );
    assert_eq!(daemon.pending_count(), 0);
    assert_eq!(daemon.upstream.socket_count(), 0);
}
