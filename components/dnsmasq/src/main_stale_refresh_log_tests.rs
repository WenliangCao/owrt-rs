//! A submitted stale refresh owns an immediate log record even without a reply.
use super::*;
use dnsmasq_rs::config::{
    lex_line,
    logging::{LoggingConfig, QueryLogging},
};
use dnsmasq_rs::dns::wire::{Message, Name, PacketWriter, Question, Section};
use dnsmasq_rs::logging::Logger;
use std::net::UdpSocket;

const NAME: &str = "stale-log.test";

fn packet(id: u16, answer: bool) -> Vec<u8> {
    let name = Name::from_ascii(NAME).unwrap();
    let mut writer = PacketWriter::new(id, if answer { 0x8180 } else { 0x100 }, 1232).unwrap();
    writer.question(&name, 1, 1).unwrap();
    if answer {
        writer
            .record(Section::Answer, &name, 1, 1, 1, &[192, 0, 2, 7])
            .unwrap();
    }
    writer.finish()
}

fn stale_refresh_log_case(deliver_late_reply: bool) {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut config = DnsConfig::default();
    config.no_resolv = true;
    config.no_hosts = true;
    config.bind_interfaces = true;
    let server_line = format!("server=127.0.0.1#{}", upstream.local_addr().unwrap().port());
    config
        .apply(&lex_line(server_line.as_bytes()).unwrap().unwrap())
        .unwrap();
    let queries = QueryLogging {
        enabled: true,
        extra: true,
        protocol: true,
        ..Default::default()
    };
    let mut daemon = DnsDaemon::new(
        config.clone(),
        Hosts::new(),
        &[],
        DaemonOptions {
            upstream_lifetime: dnsmasq_rs::dns::upstream::Lifetime::Fixed(Duration::from_secs(30)),
            ..Default::default()
        },
    )
    .unwrap();
    daemon.enable_cache(8, 0, 0, StalePolicy::Forever);
    daemon.set_query_logging(queries);
    // Use the production cache importer with an already-expired clock. The
    // actual socket query must serve this entry; no sleeps or fake wake flags.
    daemon.cache_tcp_reply(&packet(1, true), now_seconds() - 10);
    daemon.take_query_events();
    let mut owner = tests::test_owner(config, Some(daemon));
    owner.query_logging = queries;
    {
        let mut parent = owner.service.borrow_mut();
        parent.local.query_logging = true;
        for _ in 0..105 {
            parent.query_ids.next(false, None);
        }
    }
    let listener = Arc::new(DnsSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let address = listener.local_addr().unwrap();
    owner.add_listener(SocketToken(1), Some(listener), None);
    let suffix = if deliver_late_reply {
        "late"
    } else {
        "withheld"
    };
    let path =
        std::env::temp_dir().join(format!("dnsmasq-stale-log-{suffix}-{}", std::process::id()));
    let (logger, _) = Logger::start(
        &LoggingConfig {
            file: Some(path.clone()),
            ..Default::default()
        },
        &Default::default(),
        None,
    )
    .unwrap();
    owner.logger = Some(logger);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.send_to(&packet(0x1234, false), address).unwrap();
    owner.wait_for_files().unwrap();
    owner.step().unwrap();
    let mut bytes = [0; 1232];
    let (length, _) = client.recv_from(&mut bytes).unwrap();
    let answer = Message::parse(&bytes[..length]).unwrap();
    assert_eq!(answer.header.id, 0x1234);
    let records = answer.records(Section::Answer).collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].ttl, 0);
    assert_eq!(records[0].rrtype, 1);
    assert_eq!(records[0].class, 1);
    assert_eq!(records[0].rdata, &[192, 0, 2, 7]);
    let (length, refresh_peer) = upstream.recv_from(&mut bytes).unwrap();
    let refresh = Message::parse(&bytes[..length]).unwrap();
    assert_eq!(
        Question::parse(&bytes[..length], 12).unwrap().name,
        Name::from_ascii(NAME).unwrap()
    );
    let forwarded = format!(
        "UDP 106 forwarded {NAME} to 127.0.0.1#{}",
        upstream.local_addr().unwrap().port()
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        text.matches(&forwarded).count(),
        1,
        "submission must log before any upstream reply or a second owner wake"
    );
    assert!(text.contains(&format!("cached-stale {NAME} is 192.0.2.7")));
    assert!(
        !text.contains(&format!(
            "UDP 106 {}/{} forwarded",
            client.local_addr().unwrap().ip(),
            client.local_addr().unwrap().port()
        )),
        "background refresh clears client prefix"
    );
    assert_eq!(
        owner
            .service
            .borrow()
            .daemon
            .as_ref()
            .unwrap()
            .pending_count(),
        1
    );
    if deliver_late_reply {
        // The reply is deliberately delivered only after the submission log
        // has been checked. It may add a reply log, never a second forward log
        // or another client answer.
        upstream
            .send_to(&packet(refresh.header.id, true), refresh_peer)
            .unwrap();
        owner.wait_for_files().unwrap();
        owner.step().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches(&forwarded).count(), 1);
        assert!(text.contains(&format!("UDP 106 reply {NAME} is 192.0.2.7")));
        assert_eq!(
            owner
                .service
                .borrow()
                .daemon
                .as_ref()
                .unwrap()
                .pending_count(),
            0
        );
    }
    client.set_nonblocking(true).unwrap();
    assert_eq!(
        client.recv_from(&mut bytes).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "refresh must not produce a second client answer"
    );
    drop(owner);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn stale_udp_refresh_logs_submission_without_an_upstream_reply() {
    stale_refresh_log_case(false);
}

#[test]
fn stale_udp_refresh_late_reply_keeps_one_forward_log_and_no_second_answer() {
    stale_refresh_log_case(true);
}
