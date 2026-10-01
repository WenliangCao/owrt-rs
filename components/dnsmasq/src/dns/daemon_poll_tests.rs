use super::*;
use crate::config::lex_line;
use std::net::UdpSocket;

/// Admit real transactions and receive both successful responses through the
/// production transport. The caller then controls only the ordering of an
/// explicit terminal timeout/release event, avoiding wall-clock races.
fn completed_pair() -> (DnsDaemon, Vec<UpstreamEvent>, QueryId) {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut config = DnsConfig::default();
    for line in [
        "no-resolv".to_string(),
        format!("server=127.0.0.1#{}", upstream.local_addr().unwrap().port()),
    ] {
        config
            .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
            .unwrap();
    }
    let mut daemon = DnsDaemon::new(config, Hosts::new(), &[], DaemonOptions::default()).unwrap();
    let mut pending = None;
    for (index, host) in ["slow.test", "first.test", "second.test"]
        .into_iter()
        .enumerate()
    {
        let name = Name::from_ascii(host).unwrap();
        let mut query = PacketWriter::new(0x7100 + index as u16, 0x100, 512).unwrap();
        query.question(&name, 1, 1).unwrap();
        let QueryResult::Forwarded(id) = daemon
            .handle_udp(
                &query.finish(),
                ClientRequest {
                    source: "127.0.0.1:39001".parse().unwrap(),
                    destination: "127.0.0.1".parse().unwrap(),
                    interface: 1,
                },
            )
            .unwrap()
        else {
            panic!("query was not forwarded");
        };
        if index == 0 {
            pending = Some(id);
        }
        let mut packet = [0; 4096];
        let (length, peer) = upstream.recv_from(&mut packet).unwrap();
        if index != 0 {
            let question = WireQuestion::parse(&packet[..length], 12).unwrap();
            let mut reply =
                PacketWriter::new(Header::parse(&packet[..length]).unwrap().id, 0x8180, 512)
                    .unwrap();
            reply.question(&question.name, 1, 1).unwrap();
            reply
                .record_at(Section::Answer, 12, 1, 1, 60, &[192, 0, 2, index as u8])
                .unwrap();
            upstream.send_to(&reply.finish(), peer).unwrap();
        }
    }
    assert_eq!(daemon.pending_count(), 3);
    assert_eq!(daemon.upstream.socket_count(), 3);
    let mut events = Vec::new();
    for _ in 0..3 {
        events.extend(daemon.upstream.poll(Duration::from_millis(100)).unwrap());
        if events.len() == 2 {
            break;
        }
    }
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| event.result.is_ok()));
    let completed_ids = ids(&events);
    assert!(completed_ids.contains(&0x7101) && completed_ids.contains(&0x7102));
    assert_eq!(daemon.pending_count(), 1);
    let pending = pending.unwrap();
    assert!(daemon.upstream.cancel(pending));
    assert_eq!(daemon.pending_count(), 0);
    assert_eq!(daemon.upstream.socket_count(), 0);
    (daemon, events, pending)
}

fn ids(events: &[UpstreamEvent]) -> Vec<u16> {
    events
        .iter()
        .filter_map(|event| event.result.as_ref().ok())
        .flat_map(|reply| {
            reply
                .recipients
                .iter()
                .map(|recipient| recipient.original_id)
        })
        .collect()
}

#[test]
fn terminal_failure_before_between_or_after_successes_keeps_each_response() {
    for failure in 0..4 {
        for position in 0..=2 {
            let (mut daemon, mut events, pending) = completed_pair();
            let expected = ids(&events);
            let error = match failure {
                0 => ResolveError::Timeout,
                1 => ResolveError::Released(super::super::forward::ReleaseReason::Expired),
                2 => ResolveError::Released(super::super::forward::ReleaseReason::ServerGone),
                _ => ResolveError::NoServer,
            };
            events.insert(
                position,
                UpstreamEvent {
                    id: pending,
                    result: Err(error),
                },
            );
            let responses = daemon.finish_upstream_events(events, 100, None);
            assert_eq!(
                responses
                    .iter()
                    .map(|response| Header::parse(&response.packet).unwrap().id)
                    .collect::<Vec<_>>(),
                expected
            );
            for response in responses {
                assert_eq!(Header::parse(&response.packet).unwrap().flags, 0x8180);
            }
            assert_eq!(
                daemon.poll_failures(),
                PollFailures {
                    timeouts: u64::from(failure < 2),
                    upstream_errors: u64::from(failure >= 2),
                    ..PollFailures::default()
                }
            );
            assert_eq!(daemon.pending_count(), 0);
            assert_eq!(daemon.upstream.socket_count(), 0);
        }
    }
}

#[test]
fn malformed_reply_does_not_discard_another_completed_query() {
    for bad_at in 0..=1 {
        let (mut daemon, mut events, _) = completed_pair();
        let expected = ids(&events)[1 - bad_at];
        let bad = events[bad_at].result.as_mut().unwrap();
        // Keep its authenticated header/question and declared A answer, but
        // remove the record. Transport authentication does not parse RDATA.
        bad.packet
            .truncate(super::super::wire::skip_questions(&bad.packet).unwrap());
        let responses = daemon.finish_upstream_events(events, 100, None);
        assert_eq!(responses.len(), 1);
        assert_eq!(Header::parse(&responses[0].packet).unwrap().id, expected);
        assert_eq!(daemon.poll_failures().invalid_replies, 1);
    }
}

#[test]
fn one_bad_recipient_preserves_its_sibling_and_other_queries() {
    for bad_at in 0..=1 {
        let (mut daemon, mut events, _) = completed_pair();
        let expected = ids(&events);
        let reply = events[0].result.as_mut().unwrap();
        let sibling = &reply.recipients[0];
        let bad = super::super::forward::Recipient {
            client: sibling.client.clone(),
            original_id: 0x7200,
            question_name: Name::from_ascii("wrong.test").unwrap(),
        };
        reply.recipients.insert(bad_at, bad);
        let responses = daemon.finish_upstream_events(events, 100, None);
        assert_eq!(
            responses
                .iter()
                .map(|response| Header::parse(&response.packet).unwrap().id)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(daemon.poll_failures().recipient_errors, 1);
        daemon.reload_hosts(Hosts::new());
        assert_eq!(
            daemon.poll_failures().recipient_errors,
            1,
            "reload must not reset cumulative failure counts"
        );
    }
}
