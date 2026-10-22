use super::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

struct Counter(u32);
impl Random for Counter {
    fn next_u32(&mut self) -> io::Result<u32> {
        self.0 += 1;
        Ok(self.0)
    }
}
fn query(name: &str, id: u16) -> Vec<u8> {
    let mut packet = vec![0; 12];
    Header {
        id,
        flags: 0x100,
        questions: 1,
        ..Header::default()
    }
    .write(&mut packet)
    .unwrap();
    packet.extend_from_slice(Name::from_ascii(name).unwrap().as_wire());
    packet.extend_from_slice(&[0, 1, 0, 1]);
    packet
}
fn client(port: u16) -> Client {
    Client {
        source: SocketAddr::from(([192, 0, 2, 1], port)),
        destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        interface: 2,
        listener: Some(SocketToken(1)),
        reply_requested: true,
        udp_limit: 512,
        log_id: 1,
    }
}
fn group() -> ServerGroup {
    ServerGroup::new(
        GroupId(1),
        (0..3)
            .map(|i| Server {
                id: ServerId(i),
                address: SocketAddr::from(([192, 0, 2, 10 + i as u8], 53)),
                bound_socket: None,
            })
            .collect(),
        false,
        false,
    )
}
fn submit(
    table: &mut ForwardTable,
    name: &str,
    id: u16,
    port: u16,
    now: i64,
    rng: &mut Counter,
) -> Submission {
    table
        .submit(
            &query(name, id),
            client(port),
            GroupId(1),
            Flags::default(),
            Scope::Shared,
            now,
            rng,
        )
        .unwrap()
}

#[test]
fn case_changes_cannot_rewrite_compression_offsets_aliased_by_label_data() {
    let mut packet = query("", 0x1234);
    packet.resize(66, 0);
    // The first label contains another pointer: its low byte is also 'A'.
    // The encoded question then follows that pointer to the root at byte 65.
    packet[12..22].copy_from_slice(&[3, 0xc0, b'A', b'B', 0xc0, 13, 0, 1, 0, 1]);
    let upstream = Question::parse(&packet).unwrap().name;
    assert_eq!(upstream.as_wire(), &[3, 0xc0, b'A', b'B', 0]);
    let original = packet.clone();
    assert_eq!(
        flip_question_case(&mut packet, &[1]),
        Err(WireError::InvalidName)
    );
    assert_eq!(packet, original, "a rejected case change must be atomic");

    let recipient = Recipient {
        client: client(1000),
        original_id: 0x5678,
        question_name: Name::from_dotted_bytes(&[0xc0, b'a', b'B']).unwrap(),
    };
    assert_eq!(
        recipient.restore_question(&mut packet, &upstream),
        Err(WireError::InvalidName)
    );
    assert_eq!(packet, original);

    // Unchanged offset bytes remain compatible, even in this unusual layout.
    flip_question_case(&mut packet, &[2]).unwrap();
    assert_eq!(
        Question::parse(&packet).unwrap().name.as_wire(),
        &[3, 0xc0, b'A', b'b', 0]
    );
    assert_eq!(packet[14], 65);
}

#[test]
fn case_changes_preserve_valid_backward_compression() {
    let mut packet = query("", 0x0441);
    packet.truncate(12);
    packet.extend_from_slice(&[0xc0, 0, 0, 1, 0, 1]);
    // This legal binary name ends in the zero answer count in the header.
    let original = Question::parse(&packet).unwrap().name;
    assert_eq!(original.as_wire(), &[4, b'A', 1, 0, 0, 1, 0, 0]);
    flip_question_case(&mut packet, &[1]).unwrap();
    assert_eq!(
        Question::parse(&packet).unwrap().name.as_wire(),
        &[4, b'a', 1, 0, 0, 1, 0, 0]
    );
    flip_question_case(&mut packet, &[1]).unwrap();
    assert_eq!(Question::parse(&packet).unwrap().name, original);
}

#[test]
fn refresh_and_ordinary_recipients_keep_independent_delivery_flags() {
    let mut table = ForwardTable::new(Options::default());
    let mut rng = Counter(0);
    let mut refresh = client(1000);
    refresh.listener = None;
    refresh.reply_requested = false;
    let first = table
        .submit(
            &query("mixed.test", 12),
            refresh,
            GroupId(1),
            Flags::default(),
            Scope::Shared,
            100,
            &mut rng,
        )
        .unwrap();
    table.note_sent(first.id, ServerId(0), SocketToken(30), 100_000);
    assert_eq!(
        submit(&mut table, "mixed.test", 13, 1001, 100, &mut rng).kind,
        SubmissionKind::Coalesced
    );
    assert_eq!(
        submit(&mut table, "mixed.test", 12, 1000, 101, &mut rng).kind,
        SubmissionKind::ClientRetry
    );
    let recipients = &table.get(first.id).unwrap().recipients;
    assert_eq!(recipients.len(), 2);
    assert!(!recipients[0].client.reply_requested);
    assert_eq!(recipients[0].client.listener, None);
    assert!(recipients[1].client.reply_requested);
}

#[test]
fn unanswered_counts_reclamation_but_not_duplicate_expiry_or_cancellation() {
    let mut table = ForwardTable::new(Options {
        forward_max: 1,
        ..Options::default()
    });
    let mut rng = Counter(0);
    let first = submit(&mut table, "a.test", 1, 1000, 100, &mut rng);
    table.note_sent(first.id, ServerId(0), SocketToken(1), 100_000);
    submit(&mut table, "a.test", 2, 1001, 100, &mut rng);
    assert!(matches!(
        table.submit(
            &query("a.test", 3),
            client(1002),
            GroupId(1),
            Flags::default(),
            Scope::Shared,
            110,
            &mut rng
        ),
        Err(SubmitError::DuplicateFull)
    ));
    assert_eq!(table.counters().unanswered, 0);

    let second = submit(&mut table, "b.test", 4, 1000, 110, &mut rng);
    table.note_sent(second.id, ServerId(0), SocketToken(2), 110_000);
    let third = submit(&mut table, "c.test", 5, 1000, 120, &mut rng);
    assert_eq!(table.counters().unanswered, 1); // conditional ten-second slot reuse
    table.note_sent(third.id, ServerId(0), SocketToken(3), 120_000);
    table.server_gone(ServerId(0));
    assert_eq!(table.counters().unanswered, 1);
    let fourth = submit(&mut table, "d.test", 6, 1000, 130, &mut rng);
    table.note_sent(fourth.id, ServerId(0), SocketToken(4), 130_000);
    table.counters.unanswered = u32::MAX;
    let fifth = submit(&mut table, "e.test", 7, 1000, 170, &mut rng);
    assert_eq!(table.counters().unanswered, 0); // C unsigned-width absolute reclamation
    table.cancel(fifth.id);
    table.counters.queries_forwarded = u32::MAX;
    table.note_forwarded_action();
    assert_eq!(table.counters().queries_forwarded, 0);
    table.counters.background_local_answered = u32::MAX;
    table.note_background_local_answer();
    assert_eq!(table.counters().background_local_answered, 0);
}

#[test]
fn duplicate_and_retry_preserve_client_identity_case_and_limits() {
    let mut table = ForwardTable::new(Options {
        forward_max: 2,
        ..Options::default()
    });
    let mut rng = Counter(0);
    let first = submit(&mut table, "MiXeD.example", 12, 1000, 100, &mut rng);
    table.note_sent(first.id, ServerId(0), SocketToken(30), 100_000);
    assert_eq!(
        submit(&mut table, "mixed.EXAMPLE", 12, 1000, 100, &mut rng).kind,
        SubmissionKind::ClientRetry
    );
    assert_eq!(
        submit(&mut table, "mIxEd.example", 13, 1001, 101, &mut rng).kind,
        SubmissionKind::Coalesced
    );
    assert_eq!(
        submit(&mut table, "MIXED.EXAMPLE", 14, 1002, 102, &mut rng).kind,
        SubmissionKind::LateDuplicate
    );
    let pending = table.get(first.id).unwrap();
    assert_eq!(
        pending
            .recipients
            .iter()
            .map(|r| r.original_id)
            .collect::<Vec<_>>(),
        [12, 14, 13]
    );
    assert_eq!(
        pending.recipients[0].question_name,
        Name::from_ascii("MiXeD.example").unwrap()
    );
    assert!(matches!(
        table.submit(
            &query("mixed.example", 15),
            client(1003),
            GroupId(1),
            Flags::default(),
            Scope::Shared,
            103,
            &mut rng
        ),
        Err(SubmitError::DuplicateFull)
    ));
    assert!(table.get(first.id).is_some());
    assert!(matches!(
        table.submit(
            &query("mixed.example", 15),
            client(1003),
            GroupId(1),
            Flags::default(),
            Scope::Shared,
            110,
            &mut rng
        ),
        Err(SubmitError::DuplicateFull)
    ));
    assert!(table.is_empty());
    assert_eq!(table.take_released()[0].sockets, [SocketToken(30)]);
}

#[test]
fn flags_scope_and_server_group_capacity_are_explicit() {
    let mut table = ForwardTable::new(Options {
        forward_max: 2,
        ..Options::default()
    });
    let mut rng = Counter(0);
    submit(&mut table, "a", 1, 1, 100, &mut rng);
    let flags = Flags {
        no_cache: true,
        ..Flags::default()
    };
    let second = table
        .submit(
            &query("a", 2),
            client(2),
            GroupId(1),
            flags,
            Scope::Shared,
            100,
            &mut rng,
        )
        .unwrap();
    assert_eq!(second.kind, SubmissionKind::New);
    assert_eq!(
        table
            .submit(
                &query("a", 3),
                client(3),
                GroupId(1),
                flags,
                Scope::Shared,
                100,
                &mut rng
            )
            .unwrap()
            .kind,
        SubmissionKind::Coalesced
    );
    assert!(matches!(
        table.submit(
            &query("b", 4),
            client(4),
            GroupId(1),
            flags,
            Scope::Shared,
            100,
            &mut rng
        ),
        Err(SubmitError::GroupFull)
    ));
    assert_eq!(
        table
            .submit(
                &query("b", 4),
                client(4),
                GroupId(2),
                flags,
                Scope::Shared,
                100,
                &mut rng
            )
            .unwrap()
            .kind,
        SubmissionKind::New
    );
    assert!(matches!(
        table.submit(
            &query("a", 5),
            client(5),
            GroupId(1),
            flags,
            Scope::Client(client(5).source),
            100,
            &mut rng
        ),
        Err(SubmitError::GroupFull)
    ));
}

#[test]
fn ordinary_and_case_randomized_reply_matching_checks_socket_group_and_peer() {
    let mut table = ForwardTable::new(Options {
        case_randomization: true,
        ..Options::default()
    });
    let mut rng = Counter(40);
    let id = submit(&mut table, "abcdef.example", 1, 1, 100, &mut rng).id;
    let group = group();
    let mut response = table.get(id).unwrap().packet.clone();
    response[2] |= 0x80;
    assert!(table
        .accept_reply(
            &response,
            group.servers[0].address,
            SocketToken(3),
            &group,
            100
        )
        .is_none());
    table.note_sent(id, ServerId(0), SocketToken(3), 100_000);
    assert_eq!(
        table.accept_reply(
            &response,
            group.servers[0].address,
            SocketToken(3),
            &group,
            100
        ),
        Some((id, ServerId(0)))
    );
    assert!(table
        .accept_reply(&response, client(53).source, SocketToken(3), &group, 100)
        .is_none());
    assert!(table
        .accept_reply(
            &response,
            group.servers[0].address,
            SocketToken(4),
            &group,
            100
        )
        .is_none());
    response[13] ^= 0x20;
    assert!(table
        .accept_reply(
            &response,
            group.servers[0].address,
            SocketToken(3),
            &group,
            100
        )
        .is_none());
    response[13] ^= 0x20;
    assert!(table
        .accept_reply(
            &response,
            group.servers[0].address,
            SocketToken(3),
            &group,
            140
        )
        .is_none());
}

#[test]
fn case_restore_handles_compressed_question_and_more_than_32_letters() {
    let original = "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuV.example";
    let mut packet = query(original, 7);
    let before = packet.clone();
    flip_question_case(&mut packet, &[u32::MAX, u32::MAX]).unwrap();
    assert_ne!(
        Question::parse(&packet).unwrap().name,
        Name::from_ascii(original).unwrap()
    );
    let recipient = Recipient {
        client: client(1),
        original_id: 7,
        question_name: Name::from_ascii(original).unwrap(),
    };
    let upstream = Question::parse(&packet).unwrap().name;
    recipient.restore_question(&mut packet, &upstream).unwrap();
    assert_eq!(packet, before);
    let mut compressed = vec![0; 12];
    Header {
        id: 3,
        flags: 0x8180,
        questions: 1,
        ..Header::default()
    }
    .write(&mut compressed)
    .unwrap();
    compressed.extend_from_slice(&[0xc0, 18, 0, 1, 0, 1]);
    compressed.extend_from_slice(
        Name::from_ascii(&original.to_ascii_uppercase())
            .unwrap()
            .as_wire(),
    );
    let upstream = Question::parse(&compressed).unwrap().name;
    recipient
        .restore_question(&mut compressed, &upstream)
        .unwrap();
    assert_eq!(
        Question::parse(&compressed).unwrap().name,
        recipient.question_name
    );
    let mut bad = vec![0; 12];
    bad.extend_from_slice(&[0xc0, 12]);
    let before = bad.clone();
    assert_eq!(
        flip_question_case(&mut bad, &[1]),
        Err(WireError::PointerLoop)
    );
    assert_eq!(bad, before);
}

#[test]
fn strict_order_and_error_vs_client_retries_differ_at_last_server() {
    let mut table = ForwardTable::new(Options::default());
    let mut rng = Counter(0);
    let id = submit(&mut table, "a", 1, 1, 100, &mut rng).id;
    let mut group = group();
    group.strict_order = true;
    assert_eq!(
        table
            .plan(id, &mut group, SendReason::New, 100)
            .unwrap()
            .candidates,
        [ServerId(0), ServerId(1), ServerId(2)]
    );
    table.note_sent(id, ServerId(2), SocketToken(1), 100_000);
    assert_eq!(
        table
            .plan(id, &mut group, SendReason::ClientRetry, 101)
            .unwrap()
            .candidates,
        [ServerId(2)]
    );
    assert!(
        table
            .plan(id, &mut group, SendReason::UpstreamError, 101)
            .unwrap()
            .exhausted
    );
    assert!(table.get(id).is_some());
    assert_eq!(
        table
            .plan(id, &mut group, SendReason::FastRetry, 101)
            .unwrap()
            .candidates,
        [ServerId(2)]
    );
}

#[test]
fn all_server_refused_waits_but_servfail_is_delivered() {
    let mut table = ForwardTable::new(Options::default());
    let mut rng = Counter(0);
    let id = submit(&mut table, "a", 1, 1, 100, &mut rng).id;
    let mut group = group();
    assert!(
        table
            .plan(id, &mut group, SendReason::New, 100)
            .unwrap()
            .send_all
    );
    for server in 0..3 {
        table.note_sent(id, ServerId(server), SocketToken(server), 100_000);
    }
    assert_eq!(table.get(id).unwrap().forward_all, 4);
    assert_eq!(table.on_reply(id, ServerId(0), 5), Some(ReplyAction::Wait));
    assert_eq!(
        table.on_reply(id, ServerId(1), 2),
        Some(ReplyAction::Deliver)
    );
    assert_eq!(table.take_released()[0].sockets.len(), 3);
    table.finish(id);
    assert!(table.is_empty());
    assert!(table.take_released()[0].sockets.is_empty());
}

#[test]
fn free_slots_precede_timeout_reuse_and_absolute_expiry() {
    let mut table = ForwardTable::new(Options {
        forward_max: 2,
        ..Options::default()
    });
    let mut rng = Counter(0);
    let a = submit(&mut table, "a", 1, 1, 100, &mut rng).id;
    let b = submit(&mut table, "b", 2, 2, 100, &mut rng).id;
    table.finish(b);
    let c = submit(&mut table, "c", 3, 3, 110, &mut rng).id;
    assert!(table.get(a).is_some());
    let _d = submit(&mut table, "d", 4, 4, 110, &mut rng).id;
    assert!(table.get(a).is_none());
    assert!(table.get(c).is_some());
    let _ = submit(&mut table, "e", 5, 5, 150, &mut rng);
    assert!(table.get(c).is_none());
}

#[test]
fn retry_schedule_keeps_slot_order_after_holes_and_reuse() {
    let mut table = ForwardTable::new(Options {
        fast_retry_ms: 100,
        ..Options::default()
    });
    let mut rng = Counter(0);
    let a = submit(&mut table, "a", 1, 1, 100, &mut rng).id;
    let b = submit(&mut table, "b", 2, 2, 100, &mut rng).id;
    let c = submit(&mut table, "c", 3, 3, 100, &mut rng).id;
    table.finish(b);
    let reused = submit(&mut table, "reused", 4, 4, 100, &mut rng).id;
    let _unsent = submit(&mut table, "unsent", 5, 5, 100, &mut rng).id;
    let waiting = submit(&mut table, "waiting", 6, 6, 100, &mut rng).id;
    for id in [a, c, reused] {
        table.note_sent(id, ServerId(1), SocketToken(1), 100_000);
    }
    table.note_sent(waiting, ServerId(1), SocketToken(1), 100_050);
    let due = table.fast_retries(100, 100_100);
    assert_eq!(due.due, [c, reused, a]);
    assert_eq!(due.next_ms, Some(50));
    table.finish(c);
    let due = table.fast_retries(100, 100_100);
    assert_eq!(due.due, [reused, a]);
    assert_eq!(due.next_ms, Some(50));
}

#[test]
fn retry_schedule_wraps_milliseconds_and_doubles_only_after_attempt() {
    let mut table = ForwardTable::new(Options {
        fast_retry_ms: 100,
        fast_retry_timeout_s: 5,
        ..Options::default()
    });
    let mut rng = Counter(0);
    let id = submit(&mut table, "a", 1, 1, 100, &mut rng).id;
    table.note_sent(id, ServerId(1), SocketToken(1), u32::MAX - 49);
    assert_eq!(table.fast_retries(100, 49).next_ms, Some(1));
    assert_eq!(table.fast_retries(100, 50).due, [id]);
    table.note_sent(id, ServerId(1), SocketToken(1), 50);
    table.retry_finished(id);
    assert_eq!(table.fast_retries(100, 50).next_ms, Some(200));
    assert!(table.fast_retries(105, 250).due.is_empty());
    assert_eq!(table.fast_retries(105, 250).next_ms, None);
}

#[test]
fn ipv6_flowinfo_is_not_part_of_endpoint_but_scope_is() {
    let a = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 1, 2));
    let b = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 7, 2));
    let c = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 1, 3));
    assert!(same_endpoint(a, b));
    assert!(!same_endpoint(a, c));
}

#[test]
fn disabled_encoding_preserves_upstream_case_changes_for_each_recipient() {
    let upstream = Name::from_ascii("first.example").unwrap();
    for (client_name, expected) in [
        ("first.example", "First.example"),
        ("FIRST.example", "fIRST.example"),
    ] {
        let recipient = Recipient {
            client: client(1),
            original_id: 7,
            question_name: Name::from_ascii(client_name).unwrap(),
        };
        let mut packet = query("First.example", 42);
        recipient.restore_question(&mut packet, &upstream).unwrap();
        assert_eq!(Header::parse(&packet).unwrap().id, 7);
        assert_eq!(
            Question::parse(&packet).unwrap().name,
            Name::from_ascii(expected).unwrap()
        );
    }
}
