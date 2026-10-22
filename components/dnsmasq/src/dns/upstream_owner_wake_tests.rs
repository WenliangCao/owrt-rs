use super::tests::{client, group, pending_receive, query, response, transport};
use super::*;
use crate::dns::forward::Options;
use crate::dns::wire::{Header, Message, Section};

/// A containing owner registers all interests, waits once, then lets the
/// transport consume ready work with zero additional wait.
fn owner_wait(fds: &mut [PollFd], deadline: Instant) -> usize {
    let left = deadline.saturating_duration_since(Instant::now());
    let millis = left
        .as_millis()
        .saturating_add(u128::from(!left.subsec_nanos().is_multiple_of(1_000_000)));
    poll_once(fds, millis.min(i32::MAX as u128) as i32).unwrap()
}

fn idle_interests(transport: &UpstreamResolver<super::tests::Counter>) {
    let until = Instant::now() + Duration::from_secs(1);
    let mut fds = Vec::new();
    assert_eq!(transport.append_poll_fds(&mut fds, until), None);
    assert!(fds.is_empty());
}

#[test]
fn long_pending_deadline_is_never_reported_as_idle() {
    let (mut transport, _server, id, _) =
        pending_receive(Lifetime::Fixed(Duration::from_secs(120)));
    let now = Instant::now();
    let actual = now + Duration::from_secs(7200);
    transport.transactions.get_mut(&id).unwrap().deadline = actual;
    let mut fds = Vec::new();
    let bounded = now + Duration::from_secs(3600);
    assert_eq!(transport.append_poll_fds(&mut fds, bounded), Some(bounded));
    assert_eq!(fds.len(), 1);
    fds.clear();
    assert_eq!(
        transport.append_poll_fds(&mut fds, now + Duration::from_secs(10800)),
        Some(actual)
    );
    assert_eq!(fds.len(), 1);
}

#[test]
fn queued_real_completion_wakes_owner_after_its_last_socket_is_released() {
    let (mut transport, server, id, token) = pending_receive(Lifetime::ForwardTable);
    let mut request = [0; 2048];
    let (length, peer) = server.recv_from(&mut request).unwrap();
    let reply = response(&request[..length], 0x8180, true);
    server.send_to(&reply, peer).unwrap();

    // Produce the completion with a real readable FD and the real receiver,
    // leaving its terminal event queued as a caller between owner phases can.
    let mut fds = Vec::new();
    let due = transport
        .append_poll_fds(&mut fds, Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(owner_wait(&mut fds, due), 1);
    assert_ne!(fds[0].revents & POLLIN, 0);
    transport.receive_ready(token, fds[0].revents, &|_, _| false);
    assert_eq!(
        (transport.pending_count(), transport.socket_count()),
        (0, 0)
    );

    fds.clear();
    let before = Instant::now();
    let due = transport
        .append_poll_fds(&mut fds, before + Duration::from_secs(1))
        .unwrap();
    assert!(
        fds.is_empty(),
        "a queued completion owns no remaining network FD"
    );
    assert!(
        due <= Instant::now(),
        "the event must not wait for new traffic"
    );
    assert_eq!(owner_wait(&mut fds, due), 0);
    let events = transport.poll(Duration::ZERO).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, id);
    let completed = events[0].result.as_ref().unwrap();
    assert_eq!(completed.packet, reply);
    assert_eq!(completed.recipients.len(), 2);
    assert!(completed
        .recipients
        .iter()
        .all(|row| row.original_id == 0x1234));
    let message = Message::parse(&completed.packet).unwrap();
    assert_eq!(
        message.records(Section::Answer).next().unwrap().rdata,
        [192, 0, 2, 9]
    );
    assert!(transport.poll(Duration::ZERO).unwrap().is_empty());
    idle_interests(&transport);
}

#[test]
fn queued_terminal_error_wakes_without_an_fd_and_is_consumed_only_once() {
    let (mut transport, _server, id, token) = pending_receive(Lifetime::ForwardTable);
    // Inject the unusable-descriptor boundary at the existing transport IO
    // seam; admission, cancellation, event creation and polling stay real.
    transport.receive_ready_with_io(
        token,
        POLLNVAL,
        &|_, _| false,
        Instant::now(),
        |_, _| panic!("an invalid descriptor must not receive"),
        |_| panic!("an invalid descriptor must not inspect SO_ERROR"),
    );
    assert_eq!(
        (transport.pending_count(), transport.socket_count()),
        (0, 0)
    );
    let mut fds = Vec::new();
    let due = transport
        .append_poll_fds(&mut fds, Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert!(fds.is_empty());
    assert!(due <= Instant::now());
    assert_eq!(owner_wait(&mut fds, due), 0);
    let events = transport.poll(Duration::ZERO).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, id);
    assert!(matches!(events[0].result, Err(ResolveError::Io(_))));
    assert_eq!(transport.counters().unanswered, 0);
    assert!(transport.poll(Duration::ZERO).unwrap().is_empty());
    idle_interests(&transport);
}

#[test]
fn fast_retry_deadline_wakes_quiet_owner_and_retransmits_the_same_request() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut transport = transport(
        group(&[server.local_addr().unwrap()], false),
        Options {
            fast_retry_ms: 40,
            fast_retry_timeout_s: 10,
            ..Options::default()
        },
        Duration::from_secs(2),
    );
    let id = transport
        .start_udp(&query(), client(), GroupId(1), Scope::Shared)
        .unwrap()
        .id;
    let mut packet = [0; 2048];
    let (length, peer) = server.recv_from(&mut packet).unwrap();
    let initial = packet[..length].to_vec();
    let mut fds = Vec::new();
    let before = Instant::now();
    let due = transport
        .append_poll_fds(&mut fds, before + Duration::from_secs(1))
        .unwrap();
    assert!(due <= before + Duration::from_millis(45));
    assert_eq!(owner_wait(&mut fds, due), 0, "no upstream reply was sent");
    assert!(transport.poll(Duration::ZERO).unwrap().is_empty());
    let (length, retried_peer) = server.recv_from(&mut packet).unwrap();
    assert_eq!(retried_peer, peer);
    assert_eq!(&packet[..length], initial);
    assert_eq!(transport.counters().queries_forwarded, 2);

    // Once sent, the next retry is future work rather than an immediate loop.
    fds.clear();
    let after = Instant::now();
    assert!(
        transport
            .append_poll_fds(&mut fds, after + Duration::from_secs(1))
            .unwrap()
            > after
    );
    assert_eq!(owner_wait(&mut fds, after), 0);
    server
        .send_to(&response(&initial, 0x8180, true), peer)
        .unwrap();
    fds.clear();
    let due = transport
        .append_poll_fds(&mut fds, Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(owner_wait(&mut fds, due), 1);
    let events = transport.poll(Duration::ZERO).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, id);
    assert_eq!(
        Header::parse(&events[0].result.as_ref().unwrap().packet)
            .unwrap()
            .flags,
        0x8180
    );
    assert_eq!(
        (transport.pending_count(), transport.socket_count()),
        (0, 0)
    );
    idle_interests(&transport);
}

#[test]
fn empty_error_retry_timer_reenables_fd_and_consumes_a_real_queued_datagram() {
    let (mut transport, server, id, token) = pending_receive(Lifetime::ForwardTable);
    let mut request = [0; 2048];
    let (length, peer) = server.recv_from(&mut request).unwrap();
    let reply = response(&request[..length], 0x8180, true);
    let transaction_deadline = transport.transactions[&id].deadline;
    let counters = transport.counters();
    // Only the stale POLLERR/SO_ERROR seam and its timestamp are controlled.
    // A future injected timestamp makes the exclusion interval deterministic
    // even if the test thread is descheduled while preparing its real reply.
    let observed = Instant::now() + Duration::from_millis(100);
    let mut calls = 0;
    for _ in 0..3 {
        transport.receive_ready_with_io(
            token,
            POLLERR,
            &|_, _| false,
            observed,
            |_, _| {
                calls += 1;
                Err(io::ErrorKind::WouldBlock.into())
            },
            |_| Ok(None),
        );
    }
    assert_eq!(
        calls, 2,
        "a repeated empty error must yield to its retry timer"
    );
    assert_eq!(transport.transactions[&id].deadline, transaction_deadline);
    server.send_to(&reply, peer).unwrap();
    let mut fds = Vec::new();
    let due = transport
        .append_poll_fds(&mut fds, Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert!(
        fds.is_empty(),
        "even a real datagram waits while this FD is excluded"
    );
    assert_eq!(due, observed + EMPTY_ERROR_RETRY);
    assert_eq!(owner_wait(&mut fds, due), 0);
    fds.clear();
    let due = transport
        .append_poll_fds(&mut fds, Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        fds.len(),
        1,
        "the timer must restore the suppressed interest"
    );
    assert_eq!(owner_wait(&mut fds, due), 1);
    let events = transport.poll(Duration::ZERO).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, id);
    let completed = events[0].result.as_ref().unwrap();
    assert_eq!(completed.packet, reply);
    assert_eq!(completed.recipients.len(), 2);
    assert_eq!(transport.counters(), counters);
    assert_eq!(
        (transport.pending_count(), transport.socket_count()),
        (0, 0)
    );
    idle_interests(&transport);
}

#[test]
fn owner_retry_send_failure_releases_fds_and_counts_its_fallback_once() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut transport = transport(
        group(&[server.local_addr().unwrap()], false),
        Options {
            fast_retry_ms: 40,
            fast_retry_timeout_s: 10,
            ..Options::default()
        },
        Duration::from_secs(2),
    );
    let id = transport
        .start_udp(&query(), client(), GroupId(1), Scope::Shared)
        .unwrap()
        .id;
    let mut packet = [0; 2048];
    server.recv_from(&mut packet).unwrap();
    // A port-zero destination produces a real synchronous send error. The
    // scheduler still has to wake for the retry without a received datagram.
    transport.dispatcher.group_mut(GroupId(1)).unwrap().servers[0].address =
        "127.0.0.1:0".parse().unwrap();
    let mut fds = Vec::new();
    let before = Instant::now();
    let due = transport
        .append_poll_fds(&mut fds, before + Duration::from_secs(1))
        .unwrap();
    assert!(due <= before + Duration::from_millis(45));
    assert_eq!(owner_wait(&mut fds, due), 0);
    let events = transport.poll(Duration::ZERO).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, id);
    assert!(matches!(events[0].result, Err(ResolveError::Io(_))));
    assert_eq!(transport.counters().background_local_answered, 1);
    assert_eq!(transport.counters().queries_forwarded, 1);
    assert_eq!(transport.counters().unanswered, 0);
    assert_eq!(
        (transport.pending_count(), transport.socket_count()),
        (0, 0)
    );
    assert!(transport.poll(Duration::ZERO).unwrap().is_empty());
    assert_eq!(transport.counters().background_local_answered, 1);
    idle_interests(&transport);
}
