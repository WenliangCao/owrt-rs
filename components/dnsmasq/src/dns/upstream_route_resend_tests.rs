use super::tests::{client, group, query, response, transport, Counter};
use super::*;
use crate::dns::forward::Options;
use crate::dns::wire::{Name, PacketWriter};

fn server() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    socket
}

fn received(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut bytes = [0; 2048];
    let (length, peer) = socket.recv_from(&mut bytes).unwrap();
    (bytes[..length].to_vec(), peer)
}

fn assert_quiet(socket: &UdpSocket) {
    socket.set_nonblocking(true).unwrap();
    let mut bytes = [0; 2048];
    assert_eq!(
        socket.recv_from(&mut bytes).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    socket.set_nonblocking(false).unwrap();
}

fn seed(
    options: Options,
) -> (
    UpstreamResolver<Counter>,
    UdpSocket,
    QueryId,
    Vec<u8>,
    SocketAddr,
) {
    let server = server();
    let mut resolver = transport(
        group(&[server.local_addr().unwrap()], false),
        options,
        Duration::from_secs(2),
    );
    let id = resolver
        .start_udp(&query(), client(), GroupId(1), Scope::Shared)
        .unwrap()
        .id;
    let (wire, peer) = received(&server);
    (resolver, server, id, wire, peer)
}

#[test]
fn route_repeats_exact_successful_wire_on_same_socket_without_forward_side_effects() {
    let (mut resolver, server, id, wire, peer) = seed(Options::default());
    resolver.set_query_logging(crate::config::logging::QueryLogging {
        enabled: true,
        ..Default::default()
    });
    resolver.take_query_events();
    let counters = resolver.counters();
    let pending = resolver.dispatcher.table().get(id).unwrap();
    let before = (
        pending.upstream_id,
        pending.sent_to,
        pending.last_sent_ms,
        pending.retry_delay_ms,
        pending.forward_all,
    );
    let ownership = (
        resolver.pending_count(),
        resolver.socket_count(),
        resolver.sockets[&resolver.saved_udp.unwrap().socket]
            .owners
            .clone(),
    );
    for _ in 0..2 {
        resolver.resend_udp_query();
        assert_eq!(received(&server), (wire.clone(), peer));
        assert_eq!(resolver.counters(), counters);
        let pending = resolver.dispatcher.table().get(id).unwrap();
        assert_eq!(
            (
                pending.upstream_id,
                pending.sent_to,
                pending.last_sent_ms,
                pending.retry_delay_ms,
                pending.forward_all
            ),
            before
        );
        assert_eq!(
            (
                resolver.pending_count(),
                resolver.socket_count(),
                resolver.sockets[&resolver.saved_udp.unwrap().socket]
                    .owners
                    .clone()
            ),
            ownership
        );
        assert!(resolver.take_query_events().is_empty());
        assert!(resolver.events.is_empty());
    }
    assert_quiet(&server);
}

#[test]
fn new_invalid_submission_clears_save_and_reuses_only_one_packet_buffer() {
    let (mut resolver, server, _, _, _) = seed(Options::default());
    let allocation = (
        resolver.saved_udp_packet.as_ptr(),
        resolver.saved_udp_packet.capacity(),
    );
    assert!(resolver
        .start_udp(b"bad", client(), GroupId(1), Scope::Shared)
        .is_err());
    assert!(resolver.saved_udp.is_none());
    assert!(resolver.saved_udp_packet.is_empty());
    assert_eq!(
        (
            resolver.saved_udp_packet.as_ptr(),
            resolver.saved_udp_packet.capacity()
        ),
        allocation
    );
    resolver.resend_udp_query();
    assert_quiet(&server);
    let mut other = PacketWriter::new(7, 0x100, 1232).unwrap();
    other
        .question(&Name::from_ascii("another.test").unwrap(), 1, 1)
        .unwrap();
    resolver
        .start_udp(&other.finish(), client(), GroupId(1), Scope::Shared)
        .unwrap();
    received(&server);
    assert_eq!(
        (
            resolver.saved_udp_packet.as_ptr(),
            resolver.saved_udp_packet.capacity()
        ),
        allocation
    );
}

#[test]
fn newest_of_two_pending_queries_is_the_only_route_resend() {
    let (mut resolver, server, _, _, _) = seed(Options::default());
    let mut other = PacketWriter::new(7, 0x100, 1232).unwrap();
    other
        .question(&Name::from_ascii("another.test").unwrap(), 1, 1)
        .unwrap();
    let second = resolver
        .start_udp(&other.finish(), client(), GroupId(1), Scope::Shared)
        .unwrap()
        .id;
    let (wire, peer) = received(&server);
    assert_eq!(resolver.pending_count(), 2);
    resolver.resend_udp_query();
    assert_eq!(received(&server), (wire, peer));
    assert_quiet(&server);
    resolver.cancel(second);
    assert_eq!(resolver.pending_count(), 1);
    assert!(
        resolver.saved_udp.is_none(),
        "save cannot fall back to an older pending query"
    );
    resolver.resend_udp_query();
    assert_quiet(&server);
}

#[test]
fn all_servers_route_resends_only_last_successful_destination() {
    let first = server();
    let second = server();
    let mut resolver = transport(
        group(
            &[first.local_addr().unwrap(), second.local_addr().unwrap()],
            true,
        ),
        Options::default(),
        Duration::from_secs(2),
    );
    resolver
        .start_udp(&query(), client(), GroupId(1), Scope::Shared)
        .unwrap();
    received(&first);
    let expected = received(&second);
    assert_eq!(resolver.saved_udp.unwrap().server, ServerId(2));
    let counters = resolver.counters();
    resolver.resend_udp_query();
    assert_eq!(received(&second), expected);
    assert_quiet(&first);
    assert_quiet(&second);
    assert_eq!(resolver.counters(), counters);
}

#[test]
fn route_does_not_pin_socket_or_send_on_a_new_descriptor_after_cancel() {
    let (mut resolver, server, id, _, _) = seed(Options::default());
    resolver.cancel(id);
    assert_eq!((resolver.pending_count(), resolver.socket_count()), (0, 0));
    assert!(resolver.saved_udp.is_none());
    let _possibly_reused_fd = UdpSocket::bind("127.0.0.1:0").unwrap();
    resolver.resend_udp_query();
    assert_quiet(&server);
    resolver.clear();
    assert!(resolver.saved_udp_packet.is_empty());
}

#[test]
fn unmatched_real_reply_clears_save_but_empty_receive_probe_preserves_it() {
    let (mut resolver, server, id, wire, peer) = seed(Options::default());
    assert!(resolver.poll(Duration::ZERO).unwrap().is_empty());
    resolver.resend_udp_query();
    assert_eq!(received(&server), (wire.clone(), peer));
    let mut bad_reply = response(&wire, 0x8180, true);
    bad_reply[..2].copy_from_slice(&[0xff, 0xff]);
    server.send_to(&bad_reply, peer).unwrap();
    assert!(resolver.poll(Duration::from_secs(1)).unwrap().is_empty());
    assert_eq!(resolver.pending_count(), 1);
    assert!(resolver.saved_udp.is_none());
    assert!(resolver.dispatcher.table().get(id).is_some());
    resolver.resend_udp_query();
    assert_quiet(&server);
}

#[test]
fn real_servfail_retry_saves_new_send_and_batch_tail_does_not_erase_it() {
    let first = server();
    let second = server();
    let mut resolver = transport(
        group(
            &[first.local_addr().unwrap(), second.local_addr().unwrap()],
            false,
        ),
        Options::default(),
        Duration::from_secs(2),
    );
    resolver
        .start_udp(&query(), client(), GroupId(1), Scope::Shared)
        .unwrap();
    let (wire, peer) = received(&first);
    first
        .send_to(&response(&wire, 0x8182, false), peer)
        .unwrap();
    assert!(resolver.poll(Duration::from_secs(1)).unwrap().is_empty());
    let expected = received(&second);
    assert_eq!(resolver.saved_udp.unwrap().server, ServerId(2));
    let counters = resolver.counters();
    resolver.resend_udp_query();
    assert_eq!(received(&second), expected);
    assert_quiet(&first);
    assert_eq!(resolver.counters(), counters);
}

#[test]
fn real_fast_retry_success_replaces_save_and_failure_does_not_restore_old_save() {
    let (mut resolver, server, id, wire, peer) = seed(Options {
        fast_retry_ms: 40,
        ..Options::default()
    });
    resolver.run_timers_at(Instant::now(), unix_seconds(), 100);
    assert_eq!(received(&server), (wire.clone(), peer));
    assert!(resolver.saved_udp.is_some());
    resolver.resend_udp_query();
    assert_eq!(received(&server), (wire, peer));
    resolver.dispatcher.group_mut(GroupId(1)).unwrap().servers[0].address =
        "127.0.0.1:0".parse().unwrap();
    resolver.run_timers_at(Instant::now(), unix_seconds(), 1000);
    assert!(resolver.saved_udp.is_none());
    assert!(resolver.dispatcher.table().get(id).is_none());
    assert_eq!(resolver.socket_count(), 0);
    resolver.resend_udp_query();
    assert_quiet(&server);
}

#[test]
fn actual_server_retirement_clears_save_but_routing_exclusion_does_not() {
    let (mut resolver, server, _, wire, peer) = seed(Options::default());
    resolver.replace_server_groups(Vec::new(), &[]);
    assert_eq!(resolver.pending_count(), 1);
    resolver.resend_udp_query();
    assert_eq!(received(&server), (wire, peer));
    resolver.replace_server_groups(Vec::new(), &[ServerId(1)]);
    assert!(resolver.saved_udp.is_none());
    assert_eq!(resolver.socket_count(), 0);
    resolver.resend_udp_query();
    assert_quiet(&server);
}

#[test]
fn real_loop_probe_generation_invalidates_saved_udp_without_new_forward_action() {
    let (mut resolver, server, _, _, _) = seed(Options::default());
    let counters = resolver.counters();
    resolver.loop_probe_batch(Vec::new(), false);
    assert!(
        resolver.saved_udp.is_some(),
        "no generated packet means no scratch overwrite"
    );
    let address = server.local_addr().unwrap();
    let endpoint =
        crate::config::dns::parse_endpoint(format!("127.0.0.1#{}", address.port()).as_bytes())
            .unwrap();
    resolver.loop_probe_batch(
        vec![super::super::loop_detect::LoopProbe {
            server: ServerId(1),
            address,
            endpoint,
            packet: [0; 31],
        }],
        false,
    );
    assert_eq!(received(&server).0, vec![0; 31]);
    assert!(resolver.saved_udp.is_none());
    assert_eq!(resolver.counters(), counters);
    resolver.resend_udp_query();
    assert_quiet(&server);
}

#[test]
fn route_send_uses_existing_bounded_retry_without_log_or_failure_accounting() {
    let (mut resolver, server, _, wire, peer) = seed(Options::default());
    let counters = resolver.counters();
    let mut attempts = 0;
    let mut waits = 0;
    resolver.resend_udp_query_with_io(
        |socket, packet, destination| {
            attempts += 1;
            if attempts <= 2 {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                socket.send_to(packet, destination)
            }
        },
        || {
            waits += 1;
            Ok(())
        },
    );
    assert_eq!((attempts, waits), (3, 2));
    assert_eq!(received(&server), (wire.clone(), peer));
    attempts = 0;
    waits = 0;
    resolver.resend_udp_query_with_io(
        |_, _, _| {
            attempts += 1;
            Err(io::ErrorKind::WouldBlock.into())
        },
        || {
            waits += 1;
            Ok(())
        },
    );
    assert_eq!((attempts, waits), (1001, 1001));
    assert_eq!(resolver.counters(), counters);
    assert!(resolver.events.is_empty());
    assert!(
        resolver.saved_udp.is_some(),
        "C resend does not clear the successful original on send error"
    );
    resolver.resend_udp_query();
    assert_eq!(received(&server), (wire, peer));
}
