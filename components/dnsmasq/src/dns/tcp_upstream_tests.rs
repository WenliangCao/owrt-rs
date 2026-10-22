use super::*;
use crate::dns::forward::{Server as ConfiguredServer, ServerId};
use crate::dns::wire::{Name, PacketWriter, Section};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

fn query(id: u16) -> Vec<u8> {
    let mut writer = PacketWriter::new(id, 0x100, 512).unwrap();
    writer
        .question(&Name::from_ascii("tcp.test").unwrap(), 1, 1)
        .unwrap();
    writer.finish()
}

fn read_query(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut prefix = [0; 2];
    stream.read_exact(&mut prefix).unwrap();
    let mut query = vec![0; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut query).unwrap();
    query
}

fn response(query: &[u8], rcode: u16) -> Vec<u8> {
    let header = Header::parse(query).unwrap();
    let question = Question::parse(query).unwrap();
    let mut writer = PacketWriter::new(header.id, 0x8180 | rcode, 512).unwrap();
    writer
        .question(&question.name, question.rrtype, question.class)
        .unwrap();
    if rcode == 0 {
        writer
            .record(Section::Answer, &question.name, 1, 1, 60, &[192, 0, 2, 1])
            .unwrap();
    }
    writer.finish()
}

fn transport(addresses: &[SocketAddr]) -> TcpUpstream {
    TcpUpstream::new(
        [ServerGroup::new(
            GroupId(1),
            addresses
                .iter()
                .enumerate()
                .map(|(i, address)| ConfiguredServer {
                    id: ServerId(i as u64 + 1),
                    address: *address,
                    bound_socket: None,
                })
                .collect(),
            true,
            false,
        )],
        TcpOptions {
            read_timeout: Duration::from_millis(300),
            ..TcpOptions::default()
        },
    )
    .unwrap()
}

#[test]
fn immediate_source_bind_failures_yield_after_real_transport_budget() {
    let addresses: Vec<_> = (10000..10065)
        .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
        .collect();
    let mut upstream = transport(&addresses);
    // A syntactically valid, absent interface fails the real bind path before
    // connect. This exercises 65 kernel-backed attempts without a mock wait
    // or a reachable network endpoint (Darwin rejects interface binding).
    upstream.set_source_bindings(&addresses.iter().enumerate().map(|(index, address)| {
        let mut source = SourceSpec::wildcard(*address, 0);
        source.interface = b"m6b-no-if-64".to_vec();
        (ServerId(index as u64 + 1), source)
    }).collect());
    let deadline = Instant::now() + Duration::from_secs(2);
    let TcpProgress::Pending(wait) = upstream.start(GroupId(1), &query(7), deadline).unwrap()
        else { panic!("64 attempts must yield before the 65th server"); };
    assert_eq!(wait.fd, -1);
    assert_eq!(wait.events, 0);
    assert!(wait.deadline <= Instant::now());
    assert_eq!(upstream.socket_count(), 0);
    assert_eq!(upstream.take_connection_failures().len(), 64);
    assert!(matches!(upstream.step(), Err(TcpError::NoReply)));
    assert_eq!(upstream.take_connection_failures().len(), 1);
    assert_eq!(upstream.socket_count(), 0);
}

#[test]
fn successful_queries_share_connection_and_rcode_does_not_trigger_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut transport = transport(&[listener.local_addr().unwrap()]);
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        for rcode in [0, 2, 5] {
            let query = read_query(&mut stream);
            stream
                .write_all(&encode_tcp_frame(&response(&query, rcode)).unwrap())
                .unwrap();
        }
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
    });
    for (index, rcode) in [0, 2, 5].into_iter().enumerate() {
        let reply = transport
            .exchange(
                GroupId(1),
                &query(index as u16),
                Instant::now() + Duration::from_secs(2),
                &|| false,
            )
            .unwrap();
        assert_eq!(Header::parse(&reply).unwrap().rcode(), rcode);
        assert_eq!(transport.socket_count(), 1);
    }
    transport.clear();
    assert_eq!(transport.socket_count(), 0);
    worker.join().unwrap();
}

#[test]
fn unrepresentable_idle_timeouts_keep_the_finite_exchange_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut transport = transport(&[listener.local_addr().unwrap()]);
    transport.options = TcpOptions {
        connect_timeout: Duration::MAX,
        write_timeout: Duration::MAX,
        read_timeout: Duration::MAX,
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    let progress = transport.start(GroupId(1), &query(7), deadline).unwrap();
    let wait = waiting_for_reply(&mut transport, progress);
    assert_eq!(wait.deadline, deadline);
    let (mut server, _) = listener.accept().unwrap();
    let request = read_query(&mut server);
    let reply = response(&request, 0);
    server
        .write_all(&encode_tcp_frame(&reply).unwrap())
        .unwrap();
    let mut progress = transport.step().unwrap();
    loop {
        match progress {
            TcpProgress::Pending(wait) => {
                assert_eq!(wait.deadline, deadline);
                progress = step_after_poll(&mut transport, wait).unwrap();
            }
            TcpProgress::Complete(packet) => {
                assert_eq!(packet, reply);
                break;
            }
        }
    }
    transport.clear();
    assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
fn old_connection_eof_reconnects_once_and_fresh_eof_advances_server() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let next = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut transport = transport(&[listener.local_addr().unwrap(), next.local_addr().unwrap()]);
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let first = read_query(&mut stream);
        stream
            .write_all(&encode_tcp_frame(&response(&first, 0)).unwrap())
            .unwrap();
        // Finish only after the next query is sent over the retained socket.
        read_query(&mut stream);
        drop(stream);
        let (mut stream, _) = listener.accept().unwrap();
        read_query(&mut stream);
        drop(stream);
        let (mut stream, _) = next.accept().unwrap();
        let query = read_query(&mut stream);
        stream
            .write_all(&encode_tcp_frame(&response(&query, 0)).unwrap())
            .unwrap();
    });
    for id in [1, 2] {
        transport
            .exchange(
                GroupId(1),
                &query(id),
                Instant::now() + Duration::from_secs(2),
                &|| false,
            )
            .unwrap();
    }
    assert_eq!(transport.socket_count(), 1);
    transport.clear();
    worker.join().unwrap();
}

#[test]
fn cancelled_read_releases_every_owned_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut transport = transport(&[listener.local_addr().unwrap()]);
    let stopped = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stopped);
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_query(&mut stream);
        flag.store(true, Ordering::Release);
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
    });
    assert!(matches!(
        transport.exchange(
            GroupId(1),
            &query(1),
            Instant::now() + Duration::from_secs(2),
            &|| stopped.load(Ordering::Acquire)
        ),
        Err(TcpError::Cancelled)
    ));
    assert_eq!(transport.socket_count(), 0);
    worker.join().unwrap();
}

#[test]
fn refused_connect_advances_without_retaining_a_failed_socket() {
    let refused = TcpListener::bind("127.0.0.1:0").unwrap();
    let next = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut transport = transport(&[refused.local_addr().unwrap(), next.local_addr().unwrap()]);
    drop(refused);
    let worker = thread::spawn(move || {
        let (mut stream, _) = next.accept().unwrap();
        let query = read_query(&mut stream);
        stream
            .write_all(&encode_tcp_frame(&response(&query, 0)).unwrap())
            .unwrap();
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
    });
    transport
        .exchange(
            GroupId(1),
            &query(1),
            Instant::now() + Duration::from_secs(2),
            &|| false,
        )
        .unwrap();
    assert_eq!(transport.socket_count(), 1);
    transport.clear();
    assert_eq!(transport.socket_count(), 0);
    worker.join().unwrap();
}

fn step_after_poll(transport: &mut TcpUpstream, wait: TcpWait) -> Result<TcpProgress, TcpError> {
    let mut poll = [PollFd {
        fd: wait.fd,
        events: wait.events,
        revents: 0,
    }];
    let timeout = wait
        .deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(50));
    poll_fds(&mut poll, timeout.as_millis() as i32).unwrap();
    transport.step()
}

fn waiting_for_reply(transport: &mut TcpUpstream, mut progress: TcpProgress) -> TcpWait {
    loop {
        match progress {
            TcpProgress::Pending(wait) if wait.events == dnsmasq_platform::poll::POLLIN => return wait,
            TcpProgress::Pending(wait) => progress = step_after_poll(transport, wait).unwrap(),
            TcpProgress::Complete(_) => panic!("unreplied query completed"),
        }
    }
}

#[test]
fn nonblocking_exchange_yields_for_each_fragment_and_keeps_its_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut transport = transport(&[listener.local_addr().unwrap()]);
    let deadline = Instant::now() + Duration::from_secs(2);
    let began = Instant::now();
    let progress = transport.start(GroupId(1), &query(11), deadline).unwrap();
    assert!(
        began.elapsed() < Duration::from_millis(250),
        "start waited for a reply"
    );
    waiting_for_reply(&mut transport, progress);
    let (mut server, _) = listener.accept().unwrap();
    let received = read_query(&mut server);
    assert_eq!(received, query(11));
    assert!(matches!(
        transport.start(GroupId(1), &query(12), deadline),
        Err(TcpError::Busy)
    ));
    let reply = response(&received, 0);
    let frame = encode_tcp_frame(&reply).unwrap();
    // The owner must retain both partial prefix and body across repeated turns.
    for chunk in [&frame[..1], &frame[1..7], &frame[7..frame.len() - 1]] {
        server.write_all(chunk).unwrap();
        let began = Instant::now();
        let progress = transport.step().unwrap();
        assert!(
            began.elapsed() < Duration::from_millis(250),
            "step waited for a fragment"
        );
        assert!(matches!(progress, TcpProgress::Pending(_)));
    }
    server.write_all(&frame[frame.len() - 1..]).unwrap();
    let mut progress = transport.step().unwrap();
    loop {
        match progress {
            TcpProgress::Pending(wait) => progress = step_after_poll(&mut transport, wait).unwrap(),
            TcpProgress::Complete(packet) => {
                assert_eq!(packet, reply);
                break;
            }
        }
    }
    assert_eq!(transport.socket_count(), 1);
    let progress = transport.start(GroupId(1), &query(12), deadline).unwrap();
    waiting_for_reply(&mut transport, progress);
    assert_eq!(read_query(&mut server), query(12));
    transport.clear();
    assert_eq!(transport.socket_count(), 0);
    assert!(matches!(transport.step(), Err(TcpError::NotStarted)));
    let mut byte = [0];
    assert_eq!(server.read(&mut byte).unwrap(), 0);
}

#[test]
fn absolute_deadline_survives_partial_progress_and_closes_owned_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut transport = transport(&[listener.local_addr().unwrap()]);
    let deadline = Instant::now() + Duration::from_millis(120);
    let progress = transport.start(GroupId(1), &query(1), deadline).unwrap();
    let wait = waiting_for_reply(&mut transport, progress);
    assert_eq!(wait.deadline, deadline);
    let (mut server, _) = listener.accept().unwrap();
    let received = read_query(&mut server);
    let frame = encode_tcp_frame(&response(&received, 0)).unwrap();
    // Each positive read refreshes the idle timeout, but never the enclosing
    // connection deadline. The final incomplete response must be discarded.
    for chunk in [&frame[..1], &frame[1..2], &frame[2..3]] {
        server.write_all(chunk).unwrap();
        thread::sleep(Duration::from_millis(10));
        match transport.step().unwrap() {
            TcpProgress::Pending(wait) => assert_eq!(wait.deadline, deadline),
            TcpProgress::Complete(_) => panic!("incomplete response accepted"),
        }
    }
    thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    assert!(matches!(transport.step(), Err(TcpError::Deadline)));
    assert_eq!(transport.socket_count(), 0);
    let mut byte = [0];
    assert_eq!(server.read(&mut byte).unwrap(), 0);
}

#[test]
fn idle_timeout_advances_server_without_blocking_the_owner() {
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut transport = transport(&[first.local_addr().unwrap(), second.local_addr().unwrap()]);
    transport.options.read_timeout = Duration::from_millis(40);
    let deadline = Instant::now() + Duration::from_secs(2);
    let progress = transport.start(GroupId(1), &query(1), deadline).unwrap();
    let wait = waiting_for_reply(&mut transport, progress);
    let (mut stalled, _) = first.accept().unwrap();
    read_query(&mut stalled);
    thread::sleep(
        wait.deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
    );
    let progress = transport.step().unwrap();
    waiting_for_reply(&mut transport, progress);
    let (mut recovered, _) = second.accept().unwrap();
    let received = read_query(&mut recovered);
    let reply = response(&received, 0);
    recovered
        .write_all(&encode_tcp_frame(&reply).unwrap())
        .unwrap();
    let mut progress = transport.step().unwrap();
    loop {
        match progress {
            TcpProgress::Pending(wait) => progress = step_after_poll(&mut transport, wait).unwrap(),
            TcpProgress::Complete(packet) => {
                assert_eq!(packet, reply);
                break;
            }
        }
    }
    let mut byte = [0];
    assert_eq!(stalled.read(&mut byte).unwrap(), 0);
    assert_eq!(transport.socket_count(), 1);
    transport.clear();
    assert_eq!(recovered.read(&mut byte).unwrap(), 0);
}
