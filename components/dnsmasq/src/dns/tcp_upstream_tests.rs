use super::*;
use crate::dns::forward::{Server as ConfiguredServer, ServerId};
use crate::dns::wire::{Name, PacketWriter, Section};
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
