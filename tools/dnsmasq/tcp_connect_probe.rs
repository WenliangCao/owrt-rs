//! Linux isolated SYN-drop probe for cancellation/deadline/fd ownership.
use dnsmasq_rs::dns::forward::{GroupId, Server, ServerGroup, ServerId};
use dnsmasq_rs::dns::tcp_upstream::{TcpError, TcpOptions, TcpUpstream};
use dnsmasq_rs::dns::wire::{Name, PacketWriter};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn main() {
    let server: SocketAddr = std::env::args().nth(1).unwrap().parse().unwrap();
    let mut query = PacketWriter::new(0x1234, 0x100, 512).unwrap();
    query
        .question(&Name::from_ascii("connect.test").unwrap(), 1, 1)
        .unwrap();
    let query = query.finish();
    let before = fds();
    let mut completed = 0;
    for mode in [
        "cancel",
        "cancel",
        "cancel",
        "cancel",
        "cancel",
        "connect-timeout",
        "deadline",
    ] {
        let options = TcpOptions {
            connect_timeout: if mode == "connect-timeout" {
                Duration::from_millis(150)
            } else {
                Duration::from_secs(5)
            },
            ..TcpOptions::default()
        };
        let mut transport = TcpUpstream::new(
            [ServerGroup::new(
                GroupId(1),
                vec![Server {
                    id: ServerId(1),
                    address: server,
                    bound_socket: None,
                }],
                true,
                false,
            )],
            options,
        )
        .unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let producer = if mode == "cancel" {
            let flag = Arc::clone(&stopped);
            Some(std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                flag.store(true, Ordering::Release);
            }))
        } else {
            None
        };
        let start = Instant::now();
        let deadline = start
            + if mode == "deadline" {
                Duration::from_millis(150)
            } else {
                Duration::from_secs(2)
            };
        let result = transport.exchange(GroupId(1), &query, deadline, &|| {
            stopped.load(Ordering::Acquire)
        });
        let elapsed = start.elapsed();
        if let Some(producer) = producer {
            producer.join().unwrap();
        }
        assert!(
            match mode {
                "cancel" => matches!(result, Err(TcpError::Cancelled)),
                "connect-timeout" => matches!(result, Err(TcpError::NoReply)),
                "deadline" => matches!(result, Err(TcpError::Deadline)),
                _ => false,
            },
            "{mode}: {result:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(75) && elapsed < Duration::from_secs(1),
            "{mode}: {elapsed:?}"
        );
        assert_eq!(transport.socket_count(), 0);
        drop(transport);
        assert_eq!(fds(), before);
        completed += 1;
        println!("{mode} {}", elapsed.as_micros());
    }
    println!("CLOSED {completed} {before} {}", fds());
}
