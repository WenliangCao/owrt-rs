//! Requested heap and observed allocator calls for real event dispatch.
//! Instrumented diagnostic only; never a timing or full memory measurement.
#![allow(dead_code)]
#[path = "../src/acl.rs"]
mod acl;
#[path = "../src/client.rs"]
mod client;
mod heap_support;
#[path = "../src/obj.rs"]
mod obj;
#[path = "../src/server.rs"]
mod server;
#[path = "../src/sys.rs"]
mod sys;

use owrt_ubus::blob::{self, BlobBuf};
use owrt_ubus::msg::{attr, ty, Header};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

fn connection(queued: bool) -> (client::Client, UnixStream) {
    let (sock, peer) = UnixStream::pair().unwrap();
    sock.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    if queued {
        unsafe extern "C" {
            fn setsockopt(fd: i32, level: i32, name: i32, value: *const i32, len: u32) -> i32;
        }
        let size = 4096i32;
        // SAFETY: Linux SOL_SOCKET/SO_SNDBUF with a live i32 and valid fd.
        assert_eq!(unsafe { setsockopt(sock.as_raw_fd(), 1, 7, &size, 4) }, 0);
    }
    (
        client::Client::new(
            sock.into(),
            sys::Ucred::default(),
            "root".into(),
            "root".into(),
        ),
        peer,
    )
}

fn invoke(s: &mut server::Server, owner: u32, blob: &[u8]) {
    assert!(s.receive(
        owner,
        client::InMsg {
            header: Header {
                ty: ty::INVOKE,
                seq: 100,
                peer: 0
            },
            blob: blob.to_vec().into(),
            fd: None,
        }
    ));
}

fn drain(s: &mut server::Server, owner: u32, peer: &mut UnixStream, out: &mut Vec<u8>) {
    out.clear();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        assert!(std::time::Instant::now() < deadline, "queue did not drain");
        let mut buf = [0; 4096];
        loop {
            match peer.read(&mut buf) {
                Ok(0) => panic!("unexpected EOF"),
                Ok(n) => {
                    assert!(
                        out.len() + n <= out.capacity(),
                        "fixture must not allocate while draining"
                    );
                    out.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("read: {e}"),
            }
        }
        let c = s.clients.get_mut(&owner).unwrap();
        if c.tx_empty() {
            break;
        }
        assert!(c.flush());
    }
    s.touched.clear();
}

fn frame<'a>(bytes: &mut &'a [u8]) -> (Header, &'a [u8]) {
    let h = Header::decode(bytes[..Header::LEN].try_into().unwrap()).unwrap();
    let raw = client::blob_raw_len(&bytes[Header::LEN..]);
    assert!(raw >= 4 && Header::LEN + raw <= bytes.len());
    let b = &bytes[Header::LEN..Header::LEN + raw];
    *bytes = &bytes[Header::LEN + raw..];
    (h, b)
}

fn status(bytes: &[u8]) {
    let mut rest = bytes;
    let (h, b) = frame(&mut rest);
    assert_eq!((h.ty, h.seq, h.peer), (ty::STATUS, 100, 0));
    let (a, _) = blob::attr_at(&b[4..], 0).unwrap();
    assert_eq!((a.id, a.as_u32()), (attr::STATUS, Some(0)));
    assert!(rest.is_empty());
}

fn main() {
    println!("listeners,matched,payload_bytes,warm,retained_requested_bytes,construction_peak_requested_bytes,inflight_requested_bytes,alloc_calls,realloc_calls,queued");
    drop(server::Server::new(String::new()).unwrap());
    for (listeners, matched) in [(0, 0), (1, 0), (1, 1), (8, 1)] {
        for payload_bytes in [16, 32768] {
            for warm in [0, 1] {
                let mut b = BlobBuf::new();
                b.put_u32(attr::OBJID, obj::SYSTEM_OBJECT_EVENT);
                b.put_string(attr::METHOD, "send");
                let d = b.nest_start(attr::DATA);
                b.msg_string("id", "heap.event");
                let data = b.msg_open_table("data");
                b.msg_string("bytes", &"x".repeat(payload_bytes));
                b.msg_close(data);
                b.nest_end(d);
                let request = b.as_bytes().to_vec();
                drop(b);
                let mut expected = BlobBuf::new();
                expected.put_u32(attr::OBJID, 0);
                expected.put_string(attr::METHOD, "heap.event");
                let d = expected.nest_start(attr::DATA);
                expected.msg_string("bytes", &"x".repeat(payload_bytes));
                expected.nest_end(d);
                let mut expected = expected.as_bytes().to_vec();
                let mut replies = Vec::with_capacity(256);
                let mut events = Vec::with_capacity(8 * (32768 + 256));
                let baseline = heap_support::live();
                let mut s = server::Server::new(String::new()).unwrap();
                let (caller, mut caller_peer) = connection(false);
                let (listener, mut listener_peer) = connection(payload_bytes == 32768);
                s.clients.insert(2000, Box::new(caller));
                s.clients.insert(2001, Box::new(listener));
                for i in 0..listeners {
                    let id = 4000 + i;
                    s.reg.create(None, Some(id)).unwrap();
                    s.reg.get_mut(id).unwrap().client = Some(2001);
                    let mut b = BlobBuf::new();
                    b.put_u32(attr::OBJID, obj::SYSTEM_OBJECT_EVENT);
                    b.put_string(attr::METHOD, "register");
                    let d = b.nest_start(attr::DATA);
                    b.msg_u32("object", id);
                    b.msg_string("pattern", if matched == 1 { "heap.*" } else { "other.*" });
                    b.nest_end(d);
                    invoke(&mut s, 2001, b.as_bytes());
                    drain(&mut s, 2001, &mut listener_peer, &mut replies);
                    status(&replies);
                }
                for n in 0..=warm {
                    heap_support::reset_peak();
                    heap_support::reset_calls();
                    invoke(&mut s, 2000, &request);
                    let peak = heap_support::peak() - baseline;
                    let inflight = heap_support::live() - baseline;
                    let (allocs, reallocs) = heap_support::calls();
                    let queued = !s.clients[&2001].tx_empty();
                    if payload_bytes == 32768 && matched == 1 {
                        assert!(queued);
                    }
                    if payload_bytes == 16 {
                        assert!(!queued);
                    }
                    drain(&mut s, 2000, &mut caller_peer, &mut replies);
                    status(&replies);
                    drain(&mut s, 2001, &mut listener_peer, &mut events);
                    let retained = heap_support::live() - baseline;
                    let mut rest = events.as_slice();
                    for i in 0..listeners * matched {
                        let (h, actual) = frame(&mut rest);
                        assert_eq!(
                            (h.ty, h.seq, h.peer),
                            (ty::INVOKE, (n * listeners + i + 1) as u16, 0)
                        );
                        expected[8..12].copy_from_slice(&(4000 + i).to_be_bytes());
                        assert_eq!(actual, expected.as_slice());
                    }
                    assert!(rest.is_empty());
                    if n == warm {
                        println!("{listeners},{matched},{payload_bytes},{warm},{retained},{peak},{inflight},{allocs},{reallocs},{}", u8::from(queued));
                    }
                }
                drop(s);
                drop(caller_peer);
                drop(listener_peer);
                assert_eq!(
                    heap_support::live(),
                    baseline,
                    "event state survived its owners"
                );
            }
        }
    }
}
