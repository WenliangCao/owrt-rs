//! Actual ubusd dispatch/send/drain costs on local socket pairs. No poll loop
//! or independent provider is included; this is not a full-daemon benchmark.
//! Fixture cloning and socket draining are included and measured separately.
#![allow(dead_code)]
#[path = "../src/acl.rs"]
mod acl;
#[path = "../src/client.rs"]
mod client;
#[path = "../src/obj.rs"]
mod obj;
#[path = "../src/server.rs"]
mod server;
#[path = "../src/sys.rs"]
mod sys;
#[path = "../../rpcd/examples/profile_support/mod.rs"]
mod profile_support;

use client::{Client, InMsg};
use owrt_ubus::blob::BlobBuf;
use owrt_ubus::msg::{attr, ty, Header};
use std::hint::black_box;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

const CALLER: u32 = 1024;
const OWNER: u32 = 1025;
const TYPE: u32 = 2048;
const OBJECT: u32 = 4096;

fn connection() -> (Client, UnixStream) {
    let (a, b) = UnixStream::pair().unwrap();
    a.set_nonblocking(true).unwrap();
    b.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    let mut c = Client::new(a.into(), sys::Ucred { pid: std::process::id() as i32, uid: 0, gid: 0 },
                            "root".into(), "root".into());
    c.extra_gid = vec![0];
    (c, b)
}

fn fixture(count: usize, methods: usize) -> (server::Server, UnixStream, UnixStream) {
    let mut s = server::Server::new(String::new()).unwrap();
    let (caller, caller_peer) = connection();
    let (owner, owner_peer) = connection();
    s.clients.insert(CALLER, Box::new(caller));
    s.clients.insert(OWNER, Box::new(owner));
    let methods = (0..methods).map(|i| {
        let name = format!("method_{i:04}");
        let mut b = BlobBuf::new();
        let table = b.msg_open_table(&name);
        b.msg_u32("value", 5);
        b.msg_close(table);
        obj::Method::new(b.payload().to_vec())
    }).collect();
    s.reg.types.insert(TYPE, obj::ObjType { refcount: 0, methods });
    for i in 0..count {
        let id = OBJECT + i as u32;
        s.reg.create(Some(TYPE), Some(id)).unwrap();
        assert!(s.reg.set_path(id, &format!("bench.object{i:04}").into_bytes()));
        s.reg.get_mut(id).unwrap().client = Some(OWNER);
    }
    (s, caller_peer, owner_peer)
}

fn input(kind: u8, mut b: BlobBuf) -> InMsg<'static> {
    InMsg { header: Header { ty: kind, seq: 1, peer: 0 }, blob: b.as_bytes().to_vec().into(), fd: None }
}

fn copy(msg: &InMsg) -> InMsg<'static> {
    InMsg { header: msg.header, blob: msg.blob.clone().into_owned().into(), fd: None }
}

fn drain(peer: &mut UnixStream, frames: usize, scratch: &mut Vec<u8>) {
    scratch.clear();
    for _ in 0..frames {
        let offset = scratch.len();
        scratch.resize(offset + 12, 0);
        peer.read_exact(&mut scratch[offset..]).unwrap();
        let len = client::blob_raw_len(&scratch[offset + 8..]);
        assert!(len >= 4);
        scratch.resize(offset + 8 + len, 0);
        peer.read_exact(&mut scratch[offset + 12..]).unwrap();
    }
}

// Force repeated command parking. The regular profile's replies fit in the
// socket buffer and cannot reveal repeated work over the unconsumed suffix.
fn backpressure(n: u64, filter: &str) {
    unsafe extern "C" {
        fn setsockopt(fd: i32, level: i32, name: i32, value: *const i32, len: u32) -> i32;
    }
    for count in [16, 64, 256] {
        let (mut s, mut peer, _provider) = fixture(count, 1);
        peer.set_nonblocking(true).unwrap();
        let size: i32 = 4096;
        // SAFETY: the live Linux socket and i32 value have the declared size;
        // SOL_SOCKET/SO_SNDBUF changes this fixture's socket only.
        assert_eq!(unsafe { setsockopt(s.clients[&CALLER].fd(), 1, 7, &size, 4) }, 0);
        let mut signature = BlobBuf::new();
        let table = signature.msg_open_table("method_0000");
        signature.msg_string("large", &"x".repeat(16384));
        signature.msg_close(table);
        s.reg.types.get_mut(&TYPE).unwrap().methods[0] = obj::Method::new(signature.payload().to_vec());
        for mode in ["all", "prefix"] {
            let mut b = BlobBuf::new();
            if mode == "prefix" {
                b.put_string(attr::OBJPATH, "bench.object*");
            }
            let msg = input(ty::LOOKUP, b);
            let mut bytes = Vec::new();
            let mut parked = 0;
            let mut run = || {
                bytes.clear();
                parked = 0;
                assert!(s.receive(CALLER, copy(&msg)));
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                loop {
                    assert!(std::time::Instant::now() < deadline);
                    let mut buffer = [0; 4096];
                    loop {
                        match peer.read(&mut buffer) {
                            Ok(0) => panic!("unexpected EOF"),
                            Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => panic!("read: {e}"),
                        }
                    }
                    let c = s.clients.get_mut(&CALLER).unwrap();
                    if c.tx_empty() && c.cmd_queue.is_empty() {
                        break;
                    }
                    assert!(c.flush());
                    if c.tx_empty() && !c.cmd_queue.is_empty() {
                        parked += 1;
                        assert!(s.process_cmd_queue(CALLER));
                    }
                    s.touched.clear();
                }
                s.touched.clear();
                assert!(parked >= count - 1, "fixture must repeatedly park");
                black_box(&bytes);
            };
            run();
            profile_support::measure_with_warmup(&format!("backpressure_{mode}_{count}"), n, 3, filter, &mut run);
            // Validate every frame outside timing, including payloads and the
            // terminating status. Object IDs are fixed by fixture().
            let mut rest = bytes.as_slice();
            for i in 0..=count {
                let h = Header::decode(rest[..Header::LEN].try_into().unwrap()).unwrap();
                let len = client::blob_raw_len(&rest[Header::LEN..]);
                assert_eq!((h.seq, h.peer), (1, 0));
                let fields: Vec<_> = owrt_ubus::blob::iter(&rest[Header::LEN + 4..Header::LEN + len]).collect();
                if i == count {
                    assert_eq!(h.ty, ty::STATUS);
                    assert_eq!(fields[0].as_u32(), Some(0));
                } else {
                    assert_eq!(h.ty, ty::DATA);
                    assert_eq!(fields[1].as_u32(), Some(OBJECT + i as u32));
                    assert_eq!(obj::cstr_bytes(fields[0].payload), format!("bench.object{i:04}").as_bytes());
                    assert_eq!(fields[3].payload, signature.payload());
                }
                rest = &rest[Header::LEN + len..];
            }
            assert!(rest.is_empty());
        }
    }
}

fn main() {
    let n = std::env::args().nth(1).unwrap_or_else(|| "5000".into()).parse().unwrap();
    let filter = std::env::args().nth(2).unwrap_or_default();
    println!("stage,iterations,ns_per_op,allocations,reallocations,allocated_bytes");
    if filter == "backpressure" {
        backpressure(n, &filter);
        return;
    }
    for (count, methods) in [(1, 1), (64, 1), (128, 1), (1, 64)] {
        let (mut s, mut peer, _provider) = fixture(count, methods);
        for mode in ["exact", "all", "prefix"] {
            let mut b = BlobBuf::new();
            if mode != "all" {
                b.put_string(attr::OBJPATH, if mode == "exact" { "bench.object0000" } else { "bench.object*" });
            }
            let msg = input(ty::LOOKUP, b);
            let frames = if mode == "exact" { 2 } else { count + 1 };
            let mut bytes = Vec::new();
            assert!(s.receive(CALLER, copy(&msg)));
            assert!(s.clients[&CALLER].tx_empty());
            s.touched.clear();
            drain(&mut peer, frames, &mut bytes);
            let expected = bytes.clone();
            let name = format!("lookup_{mode}_objects_{count}_methods_{methods}");
            profile_support::measure(&name, n, &filter, || {
                assert!(s.receive(CALLER, copy(&msg)));
                // The real event loop consumes these after each dispatch.
                // Retaining them here makes the fixture grow with iteration
                // count and contaminates allocation diagnostics.
                s.touched.clear();
                drain(&mut peer, frames, &mut bytes);
                black_box(&bytes);
            });
            assert_eq!(bytes, expected);
            assert!(s.clients[&CALLER].tx_empty());
        }
    }
    for size in [16, 1024, 16384] {
        let (mut s, _caller_peer, mut peer) = fixture(1, 1);
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, OBJECT);
        b.put_string(attr::METHOD, "method_0000");
        b.put(attr::DATA, &vec![0x5a; size]);
        let msg = input(ty::INVOKE, b);
        let mut bytes = Vec::new();
        assert!(s.receive(CALLER, copy(&msg)));
        s.touched.clear();
        drain(&mut peer, 1, &mut bytes);
        let expected = bytes.clone();
        profile_support::measure(&format!("invoke_forward_{size}"), n, &filter, || {
            assert!(s.receive(CALLER, copy(&msg)));
            s.touched.clear();
            drain(&mut peer, 1, &mut bytes);
            black_box(&bytes);
        });
        assert_eq!(bytes, expected);
        assert!(s.clients[&OWNER].tx_empty());
        profile_support::measure(&format!("fixture_clone_{size}"), n, &filter, || {
            black_box(copy(black_box(&msg)));
        });
        let (mut client, mut peer) = connection();
        let mut rx = [0u8; client::RX_SIZE];
        let mut frame = msg.header.encode().to_vec();
        frame.extend_from_slice(&msg.blob);
        profile_support::measure(&format!("socket_write_receive_{size}"), n, &filter, || {
            peer.write_all(&frame).unwrap();
            client.begin_read(&mut rx);
            // A short read returns one complete frame, then Ok(None) on the
            // next call to end the readiness round. Large frames can also
            // need more than one read. Drive the state machine as the event
            // loop does instead of assuming every call yields a frame.
            let mut waiting_since = None;
            let read = loop {
                if let Some(read) = client.read_message(&mut rx).unwrap() {
                    break read;
                }
                let started = waiting_since.get_or_insert_with(std::time::Instant::now);
                assert!(!client.eof && started.elapsed() < std::time::Duration::from_secs(2));
            };
            assert_eq!(read.blob.len(), msg.blob.len());
            black_box(read);
            assert!(client.read_message(&mut rx).unwrap().is_none());
            client.end_read(&rx);
        });
    }
}
