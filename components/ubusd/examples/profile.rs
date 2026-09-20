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
    s.clients.insert(CALLER, caller);
    s.clients.insert(OWNER, owner);
    let methods = (0..methods).map(|i| {
        let name = format!("method_{i:04}");
        let mut b = BlobBuf::new();
        let table = b.msg_open_table(&name);
        b.msg_u32("value", 5);
        b.msg_close(table);
        obj::Method { name: name.into_bytes(), blob: b.payload().to_vec() }
    }).collect();
    s.reg.types.insert(TYPE, obj::ObjType { refcount: 0, methods });
    for i in 0..count {
        let id = OBJECT + i as u32;
        s.reg.create(Some(TYPE), Some(id)).unwrap();
        assert!(s.reg.set_path(id, format!("bench.object{i:04}").into_bytes()));
        s.reg.get_mut(id).unwrap().client = Some(OWNER);
    }
    (s, caller_peer, owner_peer)
}

fn input(kind: u8, mut b: BlobBuf) -> InMsg {
    InMsg { header: Header { ty: kind, seq: 1, peer: 0 }, blob: b.as_bytes().to_vec(), fd: None }
}

fn copy(msg: &InMsg) -> InMsg {
    InMsg { header: msg.header, blob: msg.blob.clone(), fd: None }
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

fn main() {
    let n = std::env::args().nth(1).unwrap_or_else(|| "5000".into()).parse().unwrap();
    let filter = std::env::args().nth(2).unwrap_or_default();
    println!("stage,iterations,ns_per_op,allocations,reallocations,allocated_bytes");
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
        let mut frame = msg.header.encode().to_vec();
        frame.extend_from_slice(&msg.blob);
        profile_support::measure(&format!("socket_write_receive_{size}"), n, &filter, || {
            peer.write_all(&frame).unwrap();
            let read = client.read_message().unwrap().unwrap();
            assert_eq!(read.blob.len(), msg.blob.len());
            black_box(read);
        });
    }
}
