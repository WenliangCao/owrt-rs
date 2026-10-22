//! ADD_OBJECT registration with named root credentials and allocation-call diagnostics. Requested Rust
//! heap only, not RSS/PSS, allocator internals, code or kernel buffers.
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

use owrt_ubus::blob::BlobBuf;
use owrt_ubus::msg::{attr, ty, Header};
use std::io::Read;
use std::os::unix::net::UnixStream;

fn main() {
    println!("objects,methods,name_bytes,retained_requested_bytes,construction_peak_requested_bytes,alloc_calls,realloc_calls");
    drop(server::Server::new(String::new()).unwrap());
    for (objects, methods, name_bytes) in [
        (1, 1, 8),
        (1, 16, 8),
        (1, 64, 8),
        (128, 1, 8),
        (128, 1, 32),
        (128, 16, 32),
        (128, 1, 128),
    ] {
        let mut signature = BlobBuf::new();
        for m in 0..methods {
            let mut name = format!("{m:08}");
            name.push_str(&"x".repeat(name_bytes - 8));
            let t = signature.msg_open_table(&name);
            signature.msg_u32("policy", 5);
            signature.msg_close(t);
        }
        let bytes_per_type = signature.payload().len();
        let baseline = heap_support::live();
        heap_support::reset_peak();
        heap_support::reset_calls();
        let mut s = server::Server::new(String::new()).unwrap();
        let (sock, mut peer) = UnixStream::pair().unwrap();
        sock.set_nonblocking(true).unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        s.clients.insert(
            2000,
            Box::new(client::Client::new(
                sock.into(),
                sys::Ucred::default(),
                "root".into(),
                "root".into(),
            )),
        );
        for i in 0..objects {
            let mut b = BlobBuf::new();
            b.put_string(attr::OBJPATH, &format!("object.{i:04}"));
            let t = b.nest_start(attr::SIGNATURE);
            b.put_raw_fields(signature.payload());
            b.nest_end(t);
            let blob = b.as_bytes().to_vec();
            drop(b);
            assert!(s.receive(
                2000,
                client::InMsg {
                    header: Header {
                        ty: ty::ADD_OBJECT,
                        seq: i as u16,
                        peer: 0
                    },
                    blob: blob.into(),
                    fd: None,
                }
            ));
            for expected in [ty::DATA, ty::STATUS] {
                let mut prefix = [0; 12];
                peer.read_exact(&mut prefix).unwrap();
                assert_eq!(prefix[1], expected);
                let raw =
                    (u32::from_be_bytes(prefix[8..].try_into().unwrap()) & 0x00ff_ffff) as usize;
                assert!((4..=256).contains(&raw));
                let mut payload = [0; 256];
                peer.read_exact(&mut payload[..raw - 4]).unwrap();
            }
            assert!(s.clients[&2000].tx_empty());
            s.touched.clear();
        }
        let retained = heap_support::live() - baseline;
        let peak = heap_support::peak() - baseline;
        let (allocs, reallocs) = heap_support::calls();
        assert_eq!(s.reg.paths.len(), objects);
        assert_eq!(s.reg.types.len(), objects);
        for t in s.reg.types.values() {
            assert_eq!(t.refcount, 1);
            assert_eq!(t.methods.len(), methods);
            assert_eq!(
                t.methods
                    .iter()
                    .map(|m| (m.as_bytes().len() + 3) & !3)
                    .sum::<usize>(),
                bytes_per_type
            );
        }
        drop(s);
        drop(peer);
        assert_eq!(
            heap_support::live(),
            baseline,
            "registration state survived all owners"
        );
        println!("{objects},{methods},{name_bytes},{retained},{peak},{allocs},{reallocs}");
    }
}
