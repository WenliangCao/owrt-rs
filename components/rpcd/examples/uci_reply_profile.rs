//! Actual local-root UCI handlers through complete reply construction.
//! Run inside the exact image namespace. No ubus transport time is measured.
// These profiling adapters deliberately replace daemon state. Production
// unit tests run against the real binary, never against these stubs.
#![cfg(not(test))]
#![allow(dead_code)]

#[path = "../src/delayed.rs"]
mod delayed;
#[path = "../src/glob.rs"]
mod glob;
mod profile_support;
#[path = "../src/reply.rs"]
mod reply;
#[path = "../src/session.rs"]
mod session;
#[path = "../src/uciobj.rs"]
mod uciobj;
#[path = "../src/util.rs"]
#[allow(unused_imports)]
mod util;

use owrt_ubus::{ty, BlobBuf, Connection, Header};
use profile_support::measure;
use std::cell::RefCell;
use std::hint::black_box;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

// These are the actual stores used by the handlers. Only local-root get and
// configs are exercised; neither emits events or launches delayed actions.
pub struct Ctx {
    pub sessions: RefCell<session::Store>,
    pub apply: RefCell<uciobj::Apply>,
    pub delayed: RefCell<delayed::Children>,
    pub uci_read_cache: RefCell<owrt_uci::ReadCache>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n = args
        .get(1)
        .map(|s| s.parse().expect("iterations"))
        .unwrap_or(20000);
    let filter = args.get(2).map(String::as_str).unwrap_or("");
    assert!(n > 0);
    let path = std::env::temp_dir().join(format!("uci-reply-profile-{}", std::process::id()));
    let listener = UnixListener::bind(&path).unwrap();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .write_all(
                &Header {
                    ty: ty::HELLO,
                    seq: 0,
                    peer: 42,
                }
                .encode(),
            )
            .unwrap();
        socket.write_all(&[0, 0, 0, 4]).unwrap();
        let mut byte = [0u8];
        // The measured handlers must not use the supplied Connection.
        assert_eq!(socket.read(&mut byte).unwrap(), 0);
    });
    let mut conn = Connection::connect(path.to_str()).unwrap();
    let ctx = Ctx {
        sessions: RefCell::new(session::Store::new()),
        apply: RefCell::new(uciobj::Apply::default()),
        delayed: RefCell::new(delayed::Children::default()),
        uci_read_cache: RefCell::new(owrt_uci::ReadCache::default()),
    };
    println!("stage,iterations,ns_per_op,allocs,reallocs,requested_bytes");
    for (stage, method, config) in [
        ("uci_configs_payload", "configs", None),
        ("uci_get_network_payload", "get", Some("network")),
        ("uci_get_64_payload", "get", Some("r84fixture")),
    ] {
        let mut args = BlobBuf::new();
        if let Some(config) = config {
            args.msg_string("config", config);
        }
        let fields = args.into_payload();
        let result = uciobj::call(&ctx, &mut conn, method, &fields);
        assert_eq!(result.code, 0);
        assert_eq!(result.data.len(), 1);
        assert!(!result.data[0].is_empty());
        measure(stage, n, filter, || {
            let result = uciobj::call(&ctx, &mut conn, method, &fields);
            assert_eq!(result.code, 0);
            assert_eq!(result.data.len(), 1);
            assert!(!result.data[0].is_empty());
            black_box(result);
        });
    }
    drop(conn);
    peer.join().unwrap();
    std::fs::remove_file(path).unwrap();
}
