//! Profile real session handlers, file helpers and diagnostic ubus sends.
//! Usage: rpc_profile [iterations] [stage filter]
// These profiling adapters deliberately replace daemon state. Production
// unit tests run against the real binary, never against these stubs.
#![cfg(not(test))]
#![allow(dead_code)]

#[path = "../src/glob.rs"]
mod glob;
mod profile_support;
#[path = "../src/reply.rs"]
mod reply;
#[path = "../src/session.rs"]
mod session;
#[path = "../src/util.rs"]
#[allow(unused_imports)] // only the identity helpers are measured here
mod util;

// The measured handlers never destroy sessions or touch UCI deltas. Fail if a
// future profiling path reaches the unlinked destruction callback.
mod uciobj {
    pub fn purge_dir(_: &str) {
        panic!("session destruction is outside this profiler's scope");
    }
}

use owrt_ubus::BlobBuf;
use profile_support::measure;
use std::hint::black_box;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

fn wire(n: u64, filter: &str) {
    let path = std::env::temp_dir().join(format!("rpc-profile-wire-{}", std::process::id()));
    let listener = UnixListener::bind(&path).unwrap();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let hello = owrt_ubus::Header {
            ty: owrt_ubus::ty::HELLO,
            seq: 0,
            peer: 42,
        };
        socket.write_all(&hello.encode()).unwrap();
        socket.write_all(&[0, 0, 0, 4]).unwrap();
        // Fixed storage keeps the diagnostic peer out of allocation counts.
        let mut head = [0u8; 12];
        let mut body = [0u8; 4096];
        while socket.read_exact(&mut head).is_ok() {
            let raw = (u32::from_be_bytes(head[8..12].try_into().unwrap()) & 0x00ff_ffff) as usize;
            assert!(raw >= 4);
            let mut remaining = raw - 4;
            while remaining != 0 {
                let count = remaining.min(body.len());
                socket.read_exact(&mut body[..count]).unwrap();
                remaining -= count;
            }
        }
    });
    let mut conn = owrt_ubus::Connection::connect(path.to_str()).unwrap();
    let request = owrt_ubus::Request {
        peer: 1729,
        seq: 11,
        objid: 9,
        method: "profile".into(),
        user: None,
        group: None,
        data: vec![],
        fd: None,
        no_reply: false,
    };
    let mut b = BlobBuf::new();
    b.msg_string("result", "fixed profile response");
    let fields = b.into_payload();
    measure("reply_status_send", n, filter, || {
        conn.reply_status(&request, 0, None).unwrap();
    });
    measure("reply_data_send", n, filter, || {
        conn.reply_data(&request, &fields).unwrap();
    });
    measure("reply_pair_send", n, filter, || {
        conn.reply_data_status(&request, &fields, 0).unwrap();
    });
    drop(conn);
    peer.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

fn access_args(sid: &str, object: &str, function: &str) -> Vec<u8> {
    let mut b = BlobBuf::new();
    b.msg_string("ubus_rpc_session", sid);
    b.msg_string("scope", "ubus");
    b.msg_string("object", object);
    b.msg_string("function", function);
    b.into_payload()
}

fn incoming(n: u64, filter: &str) {
    if !"incoming_request_roundtrip".contains(filter) {
        return;
    }
    let path = std::env::temp_dir().join(format!("rpc-profile-incoming-{}", std::process::id()));
    let listener = UnixListener::bind(&path).unwrap();
    let fields = access_args("00000000000000000000000000000000", "uci", "get");
    let mut request = BlobBuf::new();
    request
        .put_u32(owrt_ubus::attr::OBJID, 9)
        .put_string(owrt_ubus::attr::METHOD, "access")
        .put_string(owrt_ubus::attr::USER, "root")
        .put_string(owrt_ubus::attr::GROUP, "root")
        .put(owrt_ubus::attr::DATA, &fields);
    let header = owrt_ubus::Header {
        ty: owrt_ubus::ty::INVOKE,
        seq: 11,
        peer: 1729,
    };
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(request.as_bytes());
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let hello = owrt_ubus::Header {
            ty: owrt_ubus::ty::HELLO,
            seq: 0,
            peer: 42,
        };
        socket.write_all(&hello.encode()).unwrap();
        socket.write_all(&[0, 0, 0, 4]).unwrap();
        let mut reply = [0u8; 28];
        // Both buffers are allocated before counting. The peer waits for an
        // acknowledgement, so this includes IPC as well as receive/classify.
        while socket.write_all(&frame).is_ok() && socket.read_exact(&mut reply).is_ok() {
            assert_eq!(reply[1], owrt_ubus::ty::STATUS);
        }
    });
    let mut conn = owrt_ubus::Connection::connect(path.to_str()).unwrap();
    measure("incoming_request_roundtrip", n, filter, || {
        let owrt_ubus::Incoming::Invoke(req) = conn.read_incoming().unwrap() else {
            panic!("expected the fixed INVOKE");
        };
        assert_eq!(req.method, "access");
        assert_eq!(req.user.as_deref(), Some("root"));
        assert_eq!(req.group.as_deref(), Some("root"));
        assert_eq!(req.data, fields);
        conn.reply_status(&req, 0, None).unwrap();
        conn.recycle_request(req);
    });
    drop(conn);
    peer.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: u64 = args
        .get(1)
        .map(|s| s.parse().expect("iterations"))
        .unwrap_or(20000);
    let filter = args.get(2).map(String::as_str).unwrap_or("");
    assert!(n > 0);
    println!("stage,iterations,ns_per_op,allocs,reallocs,requested_bytes");
    let mut store = session::Store::new();
    let sid = store.create(0).expect("create profiler session");
    let denied = access_args(&sid, "uci", "get");
    let reply = session::call(&mut store, "access", &denied);
    assert_eq!(reply.code, 0);
    let result = owrt_ubus::blob::fields(&reply.data[0])
        .find(|f| f.name == "access")
        .unwrap();
    assert_eq!(result.as_bool(), Some(false));
    measure("session_access_denied", n, filter, || {
        black_box(session::call(&mut store, "access", &denied));
    });
    store
        .get(&sid)
        .unwrap()
        .grant("ubus", Some("u*"), Some("g*"));
    let allowed = access_args(&sid, "uci", "get");
    let reply = session::call(&mut store, "access", &allowed);
    let result = owrt_ubus::blob::fields(&reply.data[0])
        .find(|f| f.name == "access")
        .unwrap();
    assert_eq!(result.as_bool(), Some(true));
    measure("session_access_allowed", n, filter, || {
        black_box(session::call(&mut store, "access", &allowed));
    });
    measure("session_timers_2", n, filter, || {
        store.expire();
        black_box(store.next_expiry());
    });
    for _ in 0..62 {
        store.create(3600).expect("create timed profiler session");
    }
    measure("session_timers_64", n, filter, || {
        store.expire();
        black_box(store.next_expiry());
    });
    measure("file_owner_name", n, filter, || {
        black_box(util::user_name(0));
    });
    measure("file_group_name", n, filter, || {
        black_box(util::group_name(0));
    });
    measure("blob_status_build", n, filter, || {
        let mut b = BlobBuf::new();
        b.put_u32(owrt_ubus::attr::STATUS, 0)
            .put_u32(owrt_ubus::attr::OBJID, 42);
        black_box(b.as_bytes());
    });
    wire(n, filter);
    incoming(n, filter);
}
