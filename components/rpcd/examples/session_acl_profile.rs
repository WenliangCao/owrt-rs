//! Profile the current ACL lookup and session.access handler with fixed scopes.
//! Usage: session_acl_profile [iterations] [stage filter]
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
#[allow(unused_imports)]
mod util;

// Profiling uses permanent sessions and never destroys them.
mod uciobj {
    pub fn purge_dir(_: &str) {
        panic!("session destruction is outside this profiler's scope");
    }
}

use owrt_ubus::BlobBuf;
use profile_support::measure;
use std::hint::black_box;

fn data_handlers(n: u64, filter: &str) {
    let mut store = session::Store::new();
    let sid = store
        .create(0)
        .expect("create permanent data profile session");
    let mut set = BlobBuf::new();
    set.msg_string("ubus_rpc_session", &sid);
    let values = set.msg_open_table("values");
    for index in 0..64 {
        set.msg_string_bytes(&format!("key{index:02}"), &[b'x'; 128]);
    }
    set.msg_close(values);
    assert_eq!(session::call(&mut store, "set", set.payload()).code, 0);
    measure("data_set_64", n, filter, || {
        black_box(session::call(&mut store, "set", black_box(set.payload())));
    });

    for method in ["get", "unset"] {
        let mut b = BlobBuf::new();
        b.msg_string("ubus_rpc_session", &sid);
        let keys = b.msg_open_array("keys");
        for index in 0..64 {
            let prefix = if method == "get" { "key" } else { "missing" };
            b.msg_string("", &format!("{prefix}{index:02}"));
        }
        b.msg_close(keys);
        let response = session::call(&mut store, method, b.payload());
        assert_eq!(response.code, 0);
        if method == "get" {
            let values = owrt_ubus::blob::fields(&response.data[0]).next().unwrap();
            assert_eq!(values.children().count(), 64);
        }
        measure(&format!("data_{method}_64"), n, filter, || {
            black_box(session::call(&mut store, method, black_box(b.payload())));
        });
    }

    for method in ["grant", "revoke"] {
        let mut b = BlobBuf::new();
        b.msg_string("ubus_rpc_session", &sid)
            .msg_string("scope", "ubus");
        let objects = b.msg_open_array("objects");
        for index in 0..64 {
            let prefix = if method == "grant" {
                "service"
            } else {
                "missing"
            };
            let pair = b.msg_open_array("");
            b.msg_string("", &format!("{prefix}.{index:04}"))
                .msg_string("", "read");
            b.msg_close(pair);
        }
        b.msg_close(objects);
        assert_eq!(session::call(&mut store, method, b.payload()).code, 0);
        measure(&format!("data_{method}_64"), n, filter, || {
            black_box(session::call(&mut store, method, black_box(b.payload())));
        });
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n = args
        .get(1)
        .map(|s| s.parse().expect("iterations"))
        .unwrap_or(20000);
    let filter = args.get(2).map(String::as_str).unwrap_or("");
    assert!(n > 0);
    println!("stage,iterations,ns_per_op,allocs,reallocs,requested_bytes");
    data_handlers(n, filter);
    for count in [1, 64, 256] {
        for shape in ["exact", "prefix", "complex"] {
            let mut store = session::Store::new();
            let sid = store.create(0).expect("create permanent profile session");
            let (pattern_suffix, name_suffix) = match shape {
                "prefix" => ("*", "a"),
                "complex" => ("[ab]", "a"),
                _ => ("", ""),
            };
            for index in 0..count {
                store.get(&sid).unwrap().grant(
                    "ubus",
                    Some(&format!("service.{index:04}{pattern_suffix}")),
                    Some("read"),
                );
            }
            for (case, object, expected) in [
                ("first", format!("service.0000{name_suffix}"), true),
                (
                    "last",
                    format!("service.{:04}{name_suffix}", count - 1),
                    true,
                ),
                ("absent", "service.missing".to_owned(), false),
            ] {
                let ses = store.get(&sid).unwrap();
                assert_eq!(ses.allowed("ubus", &object, "read"), expected);
                measure(&format!("acl_{count}_{shape}_{case}"), n, filter, || {
                    black_box(ses.allowed(
                        black_box("ubus"),
                        black_box(&object),
                        black_box("read"),
                    ));
                });
                let mut b = BlobBuf::new();
                b.msg_string("ubus_rpc_session", &sid)
                    .msg_string("scope", "ubus")
                    .msg_string("object", &object)
                    .msg_string("function", "read");
                let fields = b.into_payload();
                measure(&format!("access_{count}_{shape}_{case}"), n, filter, || {
                    black_box(session::call(&mut store, "access", black_box(&fields)));
                });
            }
            // A broad first rule exposes any extra lookup work on an ACL that the
            // existing forward scan can authorize immediately.
            store
                .get(&sid)
                .unwrap()
                .grant("ubus", Some("*"), Some("read"));
            let ses = store.get(&sid).unwrap();
            assert!(ses.allowed("ubus", "service.missing", "read"));
            measure(&format!("acl_{count}_{shape}_wildcard"), n, filter, || {
                black_box(ses.allowed(
                    black_box("ubus"),
                    black_box("service.missing"),
                    black_box("read"),
                ));
            });
        }
    }
}
