//! Actual local-root UCI handlers through complete reply construction.
//! Copy to components/rpcd/examples/ in both frozen source trees unchanged.
//! Run only inside the existing exact-image profile namespace. It supplies
//! network and the 64-section r84fixture; no files or configuration are changed.
//!
//! Usage: uci_reply_extended_profile [iterations] [stage filter]
//! All rows are one request/op except uci_get_alternating_pair_payload, whose
//! ns, allocations and requested bytes are per TWO requests: network followed
//! by r84fixture. The same Ctx is retained, so its single cache entry naturally
//! misses on both calls; no private cache access or manual invalidation occurs.
//! Reply semantic checks happen before and after each timed stage. The timed
//! closures retain the original profile's cheap status/one-DATA/nonempty checks.
#![allow(dead_code)]

#[path = "../src/session.rs"]
mod session;
#[path = "../src/uciobj.rs"]
mod uciobj;
#[path = "../src/delayed.rs"]
mod delayed;
#[path = "../src/glob.rs"]
mod glob;
#[path = "../src/util.rs"]
#[allow(unused_imports)]
mod util;
mod profile_support;
#[path = "../src/reply.rs"]
mod reply;

use owrt_ubus::{blob, BlobBuf, Connection, Header, MsgType, ty};
use profile_support::measure;
use std::cell::RefCell;
use std::hint::black_box;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

// Identical to uci_reply_profile's real stores. Only local-root get/configs
// execute; neither sends events nor launches delayed actions.
pub struct Ctx {
    pub sessions: RefCell<session::Store>,
    pub apply: RefCell<uciobj::Apply>,
    pub delayed: RefCell<delayed::Children>,
    pub uci_read_cache: RefCell<owrt_uci::ReadCache>,
}

#[derive(Clone, Copy)]
enum Expected { Configs, Network, Package64, Section, Option, Filtered }

fn required<'a>(fields: &'a [u8], name: &str, ty: MsgType) -> blob::Field<'a> {
    blob::fields(fields).find(|f| f.name == name && f.ty == ty as u32)
        .unwrap_or_else(|| panic!("missing expected field {name} of type {ty:?}"))
}

fn check_section(fields: &[u8], index: usize, package_level: bool) {
    assert_eq!(required(fields, ".anonymous", MsgType::Int8).as_bool(), Some(false));
    assert_eq!(required(fields, ".type", MsgType::String).as_str(), Some("bench"));
    let name = format!("entry{index}");
    assert_eq!(required(fields, ".name", MsgType::String).as_str(), Some(name.as_str()));
    let value = format!("fixed-{index}");
    assert_eq!(required(fields, "value", MsgType::String).as_str(), Some(value.as_str()));
    let members = required(fields, "members", MsgType::Array);
    let mut members = members.children();
    assert_eq!(members.next().unwrap().as_str(), Some("alpha"));
    assert_eq!(members.next().unwrap().as_str(), Some("beta"));
    assert!(members.next().is_none());
    if package_level {
        assert_eq!(required(fields, ".index", MsgType::Int32).as_u32(), Some(index as u32));
    } else {
        assert!(!blob::fields(fields).any(|f| f.name == ".index"));
    }
}

fn validate(reply: &session::Reply, expected: Expected) {
    assert_eq!(reply.code, 0);
    assert_eq!(reply.data.len(), 1);
    let data = &reply.data[0];
    match expected {
        Expected::Configs => {
            let configs = required(data, "configs", MsgType::Array);
            assert!(configs.children().any(|f| f.as_str() == Some("network")));
            assert!(configs.children().any(|f| f.as_str() == Some("r84fixture")));
        }
        Expected::Network => {
            let values = required(data, "values", MsgType::Table);
            assert!(values.children().count() > 0);
            assert!(values.children().all(|f| f.ty == MsgType::Table as u32));
        }
        Expected::Package64 => {
            let values = required(data, "values", MsgType::Table);
            assert_eq!(values.children().count(), 64);
            for (index, section) in values.children().enumerate() {
                assert_eq!(section.name, format!("entry{index}"));
                assert_eq!(section.ty, MsgType::Table as u32);
                check_section(section.data, index, true);
            }
        }
        Expected::Section => check_section(required(data, "values", MsgType::Table).data, 0, false),
        Expected::Option => {
            assert_eq!(blob::fields(data).count(), 1);
            assert_eq!(required(data, "value", MsgType::String).as_str(), Some("fixed-0"));
        }
        Expected::Filtered => {
            let values = required(data, "values", MsgType::Table);
            assert_eq!(values.children().count(), 1);
            check_section(required(values.data, "entry0", MsgType::Table).data, 0, true);
        }
    }
}

fn call(ctx: &Ctx, conn: &mut Connection, method: &str, fields: &[u8]) -> session::Reply {
    let result = uciobj::call(ctx, conn, method, fields);
    assert_eq!(result.code, 0);
    assert_eq!(result.data.len(), 1);
    assert!(!result.data[0].is_empty());
    result
}

fn get_args(config: &str, section: bool, option: bool, filtered: bool) -> Vec<u8> {
    let mut b = BlobBuf::new();
    b.msg_string("config", config);
    if section { b.msg_string("section", "entry0"); }
    if option { b.msg_string("option", "value"); }
    if filtered {
        b.msg_string("type", "bench");
        let matches = b.msg_open_table("match");
        b.msg_string("value", "fixed-0");
        b.msg_close(matches);
    }
    b.into_payload()
}

fn main() {
    assert_eq!(std::env::var("OWRT_BENCH_NAMESPACE").as_deref(), Ok("1"),
        "run only through the existing isolated namespace profile launcher");
    let args: Vec<String> = std::env::args().collect();
    let n = args.get(1).map(|s| s.parse().expect("iterations")).unwrap_or(20000);
    let filter = args.get(2).map(String::as_str).unwrap_or("");
    assert!(n > 0);
    let path = std::env::temp_dir().join(format!("uci-reply-extended-profile-{}", std::process::id()));
    let listener = UnixListener::bind(&path).unwrap();
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.write_all(&Header { ty: ty::HELLO, seq: 0, peer: 42 }.encode()).unwrap();
        socket.write_all(&[0, 0, 0, 4]).unwrap();
        let mut byte = [0u8];
        // These read-only handlers must not use the supplied Connection.
        assert_eq!(socket.read(&mut byte).unwrap(), 0);
    });
    let mut conn = Connection::connect(path.to_str()).unwrap();
    let ctx = Ctx {
        sessions: RefCell::new(session::Store::new()),
        apply: RefCell::new(uciobj::Apply::default()),
        delayed: RefCell::new(delayed::Children::default()),
        uci_read_cache: RefCell::new(owrt_uci::ReadCache::default()),
    };
    let network = get_args("network", false, false, false);
    let fixture = get_args("r84fixture", false, false, false);
    let section = get_args("r84fixture", true, false, false);
    let option = get_args("r84fixture", true, true, false);
    let filtered = get_args("r84fixture", false, false, true);
    println!("stage,iterations,ns_per_op,allocs,reallocs,requested_bytes");
    for (stage, method, fields, expected) in [
        ("uci_configs_payload", "configs", &[][..], Expected::Configs),
        ("uci_get_network_payload", "get", network.as_slice(), Expected::Network),
        ("uci_get_64_payload", "get", fixture.as_slice(), Expected::Package64),
        ("uci_get_section_payload", "get", section.as_slice(), Expected::Section),
        ("uci_get_option_payload", "get", option.as_slice(), Expected::Option),
        ("uci_get_filtered_payload", "get", filtered.as_slice(), Expected::Filtered),
    ] {
        validate(&call(&ctx, &mut conn, method, fields), expected);
        measure(stage, n, filter, || {
            black_box(call(&ctx, &mut conn, method, black_box(fields)));
        });
        validate(&call(&ctx, &mut conn, method, fields), expected);
    }

    for (fields, expected) in [(&network, Expected::Network), (&fixture, Expected::Package64)] {
        validate(&call(&ctx, &mut conn, "get", fields), expected);
    }
    // One measured/allocation-probe operation always executes both requests.
    // Drop each reply before the next call, as the real single-request daemon
    // does after sending it; do not artificially retain two reply buffers.
    measure("uci_get_alternating_pair_payload", n, filter, || {
        black_box(call(&ctx, &mut conn, "get", black_box(&network)));
        black_box(call(&ctx, &mut conn, "get", black_box(&fixture)));
    });
    for (fields, expected) in [(&network, Expected::Network), (&fixture, Expected::Package64)] {
        validate(&call(&ctx, &mut conn, "get", fields), expected);
    }
    drop(conn);
    peer.join().unwrap();
    std::fs::remove_file(path).unwrap();
}
