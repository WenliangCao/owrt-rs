//! Profile local-root stat/list dispatch, input decoding and reply encoding.
//! Run inside the exact image namespace. No ubus, ACL or exec time is measured.
#![allow(dead_code)]

#[path = "../src/file.rs"]
mod file;
#[path = "../src/util.rs"]
mod util;
#[path = "../src/glob.rs"]
mod glob;
#[path = "../src/iwinfo/mod.rs"]
mod iwinfo;
#[path = "../src/procwait.rs"]
mod procwait;
mod profile_support;
#[path = "../src/reply.rs"]
mod reply;

use owrt_ubus::convert::{fields_to_json, object_to_payload};
use owrt_ubus::json::Json;
use owrt_ubus::Request;
use std::hint::black_box;
use profile_support::measure;

// These adapters only satisfy the unused dispatch/worker interfaces. If the
// profiler accidentally enters them, stop instead of measuring fake work.
pub struct Ctx { pub exec_timeout_ms: i32 }
impl Ctx {
    pub fn file_access_bytes(&self, sid: Option<&str>, _: &[u8], _: &str) -> bool {
        assert!(sid.is_none(), "ACL checks are outside this profiler's scope");
        true // the daemon's local-root path also returns immediately
    }
}
mod session {
    pub use crate::reply::Reply;
}
#[derive(Clone)]
pub struct Deferrer;
impl Deferrer {
    pub fn finish(&self, _: Request, _: session::Reply) {
        panic!("deferred requests are outside this profiler's scope");
    }
    pub fn defer<F>(&self, _: Request, _: F) -> Option<(Request, session::Reply)>
    where
        F: FnOnce() -> session::Reply + Send + 'static,
    {
        panic!("deferred requests are outside this profiler's scope");
    }
}
pub fn to_reply(_: Result<Option<Json>, i32>) -> session::Reply {
    panic!("dispatch is outside this profiler's scope");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n = args.get(1).map(|s| s.parse().expect("iterations")).unwrap_or(20000);
    let filter = args.get(2).map(String::as_str).unwrap_or("");
    assert!(n > 0);
    println!("stage,iterations,ns_per_op,allocs,reallocs,requested_bytes");
    let ctx = Ctx { exec_timeout_ms: 30000 };
    for (method, path) in [("stat", "/etc/config/network"), ("list", "/etc/config")] {
        let args = Json::Object(vec![("path".into(), Json::Str(path.into()))]);
        let mut req = Some(Request {
            peer: 1, seq: 1, objid: 1, method: method.into(), user: None,
            group: None, data: object_to_payload(&args), fd: None, no_reply: false,
        });
        // Reuse the owned request, as the daemon does after completing a reply.
        // Connection receive/send and ACLs are outside this measurement.
        let mut call = || {
            let file::Outcome::Now(request, reply) = file::call(&ctx, req.take().unwrap(), &Deferrer) else {
                panic!("stat/list must complete synchronously");
            };
            req = Some(request);
            assert_eq!(reply.code, 0);
            assert_eq!(reply.data.len(), 1);
            reply.data
        };
        let result = fields_to_json(&call()[0]).unwrap();
        if method == "stat" {
            assert_eq!(result.get("type").and_then(Json::as_str), Some("file"));
        } else {
            assert!(matches!(result.get("entries"), Some(Json::Array(entries)) if !entries.is_empty()));
        }
        measure(&format!("file_{method}_handler"), n, filter, || {
            black_box(call());
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn listing_keeps_raw_names_and_resolves_each_symlink_from_its_parent() {
        let root = std::env::temp_dir().join(format!("rpcd-list-path-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let long = "l".repeat(240);
        for name in [b"a".as_slice(), long.as_bytes(), b"raw-\xff"] {
            std::fs::write(root.join(OsStr::from_bytes(name)), b"contents").unwrap();
        }
        std::fs::create_dir(root.join("dir")).unwrap();
        std::os::unix::fs::symlink("a", root.join("link")).unwrap();
        std::os::unix::fs::symlink("missing", root.join("broken")).unwrap();
        let args = Json::Object(vec![("path".into(), Json::from_string_bytes(root.as_os_str().as_bytes().to_vec()))]);
        let req = Request {
            peer: 1, seq: 1, objid: 1, method: "list".into(), user: None,
            group: None, data: object_to_payload(&args), fd: None, no_reply: false,
        };
        let file::Outcome::Now(_, reply) = file::call(&Ctx { exec_timeout_ms: 30000 }, req, &Deferrer) else {
            panic!("list must complete synchronously");
        };
        assert_eq!(reply.code, 0);
        let result = fields_to_json(&reply.data[0]).unwrap();
        let Some(Json::Array(entries)) = result.get("entries") else { panic!("missing entries") };
        assert_eq!(entries.len(), 6);
        for (name, ty) in [
            (b"a".as_slice(), "file"), (long.as_bytes(), "file"), (b"raw-\xff", "file"),
            (b"dir", "directory"), (b"link", "symlink"), (b"broken", "symlink"),
        ] {
            let entry = entries.iter().find(|entry| entry.get("name").and_then(Json::as_bytes) == Some(name)).unwrap();
            assert_eq!(entry.get("type").and_then(Json::as_str), Some(ty));
            if ty == "file" {
                assert_eq!(entry.get("size"), Some(&Json::Int(8)));
            }
            if name == b"link" || name == b"broken" {
                let target = entry.get("target").unwrap();
                let (name, ty) = if name == b"link" { ("a", "file") } else { ("missing", "broken") };
                assert_eq!(target.get("name").and_then(Json::as_str), Some(name));
                assert_eq!(target.get("type").and_then(Json::as_str), Some(ty));
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
