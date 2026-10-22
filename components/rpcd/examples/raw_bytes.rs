//! Differential probe for rpcd file paths, data, exec argv/env and ACLs.
//! Run only inside the harness's disposable rootfs; all fixtures are in /tmp.
use owrt_ubus::{blob, BlobBuf, Connection, Reply};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

fn call(conn: &mut Connection, object: &str, method: &str, data: &BlobBuf) -> Reply {
    let id = conn.lookup_id(object, 2000).expect("object registered");
    conn.invoke_status(id, method, data.payload(), 5000)
        .expect("complete RPC")
}

fn string(reply: &Reply, name: &str) -> Vec<u8> {
    let fields = reply.fields();
    let field = blob::fields(&fields)
        .find(|f| f.name == name)
        .expect("string field");
    field.as_bytes().expect("string value").to_vec()
}

fn main() {
    let mut conn = Connection::connect(None).expect("ubus connection");
    let path = b"/tmp/r83-raw/file-\xff";
    let data = b"payload-\xff\xfe\x80\n";
    std::fs::create_dir_all("/tmp/r83-raw").unwrap();
    let mut b = BlobBuf::new();
    b.msg_string_bytes("path", path)
        .msg_string_bytes("data", data);
    assert_eq!(call(&mut conn, "file", "write", &b).status, 0);
    assert_eq!(std::fs::read(OsStr::from_bytes(path)).unwrap(), data);
    println!("write: non-UTF8 path and data preserved");

    let mut b = BlobBuf::new();
    b.msg_string_bytes("path", path);
    let reply = call(&mut conn, "file", "read", &b);
    assert_eq!(reply.status, 0);
    assert_eq!(string(&reply, "data"), data);
    assert_eq!(call(&mut conn, "file", "stat", &b).status, 0);
    println!("read/stat: non-UTF8 path and data preserved");

    let mut b = BlobBuf::new();
    b.msg_string("path", "/tmp/r83-raw");
    let reply = call(&mut conn, "file", "list", &b);
    assert_eq!(reply.status, 0);
    let fields = reply.fields();
    let entries = blob::fields(&fields).find(|f| f.name == "entries").unwrap();
    assert!(entries.children().any(|entry| entry
        .children()
        .any(|f| f.name == "name" && f.as_bytes() == Some(b"file-\xff".as_slice()))));
    println!("list: raw filename preserved");

    let mut b = BlobBuf::new();
    b.msg_string("command", "/bin/cat");
    let params = b.msg_open_array("params");
    b.msg_string_bytes("", path);
    b.msg_close(params);
    let reply = call(&mut conn, "file", "exec", &b);
    assert_eq!(reply.status, 0);
    assert_eq!(string(&reply, "stdout"), data);
    println!("exec: raw argv and stdout preserved");

    let executable = OsStr::from_bytes(b"/tmp/r83-raw/run-\xfe");
    std::fs::write(
        executable,
        b"#!/bin/sh\nprintf '%s' \"$R83_BYTES\"\nprintf '\\377' >&2\n",
    )
    .unwrap();
    std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut b = BlobBuf::new();
    b.msg_string_bytes("command", executable.as_bytes());
    let env = b.msg_open_table("env");
    b.msg_string_bytes("R83_BYTES", b"env-\xfd");
    b.msg_close(env);
    let reply = call(&mut conn, "file", "exec", &b);
    assert_eq!(reply.status, 0);
    assert_eq!(string(&reply, "stdout"), b"env-\xfd");
    assert_eq!(string(&reply, "stderr"), b"\xff");
    println!("exec: raw command, env and stderr preserved");

    let reply = call(&mut conn, "session", "create", &BlobBuf::new());
    assert_eq!(reply.status, 0);
    let sid = string(&reply, "ubus_rpc_session");
    let mut b = BlobBuf::new();
    b.msg_string_bytes("ubus_rpc_session", &sid)
        .msg_string("scope", "file");
    let objects = b.msg_open_array("objects");
    let grant = b.msg_open_array("");
    b.msg_string_bytes("", path).msg_string("", "read");
    b.msg_close(grant);
    b.msg_close(objects);
    assert_eq!(call(&mut conn, "session", "grant", &b).status, 0);
    let mut b = BlobBuf::new();
    b.msg_string_bytes("ubus_rpc_session", &sid)
        .msg_string_bytes("path", path);
    let reply = call(&mut conn, "file", "read", &b);
    assert_eq!(reply.status, 0);
    assert_eq!(string(&reply, "data"), data);
    let mut denied = BlobBuf::new();
    denied
        .msg_string_bytes("ubus_rpc_session", &sid)
        .msg_string_bytes("path", b"/tmp/r83-raw/file-\xfe");
    assert_eq!(call(&mut conn, "file", "read", &denied).status, 6);
    assert_eq!(call(&mut conn, "file", "remove", &b).status, 6);
    println!("ACL: raw path allowed, distinct path and ungranted write denied");

    let mut b = BlobBuf::new();
    b.msg_string_bytes("path", path);
    assert_eq!(call(&mut conn, "file", "remove", &b).status, 0);
    assert!(!std::path::Path::new(OsStr::from_bytes(path)).exists());
    println!("remove: raw path removed");
}
