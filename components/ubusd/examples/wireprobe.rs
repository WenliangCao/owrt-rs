//! Wire-level probe for the ubusd differential gate (tools/r83). Drives raw
//! ubus messages over the socket and prints what comes back in a form that
//! is sensitive to attribute order, sequence numbers and blobmsg types but
//! free of random object ids, so the C daemon and ubusd-rs can be compared
//! line for line. Not built into the package: the packaging recipe copies
//! only src/*.rs.
//!
//! Usage: wireprobe <socket> <scenario>
//!   pathless  as any user: the system objects' own verdicts once the ACL
//!             table no longer stands in the way (ubusd_acl.c:108)
//!   events    two listener objects on one connection, one event: each
//!             delivered copy carries its own `++event_seq`
//!   monitor   attribute order and sequence of MONITOR mirror messages
//!   release   REMOVE_OBJECT of an object that still has a subscriber: the
//!             owner gets NOTIFY(ACTIVE=0) between DATA and STATUS
//!   remove_reply exact REMOVE replies, type lifetime, removal event order,
//!             monitor mirrors and outbound subscription teardown
//!   aclquery  the blobmsg types inside `acl query`'s private acl table
//!             (needs an acl.d entry for root with an `acl` table on r83.priv)
//!   utf8      a STRING field carrying non-UTF-8 bytes crosses the bus intact
//!   slowlookup pause a >1 MiB LOOKUP, overwrite scratch via another client,
//!             then require every original frame in order after resuming
//!   fd_boundary Linux SCM_RIGHTS placement with exact C expectations
//!   fd_boundary_read_ahead Linux SCM_RIGHTS placement with the R134 contract

use owrt_ubus::blob::{self, Attr, BlobBuf, Field, MsgType};
use owrt_ubus::msg::{attr, ty, Header};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

#[cfg(target_os = "linux")]
#[allow(dead_code, unused_imports)]
#[path = "../src/sys.rs"]
mod fd_sys;

const EVENT_OBJ: u32 = 1;
const ACL_OBJ: u32 = 2;
const MONITOR_OBJ: u32 = 3;

struct Conn {
    s: UnixStream,
    next_seq: u16,
}

type Msg = (Header, Vec<u8>);

impl Conn {
    fn open(path: &str) -> Conn {
        let s = UnixStream::connect(path).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut c = Conn { s, next_seq: 1 };
        let (h, _) = c.recv().expect("hello");
        assert_eq!(h.ty, ty::HELLO, "first message is HELLO");
        c
    }

    fn send(&mut self, t: u8, seq: u16, peer: u32, b: &mut BlobBuf) {
        let mut out = Header { ty: t, seq, peer }.encode().to_vec();
        out.extend_from_slice(b.as_bytes());
        self.s.write_all(&out).expect("write");
    }

    /// One message: header plus the whole head blob, its 4-byte header included.
    fn recv(&mut self) -> Option<Msg> {
        let mut pre = [0u8; 12];
        self.s.read_exact(&mut pre).ok()?;
        let h = Header::decode(pre[..8].try_into().unwrap())?;
        let raw = (u32::from_be_bytes(pre[8..12].try_into().unwrap()) & 0x00ff_ffff) as usize;
        let mut blob = pre[8..].to_vec();
        blob.resize(raw.max(4), 0);
        self.s.read_exact(&mut blob[4..]).ok()?;
        Some((h, blob))
    }

    /// Send a request and collect everything that arrives up to its STATUS.
    fn request(&mut self, t: u8, peer: u32, b: &mut BlobBuf) -> (i32, Vec<Msg>) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.send(t, seq, peer, b);
        let mut got = Vec::new();
        loop {
            let (h, blob) = self.recv().expect("reply before timeout");
            if h.ty == ty::STATUS && h.seq == seq {
                let code = attrs(&blob)[attr::STATUS as usize].and_then(|a| a.as_u32()).unwrap_or(u32::MAX);
                return (code as i32, got);
            }
            got.push((h, blob));
        }
    }

    fn invoke(&mut self, objid: u32, method: &str, data: Option<&[u8]>) -> (i32, Vec<Msg>) {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, objid);
        b.put_string(attr::METHOD, method);
        if let Some(d) = data {
            b.put(attr::DATA, d);
        }
        self.request(ty::INVOKE, 0, &mut b)
    }

    /// ADD_OBJECT with an optional path and a signature of empty-policy
    /// methods; returns the object id.
    fn add_object(&mut self, path: Option<&str>, methods: &[&str]) -> u32 {
        let mut b = BlobBuf::new();
        if let Some(p) = path {
            b.put_string(attr::OBJPATH, p);
        }
        if !methods.is_empty() {
            let s = b.nest_start(attr::SIGNATURE);
            for m in methods {
                let t = b.msg_open_table(m);
                b.msg_close(t);
            }
            b.nest_end(s);
        }
        let (code, msgs) = self.request(ty::ADD_OBJECT, 0, &mut b);
        assert_eq!(code, 0, "add_object {path:?}");
        msgs.iter()
            .find(|(h, _)| h.ty == ty::DATA)
            .and_then(|(_, blob)| attrs(blob)[attr::OBJID as usize].and_then(|a| a.as_u32()))
            .expect("DATA with OBJID")
    }

    fn event_register(&mut self, pattern: &str, objid: u32) -> i32 {
        let mut d = BlobBuf::new();
        d.msg_string("pattern", pattern).msg_u32("object", objid);
        self.invoke(EVENT_OBJ, "register", Some(&d.into_payload())).0
    }

    fn event_send(&mut self, id: &str, data_fields: &[u8]) -> i32 {
        let mut d = BlobBuf::new();
        d.msg_string("id", id);
        let t = d.msg_open_table("data");
        d.put_raw_fields(data_fields);
        d.msg_close(t);
        self.invoke(EVENT_OBJ, "send", Some(&d.into_payload())).0
    }
}

fn attrs(blob: &[u8]) -> [Option<Attr<'_>>; attr::MAX] {
    let mut out: [Option<Attr<'_>>; attr::MAX] = Default::default();
    if blob.len() > 4 {
        for a in blob::iter(&blob[4..]) {
            if (a.id as usize) < attr::MAX {
                out[a.id as usize] = Some(a);
            }
        }
    }
    out
}

fn type_name(t: u8) -> &'static str {
    match t {
        ty::HELLO => "HELLO",
        ty::STATUS => "STATUS",
        ty::DATA => "DATA",
        ty::PING => "PING",
        ty::LOOKUP => "LOOKUP",
        ty::INVOKE => "INVOKE",
        ty::ADD_OBJECT => "ADD_OBJECT",
        ty::REMOVE_OBJECT => "REMOVE_OBJECT",
        ty::SUBSCRIBE => "SUBSCRIBE",
        ty::UNSUBSCRIBE => "UNSUBSCRIBE",
        ty::NOTIFY => "NOTIFY",
        ty::MONITOR => "MONITOR",
        _ => "?",
    }
}

fn field_type_name(t: u32) -> &'static str {
    match t {
        0 => "UNSPEC",
        1 => "ARRAY",
        2 => "TABLE",
        3 => "STRING",
        4 => "INT64",
        5 => "INT32",
        6 => "INT16",
        7 => "INT8",
        8 => "DOUBLE",
        _ => "?",
    }
}

/// `name:TYPE` for every field, nested containers spelled out in brackets.
fn describe(fields: impl Iterator<Item = Field<'static>>) -> String {
    let mut parts = Vec::new();
    for f in fields {
        let mut s = format!("{}:{}", f.name, field_type_name(f.ty));
        if f.ty == MsgType::Array as u32 || f.ty == MsgType::Table as u32 {
            s.push('[');
            s.push_str(&describe(f.children()));
            s.push(']');
        }
        parts.push(s);
    }
    parts.join(",")
}

fn data_fields(blob: &[u8]) -> &[u8] {
    attrs(blob)[attr::DATA as usize].map(|a| a.payload).unwrap_or(&[])
}

fn pathless(sock: &str) {
    let mut c = Conn::open(sock);
    // ACCESS on a pathless object is never a table question in C; what
    // follows is each system object's own verdict
    println!("acl.query={}", c.invoke(ACL_OBJ, "query", None).0);
    println!("acl.bogus={}", c.invoke(ACL_OBJ, "bogus", None).0);
    println!("event.bogus={}", c.invoke(EVENT_OBJ, "bogus", None).0);
    // an id >= 1024 that no object has: the ACL passed, the lookup failed
    println!("event.register(no-such-object)={}", c.event_register("r83.x", 5000));
    println!("event.send(unlisted id)={}", c.event_send("r83.unlisted", &[]));
    println!("monitor.add={}", c.invoke(MONITOR_OBJ, "add", None).0);
    println!("monitor.bogus={}", c.invoke(MONITOR_OBJ, "bogus", None).0);
}

fn events(sock: &str) {
    let mut a = Conn::open(sock);
    let mut b = Conn::open(sock);
    let o1 = a.add_object(None, &[]);
    let o2 = a.add_object(None, &[]);
    println!("register={},{}", a.event_register("r83.ev.*", o1), a.event_register("r83.ev.*", o2));
    let mut fields = BlobBuf::new();
    fields.msg_u32("n", 1);
    let payload = fields.into_payload();
    for round in 0..2 {
        println!("send={}", b.event_send("r83.ev.one", &payload));
        let (h1, b1) = a.recv().expect("first copy");
        let (h2, b2) = a.recv().expect("second copy");
        let id1 = attrs(&b1)[attr::OBJID as usize].and_then(|x| x.as_u32());
        let id2 = attrs(&b2)[attr::OBJID as usize].and_then(|x| x.as_u32());
        let method = attrs(&b1)[attr::METHOD as usize].and_then(|x| x.as_str()).unwrap_or("?");
        println!(
            "round{round}: types={},{} peers={},{} method={method} seq_delta={} objids={}",
            type_name(h1.ty),
            type_name(h2.ty),
            h1.peer,
            h2.peer,
            h2.seq.wrapping_sub(h1.seq),
            if id1 == Some(o1) && id2 == Some(o2) { "o1,o2" } else { "other" },
        );
    }
}

fn object_events(sock: &str) {
    let mut listener = Conn::open(sock);
    let mut owner = Conn::open(sock);
    let remove = |conn: &mut Conn, id| {
        let mut b = BlobBuf::new();
        b.put_u32(attr::OBJID, id);
        assert_eq!(conn.request(ty::REMOVE_OBJECT, 0, &mut b).0, 0);
    };
    let unseen = owner.add_object(Some("r98.unobserved"), &["method"]);
    remove(&mut owner, unseen);
    let first = listener.add_object(None, &[]);
    let second = listener.add_object(None, &[]);
    for (id, pattern) in [(first, "ubus.object.*"), (first, "ubus.object.add"),
                          (second, "ubus.object.*")] {
        assert_eq!(listener.event_register(pattern, id), 0);
    }
    let mut sequence = 0u16;
    for round in 0..2 {
        let path = format!("r98.visible.{round}");
        let id = owner.add_object(Some(&path), &["method"]);
        for (kind, receivers) in [("add", if round == 0 { vec![first, second] } else { vec![second] }),
                                  ("remove", if round == 0 { vec![first, second] } else { vec![second] })] {
            if kind == "remove" { remove(&mut owner, id); }
            for receiver in receivers {
                sequence += 1;
                let (header, actual) = listener.recv().expect("object event");
                assert_eq!((header.ty, header.seq, header.peer), (ty::INVOKE, sequence, 0));
                let mut expected = BlobBuf::new();
                expected.put_u32(attr::OBJID, receiver);
                expected.put_string(attr::METHOD, &format!("ubus.object.{kind}"));
                let data = expected.nest_start(attr::DATA);
                expected.msg_u32("id", id);
                expected.msg_string("path", &path);
                expected.nest_end(data);
                assert_eq!(actual, expected.as_bytes());
                println!("round={round} kind={kind} sequence={sequence} canonical=true");
            }
        }
        if round == 0 { remove(&mut listener, first); }
    }
}

fn monitor(sock: &str) {
    let mut a = Conn::open(sock);
    let (code, mut mirrored) = a.invoke(MONITOR_OBJ, "add", None);
    println!("monitor.add={code}");
    // the connect of a second client and one lookup by it
    let mut b = Conn::open(sock);
    b.request(ty::LOOKUP, 0, &mut BlobBuf::new());
    while mirrored.len() < 4 {
        match a.recv() {
            Some(m) => mirrored.push(m),
            None => break,
        }
    }
    for (i, (h, blob)) in mirrored.iter().enumerate() {
        let ids: Vec<String> = if blob.len() > 4 {
            blob::iter(&blob[4..]).map(|x| x.id.to_string()).collect()
        } else {
            Vec::new()
        };
        let at = attrs(blob);
        let mirrored_ty = at[4].and_then(|x| x.as_u32()).map(|t| type_name(t as u8)).unwrap_or("?");
        let send = at[2].and_then(|x| x.as_u32()).unwrap_or(9);
        println!(
            "m{i}: type={} seq={} attr_ids={} mirrored_type={mirrored_ty} send={send}",
            type_name(h.ty),
            h.seq,
            ids.join(","),
        );
    }
    println!("monitor.remove={}", a.invoke(MONITOR_OBJ, "remove", None).0);
}

fn release(sock: &str) {
    let mut a = Conn::open(sock);
    let mut b = Conn::open(sock);
    let target = a.add_object(Some("r83.target"), &["m"]);
    let sub = b.add_object(None, &[]);
    let mut s = BlobBuf::new();
    s.put_u32(attr::OBJID, sub).put_u32(attr::TARGET, target);
    println!("subscribe={}", b.request(ty::SUBSCRIBE, 0, &mut s).0);
    let (h, blob) = a.recv().expect("NOTIFY after subscribe");
    let active = attrs(&blob)[attr::ACTIVE as usize].and_then(|x| x.as_u32());
    println!("owner_got={} active={active:?} seq={}", type_name(h.ty), h.seq);

    let mut r = BlobBuf::new();
    r.put_u32(attr::OBJID, target);
    let (code, during) = a.request(ty::REMOVE_OBJECT, 0, &mut r);
    let mut seen: Vec<String> = during
        .iter()
        .map(|(h, blob)| {
            let at = attrs(blob);
            match h.ty {
                ty::NOTIFY => format!(
                    "NOTIFY(active={},seq={})",
                    at[attr::ACTIVE as usize].and_then(|x| x.as_u32()).unwrap_or(9),
                    h.seq
                ),
                t => type_name(t).to_owned(),
            }
        })
        .collect();
    seen.push(format!("STATUS({code})"));
    println!("release_sequence={}", seen.join(" "));
    let (h, blob) = b.recv().expect("UNSUBSCRIBE to the subscriber");
    let at = attrs(&blob);
    println!(
        "subscriber_got={} objid_is_sub={} target_is_target={} seq={}",
        type_name(h.ty),
        at[attr::OBJID as usize].and_then(|x| x.as_u32()) == Some(sub),
        at[attr::TARGET as usize].and_then(|x| x.as_u32()) == Some(target),
        h.seq
    );
}

fn remove_reply(sock: &str) {
    fn expect(c: &mut Conn, header: Header, bytes: &[u8]) {
        let (actual, blob) = c.recv().expect("remove reply before timeout");
        assert_eq!(actual.encode(), header.encode(), "remove reply header/order");
        assert_eq!(blob, bytes, "remove reply attributes/order");
    }
    fn start(c: &mut Conn, id: u32, type_id: Option<u32>) -> (Header, Vec<u8>, Vec<u8>) {
        let header = Header { ty: ty::REMOVE_OBJECT, seq: c.next_seq, peer: 0x12345678 };
        c.next_seq += 1;
        let mut request = BlobBuf::new();
        request.put_u32(attr::OBJID, id);
        c.send(header.ty, header.seq, header.peer, &mut request);
        let mut data = BlobBuf::new();
        data.put_u32(attr::OBJID, id);
        if let Some(type_id) = type_id { data.put_u32(attr::OBJTYPE, type_id); }
        expect(c, Header { ty: ty::DATA, ..header }, data.as_bytes());
        (header, request.as_bytes().to_vec(), data.as_bytes().to_vec())
    }
    fn finish(c: &mut Conn, header: Header) -> Vec<u8> {
        let mut status = BlobBuf::new();
        status.put_u32(attr::STATUS, 0);
        expect(c, Header { ty: ty::STATUS, ..header }, status.as_bytes());
        status.as_bytes().to_vec()
    }
    fn add_typed(c: &mut Conn, path: &str, existing: Option<u32>) -> (u32, u32) {
        let mut request = BlobBuf::new();
        request.put_string(attr::OBJPATH, path);
        if let Some(type_id) = existing {
            request.put_u32(attr::OBJTYPE, type_id);
        } else {
            let signature = request.nest_start(attr::SIGNATURE);
            let method = request.msg_open_table("method");
            request.msg_close(method);
            request.nest_end(signature);
        }
        let (status, frames) = c.request(ty::ADD_OBJECT, 0, &mut request);
        assert_eq!(status, 0);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0.ty, ty::DATA);
        let at = attrs(&frames[0].1);
        let id = at[attr::OBJID as usize].unwrap().as_u32().unwrap();
        let type_id = existing.unwrap_or_else(|| at[attr::OBJTYPE as usize].unwrap().as_u32().unwrap());
        (id, type_id)
    }

    let mut owner = Conn::open(sock);
    for path in [None, Some("r138.remove.typeless")] {
        let id = owner.add_object(path, &[]);
        let (header, _, _) = start(&mut owner, id, None);
        finish(&mut owner, header);
    }
    let (first, type_id) = add_typed(&mut owner, "r138.remove.first", None);
    let (last, reused) = add_typed(&mut owner, "r138.remove.last", Some(type_id));
    assert_eq!(reused, type_id);
    for (id, reply_type) in [(first, None), (last, Some(type_id))] {
        let (header, _, _) = start(&mut owner, id, reply_type);
        finish(&mut owner, header);
    }
    println!("remove_shapes=typeless_pathless,typeless_named,shared_type,last_type exact_data_status=true");

    // A pathless listener owns patterns, but cannot emit its own removal event.
    let listener = owner.add_object(None, &[]);
    assert_eq!(owner.event_register("ubus.object.remove", listener), 0);
    let (header, _, _) = start(&mut owner, listener, None);
    finish(&mut owner, header);
    let orphan_check = owner.add_object(Some("r138.remove.no_listener"), &[]);
    let (header, _, _) = start(&mut owner, orphan_check, None);
    finish(&mut owner, header);
    println!("pathless_listener_removed=true patterns_released=true");

    // Same connection exposes the required DATA -> event -> STATUS order.
    let listener = owner.add_object(None, &[]);
    assert_eq!(owner.event_register("ubus.object.remove", listener), 0);
    let path = "r138.remove.observed";
    let target = owner.add_object(Some(path), &[]);
    let (header, _, _) = start(&mut owner, target, None);
    let (event_header, event_blob) = owner.recv().expect("named removal event");
    assert_eq!((event_header.ty, event_header.peer), (ty::INVOKE, 0));
    let mut event = BlobBuf::new();
    event.put_u32(attr::OBJID, listener).put_string(attr::METHOD, "ubus.object.remove");
    let data = event.nest_start(attr::DATA);
    event.msg_u32("id", target).msg_string("path", path);
    event.nest_end(data);
    assert_eq!(event_blob, event.as_bytes());
    finish(&mut owner, header);
    let (header, _, _) = start(&mut owner, listener, None);
    finish(&mut owner, header);
    println!("named_remove_sequence=DATA,INVOKE,STATUS event_payload=true");

    let (target, type_id) = add_typed(&mut owner, "r138.remove.monitored", None);
    let mut monitor = Conn::open(sock);
    let (status, initial) = monitor.invoke(MONITOR_OBJ, "add", None);
    assert_eq!(status, 0);
    assert_eq!(initial.len(), 1);
    let mut last_seq = initial[0].0.seq;
    let (header, request, data) = start(&mut owner, target, Some(type_id));
    let status = finish(&mut owner, header);
    for (kind, send, blob) in [(ty::REMOVE_OBJECT, false, request), (ty::DATA, true, data), (ty::STATUS, true, status)] {
        let (h, mirror) = monitor.recv().expect("remove mirror");
        last_seq = last_seq.wrapping_add(1);
        assert_eq!((h.ty, h.seq), (ty::MONITOR, last_seq));
        let at = attrs(&mirror);
        assert_eq!(blob::iter(&mirror[4..]).map(|a| a.id).collect::<Vec<_>>(), [0, 1, 3, 4, 2, 5]);
        assert_eq!(at[1].unwrap().as_u32(), Some(header.peer));
        assert_eq!(at[3].unwrap().as_u32(), Some(header.seq as u32));
        assert_eq!(at[4].unwrap().as_u32(), Some(kind as u32));
        assert_eq!(at[2].unwrap().payload, &[u8::from(send)]);
        assert_eq!(at[5].unwrap().payload, &blob[4..]);
    }
    let (status, final_mirrors) = monitor.invoke(MONITOR_OBJ, "remove", None);
    assert_eq!(status, 0);
    assert_eq!(final_mirrors.len(), 1, "only monitor.remove request remains");
    println!("remove_monitor_order=request,DATA,STATUS exact_payloads=true sequences=true");

    // Existing `release` covers removal of a target with subscribers. Here
    // removal of a subscriber must still deactivate its surviving target.
    let target = owner.add_object(None, &[]);
    let mut subscriber = Conn::open(sock);
    let sub = subscriber.add_object(None, &[]);
    let mut request = BlobBuf::new();
    request.put_u32(attr::OBJID, sub).put_u32(attr::TARGET, target);
    assert_eq!(subscriber.request(ty::SUBSCRIBE, 0, &mut request).0, 0);
    for active in [true, false] {
        if !active {
            let (header, _, _) = start(&mut subscriber, sub, None);
            finish(&mut subscriber, header);
        }
        let mut notify = BlobBuf::new();
        notify.put_u32(attr::OBJID, target).put_u8(attr::ACTIVE, u8::from(active));
        expect(&mut owner, Header { ty: ty::NOTIFY, seq: if active { 1 } else { 2 }, peer: 0 }, notify.as_bytes());
    }
    let (header, _, _) = start(&mut owner, target, None);
    finish(&mut owner, header);
    println!("subscriber_removed=true target_notify_active=1,0 exact_data_status=true");
}

fn aclquery(sock: &str) {
    let mut a = Conn::open(sock);
    a.add_object(Some("r83.priv"), &["m"]);
    let (code, msgs) = a.invoke(ACL_OBJ, "query", None);
    println!("acl.query={code}");
    for (h, blob) in &msgs {
        if h.ty != ty::DATA {
            continue;
        }
        // the payload is leaked on purpose: the probe exits right after
        let data: &'static [u8] = Box::leak(data_fields(blob).to_vec().into_boxed_slice());
        for f in blob::fields(data) {
            match f.name {
                "seq" => println!("seq_type={}", field_type_name(f.ty)),
                "acl" => {
                    for entry in f.children() {
                        let mut obj = "?".to_owned();
                        let mut user = "-".to_owned();
                        let mut inner = String::new();
                        for e in entry.children() {
                            match e.name {
                                "obj" => obj = e.as_str().unwrap_or("?").to_owned(),
                                "user" => user = e.as_str().unwrap_or("?").to_owned(),
                                "acl" => inner = describe(e.children()),
                                _ => {}
                            }
                        }
                        println!("entry obj={obj} user={user} acl=[{inner}]");
                    }
                }
                other => println!("field {other}:{}", field_type_name(f.ty)),
            }
        }
    }
}

fn utf8(sock: &str) {
    let mut a = Conn::open(sock);
    let mut b = Conn::open(sock);
    let o = a.add_object(None, &[]);
    println!("register={}", a.event_register("r83.utf", o));
    let mut fields = BlobBuf::new();
    fields.msg_field(MsgType::String as u32, "s", b"caf\xe9\0");
    println!("send={}", b.event_send("r83.utf", &fields.into_payload()));
    let (h, blob) = a.recv().expect("event copy");
    let s = blob::fields(data_fields(&blob)).find(|f| f.name == "s");
    let hex: String = s
        .and_then(|f| f.as_bytes())
        .map(|bytes| bytes.iter().map(|x| format!("{x:02x}")).collect())
        .unwrap_or_default();
    println!("got={} s_hex={hex} s_is_utf8={}", type_name(h.ty), s.is_some_and(|f| f.as_str().is_some()));
}

fn slowlookup(sock: &str) {
    let mut owner = Conn::open(sock);
    let mut reader = Conn::open(sock);
    let names: Vec<String> = (0..64).map(|i| format!("method_{i:04}_{}", "x".repeat(88))).collect();
    let methods: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut expected = Vec::new();
    for i in 0..200 {
        let path = format!("r85.resume.{i:04}");
        owner.add_object(Some(&path), &methods);
        let mut b = BlobBuf::new();
        b.put_string(attr::OBJPATH, &path);
        let (code, frames) = owner.request(ty::LOOKUP, 0, &mut b);
        assert_eq!(code, 0);
        assert_eq!(frames.len(), 1, "exact lookup fixture");
        assert_eq!(frames[0].0.ty, ty::DATA);
        expected.push(frames[0].1.clone());
    }
    let total: usize = expected.iter().map(|blob| 8 + blob.len()).sum();
    let socket_budget: usize = std::fs::read_to_string("/proc/sys/net/core/wmem_default")
        .expect("socket send-buffer budget").trim().parse().unwrap();
    assert!(total > 1_048_576 && total > socket_budget * 2,
            "fixture must exceed both the transmit cap and kernel send buffer");

    reader.send(ty::LOOKUP, 700, 0, &mut BlobBuf::new());
    std::thread::sleep(Duration::from_millis(200));
    // These calls overwrite the reusable output while the reader is stopped.
    for i in 0..32 {
        let mut b = BlobBuf::new();
        b.put_string(attr::OBJPATH, &format!("r85.resume.{:04}", i % 200));
        let (code, frames) = owner.request(ty::LOOKUP, 0, &mut b);
        assert_eq!(code, 0);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].1, expected[i % 200]);
    }
    for blob in &expected {
        let (h, got) = reader.recv().expect("resumed LOOKUP DATA");
        assert_eq!((h.ty, h.seq, h.peer), (ty::DATA, 700, 0));
        assert_eq!(&got, blob, "missing, reordered or overwritten LOOKUP frame");
    }
    let (h, got) = reader.recv().expect("resumed LOOKUP STATUS");
    assert_eq!((h.ty, h.seq, h.peer), (ty::STATUS, 700, 0));
    assert_eq!(attrs(&got)[attr::STATUS as usize].and_then(|a| a.as_u32()), Some(0));
    let (code, frames) = reader.request(ty::PING, 0, &mut BlobBuf::new());
    assert_eq!(code, 0);
    assert_eq!(frames.len(), 1, "no extra or duplicate LOOKUP replies");
    assert_eq!(frames[0].0.ty, ty::DATA);
    println!("resumed_objects=200 exact_frames=true ordered=true status=0 other_client_calls=32 bytes={total}");
}

fn monitor_lookup(sock: &str) {
    let mut owner = Conn::open(sock);
    for i in 0..4 {
        owner.add_object(Some(&format!("r85.monitor.{i}")), &["method"]);
    }
    let mut monitor = Conn::open(sock);
    let (code, initial) = monitor.invoke(MONITOR_OBJ, "add", None);
    assert_eq!(code, 0);
    assert_eq!(initial.len(), 1, "mirror of monitor.add STATUS");
    let mut last_seq = initial[0].0.seq;
    for (path, count) in [("r85.monitor.0", 1), ("r85.monitor.*", 4)] {
        let mut b = BlobBuf::new();
        b.put_string(attr::OBJPATH, path);
        let query = b.as_bytes().to_vec();
        let seq = owner.next_seq;
        let (code, data) = owner.request(ty::LOOKUP, 0, &mut b);
        assert_eq!(code, 0);
        assert_eq!(data.len(), count);
        let mut status = BlobBuf::new();
        status.put_u32(attr::STATUS, 0);
        let mut expected = vec![(ty::LOOKUP, false, query)];
        expected.extend(data.into_iter().map(|(h, blob)| {
            assert_eq!((h.ty, h.seq, h.peer), (ty::DATA, seq, 0));
            (ty::DATA, true, blob)
        }));
        expected.push((ty::STATUS, true, status.as_bytes().to_vec()));
        for (kind, send, blob) in expected {
            let (h, mirror) = monitor.recv().expect("lookup mirror");
            last_seq = last_seq.wrapping_add(1);
            assert_eq!((h.ty, h.seq), (ty::MONITOR, last_seq));
            let at = attrs(&mirror);
            assert_eq!(blob::iter(&mirror[4..]).map(|a| a.id).collect::<Vec<_>>(), [0, 1, 3, 4, 2, 5]);
            assert_eq!(at[4].and_then(|a| a.as_u32()), Some(kind as u32));
            assert_eq!(at[3].and_then(|a| a.as_u32()), Some(seq as u32));
            assert_eq!(at[2].unwrap().payload, &[u8::from(send)]);
            assert_eq!(at[5].unwrap().payload, &blob[4..]);
        }
    }
    let (code, final_mirrors) = monitor.invoke(MONITOR_OBJ, "remove", None);
    assert_eq!(code, 0);
    assert_eq!(final_mirrors.len(), 1, "only the remove request remains");
    println!("exact_data=1 prefix_data=4 mirror_order=true mirror_payloads=true mirror_sequences=true");
}

// Fixture ACL grants are supplied by r97_ubusd_method_acl.sh in its private
// namespace. Print observations even on the old failing daemon so the shell
// can compare all positive and negative controls against the actual C image.
fn method_acl(sock: &str) {
    let cases: &[(&str, &str, bool)] = &[
        ("r97.wire", "ping\0suffix", true),
        ("r97.denied", "denied\0ping", false),
        ("r97.config", "ping", true),
        ("r97.wildcard", "other", true),
        ("r97.empty", "\0suffix", true),
        ("r97.padding", "ab", true),
        ("r97.normal", "ping", true),
    ];
    let mut owner = Conn::open(sock);
    let mut signatures = Vec::new();
    for &(path, name, _) in cases {
        let mut raw = BlobBuf::new();
        let t = raw.msg_open_table(name);
        raw.msg_u32("policy", 5);
        raw.msg_close(t);
        let mut field = raw.payload().to_vec();
        if path == "r97.padding" { field[9..12].fill(0xa5); }
        let mut b = BlobBuf::new();
        b.put_string(attr::OBJPATH, path);
        let t = b.nest_start(attr::SIGNATURE);
        b.put_raw_fields(&field);
        b.nest_end(t);
        let (code, reply) = owner.request(ty::ADD_OBJECT, 0, &mut b);
        assert_eq!(code, 0);
        assert!(attrs(&reply[0].1)[attr::OBJTYPE as usize].is_some());
        let mut b = BlobBuf::new();
        b.put_string(attr::OBJPATH, path);
        let (code, frames) = owner.request(ty::LOOKUP, 0, &mut b);
        assert_eq!(code, 0);
        assert_eq!(frames.len(), 1);
        let signature = attrs(&frames[0].1)[attr::SIGNATURE as usize].unwrap().payload;
        let mut expected = BlobBuf::new();
        let t = expected.msg_open_table(name.split('\0').next().unwrap());
        expected.msg_u32("policy", 5);
        expected.msg_close(t);
        println!("root {path} canonical={}", signature == expected.payload());
        signatures.push(expected.payload().to_vec());
    }
    // Only this probe drops credentials; the publishing socket keeps the
    // root peer identity captured on accept by both daemons.
    owrt_ubus::sys::drop_privileges(65534, 65534).unwrap();
    let mut reader = Conn::open(sock);
    for ((path, _, expected), signature) in cases.iter().zip(signatures) {
        let mut b = BlobBuf::new();
        b.put_string(attr::OBJPATH, path);
        let (code, frames) = reader.request(ty::LOOKUP, 0, &mut b);
        assert_eq!(code, 0);
        assert!(frames.len() <= 1);
        let canonical = frames.first().is_none_or(|(h, reply)| {
            assert_eq!(h.ty, ty::DATA);
            attrs(reply)[attr::SIGNATURE as usize].unwrap().payload == signature
        });
        println!("nobody {path} visible={} expected={expected} canonical={canonical}", !frames.is_empty());
    }
}

#[cfg(target_os = "linux")]
fn fd_boundary(sock: &str, read_ahead_contract: bool) -> bool {
    use std::fs::File;
    use std::io::ErrorKind;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::time::Instant;

    // This receiver never reads beyond the current frame. A bulk receiver
    // would reproduce the very ambiguity this scenario is meant to detect.
    fn exact(conn: &Conn, buf: &mut [u8], fds: &mut Vec<OwnedFd>) {
        let mut offset = 0;
        while offset < buf.len() {
            match fd_sys::recvmsg_fd(conn.s.as_raw_fd(), &mut buf[offset..], true) {
                Ok((n, fd)) => {
                    assert!(n > 0, "FD probe: unexpected EOF");
                    fds.extend(fd);
                    offset += n;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => panic!("FD probe recvmsg: {error}"),
            }
        }
    }
    fn receive(conn: &Conn) -> (Header, Vec<u8>, Vec<OwnedFd>) {
        let mut prefix = [0u8; 12];
        let mut fds = Vec::new();
        exact(conn, &mut prefix, &mut fds);
        let header = Header::decode(prefix[..8].try_into().unwrap()).expect("FD probe header");
        let length = (u32::from_be_bytes(prefix[8..].try_into().unwrap()) & 0x00ff_ffff) as usize;
        assert!((4..=1_048_576).contains(&length), "FD probe frame length");
        let mut blob = prefix[8..].to_vec();
        blob.resize(length, 0);
        exact(conn, &mut blob[4..], &mut fds);
        (header, blob, fds)
    }
    fn frame(object: u32, seq: u16, method: &str) -> Vec<u8> {
        let mut blob = BlobBuf::new();
        blob.put_u32(attr::OBJID, object).put_string(attr::METHOD, method);
        let mut bytes = Header { ty: ty::INVOKE, seq, peer: 0 }.encode().to_vec();
        bytes.extend_from_slice(blob.as_bytes());
        bytes
    }
    fn send_fd(conn: &Conn, first: &[u8], second: &[u8], fd: &OwnedFd) {
        let sent = fd_sys::sendmsg_two(conn.s.as_raw_fd(), first, second, Some(fd.as_raw_fd()))
            .expect("FD fixture sendmsg");
        assert_eq!(sent, first.len() + second.len(), "partial FD fixture send");
    }
    fn fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").expect("probe fd directory")
            .map(|entry| entry.expect("probe fd entry")).count()
    }
    fn run_case(sock: &str, mode: &str) -> [usize; 2] {
        let mut provider = Conn::open(sock);
        let mut caller = Conn::open(sock);
        let object = provider.add_object(None, &["first", "second"]);
        let first = frame(object, 101, "first");
        let second = frame(object, 102, "second");
        let (read_fd, write_fd) = fd_sys::nonblocking_pipe().expect("witness pipe");
        let witness = b"r113-fd-boundary-witness";
        assert_eq!(owrt_platform::unix::write_fd(write_fd.as_raw_fd(), witness), witness.len() as isize);
        let mut received = Vec::new();
        match mode {
            "separate_waited" => {
                send_fd(&caller, &first, &[], &read_fd);
                received.push(receive(&provider));
                caller.s.write_all(&second).unwrap();
            }
            "separate_queued" => {
                send_fd(&caller, &first, &[], &read_fd);
                caller.s.write_all(&second).unwrap();
            }
            "plain_first_then_fd_second" => {
                caller.s.write_all(&first).unwrap();
                send_fd(&caller, &second, &[], &read_fd);
            }
            "bundled" => send_fd(&caller, &first, &second, &read_fd),
            "fd_in_first_body" => {
                caller.s.write_all(&first[..12]).unwrap();
                send_fd(&caller, &first[12..], &[], &read_fd);
                caller.s.write_all(&second).unwrap();
            }
            "fd_on_first_body_plus_second_frame" => {
                caller.s.write_all(&first[..12]).unwrap();
                send_fd(&caller, &first[12..], &second, &read_fd);
            }
            _ => unreachable!(),
        }
        drop(read_fd);
        while received.len() < 2 {
            received.push(receive(&provider));
        }
        let mut counts = [0; 2];
        let peer = received[0].0.peer;
        for (index, (header, blob, fds)) in received.into_iter().enumerate() {
            assert_eq!((header.ty, header.seq), (ty::INVOKE, 101 + index as u16));
            assert!(peer != 0 && header.peer == peer, "FD probe caller identity changed");
            let attributes = attrs(&blob);
            assert!(attributes[attr::OBJID as usize].and_then(|a| a.as_u32()) == Some(object));
            assert_eq!(attributes[attr::METHOD as usize].and_then(|a| a.as_str()),
                       Some(if index == 0 { "first" } else { "second" }));
            counts[index] = fds.len();
            for fd in fds {
                let mut file = File::from(fd);
                let mut bytes = [0; 24];
                file.read_exact(&mut bytes[..witness.len()]).expect("FD witness bytes");
                assert_eq!(&bytes[..witness.len()], witness);
                assert_eq!(file.read(&mut bytes[..1]).unwrap_err().kind(), ErrorKind::WouldBlock,
                           "unexpected extra witness data");
            }
        }
        assert!(counts.iter().sum::<usize>() <= 1, "duplicate received FD");
        // Keep the clients connected: EPIPE proves the daemon has released its
        // witness reference, rather than letting disconnect cleanup hide a leak.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let n = owrt_platform::unix::write_fd(write_fd.as_raw_fd(), b"!");
            if n < 0 && std::io::Error::last_os_error().kind() == ErrorKind::BrokenPipe {
                break;
            }
            assert!(n == 1, "unexpected witness pipe write result");
            assert!(Instant::now() < deadline, "daemon retained witness FD");
            std::thread::sleep(Duration::from_millis(10));
        }
        counts
    }

    fd_sys::ignore_signal(fd_sys::SIGPIPE);
    let baseline = fd_count();
    // C reads exactly a 12-byte prefix with recvmsg, then the body with
    // read, so body descriptors are discarded. Restore these assertions for
    // fd_boundary; read-ahead has its own explicit scenario below.
    //
    // Linux ancillary data forms a receive barrier (unix(7), Ancillary
    // messages): a read may include preceding plain bytes, but ends after
    // the descriptor-bearing data. These fixture writes fit in one read-ahead
    // buffer. R134 assigns the descriptor to the frame holding that read's
    // last byte unless that frame's prefix was already buffered.
    // https://man7.org/linux/man-pages/man7/unix.7.html
    let cases = [
        ("separate_waited", [1, 0], true),
        ("separate_queued", [1, 0], true),
        ("plain_first_then_fd_second", [0, 1], true),
        ("bundled", [1, 0], false),
        ("fd_in_first_body", [0, 0], false),
        ("fd_on_first_body_plus_second_frame", [0, 0], false),
    ];
    let mut compatible = true;
    for (mode, c_expected, sender_framed) in cases {
        let counts = run_case(sock, mode);
        assert_eq!(fd_count(), baseline, "probe leaked descriptors");
        let c_matches = counts == c_expected;
        let (matches, expectation) = if !read_ahead_contract || sender_framed {
            (c_matches, match c_expected { [1, 0] => "1,0", [0, 1] => "0,1", _ => "0,0" })
        } else {
            match mode {
                "bundled" | "fd_on_first_body_plus_second_frame" => (counts == [0, 1], "0,1"),
                // The sender does not synchronize between prefix and body.
                // If recvmsg first consumes just the plain prefix, R134
                // closes the later body FD. If one recvmsg includes both,
                // the last-byte frame is the first frame and receives it.
                "fd_in_first_body" => (counts == [0, 0] || counts == [1, 0], "0,0|1,0"),
                _ => unreachable!(),
            }
        };
        compatible &= matches;
        if sender_framed {
            // Byte-identical records allow C/R131/R134 framed comparison.
            println!("case={mode} invoke_order=first,second seq=101,102 fds={},{} witness=true no_leak=true compatible={matches}",
                     counts[0], counts[1]);
        } else {
            let contract = if read_ahead_contract { "read_ahead" } else { "c" };
            println!("case={mode} invoke_order=first,second seq=101,102 fds={},{} witness=true no_leak=true handcrafted contract={contract} expected={expectation} contract_match={matches} c_placement={c_matches}",
                     counts[0], counts[1]);
        }
    }
    println!("fd_boundary compatible={compatible} cases=6");
    compatible
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: wireprobe <socket> <pathless|events|monitor|release|remove_reply|aclquery|utf8|slowlookup|monitor_lookup|fd_boundary|fd_boundary_read_ahead>");
        std::process::exit(2);
    }
    let sock = &args[1];
    match args[2].as_str() {
        "pathless" => pathless(sock),
        "events" => events(sock),
        "object_events" => object_events(sock),
        "monitor" => monitor(sock),
        "release" => release(sock),
        "remove_reply" => remove_reply(sock),
        "aclquery" => aclquery(sock),
        "utf8" => utf8(sock),
        "slowlookup" => slowlookup(sock),
        "monitor_lookup" => monitor_lookup(sock),
        "method_acl" => method_acl(sock),
        #[cfg(target_os = "linux")]
        "fd_boundary" | "fd_boundary_read_ahead" => {
            if !fd_boundary(sock, args[2] == "fd_boundary_read_ahead") {
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("unknown scenario {other}");
            std::process::exit(2);
        }
    }
}
