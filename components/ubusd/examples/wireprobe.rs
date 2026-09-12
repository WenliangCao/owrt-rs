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
//!   aclquery  the blobmsg types inside `acl query`'s private acl table
//!             (needs an acl.d entry for root with an `acl` table on r83.priv)
//!   utf8      a STRING field carrying non-UTF-8 bytes crosses the bus intact
//!   slowlookup pause a >1 MiB LOOKUP, overwrite scratch via another client,
//!             then require every original frame in order after resuming

use owrt_ubus::blob::{self, Attr, BlobBuf, Field, MsgType};
use owrt_ubus::msg::{attr, ty, Header};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: wireprobe <socket> <pathless|events|monitor|release|aclquery|utf8|slowlookup|monitor_lookup>");
        std::process::exit(2);
    }
    let sock = &args[1];
    match args[2].as_str() {
        "pathless" => pathless(sock),
        "events" => events(sock),
        "monitor" => monitor(sock),
        "release" => release(sock),
        "aclquery" => aclquery(sock),
        "utf8" => utf8(sock),
        "slowlookup" => slowlookup(sock),
        "monitor_lookup" => monitor_lookup(sock),
        other => {
            eprintln!("unknown scenario {other}");
            std::process::exit(2);
        }
    }
}
