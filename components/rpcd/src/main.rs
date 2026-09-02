//! rpcd-rs: the `file` and `luci` ubus objects (contract C5) as a standalone
//! object server next to the original rpcd, which keeps session/uci/rc.

mod file;
mod luci;
mod util;

use owrt_ubus::convert::{fields_to_json, object_to_payload};
use owrt_ubus::json::Json;
use owrt_ubus::{status, BlobBuf, Connection, Incoming, MsgType};

pub struct Ctx {
    pub socket: Option<String>,
    pub exec_timeout_ms: i32,
}

impl Ctx {
    /// `ops->session_access(sid, "file", path, perm)` through the original
    /// rpcd's `session access`. No session id means a local root caller.
    pub fn file_access(&self, sid: Option<&str>, path: &str, perm: &str) -> bool {
        let Some(sid) = sid else { return true };
        let Ok(mut conn) = Connection::connect(self.socket.as_deref()) else { return false };
        let Ok(id) = conn.lookup_id("session", 3000) else { return false };
        let mut b = BlobBuf::new();
        b.msg_string("ubus_rpc_session", sid)
            .msg_string("scope", "file")
            .msg_string("object", path)
            .msg_string("function", perm);
        match conn.invoke(id, "access", b.payload(), 5000) {
            Ok(reply) => fields_to_json(&reply.fields()).get("access") == Some(&Json::Bool(true)),
            Err(_) => false,
        }
    }

    /// Plain ubus call helper for the luci methods.
    pub fn ubus_call(&self, object: &str, method: &str, args: Option<&Json>) -> Option<Json> {
        let mut conn = Connection::connect(self.socket.as_deref()).ok()?;
        let id = conn.lookup_id(object, 3000).ok()?;
        let payload = args.map(object_to_payload).unwrap_or_default();
        let reply = conn.invoke_status(id, method, &payload, 30000).ok()?;
        if reply.status != 0 {
            return None;
        }
        Some(fields_to_json(&reply.fields()))
    }
}

fn sig_of(methods: &[(&'static str, Vec<(&'static str, MsgType)>)]) -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    methods.to_vec()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut socket = None;
    let mut timeout_ms = 120_000;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-s" => socket = args.next(),
            "-t" => {
                if let Some(t) = args.next().and_then(|t| t.parse::<i64>().ok()) {
                    if (1..=600).contains(&t) {
                        timeout_ms = (t * 1000) as i32;
                    } else {
                        eprintln!("Invalid execution timeout specified");
                        std::process::exit(1);
                    }
                }
            }
            _ => {}
        }
    }
    let ctx = Ctx { socket: socket.clone(), exec_timeout_ms: timeout_ms };
    let mut conn = match Connection::connect(socket.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to ubus: {e}");
            std::process::exit(1);
        }
    };
    let file_sig = sig_of(&file::signature());
    let luci_sig = sig_of(&luci::signature());
    let to_ref = |v: &Vec<(&'static str, Vec<(&'static str, MsgType)>)>| -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> { v.clone() };
    let file_methods: Vec<(&str, Vec<(&str, MsgType)>)> = to_ref(&file_sig);
    let file_refs: Vec<(&str, &[(&str, MsgType)])> = file_methods.iter().map(|(n, p)| (*n, p.as_slice())).collect();
    let luci_methods: Vec<(&str, Vec<(&str, MsgType)>)> = to_ref(&luci_sig);
    let luci_refs: Vec<(&str, &[(&str, MsgType)])> = luci_methods.iter().map(|(n, p)| (*n, p.as_slice())).collect();
    let file_id = conn.add_object("file", &file_refs, 5000).unwrap_or_else(|e| {
        eprintln!("Failed to register object 'file': {e}");
        std::process::exit(1);
    });
    let luci_id = conn.add_object("luci", &luci_refs, 5000).unwrap_or_else(|e| {
        eprintln!("Failed to register object 'luci': {e}");
        std::process::exit(1);
    });
    loop {
        let incoming = match conn.next_incoming(-1) {
            Ok(Some(i)) => i,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("ubus connection lost: {e}");
                std::process::exit(1);
            }
        };
        let Incoming::Invoke(req) = incoming else { continue };
        let args = fields_to_json(&req.data);
        let result = if req.objid == file_id {
            file::call(&ctx, &req.method, &args)
        } else if req.objid == luci_id {
            luci::call(&ctx, &req.method, &args)
        } else {
            Err(status::NOT_FOUND)
        };
        match result {
            Ok(Some(data)) => {
                let _ = conn.reply_data(&req, &object_to_payload(&data));
                let _ = conn.reply_status(&req, status::OK, None);
            }
            Ok(None) => {
                let _ = conn.reply_status(&req, status::OK, None);
            }
            Err(code) => {
                let _ = conn.reply_status(&req, code, None);
            }
        }
    }
}
