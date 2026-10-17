//! `/ubus` JSON-RPC 2.0 bridge with uhttpd's exact response shapes and error
//! codes, plus blobmsg <-> JSON conversion.

use crate::http::{Method, Request, Response, Sink};
use owrt_ubus::convert::{append_fields_json, fields_to_json, json_to_fields};
use owrt_ubus::json::{self, Json};
use owrt_ubus::{blob, BlobBuf, Connection};
use std::borrow::Cow;
use std::io::{self, Write};
use std::sync::Mutex;
use std::ops::{Deref, DerefMut};

pub const DEFAULT_SID: &str = "00000000000000000000000000000000";
pub const MAX_POST: usize = 65536;

#[derive(Clone, Copy)]
enum RpcError {
    Parse,
    Method,
    Params,
    Internal,
    Object,
    Access,
    Timeout,
}

impl RpcError {
    fn code_message(self) -> (i64, &'static str) {
        match self {
            RpcError::Parse => (-32700, "Parse error"),
            RpcError::Method => (-32601, "Method not found"),
            RpcError::Params => (-32602, "Invalid parameters"),
            RpcError::Internal => (-32603, "Internal error"),
            RpcError::Object => (-32000, "Object not found"),
            RpcError::Access => (-32002, "Access denied"),
            RpcError::Timeout => (-32003, "ubus request timed out"),
        }
    }
}

pub struct Bridge {
    pub socket: Option<String>,
    pub noauth: bool,
    pub cors: bool,
    pub timeout_ms: i32,
    pub events_retry: i32,
    pub record_calls: bool,
    pub idle: Mutex<Vec<Connection>>,
    /// object -> method -> count, exported for the stage-5 call inventory
    pub calls: Mutex<Vec<(String, String, u64)>>,
}

impl Bridge {
    fn connect(&self) -> io::Result<Lease<'_>> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(conn) = idle.pop() {
            if connected(&conn) { return Ok(Lease { conn: Some(conn), bridge: self }); }
        }
        drop(idle);
        Ok(Lease { conn: Some(Connection::connect(self.socket.as_deref())?), bridge: self })
    }

    fn record(&self, object: &str, method: &str) {
        if !self.record_calls { return; }
        if let Ok(mut calls) = self.calls.lock() {
            if let Some(entry) = calls
                .iter_mut()
                .find(|(o, m, _)| o == object && m == method)
            {
                entry.2 += 1;
            } else {
                calls.push((object.to_owned(), method.to_owned(), 1));
            }
        }
    }

    pub fn call_inventory(&self) -> String {
        let mut out = String::new();
        if let Ok(calls) = self.calls.lock() {
            let mut sorted = calls.clone();
            sorted.sort();
            for (object, method, count) in sorted {
                out.push_str(&format!("{object} {method} {count}\n"));
            }
        }
        out
    }
}

fn connected(conn: &Connection) -> bool {
    use owrt_ubus::sys::{poll_fds, PollFd, POLLHUP, POLLERR};
    let mut fds = [PollFd { fd: conn.as_raw_fd(), events: 0, revents: 0 }];
    poll_fds(&mut fds, 0).is_ok() && fds[0].revents & (POLLHUP | POLLERR) == 0
}

/// Reuse connections between calls without serialising long RPCs behind one
/// mutex. A checked-out connection belongs to one HTTP worker until its reply.
struct Lease<'a> {
    conn: Option<Connection>,
    bridge: &'a Bridge,
}

impl Deref for Lease<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection { self.conn.as_ref().expect("live lease") }
}
impl DerefMut for Lease<'_> {
    fn deref_mut(&mut self) -> &mut Connection { self.conn.as_mut().expect("live lease") }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        // A reply that arrived after its call timed out sits in `pending`
        // and nothing on the bridge ever reads it; keeping such a connection
        // would retain one stale reply per timeout (R88 httpd H-06).
        if let Some(conn) = self.conn.take().filter(|c| !c.has_pending() && connected(c)) {
            let mut idle = self.bridge.idle.lock().unwrap_or_else(|e| e.into_inner());
            if idle.len() < 8 { idle.push(conn); }
        }
    }
}

fn signature_to_json(signature: &[u8]) -> Json {
    Json::Object(
        blob::fields(signature)
            .map(|method| {
                let args = method
                    .children()
                    .map(|arg| {
                        let kind = match arg.as_u32().unwrap_or(0) {
                            7 => "boolean",
                            5 => "number",
                            3 => "string",
                            1 => "array",
                            2 => "object",
                            _ => "unknown",
                        };
                        (arg.name.to_owned(), Json::Str(kind.to_owned()))
                    })
                    .collect();
                (method.name.to_owned(), Json::Object(args))
            })
            .collect(),
    )
}

fn rpc_id(obj: Option<&Json>) -> Json {
    obj.and_then(|o| o.get("id")).cloned().unwrap_or(Json::Null)
}

/// Successful calls already own their complete wire envelope. Other methods
/// keep variable JSON values until serialization; batch output stays lazy.
enum RpcResponse {
    Json { id: Json, error: bool, value: Json },
    Encoded(Vec<u8>),
}

fn append_rpc_header(out: &mut Vec<u8>, id: &Json, error: bool) {
    out.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":");
    id.append_to(out);
    out.extend_from_slice(if error { b",\"error\":" } else { b",\"result\":" });
}

impl RpcResponse {
    fn append_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::Json { id, error, value } => {
                append_rpc_header(out, id, *error);
                value.append_to(out);
                out.push(b'}');
            }
            Self::Encoded(bytes) => out.extend_from_slice(bytes),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        if let Self::Encoded(bytes) = self { return bytes; }
        let mut out = Vec::with_capacity(128);
        self.append_to(&mut out);
        out
    }
}

fn rpc_batch(responses: impl Iterator<Item = RpcResponse>, mut emit: impl FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
    let mut out = Vec::with_capacity(128);
    emit(b"[")?;
    for (index, response) in responses.enumerate() {
        out.clear();
        if index != 0 { out.push(b','); }
        response.append_to(&mut out);
        // One reply at a time: a blocked HTTP writer stops evaluating later
        // RPCs instead of materialising a batch-sized response in memory.
        emit(&out)?;
    }
    emit(b"]")
}

fn rpc_error(id: Json, error: RpcError) -> RpcResponse {
    let (code, message) = error.code_message();
    RpcResponse::Json { id, error: true, value: Json::Object(vec![
        ("code".into(), Json::Int(code)),
        ("message".into(), Json::Str(message.into())),
    ]) }
}

fn rpc_result(id: Json, result: Json) -> RpcResponse {
    RpcResponse::Json { id, error: false, value: result }
}

/// Most replies carry a single DATA attr. Borrow that payload; multiple DATA
/// attrs still use the exact concatenation semantics of Reply::fields().
fn reply_fields(reply: &owrt_ubus::Reply) -> Cow<'_, [u8]> {
    let mut fields = reply.data.iter().flat_map(|payload| blob::iter(payload))
        .filter(|attr| attr.id == owrt_ubus::attr::DATA);
    let Some(first) = fields.next() else { return Cow::Borrowed(&[]) };
    if fields.next().is_none() {
        Cow::Borrowed(first.payload)
    } else {
        Cow::Owned(reply.fields())
    }
}

fn allowed(
    conn: &mut Connection,
    bridge: &Bridge,
    sid: &str,
    object: &str,
    function: &str,
) -> bool {
    let Ok(session_id) = conn.lookup_id("session", bridge.timeout_ms) else {
        return false;
    };
    let mut b = BlobBuf::new();
    b.msg_string("ubus_rpc_session", sid)
        .msg_string("object", object)
        .msg_string("function", function);
    match conn.invoke(session_id, "access", b.payload(), bridge.timeout_ms / 2) {
        Ok(reply) => {
            blob::fields(&reply_fields(&reply)).any(|f| f.name == "access" && f.as_bool() == Some(true))
        }
        Err(_) => false,
    }
}

/// Execute one `call`, returning the JSON-RPC response object.
fn do_call(
    bridge: &Bridge,
    id: Json,
    sid: &str,
    object: &str,
    function: &str,
    args: &Json,
    legacy: bool,
) -> RpcResponse {
    let Ok(mut conn) = bridge.connect() else {
        // The C lookup_id fails when its bus is disconnected too.
        return rpc_error(id, RpcError::Object);
    };
    let Ok(objid) = conn.lookup_id(object, bridge.timeout_ms) else {
        return rpc_error(id, RpcError::Object);
    };
    if !bridge.noauth && !allowed(&mut conn, bridge, sid, object, function) {
        return rpc_error(id, RpcError::Access);
    }
    if let Json::Object(items) = args {
        if items.iter().any(|(k, _)| k == "ubus_rpc_session") {
            return rpc_error(id, RpcError::Params);
        }
    }
    bridge.record(object, function);
    let mut b = BlobBuf::new();
    if let Json::Object(items) = args {
        for (name, value) in items {
            json_to_fields(&mut b, name, value);
        }
    }
    b.msg_string("ubus_rpc_session", sid);
    match conn.invoke_status(objid, function, b.payload(), bridge.timeout_ms) {
        Err(e) if e.to_string().contains("timed out") => rpc_error(id, RpcError::Timeout),
        Err(_) => rpc_error(id, RpcError::Internal),
        Ok(reply) => rpc_call_result(id, legacy, &reply),
    }
}

fn rpc_call_result(id: Json, legacy: bool, reply: &owrt_ubus::Reply) -> RpcResponse {
    if !legacy && reply.status != 0 {
        return RpcResponse::Json { id, error: true, value: Json::Object(vec![
            ("code".into(), Json::Int(reply.status as i64)),
            ("message".into(), Json::Str(owrt_ubus::status::name(reply.status))),
        ]) };
    }
    let data = reply_fields(reply);
    let has_data = !data.is_empty();
    // Encode into the final envelope while the reply and connection lease
    // still have their original lifetimes. Single calls can move this buffer
    // to HTTP output; batch calls append it before their per-result flush.
    // Blob length is a useful estimate for ordinary replies (as in libubox).
    // Bound the initial reservation: a large malformed or non-string field
    // can render as a very short value. Escaped output may still grow normally.
    let mut out = Vec::with_capacity(data.len().clamp(128, 32 * 1024));
    append_rpc_header(&mut out, &id, false);
    if legacy {
        out.push(b'[');
        Json::Int(reply.status as i64).append_to(&mut out);
        if has_data { out.push(b','); }
    }
    if has_data {
        append_fields_json(&data, &mut out);
    } else if !legacy {
        out.extend_from_slice(b"null");
    }
    if legacy { out.push(b']'); }
    out.push(b'}');
    RpcResponse::Encoded(out)
}

fn do_list(bridge: &Bridge, id: Json, params: Option<&Json>) -> RpcResponse {
    let Ok(mut conn) = bridge.connect() else {
        return rpc_error(id, RpcError::Internal);
    };
    match params {
        Some(Json::Array(paths)) => {
            let mut table = Vec::new();
            for path in paths {
                if let Some(path) = path.as_str() {
                    if let Ok(entries) = conn.lookup(Some(path), bridge.timeout_ms) {
                        for entry in entries {
                            table.push((entry.path, signature_to_json(&entry.signature)));
                        }
                    }
                }
            }
            rpc_result(id, Json::Object(table))
        }
        _ => {
            let names = conn
                .lookup(None, bridge.timeout_ms)
                .map(|entries| entries.into_iter().map(|e| Json::Str(e.path)).collect())
                .unwrap_or_default();
            rpc_result(id, Json::Array(names))
        }
    }
}

/// Handle one JSON-RPC request object (POST /ubus body element).
fn handle_object(bridge: &Bridge, obj: &Json, legacy: bool) -> RpcResponse {
    let id = rpc_id(Some(obj));
    let Json::Object(_) = obj else {
        return rpc_error(id, RpcError::Parse);
    };
    if obj.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
        return rpc_error(id, RpcError::Parse);
    }
    let Some(method) = obj.get("method").and_then(Json::as_str) else {
        return rpc_error(id, RpcError::Parse);
    };
    match method {
        "call" => {
            let params = obj.get("params").and_then(Json::as_array).unwrap_or(&[]);
            let sid = params.first().and_then(Json::as_str);
            let sid = match sid {
                Some(s) if !s.is_empty() => s,
                _ if bridge.noauth => DEFAULT_SID,
                Some(s) => s,
                None => return rpc_error(id, RpcError::Parse),
            };
            let object = params.get(1).and_then(Json::as_str);
            let function = params.get(2).and_then(Json::as_str);
            let args = params.get(3);
            let (Some(object), Some(function), Some(args @ Json::Object(_))) =
                (object, function, args)
            else {
                return rpc_error(id, RpcError::Parse);
            };
            do_call(bridge, id, sid, object, function, args, legacy)
        }
        "list" => do_list(bridge, id, obj.get("params")),
        _ => rpc_error(id, RpcError::Method),
    }
}

fn cors_headers<W: Write>(resp: &mut Response<W>, bridge: &Bridge, request: &Request) -> io::Result<()> {
    if bridge.cors {
        if let Some(origin) = request.header("origin") {
            let ok = request
                .header("access-control-request-method")
                .map(|m| matches!(m, "GET" | "POST" | "OPTIONS"))
                .unwrap_or(true);
            if ok {
                resp.header("Access-Control-Allow-Origin", origin)?;
                if let Some(h) = request.header("access-control-request-headers") {
                    resp.header("Access-Control-Allow-Headers", h)?;
                }
                resp.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
                resp.header("Access-Control-Allow-Credentials", "true")?;
            }
        }
    }
    Ok(())
}

fn send_json<W: Write>(
    resp: &mut Response<W>,
    bridge: &Bridge,
    request: &Request,
    code: u16,
    summary: &str,
    body: impl AsRef<[u8]>,
) -> io::Result<()> {
    resp.status(code, summary)?;
    cors_headers(resp, bridge, request)?;
    resp.header("Content-Type", "application/json")?;
    if request.method == Method::Options {
        resp.header("Content-Length", "0")?;
    }
    resp.end_headers()?;
    resp.body(body.as_ref())?;
    resp.finish()
}

fn error_only(error: RpcError) -> Vec<u8> {
    rpc_error(Json::Null, error).into_bytes()
}

/// uh_ubus_data_send's failure exit (ubus.c:944-952): the body could not be
/// taken -- no body at all, or more than UH_UBUS_MAX_POST_SIZE of it -- so the
/// connection is dropped (the unread suffix would otherwise be read as the next
/// request) and the client still gets a well-formed JSON-RPC parse error under
/// a 200, not an HTML page.
pub fn parse_error<W: Write>(
    bridge: &Bridge,
    request: &Request,
    resp: &mut Response<W>,
) -> io::Result<()> {
    resp.force_close();
    send_json(resp, bridge, request, 200, "OK", error_only(RpcError::Parse))
}

/// Entry point for any request under the ubus prefix.
pub fn handle<W: Sink>(
    bridge: &Bridge,
    prefix: &str,
    request: &Request,
    body: Option<&[u8]>,
    resp: &mut Response<W>,
) -> io::Result<()> {
    let path = request.url.split('?').next().unwrap_or("");
    let rest = &path[prefix.len()..];
    match request.method {
        Method::Options => send_json(resp, bridge, request, 200, "OK", ""),
        Method::Get => {
            if let Some(object) = rest.strip_prefix("/subscribe/") {
                return subscribe(bridge, request, resp, object);
            }
            if rest == "/list" || rest.starts_with("/list/") {
                let target = rest
                    .strip_prefix("/list")
                    .and_then(|r| r.strip_prefix('/'))
                    .filter(|s| !s.is_empty());
                let Ok(mut conn) = bridge.connect() else {
                    return send_json(
                        resp,
                        bridge,
                        request,
                        500,
                        "Ubus Protocol Error",
                        Json::Object(vec![
                            // ubus_lookup returns INVALID_ARGUMENT when
                            // ubus_start_request fails on a disconnected fd.
                            ("code".into(), Json::Int(2)),
                            ("message".into(), Json::Str("Invalid argument".into())),
                        ])
                        .to_bytes(),
                    );
                };
                match conn.lookup(target, bridge.timeout_ms) {
                    Ok(entries) => {
                        let json = if target.is_some() {
                            entries
                                .first()
                                .map(|e| signature_to_json(&e.signature))
                                .unwrap_or(Json::Object(vec![]))
                        } else {
                            Json::Object(
                                entries
                                    .into_iter()
                                    .map(|e| (e.path.clone(), signature_to_json(&e.signature)))
                                    .collect(),
                            )
                        };
                        send_json(resp, bridge, request, 200, "OK", json.to_bytes())
                    }
                    Err(error) => {
                        let code = owrt_ubus::conn::error_status(&error)
                            .unwrap_or(owrt_ubus::status::CONNECTION_FAILED);
                        send_json(
                        resp,
                        bridge,
                        request,
                        500,
                        "Ubus Protocol Error",
                        Json::Object(vec![
                            ("code".into(), Json::Int(code as i64)),
                            ("message".into(), Json::Str(owrt_ubus::status::name(code).into())),
                        ])
                        .to_bytes(),
                    )
                    },
                }
            } else {
                resp.status(404, "Not Found")?;
                resp.end_headers()?;
                resp.finish()
            }
        }
        Method::Post => {
            let Some(body) = body else {
                return parse_error(bridge, request, resp);
            };
            if body.len() > MAX_POST {
                return parse_error(bridge, request, resp);
            }
            // uhttpd hands the body to json_tokener_parse: trailing data after the
            // first value is ignored
            let parsed = json::parse_prefix_bytes(body).ok();
            if rest.is_empty() || rest == "/" {
                return match parsed {
                    Some(obj @ Json::Object(_)) => {
                        let out = handle_object(bridge, &obj, true).into_bytes();
                        send_json(resp, bridge, request, 200, "OK", &out)
                    }
                    Some(Json::Array(items)) => {
                        resp.status(200, "OK")?;
                        cors_headers(resp, bridge, request)?;
                        resp.header("Content-Type", "application/json")?;
                        resp.end_headers()?;
                        rpc_batch(items.iter().map(|item| handle_object(bridge, item, true)), |bytes| {
                            resp.body(bytes)?;
                            resp.sink().flush()
                        })?;
                        resp.finish()
                    }
                    _ => send_json(
                        resp,
                        bridge,
                        request,
                        200,
                        "OK",
                        error_only(RpcError::Parse),
                    ),
                };
            }
            if let Some(object) = rest.strip_prefix("/call/") {
                let sid = request
                    .header("authorization")
                    .and_then(|a| {
                        a.get(..7)
                            .filter(|prefix| prefix.eq_ignore_ascii_case("Bearer "))
                            .map(|_| &a[7..])
                    })
                    .unwrap_or(DEFAULT_SID);
                let out = match parsed {
                    Some(obj @ Json::Object(_)) => {
                        let id = rpc_id(Some(&obj));
                        if obj.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
                            rpc_error(id, RpcError::Parse)
                        } else if let Some(method) = obj.get("method").and_then(Json::as_str) {
                            let empty = Json::Object(vec![]);
                            let args = obj.get("params").unwrap_or(&empty);
                            do_call(bridge, id, sid, object, method, args, false)
                        } else {
                            rpc_error(id, RpcError::Parse)
                        }
                    }
                    _ => rpc_error(Json::Null, RpcError::Parse),
                };
                return send_json(resp, bridge, request, 200, "OK", out.into_bytes());
            }
            resp.status(404, "Not Found")?;
            resp.end_headers()?;
            resp.finish()
        }
        _ => resp.error(400, "Bad Request", Some("Invalid Request")),
    }
}

fn subscribe<W: Sink>(bridge: &Bridge, request: &Request, resp: &mut Response<W>, object: &str) -> io::Result<()> {
    use owrt_ubus::{attr, status, ty, Incoming};
    use owrt_ubus::sys::{poll_fds, PollFd, POLLIN, POLLHUP, POLLERR};
    // A subscription owns its socket until the HTTP client disconnects. It
    // must never return a registered subscriber to the ordinary request pool.
    let mut conn = Connection::connect(bridge.socket.as_deref())?;
    let sid = request.header("authorization").and_then(|value| {
        value.get(..7).filter(|prefix| prefix.eq_ignore_ascii_case("Bearer ")).map(|_| &value[7..])
    }).unwrap_or(DEFAULT_SID);
    let error = |code: i32, message: String| Json::Object(vec![
        ("code".into(), Json::Int(code as i64)), ("message".into(), Json::Str(message)),
    ]).to_bytes();
    if !bridge.noauth && !allowed(&mut conn, bridge, sid, object, ":subscribe") {
        return send_json(resp, bridge, request, 200, "OK", error(-13, "Permission denied".into()));
    }
    let subscriber = match conn.add_anonymous_object(bridge.timeout_ms) {
        Ok(id) => id,
        Err(_) => return send_json(resp, bridge, request, 200, "OK", error(status::UNKNOWN_ERROR, status::name(status::UNKNOWN_ERROR))),
    };
    let target = match conn.lookup_id(object, bridge.timeout_ms) {
        Ok(target) => target,
        Err(_) => return send_json(resp, bridge, request, 200, "OK", error(status::NOT_FOUND, status::name(status::NOT_FOUND))),
    };
    if conn.subscribe(subscriber, target, bridge.timeout_ms).is_err() {
        return send_json(resp, bridge, request, 200, "OK", error(status::UNKNOWN_ERROR, status::name(status::UNKNOWN_ERROR)));
    }
    resp.status(200, "OK")?;
    cors_headers(resp, bridge, request)?;
    resp.header("Content-Type", "text/event-stream")?;
    resp.end_headers()?;
    if bridge.events_retry != 0 {
        resp.body(format!("retry: {}\n", bridge.events_retry).as_bytes())?;
    }
    resp.sink().flush()?;
    loop {
        // Drain queued notifications before waiting on the descriptors.
        while let Some(incoming) = conn.next_incoming(0)? {
            match incoming {
                Incoming::Invoke(req) if req.objid == subscriber => {
                    resp.body(format!("event: {}\ndata: ", req.method).as_bytes())?;
                    resp.body(&fields_to_json(&req.data).to_bytes())?;
                    resp.body(b"\n\n")?;
                    resp.sink().flush()?;
                    conn.reply_status(&req, status::OK, None)?;
                }
                Incoming::Other(message) if message.header.ty == ty::UNSUBSCRIBE => {
                    let attrs = message.attrs();
                    if attrs[attr::OBJID as usize].and_then(|a| a.as_u32()) == Some(subscriber) {
                        return resp.finish();
                    }
                }
                _ => {}
            }
        }
        const POLLRDHUP: i16 = 0x2000;
        let mut fds = [
            PollFd { fd: conn.as_raw_fd(), events: POLLIN, revents: 0 },
            PollFd { fd: resp.sink().fd(), events: POLLRDHUP, revents: 0 },
        ];
        poll_fds(&mut fds, -1)?;
        if fds[1].revents & (POLLRDHUP | POLLHUP | POLLERR) != 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "subscriber disconnected"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_envelopes_preserve_bytes_ids_errors_and_batch_order() {
        let result = rpc_result(Json::Bytes(b"id\xff\"".to_vec()),
                                Json::Array(vec![Json::Int(0), Json::Bytes(b"a\n\x80".to_vec())]));
        let expected = b"{\"jsonrpc\":\"2.0\",\"id\":\"id\xff\\\"\",\"result\":[0,\"a\\n\x80\"]}";
        let mut prefixed = b"prefix".to_vec();
        result.append_to(&mut prefixed);
        assert_eq!(&prefixed[..6], b"prefix");
        assert_eq!(&prefixed[6..], expected);
        assert_eq!(result.into_bytes(), expected);

        let failure = rpc_error(Json::Null, RpcError::Parse);
        assert_eq!(rpc_error(Json::Null, RpcError::Parse).into_bytes(),
                   br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#);
        let collect = |items: Vec<RpcResponse>| {
            let mut out = Vec::new();
            rpc_batch(items.into_iter(), |bytes| { out.extend_from_slice(bytes); Ok(()) }).unwrap();
            out
        };
        assert_eq!(collect(vec![]), b"[]");
        let batch = collect(vec![rpc_result(Json::Int(1), Json::Null), failure]);
        assert_eq!(batch,
                   br#"[{"jsonrpc":"2.0","id":1,"result":null},{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}]"#);
        let large = rpc_result(Json::Array(vec![Json::Bool(true)]), Json::Str("x".repeat(8192)));
        let parsed = json::parse_bytes(&large.into_bytes()).unwrap();
        assert_eq!(parsed.get("id"), Some(&Json::Array(vec![Json::Bool(true)])));
        assert_eq!(parsed.get("result").and_then(Json::as_str), Some("x".repeat(8192).as_str()));
    }

    #[test]
    fn call_envelopes_preserve_status_empty_data_and_wire_bytes() {
        use owrt_ubus::{attr, Reply};
        let id = Json::Array(vec![Json::Bytes(b"id\xff\"".to_vec()), Json::Int(-3)]);
        let mut fields = BlobBuf::new();
        fields.msg_string_bytes("raw", b"a\xff\n");
        let mut data = BlobBuf::new();
        data.put(attr::DATA, fields.payload());
        let mut malformed = BlobBuf::new();
        malformed.put(attr::DATA, &[0]);
        for payloads in [vec![], vec![data.into_payload()], vec![malformed.into_payload()]] {
            for status in [0, owrt_ubus::status::PERMISSION_DENIED] {
                for legacy in [false, true] {
                    let reply = Reply { status, data: payloads.clone(), fd: None };
                    let fields = reply_fields(&reply);
                    let has_data = !fields.is_empty();
                    let expected = if !legacy && status != 0 {
                        RpcResponse::Json { id: id.clone(), error: true, value: Json::Object(vec![
                            ("code".into(), Json::Int(status as i64)),
                            ("message".into(), Json::Str(owrt_ubus::status::name(status))),
                        ]) }
                    } else if legacy {
                        let mut result = vec![Json::Int(status as i64)];
                        if has_data { result.push(fields_to_json(&fields)); }
                        rpc_result(id.clone(), Json::Array(result))
                    } else {
                        rpc_result(id.clone(), if has_data { fields_to_json(&fields) } else { Json::Null })
                    }.into_bytes();
                    let response = rpc_call_result(id.clone(), legacy, &reply);
                    let mut appended = b"prefix".to_vec();
                    response.append_to(&mut appended);
                    assert_eq!(&appended[6..], expected);
                    assert_eq!(response.into_bytes(), expected);
                }
            }
        }
        // A large DATA value that contains no valid fields renders briefly;
        // the initial estimate must not reserve its entire received size.
        let mut malformed = BlobBuf::new();
        malformed.put(attr::DATA, &vec![0; 128 * 1024]);
        let bytes = rpc_call_result(Json::Null, false,
            &Reply { status: 0, data: vec![malformed.into_payload()], fd: None }).into_bytes();
        assert_eq!(bytes, br#"{"jsonrpc":"2.0","id":null,"result":{}}"#);
        assert!(bytes.capacity() <= 32 * 1024);
        // The encoded fast path returns its original allocation to the caller.
        let response = rpc_call_result(Json::Int(1), true,
            &Reply { status: 0, data: vec![], fd: None });
        let RpcResponse::Encoded(ref bytes) = response else { panic!("call not encoded") };
        let allocation = bytes.as_ptr();
        let returned = response.into_bytes();
        assert_eq!(returned.as_ptr(), allocation);
    }

    #[test]
    fn a_failed_batch_writer_stops_before_executing_the_next_rpc() {
        let never = std::iter::once_with(|| panic!("RPC ran after opening write failed"));
        assert!(rpc_batch(never, |_| Err(io::Error::from(io::ErrorKind::BrokenPipe))).is_err());
        let mut handled = 0;
        let responses = (0..100).map(|id| {
            handled += 1;
            rpc_result(Json::Int(id), Json::Str("x".repeat(32768)))
        });
        let mut writes = 0;
        let result = rpc_batch(responses, |_| {
            writes += 1;
            if writes == 2 { Err(io::Error::from(io::ErrorKind::BrokenPipe)) } else { Ok(()) }
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(handled, 1);
    }

    #[test]
    fn reply_data_keeps_order_and_concatenation_across_messages() {
        use owrt_ubus::{attr, Reply};
        let mut fields = BlobBuf::new();
        fields.msg_bool("access", true).msg_string("value", "data");
        let data = fields.payload();
        let reply = |chunks: Vec<Vec<u8>>| Reply { status: 0, data: chunks, fd: None };
        let mut one = BlobBuf::new();
        one.put_u32(attr::OBJID, 17).put(attr::DATA, data);
        let single = reply(vec![one.into_payload()]);
        assert_eq!(&*reply_fields(&single), data);
        assert!(matches!(reply_fields(&single), Cow::Borrowed(_)));
        assert!(reply_fields(&reply(Vec::new())).is_empty());

        // A field split between DATA attrs must still be reassembled exactly,
        // even across messages or alongside unrelated protocol attrs.
        for split in 0..=data.len() {
            let mut first = BlobBuf::new();
            first.put(attr::DATA, &data[..split]).put_u32(attr::OBJID, 17);
            let mut second = BlobBuf::new();
            second.put(attr::DATA, &data[split..]);
            let multiple = reply(vec![first.into_payload(), second.into_payload()]);
            assert_eq!(&*reply_fields(&multiple), data, "split at {split}");
            assert_eq!(fields_to_json(&reply_fields(&multiple)), fields_to_json(data));
        }
    }
}
