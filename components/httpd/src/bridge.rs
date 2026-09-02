//! `/ubus` JSON-RPC 2.0 bridge with uhttpd's exact response shapes and error
//! codes, plus blobmsg <-> JSON conversion.

use crate::http::{Method, Request, Response};
use owrt_ubus::convert::{fields_to_json, object_to_payload};
use owrt_ubus::json::{self, Json};
use owrt_ubus::{blob, BlobBuf, Connection};
use std::io::{self, Write};
use std::sync::Mutex;

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
    /// object -> method -> count, exported for the stage-5 call inventory
    pub calls: Mutex<Vec<(String, String, u64)>>,
}

impl Bridge {
    fn connect(&self) -> io::Result<Connection> {
        Connection::connect(self.socket.as_deref())
    }

    fn record(&self, object: &str, method: &str) {
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

fn rpc_error(id: Json, error: RpcError) -> Json {
    let (code, message) = error.code_message();
    Json::Object(vec![
        ("jsonrpc".into(), Json::Str("2.0".into())),
        ("id".into(), id),
        (
            "error".into(),
            Json::Object(vec![
                ("code".into(), Json::Int(code)),
                ("message".into(), Json::Str(message.into())),
            ]),
        ),
    ])
}

fn rpc_result(id: Json, result: Json) -> Json {
    Json::Object(vec![
        ("jsonrpc".into(), Json::Str("2.0".into())),
        ("id".into(), id),
        ("result".into(), result),
    ])
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
            blob::fields(&reply.fields()).any(|f| f.name == "access" && f.as_bool() == Some(true))
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
) -> Json {
    let Ok(mut conn) = bridge.connect() else {
        return rpc_error(id, RpcError::Internal);
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
    let mut payload = object_to_payload(args);
    let mut b = BlobBuf::new();
    b.put_raw_fields(&payload);
    b.msg_string("ubus_rpc_session", sid);
    payload = b.into_payload();
    match conn.invoke_status(objid, function, &payload, bridge.timeout_ms) {
        Err(e) if e.to_string().contains("timed out") => rpc_error(id, RpcError::Timeout),
        Err(_) => rpc_error(id, RpcError::Internal),
        Ok(reply) => {
            let data = reply.fields();
            let has_data = !data.is_empty();
            if legacy {
                let mut result = vec![Json::Int(reply.status as i64)];
                if has_data {
                    result.push(fields_to_json(&data));
                }
                return rpc_result(id, Json::Array(result));
            }
            if reply.status != 0 {
                return Json::Object(vec![
                    ("jsonrpc".into(), Json::Str("2.0".into())),
                    ("id".into(), id),
                    (
                        "error".into(),
                        Json::Object(vec![
                            ("code".into(), Json::Int(reply.status as i64)),
                            (
                                "message".into(),
                                Json::Str(owrt_ubus::status::name(reply.status).into()),
                            ),
                        ]),
                    ),
                ]);
            }
            if has_data {
                rpc_result(id, fields_to_json(&data))
            } else {
                rpc_result(id, Json::Null)
            }
        }
    }
}

fn do_list(bridge: &Bridge, id: Json, params: Option<&Json>) -> Json {
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
fn handle_object(bridge: &Bridge, obj: &Json, legacy: bool) -> Json {
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
            let sid = params.first().and_then(Json::as_str).map(str::to_owned);
            let sid = match sid {
                Some(s) if !s.is_empty() => s,
                _ if bridge.noauth => DEFAULT_SID.to_owned(),
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
            do_call(bridge, id, &sid, object, function, args, legacy)
        }
        "list" => do_list(bridge, id, obj.get("params")),
        _ => rpc_error(id, RpcError::Method),
    }
}

fn send_json<W: Write>(
    resp: &mut Response<W>,
    bridge: &Bridge,
    request: &Request,
    code: u16,
    summary: &str,
    body: &str,
) -> io::Result<()> {
    resp.status(code, summary)?;
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
    resp.header("Content-Type", "application/json")?;
    if request.method == Method::Options {
        resp.header("Content-Length", "0")?;
    }
    resp.end_headers()?;
    resp.body(body.as_bytes())?;
    resp.finish()
}

fn error_only(error: RpcError) -> String {
    rpc_error(Json::Null, error).to_compact()
}

/// Entry point for any request under the ubus prefix.
pub fn handle<W: Write>(
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
                        &Json::Object(vec![
                            ("code".into(), Json::Int(10)),
                            ("message".into(), Json::Str("Connection failed".into())),
                        ])
                        .to_compact(),
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
                        send_json(resp, bridge, request, 200, "OK", &json.to_compact())
                    }
                    Err(_) => send_json(
                        resp,
                        bridge,
                        request,
                        500,
                        "Ubus Protocol Error",
                        &Json::Object(vec![
                            ("code".into(), Json::Int(4)),
                            ("message".into(), Json::Str("Not found".into())),
                        ])
                        .to_compact(),
                    ),
                }
            } else {
                resp.status(404, "Not Found")?;
                resp.end_headers()?;
                resp.finish()
            }
        }
        Method::Post => {
            let Some(body) = body else {
                resp.force_close();
                return send_json(
                    resp,
                    bridge,
                    request,
                    200,
                    "OK",
                    &error_only(RpcError::Parse),
                );
            };
            if body.len() > MAX_POST {
                resp.force_close();
                return send_json(
                    resp,
                    bridge,
                    request,
                    200,
                    "OK",
                    &error_only(RpcError::Parse),
                );
            }
            let parsed = std::str::from_utf8(body)
                .ok()
                .and_then(|s| json::parse(s).ok());
            if rest.is_empty() || rest == "/" {
                return match parsed {
                    Some(obj @ Json::Object(_)) => {
                        let out = handle_object(bridge, &obj, true).to_compact();
                        send_json(resp, bridge, request, 200, "OK", &out)
                    }
                    Some(Json::Array(items)) => {
                        let parts: Vec<String> = items
                            .iter()
                            .map(|item| handle_object(bridge, item, true).to_compact())
                            .collect();
                        send_json(
                            resp,
                            bridge,
                            request,
                            200,
                            "OK",
                            &format!("[{}]", parts.join(",")),
                        )
                    }
                    _ => send_json(
                        resp,
                        bridge,
                        request,
                        200,
                        "OK",
                        &error_only(RpcError::Parse),
                    ),
                };
            }
            if let Some(object) = rest.strip_prefix("/call/") {
                let sid = request
                    .header("authorization")
                    .and_then(|a| {
                        a.strip_prefix("Bearer ")
                            .or_else(|| a.strip_prefix("bearer "))
                    })
                    .unwrap_or(DEFAULT_SID)
                    .to_owned();
                let out = match parsed {
                    Some(obj @ Json::Object(_)) => {
                        let id = rpc_id(Some(&obj));
                        if obj.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
                            rpc_error(id, RpcError::Parse)
                        } else if let Some(method) = obj.get("method").and_then(Json::as_str) {
                            let args = obj.get("params").cloned().unwrap_or(Json::Object(vec![]));
                            do_call(bridge, id, &sid, object, method, &args, false)
                        } else {
                            rpc_error(id, RpcError::Parse)
                        }
                    }
                    _ => rpc_error(Json::Null, RpcError::Parse),
                };
                return send_json(resp, bridge, request, 200, "OK", &out.to_compact());
            }
            resp.status(404, "Not Found")?;
            resp.end_headers()?;
            resp.finish()
        }
        _ => resp.error(400, "Bad Request", Some("Invalid Request")),
    }
}
