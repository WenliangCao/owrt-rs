//! Trigger-free service.event fault receiver. Correctness only, never timed.
//! PREFIX-status is a line-per-request plan: integer status, sleep:SECONDS,
//! drop (never reply), or disconnect (close/re-register the service).
use super::{fields_to_json, integer, obj, require, Connection, Incoming, Json, MsgType, Result};
use owrt_ubus::Request;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{Duration, Instant};

fn append(path: &str, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

fn record(
    prefix: &str,
    event: &str,
    request: &Request,
    package: &[u8],
    status: Option<i32>,
) -> Result<()> {
    let package_hex: String = package.iter().map(|b| format!("{b:02x}")).collect();
    let mut value = obj([
        ("event", Json::Str(event.into())),
        ("peer", integer(request.peer as u64)),
        ("seq", integer(request.seq as u64)),
        ("object_id", integer(request.objid as u64)),
        ("method", Json::Str(request.method.clone())),
        ("type", Json::Str("config.change".into())),
        ("package_hex", Json::Str(package_hex)),
    ]);
    if let (Json::Object(fields), Some(status)) = (&mut value, status) {
        fields.push(("status".into(), Json::Int(status as i64)));
    }
    let line = format!("{}\n", value.to_compact());
    append(&format!("{prefix}-all.jsonl"), line.as_bytes())?;
    append(&format!("{prefix}-raw.jsonl"), line.as_bytes())
}

fn connect(socket: &str) -> Result<(Connection, u32)> {
    let mut connection = Connection::connect(Some(socket))?;
    connection.set_server_io_timeout(Duration::from_secs(2));
    let object = connection.add_object(
        "service",
        &[(
            "event",
            &[("type", MsgType::String), ("data", MsgType::Table)],
        )],
        3000,
    )?;
    Ok((connection, object))
}

pub fn serve(socket: &str, prefix: &str) -> Result<()> {
    let (mut connection, mut object) = connect(socket)?;
    fs::write(format!("{prefix}-ready"), b"ready\n")?;
    let mut delayed: Vec<(Instant, Request, Vec<u8>)> = Vec::new();
    loop {
        let mut index = 0;
        while index < delayed.len() {
            if delayed[index].0 > Instant::now() {
                index += 1;
                continue;
            }
            let (_, request, package) = delayed.remove(index);
            record(prefix, "reply", &request, &package, Some(0))?;
            connection.reply_status(&request, 0, None)?;
        }
        let Some(Incoming::Invoke(request)) = connection.next_incoming(10)? else {
            continue;
        };
        let payload = fields_to_json(&request.data)?;
        require(
            request.objid == object && request.method == "event" && request.fd.is_none(),
            "unexpected fault service request",
        )?;
        let package = payload
            .get("data")
            .and_then(|d| d.get("package"))
            .and_then(Json::as_bytes)
            .ok_or("missing raw package")?;
        require(
            payload
                == obj([
                    ("type", Json::Str("config.change".into())),
                    (
                        "data",
                        obj([("package", Json::from_string_bytes(package.to_vec()))]),
                    ),
                ]),
            "unexpected fault event payload",
        )?;
        let log_path = format!("{prefix}.log");
        let index = fs::read(&log_path)
            .unwrap_or_default()
            .iter()
            .filter(|&&b| b == b'\n')
            .count();
        let plan = fs::read_to_string(format!("{prefix}-status")).unwrap_or_default();
        let action = plan.lines().nth(index).unwrap_or("0");
        let pending = action.starts_with("sleep:")
            || action == "drop"
            || action == "disconnect"
            || action == "replace";
        let status = if pending {
            None
        } else {
            Some(action.parse::<i32>()?)
        };
        record(prefix, "receive", &request, package, status)?;
        // Legacy textual log lets old r1 scenarios keep their result assertions.
        // The raw JSONL above is authoritative for all filename bytes.
        let mut line = package.to_vec();
        line.extend_from_slice(b"\t");
        line.extend_from_slice(if pending {
            b"pending"
        } else {
            action.as_bytes()
        });
        line.push(b'\n');
        append(&log_path, &line)?;
        if let Some(seconds) = action.strip_prefix("sleep:") {
            require(delayed.len() < 64, "too many pending fault requests")?;
            delayed.push((
                Instant::now() + Duration::from_secs(seconds.parse()?),
                request,
                package.to_vec(),
            ));
        } else if action == "replace" {
            connection.remove_object(object, 3000)?;
            object = connection.add_object(
                "service",
                &[(
                    "event",
                    &[("type", MsgType::String), ("data", MsgType::Table)],
                )],
                3000,
            )?;
            require(
                object != request.objid,
                "replacement reused the old object id",
            )?;
            record(prefix, "replace", &request, package, None)?;
            record(prefix, "reply", &request, package, Some(0))?;
            connection.reply_status(&request, 0, None)?;
        } else if action == "disconnect" {
            record(prefix, "disconnect", &request, package, None)?;
            drop(connection);
            delayed.clear();
            (connection, object) = connect(socket)?;
            fs::write(format!("{prefix}-ready"), b"reconnected\n")?;
        } else if action == "drop" {
            // Deliberately omit STATUS; following requests still make progress.
        } else {
            let status = status.expect("integer status");
            record(prefix, "reply", &request, package, Some(status))?;
            connection.reply_status(&request, status, None)?;
        }
    }
}
