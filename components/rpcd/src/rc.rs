//! rpcd rc.c port: `rc list` / `rc init`. Both are deferred in C (uloop
//! process + timeout); here each request runs on a worker thread and the
//! result is handed back to the event loop through the `Deferrer`.

use crate::session::{arg, arg_str, Reply};
use crate::Deferrer;
use owrt_ubus::blob::MsgType;
use owrt_ubus::{status, BlobBuf, Request};
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};
use std::time::Duration;

const LIST_EXEC_TIMEOUT_MS: u64 = 3000;

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    use MsgType::*;
    vec![
        ("list", vec![("name", String), ("skip_running_check", Int8)]),
        ("init", vec![("name", String), ("action", String)]),
    ]
}

/// rc_check_script: owned by root:root, u+x, not o+w.
fn check_script(path: &str) -> i32 {
    let Ok(m) = fs::metadata(path) else {
        return status::NOT_FOUND;
    };
    let mode = m.mode();
    if m.uid() != 0 || m.gid() != 0 || mode & 0o100 == 0 || mode & 0o002 != 0 {
        return status::PERMISSION_DENIED;
    }
    status::OK
}

/// strtoul(s, NULL, 0): leading space, sign, 0x/0 prefixes.
fn strtoul0(b: &[u8]) -> u64 {
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut base = 10u64;
    if i + 1 < b.len()
        && b[i] == b'0'
        && (b[i + 1] == b'x' || b[i + 1] == b'X')
        && b.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit())
    {
        base = 16;
        i += 2;
    } else if i < b.len() && b[i] == b'0' {
        base = 8;
    }
    let mut v: u64 = 0;
    let mut overflow = false;
    while i < b.len() {
        let d = match b[i] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'f' => (c - b'a') as u64 + 10,
            c @ b'A'..=b'F' => (c - b'A') as u64 + 10,
            _ => break,
        };
        if d >= base {
            break;
        }
        match v.checked_mul(base).and_then(|x| x.checked_add(d)) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if overflow {
        return u64::MAX;
    }
    if neg {
        v.wrapping_neg()
    } else {
        v
    }
}

struct Entry {
    start: i32,
    stop: i32,
    enabled: bool,
    running: bool,
    use_procd: bool,
}

/// The per-script part of rc_list_readdir: header scan, rc.d link, `running`.
/// None when the `running` probe timed out (C drops the entry then).
fn scan(path: &str, name: &str, skip_running_check: bool) -> Option<Entry> {
    let mut e = Entry {
        start: -1,
        stop: -1,
        enabled: false,
        running: false,
        use_procd: false,
    };
    if let Ok(f) = fs::File::open(path) {
        let mut r = BufReader::new(f);
        let mut count = 0;
        let mut line = Vec::new();
        while (e.start < 0 || e.stop < 0 || (!skip_running_check && !e.use_procd)) && count <= 10 {
            line.clear();
            match r.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            if let Some(v) = line.strip_prefix(b"START=") {
                e.start = strtoul0(v) as u32 as i32;
            } else if let Some(v) = line.strip_prefix(b"STOP=") {
                e.stop = strtoul0(v) as u32 as i32;
            } else if !skip_running_check {
                if let Some(v) = line.strip_prefix(b"USE_PROCD=") {
                    e.use_procd = strtoul0(v) != 0;
                }
            }
            count += 1;
        }
        if e.start >= 0 {
            let link = format!("/etc/rc.d/S{:02}{}", e.start, name);
            if let Ok(m) = fs::metadata(&link) {
                if m.mode() & 0o100 != 0 {
                    e.enabled = true;
                }
            }
        }
    }
    // rc_list_exec: the child exits non-zero without exec unless the running
    // check applies and the script uses procd.
    if skip_running_check || !e.use_procd {
        e.running = false;
        return Some(e);
    }
    let child = Command::new(path)
        .arg("running")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        // fork ok / exec failed in C: exit(errno) -> not running
        e.running = false;
        return Some(e);
    };
    match crate::procwait::wait(&mut child, Duration::from_millis(LIST_EXEC_TIMEOUT_MS)) {
        Ok(crate::procwait::Outcome::Exited(st)) => {
            e.running = st.success();
            Some(e)
        }
        Ok(crate::procwait::Outcome::TimedOut) => {
            eprintln!("Timeout waiting for {path}");
            None
        }
        Err(_) => {
            e.running = false;
            Some(e)
        }
    }
}

fn list_run(req_name: Option<String>, skip_running_check: bool) -> Reply {
    let Ok(rd) = fs::read_dir("/etc/init.d") else {
        return Reply::empty(status::UNKNOWN_ERROR);
    };
    let mut b = BlobBuf::new();
    for de in rd.flatten() {
        let name = de.file_name().to_string_lossy().into_owned();
        if let Some(want) = &req_name {
            if *want != name {
                continue;
            }
        }
        let path = format!("/etc/init.d/{name}");
        if check_script(&path) != status::OK {
            continue;
        }
        if let Some(e) = scan(&path, &name, skip_running_check) {
            let t = b.msg_open_table(&name);
            if e.start >= 0 {
                b.msg_u16("start", e.start as u16);
            }
            if e.stop >= 0 {
                b.msg_u16("stop", e.stop as u16);
            }
            b.msg_bool("enabled", e.enabled);
            if !skip_running_check && e.use_procd {
                b.msg_bool("running", e.running);
            }
            b.msg_close(t);
        }
        if req_name.is_some() {
            break;
        }
    }
    Reply::one(status::OK, b.into_payload())
}

pub enum Outcome {
    Now(Request, Reply),
    Deferred,
}

fn now(req: Request, code: i32) -> Outcome {
    Outcome::Now(req, Reply::empty(code))
}

pub fn call(req: Request, deferrer: &Deferrer) -> Outcome {
    match req.method.as_str() {
        "list" => {
            if fs::read_dir("/etc/init.d").is_err() {
                return now(req, status::UNKNOWN_ERROR);
            }
            let skip = arg(&req.data, "skip_running_check", MsgType::Int8)
                .and_then(|f| f.as_bool())
                .unwrap_or(false);
            let name = arg_str(&req.data, "name").map(str::to_owned);
            match deferrer.defer(req, move || list_run(name, skip)) {
                None => Outcome::Deferred,
                Some((req, reply)) => Outcome::Now(req, reply),
            }
        }
        "init" => {
            let (Some(name), Some(action)) =
                (arg_str(&req.data, "name"), arg_str(&req.data, "action"))
            else {
                return now(req, status::INVALID_ARGUMENT);
            };
            if name.contains("..") || name.contains('/') {
                return now(req, status::INVALID_ARGUMENT);
            }
            let path = format!("/etc/init.d/{name}");
            let err = check_script(&path);
            if err != status::OK {
                return now(req, err);
            }
            if !matches!(
                action,
                "disable" | "enable" | "stop" | "start" | "restart" | "reload"
            ) {
                return now(req, status::INVALID_ARGUMENT);
            }
            let action = action.to_owned();
            match deferrer.defer(req, move || {
                if let Ok(mut child) = Command::new(&path)
                    .arg(&action)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    let _ = child.wait();
                }
                Reply::empty(status::OK)
            }) {
                None => Outcome::Deferred,
                Some((req, reply)) => Outcome::Now(req, reply),
            }
        }
        _ => now(req, status::METHOD_NOT_FOUND),
    }
}
