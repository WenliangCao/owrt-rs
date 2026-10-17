//! The `luci` object: a port of LuCI's rpcd ucode plugin
//! (`/usr/share/rpcd/ucode/luci`) and the `luci.sys` helpers it uses.

use crate::{glob, ip, util, Ctx};
use owrt_ubus::blob;
use owrt_ubus::convert::fields_to_json;
use owrt_ubus::json::{self, Json};
use owrt_ubus::{status, MsgType};
use std::process::Command;

const METHODS: &[(&str, &[(&str, MsgType)])] = {
    use MsgType::*;
    &[
        ("getVersion", &[]),
        ("getInitList", &[("name", String)]),
        ("setInitAction", &[("name", String), ("action", String)]),
        ("getUnixtime", &[]),
        ("setLocaltime", &[("localtime", Int32)]),
        ("getTimezones", &[]),
        ("getLEDs", &[]),
        ("getUSBDevices", &[]),
        ("getConntrackHelpers", &[]),
        ("getFeatures", &[]),
        ("getSwconfigFeatures", &[("switch", String)]),
        ("getSwconfigPortState", &[("switch", String)]),
        ("setPassword", &[("username", String), ("password", String)]),
        ("getBlockDevices", &[]),
        ("setBlockDetect", &[]),
        ("getMountPoints", &[]),
        ("getRealtimeStats", &[("mode", String), ("device", String)]),
        ("getConntrackList", &[]),
        ("getProcessList", &[]),
        ("getBuiltinEthernetPorts", &[]),
        ("getOdhcp6cStats", &[]),
    ]
};

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    METHODS.iter().map(|(method, policy)| (*method, policy.to_vec())).collect()
}

// ----------------------------------------------------------- helpers

fn s(v: &str) -> Json {
    Json::Str(v.to_owned())
}
fn obj(items: Vec<(&str, Json)>) -> Json {
    Json::Object(items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
fn result(v: Json) -> Json {
    obj(vec![("result", v)])
}
fn error(msg: &str) -> Json {
    obj(vec![("error", s(msg))])
}
fn readfile(path: &str) -> Option<String> {
    util::read_lossy(path).ok()
}
fn trim(v: &str) -> &str {
    v.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r')
}
/// ucode `+str` for the small integers read from sysfs; 0 for null/NaN.
fn num(v: Option<&str>) -> Json {
    let Some(v) = v else { return Json::Int(0) };
    let t = trim(v);
    if t.is_empty() {
        return Json::Int(0);
    }
    match t.parse::<i64>() {
        Ok(n) => Json::Int(n),
        Err(_) => match t.parse::<f64>() {
            Ok(f) => Json::Float(f),
            Err(_) => Json::Float(f64::NAN),
        },
    }
}
fn access(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}
/// ucode `access()` returns true or null.
fn access_or_null(path: &str) -> Json {
    if access(path) { Json::Bool(true) } else { Json::Null }
}
fn shellquote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}
fn system(cmd: &str) -> i32 {
    Command::new("/bin/sh").arg("-c").arg(cmd).status().map(|st| st.code().unwrap_or(-1)).unwrap_or(-1)
}
fn popen(cmd: &str) -> String {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}
fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}
fn dirname(p: &str) -> &str {
    match p.rfind('/') {
        Some(0) => "/",
        Some(i) => &p[..i],
        None => ".",
    }
}
fn arg_str<'a>(args: &'a Json, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Json::as_str)
}
/// `\ooo` octal escapes in /proc/mounts and /proc/swaps
fn unescape_octal(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..].len() >= 3 && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let n = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 4]).unwrap(), 8).unwrap_or(b'\\');
            out.push(n);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// -------------------------------------------------------- validation

/// ucode.so argument validation: every field must be in the policy with the
/// declared type, except `ubus_rpc_session` (string).
fn validate(method: &str, raw: &[u8]) -> Result<(), i32> {
    let Some((_, policy)) = METHODS.iter().find(|(n, _)| *n == method) else { return Err(status::METHOD_NOT_FOUND) };
    for f in blob::fields(raw) {
        match policy.iter().find(|(n, _)| *n == f.name) {
            Some((_, ty)) => {
                if f.ty != *ty as u32 {
                    return Err(status::INVALID_ARGUMENT);
                }
            }
            None => {
                if !(f.name == "ubus_rpc_session" && f.ty == MsgType::String as u32) {
                    return Err(status::INVALID_ARGUMENT);
                }
            }
        }
    }
    Ok(())
}

// -------------------------------------------------------- luci.sys

fn init_list() -> Vec<String> {
    glob::glob("/etc/init.d/*")
        .into_iter()
        .filter(|p| {
            std::fs::metadata(p)
                .map(|m| m.is_file() && (std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o100) != 0)
                .unwrap_or(false)
        })
        .map(|p| basename(&p).to_owned())
        .collect()
}

fn init_index(name: &str) -> Option<(Option<i64>, Option<i64>)> {
    let mut f = std::fs::File::open(format!("/etc/init.d/{}", basename(name))).ok()?;
    let mut buf = vec![0u8; 2048];
    let n = std::io::Read::read(&mut f, &mut buf).ok()?;
    let src = String::from_utf8_lossy(&buf[..n]).into_owned();
    let (mut start, mut stop) = (None, None);
    let mut found = false;
    for line in src.split('\n') {
        let t = line.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\r');
        for (key, slot) in [("START=", &mut start), ("STOP=", &mut stop)] {
            if let Some(v) = t.strip_prefix(key) {
                let v = v.trim_matches(|c| c == '\'' || c == '"');
                if v.len() == 2 && v.bytes().all(|b| b.is_ascii_digit()) {
                    *slot = v.parse::<i64>().ok();
                    found = true;
                }
            }
        }
    }
    if found { Some((start, stop)) } else { None }
}

fn init_enabled(name: &str) -> bool {
    let name = basename(name);
    let Ok(s2) = std::fs::metadata(format!("/etc/init.d/{name}")) else { return false };
    for path in glob::glob(&format!("/etc/rc.d/[SK][0-9][0-9]{name}")) {
        let Ok(ln) = std::fs::read_link(&path) else { continue };
        let ln = ln.to_string_lossy().into_owned();
        let target = if ln.starts_with('/') { ln } else { format!("/etc/rc.d/{ln}") };
        if let Ok(s1) = std::fs::metadata(&target) {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if s1.ino() == s2.ino() && s1.is_file() && (s1.permissions().mode() & 0o100) != 0 {
                return true;
            }
        }
    }
    false
}

fn init_action(name: &str, action: &str) -> Option<i32> {
    let name = basename(name);
    let m = std::fs::metadata(format!("/etc/init.d/{name}")).ok()?;
    if !m.is_file() {
        return None;
    }
    Some(system(&format!("env -i /etc/init.d/{name} {action} >/dev/null")))
}

fn conntrack_list() -> Vec<Json> {
    let mut protos: Vec<(String, String)> = Vec::new();
    if let Some(text) = readfile("/etc/protocols") {
        for line in text.lines() {
            let mut it = line.split([' ', '\t']).filter(|p| !p.is_empty());
            if let (Some(name), Some(num)) = (it.next(), it.next()) {
                if !name.starts_with('#') && num.bytes().all(|b| b.is_ascii_digit()) && !num.is_empty() {
                    protos.push((num.to_owned(), name.to_owned()));
                }
            }
        }
    }
    let text = readfile("/proc/net/nf_conntrack")
        .unwrap_or_else(|| popen("/usr/sbin/conntrack -L -o extended"));
    let mut out = Vec::new();
    for line in text.split_inclusive('\n') {
        // ^(ipv[46]) +([0-9]+) +\S+ +([0-9]+)( +.+)\n$
        let Some(line) = line.strip_suffix('\n') else { continue };
        let mut rest = line;
        let take = |rest: &mut &str| -> Option<String> {
            let t = rest.trim_start_matches(' ');
            let end = t.find(' ').unwrap_or(t.len());
            if end == 0 {
                return None;
            }
            let tok = t[..end].to_owned();
            *rest = &t[end..];
            Some(tok)
        };
        let Some(fam) = take(&mut rest) else { continue };
        if fam != "ipv4" && fam != "ipv6" {
            continue;
        }
        let fam = fam.as_str();
        let Some(l3) = take(&mut rest) else { continue };
        let Some(_name) = take(&mut rest) else { continue };
        let Some(l4) = take(&mut rest) else { continue };
        if !l3.bytes().all(|b| b.is_ascii_digit()) || !l4.bytes().all(|b| b.is_ascii_digit()) || !rest.starts_with(' ') || rest.trim().is_empty() {
            continue;
        }
        let mut tuples = rest;
        let mut timeout: Option<String> = None;
        {
            let t = tuples.trim_start_matches(' ');
            let end = t.find(' ').unwrap_or(t.len());
            if end > 0 && t[..end].bytes().all(|b| b.is_ascii_digit()) && end < t.len() {
                timeout = Some(t[..end].to_owned());
                tuples = &t[end..];
            }
        }
        if tuples.contains("TIME_WAIT") {
            continue;
        }
        let layer4 = protos.iter().find(|(n, _)| *n == l4).map(|(_, p)| p.clone()).unwrap_or_else(|| "unknown".into());
        let mut e: Vec<(String, Json)> = vec![
            ("bytes".into(), Json::Int(0)),
            ("packets".into(), Json::Int(0)),
            ("layer3".into(), s(fam)),
            ("layer4".into(), Json::Str(layer4)),
            ("timeout".into(), num(timeout.as_deref())),
        ];
        let set = |e: &mut Vec<(String, Json)>, k: &str, v: Json| {
            if let Some(slot) = e.iter_mut().find(|(key, _)| key == k) {
                slot.1 = v;
            } else {
                e.push((k.to_owned(), v));
            }
        };
        for tok in tuples.split(' ').filter(|t| !t.is_empty()) {
            let Some((k, v)) = tok.split_once('=') else { continue };
            if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                continue;
            }
            match k {
                "bytes" | "packets" => {
                    let cur = e.iter().find(|(key, _)| key == k).and_then(|(_, v)| if let Json::Int(i) = v { Some(*i) } else { None }).unwrap_or(0);
                    let add = v.parse::<i64>().unwrap_or(0);
                    set(&mut e, k, Json::Int(cur + add));
                }
                "src" | "dst" => {
                    if !e.iter().any(|(key, _)| key == k) {
                        let norm = ip::iptoarr(v).and_then(|a| ip::arrtoip(&a));
                        set(&mut e, k, norm.map(Json::Str).unwrap_or(Json::Null));
                    }
                }
                "sport" | "dport" => {
                    if !e.iter().any(|(key, _)| key == k) {
                        set(&mut e, k, num(Some(v)));
                    }
                }
                _ => set(&mut e, k, s(v)),
            }
        }
        out.push(Json::Object(e));
    }
    out
}

fn process_list() -> Vec<Json> {
    let text = popen("/bin/busybox top -bn1");
    let mut list = Vec::new();
    for raw in text.lines() {
        let line = trim(raw);
        // ^([0-9]+) +([0-9]+) +(.+) +([RSDZTWI][<NW ][<N ]) +([0-9]+m?) +([0-9]+%) +([0-9]+%) +(.+)$
        let b = line.as_bytes();
        let mut pos = 0;
        let token = |pos: &mut usize| -> Option<(usize, usize)> {
            while *pos < b.len() && b[*pos] == b' ' {
                *pos += 1;
            }
            let start = *pos;
            while *pos < b.len() && b[*pos] != b' ' {
                *pos += 1;
            }
            if start == *pos { None } else { Some((start, *pos)) }
        };
        let Some((ps, pe)) = token(&mut pos) else { continue };
        let pid = &line[ps..pe];
        if !pid.bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some((qs, qe)) = token(&mut pos) else { continue };
        let ppid = &line[qs..qe];
        if !ppid.bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // find STAT: first position after PPID where a 3-char state pattern is
        // followed by VSZ, %MEM, %CPU and a command
        let mut parsed = None;
        let mut i = pos;
        while i + 3 <= b.len() {
            if b[i] != b' ' && i > 0 && b[i - 1] == b' ' && b"RSDZTWI".contains(&b[i]) && b"<NW ".contains(&b[i + 1]) && b"<N ".contains(&b[i + 2]) {
                let stat = &line[i..i + 3];
                let mut p2 = i + 3;
                if p2 < b.len() && b[p2] != b' ' { i += 1; continue; }
                let vsz = token(&mut p2);
                let mem = token(&mut p2);
                let cpu = token(&mut p2);
                if let (Some((a, a2)), Some((m, m2)), Some((c, c2))) = (vsz, mem, cpu) {
                    let vsz = &line[a..a2];
                    let mem = &line[m..m2];
                    let cpu = &line[c..c2];
                    let vsz_ok = vsz.strip_suffix('m').unwrap_or(vsz).bytes().all(|x| x.is_ascii_digit()) && !vsz.is_empty();
                    let pct = |t: &str| t.strip_suffix('%').map(|d| !d.is_empty() && d.bytes().all(|x| x.is_ascii_digit())).unwrap_or(false);
                    while p2 < b.len() && b[p2] == b' ' {
                        p2 += 1;
                    }
                    if vsz_ok && pct(mem) && pct(cpu) && p2 < b.len() {
                        let user = trim(&line[pos..i]);
                        parsed = Some((user.to_owned(), stat.to_owned(), vsz.to_owned(), mem.to_owned(), cpu.to_owned(), line[p2..].to_owned()));
                        break;
                    }
                }
            }
            i += 1;
        }
        let Some((user, stat, vsz, mem, cpu, command)) = parsed else { continue };
        if command == "/bin/busybox top -bn1" {
            continue;
        }
        list.push(obj(vec![
            ("PID", s(pid)),
            ("PPID", s(ppid)),
            ("USER", Json::Str(user)),
            ("STAT", Json::Str(stat)),
            ("VSZ", Json::Str(vsz)),
            ("%MEM", Json::Str(mem)),
            ("%CPU", Json::Str(cpu)),
            ("COMMAND", Json::Str(command)),
        ]));
    }
    list
}

// ----------------------------------------------------------- methods

fn get_version() -> Json {
    let text = readfile("/usr/share/ucode/luci/version.uc").unwrap_or_default();
    let grab = |key: &str| -> Json {
        let Some(i) = text.find(&format!("{key} = '")) else { return Json::Null };
        let rest = &text[i + key.len() + 4..];
        rest.find('\'').map(|e| s(&rest[..e])).unwrap_or(Json::Null)
    };
    obj(vec![("revision", grab("revision")), ("branch", grab("branch"))])
}

fn get_init_list(args: &Json) -> Json {
    let want = arg_str(args, "name");
    let mut scripts: Vec<(String, Json)> = Vec::new();
    for name in init_list() {
        if let Some(w) = want {
            if w != name {
                continue;
            }
        }
        let idx = init_index(&name);
        let enabled = init_enabled(&name);
        scripts.push((
            name,
            obj(vec![
                ("index", idx.and_then(|(a, _)| a).map(Json::Int).unwrap_or(Json::Null)),
                ("stop", idx.and_then(|(_, b)| b).map(Json::Int).unwrap_or(Json::Null)),
                ("enabled", Json::Bool(enabled)),
            ]),
        ));
    }
    if scripts.is_empty() { error("No such init script") } else { Json::Object(scripts) }
}

fn set_init_action(args: &Json) -> Json {
    let action = arg_str(args, "action").unwrap_or("");
    match action {
        "enable" | "disable" | "start" | "stop" | "restart" | "reload" => {
            match init_action(arg_str(args, "name").unwrap_or(""), action) {
                None => error("No such init script"),
                Some(rc) => result(Json::Bool(rc == 0)),
            }
        }
        _ => error("Invalid action"),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn set_localtime(args: &Json) -> Json {
    // ucode: localtime(request.args.localtime). ucode.so does not inject the
    // policy default, so an omitted arg is null -> localtime(null) uses the
    // current time, and the reply echoes request.args.localtime (null).
    let provided = match args.get("localtime") {
        Some(Json::Int(i)) => Some(*i),
        _ => None,
    };
    if let Some(tm) = owrt_platform::rpcd::localtime(provided) {
        system(&format!(
            "date -s \"{:04}-{:02}-{:02} {:02}:{:02}:{:02}\" >/dev/null",
            tm.year + 1900, tm.mon + 1, tm.mday, tm.hour, tm.min, tm.sec
        ));
        system("/etc/init.d/sysfixtime restart >/dev/null");
    }
    result(provided.map(Json::Int).unwrap_or(Json::Null))
}

fn get_timezones() -> Json {
    let _tz = readfile("/etc/TZ");
    let zn = Command::new("uci")
        .args(["-q", "get", "system.@system[0].zonename"])
        .output()
        .ok()
        .map(|o| trim(&String::from_utf8_lossy(&o.stdout)).to_owned())
        .filter(|z| !z.is_empty());
    let text = readfile("/usr/share/ucode/luci/zoneinfo.uc").unwrap_or_default();
    let mut out: Vec<(String, Json)> = Vec::new();
    for line in text.lines() {
        let t = trim(line);
        let Some(rest) = t.strip_prefix('\'') else { continue };
        let Some(q) = rest.find('\'') else { continue };
        let zone = &rest[..q];
        let after = &rest[q + 1..];
        let Some(vs) = after.find('\'') else { continue };
        let val = &after[vs + 1..];
        let Some(ve) = val.find('\'') else { continue };
        let tzstring = &val[..ve];
        let mut o = vec![("tzstring", s(tzstring))];
        if zn.as_deref() == Some(zone) {
            o.push(("active", Json::Bool(true)));
        }
        out.push((zone.to_owned(), obj(o)));
    }
    Json::Object(out)
}

fn lsdir(path: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(path)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn get_leds() -> Json {
    let mut out: Vec<(String, Json)> = Vec::new();
    for led in lsdir("/sys/class/leds") {
        let mut triggers = Vec::new();
        let mut active: Option<String> = None;
        let t = readfile(&format!("/sys/class/leds/{led}/trigger")).unwrap_or_default();
        for trigger in trim(&t).split(' ') {
            if t.trim().is_empty() {
                break;
            }
            let clean = trigger.trim_matches(|c| c == '[' || c == ']');
            triggers.push(Json::Str(clean.to_owned()));
            if trigger != clean {
                active = Some(clean.to_owned());
            }
        }
        let mut o = vec![("triggers", Json::Array(triggers))];
        if let Some(a) = active {
            o.push(("active_trigger", Json::Str(a)));
        }
        o.push(("brightness", num(readfile(&format!("/sys/class/leds/{led}/brightness")).as_deref())));
        o.push(("max_brightness", num(readfile(&format!("/sys/class/leds/{led}/max_brightness")).as_deref())));
        out.push((led, obj(o)));
    }
    Json::Object(out)
}

fn get_usb_devices() -> Json {
    let mut devices = Vec::new();
    for path in glob::glob("/sys/bus/usb/devices/[0-9]*/manufacturer") {
        let id = basename(dirname(&path)).to_owned();
        let rf = |f: &str| readfile(&format!("/sys/bus/usb/devices/{id}/{f}"));
        devices.push(obj(vec![
            ("id", s(&id)),
            ("vid", rf("idVendor").map(|v| s(trim(&v))).unwrap_or(Json::Null)),
            ("pid", rf("idProduct").map(|v| s(trim(&v))).unwrap_or(Json::Null)),
            ("vendor", readfile(&path).map(|v| s(trim(&v))).unwrap_or(Json::Null)),
            ("product", rf("product").map(|v| s(trim(&v))).unwrap_or(Json::Null)),
            ("speed", num(rf("speed").as_deref())),
        ]));
    }
    let mut ports = Vec::new();
    for path in glob::glob("/sys/bus/usb/devices/*/*-port[0-9]*") {
        let port = basename(&path).to_owned();
        let link = std::fs::read_link(format!("{path}/device")).ok().map(|l| l.to_string_lossy().into_owned());
        ports.push(obj(vec![
            ("port", Json::Str(port)),
            ("device", link.map(|l| s(basename(&l))).unwrap_or(Json::Null)),
        ]));
    }
    obj(vec![("devices", Json::Array(devices)), ("ports", Json::Array(ports))])
}

fn get_conntrack_helpers() -> Json {
    // ucode: cursor().load('/usr/share/firewall4/helpers') || load('/usr/share/fw3/helpers.conf'),
    // then foreach(package, 'helper'): libuci semantics via owrt_uci (absolute path load,
    // strict parse, list options as arrays, missing options as null).
    let mut ctx = owrt_uci::Context::new();
    let mut pidx = owrt_uci::file::load(&mut ctx, "/usr/share/firewall4/helpers").ok();
    if pidx.is_none() {
        pidx = owrt_uci::file::load(&mut ctx, "/usr/share/fw3/helpers.conf").ok();
    }
    let mut helpers = Vec::new();
    if let Some(pidx) = pidx {
        for sec in ctx.root[pidx].sections.iter().filter(|s| s.ty == "helper") {
            let g = |k: &str| match sec.find_option(k) {
                Some(i) => match &sec.options[i].value {
                    owrt_uci::OptionValue::Str(v) => Json::Str(String::from_utf8_lossy(v).into_owned()),
                    owrt_uci::OptionValue::List(items) => Json::Array(items.iter().map(|v| Json::Str(String::from_utf8_lossy(v).into_owned())).collect()),
                },
                None => Json::Null,
            };
            helpers.push(obj(vec![
                ("name", g("name")),
                ("description", g("description")),
                ("module", g("module")),
                ("family", g("family")),
                ("proto", g("proto")),
                ("port", g("port")),
            ]));
        }
    }
    result(Json::Array(helpers))
}

fn get_features() -> Json {
    let mut r: Vec<(String, Json)> = vec![
        ("firewall".into(), Json::Bool(access("/sbin/fw3"))),
        ("firewall4".into(), Json::Bool(access("/sbin/fw4"))),
        ("opkg".into(), Json::Bool(access("/bin/opkg"))),
        ("bonding".into(), access_or_null("/sys/module/bonding")),
        ("mii_tool".into(), access_or_null("/usr/sbin/mii-tool")),
        ("offloading".into(), Json::Bool(access("/sys/module/xt_FLOWOFFLOAD/refcnt") || access("/sys/module/nft_flow_offload/refcnt"))),
        ("br2684ctl".into(), Json::Bool(access("/usr/sbin/br2684ctl"))),
        ("swconfig".into(), Json::Bool(access("/sbin/swconfig"))),
        ("zram".into(), Json::Bool(access("/sys/class/zram-control"))),
        ("sysntpd".into(), Json::Bool(std::fs::read_link("/usr/sbin/ntpd").is_ok())),
        ("ipv6".into(), Json::Bool(access("/proc/net/ipv6_route"))),
        ("dropbear".into(), Json::Bool(access("/usr/sbin/dropbear"))),
        ("cabundle".into(), Json::Bool(access("/etc/ssl/certs/ca-certificates.crt"))),
        ("relayd".into(), Json::Bool(access("/usr/sbin/relayd"))),
        ("apk".into(), Json::Bool(access("/usr/bin/apk"))),
        ("wifi".into(), Json::Bool(access("/sbin/wifi"))),
        ("ufpd".into(), Json::Bool(access("/usr/sbin/ufpd"))),
        ("vrf".into(), Json::Bool(access("/sys/module/vrf/refcnt"))),
        ("netifd_vrf".into(), Json::Bool(false)),
        ("mptcp".into(), access_or_null("/proc/sys/net/mptcp/enabled")),
    ];
    let wifi_features = ["11ac", "11ax", "11be", "11r", "acs", "eap", "mesh", "ocv", "owe", "sae", "suiteb192", "wep", "wps"];
    for (key, bin, cli) in [("hostapd", "/usr/sbin/hostapd", "/usr/sbin/hostapd_cli"), ("wpasupplicant", "/usr/sbin/wpa_supplicant", "/usr/sbin/wpa_cli")] {
        if access(bin) {
            let mut o = vec![("cli".to_owned(), Json::Bool(access(cli)))];
            for f in wifi_features {
                o.push((f.to_owned(), Json::Bool(system(&format!("{bin} -v{f} >/dev/null 2>/dev/null")) == 0)));
            }
            r.push((key.into(), Json::Object(o)));
        }
    }
    let dns = popen("dnsmasq --version 2>/dev/null");
    if let Some(line) = dns.lines().find_map(|l| l.strip_prefix("Compile time options: ")) {
        let mut o: Vec<(String, Json)> = Vec::new();
        for opt in line.split(' ').filter(|o| !o.is_empty()) {
            let f = opt.strip_prefix("no-").unwrap_or(opt);
            o.push((f.to_lowercase(), Json::Bool(f == opt)));
        }
        r.push(("dnsmasq".into(), Json::Object(o)));
    }
    r.push(("odhcpd".into(), Json::Bool(false)));
    let od = popen("odhcpd -h 2>/dev/null");
    if !od.is_empty() {
        let mut o: Vec<(String, Json)> = Vec::new();
        if let Some(line) = od.lines().find_map(|l| l.strip_prefix("Features: ")) {
            for opt in line.split(' ').filter(|o| !o.is_empty()) {
                let f = opt.strip_prefix("no-").unwrap_or(opt);
                o.push((f.to_lowercase(), Json::Bool(f == opt)));
            }
        }
        if let Some(slot) = r.iter_mut().find(|(k, _)| k == "odhcpd") {
            slot.1 = Json::Object(o);
        }
    }
    // netifd version check (apk only on this release)
    let apk = popen("apk list -I 'netifd' 2>/dev/null");
    // Check bytes before slicing: a malformed year such as "20中" must
    // return false without splitting a character and panicking. The exact
    // ucode regexp also finds a package line after a preceding notice.
    let vrf = apk.lines().find_map(|line| line.strip_prefix("netifd-"))
        .and_then(|v| v.as_bytes().get(..4))
        .is_some_and(|year| year.starts_with(b"20") && year.iter().all(u8::is_ascii_digit)
            && year >= b"2025".as_slice());
    if let Some(slot) = r.iter_mut().find(|(k, _)| k == "netifd_vrf") {
        slot.1 = Json::Bool(vrf);
    }
    let ipset = popen("ipset --help 2>/dev/null");
    let mut flag = false;
    let mut sets: Vec<(String, Json)> = Vec::new();
    for line in ipset.split_inclusive('\n') {
        if line == "Supported set types:\n" {
            flag = true;
        } else if flag {
            // ^ +([\w:,]+)\t+([0-9]+)\t
            let t = line.trim_start_matches(' ');
            if t.len() == line.len() {
                continue;
            }
            let Some((name, rest)) = t.split_once('\t') else { continue };
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':' || b == b',') {
                continue;
            }
            let rest = rest.trim_start_matches('\t');
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() || !rest[digits.len()..].starts_with('\t') {
                continue;
            }
            if !sets.iter().any(|(k, _)| k == name) {
                sets.push((name.to_owned(), Json::Int(digits.parse().unwrap_or(0))));
            }
        }
    }
    if !sets.is_empty() {
        r.push(("ipset".into(), Json::Object(sets)));
    }
    Json::Object(r)
}

fn first_group<'a>(line: &'a str, prefix: &str, stop: &[char]) -> Option<&'a str> {
    let i = line.find(prefix)?;
    let rest = &line[i + prefix.len()..];
    let end = rest.find(|c: char| stop.contains(&c)).unwrap_or(rest.len());
    if end == 0 { None } else { Some(&rest[..end]) }
}

fn get_swconfig_features(args: &Json) -> Json {
    let sw = shellquote(arg_str(args, "switch").unwrap_or("switch0"));
    let out = popen(&format!("swconfig dev {sw} help 2>/dev/null"));
    let (mut is_vlan_attr, mut r): (bool, Vec<(String, Json)>) = (false, Vec::new());
    let set = |r: &mut Vec<(String, Json)>, k: &str, v: Json| {
        if let Some(slot) = r.iter_mut().find(|(key, _)| key == k) { slot.1 = v } else { r.push((k.to_owned(), v)) }
    };
    for line in out.lines() {
        let t = line.trim_start_matches([' ', '\t']);
        let indented = t.len() != line.len();
        if indented && t.starts_with("--vlan") {
            is_vlan_attr = true;
        } else if indented && t.starts_with("--port") {
            is_vlan_attr = false;
        } else if line.contains("cpu @") {
            let title = line.strip_prefix("switch").and_then(|rest| {
                let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
                let rest = rest.strip_prefix(": ")?;
                let i = rest.find('(')?;
                let j = rest.rfind(')')?;
                if j > i { Some(rest[i + 1..j].to_owned()) } else { None }
            });
            set(&mut r, "switch_title", title.map(Json::Str).unwrap_or(Json::Null));
            let vlans = first_group(line, "vlans: ", &[' ', ',', ')', '\n']).filter(|v| v.bytes().all(|b| b.is_ascii_digit()));
            set(&mut r, "num_vlans", vlans.map(s).unwrap_or(Json::Int(16)));
            set(&mut r, "min_vid", Json::Int(1));
        } else if [": pvid", ": tag", ": vid"].iter().any(|p| line.contains(p)) {
            if is_vlan_attr {
                let v = first_group(line, ": ", &[' ', '\t', ':', '\n']).map(|w| w.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect::<String>());
                set(&mut r, "vid_option", v.map(Json::Str).unwrap_or(Json::Null));
            }
        } else if line.contains(": enable_vlan4k") {
            set(&mut r, "vlan4k_option", s("enable_vlan4k"));
        } else if line.contains(": enable_vlan") {
            set(&mut r, "vlan_option", s("enable_vlan"));
        } else if line.contains(": enable_learning") {
            set(&mut r, "learning_option", s("enable_learning"));
        } else if line.contains(": enable_mirror_rx") {
            set(&mut r, "mirror_option", s("enable_mirror_rx"));
        } else if line.contains(": max_length") {
            set(&mut r, "jumbo_option", s("max_length"));
        }
    }
    if r.is_empty() { error("No such switch") } else { Json::Object(r) }
}

fn get_swconfig_port_state(args: &Json) -> Json {
    let sw = shellquote(arg_str(args, "switch").unwrap_or("switch0"));
    let out = popen(&format!("swconfig dev {sw} show 2>/dev/null"));
    let mut ports: Vec<Vec<(String, Json)>> = Vec::new();
    for line in out.lines() {
        if line.starts_with("VLAN ") && line.contains(':') && !ports.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Port ") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() && rest[digits.len()..].starts_with(':') {
                ports.push(vec![
                    ("port".into(), Json::Int(digits.parse().unwrap_or(0))),
                    ("duplex".into(), Json::Bool(false)),
                    ("speed".into(), Json::Int(0)),
                    ("link".into(), Json::Bool(false)),
                    ("auto".into(), Json::Bool(false)),
                    ("rxflow".into(), Json::Bool(false)),
                    ("txflow".into(), Json::Bool(false)),
                ]);
            }
        }
        if let Some(port) = ports.last_mut() {
            let set = |port: &mut Vec<(String, Json)>, k: &str, v: Json| {
                if let Some(slot) = port.iter_mut().find(|(key, _)| key == k) { slot.1 = v }
            };
            let speed_is_zero = |port: &Vec<(String, Json)>| port.iter().any(|(k, v)| k == "speed" && *v == Json::Int(0));
            if line.contains("full duplex") || line.contains("full-duplex") {
                set(port, "duplex", Json::Bool(true));
            }
            if let Some(v) = first_group(line, " speed:", &[' ', '\n']).and_then(|v| v.parse::<i64>().ok()) {
                set(port, "speed", Json::Int(v));
            }
            if let Some(i) = line.find(" Mbps") {
                let digits: String = line[..i].chars().rev().take_while(|c| c.is_ascii_digit()).collect::<String>().chars().rev().collect();
                if !digits.is_empty() && speed_is_zero(port) {
                    set(port, "speed", Json::Int(digits.parse().unwrap_or(0)));
                }
            }
            if let Some(v) = first_group(line, "link: ", &[' ', '\n']).and_then(|v| v.parse::<i64>().ok()) {
                if speed_is_zero(port) {
                    set(port, "speed", Json::Int(v));
                }
            }
            if line.contains("link:up") || line.contains("link: up") || line.contains("status:up") || line.contains("status: up") {
                set(port, "link", Json::Bool(true));
            }
            if line.contains("auto-negotiate") || (line.contains("link:") && line[line.find("link:").unwrap()..].contains("auto")) {
                set(port, "auto", Json::Bool(true));
            }
            if line.contains("link:") && line[line.find("link:").unwrap()..].contains("rxflow") {
                set(port, "rxflow", Json::Bool(true));
            }
            if line.contains("link:") && line[line.find("link:").unwrap()..].contains("txflow") {
                set(port, "txflow", Json::Bool(true));
            }
        }
    }
    if ports.is_empty() {
        error("No such switch")
    } else {
        result(Json::Array(ports.into_iter().map(Json::Object).collect()))
    }
}

fn set_password(args: &Json) -> Json {
    let u = shellquote(arg_str(args, "username").unwrap_or("root"));
    let p = shellquote(arg_str(args, "password").unwrap_or("password"));
    result(Json::Bool(system(&format!("(echo {p}; sleep 1; echo {p}) | /bin/busybox passwd {u} >/dev/null 2>&1")) == 0))
}

fn get_block_devices() -> Json {
    let out = popen("/sbin/block info 2>/dev/null");
    let mut r: Vec<(String, Json)> = Vec::new();
    for line in out.lines() {
        let Some(rest) = line.strip_prefix("/dev/") else { continue };
        let Some(colon) = rest.find(':') else { continue };
        let dev = &rest[..colon];
        if dev.is_empty() {
            continue;
        }
        let size = match num(readfile(&format!("/sys/class/block/{dev}/size")).as_deref()) {
            Json::Int(n) => Json::Int(n * 512),
            other => other,
        };
        let mut e = vec![("dev".to_owned(), Json::Str(format!("/dev/{dev}"))), ("size".to_owned(), size)];
        let mut tail = &rest[colon + 1..];
        while let Some(i) = tail.find("=\"") {
            let key_start = tail[..i].rfind(' ').map(|p| p + 1).unwrap_or(0);
            let key = &tail[key_start..i];
            let after = &tail[i + 2..];
            let Some(end) = after.find('"') else { break };
            if !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') && key_start > 0 {
                e.push((key.to_lowercase(), s(&after[..end])));
            }
            tail = &after[end + 1..];
        }
        r.push((dev.to_owned(), Json::Object(e)));
    }
    if let Some(swaps) = readfile("/proc/swaps") {
        for line in swaps.lines() {
            let mut it = line.split_whitespace();
            let (Some(name), Some(_ty), Some(size)) = (it.next(), it.next(), it.next()) else { continue };
            if !name.starts_with('/') || !size.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            r.push((
                format!("swap:{name}"),
                obj(vec![
                    ("dev", Json::Str(unescape_octal(name))),
                    ("type", s("swap")),
                    ("size", Json::Int(size.parse::<i64>().unwrap_or(0) * 1024)),
                ]),
            ));
        }
    }
    Json::Object(r)
}

fn set_block_detect() -> Json {
    result(Json::Bool(system("/sbin/block detect > /etc/config/fstab") == 0))
}

fn get_mount_points() -> Json {
    let Some(text) = readfile("/proc/mounts") else { return error("No such file or directory") };
    let mut out = Vec::new();
    for line in text.lines() {
        let m: Vec<&str> = line.split(' ').collect();
        if m.len() < 2 {
            continue;
        }
        let device = unescape_octal(m[0]);
        let mount = unescape_octal(m[1]);
        if let Some(st) = util::statvfs_of(&mount) {
            if st.f_blocks > 0 {
                out.push(obj(vec![
                    ("device", Json::Str(device)),
                    ("mount", Json::Str(mount)),
                    ("size", Json::Int((st.f_bsize * st.f_blocks) as i64)),
                    ("avail", Json::Int((st.f_bsize * st.f_bavail) as i64)),
                    ("free", Json::Int((st.f_bsize * st.f_bfree) as i64)),
                ]));
            }
        }
    }
    result(Json::Array(out))
}

fn get_realtime_stats(args: &Json) -> Json {
    let device = shellquote(arg_str(args, "device").unwrap_or("eth0"));
    let flags = match arg_str(args, "mode").unwrap_or("interface") {
        "interface" => format!("-i {device}"),
        "wireless" => format!("-r {device}"),
        "conntrack" => "-c".to_owned(),
        "load" => "-l".to_owned(),
        _ => return error("Invalid mode"),
    };
    let out = popen(&format!("luci-bwc {flags}"));
    match json::parse(&format!("[{out}]")) {
        Ok(v) => result(v),
        Err(e) => error(&e),
    }
}

fn get_builtin_ethernet_ports() -> Json {
    let board = readfile("/etc/board.json").and_then(|t| json::parse(&t).ok()).unwrap_or(Json::Object(vec![]));
    let mut ports = Vec::new();
    for k in ["lan", "wan"] {
        let Some(net) = board.get("network").and_then(|n| n.get(k)) else { continue };
        match net.get("ports") {
            Some(Json::Array(list)) => {
                for ifname in list {
                    ports.push(obj(vec![("role", s(k)), ("device", ifname.clone())]));
                }
            }
            _ => {
                if let Some(Json::Str(d)) = net.get("device") {
                    ports.push(obj(vec![("role", s(k)), ("device", s(d))]));
                }
            }
        }
    }
    if util::machine() == "x86_64" {
        let first = ports.first().and_then(|p| p.get("device")).and_then(Json::as_str).map(str::to_owned);
        if let Some(first) = first.filter(|d| d.starts_with("eth") && d[3..].bytes().all(|b| b.is_ascii_digit()) && d.len() > 3) {
            let bus = std::fs::canonicalize(format!("/sys/class/net/{first}/device/subsystem")).ok();
            for netdev in lsdir("/sys/class/net") {
                if !(netdev.starts_with("eth") && netdev.len() > 3 && netdev[3..].bytes().all(|b| b.is_ascii_digit())) {
                    continue;
                }
                if ports.iter().any(|p| p.get("device").and_then(Json::as_str) == Some(netdev.as_str())) {
                    continue;
                }
                if std::fs::canonicalize(format!("/sys/class/net/{netdev}/device/subsystem")).ok() != bus {
                    continue;
                }
                ports.push(obj(vec![("role", s("unknown")), ("device", Json::Str(netdev))]));
            }
        }
    }
    result(Json::Array(ports))
}

fn get_odhcp6c_stats(ctx: &Ctx) -> Result<Json, i32> {
    let Some(Json::Object(devs)) = ctx.ubus_call("network.device", "status", None) else { return Err(status::NO_DATA) };
    let mut stats: Vec<(String, Json)> = Vec::new();
    for (dev, _) in devs {
        if let Some(m) = ctx.ubus_call(&format!("odhcp6c.{dev}"), "get_statistics", None) {
            stats.push((dev, m));
        }
    }
    Ok(result(Json::Object(stats)))
}

/// Dispatch one `luci` method (raw blobmsg payload for validation).
pub fn call(ctx: &Ctx, method: &str, raw: &[u8]) -> Result<Option<Json>, i32> {
    validate(method, raw)?;
    let args = fields_to_json(raw);
    let out = match method {
        "getVersion" => get_version(),
        "getInitList" => get_init_list(&args),
        "setInitAction" => set_init_action(&args),
        "getUnixtime" => result(Json::Int(now())),
        "setLocaltime" => set_localtime(&args),
        "getTimezones" => get_timezones(),
        "getLEDs" => get_leds(),
        "getUSBDevices" => get_usb_devices(),
        "getConntrackHelpers" => get_conntrack_helpers(),
        "getFeatures" => get_features(),
        "getSwconfigFeatures" => get_swconfig_features(&args),
        "getSwconfigPortState" => get_swconfig_port_state(&args),
        "setPassword" => set_password(&args),
        "getBlockDevices" => get_block_devices(),
        "setBlockDetect" => set_block_detect(),
        "getMountPoints" => get_mount_points(),
        "getRealtimeStats" => get_realtime_stats(&args),
        "getConntrackList" => result(Json::Array(conntrack_list())),
        "getProcessList" => result(Json::Array(process_list())),
        "getBuiltinEthernetPorts" => get_builtin_ethernet_ports(),
        "getOdhcp6cStats" => get_odhcp6c_stats(ctx)?,
        _ => return Err(status::METHOD_NOT_FOUND),
    };
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use owrt_ubus::BlobBuf;

    #[test]
    fn validation_checks_every_supplied_field_and_preserves_the_session_exception() {
        for (method, policy) in signature() {
            assert_eq!(validate(method, &[]), Ok(()));
            let mut args = BlobBuf::new();
            for (name, ty) in &policy {
                args.msg_field(*ty as u32, name, &[0; 4]);
            }
            args.msg_string("ubus_rpc_session", "session");
            assert_eq!(validate(method, &args.into_payload()), Ok(()), "{method}");

            let mut args = BlobBuf::new();
            args.msg_u32("ubus_rpc_session", 1);
            assert_eq!(validate(method, &args.into_payload()), Err(status::INVALID_ARGUMENT), "{method}");
            let mut args = BlobBuf::new();
            args.msg_string("unexpected", "value");
            assert_eq!(validate(method, &args.into_payload()), Err(status::INVALID_ARGUMENT), "{method}");

            for (name, ty) in policy {
                let mut args = BlobBuf::new();
                args.msg_field(ty as u32, name, &[0; 4]);
                args.msg_bool(name, true);
                assert_eq!(validate(method, &args.into_payload()), Err(status::INVALID_ARGUMENT), "{method}.{name}");
            }
        }
        assert_eq!(validate("not-a-method", &[]), Err(status::METHOD_NOT_FOUND));
    }
}
