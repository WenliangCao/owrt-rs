//! Everything fw4 reads from the outside world (UCI files, ubus, /sys, /proc,
//! nft) behind one struct with a real backend and a mock backend that mirrors
//! the upstream test-suite fixture layout (`uci/*.json`, `ubus/*.json`,
//! `fs/{open,stat,opendir,glob,popen}~<mangled path>`). The mock backend also
//! emits the `[call] ...` trace lines the upstream tests expect on stderr.

use crate::uci::Config;
use owrt_ubus::convert::{fields_to_json, object_to_payload};
use owrt_ubus::json::{self, Json};
use std::io::{self, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;

pub struct Inputs {
    mock_dirs: Option<Vec<String>>,
    trace: bool,
    pub uci_dir: String,
}

fn mangle(s: &str) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

/// mocklib `format_json` used in trace lines.
fn format_json(v: &Json) -> String {
    fn format_value(v: &Json) -> String {
        match v {
            Json::Object(o) => format!("{{ /* {} keys */ }}", o.len()),
            Json::Array(a) => format!("[ /* {} items */ ]", a.len()),
            Json::Str(s) => {
                let s = if s.chars().count() > 64 {
                    format!("{}...", s.chars().take(64).collect::<String>())
                } else {
                    s.clone()
                };
                Json::Str(s).to_compact()
            }
            other => other.to_compact(),
        }
    }
    match v {
        Json::Object(o) => {
            let mut keys: Vec<&(String, Json)> = o.iter().collect();
            keys.sort_by(|a, b| a.0.cmp(&b.0));
            let mut rv = String::from("{");
            for (i, (k, val)) in keys.iter().enumerate() {
                rv.push_str(&format!(
                    "{} {}: {}",
                    if i > 0 { "," } else { "" },
                    Json::Str(k.clone()).to_compact(),
                    format_value(val)
                ));
            }
            rv.push_str(" }");
            rv
        }
        Json::Array(a) => {
            let mut rv = String::from("[");
            for (i, val) in a.iter().enumerate() {
                rv.push_str(&format!(
                    "{} {}",
                    if i > 0 { "," } else { "" },
                    format_value(val)
                ));
            }
            rv.push_str(" ]");
            rv
        }
        other => format_value(other),
    }
}

impl Inputs {
    pub fn real() -> Inputs {
        Inputs {
            mock_dirs: None,
            trace: false,
            uci_dir: "/etc/config".into(),
        }
    }

    pub fn mock(dirs: Vec<String>, trace: bool) -> Inputs {
        Inputs {
            mock_dirs: Some(dirs),
            trace,
            uci_dir: String::new(),
        }
    }

    pub fn is_mock(&self) -> bool {
        self.mock_dirs.is_some()
    }

    fn trace(&self, line: &str) {
        if self.trace {
            let _ = writeln!(std::io::stderr(), "[call] {line}");
        }
    }

    fn mock_read(&self, rel: &str) -> Option<String> {
        for dir in self.mock_dirs.as_ref()? {
            if let Ok(s) = std::fs::read_to_string(format!("{dir}/{rel}")) {
                return Some(s);
            }
        }
        None
    }

    fn mock_json(&self, rel: &str) -> Option<Json> {
        json::parse(&self.mock_read(rel)?).ok()
    }

    /// `uci.cursor().load(name)`; `name` may be a full path.
    pub fn uci_load(&self, name: &str) -> Config {
        let base = name.rsplit('/').next().unwrap_or(name);
        if self.is_mock() {
            if let Some(j) = self.mock_json(&format!("uci/{base}.json")) {
                return Config::from_mock(&j);
            }
            // plain UCI text fixture (device captures)
            return match self.mock_read(&format!("uci/{base}")) {
                Some(text) => Config::parse_text(base, &text),
                None => Config::empty(),
            };
        }
        Config::load(&self.uci_dir, name)
    }

    /// `ubus.connect().call(object, method, args)`; None on failure.
    pub fn ubus_call(&self, object: &str, method: &str, args: Option<&Json>) -> Option<Json> {
        if self.is_mock() {
            let mut sig = vec![format!("{object}~{method}")];
            if let Some(Json::Object(items)) = args {
                let mut keys: Vec<&(String, Json)> = items.iter().collect();
                keys.sort_by(|a, b| a.0.cmp(&b.0));
                for (k, v) in keys {
                    match v {
                        Json::Str(_)
                        | Json::Bytes(_)
                        | Json::Int(_)
                        | Json::Float(_)
                        | Json::Bool(_) => {
                            sig.push(format!("{k}-{}", mangle(&crate::val::to_str(v))))
                        }
                        Json::Array(_) => sig.push("array".into()),
                        Json::Object(_) => sig.push("object".into()),
                        Json::Null => sig.push("null".into()),
                    }
                }
            }
            while !sig.is_empty() {
                if let Some(mock) = self.mock_json(&format!("ubus/{}.json", sig.join("~"))) {
                    self.trace(&format!(
                        "ctx.call object <{object}> method <{method}> args <{}>",
                        args.map(format_json).unwrap_or_else(|| "null".into())
                    ));
                    return Some(mock);
                }
                sig.pop();
            }
            return None;
        }
        // C ubus_connect_ctx initializes uloop before attempting to connect,
        // so SIGPIPE becomes ignored even when the bus socket is unavailable.
        owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);
        let mut conn = owrt_ubus::Connection::connect(None).ok()?;
        Self::call_on(&mut conn, object, method, args)
    }

    fn call_on(
        conn: &mut owrt_ubus::Connection,
        object: &str,
        method: &str,
        args: Option<&Json>,
    ) -> Option<Json> {
        let id = conn.lookup_id(object, 3000).ok()?;
        let payload = args.map(object_to_payload).unwrap_or_default();
        let reply = conn.invoke_status(id, method, &payload, 30000).ok()?;
        if reply.status != 0 {
            return None;
        }
        fields_to_json(&reply.fields()).ok()
    }

    /// fw4.read_ubus uses one connection for both input objects and emits
    /// its connection warning once, even if both calls would have failed.
    pub fn ubus_state(&self) -> io::Result<(Option<Json>, Option<Json>)> {
        let args = Json::Object(vec![("type".into(), Json::Str("firewall".into()))]);
        if self.is_mock() {
            return Ok((
                self.ubus_call("network.interface", "dump", None),
                self.ubus_call("service", "get_data", Some(&args)),
            ));
        }
        // C ubus_connect_ctx initializes uloop before attempting to connect,
        // so SIGPIPE becomes ignored even when the bus socket is unavailable.
        owrt_ubus::sys::ignore_signal(owrt_ubus::sys::SIGPIPE);
        let mut conn = owrt_ubus::Connection::connect(None)?;
        Ok((
            Self::call_on(&mut conn, "network.interface", "dump", None),
            Self::call_on(&mut conn, "service", "get_data", Some(&args)),
        ))
    }

    /// `fs.open(path, "r")` + read everything.
    pub fn read_all(&self, path: &str) -> Option<String> {
        self.read_open(path).ok()
    }

    /// Preserve open failures separately from a read that reaches an error
    /// (e.g. a directory). parse_setfile's line loop treats the latter as EOF.
    pub fn read_open(&self, path: &str) -> io::Result<String> {
        if self.is_mock() {
            let data = self
                .mock_read(&format!("fs/open~{}.txt", mangle(path)))
                .ok_or_else(|| io::Error::other("Unspecified error"))?;
            self.trace(&format!("fs.open path <{path}> mode <r>"));
            return Ok(data);
        }
        // fs.readfile returns raw bytes; one stray non-UTF-8 byte in an include
        // file must not make the whole file vanish (DEVIATION: invalid bytes
        // become U+FFFD instead of being copied through).
        let mut file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        let _ = file.read_to_end(&mut bytes);
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// `fs.readfile(path)`.
    pub fn readfile(&self, path: &str) -> Option<String> {
        if self.is_mock() {
            let data = self.mock_read(&format!("fs/open~{}.txt", mangle(path)))?;
            self.trace(&format!("fs.readfile path <{path}> limit <null>"));
            return Some(data);
        }
        // fs.readfile returns raw bytes; one stray non-UTF-8 byte in an include
        // file must not make the whole file vanish (DEVIATION: invalid bytes
        // become U+FFFD instead of being copied through).
        std::fs::read(path)
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// `fs.access(path)`.
    pub fn access(&self, path: &str) -> bool {
        if self.is_mock() {
            return self
                .mock_read(&format!("fs/open~{}.txt", mangle(path)))
                .is_some();
        }
        Path::new(path).exists()
    }

    /// `fs.stat(path)?.type == "directory"`.
    pub fn stat_is_dir(&self, path: &str) -> bool {
        if self.is_mock() {
            let mock = self.mock_json(&format!("fs/stat~{}.json", mangle(path)));
            self.trace(&format!("fs.stat path <{path}>"));
            return match mock {
                Some(m) => m.get("type").and_then(Json::as_str) == Some("directory"),
                None => path.ends_with('/'),
            };
        }
        Path::new(path).is_dir()
    }

    /// `fs.readlink(path) ?? path`.
    pub fn readlink_or_self(&self, path: &str) -> String {
        if self.is_mock() {
            self.trace(&format!("fs.readlink path <{path}>"));
            return path.to_owned();
        }
        std::fs::read_link(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_owned())
    }

    /// `fs.opendir(path)` entries (including "." and ".."), None if missing.
    pub fn opendir(&self, path: &str) -> Option<Vec<String>> {
        if self.is_mock() {
            let mock = self.mock_json(&format!("fs/opendir~{}.json", mangle(path)));
            self.trace(&format!("fs.opendir path <{path}>"));
            return Some(json_strings(mock.as_ref()));
        }
        let rd = std::fs::read_dir(path).ok()?;
        let mut out = vec![".".to_owned(), "..".to_owned()];
        out.extend(
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned()),
        );
        Some(out)
    }

    /// `fs.lsdir(path)` (without "." and "..").
    pub fn lsdir(&self, path: &str) -> Vec<String> {
        if self.is_mock() {
            let mock = self.mock_json(&format!("fs/opendir~{}.json", mangle(path)));
            self.trace(&format!("fs.lsdir path <{path}>"));
            return json_strings(mock.as_ref());
        }
        match std::fs::read_dir(path) {
            Ok(rd) => rd
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// `fs.glob(pattern)`; only `dir/*.ext` patterns are needed.
    pub fn glob(&self, pattern: &str) -> Vec<String> {
        if self.is_mock() {
            let mock = self.mock_json(&format!("fs/glob~{}.json", mangle(pattern)));
            self.trace(&format!("fs.glob pattern <{pattern}>"));
            return json_strings(mock.as_ref());
        }
        let (dir, file_pat) = match pattern.rsplit_once('/') {
            Some(x) => x,
            None => (".", pattern),
        };
        let Some(suffix) = file_pat.strip_prefix('*') else {
            return if Path::new(pattern).exists() {
                vec![pattern.to_owned()]
            } else {
                vec![]
            };
        };
        let mut out: Vec<String> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !n.starts_with('.') && n.ends_with(suffix))
                .map(|n| format!("{dir}/{n}"))
                .collect(),
            Err(_) => Vec::new(),
        };
        out.sort();
        out
    }

    /// `fs.popen(cmd, "r").read("all")`.
    pub fn popen_read(&self, cmd: &str) -> io::Result<String> {
        if self.is_mock() {
            let data = self.mock_read(&format!("fs/popen~{}.txt", mangle(cmd)));
            if data.is_some() {
                self.trace(&format!("fs.popen cmdline <{cmd}> mode <r>"));
            }
            return data.ok_or_else(|| io::Error::other("Unspecified error"));
        }
        let out = Command::new("/bin/sh").arg("-c").arg(cmd).output()?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// `system(cmd)` exit code.
    pub fn system(&self, cmd: &str) -> i32 {
        if self.is_mock() {
            self.trace(&format!("system command <{cmd}> timeout <null>"));
            return 0;
        }
        match Command::new("/bin/sh").arg("-c").arg(cmd).status() {
            Ok(st) => exit_code(st),
            Err(_) => -1,
        }
    }

    /// `system([argv...], timeout_ms)` exit code (no shell).
    pub fn system_argv(&self, argv: &[String], timeout_ms: u64) -> i32 {
        if self.is_mock() {
            let arr = Json::Array(argv.iter().map(|a| Json::Str(a.clone())).collect());
            self.trace(&format!(
                "system command <{}> timeout <{timeout_ms}>",
                format_json(&arr)
            ));
            return 0;
        }
        let Some((prog, rest)) = argv.split_first() else {
            return -1;
        };
        let mut command = Command::new(prog);
        command.args(rest);
        // ucode system() preserves the inherited disposition; Command resets
        // SIGPIPE unless explicitly restored in its child hook.
        let Ok(sigpipe) = owrt_platform::unix::observe_signal(owrt_ubus::sys::SIGPIPE) else {
            return -1;
        };
        owrt_platform::unix::inherit_signal(&mut command, owrt_ubus::sys::SIGPIPE, sigpipe);
        let Ok(mut child) = command.spawn() else {
            return -1;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            match child.try_wait() {
                Ok(Some(st)) => return exit_code(st),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        return child.wait().map(exit_code).unwrap_or(-1);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(_) => return -1,
            }
        }
    }

    /// `fs.open(path, "w")` + write; used for the state file.
    pub fn write_file(&self, path: &str, data: &str) -> io::Result<()> {
        if self.is_mock() {
            return Ok(());
        }
        std::fs::write(path, data)
    }
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(1))
}

/// Report this operation's errno. The pinned ucode fs.open() does not set
/// fs.last_error on open failure, so its fs.error() can report an unrelated
/// earlier error; retaining that stale state is not a compatibility goal.
pub fn fs_error(error: &io::Error) -> String {
    let text = error.to_string();
    if let Some(code) = error.raw_os_error() {
        text.strip_suffix(&format!(" (os error {code})"))
            .unwrap_or(&text)
            .to_owned()
    } else {
        text
    }
}
fn json_strings(v: Option<&Json>) -> Vec<String> {
    match v {
        Some(Json::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mangling_and_trace_format() {
        assert_eq!(
            mangle("/sys/class/net/eth0/flags"),
            "_sys_class_net_eth0_flags"
        );
        assert_eq!(
            mangle("/usr/sbin/nft --terse --json list flowtables inet"),
            "_usr_sbin_nft_--terse_--json_list_flowtables_inet"
        );
        assert_eq!(
            mangle("/usr/share/nftables.d/table-pre/*.nft"),
            "_usr_share_nftables_d_table-pre_nft"
        );
        let args = json::parse(r#"{"type":"firewall"}"#).unwrap();
        assert_eq!(format_json(&args), r#"{ "type": "firewall" }"#);
    }
}
