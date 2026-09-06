//! rpcd session.c port: session store, ACL grants/lookup, login, freeze/thaw.
//!
//! Storage mirrors the C AVL trees with BTreeMaps (strcmp order): sessions by
//! id, per-session data by key, ACL scopes by name; ACL entries within a
//! scope are kept sorted by their wildcard-free prefix key with equal keys in
//! insertion order (avl with allow_dups).

use crate::glob::fnmatch;
use owrt_ubus::blob::{self, Field, MsgType};
use owrt_ubus::json::Json;
use owrt_ubus::{status, BlobBuf};
use std::collections::BTreeMap;
use std::ffi::{c_char, CStr, CString};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::time::{Duration, Instant};

pub const SID_LEN: usize = 32;
pub const DEFAULT_TIMEOUT: i32 = 300;
pub const DEFAULT_SID: &str = "00000000000000000000000000000000";
/// Decision 0013: rpcd-rs keeps its runtime state apart from the C rpcd's
/// /var/run/rpcd, which purges `uci-*` under its own prefix on start.
pub const RUN_DIR: &str = "/var/run/rpcd-rs";
pub const SESSION_DIR: &str = "/var/run/rpcd-rs/sessions";
pub const ACL_DIR: &str = "/usr/share/rpcd/acl.d";

#[cfg_attr(target_env = "gnu", link(name = "crypt"))]
extern "C" {
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

/// A stored session data value with its original blobmsg type.
#[derive(Clone, Debug)]
pub struct RawField {
    pub ty: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Acl {
    pub object: String,
    pub function: String,
    /// avl key: object up to the first `*?[` (uh_id_len)
    pub key: String,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub id: String,
    pub timeout: i32,
    /// uloop timer deadline; None when no timer is pending (timeout <= 0)
    pub expires: Option<Instant>,
    pub data: BTreeMap<String, RawField>,
    pub acls: BTreeMap<String, Vec<Acl>>,
}

impl Session {
    fn new(id: &str) -> Session {
        Session {
            id: id.to_owned(),
            timeout: 0,
            expires: None,
            data: BTreeMap::new(),
            acls: BTreeMap::new(),
        }
    }

    /// rpc_touch_session
    fn touch(&mut self) {
        if self.timeout > 0 {
            let ms = (self.timeout as i64 * 1000).clamp(0, i32::MAX as i64) as u64;
            self.expires = Some(Instant::now() + Duration::from_millis(ms));
        }
    }

    /// uloop_timeout_remaining64(&t) / 1000
    fn expires_secs(&self) -> u64 {
        match self.expires {
            None => 0, // -1 / 1000 == 0
            Some(end) => {
                let now = Instant::now();
                if end <= now {
                    0
                } else {
                    (end - now).as_millis() as u64 / 1000
                }
            }
        }
    }

    /// rpc_session_grant
    pub fn grant(&mut self, scope: &str, object: Option<&str>, function: Option<&str>) -> i32 {
        let (Some(object), Some(function)) = (object, function) else {
            return status::INVALID_ARGUMENT;
        };
        let key = object[..uh_id_len(object)].to_owned();
        let list = self.acls.entry(scope.to_owned()).or_default();
        if list.iter().any(|a| a.object == object && a.function == function) {
            return 0;
        }
        // insert after the last entry whose key <= new key (avl dup order)
        let pos = list.iter().rposition(|a| a.key.as_str() <= key.as_str()).map_or(0, |i| i + 1);
        list.insert(
            pos,
            Acl {
                object: object.to_owned(),
                function: function.to_owned(),
                key,
            },
        );
        0
    }

    /// rpc_session_revoke
    pub fn revoke(&mut self, scope: &str, object: Option<&str>, function: Option<&str>) -> i32 {
        let Some(list) = self.acls.get_mut(scope) else { return 0 };
        match (object, function) {
            (None, None) => {
                self.acls.remove(scope);
            }
            (Some(object), function) => {
                let function = function.unwrap_or("");
                list.retain(|a| !(a.object == object && a.function == function));
                if list.is_empty() {
                    self.acls.remove(scope);
                }
            }
            _ => {}
        }
        0
    }

    /// rpc_session_acl_allowed
    pub fn allowed(&self, scope: &str, obj: &str, fun: &str) -> bool {
        match self.acls.get(scope) {
            Some(list) => list
                .iter()
                .any(|a| fnmatch(a.object.as_bytes(), obj.as_bytes()) && fnmatch(a.function.as_bytes(), fun.as_bytes())),
            None => false,
        }
    }

    /// rpc_session_set: same-named value is replaced; the value keeps its type.
    pub fn set(&mut self, f: &Field) {
        self.data.insert(
            f.name.to_owned(),
            RawField {
                ty: f.ty,
                data: f.data.to_vec(),
            },
        );
    }

    /// rpc_session_dump_acls
    fn dump_acls(&self, b: &mut BlobBuf) {
        for (scope, list) in &self.acls {
            let c = b.msg_open_table(scope);
            let mut lastobj: Option<&str> = None;
            let mut d: Option<usize> = None;
            for acl in list {
                if lastobj != Some(acl.object.as_str()) {
                    if let Some(cookie) = d.take() {
                        b.msg_close(cookie);
                    }
                    d = Some(b.msg_open_array(&acl.object));
                }
                b.msg_string("", &acl.function);
                lastobj = Some(acl.object.as_str());
            }
            if let Some(cookie) = d {
                b.msg_close(cookie);
            }
            b.msg_close(c);
        }
    }

    fn dump_data(&self, b: &mut BlobBuf) {
        for (name, v) in &self.data {
            b.msg_field(v.ty, name, &v.data);
        }
    }

    /// rpc_session_to_blob
    pub fn to_blob(&self, acls: bool) -> Vec<u8> {
        let mut b = BlobBuf::new();
        b.msg_string("ubus_rpc_session", &self.id);
        b.msg_u32("timeout", self.timeout as u32);
        b.msg_u64("expires", self.expires_secs());
        if acls {
            let c = b.msg_open_table("acls");
            self.dump_acls(&mut b);
            b.msg_close(c);
        }
        let c = b.msg_open_table("data");
        self.dump_data(&mut b);
        b.msg_close(c);
        b.into_payload()
    }
}

/// strcspn(str, "*?[")
fn uh_id_len(s: &str) -> usize {
    s.bytes().position(|c| matches!(c, b'*' | b'?' | b'[')).unwrap_or(s.len())
}

pub struct Store {
    pub sessions: BTreeMap<String, Session>,
    /// uci.c `apply_sid`: the session with a pending rollback-armed apply
    pub apply_sid: Option<String>,
}

impl Store {
    /// rpc_session_api_init: the default session gets the unauthenticated ACLs.
    pub fn new() -> Store {
        let mut store = Store {
            sessions: BTreeMap::new(),
            apply_sid: None,
        };
        let mut ses = Session::new(DEFAULT_SID);
        setup_acls(&mut ses, None);
        store.sessions.insert(DEFAULT_SID.to_owned(), ses);
        store
    }

    /// rpc_random: 16 bytes from /dev/urandom as 32 hex chars.
    fn random_id() -> Option<String> {
        let mut f = fs::File::open("/dev/urandom").ok()?;
        let mut buf = [0u8; 16];
        f.read_exact(&mut buf).ok()?;
        Some(buf.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// rpc_session_create
    pub fn create(&mut self, timeout: i32) -> Option<String> {
        let id = Self::random_id()?;
        let mut ses = Session::new(&id);
        ses.timeout = timeout;
        ses.touch();
        self.sessions.insert(id.clone(), ses);
        Some(id)
    }

    /// rpc_session_get: lookup + touch
    pub fn get(&mut self, id: &str) -> Option<&mut Session> {
        let ses = self.sessions.get_mut(id)?;
        ses.touch();
        Some(ses)
    }

    /// rpc_session_destroy (with the uci savedir purge callback)
    pub fn destroy(&mut self, id: &str) {
        if self.sessions.remove(id).is_some() {
            crate::uciobj::purge_dir(&format!("{RUN_DIR}/uci-{id}"));
        }
    }

    /// rpc_session_access
    pub fn access(&mut self, sid: &str, scope: &str, object: &str, function: &str) -> bool {
        match self.get(sid) {
            Some(ses) => ses.allowed(scope, object, function),
            None => false,
        }
    }

    pub fn next_expiry(&self) -> Option<Instant> {
        self.sessions.values().filter_map(|s| s.expires).min()
    }

    /// Destroy every session whose timer has fired.
    pub fn expire(&mut self) {
        let now = Instant::now();
        let dead: Vec<String> = self
            .sessions
            .values()
            .filter(|s| s.expires.is_some_and(|e| e <= now))
            .map(|s| s.id.clone())
            .collect();
        for id in dead {
            self.destroy(&id);
        }
    }

    /// rpc_session_freeze: persist non-default sessions for a re-exec.
    pub fn freeze(&self) {
        let _ = fs::DirBuilder::new().recursive(true).mode(0o700).create(SESSION_DIR);
        for ses in self.sessions.values() {
            if ses.id == DEFAULT_SID {
                continue;
            }
            let path = format!("{SESSION_DIR}/{}", ses.id);
            let mut b = BlobBuf::new();
            b.put_raw_fields(&ses.to_blob(false));
            let bytes = b.as_bytes().to_vec();
            let _ = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, &bytes));
        }
    }

    /// rpc_session_thaw
    pub fn thaw(&mut self) {
        let Ok(entries) = fs::read_dir(SESSION_DIR) else { return };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !validate_sid(&name) {
                continue;
            }
            let path = format!("{SESSION_DIR}/{name}");
            if let Ok(bytes) = fs::read(&path) {
                self.from_blob(&bytes);
            }
            let _ = fs::remove_file(&path);
        }
    }

    /// rpc_session_from_blob
    #[allow(clippy::wrong_self_convention)] // C name; fills an existing session
    fn from_blob(&mut self, bytes: &[u8]) -> bool {
        let Some((head, _)) = blob::attr_at(bytes, 0) else { return false };
        let mut sid = None;
        let mut timeout = None;
        let mut expires = None;
        let mut data: Option<Vec<u8>> = None;
        for f in blob::fields(head.payload) {
            match (f.name, f.ty) {
                ("ubus_rpc_session", t) if t == MsgType::String as u32 => sid = f.as_str().map(str::to_owned),
                ("timeout", t) if t == MsgType::Int32 as u32 => timeout = f.as_u32(),
                ("expires", t) if t == MsgType::Int64 as u32 => expires = f.as_u64(),
                ("data", t) if t == MsgType::Table as u32 => data = Some(f.data.to_vec()),
                _ => {}
            }
        }
        let (Some(sid), Some(timeout), Some(expires), Some(data)) = (sid, timeout, expires, data) else {
            return false;
        };
        let mut ses = Session::new(&sid[..sid.len().min(SID_LEN)]);
        ses.timeout = timeout as i32;
        let mut user: Option<String> = None;
        for f in blob::fields(&data) {
            ses.set(&f);
            if f.ty == MsgType::String as u32 && f.name == "username" {
                user = f.as_str().map(str::to_owned);
            }
        }
        if let Some(user) = user {
            if let Some(login) = test_login(&user, None) {
                setup_acls(&mut ses, Some(&login));
            }
        }
        let ms = (expires as i64 * 1000).clamp(0, i32::MAX as i64) as u64;
        ses.expires = Some(Instant::now() + Duration::from_millis(ms));
        self.sessions.insert(ses.id.clone(), ses);
        true
    }
}

/// rpc_validate_sid
pub fn validate_sid(id: &str) -> bool {
    id.len() == SID_LEN && id.bytes().all(|b| b.is_ascii_hexdigit())
}

// ------------------------------------------------------------ login

/// The `login` uci section that matched: its option lists are what
/// rpc_login_test_permission consults.
pub struct Login {
    pub options: Vec<(String, owrt_uci::OptionValue)>,
}

/// rpc_login_test_password
fn test_password(hash: &str, password: &str) -> bool {
    if hash.is_empty() {
        return true;
    }
    if let Some(user) = hash.strip_prefix("$p$") {
        // getspnam(user)->sp_pwdp
        let Ok(shadow) = crate::util::read_lossy("/etc/shadow") else { return false };
        for line in shadow.lines() {
            let mut it = line.splitn(3, ':');
            let (Some(name), Some(pw)) = (it.next(), it.next()) else { continue };
            if name == user {
                return test_password(pw, password);
            }
        }
        return false;
    }
    let (Ok(key), Ok(salt)) = (CString::new(password), CString::new(hash)) else { return false };
    // SAFETY: crypt takes two NUL-terminated strings and returns either NULL
    // or a pointer to libc's static result buffer, valid until the next call
    // (we are single-threaded here and copy it out immediately).
    let out = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    if out.is_null() {
        return false;
    }
    // SAFETY: crypt returned non-null (checked above); the string it points at
    // is NUL-terminated and stays valid until the next crypt call, and it is
    // compared before anything else can call crypt.
    let s = unsafe { CStr::from_ptr(out) };
    s.to_bytes() == hash.as_bytes()
}

/// rpc_login_test_login: find a `login` section whose username matches and
/// (when password is Some) whose password verifies.
pub fn test_login(username: &str, password: Option<&str>) -> Option<Login> {
    let mut ctx = owrt_uci::Context::new();
    let pidx = owrt_uci::file::load(&mut ctx, "rpcd").ok()?;
    let p = &ctx.root[pidx];
    for s in &p.sections {
        if s.ty != "login" {
            continue;
        }
        let Some(u) = s.find_option("username") else { continue };
        let owrt_uci::OptionValue::Str(u) = &s.options[u].value else { continue };
        if u.as_slice() != username.as_bytes() {
            continue;
        }
        let login = Login {
            options: s.options.iter().map(|o| (o.name.clone(), o.value.clone())).collect(),
        };
        let Some(password) = password else { return Some(login) };
        let Some(pw) = s.find_option("password") else { continue };
        let owrt_uci::OptionValue::Str(hash) = &s.options[pw].value else { continue };
        if test_password(&String::from_utf8_lossy(hash), password) {
            return Some(login);
        }
    }
    None
}

/// rpc_login_test_permission
fn test_permission(login: Option<&Login>, perm: &str, group: &str) -> bool {
    let Some(login) = login else {
        return group == "unauthenticated";
    };
    for (name, value) in &login.options {
        let owrt_uci::OptionValue::List(items) = value else { continue };
        if name != perm {
            continue;
        }
        // negative expressions first
        for item in items {
            let Some(mut p) = item.strip_prefix(b"!") else { continue };
            while let [first, rest @ ..] = p {
                if !first.is_ascii_whitespace() {
                    break;
                }
                p = rest;
            }
            if p.is_empty() {
                continue;
            }
            if fnmatch(p, group.as_bytes()) {
                return false;
            }
        }
        for item in items {
            if item.is_empty() || item.starts_with(b"!") {
                continue;
            }
            if fnmatch(item, group.as_bytes()) {
                return true;
            }
        }
    }
    if perm == "read" {
        return test_permission(Some(login), "write", group);
    }
    false
}

/// rpc_login_setup_acl_scope
fn setup_acl_scope(ses: &mut Session, perm: &str, scope: &str, value: &Json) {
    match value {
        Json::Object(objs) => {
            for (obj, funcs) in objs {
                let Json::Array(funcs) = funcs else { continue };
                for f in funcs {
                    if let Json::Str(f) = f {
                        ses.grant(scope, Some(obj), Some(f));
                    }
                }
            }
        }
        Json::Array(objs) => {
            for o in objs {
                if let Json::Str(o) = o {
                    ses.grant(scope, Some(o), Some(perm));
                }
            }
        }
        _ => {}
    }
}

/// rpc_login_setup_acl_file
fn setup_acl_file(ses: &mut Session, login: Option<&Login>, path: &str) {
    let text = crate::util::read_lossy(path).unwrap_or_default();
    let Ok(Json::Object(groups)) = owrt_ubus::json::parse(&text) else {
        eprintln!("Failed to parse {path}");
        return;
    };
    for (group, perms) in &groups {
        let Json::Object(perms) = perms else { continue };
        for (perm, scopes) in perms {
            let Json::Object(scopes) = scopes else { continue };
            if perm != "read" && perm != "write" {
                continue;
            }
            if !test_permission(login, perm, group) {
                continue;
            }
            for (scope, value) in scopes {
                setup_acl_scope(ses, perm, scope, value);
                ses.grant("access-group", Some(group), Some(perm));
            }
        }
    }
}

/// rpc_login_setup_acls: glob(ACL_DIR/*.json) in sorted order.
pub fn setup_acls(ses: &mut Session, login: Option<&Login>) {
    let Ok(entries) = fs::read_dir(ACL_DIR) else { return };
    let mut files: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.') && n.ends_with(".json"))
        .collect();
    files.sort();
    for f in files {
        setup_acl_file(ses, login, &format!("{ACL_DIR}/{f}"));
    }
}

// ------------------------------------------------------------ ubus methods

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    use MsgType::*;
    vec![
        ("create", vec![("timeout", Int32)]),
        ("list", vec![("ubus_rpc_session", String)]),
        ("grant", vec![("ubus_rpc_session", String), ("scope", String), ("objects", Array)]),
        ("revoke", vec![("ubus_rpc_session", String), ("scope", String), ("objects", Array)]),
        ("access", vec![("ubus_rpc_session", String), ("scope", String), ("object", String), ("function", String)]),
        ("set", vec![("ubus_rpc_session", String), ("values", Table)]),
        ("get", vec![("ubus_rpc_session", String), ("keys", Array)]),
        ("unset", vec![("ubus_rpc_session", String), ("keys", Array)]),
        ("destroy", vec![("ubus_rpc_session", String)]),
        ("login", vec![("username", String), ("password", String), ("timeout", Int32)]),
    ]
}

/// blobmsg_parse with a one-entry policy: first field with that name and type.
pub fn arg<'a>(raw: &'a [u8], name: &str, ty: MsgType) -> Option<Field<'a>> {
    blob::fields(raw).find(|f| f.name == name && f.ty == ty as u32)
}

pub fn arg_str<'a>(raw: &'a [u8], name: &str) -> Option<&'a str> {
    arg(raw, name, MsgType::String).and_then(|f| f.as_str())
}

/// Result of a session method: status plus zero or more DATA payloads.
pub struct Reply {
    pub code: i32,
    pub data: Vec<Vec<u8>>,
}

fn ok(data: Vec<Vec<u8>>) -> Reply {
    Reply { code: 0, data }
}
fn err(code: i32) -> Reply {
    Reply { code, data: vec![] }
}

pub fn call(store: &mut Store, method: &str, raw: &[u8]) -> Reply {
    match method {
        "create" => {
            let timeout = arg(raw, "timeout", MsgType::Int32)
                .and_then(|f| f.as_u32())
                .map(|v| v as i32)
                .unwrap_or(DEFAULT_TIMEOUT);
            match store.create(timeout) {
                Some(id) => ok(vec![store.sessions[&id].to_blob(true)]),
                None => ok(vec![]),
            }
        }
        "list" => match arg_str(raw, "ubus_rpc_session") {
            None => ok(store.sessions.values().map(|s| s.to_blob(true)).collect()),
            Some(sid) => match store.get(sid) {
                Some(ses) => ok(vec![ses.to_blob(true)]),
                None => err(status::NOT_FOUND),
            },
        },
        "grant" | "revoke" => {
            let Some(sid) = arg_str(raw, "ubus_rpc_session") else { return err(status::INVALID_ARGUMENT) };
            let scope = arg_str(raw, "scope").unwrap_or("ubus").to_owned();
            let objects = arg(raw, "objects", MsgType::Array).map(|f| f.data.to_vec());
            let grant = method == "grant";
            let Some(ses) = store.get(sid) else { return err(status::NOT_FOUND) };
            let Some(objects) = objects else {
                let rc = if grant { ses.grant(&scope, None, None) } else { ses.revoke(&scope, None, None) };
                return err(rc);
            };
            for pair in blob::fields(&objects) {
                if pair.ty != MsgType::Array as u32 {
                    continue;
                }
                let mut object = None;
                let mut function = None;
                for s in pair.children() {
                    if s.ty != MsgType::String as u32 {
                        continue;
                    }
                    if object.is_none() {
                        object = s.as_str();
                    } else if function.is_none() {
                        function = s.as_str();
                    } else {
                        break;
                    }
                }
                if let (Some(o), Some(f)) = (object, function) {
                    if grant {
                        ses.grant(&scope, Some(o), Some(f));
                    } else {
                        ses.revoke(&scope, Some(o), Some(f));
                    }
                }
            }
            ok(vec![])
        }
        "access" => {
            let Some(sid) = arg_str(raw, "ubus_rpc_session") else { return err(status::INVALID_ARGUMENT) };
            let scope = arg_str(raw, "scope").unwrap_or("ubus").to_owned();
            let object = arg_str(raw, "object").map(str::to_owned);
            let function = arg_str(raw, "function").map(str::to_owned);
            let Some(ses) = store.get(sid) else { return err(status::NOT_FOUND) };
            let mut b = BlobBuf::new();
            if let (Some(o), Some(f)) = (object, function) {
                b.msg_bool("access", ses.allowed(&scope, &o, &f));
            } else {
                ses.dump_acls(&mut b);
            }
            ok(vec![b.into_payload()])
        }
        "set" => {
            let (Some(sid), Some(values)) = (arg_str(raw, "ubus_rpc_session"), arg(raw, "values", MsgType::Table)) else {
                return err(status::INVALID_ARGUMENT);
            };
            let values = values.data.to_vec();
            let Some(ses) = store.get(sid) else { return err(status::NOT_FOUND) };
            for f in blob::fields(&values) {
                if f.name.is_empty() {
                    continue;
                }
                ses.set(&f);
            }
            ok(vec![])
        }
        "get" => {
            let Some(sid) = arg_str(raw, "ubus_rpc_session") else { return err(status::INVALID_ARGUMENT) };
            let keys = arg(raw, "keys", MsgType::Array).map(|f| f.data.to_vec());
            let Some(ses) = store.get(sid) else { return err(status::NOT_FOUND) };
            let mut b = BlobBuf::new();
            let c = b.msg_open_table("values");
            match keys {
                Some(keys) => {
                    for k in blob::fields(&keys) {
                        if k.ty != MsgType::String as u32 {
                            continue;
                        }
                        let Some(name) = k.as_str() else { continue };
                        if let Some(v) = ses.data.get(name) {
                            b.msg_field(v.ty, name, &v.data);
                        }
                    }
                }
                None => ses.dump_data(&mut b),
            }
            b.msg_close(c);
            ok(vec![b.into_payload()])
        }
        "unset" => {
            let Some(sid) = arg_str(raw, "ubus_rpc_session") else { return err(status::INVALID_ARGUMENT) };
            let keys = arg(raw, "keys", MsgType::Array).map(|f| f.data.to_vec());
            let Some(ses) = store.get(sid) else { return err(status::NOT_FOUND) };
            match keys {
                None => ses.data.clear(),
                Some(keys) => {
                    for k in blob::fields(&keys) {
                        if k.ty != MsgType::String as u32 {
                            continue;
                        }
                        if let Some(name) = k.as_str() {
                            ses.data.remove(name);
                        }
                    }
                }
            }
            ok(vec![])
        }
        "destroy" => {
            let Some(sid) = arg_str(raw, "ubus_rpc_session") else { return err(status::INVALID_ARGUMENT) };
            if sid == DEFAULT_SID {
                return err(status::PERMISSION_DENIED);
            }
            if store.get(sid).is_none() {
                return err(status::NOT_FOUND);
            }
            store.destroy(sid);
            ok(vec![])
        }
        "login" => {
            let (Some(username), Some(password)) = (arg_str(raw, "username"), arg_str(raw, "password")) else {
                return err(status::INVALID_ARGUMENT);
            };
            let username = username.to_owned();
            let Some(login) = test_login(&username, Some(password)) else {
                return err(status::PERMISSION_DENIED);
            };
            let timeout = arg(raw, "timeout", MsgType::Int32)
                .and_then(|f| f.as_u32())
                .map(|v| v as i32)
                .unwrap_or(DEFAULT_TIMEOUT);
            // rpc_reclaim_apply_session
            let reclaimed = match store.apply_sid.clone() {
                Some(asid) => match store.get(&asid) {
                    Some(ses) => match ses.data.get("username") {
                        Some(u) if u.ty == MsgType::String as u32 => {
                            let stored = u.data.split(|&b| b == 0).next().unwrap_or(&[]);
                            if stored == username.as_bytes() { Some(asid) } else { None }
                        }
                        _ => None,
                    },
                    None => None,
                },
                None => None,
            };
            let sid = match reclaimed {
                Some(sid) => sid,
                None => match store.create(timeout) {
                    Some(sid) => sid,
                    None => return err(status::UNKNOWN_ERROR),
                },
            };
            let ses = store.sessions.get_mut(&sid).expect("just created");
            setup_acls(ses, Some(&login));
            // rpc_session_set(ses, tb[RPC_L_USERNAME]) keeps the field as sent
            if let Some(f) = arg(raw, "username", MsgType::String) {
                ses.set(&f);
            }
            ok(vec![ses.to_blob(true)])
        }
        _ => err(status::METHOD_NOT_FOUND),
    }
}
