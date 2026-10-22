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
use std::ffi::CString;
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
pub const ACL_DIR: &str = "/usr/share/rpcd/acl.d";

/// A stored session data value with its original blobmsg type.
#[derive(Clone)]
pub struct RawField {
    pub ty: u32,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for RawField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawField")
            .field("ty", &self.ty)
            .field("data_len", &self.data.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct Acl {
    pub object: Vec<u8>,
    pub function: String,
    /// avl key: object up to the first `*?[` (uh_id_len)
    pub key: Vec<u8>,
}

#[derive(Clone)]
pub struct Session {
    pub id: String,
    /// Independent random name: directory listings must not reveal the SID.
    dirname: String,
    timeout: i32,
    /// uloop timer deadline; None when no timer is pending (timeout <= 0)
    expires: Option<Instant>,
    pub data: BTreeMap<String, RawField>,
    pub acls: BTreeMap<String, Vec<Acl>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The SID is a bearer credential; arbitrary data keys and values may
        // hold credentials too. Never expose them through derived diagnostics.
        f.debug_struct("Session")
            .field("timeout", &self.timeout)
            .field("expires", &self.expires)
            .field("data_count", &self.data.len())
            .field("acl_scope_count", &self.acls.len())
            .finish_non_exhaustive()
    }
}

impl Session {
    fn new(id: &str, dirname: String) -> Session {
        Session {
            id: id.to_owned(),
            dirname,
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
        self.grant_bytes(scope, object.map(str::as_bytes), function)
    }

    fn grant_bytes(&mut self, scope: &str, object: Option<&[u8]>, function: Option<&str>) -> i32 {
        let (Some(object), Some(function)) = (object, function) else {
            return status::INVALID_ARGUMENT;
        };
        // C stores the object as a C string, so the key ends at a NUL as well.
        let end = object
            .iter()
            .position(|c| matches!(c, b'*' | b'?' | b'[' | 0))
            .unwrap_or(object.len());
        let key = object[..end].to_vec();
        let list = self.acls.entry(scope.to_owned()).or_default();
        if list
            .iter()
            .any(|a| a.object == object && a.function == function)
        {
            return 0;
        }
        // insert after the last entry whose key <= new key (avl dup order)
        let pos = list.iter().rposition(|a| a.key <= key).map_or(0, |i| i + 1);
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
        self.revoke_bytes(scope, object.map(str::as_bytes), function)
    }

    fn revoke_bytes(&mut self, scope: &str, object: Option<&[u8]>, function: Option<&str>) -> i32 {
        let Some(list) = self.acls.get_mut(scope) else {
            return 0;
        };
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
        self.allowed_bytes(scope, obj.as_bytes(), fun)
    }

    fn allowed_bytes(&self, scope: &str, obj: &[u8], fun: &str) -> bool {
        let Some(list) = self.acls.get(scope) else {
            return false;
        };
        let matches =
            |a: &Acl| fnmatch(&a.object, obj) && fnmatch(a.function.as_bytes(), fun.as_bytes());
        // Small scopes benefit from a simple scan, including the usual single
        // wildcard grant. Larger scopes are already sorted by literal prefix.
        if list.len() <= 8 {
            return list.iter().any(|a| obj.starts_with(&a.key) && matches(a));
        }
        // A leading wildcard or first literal match was already cheap in the
        // forward scan. Preserve it before searching the remaining key ranges.
        let first = &list[0];
        if obj.starts_with(&first.key) && matches(first) {
            return true;
        }
        let list = &list[1..];
        let mut end = list.partition_point(|a| a.key.as_slice() <= obj);
        while end != 0 {
            let acl = &list[end - 1];
            if obj.starts_with(&acl.key) {
                if matches(acl) {
                    return true;
                }
                end -= 1;
            } else {
                // A smaller key that prefixes obj cannot extend beyond the
                // first differing byte: all longer prefixes sort after acl.
                // Jump over that whole unrelated key range, keeping equal
                // prefix keys (and the empty wildcard prefix) in consideration.
                let common = acl.key.iter().zip(obj).take_while(|(a, b)| a == b).count();
                end = list[..end - 1].partition_point(|a| a.key.as_slice() <= &obj[..common]);
            }
        }
        false
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
            let mut lastobj: Option<&[u8]> = None;
            let mut d: Option<usize> = None;
            for acl in list {
                if lastobj != Some(acl.object.as_slice()) {
                    if let Some(cookie) = d.take() {
                        b.msg_close(cookie);
                    }
                    d = Some(b.msg_open_array_bytes(&acl.object));
                }
                b.msg_string("", &acl.function);
                lastobj = Some(acl.object.as_slice());
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

pub struct Store {
    sessions: BTreeMap<String, Session>,
    run_dir: String,
    /// A lower bound on the next timer. Touch/removal may leave it early,
    /// but insertion and thaw must never leave it later than a live timer.
    expiry_hint: Option<Instant>,
    /// uci.c `apply_sid`: the session with a pending rollback-armed apply
    pub apply_sid: Option<String>,
}

impl Store {
    /// rpc_session_api_init: the default session gets the unauthenticated ACLs.
    pub fn new() -> Store {
        Self::with_random(RUN_DIR, Self::random_id)
    }

    fn with_random(run_dir: &str, mut random: impl FnMut() -> Option<String>) -> Store {
        let mut store = Store {
            sessions: BTreeMap::new(),
            run_dir: run_dir.to_owned(),
            expiry_hint: None,
            apply_sid: None,
        };
        // Like rpc_session_api_init, entropy failure leaves no default session.
        if let Some(dirname) = random().filter(|name| validate_sid(name) && name != DEFAULT_SID) {
            let mut ses = Session::new(DEFAULT_SID, dirname);
            setup_acls(&mut ses, None);
            store.sessions.insert(DEFAULT_SID.to_owned(), ses);
        }
        store
    }

    #[cfg(test)]
    pub(crate) fn at(run_dir: &str) -> Store {
        Self::with_random(run_dir, Self::random_id)
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
        self.create_with_random(timeout, Self::random_id)
    }

    fn create_with_random(
        &mut self,
        timeout: i32,
        mut random: impl FnMut() -> Option<String>,
    ) -> Option<String> {
        let dirname = random()?;
        let id = random()?;
        if !validate_sid(&id)
            || !validate_sid(&dirname)
            || id == DEFAULT_SID
            || id == dirname
            || self.sessions.contains_key(&id)
            || self.sessions.contains_key(&dirname)
            || self
                .sessions
                .values()
                .any(|ses| ses.dirname == dirname || ses.dirname == id)
        {
            return None;
        }
        let mut ses = Session::new(&id, dirname);
        ses.timeout = timeout;
        ses.touch();
        self.insert(ses);
        Some(id)
    }

    /// Return the runtime name without extending the session's lifetime.
    pub fn dirname(&self, id: &str) -> Option<&str> {
        self.sessions.get(id).map(|ses| ses.dirname.as_str())
    }

    /// Return this session's private UCI delta directory, without touching it.
    pub fn savedir(&self, id: &str) -> Option<String> {
        self.dirname(id)
            .map(|name| format!("{}/uci-{name}", self.run_dir))
    }

    /// rpc_session_get: lookup + touch
    pub fn get(&mut self, id: &str) -> Option<&mut Session> {
        let ses = self.sessions.get_mut(id)?;
        ses.touch();
        // Usually touch extends a timer. A thawed record can have a longer
        // remaining time than its timeout, so also include the new deadline.
        Self::note_expiry(&mut self.expiry_hint, ses.expires);
        Some(ses)
    }

    fn note_expiry(hint: &mut Option<Instant>, expires: Option<Instant>) {
        if let Some(end) = expires {
            *hint = Some(hint.map_or(end, |old| old.min(end)));
        }
    }

    fn insert(&mut self, ses: Session) {
        Self::note_expiry(&mut self.expiry_hint, ses.expires);
        self.sessions.insert(ses.id.clone(), ses);
    }

    /// rpc_session_destroy (with the uci savedir purge callback)
    pub fn destroy(&mut self, id: &str) {
        if let Some(ses) = self.sessions.remove(id) {
            crate::uciobj::purge_dir(&format!("{}/uci-{}", self.run_dir, ses.dirname));
        }
    }

    /// rpc_session_access
    pub fn access(&mut self, sid: &str, scope: &str, object: &str, function: &str) -> bool {
        self.access_bytes(sid, scope, object.as_bytes(), function)
    }

    pub fn access_bytes(&mut self, sid: &str, scope: &str, object: &[u8], function: &str) -> bool {
        match self.get(sid) {
            Some(ses) => ses.allowed_bytes(scope, object, function),
            None => false,
        }
    }

    pub fn next_expiry(&self) -> Option<Instant> {
        self.expiry_hint
    }

    /// Destroy every session whose timer has fired.
    pub fn expire(&mut self) {
        if self.expiry_hint.is_some() {
            self.expire_at(Instant::now());
        }
    }

    fn expire_at(&mut self, now: Instant) {
        if !self.expiry_hint.is_some_and(|end| end <= now) {
            return;
        }
        let mut dead = Vec::new();
        let mut next = None;
        for ses in self.sessions.values() {
            if ses.expires.is_some_and(|end| end <= now) {
                dead.push(ses.id.clone());
            } else {
                Self::note_expiry(&mut next, ses.expires);
            }
        }
        self.expiry_hint = next;
        for id in dead {
            self.destroy(&id);
        }
    }

    /// rpc_session_freeze: persist non-default sessions for a re-exec.
    pub fn freeze(&self) {
        let directory = format!("{}/sessions", self.run_dir);
        let _ = fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory);
        for ses in self.sessions.values() {
            if ses.id == DEFAULT_SID {
                continue;
            }
            let path = format!("{directory}/{}", ses.dirname);
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
        let directory = format!("{}/sessions", self.run_dir);
        let Ok(entries) = fs::read_dir(&directory) else {
            return;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !validate_sid(&name) {
                continue;
            }
            let path = format!("{directory}/{name}");
            if let Ok(bytes) = fs::read(&path) {
                self.restore_blob(&bytes, &name, Self::random_id);
            }
            let _ = fs::remove_file(&path);
        }
    }

    /// rpc_session_from_blob
    fn restore_blob(
        &mut self,
        bytes: &[u8],
        dirname: &str,
        mut random: impl FnMut() -> Option<String>,
    ) -> bool {
        let Some((head, _)) = blob::attr_at(bytes, 0) else {
            return false;
        };
        let mut sid = None;
        let mut timeout = None;
        let mut expires = None;
        let mut data: Option<Vec<u8>> = None;
        for f in blob::fields(head.payload) {
            match (f.name, f.ty) {
                ("ubus_rpc_session", t) if t == MsgType::String as u32 => {
                    sid = f.as_str().map(str::to_owned)
                }
                ("timeout", t) if t == MsgType::Int32 as u32 => timeout = f.as_u32(),
                ("expires", t) if t == MsgType::Int64 as u32 => expires = f.as_u64(),
                ("data", t) if t == MsgType::Table as u32 => data = Some(f.data.to_vec()),
                _ => {}
            }
        }
        let (Some(sid), Some(timeout), Some(expires), Some(data)) = (sid, timeout, expires, data)
        else {
            return false;
        };
        if !validate_sid(&sid) || !validate_sid(dirname) || sid == DEFAULT_SID {
            return false;
        }
        let dirname = if dirname == sid {
            // Older frozen sessions used the credential as their filename.
            // Preserve staged changes by renaming before restoring the session;
            // never fall back to publishing its SID when migration fails.
            let Some(name) = random().filter(|name| {
                validate_sid(name)
                    && name != &sid
                    && !self.sessions.contains_key(name)
                    && !self.sessions.values().any(|ses| &ses.dirname == name)
            }) else {
                return false;
            };
            let old = format!("{}/uci-{sid}", self.run_dir);
            let new = format!("{}/uci-{name}", self.run_dir);
            // Avoid replacing any existing staging directory on collision.
            match fs::symlink_metadata(&new) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return false,
            }
            if let Err(error) = fs::rename(&old, &new) {
                if error.kind() != std::io::ErrorKind::NotFound
                    || !fs::symlink_metadata(&old)
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                {
                    return false;
                }
            }
            name
        } else {
            dirname.to_owned()
        };
        let mut ses = Session::new(&sid, dirname);
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
        let ms = (expires as i64)
            .saturating_mul(1000)
            .clamp(0, i32::MAX as i64) as u64;
        ses.expires = Some(Instant::now() + Duration::from_millis(ms));
        self.insert(ses);
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
        let Ok(shadow) = crate::util::read_lossy("/etc/shadow") else {
            return false;
        };
        for line in shadow.lines() {
            let mut it = line.splitn(3, ':');
            let (Some(name), Some(pw)) = (it.next(), it.next()) else {
                continue;
            };
            if name == user {
                return test_password(pw, password);
            }
        }
        return false;
    }
    let (Ok(key), Ok(salt)) = (CString::new(password), CString::new(hash)) else {
        return false;
    };
    owrt_platform::rpcd::crypt_matches(&key, &salt, hash.as_bytes())
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
        let Some(u) = s.find_option("username") else {
            continue;
        };
        let owrt_uci::OptionValue::Str(u) = &s.options[u].value else {
            continue;
        };
        if u.as_slice() != username.as_bytes() {
            continue;
        }
        let login = Login {
            options: s
                .options
                .iter()
                .map(|o| (o.name.clone(), o.value.clone()))
                .collect(),
        };
        let Some(password) = password else {
            return Some(login);
        };
        let Some(pw) = s.find_option("password") else {
            continue;
        };
        let owrt_uci::OptionValue::Str(hash) = &s.options[pw].value else {
            continue;
        };
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
        let owrt_uci::OptionValue::List(items) = value else {
            continue;
        };
        if name != perm {
            continue;
        }
        // negative expressions first
        for item in items {
            let Some(mut p) = item.strip_prefix(b"!") else {
                continue;
            };
            while let [first, rest @ ..] = p {
                if !first.is_ascii_whitespace() {
                    break;
                }
                p = rest;
            }
            if p.is_empty() {
                continue;
            }
            if crate::glob::fnmatch_escaped(p, group.as_bytes()) {
                return false;
            }
        }
        for item in items {
            if item.is_empty() || item.starts_with(b"!") {
                continue;
            }
            if crate::glob::fnmatch_escaped(item, group.as_bytes()) {
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
    // ACL identifiers must never be silently changed into U+FFFD grants.
    // As at the ubus function boundary, reject unrepresentable text. The
    // exact C implementation accepts raw bytes; we skip this entire file.
    let Ok(text) = fs::read_to_string(path) else {
        eprintln!("Failed to read {path}");
        return;
    };
    let Ok(Json::Object(groups)) = owrt_ubus::json::parse(&text) else {
        eprintln!("Failed to parse {path}");
        return;
    };
    for (group, perms) in &groups {
        let Json::Object(perms) = perms else { continue };
        for (perm, scopes) in perms {
            let Json::Object(scopes) = scopes else {
                continue;
            };
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
    let Ok(entries) = fs::read_dir(ACL_DIR) else {
        return;
    };
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
        (
            "grant",
            vec![
                ("ubus_rpc_session", String),
                ("scope", String),
                ("objects", Array),
            ],
        ),
        (
            "revoke",
            vec![
                ("ubus_rpc_session", String),
                ("scope", String),
                ("objects", Array),
            ],
        ),
        (
            "access",
            vec![
                ("ubus_rpc_session", String),
                ("scope", String),
                ("object", String),
                ("function", String),
            ],
        ),
        ("set", vec![("ubus_rpc_session", String), ("values", Table)]),
        ("get", vec![("ubus_rpc_session", String), ("keys", Array)]),
        ("unset", vec![("ubus_rpc_session", String), ("keys", Array)]),
        ("destroy", vec![("ubus_rpc_session", String)]),
        (
            "login",
            vec![
                ("username", String),
                ("password", String),
                ("timeout", Int32),
            ],
        ),
    ]
}

/// blobmsg_parse with a one-entry policy: first field with that name and type.
pub fn arg<'a>(raw: &'a [u8], name: &str, ty: MsgType) -> Option<Field<'a>> {
    blob::fields(raw).find(|f| f.name == name && f.ty == ty as u32)
}

pub fn arg_str<'a>(raw: &'a [u8], name: &str) -> Option<&'a str> {
    arg(raw, name, MsgType::String).and_then(|f| f.as_str())
}

/// An invalid explicit SID must remain a failed lookup, never local root.
pub fn arg_sid(raw: &[u8]) -> Option<&str> {
    arg(raw, "ubus_rpc_session", MsgType::String).map(|f| f.as_str().unwrap_or(""))
}

pub use crate::reply::Reply;

// Immutable wire templates, not cached authorization results. Every request
// still resolves/touches the session and evaluates its current ACL rules.
const ACCESS_FALSE: &[u8] = b"\x87\0\0\x11\0\x06access\0\0\0\0\0\0\0\0";
const ACCESS_TRUE: &[u8] = b"\x87\0\0\x11\0\x06access\0\0\0\0\x01\0\0\0";

fn ok(data: Vec<Vec<u8>>) -> Reply {
    Reply::many(0, data)
}
fn err(code: i32) -> Reply {
    Reply::empty(code)
}

pub fn call(store: &mut Store, method: &str, raw: &[u8]) -> Reply {
    match method {
        "create" => {
            let timeout = arg(raw, "timeout", MsgType::Int32)
                .and_then(|f| f.as_u32())
                .map(|v| v as i32)
                .unwrap_or(DEFAULT_TIMEOUT);
            match store.create(timeout) {
                Some(id) => Reply::one(0, store.sessions[&id].to_blob(true)),
                None => ok(vec![]),
            }
        }
        "list" => match arg_sid(raw) {
            None => ok(store.sessions.values().map(|s| s.to_blob(true)).collect()),
            Some(sid) => match store.get(sid) {
                Some(ses) => Reply::one(0, ses.to_blob(true)),
                None => err(status::NOT_FOUND),
            },
        },
        "grant" | "revoke" => {
            let Some(sid) = arg_sid(raw) else {
                return err(status::INVALID_ARGUMENT);
            };
            let scope = arg_str(raw, "scope").unwrap_or("ubus").to_owned();
            let objects = arg(raw, "objects", MsgType::Array).map(|f| f.data.to_vec());
            let grant = method == "grant";
            let Some(ses) = store.get(sid) else {
                return err(status::NOT_FOUND);
            };
            let Some(objects) = objects else {
                let rc = if grant {
                    ses.grant(&scope, None, None)
                } else {
                    ses.revoke(&scope, None, None)
                };
                return err(rc);
            };
            for pair in blob::fields(&objects) {
                if pair.ty != MsgType::Array as u32 {
                    continue;
                }
                // Select the first two STRING fields before validation. A
                // rejected non-UTF-8 function must not promote a third item
                // into a different grant/revoke operation.
                let mut strings = pair.children().filter(|s| s.ty == MsgType::String as u32);
                let object = strings.next().and_then(|s| s.as_bytes());
                let function = strings.next().and_then(|s| s.as_str());
                if let (Some(o), Some(f)) = (object, function) {
                    if grant {
                        ses.grant_bytes(&scope, Some(o), Some(f));
                    } else {
                        ses.revoke_bytes(&scope, Some(o), Some(f));
                    }
                }
            }
            ok(vec![])
        }
        "access" => {
            // Decode each field once. Keep the first matching STRING before
            // validating its value, exactly as the individual arg() lookups do.
            let mut args = [None; 4];
            let mut remaining = args.len();
            for field in blob::fields(raw) {
                if field.ty != MsgType::String as u32 {
                    continue;
                }
                let index = match field.name {
                    "ubus_rpc_session" => 0,
                    "scope" => 1,
                    "object" => 2,
                    "function" => 3,
                    _ => continue,
                };
                if args[index].is_none() {
                    args[index] = Some(field);
                    remaining -= 1;
                    if remaining == 0 {
                        break;
                    }
                }
            }
            let [sid, scope, object, function] = args;
            let Some(sid) = sid.and_then(|f| f.as_str()) else {
                return err(status::INVALID_ARGUMENT);
            };
            let scope = scope.and_then(|f| f.as_str()).unwrap_or("ubus");
            let object = object.and_then(|f| f.as_bytes());
            let function = function.and_then(|f| f.as_str());
            let Some(ses) = store.get(sid) else {
                return err(status::NOT_FOUND);
            };
            if let (Some(o), Some(f)) = (object, function) {
                let allowed = ses.allowed_bytes(scope, o, f);
                return Reply::constant(0, if allowed { ACCESS_TRUE } else { ACCESS_FALSE });
            }
            let mut b = BlobBuf::with_capacity(24);
            ses.dump_acls(&mut b);
            Reply::one(0, b.into_payload())
        }
        "set" => {
            let (Some(sid), Some(values)) = (arg_sid(raw), arg(raw, "values", MsgType::Table))
            else {
                return err(status::INVALID_ARGUMENT);
            };
            let Some(ses) = store.get(sid) else {
                return err(status::NOT_FOUND);
            };
            for f in blob::fields(values.data) {
                if f.name.is_empty() {
                    continue;
                }
                ses.set(&f);
            }
            ok(vec![])
        }
        "get" => {
            let Some(sid) = arg_sid(raw) else {
                return err(status::INVALID_ARGUMENT);
            };
            let keys = arg(raw, "keys", MsgType::Array).map(|f| f.data);
            let Some(ses) = store.get(sid) else {
                return err(status::NOT_FOUND);
            };
            let mut b = BlobBuf::new();
            let c = b.msg_open_table("values");
            match keys {
                Some(keys) => {
                    for k in blob::fields(keys) {
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
            Reply::one(0, b.into_payload())
        }
        "unset" => {
            let Some(sid) = arg_sid(raw) else {
                return err(status::INVALID_ARGUMENT);
            };
            let keys = arg(raw, "keys", MsgType::Array).map(|f| f.data);
            let Some(ses) = store.get(sid) else {
                return err(status::NOT_FOUND);
            };
            match keys {
                None => ses.data.clear(),
                Some(keys) => {
                    for k in blob::fields(keys) {
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
            let Some(sid) = arg_sid(raw) else {
                return err(status::INVALID_ARGUMENT);
            };
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
            let (Some(username), Some(password)) =
                (arg_str(raw, "username"), arg_str(raw, "password"))
            else {
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
                            if stored == username.as_bytes() {
                                Some(asid)
                            } else {
                                None
                            }
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
            Reply::one(0, ses.to_blob(true))
        }
        _ => err(status::METHOD_NOT_FOUND),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn debug_omits_session_credentials_and_raw_data() {
        let mut session = Session::new("session-bearer-secret", "directory-secret".into());
        let value = RawField {
            ty: MsgType::String as u32,
            data: b"credential-secret\0".to_vec(),
        };
        session.data.insert("sensitive-key".into(), value.clone());
        for debug in [
            format!("{session:?}"),
            format!("{session:#?}"),
            format!("{value:?}"),
            format!("{value:#?}"),
        ] {
            for secret in [
                "session-bearer-secret",
                "directory-secret",
                "sensitive-key",
                "credential-secret",
            ] {
                assert!(!debug.contains(secret));
            }
            assert!(!debug.contains(&format!("{:?}", value.data)));
        }
        assert!(format!("{session:?}").contains("data_count: 1"));
        assert!(format!("{value:?}").contains("data_len: 18"));
    }

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "rpcd-session-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn store(&self) -> Store {
            Store::at(self.0.to_str().unwrap())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn entropy_failure_never_creates_a_session_or_a_shared_directory_name() {
        let mut store = Store::with_random("/nonexistent/rpcd-session-test", || None);
        assert!(store.dirname(DEFAULT_SID).is_none());
        assert_eq!(store.create_with_random(120, || None), None);
        let mut values = [Some("a".repeat(32)), None].into_iter();
        assert_eq!(
            store.create_with_random(120, || values.next().flatten()),
            None
        );
        assert!(store.sessions.is_empty());
        let mut values = ["a".repeat(32), "b".repeat(32)].into_iter();
        let sid = store.create_with_random(120, || values.next()).unwrap();
        let dirname = store.dirname(&sid).unwrap().to_owned();
        // Failed entropy and collisions cannot replace an already live session.
        assert_eq!(store.create_with_random(120, || Some(sid.clone())), None);
        assert_eq!(store.dirname(&sid), Some(dirname.as_str()));
        assert_eq!(store.sessions.len(), 1);
    }

    #[test]
    fn directory_lookup_is_independent_and_does_not_touch_session_expiry() {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        assert_ne!(store.dirname(DEFAULT_SID), Some(DEFAULT_SID));
        assert!(validate_sid(store.dirname(DEFAULT_SID).unwrap()));
        let sid = store.create(120).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        store.sessions.get_mut(&sid).unwrap().expires = Some(deadline);
        let dirname = store.dirname(&sid).unwrap();
        assert!(validate_sid(dirname));
        assert_ne!(dirname, sid);
        assert!(!store.savedir(&sid).unwrap().contains(&sid));
        assert_eq!(store.sessions[&sid].expires, Some(deadline));
        assert_eq!(store.dirname("missing"), None);
        let fields = store.sessions[&sid].to_blob(false);
        assert_eq!(arg_sid(&fields), Some(sid.as_str()));
        assert!(arg_str(&fields, "dirname").is_none());
    }

    #[test]
    fn freeze_thaw_and_destroy_preserve_staged_changes_without_token_filenames() {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        let sid = store.create(120).unwrap();
        let dirname = store.dirname(&sid).unwrap().to_owned();
        let savedir = store.savedir(&sid).unwrap();
        fs::create_dir(&savedir).unwrap();
        let delta = std::path::Path::new(&savedir).join("network");
        fs::write(&delta, b"network.lan.proto='static'\n").unwrap();
        store.freeze();
        let frozen = fixture.0.join("sessions");
        assert!(!frozen.join(&sid).exists());
        assert_eq!(fs::read_dir(&frozen).unwrap().count(), 1);
        assert_eq!(
            fs::metadata(frozen.join(&dirname))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let mut thawed = fixture.store();
        thawed.thaw();
        assert_eq!(thawed.dirname(&sid), Some(dirname.as_str()));
        assert_eq!(thawed.savedir(&sid), Some(savedir.clone()));
        assert_eq!(fs::read(&delta).unwrap(), b"network.lan.proto='static'\n");
        assert_eq!(fs::read_dir(&frozen).unwrap().count(), 0);
        thawed.destroy(&sid);
        assert!(!std::path::Path::new(&savedir).exists());
        assert!(thawed.dirname(&sid).is_none());
    }

    #[test]
    fn legacy_thaw_renames_staged_changes_before_restoring_the_session() {
        let fixture = Fixture::new();
        let sid = "a".repeat(32);
        let old = fixture.0.join(format!("uci-{sid}"));
        fs::create_dir(&old).unwrap();
        fs::write(old.join("network"), b"network.lan.proto='static'\n").unwrap();
        let frozen = fixture.0.join("sessions");
        fs::create_dir(&frozen).unwrap();
        fs::write(frozen.join(&sid), frozen_session(&sid, 120).as_bytes()).unwrap();
        let mut store = fixture.store();
        store.thaw();
        assert_ne!(store.dirname(&sid), Some(sid.as_str()));
        let new = store.savedir(&sid).unwrap();
        assert_eq!(
            fs::read(std::path::Path::new(&new).join("network")).unwrap(),
            b"network.lan.proto='static'\n"
        );
        assert!(!old.exists());
        assert!(!frozen.join(&sid).exists());
        store.freeze();
        assert!(!frozen.join(&sid).exists());
        assert!(frozen.join(store.dirname(&sid).unwrap()).exists());
    }

    #[test]
    fn legacy_thaw_fails_closed_without_entropy_or_when_rename_would_clobber() {
        let fixture = Fixture::new();
        let sid = "a".repeat(32);
        let dirname = "b".repeat(32);
        let old = fixture.0.join(format!("uci-{sid}"));
        let occupied = fixture.0.join(format!("uci-{dirname}"));
        fs::create_dir(&old).unwrap();
        fs::write(old.join("network"), b"preserved").unwrap();
        let mut store = fixture.store();
        let mut blob = frozen_session(&sid, 120);
        assert!(!store.restore_blob(blob.as_bytes(), &sid, || None));
        fs::create_dir(&occupied).unwrap();
        assert!(!store.restore_blob(blob.as_bytes(), &sid, || Some(dirname.clone())));
        assert!(store.dirname(&sid).is_none());
        assert_eq!(fs::read(old.join("network")).unwrap(), b"preserved");
        assert!(!store.restore_blob(blob.as_bytes(), "../invalid", || Some(dirname.clone())));
    }

    #[test]
    fn flash_compat_acl_extends_only_the_existing_luci_group() {
        let fixture = Fixture::new();
        let old = fixture.0.join("luci-system.json");
        let compat = fixture.0.join("owrt-rpcd-compat.json");
        // Exact flash read group from LuCI 128a7812f4be233c5dd7f7466f534fd888785caf.
        fs::write(
            &old,
            include_str!("../tests/fixtures/luci-system-flash-25.12.5.json"),
        )
        .unwrap();
        fs::write(
            &compat,
            include_str!("../../../packaging/openwrt/owrt-rpcd/files/owrt-rpcd-compat.json"),
        )
        .unwrap();
        let login = Login {
            options: vec![(
                "read".into(),
                owrt_uci::OptionValue::List(vec!["luci-mod-system-flash".into()]),
            )],
        };
        let mut session = test_session("flash-read");
        setup_acl_file(&mut session, Some(&login), old.to_str().unwrap());
        assert!(session.allowed("file", "/proc/mounts", "read"));
        assert!(!session.allowed("file", "/proc/123/mounts", "read"));
        setup_acl_file(&mut session, Some(&login), compat.to_str().unwrap());
        assert!(session.allowed("file", "/proc/123/mounts", "read"));
        assert!(!session.allowed("file", "/proc/123/mounts", "write"));
        assert!(!session.allowed("file", "/proc/123/environ", "read"));
        let mut other = test_session("unprivileged");
        setup_acl_file(&mut other, None, old.to_str().unwrap());
        setup_acl_file(&mut other, None, compat.to_str().unwrap());
        assert!(!other.allowed("file", "/proc/123/mounts", "read"));
    }

    #[test]
    fn borrowed_data_handlers_keep_raw_types_duplicate_keys_and_empty_name_rules() {
        let mut store = empty_store();
        store.insert(test_session("borrowed-data"));
        let mut request = BlobBuf::new();
        request.msg_string("ubus_rpc_session", "borrowed-data");
        let values = request.msg_open_table("values");
        request.msg_string_bytes("raw", b"value\xff");
        request.msg_u16("number", 65535);
        request.msg_string("", "ignored");
        request.msg_close(values);
        assert_eq!(call(&mut store, "set", request.payload()).code, 0);
        assert_eq!(store.sessions["borrowed-data"].data.len(), 2);

        let mut request = BlobBuf::new();
        request.msg_string("ubus_rpc_session", "borrowed-data");
        let keys = request.msg_open_array("keys");
        request.msg_string("", "raw");
        request.msg_u32("", 5); // non-STRING keys are ignored
        request.msg_string("", "raw"); // duplicates stay in request order
        request.msg_string("", "number");
        request.msg_close(keys);
        let response = call(&mut store, "get", request.payload());
        let mut expected = BlobBuf::new();
        let values = expected.msg_open_table("values");
        expected.msg_string_bytes("raw", b"value\xff");
        expected.msg_string_bytes("raw", b"value\xff");
        expected.msg_u16("number", 65535);
        expected.msg_close(values);
        assert_eq!(response.code, 0);
        assert_eq!(&response.data[0], expected.payload());

        assert_eq!(call(&mut store, "unset", request.payload()).code, 0);
        assert!(store.sessions["borrowed-data"].data.is_empty());
    }

    #[test]
    fn constant_access_wire_matches_codec_and_grants_are_rechecked() {
        for (allowed, wire) in [(false, ACCESS_FALSE), (true, ACCESS_TRUE)] {
            let mut b = BlobBuf::new();
            b.msg_bool("access", allowed);
            assert_eq!(wire, b.into_payload());
        }
        let mut store = Store::new();
        let sid = store.create(0).unwrap();
        let mut b = BlobBuf::new();
        b.msg_string("ubus_rpc_session", &sid)
            .msg_string("scope", "ubus")
            .msg_string("object", "changing")
            .msg_string("function", "read");
        let raw = b.into_payload();
        assert_eq!(&call(&mut store, "access", &raw).data[0], ACCESS_FALSE);
        store
            .get(&sid)
            .unwrap()
            .grant("ubus", Some("changing"), Some("read"));
        assert_eq!(&call(&mut store, "access", &raw).data[0], ACCESS_TRUE);
        store
            .get(&sid)
            .unwrap()
            .revoke("ubus", Some("changing"), Some("read"));
        assert_eq!(&call(&mut store, "access", &raw).data[0], ACCESS_FALSE);
    }

    #[test]
    fn indexed_acl_lookup_keeps_shorter_prefixes_duplicates_and_raw_bytes() {
        let mut session = test_session("indexed-acl");
        for index in 0..64 {
            session.grant("ubus", Some(&format!("a{index:02}*")), Some("denied"));
        }
        for (object, function) in [
            (b"a*".as_slice(), "read"),
            (b"a[0-9]*", "write"),
            (b"a?9", "stat"),
            (b"", "empty"),
            (b"\xff*", "raw"),
            (b"nu\0ignored", "nul"),
            (b"*", "wildcard"),
        ] {
            assert_eq!(session.grant_bytes("ubus", Some(object), Some(function)), 0);
        }
        let before = session.to_blob(true);
        session.grant("ubus", Some("a*"), Some("read"));
        assert_eq!(before, session.to_blob(true));
        for (object, function) in [
            (b"a99".as_slice(), "read"), // skips a00..a63 but must keep a*
            (b"a99", "write"),           // equal keys retain every function
            (b"a99", "stat"),
            (b"", "empty"),
            (b"\xff", "raw"),
            (b"nu\0tail", "nul"),
            (b"zzzzz", "wildcard"),
        ] {
            assert!(
                session.allowed_bytes("ubus", object, function),
                "{object:?} {function}"
            );
            assert!(!session.allowed_bytes("missing", object, function));
        }
        assert!(!session.allowed("ubus", "a99", "denied"));
        session.revoke("ubus", Some("a*"), Some("read"));
        assert!(!session.allowed("ubus", "a99", "read"));
        assert!(session.allowed("ubus", "a99", "write"));
        session.revoke("ubus", None, None);
        assert!(!session.allowed("ubus", "a99", "write"));
    }

    #[test]
    fn indexed_acl_lookup_matches_linear_scan_across_generated_patterns() {
        let mut session = test_session("indexed-acl-generated");
        let mut state = 0xa076_1d64_78bd_642fu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as usize
        };
        let alphabet = b"abcde012*?[]\0\xff";
        let functions = ["read", "r*", "[rw]rite", "?", "", "all"];
        for count in 0..128 {
            let len = next() % 12;
            let object: Vec<u8> = (0..len)
                .map(|_| alphabet[next() % alphabet.len()])
                .collect();
            let function = functions[next() % functions.len()];
            session.grant_bytes("ubus", Some(&object), Some(function));
            let list = &session.acls["ubus"];
            assert!(list.windows(2).all(|a| a[0].key <= a[1].key));
            for _ in 0..128 {
                let len = next() % 14;
                let object: Vec<u8> = (0..len)
                    .map(|_| alphabet[next() % alphabet.len()])
                    .collect();
                let function = functions[next() % functions.len()];
                let linear = list.iter().any(|a| {
                    object.starts_with(&a.key)
                        && fnmatch(&a.object, &object)
                        && fnmatch(a.function.as_bytes(), function.as_bytes())
                });
                assert_eq!(
                    session.allowed_bytes("ubus", &object, function),
                    linear,
                    "{count} rules: {object:?} {function}"
                );
            }
        }
    }

    fn test_session(id: &str) -> Session {
        Session::new(id, "b".repeat(32))
    }

    fn empty_store() -> Store {
        Store {
            sessions: BTreeMap::new(),
            run_dir: "/nonexistent/rpcd-session-test".into(),
            expiry_hint: None,
            apply_sid: None,
        }
    }

    fn timer(id: &str, expires: Option<Instant>) -> Session {
        let mut session = test_session(&format!("timer-test-{}-{id}", std::process::id()));
        session.expires = expires;
        session
    }

    #[test]
    fn access_preserves_typed_duplicates_raw_objects_and_acl_dump_fallback() {
        let mut store = empty_store();
        let mut session = test_session("access-test");
        assert_eq!(
            session.grant_bytes("file", Some(b"/raw\xff"), Some("read")),
            0
        );
        store.insert(session);
        let mut b = BlobBuf::new();
        b.msg_string("function", "read");
        b.msg_string_bytes("object", b"/raw\xff");
        b.msg_u32("ubus_rpc_session", 1); // a wrong type does not claim the slot
        b.msg_string("ubus_rpc_session", "access-test");
        b.msg_string("ubus_rpc_session", "missing");
        b.msg_string("scope", "file");
        b.msg_string("scope", "ubus");
        let reply = call(&mut store, "access", b.payload());
        assert_eq!(reply.code, 0);
        assert_eq!(
            blob::fields(&reply.data[0]).next().unwrap().as_bool(),
            Some(true)
        );

        // A malformed first STRING is still the selected field. A later valid
        // duplicate must not turn an invalid SID into an authorized request.
        let mut b = BlobBuf::new();
        b.msg_field(MsgType::String as u32, "ubus_rpc_session", b"\xff\0");
        b.msg_string("ubus_rpc_session", "access-test");
        assert_eq!(
            call(&mut store, "access", b.payload()).code,
            status::INVALID_ARGUMENT
        );

        let mut b = BlobBuf::new();
        b.msg_string("ubus_rpc_session", "access-test");
        b.msg_string_bytes("object", b"/raw\xff");
        // Missing function selects the full ACL dump rather than a boolean.
        let reply = call(&mut store, "access", b.payload());
        assert_eq!(reply.code, 0);
        assert_eq!(blob::fields(&reply.data[0]).next().unwrap().name, "file");
    }

    #[test]
    fn expiration_includes_new_earlier_timers_and_keeps_permanent_sessions() {
        let now = Instant::now();
        let later = now + Duration::from_secs(120);
        let earlier = now + Duration::from_secs(60);
        let mut store = empty_store();
        assert_eq!(store.next_expiry(), None);
        let permanent = timer("permanent", None);
        let permanent_id = permanent.id.clone();
        store.insert(permanent);
        store.insert(timer("later", Some(later)));
        let early = timer("early", Some(earlier));
        let early_id = early.id.clone();
        store.insert(early);
        assert_eq!(store.next_expiry(), Some(earlier));
        store.expire_at(earlier - Duration::from_nanos(1));
        assert_eq!(store.sessions.len(), 3);
        store.expire_at(earlier);
        assert!(!store.sessions.contains_key(&early_id));
        assert_eq!(store.next_expiry(), Some(later));
        store.expire_at(later);
        assert_eq!(store.sessions.len(), 1);
        assert!(store.sessions.contains_key(&permanent_id));
        assert_eq!(store.next_expiry(), None);
    }

    #[test]
    fn touch_allows_an_early_wakeup_without_expiring_the_extended_session() {
        let now = Instant::now();
        let old_deadline = now + Duration::from_secs(10);
        let mut store = empty_store();
        let mut session = timer("touch", Some(old_deadline));
        session.timeout = 120;
        let id = session.id.clone();
        store.insert(session);
        let extended = store.get(&id).unwrap().expires.unwrap();
        assert!(extended > old_deadline);
        assert_eq!(store.next_expiry(), Some(old_deadline));
        store.expire_at(old_deadline);
        assert!(store.sessions.contains_key(&id));
        assert_eq!(store.next_expiry(), Some(extended));
    }

    #[test]
    fn removal_leaves_only_a_harmless_early_wakeup() {
        let now = Instant::now();
        let mut store = empty_store();
        let first = timer("removed", Some(now));
        let id = first.id.clone();
        store.insert(first);
        let later = now + Duration::from_secs(60);
        store.insert(timer("survivor", Some(later)));
        store.destroy(&id);
        store.expire_at(now);
        assert_eq!(store.sessions.len(), 1);
        assert_eq!(store.next_expiry(), Some(later));
    }

    #[test]
    fn thaw_and_touch_cannot_hide_an_earlier_deadline() {
        let mut store = empty_store();
        let mut blob = BlobBuf::new();
        blob.msg_string("ubus_rpc_session", "12345678901234567890123456789012");
        blob.msg_u32("timeout", 1);
        blob.msg_u64("expires", 120);
        let data = blob.msg_open_table("data");
        blob.msg_close(data);
        assert!(store.restore_blob(blob.as_bytes(), &"b".repeat(32), || None));
        let thawed = store.next_expiry().unwrap();
        let touched = store
            .get("12345678901234567890123456789012")
            .unwrap()
            .expires
            .unwrap();
        assert!(touched < thawed);
        assert_eq!(store.next_expiry(), Some(touched));
        // Replacing a record during thaw also includes its new deadline.
        let mut replacement = BlobBuf::new();
        replacement.msg_string("ubus_rpc_session", "12345678901234567890123456789012");
        replacement.msg_u32("timeout", 0);
        replacement.msg_u64("expires", 0);
        let data = replacement.msg_open_table("data");
        replacement.msg_close(data);
        assert!(store.restore_blob(replacement.as_bytes(), &"b".repeat(32), || None));
        assert!(store.next_expiry().unwrap() < touched);
    }

    fn frozen_session(sid: &str, expires: u64) -> BlobBuf {
        let mut blob = BlobBuf::new();
        blob.msg_string("ubus_rpc_session", sid);
        blob.msg_u32("timeout", 120);
        blob.msg_u64("expires", expires);
        let data = blob.msg_open_table("data");
        blob.msg_close(data);
        blob
    }

    #[test]
    fn thaw_rejects_corrupt_session_ids_without_panicking() {
        let mut store = empty_store();
        for sid in [
            format!("{}é", "a".repeat(31)),
            "a".repeat(31),
            "g".repeat(32),
            "a".repeat(33),
        ] {
            assert!(!store.restore_blob(
                frozen_session(&sid, 120).as_bytes(),
                &"b".repeat(32),
                || None
            ));
            assert!(store.sessions.is_empty());
        }
        assert!(store.restore_blob(
            frozen_session(&"a".repeat(32), 120).as_bytes(),
            &"b".repeat(32),
            || None
        ));
    }

    #[test]
    fn thaw_clamps_corrupt_expiration_without_overflow() {
        for expires in [
            120,
            i32::MAX as u64,
            i64::MAX as u64 / 1000 + 1,
            i64::MAX as u64,
            u64::MAX,
        ] {
            let mut store = empty_store();
            let before = Instant::now();
            assert!(store.restore_blob(
                frozen_session(&"a".repeat(32), expires).as_bytes(),
                &"b".repeat(32),
                || None
            ));
            let remaining = store
                .next_expiry()
                .unwrap()
                .saturating_duration_since(before);
            let expected = (expires as i64)
                .saturating_mul(1000)
                .clamp(0, i32::MAX as i64) as u64;
            assert!(remaining >= Duration::from_millis(expected));
            assert!(remaining < Duration::from_millis(expected + 1000));
        }
    }

    #[test]
    fn malformed_explicit_sid_does_not_list_every_session() {
        let mut store = Store::new();
        let mut args = BlobBuf::new();
        args.msg_string_bytes("ubus_rpc_session", b"\xff");
        let reply = call(&mut store, "list", args.payload());
        assert_eq!(reply.code, status::NOT_FOUND);
        assert!(reply.data.iter().next().is_none());
        assert_eq!(call(&mut store, "list", &[]).code, 0);
    }
}
