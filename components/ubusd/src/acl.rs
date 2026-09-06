//! ubusd's first authorization layer: `/usr/share/acl.d/*.json`.
//!
//! Two rules from the C implementation that are easy to get wrong and are
//! reproduced verbatim here: root (uid 0) bypasses every check, and a `user`
//! or `group` name that does not resolve maps to id 0 rather than "no match".

use crate::obj::strmatch_len;
use owrt_ubus::json::{self, Json};
use std::io;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AclType {
    Publish,
    Subscribe,
    Access,
    Listen,
    Send,
}

pub struct AclEntry {
    /// Object pattern with any trailing `*` stripped.
    key: Vec<u8>,
    partial: bool,
    user: Option<String>,
    group: Option<String>,
    uid: i64,
    gid: i64,
    methods: Vec<String>,
    /// The `acl` table of an access entry, kept as JSON for `acl query`.
    priv_acl: Option<Json>,
    subscribe: bool,
    publish: bool,
    listen: bool,
    send: bool,
}

#[derive(Default)]
pub struct Acl {
    /// Sorted by key so the monotonic match-length scan is valid; equal keys
    /// keep insertion order, matching an avl tree with duplicates allowed.
    entries: Vec<AclEntry>,
    pub seq: u32,
}

/// What a client's credentials look like to the ACL layer.
pub struct Cred<'a> {
    pub uid: u32,
    pub gid: u32,
    pub extra_gid: &'a [u32],
}

impl Acl {
    /// `ubusd_acl_check`: 0 means allowed. `None` for `cred` is the internal
    /// caller, which is always allowed.
    pub fn check(&self, cred: Option<&Cred>, obj: &[u8], method: Option<&[u8]>, ty: AclType) -> bool {
        let Some(cred) = cred else { return true };
        if cred.uid == 0 {
            return true;
        }
        let mut match_len = 0usize;
        for e in &self.entries {
            let (full, cur) = strmatch_len(obj, &e.key);
            if cur < match_len {
                break;
            }
            match_len = cur;
            if !full && (!e.partial || match_len != e.key.len()) {
                continue;
            }
            if !e.matches_cred(cred) {
                continue;
            }
            let ok = match ty {
                AclType::Publish => e.publish,
                AclType::Subscribe => e.subscribe,
                AclType::Listen => e.listen,
                AclType::Send => e.send,
                AclType::Access => method.is_some_and(|m| {
                    e.methods.iter().any(|c| c == "*" || c.as_bytes() == m)
                }),
            };
            if ok {
                return true;
            }
        }
        false
    }

    /// Entries carrying a private `acl` table that match `path` -- the payload
    /// of the `acl` object's `query` method.
    pub fn private_for(&self, path: &[u8]) -> Vec<(&AclEntry, &Json)> {
        let mut out = Vec::new();
        let mut match_len = 0usize;
        for e in &self.entries {
            let Some(p) = &e.priv_acl else { continue };
            let (full, cur) = strmatch_len(path, &e.key);
            if cur < match_len {
                break;
            }
            match_len = cur;
            if !full && (!e.partial || match_len != e.key.len()) {
                continue;
            }
            out.push((e, p));
        }
        out
    }

    /// Reload every `*.json` under `dir`. Files that are not regular, not owned
    /// by root, or group/other-writable or other-executable are skipped with a
    /// message, as in the C loader; a parse failure skips just that file.
    pub fn load(&mut self, dir: &str) -> u32 {
        let mut files: Vec<String> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path().to_string_lossy().into_owned())
                .filter(|p| p.ends_with(".json"))
                .collect(),
            Err(_) => Vec::new(),
        };
        files.sort();

        let mut entries = Vec::new();
        for path in &files {
            match load_file(path) {
                Ok(mut es) => entries.append(&mut es),
                Err(e) => eprintln!("ubusd: {path}: {e}"),
            }
        }
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        self.entries = entries;
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }
}

impl AclEntry {
    fn matches_cred(&self, cred: &Cred) -> bool {
        if self.uid != -1 && cred.uid as i64 == self.uid {
            return true;
        }
        if self.gid != -1 {
            if cred.gid as i64 == self.gid {
                return true;
            }
            if cred.extra_gid.iter().any(|g| *g as i64 == self.gid) {
                return true;
            }
        }
        false
    }

    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }
}

fn load_file(path: &str) -> io::Result<Vec<AclEntry>> {
    let st = crate::sys::stat_of(path)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "stat failed"))?;
    if st.mode & crate::sys::S_IFMT != crate::sys::S_IFREG {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    if st.uid != 0 || st.gid != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "wrong owner"));
    }
    if st.mode & (crate::sys::S_IWOTH | crate::sys::S_IWGRP | crate::sys::S_IXOTH) != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "wrong permissions"));
    }

    let text = std::fs::read_to_string(path)?;
    let doc = json::parse(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // `user` wins over `group`; a file with neither is ignored entirely.
    let (user, group, uid, gid) = match (doc.get("user").and_then(Json::as_str), doc.get("group").and_then(Json::as_str)) {
        (Some(u), _) => {
            let uid = crate::sys::user_id(u).unwrap_or(0) as i64;
            (Some(u.to_owned()), None, uid, -1)
        }
        (None, Some(g)) => {
            let gid = crate::sys::group_id(g).unwrap_or(0) as i64;
            (None, Some(g.to_owned()), -1, gid)
        }
        _ => return Ok(Vec::new()),
    };

    let mut out = Vec::new();
    let mut push = |obj: &str, f: &dyn Fn(&mut AclEntry)| {
        if obj.is_empty() {
            return;
        }
        let partial = obj.ends_with('*');
        let key = if partial { &obj[..obj.len() - 1] } else { obj };
        let mut e = AclEntry {
            key: key.as_bytes().to_vec(),
            partial,
            user: user.clone(),
            group: group.clone(),
            uid,
            gid,
            methods: Vec::new(),
            priv_acl: None,
            subscribe: false,
            publish: false,
            listen: false,
            send: false,
        };
        f(&mut e);
        out.push(e);
    };

    if let Some(Json::Object(access)) = doc.get("access") {
        for (name, spec) in access {
            let methods = spec.get("methods");
            let tags = spec.get("tags");
            let priv_acl = spec.get("acl");
            if methods.is_none() && tags.is_none() && priv_acl.is_none() {
                continue;
            }
            let list: Vec<String> = methods
                .and_then(Json::as_array)
                .map(|a| a.iter().filter_map(Json::as_str).map(str::to_owned).collect())
                .unwrap_or_default();
            let p = priv_acl.cloned();
            push(name, &|e: &mut AclEntry| {
                e.methods = list.clone();
                e.priv_acl = p.clone();
            });
        }
    }
    for (field, set) in [
        ("subscribe", 0usize),
        ("publish", 1),
        ("listen", 2),
        ("send", 3),
    ] {
        if let Some(arr) = doc.get(field).and_then(Json::as_array) {
            for item in arr.iter().filter_map(Json::as_str) {
                push(item, &|e: &mut AclEntry| match set {
                    0 => e.subscribe = true,
                    1 => e.publish = true,
                    2 => e.listen = true,
                    _ => e.send = true,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, partial: bool, uid: i64) -> AclEntry {
        AclEntry {
            key: key.as_bytes().to_vec(),
            partial,
            user: None,
            group: None,
            uid,
            gid: -1,
            methods: vec!["call".to_owned()],
            priv_acl: None,
            subscribe: false,
            publish: true,
            listen: false,
            send: false,
        }
    }

    fn acl(entries: Vec<AclEntry>) -> Acl {
        let mut a = Acl::default();
        let mut e = entries;
        e.sort_by(|x, y| x.key.cmp(&y.key));
        a.entries = e;
        a
    }

    #[test]
    fn root_bypasses_every_check() {
        let a = acl(vec![]);
        let cred = Cred { uid: 0, gid: 0, extra_gid: &[] };
        assert!(a.check(Some(&cred), b"anything", Some(b"call"), AclType::Publish));
    }

    #[test]
    fn internal_caller_is_always_allowed() {
        let a = acl(vec![]);
        assert!(a.check(None, b"ubus.object.add", None, AclType::Send));
    }

    #[test]
    fn non_root_needs_a_matching_entry() {
        let a = acl(vec![entry("dnsmasq", false, 100)]);
        let ok = Cred { uid: 100, gid: 100, extra_gid: &[] };
        let other = Cred { uid: 101, gid: 101, extra_gid: &[] };
        assert!(a.check(Some(&ok), b"dnsmasq", None, AclType::Publish));
        assert!(!a.check(Some(&other), b"dnsmasq", None, AclType::Publish));
        assert!(!a.check(Some(&ok), b"dnsmasq.dns", None, AclType::Publish));
    }

    #[test]
    fn partial_entry_matches_prefix_only() {
        let a = acl(vec![entry("hostapd.", true, 100)]);
        let c = Cred { uid: 100, gid: 100, extra_gid: &[] };
        assert!(a.check(Some(&c), b"hostapd.wlan0", None, AclType::Publish));
        assert!(!a.check(Some(&c), b"hostapd", None, AclType::Publish));
    }

    #[test]
    fn access_needs_the_method_or_a_wildcard() {
        let a = acl(vec![entry("hotplug.dhcp", false, 100)]);
        let c = Cred { uid: 100, gid: 100, extra_gid: &[] };
        assert!(a.check(Some(&c), b"hotplug.dhcp", Some(b"call"), AclType::Access));
        assert!(!a.check(Some(&c), b"hotplug.dhcp", Some(b"other"), AclType::Access));
    }

    #[test]
    fn supplementary_group_matches() {
        let mut e = entry("log", false, -1);
        e.gid = 42;
        let a = acl(vec![e]);
        let c = Cred { uid: 100, gid: 7, extra_gid: &[42] };
        assert!(a.check(Some(&c), b"log", None, AclType::Publish));
    }
}
