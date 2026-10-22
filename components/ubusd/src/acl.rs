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
    /// caller, which is always allowed. `None` for `obj` is an object without
    /// a path -- the event/acl/monitor system objects and anonymous subscriber
    /// objects -- and is allowed for every caller: ubusd_acl.c:108
    /// `if (!cl || !cl->uid || !obj) return 0;`. The system objects then apply
    /// their own checks (SEND/LISTEN on the event id, root-only for monitor).
    pub fn check(
        &self,
        cred: Option<&Cred>,
        obj: Option<&[u8]>,
        method: Option<&[u8]>,
        ty: AclType,
    ) -> bool {
        let Some(cred) = cred else { return true };
        if cred.uid == 0 {
            return true;
        }
        let Some(obj) = obj else { return true };
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
                    e.methods.iter().any(|c| {
                        // JSON strings can contain NUL too; C strcmp stops
                        // there for both named grants and the wildcard.
                        let c = crate::obj::cstr_bytes(c.as_bytes());
                        c == b"*" || c == m
                    })
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
    ///
    /// Returns false, leaving the table and `seq` untouched, when there is
    /// nothing to load: `ubusd_acl_load` returns before `vlist_update` when
    /// `glob("<dir>/*.json")` fails (missing or empty directory), so a HUP
    /// during a transient empty acl.d does not strip every daemon of its
    /// permissions and sends no `ubus.acl.sequence` event.
    pub fn load(&mut self, dir: &str) -> bool {
        let files = acl_files(dir);
        if files.is_empty() {
            return false;
        }

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
        true
    }
}

/// What `glob("<dir>/*.json")` returns: the sorted `*.json` entries, minus
/// dotfiles, which `*` never matches without GLOB_PERIOD.
fn acl_files(dir: &str) -> Vec<String> {
    let mut files: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.ends_with(".json") && !name.starts_with('.')
            })
            .map(|e| e.path().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    files
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if st.uid != 0 || st.gid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong owner",
        ));
    }
    if st.mode & (crate::sys::S_IWOTH | crate::sys::S_IWGRP | crate::sys::S_IXOTH) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong permissions",
        ));
    }

    let text = std::fs::read_to_string(path)?;
    let doc = json::parse(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // `user` wins over `group`; a file with neither is ignored entirely.
    let (user, group, uid, gid) = match (
        doc.get("user").and_then(Json::as_str),
        doc.get("group").and_then(Json::as_str),
    ) {
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
            let methods = spec.get("methods").filter(|v| matches!(v, Json::Array(_)));
            let tags = spec.get("tags").filter(|v| matches!(v, Json::Array(_)));
            let priv_acl = spec.get("acl").filter(|v| matches!(v, Json::Object(_)));
            if methods.is_none() && tags.is_none() && priv_acl.is_none() {
                continue;
            }
            let list: Vec<String> = methods
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Json::as_str)
                        .map(str::to_owned)
                        .collect()
                })
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

    impl Acl {
        pub(crate) fn send_group_fixture(key: &str, gid: u32) -> Self {
            let mut e = entry(key, false, -1);
            e.gid = i64::from(gid);
            e.methods.clear();
            e.publish = false;
            e.send = true;
            acl(vec![e])
        }
    }

    #[test]
    fn method_grants_use_c_string_names() {
        let cred = Cred {
            uid: 1234,
            gid: 1234,
            extra_gid: &[],
        };
        for (grant, method, allowed) in [
            ("ping\0suffix", &b"ping"[..], true),
            ("*\0suffix", b"other", true),
            ("safe\0ping", b"ping", false),
            ("\0suffix", b"", true),
        ] {
            let mut e = entry("example", false, 1234);
            e.methods = vec![grant.to_owned()];
            let a = acl(vec![e]);
            assert_eq!(
                a.check(Some(&cred), Some(b"example"), Some(method), AclType::Access),
                allowed
            );
        }
    }

    #[test]
    fn root_bypasses_every_check() {
        let a = acl(vec![]);
        let cred = Cred {
            uid: 0,
            gid: 0,
            extra_gid: &[],
        };
        assert!(a.check(
            Some(&cred),
            Some(b"anything"),
            Some(b"call"),
            AclType::Publish
        ));
    }

    #[test]
    fn internal_caller_is_always_allowed() {
        let a = acl(vec![]);
        assert!(a.check(None, Some(b"ubus.object.add"), None, AclType::Send));
    }

    // ubusd_acl.c:108 `!obj -> return 0`: an object without a path (the
    // event/acl/monitor system objects, anonymous subscriber objects) passes
    // the ACCESS check for any uid, whatever the table holds. hostapd runs as
    // `network` and reaches the event object's own SEND check only this way.
    #[test]
    fn pathless_object_bypasses_the_table_like_c() {
        let mut e = entry("bss.", true, 101);
        e.send = true;
        let a = acl(vec![e]);
        let network = Cred {
            uid: 101,
            gid: 101,
            extra_gid: &[],
        };
        for method in [&b"send"[..], b"register", b"query", b"add"] {
            assert!(a.check(Some(&network), None, Some(method), AclType::Access));
        }
        let empty = acl(vec![]);
        assert!(empty.check(Some(&network), None, Some(b"send"), AclType::Access));
        // an empty path is a real path, not the absence of one
        assert!(!empty.check(Some(&network), Some(b""), Some(b"send"), AclType::Access));
        // the SEND check that follows in ubusd_send_event still applies to the id
        assert!(!empty.check(Some(&network), Some(b"bss.add"), None, AclType::Send));
        assert!(a.check(Some(&network), Some(b"bss.add"), None, AclType::Send));
    }

    // ubusd_acl_load() returns when glob() finds no *.json (missing or empty
    // dir): the previous table stays, seq is not bumped.
    #[test]
    fn load_with_no_files_keeps_the_previous_table() {
        let mut a = acl(vec![entry("dnsmasq", false, 453)]);
        let seq_before = a.seq;
        let dir = std::env::temp_dir().join(format!("owrt-empty-acl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("notes.txt"), "not an acl file").unwrap();
        assert!(!a.load(dir.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
        let dnsmasq = Cred {
            uid: 453,
            gid: 453,
            extra_gid: &[],
        };
        assert!(a.check(Some(&dnsmasq), Some(b"dnsmasq"), None, AclType::Publish));
        assert_eq!(a.seq, seq_before);
        assert!(!a.load("/nonexistent/owrt/acl.d"));
        assert!(a.check(Some(&dnsmasq), Some(b"dnsmasq"), None, AclType::Publish));
        assert_eq!(a.seq, seq_before);
    }

    // glob("*.json") never matches dotfiles; the loader must not either.
    #[test]
    fn dotfiles_are_not_acl_files() {
        let dir = std::env::temp_dir().join(format!("owrt-dot-acl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".hidden.json"), "{}").unwrap();
        std::fs::write(dir.join("b.json"), "{}").unwrap();
        std::fs::write(dir.join("a.json"), "{}").unwrap();
        std::fs::write(dir.join("c.json.bak"), "{}").unwrap();
        let files = acl_files(dir.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        let names: Vec<&str> = files
            .iter()
            .map(|p| p.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(names, ["a.json", "b.json"]);
    }

    #[test]
    fn non_root_needs_a_matching_entry() {
        let a = acl(vec![entry("dnsmasq", false, 100)]);
        let ok = Cred {
            uid: 100,
            gid: 100,
            extra_gid: &[],
        };
        let other = Cred {
            uid: 101,
            gid: 101,
            extra_gid: &[],
        };
        assert!(a.check(Some(&ok), Some(b"dnsmasq"), None, AclType::Publish));
        assert!(!a.check(Some(&other), Some(b"dnsmasq"), None, AclType::Publish));
        assert!(!a.check(Some(&ok), Some(b"dnsmasq.dns"), None, AclType::Publish));
    }

    #[test]
    fn partial_entry_matches_prefix_only() {
        let a = acl(vec![entry("hostapd.", true, 100)]);
        let c = Cred {
            uid: 100,
            gid: 100,
            extra_gid: &[],
        };
        assert!(a.check(Some(&c), Some(b"hostapd.wlan0"), None, AclType::Publish));
        assert!(!a.check(Some(&c), Some(b"hostapd"), None, AclType::Publish));
    }

    #[test]
    fn access_needs_the_method_or_a_wildcard() {
        let a = acl(vec![entry("hotplug.dhcp", false, 100)]);
        let c = Cred {
            uid: 100,
            gid: 100,
            extra_gid: &[],
        };
        assert!(a.check(
            Some(&c),
            Some(b"hotplug.dhcp"),
            Some(b"call"),
            AclType::Access
        ));
        assert!(!a.check(
            Some(&c),
            Some(b"hotplug.dhcp"),
            Some(b"other"),
            AclType::Access
        ));
    }

    #[test]
    fn supplementary_group_matches() {
        let mut e = entry("log", false, -1);
        e.gid = 42;
        let a = acl(vec![e]);
        let c = Cred {
            uid: 100,
            gid: 7,
            extra_gid: &[42],
        };
        assert!(a.check(Some(&c), Some(b"log"), None, AclType::Publish));
    }
}
