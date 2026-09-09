//! R81 audit (ubusd): unit tests demonstrating findings F1, F3, F4, F5.
//!
//! These tests need the crate's private items, so they are written as an
//! in-crate test module. To run them, add ONE line at the bottom of
//! `components/ubusd/src/acl.rs`:
//!
//!     #[cfg(test)] #[path = "../../../tools/audit/r81_ubusd_acl_pathless.rs"] mod r81_audit;
//!
//! then `cargo test -p owrt-ubusd r81_`. Every test below is expected to FAIL
//! on the current tree and PASS once the corresponding finding is fixed.
//! (Not run by the auditor: no cargo on the audit host.)

use super::*;

fn entry(key: &str, partial: bool, uid: i64) -> AclEntry {
    AclEntry {
        key: key.as_bytes().to_vec(),
        partial,
        user: None,
        group: None,
        uid,
        gid: -1,
        methods: vec!["*".to_owned()],
        priv_acl: None,
        subscribe: false,
        publish: true,
        listen: false,
        send: true,
    }
}

fn acl_with(entries: Vec<AclEntry>) -> Acl {
    let mut a = Acl::default();
    let mut e = entries;
    e.sort_by(|x, y| x.key.cmp(&y.key));
    a.entries = e;
    a
}

/// F1: ubusd_acl_check() returns 0 (allow) when `obj == NULL`, i.e. for every
/// object that has no path: the three system objects (event/acl/monitor) and
/// anonymous subscriber objects. ubusd-rs passes b"" for such objects and
/// Acl::check then denies every non-root caller, so hostapd (uid `network`,
/// wpad_acl.json "send": ["bss.*", ...]) can never reach the event object's
/// own SEND check: ubus_send_event("bss.add") -> PERMISSION_DENIED.
#[test]
fn r81_f1_pathless_object_bypasses_acl_like_c() {
    // the device's wpad_acl.json shape: user network, send bss.*
    let a = acl_with(vec![entry("bss.", true, 101)]);
    let network = Cred { uid: 101, gid: 101, extra_gid: &[] };
    // C: !obj -> return 0 (allowed) regardless of ACL contents
    assert!(
        a.check(Some(&network), b"", Some(b"send"), AclType::Access),
        "C allows ACCESS on a pathless (system/anonymous) object for any uid"
    );
    assert!(a.check(Some(&network), b"", Some(b"register"), AclType::Access));
    assert!(a.check(Some(&network), b"", Some(b"query"), AclType::Access));
    // and with an empty ACL table too
    let empty = acl_with(vec![]);
    assert!(empty.check(Some(&network), b"", Some(b"send"), AclType::Access));
    // the SEND check that follows in ubusd_send_event still applies to the id
    assert!(empty.check(Some(&network), b"bss.add", None, AclType::Send) == false);
    assert!(a.check(Some(&network), b"bss.add", None, AclType::Send));
}

/// F5: ubusd_acl_load() returns early when glob() finds no *.json (missing
/// dir, empty dir, GLOB_ABORTED): the previous table stays, seq is NOT bumped
/// and no ubus.acl.sequence event is sent. Acl::load() wipes the table.
#[test]
fn r81_f5_load_with_no_files_keeps_previous_table() {
    let mut a = acl_with(vec![entry("dnsmasq", false, 453)]);
    let seq_before = a.seq;
    let dir = std::env::temp_dir().join(format!("r81-empty-acl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    a.load(dir.to_str().unwrap());
    let _ = std::fs::remove_dir(&dir);
    let dnsmasq = Cred { uid: 453, gid: 453, extra_gid: &[] };
    assert!(
        a.check(Some(&dnsmasq), b"dnsmasq", None, AclType::Publish),
        "an empty acl dir must not flush the loaded ACLs (C returns before vlist_update)"
    );
    assert_eq!(a.seq, seq_before, "C does not bump ubusd_acl_seq when glob() fails");
    // a missing directory is the same case (glob -> GLOB_NOMATCH/ABORTED)
    a.load("/nonexistent/r81/acl.d");
    assert!(a.check(Some(&dnsmasq), b"dnsmasq", None, AclType::Publish));
}

/// F6: glob("*.json") never matches dotfiles; read_dir + ends_with(".json")
/// does. A root-owned `.foo.json` is loaded by ubusd-rs and ignored by C.
#[test]
fn r81_f6_dotfiles_are_not_acl_files() {
    let dir = std::env::temp_dir().join(format!("r81-dot-acl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join(".hidden.json");
    std::fs::write(&f, r#"{"user":"root","publish":["r81.hidden"]}"#).unwrap();
    let mut a = Acl::default();
    a.load(dir.to_str().unwrap());
    let _ = std::fs::remove_file(&f);
    let _ = std::fs::remove_dir(&dir);
    // (only meaningful when the test runs as root, since non-root-owned files
    // are skipped by both implementations; otherwise the assertion is vacuous)
    assert!(a.entries.iter().all(|e| e.key != b"r81.hidden"));
}
