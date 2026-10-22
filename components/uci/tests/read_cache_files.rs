//! Cached base parses must still observe the current file and delta chain.

use owrt_uci::{delta, file, Context, Error, Package, ReadCache};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "owrt-uci-cache-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for sub in ["config", "override", "alice", "bob", "state"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        Self(dir)
    }
    fn ctx(&self, sid: &str, state: bool) -> Context<'static> {
        let mut ctx = Context::new();
        ctx.set_confdir(self.0.join("config").to_str().unwrap());
        ctx.set_conf2dir(self.0.join("override").to_str().unwrap());
        ctx.delta_path.clear();
        delta::set_savedir(&mut ctx, self.0.join(sid).to_str().unwrap());
        if state {
            delta::set_savedir(&mut ctx, self.0.join("state").to_str().unwrap());
        }
        ctx
    }
    fn compare(&self, cache: &mut ReadCache, sid: &str, state: bool) -> Result<Package, Error> {
        let mut expected = self.ctx(sid, state);
        let a = file::load(&mut expected, "sample");
        let mut actual = self.ctx(sid, state);
        let b = file::load_cached(&mut actual, "sample", cache);
        assert_eq!(b, a);
        assert_eq!(actual.root, expected.root);
        assert_eq!(actual.err, expected.err);
        assert_eq!(actual.pctx, expected.pctx);
        b.map(|i| {
            let result = actual.root.remove(i);
            cache.recycle(result.clone());
            result
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn each_load_observes_same_size_rewrite_rename_links_override_and_removal() {
    let f = Fixture::new();
    let path = f.0.join("config/sample");
    let mut cache = ReadCache::default();
    fs::write(&path, b"config example a\noption value first\n").unwrap();
    let first = f.compare(&mut cache, "alice", false).unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false).unwrap(), first);
    let stamp = fs::metadata(&path).unwrap().modified().unwrap();
    fs::write(&path, b"config example a\noption value other\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(stamp)
        .unwrap();
    let rewritten = f.compare(&mut cache, "alice", false).unwrap();
    assert_ne!(rewritten.sections, first.sections);
    fs::write(f.0.join("replacement"), b"config example replaced\n").unwrap();
    fs::rename(f.0.join("replacement"), &path).unwrap();
    assert_eq!(
        f.compare(&mut cache, "alice", false).unwrap().sections[0].name,
        "replaced"
    );
    fs::remove_file(&path).unwrap();
    symlink("../linked", &path).unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false), Err(Error::NotFound));
    fs::write(f.0.join("linked"), b"config example linked\n").unwrap();
    assert_eq!(
        f.compare(&mut cache, "alice", false).unwrap().sections[0].name,
        "linked"
    );
    fs::write(f.0.join("override/sample"), b"config example override\n").unwrap();
    assert_eq!(
        f.compare(&mut cache, "alice", false).unwrap().sections[0].name,
        "override"
    );
    fs::remove_file(f.0.join("override/sample")).unwrap();
    assert_eq!(
        f.compare(&mut cache, "alice", false).unwrap().sections[0].name,
        "linked"
    );
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false), Err(Error::NotFound));
}

#[test]
fn session_and_state_deltas_are_never_reused_or_leaked_to_another_caller() {
    let f = Fixture::new();
    fs::write(
        f.0.join("config/sample"),
        b"config example a\noption value base\n",
    )
    .unwrap();
    let mut cache = ReadCache::default();
    let base = f.compare(&mut cache, "alice", false).unwrap();
    for _ in 0..3 {
        f.compare(&mut cache, "alice", false).unwrap();
    }
    fs::write(f.0.join("alice/sample"), b"sample.a.value='alice'\n").unwrap();
    let alice = f.compare(&mut cache, "alice", false).unwrap();
    assert_ne!(alice.sections, base.sections);
    assert_eq!(
        f.compare(&mut cache, "bob", false).unwrap().sections,
        base.sections
    );
    fs::write(f.0.join("alice/sample"), b"sample.a.value='changed'\n").unwrap();
    let changed = f.compare(&mut cache, "alice", false).unwrap();
    assert_ne!(changed.sections, alice.sections);
    fs::write(f.0.join("state/sample"), b"sample.a.value='state'\n").unwrap();
    let state = f.compare(&mut cache, "alice", true).unwrap();
    assert_ne!(state.sections, changed.sections);
    assert_eq!(
        f.compare(&mut cache, "alice", false).unwrap().sections,
        changed.sections
    );
    fs::remove_file(f.0.join("alice/sample")).unwrap();
    assert_eq!(
        f.compare(&mut cache, "alice", false).unwrap().sections,
        base.sections
    );
}

#[test]
fn recycled_session_edits_cannot_change_the_next_base_model() {
    let f = Fixture::new();
    fs::write(f.0.join("config/sample"),
        b"config example a\noption value 'long base scalar value'\nlist items 'long base list value'\nlist items tail\nconfig other b\noption x yes\n").unwrap();
    let mut cache = ReadCache::default();
    let base = f.compare(&mut cache, "bob", false).unwrap();
    for _ in 0..3 {
        f.compare(&mut cache, "bob", false).unwrap();
    }
    for edit in [
        "sample.a.value='long session edit data'\n-sample.b\n",
        "-sample.a.items\nsample.a.items='scalar'\n+sample.c='added'\n",
        "-sample.a.value\n|sample.a.value='changed to list'\n@sample.a='renamed'\n",
        "sample.a.value='changed'\ninvalid delta\n",
    ] {
        fs::write(f.0.join("alice/sample"), edit).unwrap();
        f.compare(&mut cache, "alice", false).unwrap();
        assert_eq!(
            f.compare(&mut cache, "bob", false).unwrap().sections,
            base.sections
        );
    }
}

#[test]
fn hot_cache_keeps_state_order_anonymous_sections_and_session_edits_isolated() {
    let f = Fixture::new();
    fs::write(f.0.join("config/sample"),
        b"config example a\noption value base\nconfig example\noption value anonymous\nconfig example b\noption value last\n").unwrap();
    let mut cache = ReadCache::default();
    let base = f.compare(&mut cache, "bob", false).unwrap();
    assert!(base.sections[1].anonymous);
    for _ in 0..3 {
        f.compare(&mut cache, "bob", false).unwrap();
    }
    fs::write(
        f.0.join("alice/sample"),
        b"-sample.b\n+sample.added='example'\nsample.added.value='alice'\n^sample.added='0'\n",
    )
    .unwrap();
    fs::write(
        f.0.join("state/sample"),
        b"sample.a.value='state'\n+sample.state_added='example'\n^sample.a='0'\n",
    )
    .unwrap();
    for _ in 0..3 {
        let alice = f.compare(&mut cache, "alice", false).unwrap();
        assert_eq!(alice.sections[0].name, "added");
        assert!(alice.sections[0].anonymous);
        assert!(alice.find_section("b").is_none());
        let state = f.compare(&mut cache, "alice", true).unwrap();
        assert_eq!(state.sections[0].name, "a");
        assert!(state.find_section("state_added").is_some());
        let bob_state = f.compare(&mut cache, "bob", true).unwrap();
        assert!(bob_state.find_section("added").is_none());
        assert!(bob_state.find_section("b").is_some());
        assert_eq!(
            f.compare(&mut cache, "bob", false).unwrap().sections,
            base.sections
        );
    }
    fs::remove_file(f.0.join("state/sample")).unwrap();
    fs::remove_file(f.0.join("alice/sample")).unwrap();
    assert_eq!(
        f.compare(&mut cache, "alice", true).unwrap().sections,
        base.sections
    );
}

#[test]
fn near_limit_hot_reads_observe_same_size_rewrites_and_shortening() {
    let f = Fixture::new();
    let path = f.0.join("config/sample");
    let mut bytes = b"config example a\noption value '".to_vec();
    bytes.resize(32 * 1024 - 18, b'a');
    bytes.extend_from_slice(b"'\n");
    fs::write(&path, &bytes).unwrap();
    let mut cache = ReadCache::default();
    let base = f.compare(&mut cache, "alice", false).unwrap();
    for _ in 0..3 {
        f.compare(&mut cache, "alice", false).unwrap();
    }
    let stamp = fs::metadata(&path).unwrap().modified().unwrap();
    bytes[100] = b'b';
    fs::write(&path, &bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(stamp)
        .unwrap();
    let changed = f.compare(&mut cache, "alice", false).unwrap();
    assert_ne!(changed.sections, base.sections);
    for _ in 0..3 {
        f.compare(&mut cache, "alice", false).unwrap();
    }
    fs::write(&path, b"config example a\noption value short\n").unwrap();
    let short = f.compare(&mut cache, "alice", false).unwrap();
    assert_eq!(
        short.sections[0].options[0].value,
        owrt_uci::OptionValue::Str("short".into())
    );
    for _ in 0..3 {
        assert_eq!(f.compare(&mut cache, "alice", false).unwrap(), short);
    }
}
