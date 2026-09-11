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
            "owrt-uci-cache-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for sub in ["config", "override", "alice", "bob", "state"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        Self(dir)
    }
    fn ctx(&self, sid: &str, state: bool) -> Context {
        let mut ctx = Context::new();
        ctx.set_confdir(self.0.join("config").to_str().unwrap());
        ctx.set_conf2dir(self.0.join("override").to_str().unwrap());
        ctx.delta_path.clear();
        delta::set_savedir(&mut ctx, self.0.join(sid).to_str().unwrap());
        if state { delta::set_savedir(&mut ctx, self.0.join("state").to_str().unwrap()); }
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
        b.map(|i| actual.root.remove(i))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
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
    fs::File::options().write(true).open(&path).unwrap().set_modified(stamp).unwrap();
    let rewritten = f.compare(&mut cache, "alice", false).unwrap();
    assert_ne!(rewritten.sections, first.sections);
    fs::write(f.0.join("replacement"), b"config example replaced\n").unwrap();
    fs::rename(f.0.join("replacement"), &path).unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false).unwrap().sections[0].name, "replaced");
    fs::remove_file(&path).unwrap();
    symlink("../linked", &path).unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false), Err(Error::NotFound));
    fs::write(f.0.join("linked"), b"config example linked\n").unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false).unwrap().sections[0].name, "linked");
    fs::write(f.0.join("override/sample"), b"config example override\n").unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false).unwrap().sections[0].name, "override");
    fs::remove_file(f.0.join("override/sample")).unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false).unwrap().sections[0].name, "linked");
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false), Err(Error::NotFound));
}

#[test]
fn session_and_state_deltas_are_never_reused_or_leaked_to_another_caller() {
    let f = Fixture::new();
    fs::write(f.0.join("config/sample"), b"config example a\noption value base\n").unwrap();
    let mut cache = ReadCache::default();
    let base = f.compare(&mut cache, "alice", false).unwrap();
    fs::write(f.0.join("alice/sample"), b"sample.a.value='alice'\n").unwrap();
    let alice = f.compare(&mut cache, "alice", false).unwrap();
    assert_ne!(alice.sections, base.sections);
    assert_eq!(f.compare(&mut cache, "bob", false).unwrap().sections, base.sections);
    fs::write(f.0.join("alice/sample"), b"sample.a.value='changed'\n").unwrap();
    let changed = f.compare(&mut cache, "alice", false).unwrap();
    assert_ne!(changed.sections, alice.sections);
    fs::write(f.0.join("state/sample"), b"sample.a.value='state'\n").unwrap();
    let state = f.compare(&mut cache, "alice", true).unwrap();
    assert_ne!(state.sections, changed.sections);
    assert_eq!(f.compare(&mut cache, "alice", false).unwrap().sections, changed.sections);
    fs::remove_file(f.0.join("alice/sample")).unwrap();
    assert_eq!(f.compare(&mut cache, "alice", false).unwrap().sections, base.sections);
}
