//! Exercise the public loading path: delta errors must not be swallowed and
//! interrupted packages must not enter the context's loaded-package cache.
use owrt_uci::{delta, file, sys, Context, Error, ReadCache};
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "uci-budget-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(dir.join("config")).unwrap();
        fs::create_dir(dir.join("delta")).unwrap();
        fs::write(
            dir.join("config/alpha"),
            "config test 's'\n option value 'base'\n",
        )
        .unwrap();
        fs::write(dir.join("delta/alpha"), "alpha.s.value='staged'\n").unwrap();
        Self(dir)
    }

    fn context<'a>(&self, timeout: Duration, cancelled: &'a AtomicBool) -> Context<'a> {
        let mut ctx = Context::new();
        ctx.set_confdir(self.0.join("config").to_str().unwrap());
        ctx.set_conf2dir("");
        ctx.delta_path.clear();
        delta::set_savedir(&mut ctx, self.0.join("delta").to_str().unwrap());
        ctx.set_io_budget(timeout, cancelled);
        ctx
    }

    fn hold(&self, kind: &str) -> File {
        let file = File::open(self.0.join(kind).join("alpha")).unwrap();
        sys::lock(&file, sys::LOCK_EX).unwrap();
        file
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn base_and_delta_lock_timeouts_do_not_cache_partial_packages() {
    for kind in ["config", "delta"] {
        let f = Fixture::new();
        let cancelled = AtomicBool::new(false);
        let mut ctx = f.context(Duration::from_millis(40), &cancelled);
        let holder = f.hold(kind);
        let start = Instant::now();
        assert_eq!(
            file::load(&mut ctx, "alpha"),
            Err(Error::TimedOut),
            "{kind}"
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(
            ctx.root.is_empty(),
            "{kind}: partially loaded package was cached"
        );
        drop(holder);
        ctx.set_io_budget(Duration::from_secs(2), &cancelled);
        let p = file::load(&mut ctx, "alpha").unwrap();
        assert_eq!(
            ctx.root[p].sections[0].options[0].value,
            owrt_uci::OptionValue::Str(b"staged".to_vec().into())
        );
    }
}

#[test]
fn base_and_delta_waits_notice_cancellation_while_the_lock_is_held() {
    for kind in ["config", "delta"] {
        let f = Fixture::new();
        let cancelled = AtomicBool::new(false);
        let _holder = f.hold(kind);
        let mut ctx = f.context(Duration::from_secs(10), &cancelled);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(40));
                cancelled.store(true, Ordering::Relaxed);
            });
            let start = Instant::now();
            assert_eq!(
                file::load(&mut ctx, "alpha"),
                Err(Error::Cancelled),
                "{kind}"
            );
            assert!(start.elapsed() < Duration::from_secs(2));
        });
        assert!(ctx.root.is_empty());
    }
}

#[test]
fn releasing_a_lock_before_the_deadline_loads_the_current_delta() {
    let f = Fixture::new();
    let cancelled = AtomicBool::new(false);
    let holder = f.hold("delta");
    let mut ctx = f.context(Duration::from_secs(2), &cancelled);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            drop(holder);
        });
        let p = file::load(&mut ctx, "alpha").unwrap();
        assert_eq!(
            ctx.root[p].sections[0].options[0].value,
            owrt_uci::OptionValue::Str(b"staged".to_vec().into())
        );
    });
}

#[test]
fn cached_load_rechecks_base_and_delta_locks_and_cancellation() {
    for kind in ["config", "delta"] {
        let f = Fixture::new();
        let cancelled = AtomicBool::new(false);
        let mut cache = ReadCache::default();
        for _ in 0..3 {
            let mut ctx = f.context(Duration::from_secs(2), &cancelled);
            file::load_cached(&mut ctx, "alpha", &mut cache).unwrap();
        }
        let holder = f.hold(kind);
        let mut ctx = f.context(Duration::from_millis(40), &cancelled);
        assert_eq!(
            file::load_cached(&mut ctx, "alpha", &mut cache),
            Err(Error::TimedOut)
        );
        assert!(ctx.root.is_empty());
        cancelled.store(true, Ordering::Relaxed);
        ctx.set_io_budget(Duration::from_secs(2), &cancelled);
        assert_eq!(
            file::load_cached(&mut ctx, "alpha", &mut cache),
            Err(Error::Cancelled)
        );
        assert!(ctx.root.is_empty());
        drop(holder);
        cancelled.store(false, Ordering::Relaxed);
        fs::write(f.0.join("delta/alpha"), "alpha.s.value='recovered'\n").unwrap();
        ctx.set_io_budget(Duration::from_secs(2), &cancelled);
        let p = file::load_cached(&mut ctx, "alpha", &mut cache).unwrap();
        assert_eq!(
            ctx.root[p].sections[0].options[0].value,
            owrt_uci::OptionValue::Str(b"recovered".to_vec().into())
        );
    }
}
