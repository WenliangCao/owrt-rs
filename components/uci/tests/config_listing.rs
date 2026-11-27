//! GLOB_MARK and live-directory semantics needed by rpcd uci.configs.

use owrt_uci::{file, Context, Error};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    dir: PathBuf,
    ctx: Context<'static>,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "owrt-uci-list-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let mut ctx = Context::new();
        ctx.set_confdir(dir.to_str().unwrap());
        Self { dir, ctx }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn distinguishes_no_glob_match_from_matches_that_are_all_excluded() {
    let f = Fixture::new();
    assert_eq!(file::list_config_files(&f.ctx), Err(Error::NotFound));
    fs::write(f.dir.join(".hidden"), "").unwrap();
    assert_eq!(file::list_config_files(&f.ctx), Err(Error::NotFound));
    fs::write(f.dir.join("has.dot"), "").unwrap();
    fs::write(f.dir.join("bad name"), "").unwrap();
    fs::write(f.dir.join(std::ffi::OsStr::from_bytes(b"bad\xffname")), "").unwrap();
    fs::create_dir(f.dir.join("directory")).unwrap();
    assert_eq!(
        file::list_config_files(&f.ctx).unwrap(),
        Vec::<String>::new()
    );
}

#[test]
fn follows_link_targets_and_observes_add_remove_and_type_changes() {
    let f = Fixture::new();
    fs::write(f.dir.join("zeta"), "").unwrap();
    fs::write(f.dir.join("alpha"), "").unwrap();
    fs::create_dir(f.dir.join("directory")).unwrap();
    symlink("zeta", f.dir.join("filelink")).unwrap();
    symlink("directory", f.dir.join("dirlink")).unwrap();
    symlink("missing", f.dir.join("broken")).unwrap();
    assert_eq!(
        file::list_config_files(&f.ctx).unwrap(),
        ["alpha", "broken", "filelink", "zeta"]
    );

    fs::remove_file(f.dir.join("zeta")).unwrap();
    fs::create_dir(f.dir.join("zeta")).unwrap();
    fs::remove_dir(f.dir.join("directory")).unwrap();
    fs::write(f.dir.join("directory"), "").unwrap();
    fs::remove_file(f.dir.join("alpha")).unwrap();
    fs::write(f.dir.join("newconfig"), "").unwrap();
    assert_eq!(
        file::list_config_files(&f.ctx).unwrap(),
        ["broken", "directory", "dirlink", "newconfig"]
    );
}

#[test]
fn names_survive_directory_buffer_refills_and_long_record_boundaries() {
    let f = Fixture::new();
    let mut expected = Vec::new();
    for i in 0..300 {
        let name = format!("{i:03}_{}", "x".repeat(if i % 2 == 0 { 251 } else { 123 }));
        fs::write(f.dir.join(&name), "").unwrap();
        expected.push(name);
    }
    assert_eq!(file::list_config_files(&f.ctx).unwrap(), expected);
    assert_eq!(
        file::list_config_files_in("bad\0directory"),
        Err(Error::NotFound)
    );
}
