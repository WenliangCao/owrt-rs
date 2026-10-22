//! A failed commit must leave the saved draft available for the next attempt.
use owrt_uci::{delta, file, Context, Error};
use std::fs;
use std::path::PathBuf;

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn failed_staging_keeps_delta_and_retry_applies_it_once() {
    let f =
        Fixture(std::env::temp_dir().join(format!("uci-commit-failure-{}", std::process::id())));
    fs::create_dir_all(f.0.join("config")).unwrap();
    fs::create_dir_all(f.0.join("delta")).unwrap();
    let original = b"config x 's'\n list values 'old'\n";
    let draft = b"|sample.s.values='new'\n";
    fs::write(f.0.join("config/sample"), original).unwrap();
    fs::write(f.0.join("delta/sample"), draft).unwrap();
    let mut ctx = Context::new();
    ctx.set_confdir(f.0.join("config").to_str().unwrap());
    ctx.set_conf2dir("");
    ctx.delta_path.clear();
    delta::set_savedir(&mut ctx, f.0.join("delta").to_str().unwrap());
    let pidx = file::load(&mut ctx, "sample").unwrap();

    // The existing configuration can still be opened and locked, but the
    // staging directory cannot create a temporary file. This works as root too.
    ctx.set_confdir(f.0.join("missing").to_str().unwrap());
    assert_eq!(file::commit(&mut ctx, pidx, false), Err(Error::Io));
    assert_eq!(fs::read(f.0.join("config/sample")).unwrap(), original);
    assert_eq!(fs::read(f.0.join("delta/sample")).unwrap(), draft);

    ctx.set_confdir(f.0.join("config").to_str().unwrap());
    file::commit(&mut ctx, pidx, false).unwrap();
    assert!(fs::read(f.0.join("delta/sample")).unwrap().is_empty());
    assert_eq!(
        fs::read_to_string(f.0.join("config/sample")).unwrap(),
        "\nconfig x 's'\n\tlist values 'old'\n\tlist values 'new'\n\n"
    );
}
