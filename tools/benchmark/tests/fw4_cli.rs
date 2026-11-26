//! CLI checks for normalized fw4 validation and retained failure bytes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BENCH: &str = env!("CARGO_BIN_EXE_owrt-benchmark");
const C: &[u8] = b"define lan_subnets = { 2001:db8::/64, fd00::/60 }\naccept\ndrop\n";
const RUST: &[u8] = b"define lan_subnets = { fd00::/60, 2001:db8::/64 }\naccept\ndrop\n";

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("owrt-fw4-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("samples")).unwrap();
        fs::write(root.join("c.stdout"), C).unwrap();
        fs::write(root.join("rust.stdout"), RUST).unwrap();
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn measure(&self, journal: bool, program: Option<&[&str]>) -> Output {
        let actual = self.path("rust.stdout");
        let default = ["/bin/cat", actual.to_str().unwrap()];
        let mut command = Command::new(BENCH);
        command
            .args(["exec-fw4", "2", "1"])
            .arg(self.path("c.stdout"))
            .args(["-", "--"])
            .args(program.unwrap_or(&default));
        command
            .env_remove("OWRT_BENCH_EXEC_JOURNAL")
            .env_remove("OWRT_BENCH_EXEC_ARTIFACTS");
        if journal {
            command
                .env("OWRT_BENCH_EXEC_JOURNAL", self.path("samples.jsonl"))
                .env("OWRT_BENCH_EXEC_ARTIFACTS", self.path("samples"));
        }
        command.output().unwrap()
    }

    /// `(event, phase)` of every journal entry.
    fn journal(&self) -> Vec<(String, String)> {
        let field = |line: &str, name: &str| {
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            let start = compact
                .find(&format!("\"{name}\":\""))
                .map(|i| i + name.len() + 4)
                .unwrap_or(0);
            compact[start..]
                .split('"')
                .next()
                .unwrap_or_default()
                .to_owned()
        };
        fs::read_to_string(self.path("samples.jsonl"))
            .unwrap()
            .lines()
            .map(|line| (field(line, "event"), field(line, "phase")))
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn sample(root: &Path, index: usize, stream: &str) -> Vec<u8> {
    fs::read(root.join(format!("samples/iteration-{index:06}/exec.{stream}"))).unwrap()
}

#[test]
fn permutation_succeeds_and_every_sample_keeps_original_bytes() {
    let fixture = Fixture::new("permutation");
    let result = fixture.measure(true, None);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let data: String = String::from_utf8(result.stdout)
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    for field in ["\"successful\":2", "\"warmup\":1", "\"errors\":0"] {
        assert!(data.contains(field), "{field}: {data}");
    }
    for index in 0..3 {
        assert_eq!(sample(&fixture.root, index, "stdout"), RUST);
    }
    let events: Vec<String> = fixture.journal().into_iter().map(|entry| entry.0).collect();
    assert_eq!(events, ["started", "completed"].repeat(3));
}

#[test]
fn wrong_membership_fails_against_c_and_keeps_failing_warmup() {
    let fixture = Fixture::new("membership");
    let wrong = String::from_utf8(RUST.to_vec())
        .unwrap()
        .replace(", 2001:db8::/64", "");
    fs::write(fixture.path("rust.stdout"), &wrong).unwrap();
    let result = fixture.measure(true, None);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(sample(&fixture.root, 0, "stdout"), wrong.as_bytes());
    let last = fixture.journal().pop().unwrap();
    assert_eq!(last, ("failed".to_owned(), "warmup".to_owned()));
}

#[test]
fn nonzero_exit_and_missing_evidence_are_rejected() {
    let fixture = Fixture::new("nonzero");
    let result = fixture.measure(
        true,
        Some(&["/bin/sh", "-c", "echo diagnostic >&2; exit 9"]),
    );
    assert!(!result.status.success());
    assert_eq!(sample(&fixture.root, 0, "stderr"), b"diagnostic\n");
    let result = fixture.measure(false, None);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("requires a journal"));
}

#[test]
fn reference_comparison_accepts_order_but_rejects_environment_change() {
    let fixture = Fixture::new("compare");
    let compare = || {
        Command::new(BENCH)
            .arg("fw4-compare")
            .arg(fixture.path("c.stdout"))
            .arg(fixture.path("rust.stdout"))
            .status()
            .unwrap()
            .success()
    };
    assert!(compare());
    let rust = String::from_utf8(RUST.to_vec()).unwrap();
    fs::write(
        fixture.path("rust.stdout"),
        rust.replace("2001:db8::/64", "2001:db8:1::/64"),
    )
    .unwrap();
    assert!(!compare());
    fs::write(
        fixture.path("rust.stdout"),
        rust.replace("accept\ndrop", "drop\naccept"),
    )
    .unwrap();
    assert!(!compare());
}
