//! Exercises the actual `isolated.sh` shell gates with fixture proc trees.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn temp(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("owrt-isolated-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

/// The indented shell function `name` from `isolated.sh`, up to its closing brace.
fn function(name: &str) -> String {
    let script =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("isolated.sh")).unwrap();
    let start = script.find(&format!("    {name}()")).unwrap();
    let end = start + script[start..].find("\n    }").unwrap() + "\n    }".len();
    script[start..end].to_owned()
}

fn process(proc: &Path, pid: u32, parent: u32, state: &str) {
    let path = proc.join(pid.to_string());
    fs::create_dir_all(&path).unwrap();
    fs::write(
        path.join("status"),
        format!("Name:\tfixture with spaces\nState:\t{state}\nPPid:\t{parent}\n"),
    )
    .unwrap();
}

fn reaped(proc: &Path) -> bool {
    let script = function("netifd_children_reaped") + "\nsubject=42\nnetifd_children_reaped \"$1\"";
    Command::new("sh")
        .args(["-c", &script, "gate"])
        .arg(proc)
        .status()
        .unwrap()
        .success()
}

#[test]
fn live_and_zombie_children_must_be_reaped() {
    let proc = temp("zombie");
    process(&proc, 42, 1, "S");
    process(&proc, 43, 42, "S");
    assert!(!reaped(&proc));
    process(&proc, 43, 42, "Z");
    assert!(!reaped(&proc));
    fs::remove_file(proc.join("43/status")).unwrap();
    assert!(reaped(&proc));
    fs::remove_dir_all(proc).unwrap();
}

#[test]
fn exact_parent_id_and_unrelated_processes() {
    let proc = temp("parent");
    process(&proc, 42, 1, "S");
    process(&proc, 43, 420, "S");
    assert!(reaped(&proc));
    fs::remove_dir_all(proc).unwrap();
}

#[test]
fn unreadable_proc_tree_is_not_an_empty_child_list() {
    let proc = temp("empty");
    assert!(!reaped(&proc));
    fs::remove_dir_all(proc).unwrap();
}

#[test]
fn full_fixture_order_crosses_one_hundred_interfaces() {
    let script = function("netifd_expect") + "\nnetifd_digits=$1\nnetifd_expect \"$2\"";
    for count in [2usize, 32, 64, 128] {
        let digits = if count == 128 { 3 } else { 2 };
        let output = Command::new("sh")
            .args([
                "-c",
                &script,
                "fixture",
                &digits.to_string(),
                &count.to_string(),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let rows: Vec<&str> = text.split("{\"interface\":\"").skip(1).collect();
        let names: Vec<&str> = rows
            .iter()
            .map(|row| &row[..row.find('"').unwrap()])
            .collect();
        assert_eq!(names.len(), count);
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names, sorted);
        assert_eq!(&names[count - 2..], ["lan", "loopback"]);
        for (index, row) in rows[..count - 2].iter().enumerate() {
            assert!(
                row.contains(&format!(
                    "\"ipv4-address\":[{{\"address\":\"198.18.{index}.1\""
                )),
                "{row}"
            );
        }
    }
}
