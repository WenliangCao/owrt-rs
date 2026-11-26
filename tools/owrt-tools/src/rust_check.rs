//! Linux Rust gates (`make test/check-rust/fmt-check/build`).
//!
//! Crates compile as the calling user; only already-built test executables
//! of privileged suites cross the sudo boundary, through `run-test`.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use crate::util::{self, bail, ensure, strings, Args, Env, Result};

const COMPONENTS: [&str; 14] = [
    "platform", "ubus", "uci", "reload-config", "logd", "httpd", "fw4",
    "rpcd", "ubusd", "netifd", "procd", "dnsmasq/platform", "dnsmasq", "odhcpd",
];
/// Business roots, even when a platform binary adapter invokes them. Forbid
/// is deliberately stronger than deny: no descendant may opt out.
const BUSINESS_ROOTS: [&str; 13] = [
    "dnsmasq/src/lib.rs", "dnsmasq/src/main.rs", "fw4/src/lib.rs",
    "procd/src/main.rs", "reload-config/src/main.rs", "rpcd/src/main.rs",
    "ubusd/src/main.rs", "ubus/src/lib.rs", "uci/src/lib.rs",
    "httpd/src/main.rs", "logd/src/main.rs", "netifd/src/lib.rs",
    "netifd/src/main.rs",
];
/// Ignored tests that need only the namespace our runner supplies; the rest
/// need an independently built exact-C oracle or corpus.
const DNS_NAMESPACE_PREFIXES: [&str; 8] = [
    "net::", "interfaces::", "interfaces_ipv4::", "listeners::",
    "tftp_listener::", "dhcp::service::", "tftp_admission_tests::",
    "tests::dns_listener_factories_preserve_bound_ipv4_policy_on_rebind",
];

fn linux_only() -> Result<()> {
    ensure!(util::is_linux(), "Rust gates require Linux; use ssh oracle or CI, not a Mac build");
    Ok(())
}

/// Rejects weakening a business root before a compiler can hide the change.
fn verify_business_boundaries(root: &Path, roots: &[&str]) -> Result<()> {
    static FORBID: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^\s*#!\[forbid\(unsafe_code\)\]\s*$").unwrap());
    for relative in roots {
        let source = util::read_text(&root.join("components").join(relative))?;
        ensure!(FORBID.is_match(&source), "business root must retain #![forbid(unsafe_code)]: {relative}");
    }
    Ok(())
}

/// Cargo runner: only the already-built ELF crosses the sudo boundary.
fn run_test(arguments: &[String]) -> Result<i32> {
    linux_only()?;
    ensure!(arguments.first().is_some_and(|exe| Path::new(exe).is_file()),
            "Cargo runner requires a built test executable");
    let temporary = util::TempDir::try_new("owrt-rust-test")?.keep();
    let mut command = strings(["sudo", "-n", "env"]);
    command.push(format!("TMPDIR={}", temporary.display()));
    command.push("sh".into());
    command.push(util::display(&util::repo().join("tools/dnsmasq/run_isolated.sh")));
    command.extend(arguments.iter().cloned());
    let status = util::command(&command, Some(&util::repo()), None).status();
    // Tests can create root-owned mode-0700 fixtures. The parent owns this
    // freshly generated directory; never clean caller-supplied paths here.
    util::run_checked(&strings(["sudo", "-n", "rm", "-rf", "--", &util::display(&temporary)]), None, None)?;
    Ok(util::exit_code(status?))
}

/// `(has [features], runs doctests)` for a crate manifest.
fn configuration(manifest: &Path) -> Result<(bool, bool)> {
    static FEATURES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^\[features\]$").unwrap());
    static PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^path\s*=\s*"([^"\n]+)"\s*$"#).unwrap());
    static NO_DOCTEST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^doctest\s*=\s*false\s*$").unwrap());
    let text = util::read_text(manifest)?;
    let library = lib_section(&text);
    let path = library.and_then(|section| PATH.captures(section)).map_or("src/lib.rs", |c| c.get(1).unwrap().as_str());
    let docs = manifest.parent().unwrap().join(path).is_file() && !library.is_some_and(|s| NO_DOCTEST.is_match(s));
    Ok((FEATURES.is_match(&text), docs))
}

/// The body of `[lib]` up to the next section header.
pub fn lib_section(text: &str) -> Option<&str> {
    let start = text.match_indices("[lib]\n").find(|(index, _)| *index == 0 || text.as_bytes()[index - 1] == b'\n')?.0;
    let body = &text[start + "[lib]\n".len()..];
    let end = body.match_indices('\n').find(|(index, _)| body[index + 1..].starts_with('[')).map_or(body.len(), |(i, _)| i + 1);
    Some(if body.starts_with('[') { "" } else { &body[..end] })
}

fn runner_config(host: &str) -> Vec<String> {
    // A TOML array preserves spaces in the checkout path; no shell evaluation.
    let runner = serde_json::json!([util::display(&std::env::current_exe().unwrap_or_default()), "rust-check", "run-test"]);
    vec!["--config".into(), format!("target.{host}.runner={}", util::line_json(&runner))]
}

fn commands(mode: &str, manifest: &Path, host: &str) -> Result<Vec<(String, Vec<String>)>> {
    let (features, docs) = configuration(manifest)?;
    let manifest_text = util::display(manifest);
    let base = strings(["--locked", "--manifest-path", &manifest_text, "--target", host]);
    let mut feature_sets: Vec<(Vec<String>, &str)> = vec![(vec![], "default")];
    if features {
        feature_sets.push((strings(["--all-features"]), "all-features"));
    }
    let isolated = matches!(manifest.parent().and_then(Path::file_name).and_then(|n| n.to_str()), Some("dnsmasq" | "procd"));
    let runner = if isolated { runner_config(host) } else { vec![] };
    let cargo = |verb: &str, rest: &[Vec<String>]| -> Vec<String> {
        let mut command = strings(["mbx", verb]);
        for part in rest {
            command.extend(part.iter().cloned());
        }
        command
    };
    let mut rows = Vec::new();
    match mode {
        "fmt-check" => rows.push(("fmt".into(), strings(["mbx", "fmt", "--manifest-path", &manifest_text, "--check"]))),
        "build" => rows.push(("build".into(), cargo("build", &[base.clone(), strings(["--release"])]))),
        "check" => {
            for (flags, label) in &feature_sets {
                rows.push((format!("check-{label}"), cargo("check", &[base.clone(), flags.clone(), strings(["--all-targets"])])));
                rows.push((format!("clippy-{label}"),
                           cargo("clippy", &[base.clone(), flags.clone(), strings(["--all-targets", "--", "-D", "warnings"])])));
                if has_examples(manifest)? {
                    rows.push((format!("examples-{label}"), cargo("check", &[base.clone(), flags.clone(), strings(["--examples"])])));
                }
            }
        }
        "test" => {
            for (flags, label) in &feature_sets {
                rows.push((format!("test-{label}"), cargo("test", &[
                    base.clone(), flags.clone(), runner.clone(), strings(["--all-targets", "--", "--test-threads=1"]),
                ])));
            }
            if docs {
                let flags = if features { strings(["--all-features"]) } else { vec![] };
                rows.push(("doc".into(), cargo("test", &[base.clone(), flags, strings(["--doc"])])));
            }
        }
        other => bail!("unknown Rust gate mode: {other}"),
    }
    Ok(rows)
}

fn has_examples(manifest: &Path) -> Result<bool> {
    let directory = manifest.parent().unwrap().join("examples");
    Ok(directory.is_dir()
        && std::fs::read_dir(directory)?.any(|entry| entry.is_ok_and(|e| e.path().extension().is_some_and(|x| x == "rs"))))
}

/// Runs one gate step with all output in `log`.
pub type Executor<'a> = dyn FnMut(&[String], &Path, &Env) -> Result<()> + 'a;

fn execute(command: &[String], log: &Path, env: &Env) -> Result<()> {
    println!("+ {}", command.join(" "));
    std::fs::create_dir_all(log.parent().unwrap())?;
    let code = util::run_to_log(command, log, Some(&util::repo()), Some(env))?;
    if code != 0 {
        let text = util::read_lossy(log)?;
        let lines = util::splitlines(&text);
        eprintln!("{}", lines[lines.len().saturating_sub(60)..].join("\n"));
        bail!("command {:?} exited {code}", command);
    }
    Ok(())
}

fn namespace_tests(manifest: &Path, host: &str, output: &Path, env: &Env, exec: &mut Executor) -> Result<()> {
    // Run each ignored namespace case in its own new namespace: some cases
    // deliberately leave loopback aliases or process limits changed.
    for (target, label) in [(strings(["--lib"]), "lib"), (strings(["--bin", "dnsmasq-rs"]), "bin")] {
        let mut base = strings(["mbx", "test", "--locked", "--manifest-path", &util::display(manifest), "--target", host, "--all-features"]);
        base.extend(runner_config(host));
        base.extend(target);
        let listing = output.join(format!("dnsmasq-ignored-{label}.log"));
        let mut list = base.clone();
        list.extend(strings(["--", "--ignored", "--list"]));
        exec(&list, &listing, env)?;
        let text = util::read_lossy(&listing).unwrap_or_default();
        let names: Vec<&str> = text.lines().filter_map(|line| line.strip_suffix(": test")).collect();
        for (index, name) in names.into_iter().enumerate() {
            // The platform binary adapter nests the unchanged business owner
            // under daemon; preserve the exact discovered name when executing.
            let business = name.strip_prefix("daemon::").unwrap_or(name);
            if !DNS_NAMESPACE_PREFIXES.iter().any(|prefix| business.starts_with(prefix)) {
                println!("requires separate oracle/corpus: {name}");
                continue;
            }
            let mut command = base.clone();
            command.push(name.into());
            command.extend(strings(["--", "--exact", "--ignored", "--test-threads=1"]));
            exec(&command, &output.join(format!("dnsmasq-namespace-{label}-{index}.log")), env)?;
        }
    }
    Ok(())
}

/// Runs every step for `mode`, returning the summary lines it printed.
fn gates(mode: &str, benchmark: bool, output: &Path, host: &str, exec: &mut Executor) -> Result<Vec<String>> {
    let root = util::repo();
    let mut env = util::current_env();
    env.insert("CARGO_INCREMENTAL".into(), "0".into());
    for key in ["RUSTFLAGS", "RUSTDOCFLAGS"] {
        let flags = format!("{} -Dwarnings", env.get(key).map_or("", String::as_str));
        env.insert(key.into(), flags.trim().to_owned());
    }
    let mut manifests: Vec<PathBuf> = if benchmark {
        vec![root.join("tools/benchmark/Cargo.toml")]
    } else {
        let mut crates: Vec<PathBuf> =
            COMPONENTS.iter().map(|name| root.join("components").join(name).join("Cargo.toml")).collect();
        // The host tooling gets the same test, Clippy and format gates.
        crates.push(root.join("tools/owrt-tools/Cargo.toml"));
        crates
    };
    if mode == "fmt-check" && !benchmark {
        manifests.push(root.join("tools/benchmark/Cargo.toml"));
    }
    for manifest in &manifests {
        let parent = manifest.parent().unwrap();
        let name = if benchmark {
            "benchmark".to_owned()
        } else {
            util::display(parent.strip_prefix(&root).unwrap_or(parent)).replace('/', "-")
        };
        for (step, command) in commands(mode, manifest, host)? {
            exec(&command, &output.join(format!("{name}-{step}.log")), &env)?;
        }
        if mode == "test" && parent == root.join("components/dnsmasq") {
            namespace_tests(manifest, host, output, &env, exec)?;
        }
    }
    let mut summary = Vec::new();
    if !benchmark && matches!(mode, "check" | "fmt-check") {
        // Fuzz targets are standalone binaries, not libtest targets. Keep
        // their API/format checks separate from the 14 component test gates.
        let fuzz = util::display(&root.join("components/dnsmasq/fuzz/Cargo.toml"));
        let command = if mode == "check" {
            strings(["mbx", "check", "--locked", "--manifest-path", &fuzz, "--target", host, "--bins"])
        } else {
            strings(["mbx", "fmt", "--manifest-path", &fuzz, "--check"])
        };
        exec(&command, &output.join(format!("dnsmasq-fuzz-{mode}.log")), &env)?;
        summary.push(format!("Rust fuzz {mode}: passed"));
    }
    summary.push(format!("Rust {mode}: passed ({} crates)", manifests.len()));
    Ok(summary)
}

pub fn main(raw: &[String]) -> Result<i32> {
    if raw.first().is_some_and(|arg| arg == "run-test") {
        return run_test(&raw[1..]);
    }
    let args = Args::parse(raw, &["--output"], &["--benchmark"])?;
    let [mode] = args.exact(&["test|check|build|fmt-check"])?.try_into().expect("one positional");
    ensure!(matches!(mode.as_str(), "test" | "check" | "build" | "fmt-check"), "unknown mode: {mode}");
    linux_only()?;
    let root = util::repo();
    verify_business_boundaries(&root, &BUSINESS_ROOTS)?;
    ensure!(util::euid() != 0, "run Rust gates as an ordinary user; only the test runner uses sudo");
    ensure!(util::output(&strings(["sh", "-c", "command -v mbx"]), None, None).is_ok(),
            "mbx is required; CI installs the pinned verified release");
    let version = util::output(&strings(["rustc", "-vV"]), None, None)?;
    let host = version.split("host: ").nth(1).and_then(|rest| rest.lines().next()).unwrap_or_default().to_owned();
    let output = args.value("--output").map_or_else(|| root.join("work/out/rust-host"), PathBuf::from);
    for line in gates(&mode, args.flag("--benchmark"), &output, &host, &mut execute)? {
        println!("{line}");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    const HOST: &str = "x86_64-unknown-linux-gnu";

    fn recorded(mode: &str, benchmark: bool) -> (Vec<Vec<String>>, Vec<String>) {
        let mut commands = Vec::new();
        let summary = gates(mode, benchmark, Path::new("/unused"), HOST, &mut |command: &[String], _: &Path, _: &Env| {
            commands.push(command.to_vec());
            Ok(())
        })
        .unwrap();
        (commands, summary)
    }

    #[test]
    fn business_boundary_rejects_deny_and_conditional_forbid() {
        let root = TempDir::new("boundary");
        let source = root.path().join("components/example/src/lib.rs");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, "#![forbid(unsafe_code)]\npub fn safe() {}\n").unwrap();
        verify_business_boundaries(root.path(), &["example/src/lib.rs"]).unwrap();
        for weakened in ["#![deny(unsafe_code)]", "#![cfg_attr(test, forbid(unsafe_code))]", "// #![forbid(unsafe_code)]"] {
            std::fs::write(&source, format!("{weakened}\n")).unwrap();
            let error = verify_business_boundaries(root.path(), &["example/src/lib.rs"]).unwrap_err();
            assert!(error.to_string().contains("must retain"));
        }
    }

    #[test]
    fn component_check_entry_also_checks_locked_fuzz_bins() {
        let (commands, summary) = recorded("check", false);
        let fuzz = util::display(&util::repo().join("components/dnsmasq/fuzz/Cargo.toml"));
        let fuzz_rows: Vec<_> = commands.iter().filter(|command| command.contains(&fuzz)).collect();
        assert_eq!(fuzz_rows, [&strings(["mbx", "check", "--locked", "--manifest-path", &fuzz, "--target", HOST, "--bins"])]);
        assert!(summary.contains(&"Rust check: passed (15 crates)".to_owned()));
        assert!(summary.contains(&"Rust fuzz check: passed".to_owned()));
    }

    #[test]
    fn fmt_entry_includes_fuzz_and_tools_but_benchmark_entries_stay_scoped() {
        let fuzz = util::display(&util::repo().join("components/dnsmasq/fuzz/Cargo.toml"));
        let (commands, summary) = recorded("fmt-check", false);
        assert!(commands.contains(&strings(["mbx", "fmt", "--manifest-path", &fuzz, "--check"])));
        let tools = util::display(&util::repo().join("tools/owrt-tools/Cargo.toml"));
        assert!(commands.iter().any(|command| command.contains(&tools)));
        assert!(summary.contains(&"Rust fuzz fmt-check: passed".to_owned()));
        for mode in ["check", "fmt-check"] {
            let (commands, summary) = recorded(mode, true);
            assert!(!commands.is_empty());
            assert!(!commands.iter().any(|command| command.contains(&fuzz)));
            assert!(!summary.iter().any(|line| line.contains("Rust fuzz")));
        }
    }

    #[test]
    fn manifest_inventory_includes_both_platform_crates() {
        let components = util::repo().join("components");
        let mut actual: Vec<String> = std::fs::read_dir(&components)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                path.join("Cargo.toml").is_file().then(|| path.file_name().unwrap().to_string_lossy().into_owned())
            })
            .collect();
        actual.push("dnsmasq/platform".into());
        actual.sort();
        let mut expected: Vec<String> = COMPONENTS.iter().map(|name| (*name).to_owned()).collect();
        expected.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    fn dns_features_and_real_main_process_tests_keep_the_runner() {
        let manifest = util::repo().join("components/dnsmasq/Cargo.toml");
        let rows = commands("test", &manifest, HOST).unwrap();
        let tests: Vec<_> = rows.iter().filter(|(label, _)| label.starts_with("test-")).collect();
        assert_eq!(tests.iter().map(|(label, _)| label.as_str()).collect::<Vec<_>>(), ["test-default", "test-all-features"]);
        for (_, command) in &tests {
            assert_eq!(command[0], "mbx");
            for flag in ["--locked", "--all-targets", "--test-threads=1"] {
                assert!(command.contains(&flag.to_owned()), "{flag}");
            }
            let config = &command[command.iter().position(|arg| arg == "--config").unwrap() + 1];
            let runner: serde_json::Value = serde_json::from_str(config.split_once('=').unwrap().1).unwrap();
            assert_eq!(runner.as_array().unwrap().last().unwrap(), "run-test");
        }
        assert!(tests[1].1.contains(&"--all-features".to_owned()));
    }

    #[test]
    fn example_checks_compile_normal_profiler_programs() {
        let manifest = util::repo().join("components/rpcd/Cargo.toml");
        let rows: std::collections::BTreeMap<_, _> = commands("check", &manifest, HOST).unwrap().into_iter().collect();
        assert!(rows["examples-default"].contains(&"--examples".to_owned()));
        assert!(!rows["examples-default"].contains(&"--all-targets".to_owned()));
        assert_eq!(rows["clippy-default"][rows["clippy-default"].len() - 3..], strings(["--", "-D", "warnings"]));
    }

    #[test]
    fn explicit_business_library_path_keeps_doctest_gate() {
        let root = TempDir::new("doctest");
        std::fs::create_dir(root.path().join("src")).unwrap();
        std::fs::write(root.path().join("src/main.rs"), "#![forbid(unsafe_code)]\n").unwrap();
        let manifest = root.path().join("Cargo.toml");
        std::fs::write(&manifest, "[package]\nname=\"fixture\"\n[lib]\npath=\"src/main.rs\"\n").unwrap();
        assert_eq!(configuration(&manifest).unwrap(), (false, true));
        let rows: std::collections::BTreeMap<_, _> = commands("test", &manifest, HOST).unwrap().into_iter().collect();
        assert!(rows["doc"].contains(&"--doc".to_owned()));
        std::fs::write(&manifest, "[package]\nname=\"fixture\"\n[lib]\npath=\"src/main.rs\"\ndoctest = false\n[features]\n").unwrap();
        assert_eq!(configuration(&manifest).unwrap(), (true, false));
    }

    #[test]
    fn namespace_discovery_keeps_platform_adapter_test_names() {
        let name = "daemon::tests::dns_listener_factories_preserve_bound_ipv4_policy_on_rebind";
        let output = TempDir::new("namespace");
        let mut executed = Vec::new();
        namespace_tests(&util::repo().join("components/dnsmasq/Cargo.toml"), HOST, output.path(), &Env::new(),
            &mut |command: &[String], log: &Path, _: &Env| {
                if command.contains(&"--list".to_owned()) {
                    let listed = if command.contains(&"--bin".to_owned()) { format!("{name}: test\nother::x: test\n") } else { String::new() };
                    std::fs::write(log, listed).unwrap();
                } else {
                    executed.push(command.to_vec());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(executed.len(), 1);
        assert!(executed[0].contains(&name.to_owned()));
        assert!(executed[0].contains(&"--exact".to_owned()));
    }

    #[test]
    fn compilation_failure_cannot_be_reported_as_success() {
        let folder = TempDir::new("failure");
        let error = execute(&strings(["sh", "-c", "exit 7"]), &folder.path().join("failure.log"), &util::current_env());
        assert!(error.unwrap_err().to_string().contains("exited 7"));
    }
}
