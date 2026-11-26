//! The two programs the unchanged dnsmasq SDK recipe executes during a PGO
//! build. `ci-build-dnsmasq` copies this binary under the names below; the
//! binary dispatches on its own name, so the recipe sees a plain executable.
//!
//! * `pgo-cargo` (the recipe's `$(V1_CARGO)`): appends exactly one profile
//!   flag set after the recipe's own RUSTFLAGS and records a receipt.
//! * `map-cc` (the recipe's target compiler): adds `-Wl,-Map=` to the final
//!   static PIE link only; code generation flags are unchanged.

use std::os::unix::process::CommandExt;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::util::{self, bail, ensure, Env, Result};

pub const PGO_CARGO: &str = "pgo-cargo";
pub const MAP_CC: &str = "map-cc";

/// Variables that would change code generation behind the recipe's back.
const OVERRIDES: [&str; 6] = ["CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                              "LLVM_PROFILE_FILE", "CARGO_TARGET_DIR"];

fn sha(path: &str) -> Result<String> {
    util::sha256_file(Path::new(path))
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| util::Error::new(format!("PGO plan field missing: {key}")))
}

/// Validates the SDK Cargo invocation against the plan and returns the
/// receipt, or `None` for the toolchain's `--version` probe.
pub fn prepare(plan: &Value, argv: &[String], env: &Env, wrapper_sha256: &str) -> Result<Option<Value>> {
    if argv == ["--version"] {
        return Ok(None);
    }
    let build = Path::new(field(plan, "build_dir")?);
    let expected_argv = [
        "build".to_owned(), "--release".into(), "--frozen".into(), "--manifest-path".into(),
        util::display(&build.join("dnsmasq/Cargo.toml")), "--bin".into(), "dnsmasq-rs".into(),
        "--target-dir".into(), util::display(&build.join("dnsmasq/target")),
    ];
    ensure!(argv == expected_argv, "unexpected SDK Cargo invocation");
    let adapter = &plan["build_adapter"];
    ensure!(adapter.is_object() && !adapter.as_object().unwrap().is_empty()
                && sha(field(adapter, "path")?).ok().as_deref() == adapter["sha256"].as_str(),
            "mbx build adapter identity missing or changed");
    let expected = plan["recipe_environment"].as_object().cloned().unwrap_or_default();
    for (name, value) in &expected {
        ensure!(env.get(name).map(String::as_str) == value.as_str(), "unexpected SDK recipe environment: {name}");
    }
    for (name, value) in env {
        let profile = name.starts_with("CARGO_PROFILE_") && name != "CARGO_PROFILE_RELEASE_PANIC";
        ensure!(value.is_empty() || !(OVERRIDES.contains(&name.as_str()) || profile),
                "unexpected compiler/profile override: {name}");
    }
    let linker = env.get("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER")
        .ok_or_else(|| util::Error::new("SDK recipe did not set the static PIE linker"))?;
    let linker_sha = sha(linker)?;
    ensure!(plan["static_pie_linker_sha256"] == linker_sha.as_str(), "static PIE linker identity changed");
    let mapping = plan.get("map_compiler").filter(|value| !value.is_null());
    if let Some(mapping) = mapping {
        let same = |variable: &str, key: &str| env.get(variable).map(String::as_str) == mapping[key].as_str();
        let identical = |path: &str, key: &str| -> bool {
            mapping[path].as_str().and_then(|p| sha(p).ok()).as_deref() == mapping[key].as_str()
        };
        ensure!(same("DNSMASQ_STATIC_PIE_CC", "wrapper") && same("PERF_SDK_CC", "sdk_cc")
                    && same("PERF_LINK_MAP", "output_path")
                    && identical("wrapper", "wrapper_sha256") && identical("sdk_cc", "sdk_cc_sha256"),
                "link-map wrapper or SDK compiler identity changed");
    }
    let recipe_flags = env.get("RUSTFLAGS").cloned().unwrap_or_default();
    ensure!(!recipe_flags.contains("profile-") && !recipe_flags.contains("pgo-"), "recipe already supplies PGO flags");
    let mode = plan["mode"].as_str().unwrap_or("use");
    let (added, identity) = match mode {
        "generate" => {
            ensure!(!["profile", "profile_sha256", "profile_bytes"].iter().any(|key| plan.get(*key).is_some()),
                    "instrumentation must not consume a profile");
            let directory = field(plan, "profile_output_dir")?;
            ensure!(directory.starts_with('/') && !directory.chars().any(char::is_whitespace),
                    "invalid instrumentation profile output directory");
            (format!("-Cprofile-generate={directory}"), json!({"profile_output_dir": directory}))
        }
        "use" => {
            let profile = field(plan, "profile")?;
            let size = std::fs::metadata(profile).map(|meta| meta.len()).ok();
            ensure!(profile.starts_with('/') && !profile.chars().any(char::is_whitespace)
                        && size.is_some() && plan["profile_bytes"].as_u64() == size
                        && plan["profile_sha256"] == sha(profile)?.as_str(),
                    "frozen PGO profile identity changed");
            (format!("-Cprofile-use={profile} -Cllvm-args=-pgo-warn-missing-function"),
             json!({"profile_sha256": plan["profile_sha256"], "profile_bytes": plan["profile_bytes"]}))
        }
        _ => bail!("unknown PGO mode"),
    };
    let mut receipt = Map::new();
    receipt.insert("mode".into(), json!(mode));
    receipt.insert("argv".into(), json!(argv));
    receipt.insert("cargo_verbosity".into(), json!("normal"));
    receipt.insert("recipe_environment".into(), Value::Object(expected));
    receipt.insert("build_adapter".into(), adapter.clone());
    receipt.insert("recipe_rustflags".into(), json!(recipe_flags));
    receipt.insert("added_rustflags".into(), json!(added));
    receipt.insert("effective_rustflags".into(), json!(format!("{recipe_flags} {added}")));
    receipt.extend(identity.as_object().unwrap().clone());
    if let Some(mapping) = mapping {
        receipt.insert("map_compiler".into(), mapping.clone());
    }
    receipt.insert("static_pie_linker_sha256".into(), json!(linker_sha));
    receipt.insert("wrapper_sha256".into(), json!(wrapper_sha256));
    Ok(Some(Value::Object(receipt)))
}

fn own_sha256() -> Result<String> {
    util::sha256_file(&std::env::current_exe()?)
}

/// Replaces this process; returns only on failure.
fn exec(program: &str, args: &[String], env: &Env) -> Result<i32> {
    let error = std::process::Command::new(program).args(args).env_clear().envs(env).exec();
    bail!("exec {program}: {error}")
}

pub fn pgo_cargo(argv: &[String]) -> Result<i32> {
    let mut env = util::current_env();
    let plan_path = env.get("DNSMASQ_PGO_BUILD_PLAN").cloned()
        .ok_or_else(|| util::Error::new("DNSMASQ_PGO_BUILD_PLAN is not set"))?;
    let plan = util::read_json(Path::new(&plan_path))?;
    let mut executable = field(&plan, "cargo")?.to_owned();
    if let Some(mut receipt) = prepare(&plan, argv, &env, &own_sha256()?)? {
        executable = field(&receipt["build_adapter"], "path")?.to_owned();
        receipt["plan_sha256"] = json!(sha(&plan_path)?);
        util::write_json_new(Path::new(field(&plan, "receipt")?), &receipt)?;
        env.insert("RUSTFLAGS".into(), field(&receipt, "effective_rustflags")?.to_owned());
    }
    // Preserve normal recipe verbosity. Diagnostic -vv also changes dependency
    // --cap-lints from allow to warn and emits Cargo's ignored-hint advisories.
    exec(&executable, argv, &env)
}

/// The SDK compiler invocation, with a link map for the static PIE link.
pub fn map_command(args: &[String], env: &Env) -> Result<Vec<String>> {
    let cc = env.get("PERF_SDK_CC").map(String::as_str).unwrap_or("");
    ensure!(cc.starts_with('/') && Path::new(cc).is_file(), "expected actual SDK compiler");
    let mut command = vec![cc.to_owned()];
    command.extend(args.iter().cloned());
    if args.iter().any(|arg| arg == "-static-pie") {
        let output = env.get("PERF_LINK_MAP").map(String::as_str).unwrap_or("");
        ensure!(output.starts_with('/') && Path::new(output).components().any(|c| c.as_os_str() == "private"),
                "linker map must be a private absolute output path");
        command.push(format!("-Wl,-Map={output}"));
    }
    Ok(command)
}

pub fn map_cc(args: &[String]) -> Result<i32> {
    let env = util::current_env();
    let command = map_command(args, &env)?;
    exec(&command[0], &command[1..], &env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{strings, TempDir};
    use std::fs;

    struct Fixture {
        _temp: TempDir,
        root: std::path::PathBuf,
        profile: String,
        linker: String,
        env: Env,
        plan: Value,
        argv: Vec<String>,
    }

    fn fixture() -> Fixture {
        let temp = TempDir::new("pgo");
        let root = fs::canonicalize(temp.path()).unwrap();
        let profile = root.join("profile.profdata");
        fs::write(&profile, "frozen synthetic profile").unwrap();
        let linker = root.join("linker.sh");
        fs::write(&linker, "unchanged static PIE linker").unwrap();
        let adapter = root.join("mbx-cargo");
        fs::write(&adapter, "verified adapter").unwrap();
        let (profile, linker) = (util::display(&profile), util::display(&linker));
        let env: Env = [("RUSTUP_TOOLCHAIN", "1.98.1"), ("CARGO_BUILD_TARGET", "aarch64-unknown-linux-musl"),
                        ("CARGO_PROFILE_RELEASE_PANIC", "abort"), ("RUSTFLAGS", "-Cforce-unwind-tables=no"),
                        ("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER", linker.as_str())]
            .iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        let plan = json!({"build_dir": util::display(&root), "profile": profile,
                          "build_adapter": {"path": util::display(&adapter), "sha256": sha(&util::display(&adapter)).unwrap()},
                          "profile_sha256": sha(&profile).unwrap(), "profile_bytes": 24,
                          "static_pie_linker_sha256": sha(&linker).unwrap(), "recipe_environment": env});
        let argv = strings(["build", "--release", "--frozen", "--manifest-path", &util::display(&root.join("dnsmasq/Cargo.toml")),
                            "--bin", "dnsmasq-rs", "--target-dir", &util::display(&root.join("dnsmasq/target"))]);
        Fixture { _temp: temp, root, profile, linker, env, plan, argv }
    }

    #[test]
    fn recipe_receives_one_exact_profile_use_suffix() {
        let f = fixture();
        let result = prepare(&f.plan, &f.argv, &f.env, "w").unwrap().unwrap();
        assert_eq!(result["effective_rustflags"],
                   format!("-Cforce-unwind-tables=no -Cprofile-use={} -Cllvm-args=-pgo-warn-missing-function", f.profile));
        assert_eq!(result["mode"], "use");
        assert_eq!(result["wrapper_sha256"], "w");
        let keys: Vec<&str> = result.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["mode", "argv", "cargo_verbosity", "recipe_environment", "build_adapter", "recipe_rustflags",
                          "added_rustflags", "effective_rustflags", "profile_sha256", "profile_bytes",
                          "static_pie_linker_sha256", "wrapper_sha256"]);
        assert!(prepare(&f.plan, &strings(["--version"]), &f.env, "w").unwrap().is_none());
    }

    #[test]
    fn missing_or_changed_build_adapter_is_rejected() {
        let f = fixture();
        for identity in [Value::Null, json!({"path": f.plan["build_adapter"]["path"], "sha256": "0".repeat(64)})] {
            let mut plan = f.plan.clone();
            plan["build_adapter"] = identity;
            let error = prepare(&plan, &f.argv, &f.env, "w").unwrap_err();
            assert!(error.to_string().contains("mbx build adapter"), "{error}");
        }
    }

    #[test]
    fn wrong_profile_linker_argv_and_codegen_overrides_are_rejected() {
        let f = fixture();
        for (name, value) in [("LLVM_PROFILE_FILE", "raw"), ("CARGO_PROFILE_RELEASE_OPT_LEVEL", "2"),
                              ("RUSTC_WRAPPER", "other"), ("RUSTFLAGS", "-Cprofile-generate=/tmp/profile")] {
            let mut env = f.env.clone();
            env.insert(name.into(), value.into());
            assert!(prepare(&f.plan, &f.argv, &env, "w").is_err(), "{name}");
        }
        let mut env = f.env.clone();
        env.insert("RUSTC_WRAPPER".into(), String::new());
        assert!(prepare(&f.plan, &f.argv, &env, "w").is_ok(), "empty overrides are ignored");
        let mut argv = f.argv.clone();
        argv.extend(strings(["--features", "m6b-diagnostics"]));
        assert!(prepare(&f.plan, &argv, &f.env, "w").is_err());
        fs::write(&f.profile, "changed").unwrap();
        assert!(prepare(&f.plan, &f.argv, &f.env, "w").is_err());
        fs::write(&f.profile, "frozen synthetic profile").unwrap();
        fs::write(&f.linker, "changed").unwrap();
        assert!(prepare(&f.plan, &f.argv, &f.env, "w").is_err());
    }

    #[test]
    fn generate_has_no_profile_input() {
        let f = fixture();
        let mut plan = f.plan.clone();
        for key in ["profile", "profile_sha256", "profile_bytes"] {
            plan.as_object_mut().unwrap().remove(key);
        }
        plan["mode"] = json!("generate");
        plan["profile_output_dir"] = json!("/tmp/dnsmasq-ci-pgo");
        let result = prepare(&plan, &f.argv, &f.env, "w").unwrap().unwrap();
        assert_eq!(result["added_rustflags"], "-Cprofile-generate=/tmp/dnsmasq-ci-pgo");
        assert!(result.get("profile_sha256").is_none());
        let mut consuming = plan.clone();
        consuming["profile_sha256"] = json!("e".repeat(64));
        assert!(prepare(&consuming, &f.argv, &f.env, "w").unwrap_err().to_string().contains("must not consume"));
        plan["mode"] = json!("other");
        assert!(prepare(&plan, &f.argv, &f.env, "w").unwrap_err().to_string().contains("unknown PGO"));
    }

    #[test]
    fn map_wrapper_changes_only_static_pie_link_and_has_frozen_identity() {
        let f = fixture();
        let output = util::display(&f.root.join("private/link.map"));
        let env: Env = [("PERF_SDK_CC".to_owned(), f.linker.clone()), ("PERF_LINK_MAP".to_owned(), output.clone())].into();
        assert_eq!(map_command(&strings(["--version"]), &env).unwrap(), [f.linker.clone(), "--version".into()]);
        assert_eq!(map_command(&strings(["-static-pie", "object.o"]), &env).unwrap(),
                   [f.linker.clone(), "-static-pie".into(), "object.o".into(), format!("-Wl,-Map={output}")]);
        let mut relative = env.clone();
        relative.insert("PERF_LINK_MAP".into(), "relative.map".into());
        assert!(map_command(&strings(["-static-pie"]), &relative).unwrap_err().to_string().contains("private absolute"));
        let shim = util::display(&f.root.join("map-cc"));
        fs::write(&shim, "frozen map wrapper").unwrap();
        let mut recipe = f.env.clone();
        recipe.extend(env.clone());
        recipe.insert("DNSMASQ_STATIC_PIE_CC".into(), shim.clone());
        let mapping = json!({"wrapper": shim, "wrapper_sha256": sha(&shim).unwrap(), "sdk_cc": f.linker,
                             "sdk_cc_sha256": sha(&f.linker).unwrap(), "output_path": output});
        let mut plan = f.plan.clone();
        plan["map_compiler"] = mapping.clone();
        plan["recipe_environment"] = json!(recipe);
        let receipt = prepare(&plan, &f.argv, &recipe, "w").unwrap().unwrap();
        assert_eq!(receipt["map_compiler"], mapping);
        assert_eq!(receipt["recipe_rustflags"], "-Cforce-unwind-tables=no");
        fs::write(&shim, "changed map wrapper").unwrap();
        assert!(prepare(&plan, &f.argv, &recipe, "w").unwrap_err().to_string().contains("wrapper or SDK compiler identity"));
    }
}
