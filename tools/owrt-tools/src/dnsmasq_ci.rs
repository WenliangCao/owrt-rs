//! Fresh SDK builds of dnsmasq for the release image and the PGO workflow.
//!
//! * `ci-build-dnsmasq WORK`: the release step. Builds the accepted product
//!   commit from a `git archive` of its frozen input map through the unchanged
//!   SDK recipe and frozen PGO profile. A PGO release requires the fresh ELF
//!   to equal the accepted artifact; source/profile identity alone never
//!   qualifies a different executable.
//! * `ci-check-dnsmasq-target WORK`: a diagnostic build of the checked-out
//!   revision that rejects every compiler warning.
//! * `ci-check-dnsmasq-pgo-pipeline WORK --spec S --stage X`: canonical PGO
//!   generate / candidate-use / frozen-use builds from an explicit freeze.
//!
//! None of these builds firmware, publishes, installs or deploys.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::dnsmasq_package as package;
use crate::history::resolve_commit;
use crate::pgo_wrappers::{MAP_CC, PGO_CARGO};
use crate::util::{self, ensure, is_hex, strings, Args, Env, JsonExt, Result};
use crate::warnings;

const PGO_BUILD_SLOT: &str = "/home/ubuntu/dnsmasq-perf-20261015/root/private/sdk-build-slot";
pub const PGO_STAGES: [&str; 3] = ["generate", "candidate-use", "frozen-use"];
const TOOLCHAIN: &str = "staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl";

/// The native image specification for `OPENWRT_VERSION`, as the final image
/// integration selects it; never an older release's.
pub fn image_spec(repo: &Path, env: &Env) -> Result<Value> {
    let version = env.get("OPENWRT_VERSION").cloned().unwrap_or_default();
    ensure!(package::release_manifest(&version).is_ok(), "set OPENWRT_VERSION to a release version");
    let path = env.get("OWRT_NATIVE_SPEC").map_or_else(
        || repo.join(format!("packaging/image/native-{version}.json")), PathBuf::from);
    ensure!(path.is_file(), "no qualified native image specification for {version}: {}", path.display());
    let spec = util::read_json(&path)?;
    ensure!(spec["openwrt"] == version.as_str(), "release version differs from pinned image");
    Ok(spec)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = bytes.get(index + 1..index + 3).and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[index], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                index += 3;
            }
            (byte, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `(owner/repo, tag, asset)` of one literal GitHub release asset URL; `gh`
/// handles private-repository authentication.
pub fn profile_asset(url: &str) -> Result<(String, String, String)> {
    let literal = |part: &str| {
        !part.is_empty() && part != "." && part != ".."
            && part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    };
    let path = url.strip_prefix("https://github.com/").filter(|rest| !rest.contains(['?', '#']));
    let parts: Vec<String> = path.map(|path| path.trim_matches('/').split('/').map(percent_decode).collect()).unwrap_or_default();
    ensure!(parts.len() == 6 && parts[2] == "releases" && parts[3] == "download", "expected fixed GitHub profile release URL");
    ensure!([0, 1, 4, 5].iter().all(|index| literal(&parts[*index])),
            "profile release URL must name literal owner/repo/tag/asset");
    Ok((format!("{}/{}", parts[0], parts[1]), parts[4].clone(), parts[5].clone()))
}

/// Runs one logged command (seam for tests).
pub type Runner<'a> = dyn FnMut(&[String], &Path) -> Result<()> + 'a;

fn run_logged(command: &[String], log: &Path) -> Result<()> {
    util::run_logged(command, log, None, None).map(drop)
}

pub fn download_profile(spec: &Value, out: &Path, run: &mut Runner) -> Result<(PathBuf, Vec<String>)> {
    let (mut repo, tag, name) = profile_asset(spec["profile_url"].as_str().unwrap_or_default())?;
    // Frozen evidence retains its original URL; the audited assets now live
    // in the independent public repository. The profile identity is unchanged.
    if repo == "WenliangCao/owrt-control-plane-rs" {
        repo = "WenliangCao/owrt-rs".into();
    }
    ensure!(spec["profile_sha256"].as_str().is_some_and(|d| is_hex(d, 64))
                && spec["profile_bytes"].as_u64().is_some_and(|bytes| bytes > 0),
            "invalid frozen PGO profile identity");
    let directory = out.join("pgo");
    fs::create_dir(&directory)?;
    let command = strings(["gh", "release", "download", &tag, "--repo", &repo, "--pattern", &name,
                           "--dir", &util::display(&directory)]);
    run(&command, &out.join("profile-download.log"))?;
    let profile = directory.join(&name);
    let size = fs::metadata(&profile).ok().filter(|meta| meta.is_file()).map(|meta| meta.len());
    ensure!(size.is_some() && size == spec["profile_bytes"].as_u64()
                && spec["profile_sha256"] == util::sha256_file(&profile)?.as_str(),
            "downloaded PGO profile differs from freeze");
    Ok((profile, command))
}

fn has_symlink_ancestor(path: &Path) -> bool {
    path.ancestors().any(util::is_symlink)
}

/// The fixed PGO build directory. owrt-ubus is a sibling outside dnsmasq's
/// workspace, so Cargo's stable PackageId hash includes this absolute path in
/// `-Cmetadata`; it must be fresh and reached without symlinks.
pub fn pgo_build_slot(path: &Path) -> Result<PathBuf> {
    ensure!(!path.exists() && !has_symlink_ancestor(path), "PGO build slot must be fresh and have no symlink ancestors");
    let parent = path.parent().unwrap();
    if !parent.exists() {
        util::run_checked(&strings(["sudo", "-n", "install", "-d", "-m", "0755", "-o", &util::uid().to_string(),
                                    "-g", &util::gid().to_string(), &util::display(parent)]), None, None)?;
    }
    use std::os::unix::fs::MetadataExt;
    ensure!(parent.is_dir() && fs::metadata(parent)?.uid() == util::uid() && !path.exists() && !has_symlink_ancestor(path),
            "PGO build parent is not the runner-owned task directory");
    Ok(path.to_path_buf())
}

fn identity(path: &Path) -> Result<Value> {
    Ok(json!({"bytes": fs::metadata(path)?.len(), "sha256": util::sha256_file(path)?}))
}

/// Sorted `dir/*/*` files (Python `sorted(dir.glob("*/*"))`).
fn two_level(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(directory) else { return Ok(found) };
    for entry in entries {
        let child = entry?.path();
        if child.is_dir() {
            for inner in fs::read_dir(&child)? {
                found.push(inner?.path());
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Keeps actual failed output and small Cargo identity records, never a
/// target cache. Host build-script identities can propagate into target crate
/// metadata, so both sides are kept, including stdout/cfg and executables.
pub fn retain_pgo_compilation(out: &Path, build_dir: &Path, output: &Path, report: &mut Value) -> Result<()> {
    let evidence = out.join("pgo-compilation");
    fs::create_dir(&evidence)?;
    let prestrip = build_dir.join("dnsmasq/target/aarch64-unknown-linux-musl/release/dnsmasq-rs");
    if prestrip.is_file() {
        util::copy2(&prestrip, &evidence.join("dnsmasq-prestrip"))?;
    }
    for package in package::find_apks(output)? {
        util::copy2(&package, &evidence.join(package.file_name().unwrap()))?;
    }
    if let Some(mapping) = report.get_mut("link_map") {
        util::copy2(Path::new(mapping.str_field("wrapper")?), &evidence.join(MAP_CC))?;
        let source_map = PathBuf::from(mapping.str_field("output_path")?);
        if source_map.is_file() {
            let retained = evidence.join("link.map");
            util::copy2(&source_map, &retained)?;
            mapping["path"] = json!(util::display(&retained));
            mapping["bytes"] = json!(fs::metadata(&retained)?.len());
            mapping["sha256"] = json!(util::sha256_file(&retained)?);
        }
    }
    let (mut rows, mut scripts, mut identities) = (Map::new(), Map::new(), Map::new());
    let target = build_dir.join("dnsmasq/target");
    let selected = ["owrt-ubus-", "owrt-platform-", "dnsmasq-rs-", "dnsmasq-platform-", "rustix-"];
    let is_selected = |path: &Path| {
        path.is_file() && path.parent().and_then(Path::file_name).map(|n| n.to_string_lossy().into_owned())
            .is_some_and(|name| selected.iter().any(|prefix| name.starts_with(prefix)))
    };
    for release in [target.join("release"), prestrip.parent().unwrap().to_path_buf()] {
        for path in two_level(&release.join(".fingerprint"))? {
            if is_selected(&path) {
                let name = util::display(path.strip_prefix(&target).unwrap());
                identities.insert(name.clone(), identity(&path)?);
                if path.extension().is_some_and(|ext| ext == "json") {
                    rows.insert(name, util::read_json(&path)?);
                }
            }
        }
        for path in two_level(&release.join("build"))? {
            if is_selected(&path) {
                let name = util::display(path.strip_prefix(&target).unwrap());
                identities.insert(name.clone(), identity(&path)?);
                if matches!(path.file_name().and_then(|n| n.to_str()), Some("output" | "stderr" | "root-output")) {
                    scripts.insert(name, json!(util::read_text(&path)?));
                }
            }
        }
    }
    util::write_json(&evidence.join("cargo-fingerprints.json"), &Value::Object(rows))?;
    util::write_json(&evidence.join("cargo-build-scripts.json"), &Value::Object(scripts))?;
    util::write_json(&evidence.join("cargo-identities.json"), &Value::Object(identities))?;
    let mut files = Map::new();
    let mut entries: Vec<PathBuf> = fs::read_dir(&evidence)?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_file()).collect();
    entries.sort();
    for path in entries {
        files.insert(path.file_name().unwrap().to_string_lossy().into_owned(), identity(&path)?);
    }
    report["pgo"]["compilation_evidence"] = Value::Object(files);
    Ok(())
}

pub fn verify_pgo_build(out: &Path, report: &mut Value) -> Result<()> {
    const DIAGNOSTICS: [&str; 6] = ["no profile data available", "hash mismatch", "control flow change",
                                    "profile data may be out of date", "malformed instrumentation profile",
                                    "unsupported instrumentation profile"];
    let invocation = out.join("pgo-invocation.json");
    ensure!(invocation.is_file(), "SDK compilation did not invoke the PGO Cargo wrapper");
    let receipt = util::read_json(&invocation)?;
    let mode = report["pgo"].get("mode").and_then(Value::as_str).unwrap_or("use").to_owned();
    ensure!(receipt["mode"] == mode.as_str(), "PGO invocation mode differs from plan");
    ensure!(receipt["cargo_verbosity"] == "normal", "canonical PGO requires normal Cargo verbosity");
    ensure!(receipt.get("build_adapter") == report.get("build_adapter"), "PGO build did not use the verified mbx adapter");
    let effective = receipt["effective_rustflags"].as_str().unwrap_or_default();
    if mode == "generate" {
        ensure!(receipt["profile_output_dir"] == report["pgo"]["profile_output_dir"] && !effective.contains("-Cprofile-use"),
                "instrumentation invocation differs from plan");
    } else {
        ensure!(receipt["profile_sha256"] == report["pgo"]["profile_sha256"]
                    && receipt["profile_bytes"] == report["pgo"]["profile_bytes"],
                "PGO invocation does not match the frozen profile");
        ensure!(!effective.contains("-Cprofile-generate"), "instrumented build is not a release");
    }
    let log = util::read_lossy(&out.join("compile.log"))?;
    let bad: Vec<&str> = log.split('\n')
        .filter(|line| { let lower = line.to_lowercase(); DIAGNOSTICS.iter().any(|d| lower.contains(d)) })
        .collect();
    ensure!(bad.is_empty(), "profile missing/mismatch/invalid diagnostics: {:?}", &bad[..bad.len().min(5)]);
    let warnings = util::splitlines(&log).iter().filter(|line| line.contains("warning:")).count();
    let pgo = &mut report["pgo"];
    pgo["invocation"] = receipt;
    pgo["invocation_sha256"] = json!(util::sha256_file(&invocation)?);
    pgo["profile_diagnostics"] = json!(bad);
    pgo["compile_warning_lines"] = json!(warnings);
    Ok(())
}

/// The input map and digest of `frozen_source` (or the checkout), which
/// must equal the spec's frozen identity.
pub fn source_identity(spec: &Value, frozen_source: Option<&Path>) -> Result<(package::Inputs, String)> {
    let repo = util::repo();
    let root = frozen_source.unwrap_or(&repo);
    let files = package::inputs(root, spec["openwrt"].as_str().unwrap_or("25.12.5"))?;
    let digest = package::input_digest(&files);
    ensure!(spec["source_digest"] == digest.as_str(), "dnsmasq source/SDK recipe differs from accepted main product");
    if let Some(frozen) = spec.get("source_files") {
        ensure!(package::input_value(&files) == *frozen && spec["source_file_count"].as_u64() == Some(files.len() as u64),
                "dnsmasq complete frozen input map differs");
    }
    if frozen_source.is_none() {
        let mut command = strings(["git", "-C", &util::display(&repo), "status", "--porcelain", "--"]);
        command.extend(files.iter().map(|(name, _)| name.clone()));
        ensure!(util::output(&command, None, None)?.is_empty(), "dnsmasq release inputs have uncommitted changes");
    }
    Ok((files, digest))
}

pub fn validate_pgo_stage(spec: &Value, stage: &str, frozen_source: Option<&Path>) -> Result<()> {
    ensure!(PGO_STAGES.contains(&stage), "unknown PGO build stage");
    if stage != "frozen-use" {
        ensure!(frozen_source.is_some() && spec.get("pgo").is_some(),
                "training and candidate creation require an explicit diagnostic source archive");
        ensure!(!["reference_elf_sha256", "reference_elf_bytes"].iter().any(|key| spec.get(*key).is_some()),
                "cannot bypass a frozen reference with a diagnostic stage");
        if stage == "generate" {
            ensure!(!["profile_url", "profile_sha256", "profile_bytes"].iter().any(|key| spec["pgo"].get(*key).is_some()),
                    "instrumentation must not consume a profile");
        }
    }
    Ok(())
}

pub fn verify_pgo_elf(stage: &str, elf: &Path, report: &mut Value) -> Result<()> {
    if stage == "frozen-use" {
        ensure!(report["elf"]["matches_accepted_reference"] == true,
                "fresh CI PGO ELF differs from frozen reference; preserve evidence and investigate, never substitute the reference");
    }
    if stage != "generate" {
        let data = fs::read(elf)?;
        ensure!(!data.windows(22).any(|window| window == b"__llvm_profile_runtime"), "profile generation runtime in release ELF");
    }
    if stage != "frozen-use" {
        report["release_qualified"] = json!(false);
        report["artifact_purpose"] = json!(if stage == "generate" { "instrumented-training-only" } else { "unqualified-candidate" });
    }
    Ok(())
}

/// Keeps frozen product packaging time distinct from release provenance.
///
/// Native integration needs `source_commit` = the common release checkout;
/// PGO inputs keep their original product commit and deterministic package
/// epoch. Legacy specs without an epoch keep the release-HEAD behavior.
pub fn source_epoch(spec: &Value, release_commit: &str, commit_time: &mut dyn FnMut(&str) -> Result<String>) -> Result<String> {
    let frozen = spec.get("source_date_epoch").filter(|value| !value.is_null());
    let commit = if frozen.is_some() { spec.str_field("source_commit")? } else { release_commit };
    let epoch = commit_time(&resolve_commit(&util::repo(), commit)?)?.trim().to_owned();
    ensure!(frozen.is_none_or(|value| value.as_u64().is_some_and(|v| v > 0 && v.to_string() == epoch)),
            "source timestamp differs from frozen product commit");
    Ok(epoch)
}

fn git_commit_time(commit: &str) -> Result<String> {
    util::output(&strings(["git", "-C", &util::display(&util::repo()), "show", "-s", "--format=%ct", commit]), None, None)
}

/// Extracts the accepted product commit, so later shared-library edits on
/// the release branch cannot change the frozen dnsmasq inputs.
fn release_source(work: &Path, spec: &Value) -> Result<PathBuf> {
    let names: Vec<String> = spec.obj_field("source_files")?.keys().cloned().collect();
    extract_commit(&work.join("out/dnsmasq-source.tar"), &work.join("out/dnsmasq-frozen-source"),
                   &resolve_commit(&util::repo(), spec.str_field("source_commit")?)?, &names)
}

fn extract_commit(archive: &Path, frozen: &Path, commit: &str, names: &[String]) -> Result<PathBuf> {
    let mut command = strings(["git", "-C", &util::display(&util::repo()), "archive", "--format=tar", "--output",
                               &util::display(archive), commit, "--"]);
    command.extend(names.iter().cloned());
    util::run_checked(&command, None, None)?;
    fs::create_dir(frozen)?;
    util::run_checked(&strings(["tar", "-xf", &util::display(archive), "-C", &util::display(frozen)]), None, None)?;
    Ok(frozen.to_path_buf())
}

/// The static PIE linker the snapshot's recipe uses (frozen trees carry the
/// historical wrapper).
fn static_pie_linker(source: &Path) -> Result<PathBuf> {
    package::STATIC_PIE_LINKERS.iter().map(|name| source.join(name)).find(|path| path.is_file())
        .ok_or_else(|| util::Error::new("dnsmasq recipe has no static PIE linker"))
}

/// Copies this binary under one of the recipe-facing wrapper names.
fn install_wrapper(target: &Path) -> Result<()> {
    util::copy2(&std::env::current_exe()?, target)?;
    util::set_mode(target, 0o755)
}

fn string_env(pairs: &[(&str, String)]) -> Env {
    pairs.iter().map(|(key, value)| ((*key).to_owned(), value.clone())).collect()
}

pub fn build(work: &Path, spec: &Value, report: &mut Value, frozen_source: Option<&Path>, pgo_stage: &str,
             release_commit: Option<&str>) -> Result<()> {
    // Frozen inputs come from a git archive whose complete input digest must
    // match the spec. A release build also records its own checkout commit.
    validate_pgo_stage(spec, pgo_stage, frozen_source)?;
    let repo = util::repo();
    let root = frozen_source.map_or_else(|| repo.clone(), Path::to_path_buf);
    let (files, digest) = source_identity(spec, frozen_source)?;
    let out = work.join("out/dnsmasq");
    let source = out.join("source");
    let version = spec["openwrt"].as_str().unwrap_or("25.12.5").to_owned();
    package::snapshot(&root, &source, &files, &version)?;
    let product_commit = spec.str_field("source_commit")?;
    let commit = match release_commit {
        Some(commit) => commit.to_owned(),
        None if frozen_source.is_some() => product_commit.to_owned(),
        None => util::git_head(&repo)?,
    };
    report["source_files"] = package::input_value(&files);
    report["source_digest"] = json!(digest);
    report["source_commit"] = json!(commit);
    report["accepted_product_git_commit"] = json!(resolve_commit(&repo, product_commit)?);
    report["accepted_product_commit"] = json!(product_commit);
    report["build_mode"] = json!("compile-and-package");
    let epoch = source_epoch(spec, &commit, &mut git_commit_time)?;
    let (archive_name, archive_hash) = package::pinned_sdk(&source.join(package::release_manifest(&version)?))?;
    ensure!(util::sha256_file(&work.join("dl").join(&archive_name))? == archive_hash, "SDK archive differs from accepted release");
    let sdk = work.join(archive_name.trim_end_matches(".tar.zst"));
    ensure!(sdk.is_dir(), "matching extracted SDK is missing");
    report["sdk"] = json!({"name": util::display(Path::new(sdk.file_name().unwrap())), "archive_sha256": archive_hash,
                           "files": package::input_value(&package::sdk_inputs(&sdk)?)});
    let toolchain = sdk.join(TOOLCHAIN);
    let mut env = package::clean_build_env();
    env.retain(|name, _| !name.starts_with("CARGO_PROFILE_") && name != "LLVM_PROFILE_FILE");
    env.insert("RUSTUP_TOOLCHAIN".into(), package::rust_channel(&source.join("rust-toolchain.toml"))?);
    env.insert("SOURCE_DATE_EPOCH".into(), epoch.clone());
    let cargo = package::which("cargo").ok_or_else(|| util::Error::new("cargo executable missing"))?;
    let cargo = package::safe_path(&std::path::absolute(cargo)?)?;
    let gcc = toolchain.join("bin/aarch64-openwrt-linux-musl-gcc");
    let version_of = |program: &Path, flag: &str, log: &str, env: Option<&Env>| -> Result<Value> {
        Ok(json!(util::run_logged(&[util::display(program), flag.into()], &out.join(log), None, env)?.trim()))
    };
    report["toolchain"] = json!({
        "cargo": version_of(&cargo, "--version", "cargo-version.log", Some(&env))?,
        "rustc": version_of(&cargo.with_file_name("rustc"), "-Vv", "rustc-version.log", Some(&env))?,
        "target_cc": version_of(&gcc, "--version", "target-cc-version.log", None)?,
    });
    let pgo = spec.get("pgo").filter(|value| value.is_object());
    let build_dir = match pgo {
        Some(pgo) => pgo_build_slot(&package::safe_path(Path::new(pgo["build_slot"].as_str().unwrap_or(PGO_BUILD_SLOT)))?)?,
        None => out.join("package-build"),
    };
    let output = out.join("sdk-output");
    let cargo_home = package::safe_path(&package::home_dir(&env, "CARGO_HOME", ".cargo"))?;
    let rustup_home = package::safe_path(&package::home_dir(&env, "RUSTUP_HOME", ".rustup"))?;
    // Populate the locked registry inputs before the SDK's offline Cargo
    // build. Cargo verifies each registry checksum; the lockfile is unchanged.
    util::run_logged(&strings(["cargo", "fetch", "--locked", "--target", "aarch64-unknown-linux-musl", "--manifest-path",
                               &util::display(&source.join("components/dnsmasq/Cargo.toml"))])
                         .into_iter().enumerate().map(|(i, a)| if i == 0 { util::display(&cargo) } else { a }).collect::<Vec<_>>(),
                     &out.join("cargo-fetch.log"), None, Some(&env))?;
    let adapter_root = if source.join("tools/mbx_cargo.sh").is_file() { source.clone() } else { repo.clone() };
    let mut build_cargo = package::safe_path(&adapter_root.join("tools/mbx_cargo.sh"))?;
    ensure!(package::is_executable(&build_cargo), "mbx Cargo adapter missing");
    report["build_adapter"] = json!({"path": util::display(&build_cargo), "sha256": util::sha256_file(&build_cargo)?});
    match package::input_map(&files).get("tools/mbx_cargo.sh") {
        Some(frozen) => {
            ensure!(report["build_adapter"]["sha256"] == frozen.as_str(), "build adapter differs from frozen source identity");
            report["build_adapter_compatibility"] = json!("source-snapshot-bound");
        }
        None => report["build_adapter_compatibility"] = json!("legacy freeze has no adapter; current adapter identified separately"),
    }
    let mut cc_override = Vec::new();
    if let Some(pgo) = pgo {
        ensure!(env["RUSTUP_TOOLCHAIN"] == "1.98.1", "PGO requires pinned Rust 1.98.1");
        let mode = if pgo_stage == "generate" { "generate" } else { "use" };
        let (profile_input, download) = if mode == "generate" {
            (json!({"profile_output_dir": pgo["profile_output_dir"]}), Value::Null)
        } else {
            let (profile, download) = download_profile(pgo, &out, &mut run_logged)?;
            (json!({"profile": util::display(&profile), "profile_sha256": pgo["profile_sha256"],
                    "profile_bytes": pgo["profile_bytes"]}), json!(download))
        };
        build_cargo = out.join(PGO_CARGO);
        install_wrapper(&build_cargo)?;
        let mut cc = util::display(&gcc);
        let mut map_environment = Env::new();
        if pgo.get("retain_link_map") == Some(&json!(true)) {
            let private = out.join("private");
            fs::create_dir(&private)?;
            let map_cc = private.join(MAP_CC);
            install_wrapper(&map_cc)?;
            map_environment = string_env(&[("PERF_SDK_CC", cc.clone()),
                                           ("PERF_LINK_MAP", util::display(&private.join("link.map")))]);
            env.extend(map_environment.clone());
            report["link_map"] = json!({"wrapper": util::display(&map_cc), "wrapper_sha256": util::sha256_file(&map_cc)?,
                                        "sdk_cc": cc, "sdk_cc_sha256": util::sha256_file(Path::new(&cc))?,
                                        "output_path": map_environment["PERF_LINK_MAP"]});
            cc = util::display(&map_cc);
            cc_override.push(format!("TARGET_CC_NOCACHE={}", map_cc.display()));
        }
        let flags = format!("-Cforce-unwind-tables=no --remap-path-prefix={}=/build --remap-path-prefix={}=/cargo \
                             -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now \
                             -Clink-arg=-Wl,-z,relro -Crelocation-model=pie -Ctarget-feature=+crt-static -Dwarnings",
                            build_dir.display(), cargo_home.display());
        let mut recipe = string_env(&[("RUSTUP_TOOLCHAIN", "1.98.1".into()), ("CARGO_HOME", util::display(&cargo_home)),
                                      ("RUSTUP_HOME", util::display(&rustup_home)),
                                      ("CARGO_BUILD_TARGET", "aarch64-unknown-linux-musl".into()),
                                      ("CARGO_PROFILE_RELEASE_PANIC", "abort".into()), ("RUSTFLAGS", flags),
                                      ("DNSMASQ_STATIC_PIE_CC", cc)]);
        let mut recipe_environment = Map::new();
        for key in ["RUSTUP_TOOLCHAIN", "CARGO_HOME", "RUSTUP_HOME", "CARGO_BUILD_TARGET", "CARGO_PROFILE_RELEASE_PANIC",
                    "RUSTFLAGS", "DNSMASQ_STATIC_PIE_CC", "PERF_SDK_CC", "PERF_LINK_MAP"] {
            if let Some(value) = recipe.remove(key).or_else(|| map_environment.get(key).cloned()) {
                recipe_environment.insert(key.into(), json!(value));
            }
        }
        let mut plan = json!({"mode": mode, "cargo": util::display(&cargo), "build_adapter": report["build_adapter"],
                              "build_dir": util::display(&build_dir)});
        plan.as_object_mut().unwrap().extend(profile_input.as_object().unwrap().clone());
        plan["receipt"] = json!(util::display(&out.join("pgo-invocation.json")));
        plan["static_pie_linker_sha256"] = json!(util::sha256_file(&static_pie_linker(&source)?)?);
        plan["recipe_environment"] = Value::Object(recipe_environment);
        if !map_environment.is_empty() {
            plan["map_compiler"] = report["link_map"].clone();
        }
        let plan_path = out.join("pgo-plan.json");
        util::write_json(&plan_path, &plan)?;
        env.insert("DNSMASQ_PGO_BUILD_PLAN".into(), util::display(&plan_path));
        let mut record = pgo.clone();
        record["download_command"] = download;
        record["plan_sha256"] = json!(util::sha256_file(&plan_path)?);
        record["wrapper_sha256"] = json!(util::sha256_file(&build_cargo)?);
        record["mode"] = json!(mode);
        record["training_repeated"] = json!(false);
        report["pgo"] = record;
    }
    let mut variables = strings(["V=s", "-j1"]);
    variables.extend(cc_override);
    if pgo.is_some() {
        variables.push("CONFIG_AUTOREMOVE=".into());
    }
    let release = spec.str_field("package_release")?;
    variables.extend([format!("V1_PACKAGE_RELEASE={release}"),
                      format!("OWRT_COMPONENTS_SOURCE={}", source.join("components").display()),
                      format!("OWRT_DNSMASQ_BUILD_DIR={}", build_dir.display()),
                      format!("OWRT_DNSMASQ_OUTPUT_DIR={}", output.display()),
                      format!("V1_CARGO={}", build_cargo.display()),
                      format!("V1_CARGO_HOME={}", cargo_home.display()),
                      format!("V1_RUSTUP_HOME={}", rustup_home.display())]);
    report["commands"] = json!([]);
    let mut commands: Vec<Vec<String>> = Vec::new();
    let _lock = util::FileLock::acquire(&sdk.join(".owrt-dnsmasq-build.lock"))?;
    let recipe = package::with_recipe(&sdk, &source.join("packaging/openwrt/owrt-dnsmasq"), &out, report, |report| {
        let recipe_path = PathBuf::from(report.str_field("sdk_recipe_path")?);
        let target = util::display(recipe_path.strip_prefix(&sdk).unwrap_or(&recipe_path));
        for stage in ["prepare", "compile"] {
            let mut command = vec!["make".to_owned(), format!("{target}/{stage}")];
            command.extend(variables.iter().cloned());
            commands.push(command.clone());
            let result = util::run_logged(&command, &out.join(format!("{stage}.log")), Some(&sdk), Some(&env))
                .and_then(|_| util::check_interrupted("dnsmasq release build"));
            if stage == "compile" && pgo.is_some() {
                retain_pgo_compilation(&out, &build_dir, &output, report)?;
            }
            result?;
            if stage == "prepare" {
                for (name, expected) in &files {
                    if let Some(relative) = name.strip_prefix("components/") {
                        ensure!(util::sha256_file(&build_dir.join(relative))? == *expected, "SDK prepare copied stale source: {name}");
                    }
                }
            }
        }
        Ok(())
    });
    report["commands"] = json!(commands);
    recipe?;
    if let Some(pgo) = pgo {
        verify_pgo_build(&out, report)?;
        if pgo.get("retain_link_map") == Some(&json!(true)) {
            ensure!(report["link_map"]["bytes"].as_u64().unwrap_or(0) > 0, "same-build linker map was not produced");
        }
    }
    let packages = package::find_apks(&output)?;
    let package_id = package::package_id(release)?;
    ensure!(packages.len() == 1 && packages[0].file_name().is_some_and(|n| n.to_string_lossy() == format!("dnsmasq-{package_id}.apk")),
            "unexpected dnsmasq SDK outputs: {packages:?}");
    let artifact = out.join(packages[0].file_name().unwrap());
    util::copy2(&packages[0], &artifact)?;
    let payload = out.join("payload");
    fs::create_dir(&payload)?;
    let apk = sdk.join("staging_dir/host/bin/apk");
    package::extract_apk(&apk, &artifact, &payload, &out.join("extract.log"))?;
    report["payload_files"] = package::input_value(&package::audit_payload(&payload)?);
    let elf = payload.join("usr/sbin/dnsmasq");
    let text = package::readelf_text(&toolchain.join("bin/aarch64-openwrt-linux-musl-readelf"), &elf, &out.join("elf-readelf.log"))?;
    report["elf_layout"] = package::audit_elf(&fs::read(&elf)?, &text)?;
    let metadata = util::run_logged(&[util::display(&apk), "adbdump".into(), util::display(&artifact)],
                                    &out.join("apk-metadata.log"), None, None)?;
    report["apk_metadata"] = package::audit_metadata(&metadata, release)?;
    ensure!(package::input_map(&package::inputs(&root, &version)?) == package::input_map(&files),
            "dnsmasq source changed while building");
    let elf_sha = util::sha256_file(&elf)?;
    let reference = spec.get("reference_elf_sha256").cloned().unwrap_or(Value::Null);
    report["elf"] = json!({"sha256": elf_sha, "size": fs::metadata(&elf)?.len(), "reference_sha256": reference,
                           "matches_accepted_reference": reference == elf_sha.as_str()});
    if pgo.is_some() {
        verify_pgo_elf(pgo_stage, &elf, report)?;
    }
    report["artifact"] = json!({"name": util::display(Path::new(artifact.file_name().unwrap())),
                                "sha256": util::sha256_file(&artifact)?, "size": fs::metadata(&artifact)?.len()});
    report["budget"] = json!({"elf_max_bytes": spec["elf_max_bytes"], "apk_max_bytes": spec["apk_max_bytes"]});
    if pgo_stage == "generate" {
        report["final_release_budget"] = report["budget"].clone();
        report["budget"] = spec["instrumentation_budget"].clone();
        report["budget_scope"] = json!("instrumented-training-only");
    }
    package::audit_sizes(report)?;
    report["binary_sha256"] = json!({"dnsmasq-rs": elf_sha});
    report["source_date_epoch"] = json!(epoch);
    report["physical_boot_tested"] = json!(false);
    report["compiler_warnings"] = warnings::scan(&warnings::logs_in(&out)?)?;
    ensure!(report["compiler_warnings"]["strict_compiler_warnings_zero"] == true,
            "compiler/Cargo warning in dnsmasq build; original diagnostics retained");
    report["status"] = json!("built-and-audited");
    Ok(())
}

fn work_dir(argument: &str) -> Result<PathBuf> {
    package::safe_path(&fs::canonicalize(argument).or_else(|_| std::path::absolute(argument))?)
}

fn new_out(work: &Path) -> Result<PathBuf> {
    let out = work.join("out/dnsmasq");
    fs::create_dir_all(out.parent().unwrap())?;
    fs::create_dir(&out)?;
    Ok(out)
}

/// `owrt-tools ci-build-dnsmasq WORK`: the release image's dnsmasq step.
pub fn build_main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &[], &[])?;
    let [work] = args.exact(&["WORK"])?.try_into().expect("one positional");
    let work = work_dir(&work)?;
    let selected = image_spec(&util::repo(), &util::current_env())?;
    ensure!(util::is_linux(), "matching Linux SDK build host required");
    let spec = selected.field("dnsmasq_build")?.clone();
    let out = new_out(&work)?;
    let mut report = json!({"status": "building", "scope": "Fresh SDK build; final image runtime acceptance remains separate"});
    util::trap_interrupts();
    let result = util::git_head(&util::repo()).and_then(|head| {
        let frozen = release_source(&work, &spec)?;
        build(&work, &spec, &mut report, Some(&frozen), "frozen-use", Some(&head))
    });
    if let Err(error) = &result {
        report["status"] = json!("failed");
        report["error"] = json!(error.to_string());
    }
    util::write_json(&out.join("manifest.json"), &report)?;
    result?;
    let summary = json!({"status": report["status"], "elf": report["elf"], "artifact": report["artifact"]});
    println!("{}", util::pretty_json(&summary));
    Ok(0)
}

// ------------------------------------------------- diagnostic target check

/// The checked-out revision as a diagnostic build spec (no PGO).
fn source_spec(env: &Env) -> Result<Value> {
    let repo = util::repo();
    let version = env.get("OPENWRT_VERSION").cloned().unwrap_or_else(|| "25.12.5".into());
    let files = package::inputs(&repo, &version)?;
    let spec = json!({"openwrt": version, "source_commit": util::git_head(&repo)?, "source_digest": package::input_digest(&files),
                      "package_release": "4", "reference_elf_sha256": null,
                      "elf_max_bytes": 2_500_000, "apk_max_bytes": 1_400_000});
    source_identity(&spec, None)?; // Reject dirty product/recipe inputs before archiving.
    Ok(spec)
}

/// Archives every product/recipe input from Git, not the current checkout.
/// A frozen spec names its own complete input map; a source spec uses the
/// checkout's current map.
fn freeze_source(out: &Path, spec: &Value) -> Result<PathBuf> {
    let names: Vec<String> = match spec.get("source_files").and_then(Value::as_object) {
        Some(files) => files.keys().cloned().collect(),
        None => package::inputs(&util::repo(), spec["openwrt"].as_str().unwrap_or("25.12.5"))?
            .into_iter().map(|(name, _)| name).collect(),
    };
    let archive = out.join("source.tar");
    let git_commit = resolve_commit(&util::repo(), spec.str_field("source_commit")?)?;
    let frozen = extract_commit(&archive, &out.join("frozen-source"), &git_commit, &names)?;
    let (files, digest) = source_identity(spec, Some(&frozen))?;
    ensure!(spec.get("source_file_count").is_none_or(|count| count.as_u64() == Some(files.len() as u64)),
            "frozen source input count differs from candidate");
    util::write_json(&out.join("source-manifest.json"), &json!({
        "commit": spec["source_commit"], "git_commit": git_commit, "digest": digest,
        "files": package::input_value(&files), "archive_sha256": util::sha256_file(&archive)?}))?;
    Ok(frozen)
}

fn prepare_sdk(work: &Path, out: &Path, frozen: &Path, spec: &Value, run: &mut dyn FnMut(&[String], &Path, Option<&Path>) -> Result<()>,
               sha: &dyn Fn(&Path) -> Result<String>) -> Result<()> {
    let version = spec["openwrt"].as_str().unwrap_or("25.12.5");
    let (name, expected) = package::pinned_sdk(&frozen.join(package::release_manifest(version)?))?;
    let download = work.join("dl").join(&name);
    fs::create_dir_all(download.parent().unwrap())?;
    if !download.exists() {
        let url = format!("https://downloads.openwrt.org/releases/{version}/targets/mediatek/filogic/{name}");
        run(&strings(["curl", "--fail", "--show-error", "--location", "--output", &util::display(&download), &url]),
            &out.join("sdk-download.log"), None)?;
    }
    ensure!(sha(&download)? == expected, "SDK archive checksum mismatch");
    let sdk = work.join(name.trim_end_matches(".tar.zst"));
    ensure!(!sdk.exists(), "target validation requires a fresh extracted SDK");
    run(&strings(["tar", "-xf", &util::display(&download), "-C", &util::display(work)]), &out.join("sdk-extract.log"), None)?;
    if !sdk.join(".config").exists() {
        run(&strings(["make", "defconfig"]), &out.join("sdk-defconfig.log"), Some(&sdk))?;
    }
    Ok(())
}

/// Files in `out` matching single-level glob patterns such as `pgo-*.json`
/// or `pgo/*`.
fn glob_files(out: &Path, pattern: &str) -> Vec<PathBuf> {
    let (directory, name) = pattern.rsplit_once('/').map_or((out.to_path_buf(), pattern), |(d, n)| (out.join(d), n));
    let (prefix, suffix) = name.split_once('*').unwrap_or((name, ""));
    let exact = !name.contains('*');
    let Ok(entries) = fs::read_dir(&directory) else { return Vec::new() };
    entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            let file = path.file_name().unwrap().to_string_lossy();
            path.is_file() && if exact { file == name } else {
                file.len() >= prefix.len() + suffix.len() && file.starts_with(prefix) && file.ends_with(suffix)
            }
        })
        .collect()
}

/// The complete build log and original SDK outputs survive every failure.
fn retain_outputs(out: &Path, report: &mut Value) -> Result<()> {
    let elf = out.join("payload/usr/sbin/dnsmasq");
    if elf.is_file() {
        util::copy2(&elf, &out.join("dnsmasq-rs"))?;
    }
    if glob_files(out, "*.apk").is_empty() {
        for package in package::find_apks(&out.join("sdk-output"))? {
            util::copy2(&package, &out.join(package.file_name().unwrap()))?;
        }
    }
    let retained: BTreeSet<PathBuf> = ["*.apk", "*.log", "source.tar", "source-manifest.json", "dnsmasq-rs",
                                       "pgo/*", "pgo-compilation/*", "pgo-*.json", PGO_CARGO]
        .iter().flat_map(|pattern| glob_files(out, pattern)).collect();
    let mut rows = Map::new();
    for path in retained {
        rows.insert(util::display(path.strip_prefix(out).unwrap()), identity(&path)?);
    }
    report["retained"] = Value::Object(rows);
    Ok(())
}

/// The three external steps of a target check (seam for tests).
trait TargetSteps {
    fn freeze_source(&mut self, out: &Path, spec: &Value) -> Result<PathBuf>;
    fn prepare_sdk(&mut self, work: &Path, out: &Path, frozen: &Path, spec: &Value) -> Result<()>;
    fn build(&mut self, work: &Path, spec: &Value, report: &mut Value, frozen: &Path, stage: &str) -> Result<()>;
}

struct SdkSteps;

impl TargetSteps for SdkSteps {
    fn freeze_source(&mut self, out: &Path, spec: &Value) -> Result<PathBuf> {
        freeze_source(out, spec)
    }

    fn prepare_sdk(&mut self, work: &Path, out: &Path, frozen: &Path, spec: &Value) -> Result<()> {
        prepare_sdk(work, out, frozen, spec,
                    &mut |command, log, cwd| util::run_logged(command, log, cwd, None).map(drop), &util::sha256_file)
    }

    fn build(&mut self, work: &Path, spec: &Value, report: &mut Value, frozen: &Path, stage: &str) -> Result<()> {
        build(work, spec, report, Some(frozen), stage, None)
    }
}

fn target_run(work: &Path, spec: Option<Value>, stage: &str, steps: &mut dyn TargetSteps) -> Result<()> {
    let out = new_out(work)?;
    let mut report = json!({"status": "building", "scope": "diagnostic target build only; not accepted for deployment",
                            "pgo": false, "firmware_built": false, "physical_boot_tested": false, "release_qualified": false,
                            "runner_commit": util::git_head(&util::repo())?});
    let result = (|| -> Result<()> {
        let spec = match spec {
            Some(spec) => spec,
            None => source_spec(&util::current_env())?,
        };
        if spec.get("pgo").is_some() {
            report["pgo_stage"] = json!(stage);
            report["artifact_purpose"] = json!(match stage {
                "generate" => "instrumented-training-only",
                "candidate-use" => "unqualified-candidate",
                _ => "frozen-reference-reproduction",
            });
        }
        util::write_json(&out.join("build-spec.json"), &spec)?;
        let frozen = steps.freeze_source(&out, &spec)?;
        steps.prepare_sdk(work, &out, &frozen, &spec)?;
        steps.build(work, &spec, &mut report, &frozen, stage)?;
        if let Some(bytes) = spec.get("reference_elf_bytes") {
            ensure!(report["elf"]["size"] == *bytes, "fresh CI ELF size differs from frozen reference");
        }
        let found = warnings::scan(&warnings::logs_in(&out)?)?;
        report["warnings"] = found.clone();
        ensure!(found["strict_compiler_warnings_zero"] == true,
                "Rust/Cargo or unclassified compiler warning; see warnings.json and original logs");
        let compile = util::read_lossy(&out.join("compile.log"))?;
        ensure!(compile.contains("dnsmasq-platform") && compile.contains("dnsmasq-rs"),
                "target product/platform compilation evidence missing");
        report["status"] = json!(match stage {
            "generate" => "built-instrumented-training-only",
            "candidate-use" => "created-unqualified-pgo-candidate",
            _ => "passed-target-build-and-zero-compiler-warnings",
        });
        Ok(())
    })();
    if let Err(error) = &result {
        report["status"] = json!("failed");
        report["error"] = json!(error.to_string());
    }
    let map = report.as_object_mut().unwrap();
    for (from, to) in [("accepted_product_commit", "checked_product_commit"),
                       ("accepted_product_git_commit", "checked_product_git_commit")] {
        if let Some(value) = map.shift_remove(from) {
            map.insert(to.into(), value);
        }
    }
    report["warnings"] = warnings::scan(&warnings::logs_in(&out)?)?;
    util::write_json(&out.join("warnings.json"), &report["warnings"])?;
    retain_outputs(&out, &mut report)?;
    util::write_json(&out.join("manifest.json"), &report)?;
    result?;
    let summary = json!({"status": report["status"], "elf": report["elf"], "artifact": report["artifact"],
                         "warnings": report["warnings"]});
    println!("{}", util::pretty_json(&summary));
    Ok(())
}

fn require_target_host() -> Result<()> {
    ensure!(util::is_x86_64_linux(), "native x86_64 Linux host required; no SDK wrapper modifications");
    Ok(())
}

/// `owrt-tools ci-check-dnsmasq-target WORK`.
pub fn target_main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &[], &[])?;
    let [work] = args.exact(&["WORK"])?.try_into().expect("one positional");
    require_target_host()?;
    util::trap_interrupts();
    target_run(&work_dir(&work)?, None, "frozen-use", &mut SdkSteps)?;
    Ok(0)
}

// ------------------------------------------------------ canonical PGO stages

const BUILD_SLOT: &str = "/home/ubuntu/owrt-unified-v022-20261017/private/dnsmasq-sdk-build-slot";
const PROFILE_OUTPUT: &str = "/tmp/dnsmasq-unified-v022-ci-pgo";
const PROFILE_RELEASES: [(&str, &str, &str); 2] = [
    ("25.12.5", "WenliangCao/owrt-control-plane-rs", "dnsmasq-k-pgo-inputs-20261017"),
    ("25.12.6", "WenliangCao/owrt-rs", "dnsmasq-v033-pgo-inputs-20261023"),
];

fn frozen_hash(value: &Value, length: usize) -> bool {
    value.as_str().is_some_and(|text| is_hex(text, length))
}

/// Loads and validates a committed freeze for one explicit PGO stage.
pub fn load_spec(path: &Path, expected_stage: &str) -> Result<Value> {
    let spec = util::read_json(path)?;
    let version = spec.get("openwrt").map_or(Some("25.12.5"), Value::as_str);
    let release = PROFILE_RELEASES.iter().find(|(name, _, _)| Some(*name) == version);
    ensure!(release.is_some(), "PGO requires an explicitly supported OpenWrt baseline");
    let (version, profile_repo, profile_tag) = *release.unwrap();
    ensure!(frozen_hash(&spec["source_commit"], 40), "full source commit required");
    ensure!(spec["source_date_epoch"].as_u64().is_some_and(|epoch| epoch > 0), "source timestamp must be frozen");
    let files = spec.get("source_files").and_then(Value::as_object).filter(|files| !files.is_empty());
    ensure!(files.is_some_and(|files| files.iter().all(|(name, digest)| {
        !name.starts_with('/') && !name.split('/').any(|part| part == "..") && frozen_hash(digest, 64)
    })), "complete source input map required");
    let files = files.unwrap();
    ensure!(files.contains_key("components/platform/Cargo.toml") && files.contains_key("components/dnsmasq/platform/Cargo.toml"),
            "integrated shared platform source is required");
    if version == "25.12.6" {
        ensure!(files.contains_key("manifests/release-25.12.6.json") && !files.contains_key("manifests/release-25.12.5.json"),
                "OpenWrt 25.12.6 requires its own frozen SDK manifest");
    }
    let digest = util::canonical_digest(&spec["source_files"]);
    ensure!(spec["source_digest"] == digest.as_str() && spec["source_file_count"].as_u64() == Some(files.len() as u64),
            "source input digest/count differs from frozen map");
    ensure!(spec["elf_max_bytes"] == 2_500_000 && spec["apk_max_bytes"] == 1_400_000 && spec["package_release"] == "4",
            "final package budgets/release differ");
    let stage = spec["pgo_stage"].as_str().unwrap_or_default();
    ensure!(PGO_STAGES.contains(&stage) && stage == expected_stage, "explicit dispatch stage must match frozen spec");
    let pgo = spec.get("pgo").cloned().unwrap_or_else(|| json!({}));
    ensure!(pgo["build_slot"] == BUILD_SLOT && pgo["retain_link_map"] == true,
            "canonical build slot and same-build linker map required");
    if stage == "generate" {
        ensure!(spec.get("instrumentation_budget") == Some(&json!({"elf_max_bytes": 6_000_000, "apk_max_bytes": 3_500_000})),
                "training-only instrumentation budget differs");
        ensure!(pgo == json!({"build_slot": BUILD_SLOT, "profile_output_dir": PROFILE_OUTPUT, "retain_link_map": true}),
                "generation must not consume an input profile");
    } else {
        ensure!(spec.get("instrumentation_budget").is_none() && pgo.get("profile_output_dir").is_none(),
                "use artifacts cannot use instrumentation settings/budgets");
        ensure!(frozen_hash(&pgo["profile_sha256"], 64) && pgo["profile_bytes"].as_u64().is_some_and(|bytes| bytes > 0),
                "profile hash/size must be frozen");
        let (repo, tag, name) = profile_asset(pgo["profile_url"].as_str().unwrap_or_default())?;
        let commit = spec.str_field("source_commit")?;
        ensure!(repo == profile_repo && tag == profile_tag
                    && name == format!("dnsmasq-{}-{}.profdata", &commit[..8], pgo.str_field("profile_sha256")?),
                "profile must name its unique source/hash build-input asset");
        let provenance = &pgo["training"];
        ensure!(["generator_manifest_sha256", "generator_elf_sha256", "training_receipt_sha256"]
                    .iter().all(|key| frozen_hash(&provenance[*key], 64)),
                "canonical generator/training provenance must be frozen");
    }
    if stage == "frozen-use" {
        ensure!(frozen_hash(&spec["reference_elf_sha256"], 64)
                    && spec["reference_elf_bytes"].as_u64().is_some_and(|bytes| bytes > 0 && Some(bytes) <= spec["elf_max_bytes"].as_u64()),
                "accepted reference ELF hash/size must be frozen");
    } else {
        ensure!(!["reference_elf_sha256", "reference_elf_bytes"].iter().any(|key| spec.get(*key).is_some()),
                "diagnostic stages cannot bypass a frozen reference ELF");
    }
    Ok(spec)
}

/// `owrt-tools ci-check-dnsmasq-pgo-pipeline WORK --spec S --stage X`.
pub fn pgo_pipeline_main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &["--spec", "--stage"], &[])?;
    let [work] = args.exact(&["WORK"])?.try_into().expect("one positional");
    let stage = args.required("--stage")?;
    ensure!(PGO_STAGES.contains(&stage), "--stage must be one of {PGO_STAGES:?}");
    let work = work_dir(&work)?;
    let spec = load_spec(Path::new(args.required("--spec")?), stage)?;
    require_target_host()?;
    util::trap_interrupts();
    target_run(&work, Some(spec), stage, &mut SdkSteps)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{bail, TempDir};

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect()
    }

    #[test]
    fn image_selection_uses_version_and_never_falls_back_to_an_old_release() {
        let temp = TempDir::new("image-spec");
        let specs = temp.path().join("packaging/image");
        fs::create_dir_all(&specs).unwrap();
        for version in ["25.12.5", "25.12.6"] {
            fs::write(specs.join(format!("native-{version}.json")), json!({"openwrt": version}).to_string()).unwrap();
            assert_eq!(image_spec(temp.path(), &env(&[("OPENWRT_VERSION", version)])).unwrap()["openwrt"], version);
        }
        let error = image_spec(temp.path(), &env(&[("OPENWRT_VERSION", "25.12.7")])).unwrap_err();
        assert!(error.to_string().contains("no qualified native image specification"));
        let candidate = temp.path().join("candidate.json");
        fs::write(&candidate, r#"{"openwrt": "25.12.6"}"#).unwrap();
        let explicit = util::display(&candidate);
        assert!(image_spec(temp.path(), &env(&[("OPENWRT_VERSION", "25.12.6"), ("OWRT_NATIVE_SPEC", &explicit)])).is_ok());
        let error = image_spec(temp.path(), &env(&[("OPENWRT_VERSION", "25.12.5"), ("OWRT_NATIVE_SPEC", &explicit)])).unwrap_err();
        assert!(error.to_string().contains("release version differs"));
    }

    #[test]
    fn release_commit_does_not_replace_the_frozen_product_epoch() {
        let spec = json!({"source_commit": "a".repeat(40), "source_date_epoch": 1234});
        let mut asked = Vec::new();
        let mut time = |answer: &'static str| {
            move |commit: &str| -> Result<String> { let _ = commit; Ok(answer.to_owned()) }
        };
        assert_eq!(source_epoch(&spec, &"b".repeat(40), &mut |commit| { asked.push(commit.to_owned()); Ok("1234\n".into()) }).unwrap(), "1234");
        assert_eq!(asked, ["a".repeat(40)]);
        assert!(source_epoch(&spec, &"b".repeat(40), &mut time("1235\n")).unwrap_err().to_string().contains("frozen product commit"));
        let legacy = json!({"source_commit": "a".repeat(40)});
        asked.clear();
        assert_eq!(source_epoch(&legacy, &"b".repeat(40), &mut |commit| { asked.push(commit.to_owned()); Ok("5678\n".into()) }).unwrap(), "5678");
        assert_eq!(asked, ["b".repeat(40)]);
    }

    #[test]
    fn fixed_slot_rejects_existing_outputs_and_symlink_ancestors() {
        let temp = TempDir::new("slot");
        let root = fs::canonicalize(temp.path()).unwrap();
        let slot = root.join("sdk-build-slot");
        assert_eq!(pgo_build_slot(&slot).unwrap(), slot);
        fs::create_dir(&slot).unwrap();
        assert!(pgo_build_slot(&slot).is_err());
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&slot, &alias).unwrap();
        assert!(pgo_build_slot(&alias.join("fresh")).is_err());
    }

    #[test]
    fn compilation_evidence_keeps_outputs_and_selected_fingerprints() {
        let temp = TempDir::new("evidence");
        let root = temp.path();
        let build = root.join("slot");
        let target = build.join("dnsmasq/target/aarch64-unknown-linux-musl/release");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("dnsmasq-rs"), "compiled-elf").unwrap();
        for name in ["owrt-ubus-abcd", "dnsmasq-rs-efab", "dnsmasq-platform-1122", "owrt-platform-5566", "rustix-3344", "unrelated-1234"] {
            fs::create_dir_all(target.join(".fingerprint").join(name)).unwrap();
            fs::write(target.join(".fingerprint").join(name).join("lib.json"), r#"{"metadata":"actual"}"#).unwrap();
        }
        let host = build.join("dnsmasq/target/release");
        fs::create_dir_all(host.join(".fingerprint/rustix-host")).unwrap();
        fs::write(host.join(".fingerprint/rustix-host/build-script-build-script-build.json"), r#"{"metadata":"host"}"#).unwrap();
        fs::create_dir_all(host.join("build/rustix-host")).unwrap();
        fs::write(host.join("build/rustix-host/build-script-build"), "host executable").unwrap();
        fs::create_dir_all(target.join("build/rustix-3344")).unwrap();
        fs::write(target.join("build/rustix-3344/output"), "cargo:rustc-cfg=linux_raw\n").unwrap();
        let packages = root.join("packages");
        fs::create_dir(&packages).unwrap();
        fs::write(packages.join("dnsmasq-2.93-r4.apk"), "actual-package").unwrap();
        let link_map = root.join("link.map");
        fs::write(&link_map, "actual same-build map\n").unwrap();
        let wrapper = root.join("wrapper");
        fs::write(&wrapper, "wrapper").unwrap();
        let mut report = json!({"pgo": {}, "link_map": {"wrapper": util::display(&wrapper), "output_path": util::display(&link_map)}});
        retain_pgo_compilation(root, &build, &packages, &mut report).unwrap();
        let evidence = root.join("pgo-compilation");
        assert_eq!(fs::read_to_string(evidence.join("dnsmasq-prestrip")).unwrap(), "compiled-elf");
        assert_eq!(fs::read_to_string(evidence.join("dnsmasq-2.93-r4.apk")).unwrap(), "actual-package");
        assert_eq!(fs::read_to_string(evidence.join("link.map")).unwrap(), "actual same-build map\n");
        assert_eq!(report["link_map"]["sha256"], util::sha256_file(&link_map).unwrap());
        assert!(report["pgo"]["compilation_evidence"].get("link.map").is_some());
        let fingerprints = util::read_json(&evidence.join("cargo-fingerprints.json")).unwrap();
        assert_eq!(fingerprints.as_object().unwrap().len(), 6);
        assert_eq!(fingerprints["release/.fingerprint/rustix-host/build-script-build-script-build.json"], json!({"metadata": "host"}));
        assert!(fingerprints.get("aarch64-unknown-linux-musl/release/.fingerprint/dnsmasq-platform-1122/lib.json").is_some());
        let scripts = util::read_json(&evidence.join("cargo-build-scripts.json")).unwrap();
        assert_eq!(scripts["aarch64-unknown-linux-musl/release/build/rustix-3344/output"], "cargo:rustc-cfg=linux_raw\n");
        let identities = util::read_json(&evidence.join("cargo-identities.json")).unwrap();
        assert_eq!(identities["release/build/rustix-host/build-script-build"]["sha256"],
                   util::sha256_file(&host.join("build/rustix-host/build-script-build")).unwrap());
    }

    #[test]
    fn fixed_asset_url_and_download_identity() {
        let url = "https://github.com/owner/repo/releases/download/build-inputs/profile.profdata";
        assert_eq!(profile_asset(url).unwrap(), ("owner/repo".into(), "build-inputs".into(), "profile.profdata".into()));
        for invalid in [format!("{url}?token=secret"), url.replace("github.com", "elsewhere.test"),
                        url.replace("profile.profdata", "*.profdata"), url.replace("build-inputs", ".."),
                        url.replace("profile.profdata", "%2A.profdata")] {
            assert!(profile_asset(&invalid).is_err(), "{invalid}");
        }
        let temp = TempDir::new("download");
        let profile = temp.path().join("profile.profdata");
        fs::write(&profile, "frozen synthetic profile").unwrap();
        let spec = json!({"profile_url": url, "profile_sha256": util::sha256_file(&profile).unwrap(), "profile_bytes": 24});
        let content = fs::read(&profile).unwrap();
        let mut fake = |command: &[String], _: &Path| -> Result<()> {
            assert_eq!(command[..4], strings(["gh", "release", "download", "build-inputs"]));
            assert_eq!(command[command.iter().position(|a| a == "--repo").unwrap() + 1], "owner/repo");
            let directory = PathBuf::from(&command[command.iter().position(|a| a == "--dir").unwrap() + 1]);
            fs::write(directory.join("profile.profdata"), &content)?;
            Ok(())
        };
        let out = temp.path().join("good");
        fs::create_dir(&out).unwrap();
        let (path, _) = download_profile(&spec, &out, &mut fake).unwrap();
        assert_eq!(util::sha256_file(&path).unwrap(), spec["profile_sha256"]);
        let bad = temp.path().join("bad");
        fs::create_dir(&bad).unwrap();
        let mut changed = spec.clone();
        changed["profile_sha256"] = json!("0".repeat(64));
        assert!(download_profile(&changed, &bad, &mut fake).unwrap_err().to_string().contains("differs from freeze"));
    }

    #[test]
    fn legacy_profile_location_moves_without_changing_frozen_identity() {
        let original = "WenliangCao/owrt-control-plane-rs";
        for (repository, expected) in [(original.to_owned(), "WenliangCao/owrt-rs".to_owned()),
                                       (format!("{original}-other"), format!("{original}-other")),
                                       ("other/owrt-control-plane-rs".to_owned(), "other/owrt-control-plane-rs".to_owned())] {
            let temp = TempDir::new("legacy-profile");
            let url = format!("https://github.com/{repository}/releases/download/build-inputs/profile.profdata");
            let spec = json!({"profile_url": url, "profile_sha256": util::sha256_bytes(b"p"), "profile_bytes": 1});
            let (_, command) = download_profile(&spec, temp.path(), &mut |command: &[String], _: &Path| {
                assert_eq!(command[command.iter().position(|a| a == "--repo").unwrap() + 1], expected);
                fs::write(PathBuf::from(&command[command.len() - 1]).join("profile.profdata"), "p")?;
                Ok(())
            }).unwrap();
            assert_eq!(command[command.iter().position(|a| a == "--repo").unwrap() + 1], expected);
        }
    }

    fn receipt_fixture(root: &Path, mode: &str) -> Value {
        let mut receipt = json!({"mode": mode, "cargo_verbosity": "normal", "build_adapter": {"path": "/a", "sha256": "b"},
                                 "effective_rustflags": "-Cforce-unwind-tables=no"});
        if mode == "use" {
            receipt["profile_sha256"] = json!("e".repeat(64));
            receipt["profile_bytes"] = json!(5);
        } else {
            receipt["profile_output_dir"] = json!("/tmp/dnsmasq-ci-pgo");
        }
        fs::write(root.join("pgo-invocation.json"), receipt.to_string()).unwrap();
        fs::write(root.join("compile.log"), "Finished release profile\n").unwrap();
        receipt
    }

    #[test]
    fn missing_or_mismatched_profile_diagnostics_fail_closed() {
        let temp = TempDir::new("diagnostics");
        let root = temp.path();
        receipt_fixture(root, "use");
        let mut report = json!({"build_adapter": {"path": "/a", "sha256": "b"},
                                "pgo": {"profile_sha256": "e".repeat(64), "profile_bytes": 5}});
        verify_pgo_build(root, &mut report).unwrap();
        assert_eq!(report["pgo"]["profile_diagnostics"], json!([]));
        for warning in ["warning: no profile data available for function", "warning: hash mismatch",
                        "warning: profile data may be out of date", "malformed instrumentation profile"] {
            fs::write(root.join("compile.log"), warning).unwrap();
            assert!(verify_pgo_build(root, &mut report).is_err(), "{warning}");
        }
        fs::write(root.join("compile.log"), "Finished release profile\n").unwrap();
        let mut other_adapter = report.clone();
        other_adapter["build_adapter"] = json!({"path": "/other", "sha256": "b"});
        assert!(verify_pgo_build(root, &mut other_adapter).is_err());
        fs::remove_file(root.join("pgo-invocation.json")).unwrap();
        assert!(verify_pgo_build(root, &mut report).is_err());
    }

    #[test]
    fn generate_keeps_diagnostic_gate() {
        let temp = TempDir::new("generate");
        let root = temp.path();
        receipt_fixture(root, "generate");
        let mut report = json!({"build_adapter": {"path": "/a", "sha256": "b"},
                                "pgo": {"mode": "generate", "profile_output_dir": "/tmp/dnsmasq-ci-pgo"}});
        verify_pgo_build(root, &mut report).unwrap();
        fs::write(root.join("compile.log"), "warning: hash mismatch\n").unwrap();
        assert!(verify_pgo_build(root, &mut report).unwrap_err().to_string().contains("profile missing/mismatch"));
    }

    #[test]
    fn unqualified_creation_cannot_bypass_frozen_reference() {
        let temp = TempDir::new("stage");
        let spec = json!({"pgo": {}, "reference_elf_sha256": "e".repeat(64)});
        assert!(validate_pgo_stage(&spec, "candidate-use", Some(temp.path())).unwrap_err().to_string().contains("cannot bypass"));
        assert!(validate_pgo_stage(&json!({"pgo": {}}), "candidate-use", None).unwrap_err().to_string().contains("diagnostic source archive"));
        assert!(validate_pgo_stage(&json!({"pgo": {"profile_url": "x"}}), "generate", Some(temp.path())).is_err());
        assert!(validate_pgo_stage(&json!({}), "other", None).is_err());
        let elf = temp.path().join("elf");
        fs::write(&elf, "actual candidate").unwrap();
        let mut report = json!({"elf": {"matches_accepted_reference": false}});
        assert!(verify_pgo_elf("frozen-use", &elf, &mut report).unwrap_err().to_string().contains("differs from frozen reference"));
        verify_pgo_elf("candidate-use", &elf, &mut report).unwrap();
        assert_eq!(report["release_qualified"], false);
        assert_eq!(report["artifact_purpose"], "unqualified-candidate");
        fs::write(&elf, "x__llvm_profile_runtimey").unwrap();
        assert!(verify_pgo_elf("candidate-use", &elf, &mut report).unwrap_err().to_string().contains("generation runtime"));
        let mut accepted = json!({"elf": {"matches_accepted_reference": true}});
        fs::write(&elf, "frozen accepted ELF").unwrap();
        verify_pgo_elf("frozen-use", &elf, &mut accepted).unwrap();
        assert!(accepted.get("release_qualified").is_none() && accepted.get("artifact_purpose").is_none());
    }

    #[test]
    fn committed_pgo_freezes_still_validate() {
        let manifests = util::repo().join("manifests");
        for (file, stage) in [("dnsmasq-pgo-frozen-v033.json", "frozen-use"), ("dnsmasq-pgo-use-v033.json", "candidate-use"),
                              ("dnsmasq-pgo-generate-v033.json", "generate")] {
            load_spec(&manifests.join(file), stage).unwrap_or_else(|error| panic!("{file}: {error}"));
            assert!(load_spec(&manifests.join(file), if stage == "generate" { "frozen-use" } else { "generate" }).is_err());
        }
    }

    #[test]
    fn frozen_source_archive_matches_current_revision() {
        for version in ["25.12.5", "25.12.6"] {
            let temp = TempDir::new("freeze");
            let spec = source_spec(&env(&[("OPENWRT_VERSION", version)])).unwrap();
            let frozen = freeze_source(temp.path(), &spec).unwrap();
            let (files, digest) = source_identity(&spec, Some(&frozen)).unwrap();
            let names: BTreeSet<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
            assert_eq!(spec["openwrt"], version);
            assert_eq!(package::input_map(&files), package::input_map(&package::inputs(&util::repo(), version).unwrap()));
            assert_eq!(spec["source_digest"], digest.as_str());
            assert!(names.contains(format!("manifests/release-{version}.json").as_str()));
            assert!(names.contains(package::SELF_INPUT) && names.contains("components/dnsmasq/platform/src/lib.rs"));
            fs::write(frozen.join("components/dnsmasq/platform/src/lib.rs"), "changed").unwrap();
            assert!(source_identity(&spec, Some(&frozen)).unwrap_err().to_string().contains("differs"));
        }
    }

    #[test]
    fn frozen_v033_spec_archives_its_own_inputs_not_the_checkouts() {
        let temp = TempDir::new("freeze-v033");
        let spec = load_spec(&util::repo().join("manifests/dnsmasq-pgo-frozen-v033.json"), "frozen-use").unwrap();
        let frozen = freeze_source(temp.path(), &spec).unwrap();
        assert!(frozen.join("tools/dnsmasq/build_package.py").is_file());
        assert!(frozen.join("packaging/openwrt/owrt-dnsmasq/static-pie-linker.py").is_file());
        assert!(!frozen.join(package::SELF_INPUT).exists());
    }

    #[test]
    fn new_sdk_uses_frozen_version_and_checksum_before_extraction() {
        let temp = TempDir::new("sdk");
        let frozen = temp.path().join("frozen");
        fs::create_dir_all(frozen.join("manifests")).unwrap();
        let name = "openwrt-sdk-25.12.6-test.tar.zst";
        fs::write(frozen.join("manifests/release-25.12.6.json"),
                  json!({"inputs": {"sdk": format!("{name} sha256 {}", "a".repeat(64))}}).to_string()).unwrap();
        let (work, out) = (temp.path().join("work"), temp.path().join("out"));
        fs::create_dir(&out).unwrap();
        let mut commands = Vec::new();
        prepare_sdk(&work, &out, &frozen, &json!({"openwrt": "25.12.6"}),
                    &mut |command, _, _| { commands.push(command.to_vec()); Ok(()) }, &|_| Ok("a".repeat(64))).unwrap();
        assert_eq!(commands[0].last().unwrap(), &format!("https://downloads.openwrt.org/releases/25.12.6/targets/mediatek/filogic/{name}"));
        assert_eq!(commands[1][..2], strings(["tar", "-xf"]));
        commands.clear();
        let error = prepare_sdk(&work, &out, &frozen, &json!({"openwrt": "25.12.6"}),
                                &mut |command, _, _| { commands.push(command.to_vec()); Ok(()) }, &|_| Ok("b".repeat(64)));
        assert!(error.unwrap_err().to_string().contains("SDK archive checksum mismatch"));
        assert!(!commands.iter().any(|command| command[0] == "tar"));
    }

    struct FakeSteps {
        root: PathBuf,
        fail: bool,
    }

    impl TargetSteps for FakeSteps {
        fn freeze_source(&mut self, _: &Path, _: &Value) -> Result<PathBuf> {
            Ok(self.root.clone())
        }

        fn prepare_sdk(&mut self, _: &Path, _: &Path, _: &Path, _: &Value) -> Result<()> {
            Ok(())
        }

        fn build(&mut self, work: &Path, spec: &Value, report: &mut Value, _: &Path, _: &str) -> Result<()> {
            let out = work.join("out/dnsmasq");
            if self.fail {
                fs::write(out.join("compile.log"), "error: could not compile dnsmasq-rs\n")?;
                fs::create_dir(out.join("sdk-output"))?;
                fs::write(out.join("sdk-output/dnsmasq-2.93-r4.apk"), "partial actual package")?;
                bail!("command [\"make\", \"compile\"] exited 2");
            }
            fs::write(out.join("compile.log"), "Compiling dnsmasq-platform\nCompiling dnsmasq-rs\nwarning: linker stderr: host loader failed\n")?;
            fs::create_dir_all(out.join("payload/usr/sbin"))?;
            fs::write(out.join("payload/usr/sbin/dnsmasq"), "actual elf")?;
            fs::write(out.join("dnsmasq-2.93-r4.apk"), "actual apk")?;
            report["accepted_product_commit"] = spec["source_commit"].clone();
            report["accepted_product_git_commit"] = json!(resolve_commit(&util::repo(), spec.str_field("source_commit")?)?);
            Ok(())
        }
    }

    #[test]
    fn successful_build_with_linker_warning_fails_and_retains_outputs() {
        let temp = TempDir::new("target-run");
        let spec = json!({"source_commit": "a".repeat(40)});
        let mut steps = FakeSteps { root: temp.path().to_path_buf(), fail: false };
        let error = target_run(temp.path(), Some(spec), "frozen-use", &mut steps).unwrap_err();
        assert!(error.to_string().contains("compiler warning"));
        let out = temp.path().join("out/dnsmasq");
        let report = util::read_json(&out.join("manifest.json")).unwrap();
        assert_eq!(report["status"], "failed");
        assert_eq!(report["checked_product_git_commit"], "a".repeat(40));
        assert!(report.get("accepted_product_commit").is_none());
        assert_eq!(report["warnings"]["strict_compiler_warnings_zero"], false);
        assert_eq!(fs::read_to_string(out.join("dnsmasq-rs")).unwrap(), "actual elf");
        assert!(report["retained"].get("dnsmasq-2.93-r4.apk").is_some());
        assert!(out.join("warnings.json").is_file());
    }

    #[test]
    fn compile_failure_keeps_partial_package_and_original_error() {
        let temp = TempDir::new("target-fail");
        let mut steps = FakeSteps { root: temp.path().to_path_buf(), fail: true };
        assert!(target_run(temp.path(), Some(json!({"source_commit": "a".repeat(40)})), "frozen-use", &mut steps).is_err());
        let out = temp.path().join("out/dnsmasq");
        let report = util::read_json(&out.join("manifest.json")).unwrap();
        assert_eq!(report["status"], "failed");
        assert!(report["error"].as_str().unwrap().contains("exited 2"));
        assert_eq!(fs::read_to_string(out.join("dnsmasq-2.93-r4.apk")).unwrap(), "partial actual package");
    }
}
