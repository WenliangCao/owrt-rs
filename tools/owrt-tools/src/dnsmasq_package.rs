//! Builds and audits a dnsmasq replacement APK in the matching OpenWrt SDK.
//!
//! Inputs are snapshotted before `prepare`; output and build directories are
//! new and task-owned. The SDK package recipe is restored even when `make`
//! fails. Logs, source hashes, artifacts and failure manifests stay under the
//! ignored `private/` tree. This file is itself a frozen build input: its
//! digest is part of every new dnsmasq source identity.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::util::{self, bail, ensure, is_hex, strings, Args, Env, JsonExt, Result};

pub const PACKAGE: &str = "dnsmasq";
pub const RECIPE: &str = "owrt-dnsmasq";
pub const TARGET: &str = "aarch64-unknown-linux-musl";
pub const ARCH: &str = "aarch64_cortex-a53";
pub const PACKAGE_VERSION: &str = "2.93";
pub const PACKAGE_RELEASE: &str = "4";
pub const REPLACEMENT_FILES: [&str; 11] = [
    "etc/config/dhcp",
    "etc/dnsmasq.conf",
    "etc/hotplug.d/ntp/25-dnsmasqsec",
    "etc/init.d/dnsmasq",
    "etc/uci-defaults/50-dnsmasq-migrate-ipset.sh",
    "etc/uci-defaults/50-dnsmasq-migrate-resolv-conf-auto.sh",
    "usr/lib/dnsmasq/dhcp-script.sh",
    "usr/sbin/dnsmasq",
    "usr/share/acl.d/dnsmasq_acl.json",
    "usr/share/dnsmasq/dhcpbogushostname.conf",
    "usr/share/dnsmasq/rfc6761.conf",
];
pub const PACKAGE_METADATA_FILES: [&str; 5] = [
    "lib/apk/packages/dnsmasq.conffiles",
    "lib/apk/packages/dnsmasq.conffiles_static",
    "lib/apk/packages/dnsmasq.list",
    "lib/apk/packages/dnsmasq.rusers",
    "lib/upgrade/keep.d/dnsmasq",
];
/// This module, as it is bound into new frozen source identities.
pub const SELF_INPUT: &str = "tools/owrt-tools/src/dnsmasq_package.rs";
/// Trees frozen before the Rust tooling bind the Python builder instead.
const LEGACY_INPUTS: [&str; 2] = ["tools/dnsmasq/build_package.sh", "tools/dnsmasq/build_package.py"];
/// Static PIE linker wrappers, newest first; frozen trees carry their own.
pub const STATIC_PIE_LINKERS: [&str; 2] = [
    "packaging/openwrt/owrt-dnsmasq/static-pie-linker.sh",
    "packaging/openwrt/owrt-dnsmasq/static-pie-linker.py",
];

/// The sorted `/`-prefixed ownership list the SDK writes for the package.
pub fn ownership_list() -> Vec<String> {
    let mut list: Vec<String> = REPLACEMENT_FILES
        .iter()
        .chain(["lib/apk/packages/dnsmasq.rusers", "lib/upgrade/keep.d/dnsmasq"].iter())
        .map(|path| format!("/{path}"))
        .collect();
    list.sort();
    list
}

pub fn package_id(release: &str) -> Result<String> {
    ensure!(matches!(release, "2" | "3" | "4"), "package release must be 2, 3 or 4");
    Ok(format!("{PACKAGE_VERSION}-r{release}"))
}

/// The SDK's Make recipes do not quote all expanded paths, so reject shell and
/// make metacharacters before passing any caller-controlled path to them.
pub fn safe_path(path: &Path) -> Result<PathBuf> {
    static SAFE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/[A-Za-z0-9_./+-]+$").unwrap());
    let text = path.to_str().unwrap_or("");
    ensure!(SAFE.is_match(text) && !text.contains('\n'), "unsupported SDK path: {}", path.display());
    Ok(path.to_path_buf())
}

/// Regular files at or below `path` in sorted order; symlinks are refused.
pub fn files_below(path: &Path) -> Result<Vec<PathBuf>> {
    ensure!(path.exists() && !util::is_symlink(path), "missing or symlink input: {}", path.display());
    let values = if path.is_file() { vec![path.to_path_buf()] } else { util::walk_sorted(path)? };
    let mut files = Vec::new();
    for value in values {
        ensure!(!util::is_symlink(&value), "source symlink is not supported: {}", value.display());
        if value.is_file() {
            files.push(value);
        }
    }
    Ok(files)
}

pub fn release_manifest(version: &str) -> Result<String> {
    static VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$").unwrap());
    ensure!(VERSION.is_match(version), "invalid OpenWrt release version");
    Ok(format!("manifests/release-{version}.json"))
}

/// Ordered `(relative path, sha256)` pairs of every dnsmasq build input.
pub type Inputs = Vec<(String, String)>;

pub fn input_map(inputs: &Inputs) -> BTreeMap<String, String> {
    inputs.iter().cloned().collect()
}

pub fn input_value(inputs: &Inputs) -> Value {
    util::string_map(inputs)
}

/// The frozen source digest over the sorted input map.
pub fn input_digest(inputs: &Inputs) -> String {
    util::canonical_digest(&input_value(inputs))
}

pub fn inputs(root: &Path, version: &str) -> Result<Inputs> {
    let mut paths = vec!["rust-toolchain.toml".to_owned(), release_manifest(version)?,
                         "packaging/openwrt/owrt-dnsmasq".to_owned()];
    // Historical frozen trees keep their original map; new snapshots bind
    // this builder as well as the SDK recipe that invokes it.
    if root.join(LEGACY_INPUTS[1]).exists() {
        paths.extend(LEGACY_INPUTS.iter().map(|path| (*path).to_owned()));
    } else {
        paths.push(SELF_INPUT.to_owned());
    }
    paths.extend(strings(["components/dnsmasq/Cargo.lock", "components/dnsmasq/platform/Cargo.toml",
                          "components/dnsmasq/platform/src"]));
    if root.join("tools/mbx_cargo.sh").exists() {
        paths.push("tools/mbx_cargo.sh".into());
    }
    let manifest: toml::Value = toml::from_str(&util::read_text(&root.join("components/dnsmasq/Cargo.toml"))?)?;
    let targets = |kind: &str| manifest.get(kind).and_then(toml::Value::as_array).cloned().unwrap_or_default();
    let declared_path = |target: &toml::Value| target.get("path").and_then(toml::Value::as_str).map(str::to_owned);
    if targets("bin").iter().any(|target| declared_path(target).as_deref() == Some("platform/entry.rs")) {
        // Current executables register fixed platform workers outside src/.
        // Detect the declared path, not file existence: a missing adapter must
        // fail rather than silently looking like an older frozen source tree.
        paths.extend(strings(["components/dnsmasq/platform/entry.rs", "components/dnsmasq/platform/register.rs",
                              "components/dnsmasq/platform/tests", "components/dnsmasq/tests"]));
        for target in targets("test") {
            if let Some(path) = declared_path(&target) {
                paths.push(format!("components/dnsmasq/{path}"));
            }
        }
    }
    // Older frozen trees predate the shared core boundary; current trees must
    // bind all of it alongside ubus, without sweeping local build artifacts in.
    if root.join("components/platform/Cargo.toml").is_file() {
        paths.extend(strings(["components/platform/Cargo.toml", "components/platform/src"]));
    }
    for component in ["dnsmasq", "ubus"] {
        paths.push(format!("components/{component}/Cargo.toml"));
        paths.push(format!("components/{component}/src"));
    }
    let mut found: Vec<(String, String)> = Vec::new();
    for name in paths {
        for path in files_below(&root.join(&name))? {
            let relative = util::display(path.strip_prefix(root).expect("input is below root"));
            let digest = util::sha256_file(&path)?;
            // A later duplicate replaces the value in place (Python dict).
            match found.iter_mut().find(|(existing, _)| *existing == relative) {
                Some(entry) => entry.1 = digest,
                None => found.push((relative, digest)),
            }
        }
    }
    Ok(found)
}

pub fn snapshot(root: &Path, destination: &Path, expected: &Inputs, version: &str) -> Result<()> {
    for (name, digest) in expected {
        let target = destination.join(name);
        fs::create_dir_all(target.parent().unwrap())?;
        util::copy2(&root.join(name), &target)?;
        ensure!(util::sha256_file(&target)? == *digest, "input changed while copying: {name}");
    }
    ensure!(input_map(&inputs(root, version)?) == input_map(expected), "inputs changed during source snapshot");
    Ok(())
}

/// Identities of the pinned SDK tools used for code generation or packaging.
pub fn sdk_inputs(sdk: &Path) -> Result<Inputs> {
    let toolchain = sdk.join(format!("staging_dir/toolchain-{ARCH}_gcc-14.3.0_musl"));
    let mut paths: Vec<PathBuf> = [
        ".config", "rules.mk", "include/package.mk", "include/package-pack.mk", "include/feeds.mk",
        "scripts/rstrip.sh", "staging_dir/host/bin/apk", "staging_dir/host/bin/sstrip",
        "staging_dir/host/bin/patchelf", "staging_dir/host/bin/.apk.bin",
        "staging_dir/host/bin/.sstrip.bin", "staging_dir/host/bin/.patchelf.bin", "staging_dir/host/lib/runas.so",
        "staging_dir/host/lib/ld-linux-x86-64.so.2",
    ]
    .iter()
    .map(|name| sdk.join(name))
    .collect();
    paths.extend(["include/stdio.h", "lib/libc.so", "lib/crt1.o"].iter().map(|name| toolchain.join(name)));
    // Hash the executable wrappers and their hidden .bin implementations.
    let mut binaries: Vec<PathBuf> = fs::read_dir(toolchain.join("bin"))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect();
    binaries.sort();
    paths.extend(binaries);
    paths
        .iter()
        .map(|path| Ok((util::display(path.strip_prefix(sdk).unwrap()), util::sha256_file(path)?)))
        .collect()
}

/// Binds a previously validated ELF to product, packaging and SDK inputs.
///
/// `source_commit` identifies the product used for the ELF. `source_files`
/// also locks the later packaging recipe and scripts; packaging does not
/// claim that those later tools were part of the product commit.
pub fn verify_freeze(freeze: &Value, source_files: &BTreeMap<String, String>, sdk: &Value, source_commit: &str,
                     epoch: &str, expected_elf: &str, release: &str) -> Result<()> {
    ensure!(freeze.is_object(), "freeze manifest must be a JSON object");
    ensure!(freeze["schema"] == 1 && freeze["frozen"] == true, "freeze manifest must have schema 1 and frozen=true");
    ensure!(!truthy(&freeze["pending"]), "freeze manifest still has pending validation");
    ensure!(freeze.get("package_release").map_or(release == "2", |value| value == release),
            "freeze manifest package release differs from --package-release");
    ensure!(freeze["source_commit"] == source_commit, "freeze manifest product commit differs from --source-commit");
    ensure!(python_str(&freeze["source_date_epoch"]) == epoch,
            "freeze manifest source timestamp differs from --source-date-epoch");
    ensure!(freeze["rust_elf_sha256"] == expected_elf, "freeze manifest ELF differs from --expected-elf-sha256");
    let locked = freeze["source_files"].as_object()
        .ok_or_else(|| util::Error::new("freeze manifest must contain the complete source_files map"))?;
    ensure!(locked.values().all(|digest| digest.as_str().is_some_and(|d| is_hex(d, 64))),
            "freeze source_files must map names to SHA256 hashes");
    let mut changed: Vec<&String> = source_files.keys().chain(locked.keys())
        .filter(|name| source_files.get(*name).map(String::as_str) != locked.get(*name).and_then(Value::as_str))
        .collect();
    changed.sort();
    changed.dedup();
    ensure!(changed.is_empty(), "source/packaging inputs differ from freeze: {changed:?}");
    ensure!(freeze["sdk_archive_sha256"] == sdk["archive_sha256"], "freeze manifest SDK archive identity differs");
    ensure!(freeze["sdk_files"] == sdk["files"], "freeze manifest SDK file identities differ");
    let postprocess = &freeze["postprocess"];
    ensure!(
        matches!(postprocess["mode"].as_str(), Some("none" | "sdk-sstrip"))
            && postprocess["output_sha256"] == expected_elf
            && postprocess["input_sha256"].as_str().is_some_and(|digest| is_hex(digest, 64)),
        "freeze must identify postprocessing, including an explicit none when not applied"
    );
    if postprocess["mode"] == "none" {
        ensure!(postprocess["input_sha256"] == expected_elf && truthy(&postprocess["reason"]),
                "postprocess=none must preserve ELF identity and record why no extra processing ran");
    }
    Ok(())
}

/// Python truthiness of a JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Python `str(value)` for the scalar JSON values freezes store.
pub fn python_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".into(),
        Value::Bool(flag) => if *flag { "True".into() } else { "False".into() },
        other => other.to_string(),
    }
}

/// Swaps the task recipe into the SDK for `body`, then restores the original.
///
/// SDK discovery scans even hidden directories below `package/`, so the
/// recovery copy stays outside that tree and cannot become a second recipe.
pub fn with_recipe<T>(sdk: &Path, source: &Path, out: &Path, report: &mut Value,
                      body: impl FnOnce(&mut Value) -> Result<T>) -> Result<T> {
    let stock = sdk.join("package/network/services/dnsmasq");
    let active = if stock.exists() { stock } else { sdk.join("package").join(RECIPE) };
    report["sdk_recipe_path"] = json!(util::display(&active));
    let backup = sdk.join(format!(".dnsmasq-backup-{}", out.file_name().unwrap_or_default().to_string_lossy()));
    ensure!(!backup.exists(), "package recovery backup already exists: {}", backup.display());
    let existed = active.exists() || util::is_symlink(&active);
    if existed {
        fs::rename(&active, &backup)?;
    }
    let result = util::copy_tree(source, &active).and_then(|()| body(report));
    // Either the installed copy or a failed partial copy into the previously
    // absent destination; the original stays in the backup throughout.
    let cleanup = (|| -> Result<()> {
        if active.exists() {
            fs::remove_dir_all(&active)?;
        }
        if existed {
            fs::rename(&backup, &active)?;
        }
        Ok(())
    })();
    cleanup?;
    report["sdk_recipe_restored"] = json!(true);
    result
}

pub fn audit_payload(payload: &Path) -> Result<Inputs> {
    let found: Inputs = files_below(payload)?
        .iter()
        .map(|path| Ok((util::display(path.strip_prefix(payload).unwrap()), util::sha256_file(path)?)))
        .collect::<Result<_>>()?;
    let mut names: Vec<&str> = found.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    let mut allowed: Vec<&str> = REPLACEMENT_FILES.iter().chain(PACKAGE_METADATA_FILES.iter()).copied().collect();
    allowed.sort_unstable();
    ensure!(names == allowed, "unexpected package payload paths: {names:?}");
    let listing = util::read_text(&payload.join("lib/apk/packages/dnsmasq.list"))?;
    ensure!(util::splitlines(&listing) == ownership_list(), "unexpected package ownership list: {listing:?}");
    // The pinned SDK generates this from conffiles. Installing another copy
    // in the recipe makes package-pack.mk append the same directory twice.
    ensure!(util::read_text(&payload.join("lib/upgrade/keep.d/dnsmasq"))? == "/etc/dnsmasq.d/\n",
            "upgrade keep file differs from the image's single directory entry");
    Ok(found)
}

/// Checks replacement identity without treating `apk adbdump` text as authority.
pub fn audit_metadata(metadata: &str, release: &str) -> Result<Value> {
    static LIBGCC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^    - libgcc1?(?:[<>=~]|\s*$)").unwrap());
    let identity = package_id(release)?;
    let lines: Vec<&str> = metadata.split('\n').collect();
    for (field, expected) in [("name", PACKAGE), ("version", identity.as_str()), ("arch", ARCH)] {
        ensure!(lines.contains(&format!("  {field}: {expected}").as_str()),
                "APK metadata {field} does not identify {expected}");
    }
    for (field, values) in [("provides", &["dnsmasq-any"][..]), ("depends", &["libc", "libubus20251202"][..])] {
        let block = metadata_block(&lines, field);
        ensure!(block.as_ref().is_some_and(|block| values.iter().all(|value| block.contains(&format!("    - {value}").as_str()))),
                "APK metadata {field} misses required entries");
        if field == "depends" {
            ensure!(!block.unwrap().iter().any(|line| LIBGCC.is_match(line)),
                    "static PIE package must not add a direct libgcc/libgcc1 dependency");
        }
    }
    for script in ["post-install", "pre-deinstall", "post-upgrade"] {
        ensure!(lines.contains(&format!("  {script}: |").as_str()), "APK metadata misses {script} script");
    }
    Ok(json!({"name": PACKAGE, "version": identity, "arch": ARCH, "provides": ["dnsmasq-any"],
              "replacement": format!("same package name dnsmasq, newer release {identity}"),
              "variant_exclusion": "requires lifecycle solver tests with stock variant APKs",
              "depends": ["libc", "libubus20251202"]}))
}

/// The `  field:` line and its continuation lines, up to the next two-space
/// indented field or the data block.
fn metadata_block<'a>(lines: &[&'a str], field: &str) -> Option<Vec<&'a str>> {
    let prefix = format!("  {field}:");
    let start = lines.iter().position(|line| line.starts_with(&prefix))?;
    let mut block = vec![lines[start]];
    for line in &lines[start + 1..] {
        let next_field = line.len() > 2 && line.starts_with("  ") && line.as_bytes()[2].is_ascii_lowercase();
        if next_field || line.starts_with("# data block") {
            break;
        }
        block.push(line);
    }
    Some(block)
}

fn le(data: &[u8], offset: usize, size: usize) -> Result<u64> {
    let bytes = data.get(offset..offset + size).ok_or_else(|| util::Error::new("ELF field outside file"))?;
    Ok(bytes.iter().rev().fold(0, |value, byte| (value << 8) | u64::from(*byte)))
}

/// Checks the static PIE layout; runtime ASLR/RELRO is a separate gate.
pub fn audit_elf(data: &[u8], readelf: &str) -> Result<Value> {
    static NEEDED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]").unwrap());
    static FLAGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(FLAGS_1\)\s+Flags:\s*([^\n]+)").unwrap());
    static PATHS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\((?:RPATH|RUNPATH)\)").unwrap());
    const PT_LOAD: u64 = 1;
    const PT_INTERP: u64 = 3;
    const PT_GNU_STACK: u64 = 0x6474_e551;
    const PT_GNU_RELRO: u64 = 0x6474_e552;
    ensure!(data.len() >= 64 && data[..7] == *b"\x7fELF\x02\x01\x01", "package ELF must be ELF64 little-endian");
    ensure!((le(data, 16, 2)?, le(data, 18, 2)?) == (3, 183), "package ELF must be AArch64 ET_DYN");
    let offset = le(data, 32, 8)?;
    let (size, count) = (le(data, 54, 2)?, le(data, 56, 2)?);
    let length = data.len() as u64;
    ensure!(size == 56 && count > 0 && offset >= 64 && offset.checked_add(count * size).is_some_and(|end| end <= length),
            "invalid package ELF program headers");
    // (type, flags, offset, vaddr, paddr, filesz, memsz, align)
    let headers: Vec<[u64; 8]> = (0..count)
        .map(|index| {
            let base = (offset + index * size) as usize;
            Ok([le(data, base, 4)?, le(data, base + 4, 4)?, le(data, base + 8, 8)?, le(data, base + 16, 8)?,
                le(data, base + 24, 8)?, le(data, base + 32, 8)?, le(data, base + 40, 8)?, le(data, base + 48, 8)?])
        })
        .collect::<Result<_>>()?;
    ensure!(headers.iter().all(|row| row[2].checked_add(row[5]).is_some_and(|end| end <= length)),
            "package ELF segment exceeds file");
    let loads: Vec<_> = headers.iter().filter(|row| row[0] == PT_LOAD).collect();
    ensure!(!loads.is_empty() && loads.iter().all(|row| row[5] <= row[6] && row[1] & 3 != 3),
            "package ELF has invalid or writable-executable LOAD segments");
    ensure!(!headers.iter().any(|row| row[0] == PT_INTERP), "static PIE must not have a program interpreter");
    let stacks: Vec<_> = headers.iter().filter(|row| row[0] == PT_GNU_STACK).collect();
    ensure!(stacks.len() == 1 && stacks[0][1] & 1 == 0, "package ELF must have a non-executable GNU_STACK");
    ensure!(headers.iter().any(|row| row[0] == PT_GNU_RELRO && row[6] > 0),
            "package ELF must have a nonempty GNU_RELRO segment");
    ensure!(!NEEDED.is_match(readelf), "static PIE must not depend on shared libraries");
    let flags: Vec<&str> = FLAGS.captures(readelf).map_or(vec![], |c| c.get(1).unwrap().as_str().split_whitespace().collect());
    ensure!(flags.contains(&"PIE"), "package ELF must have the PIE dynamic flag");
    ensure!(!readelf.contains("TEXTREL"), "package ELF must not use text relocations");
    ensure!(!PATHS.is_match(readelf), "package ELF must not override the image library search path");
    Ok(json!({"type": "ET_DYN", "machine": "AArch64", "linkage": "static-pie", "interpreter": null,
              "needed": [], "pie": true, "bind_now": flags.contains(&"NOW") || readelf.contains("(BIND_NOW)"),
              "gnu_relro": true, "nx_stack": true, "writable_executable_load": false,
              "runtime_protections_verified": false}))
}

pub fn read_budget(path: &Path) -> Result<Value> {
    ensure!(path.is_file(), "M4 budget is missing: {}", path.display());
    let budget: Value = serde_json::from_str(&util::read_text(path)?)
        .map_err(|error| util::Error::new(format!("invalid M4 budget: {error}")))?;
    ensure!(budget["schema"] == 1, "M4 budget schema must be 1");
    for field in ["elf_max_bytes", "apk_max_bytes"] {
        ensure!(budget[field].as_u64().is_some_and(|value| value > 0), "M4 budget {field} must be a positive integer");
    }
    let mut result = json!({"schema": 1, "elf_max_bytes": budget["elf_max_bytes"],
                            "apk_max_bytes": budget["apk_max_bytes"], "sha256": util::sha256_file(path)?});
    if let Some(accepted) = budget.get("user_accepted_elf") {
        let original = accepted["original_target_bytes"].as_u64();
        ensure!(accepted["sha256"].as_str().is_some_and(|digest| is_hex(digest, 64))
                    && accepted["bytes"] == budget["elf_max_bytes"]
                    && original.is_some_and(|bytes| bytes > 0 && accepted["bytes"].as_u64().is_some_and(|b| bytes < b))
                    && accepted["reason"].as_str().is_some_and(|reason| !reason.is_empty()),
                "user ELF exception must identify the accepted bytes, SHA256, original target and reason");
        result["user_accepted_elf"] = accepted.clone();
    }
    Ok(result)
}

/// Records both size measurements even when either target is exceeded.
pub fn audit_sizes(report: &mut Value) -> Result<()> {
    let elf_size = report["elf"]["size"].as_u64().unwrap_or(0);
    let apk_size = report["artifact"]["size"].as_u64().unwrap_or(0);
    if let Some(accepted) = report["budget"].get("user_accepted_elf").cloned().filter(truthy) {
        report["original_elf_target_met"] = json!(elf_size <= accepted["original_target_bytes"].as_u64().unwrap_or(0));
        ensure!(report["elf"].get("sha256") == Some(&accepted["sha256"]) && report["elf"]["size"] == accepted["bytes"],
                "user ELF size exception does not authorize this artifact");
        report["size_acceptance"] = json!("explicit-user-exception; original ELF target remains unmet");
    }
    let apk_max = report["budget"]["apk_max_bytes"].as_u64().unwrap_or(0);
    let elf_max = report["budget"]["elf_max_bytes"].as_u64().unwrap_or(0);
    let (apk_ok, elf_ok) = (apk_size <= apk_max, elf_size <= elf_max);
    report["budget_checks"] = json!({"apk": apk_ok, "elf": elf_ok});
    let mut failures = Vec::new();
    if !apk_ok {
        failures.push(format!("APK size {apk_size} exceeds target {apk_max} bytes"));
    }
    if !elf_ok {
        failures.push(format!("ELF size {elf_size} exceeds target {elf_max} bytes"));
    }
    if !failures.is_empty() {
        report["failure_boundary"] = json!("size-target");
        bail!("{}", failures.join("; "));
    }
    Ok(())
}

/// The SDK archive name and SHA-256 pinned by a release manifest.
pub fn pinned_sdk(manifest: &Path) -> Result<(String, String)> {
    let value = util::read_json(manifest)?;
    let pin = value.field("inputs")?.str_field("sdk")?;
    let (name, digest) = pin.split_once(" sha256 ").ok_or_else(|| util::Error::new("malformed SDK pin"))?;
    Ok((name.to_owned(), digest.to_owned()))
}

pub fn rust_channel(toolchain_file: &Path) -> Result<String> {
    let value: toml::Value = toml::from_str(&util::read_text(toolchain_file)?)?;
    value.get("toolchain").and_then(|t| t.get("channel")).and_then(toml::Value::as_str)
        .map(str::to_owned).ok_or_else(|| util::Error::new("rust-toolchain.toml has no channel"))
}

/// Environment for the SDK recipe: no ambient compiler overrides.
pub fn clean_build_env() -> Env {
    let mut env = util::current_env();
    for name in ["CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTFLAGS",
                 "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"] {
        env.remove(name);
    }
    env
}

struct Options {
    sdk: PathBuf,
    version: String,
    release: String,
    source_commit: Option<String>,
    source_date_epoch: Option<String>,
    expected_source_digest: Option<String>,
    expected_elf: String,
    frozen_elf: Option<PathBuf>,
    freeze_manifest: Option<PathBuf>,
}

fn audit_build(options: &Options, out: &Path, report: &mut Value) -> Result<()> {
    let root = util::repo();
    let sdk = safe_path(&fs::canonicalize(&options.sdk).unwrap_or_else(|_| options.sdk.clone()))?;
    ensure!(util::is_linux(), "matching Linux SDK build host required");
    ensure!(sdk.is_dir(), "SDK is missing: {}", sdk.display());
    let version = options.version.as_str();
    let source_hashes = inputs(&root, version)?;
    let source = out.join("source");
    snapshot(&root, &source, &source_hashes, version)?;
    report["source_files"] = input_value(&source_hashes);
    report["source_digest"] = json!(input_digest(&source_hashes));
    if let Some(expected) = &options.expected_source_digest {
        ensure!(report["source_digest"] == expected.as_str(), "source snapshot differs from frozen input digest");
    }
    let epoch = if let Some(commit) = &options.source_commit {
        ensure!(is_hex(commit, 40), "source commit must be a full SHA1");
        let epoch = options.source_date_epoch.clone().filter(|e| !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()));
        ensure!(epoch.is_some() && options.expected_source_digest.is_some(),
                "a copied source snapshot requires commit, epoch and frozen source digest");
        report["git_commit"] = json!(commit);
        report["source_commit_provenance"] = json!("caller; frozen source digest checked");
        report["source_git_status"] = Value::Null;
        epoch.unwrap()
    } else {
        let repo = util::display(&root);
        report["git_commit"] = json!(util::git_head(&root)?);
        report["source_commit_provenance"] = json!("local git checkout; exact file hashes remain authoritative");
        let mut status = strings(["git", "-C", &repo, "status", "--porcelain", "--", "rust-toolchain.toml"]);
        status.push(release_manifest(version)?);
        status.extend(strings(["components/dnsmasq", "components/ubus", "components/platform",
                               "packaging/openwrt/owrt-dnsmasq", SELF_INPUT]));
        let dirty = util::output(&status, None, None)?;
        report["source_git_status"] = json!(dirty);
        ensure!(dirty.is_empty(), "build inputs have uncommitted changes; source commit would be inaccurate");
        util::output(&strings(["git", "-C", &repo, "show", "-s", "--format=%ct", "HEAD"]), None, None)?.trim().to_owned()
    };
    let (archive_name, expected_hash) = pinned_sdk(&source.join(release_manifest(version)?))?;
    ensure!(sdk.file_name().is_some_and(|name| name.to_string_lossy() == archive_name.trim_end_matches(".tar.zst")),
            "SDK name differs from pinned release manifest");
    ensure!(util::sha256_file(&sdk.parent().unwrap().join(&archive_name))? == expected_hash,
            "SDK archive differs from pinned release manifest");
    let toolchain = sdk.join(format!("staging_dir/toolchain-{ARCH}_gcc-14.3.0_musl"));
    let readelf = toolchain.join("bin/aarch64-openwrt-linux-musl-readelf");
    let apk = sdk.join("staging_dir/host/bin/apk");
    let sdk_files = sdk_inputs(&sdk)?;
    report["sdk"] = json!({"path": util::display(&sdk), "archive_sha256": expected_hash, "files": input_value(&sdk_files)});
    let channel = rust_channel(&source.join("rust-toolchain.toml"))?;
    let mut env = clean_build_env();
    env.insert("RUSTUP_TOOLCHAIN".into(), channel.clone());
    env.insert("SOURCE_DATE_EPOCH".into(), epoch.clone());
    report["rust_channel"] = json!(channel);
    report["source_date_epoch"] = json!(epoch);
    let (build, output) = (out.join("package-build"), out.join("sdk-output"));
    report["package_release"] = json!(options.release);
    report["package_id"] = json!(package_id(&options.release)?);
    let mut make_vars = strings(["V=s", "-j1"]);
    make_vars.push(format!("V1_PACKAGE_RELEASE={}", options.release));
    make_vars.push(format!("OWRT_COMPONENTS_SOURCE={}", source.join("components").display()));
    make_vars.push(format!("OWRT_DNSMASQ_BUILD_DIR={}", build.display()));
    make_vars.push(format!("OWRT_DNSMASQ_OUTPUT_DIR={}", output.display()));
    if let (Some(frozen_elf), Some(manifest)) = (&options.frozen_elf, &options.freeze_manifest) {
        let frozen_elf = safe_path(&fs::canonicalize(frozen_elf)?)?;
        let manifest = fs::canonicalize(manifest)?;
        let manifest_digest = util::sha256_file(&manifest)?;
        let freeze = util::read_json(&manifest)?;
        verify_freeze(&freeze, &input_map(&source_hashes), &report["sdk"], options.source_commit.as_deref().unwrap_or(""),
                      &epoch, &options.expected_elf, &options.release)?;
        ensure!(frozen_elf.is_file() && util::sha256_file(&frozen_elf)? == options.expected_elf,
                "frozen ELF input does not match its validated identity");
        let copied = out.join("frozen-dnsmasq");
        util::copy2(&frozen_elf, &copied)?;
        util::copy2(&manifest, &out.join("freeze-manifest.json"))?;
        ensure!(util::sha256_file(&copied)? == options.expected_elf && util::sha256_file(&manifest)? == manifest_digest
                    && util::sha256_file(&out.join("freeze-manifest.json"))? == manifest_digest,
                "frozen inputs changed during snapshot");
        report["build_mode"] = json!("package-frozen-elf");
        report["freeze_manifest_sha256"] = json!(manifest_digest);
        report["frozen_elf_input"] = json!({"sha256": util::sha256_file(&copied)?, "size": fs::metadata(&copied)?.len()});
        report["frozen_build_profile"] = freeze.get("build_profile").cloned().unwrap_or(Value::Null);
        report["postprocess"] = freeze["postprocess"].clone();
        report["strip_policy"] = json!("skip SDK RSTRIP to preserve the previously validated frozen ELF identity");
        make_vars.push(format!("OWRT_DNSMASQ_FROZEN_ELF={}", copied.display()));
    } else {
        let cargo = match std::env::var("CARGO").ok().filter(|value| !value.is_empty()) {
            Some(cargo) => PathBuf::from(cargo),
            None => which("cargo").unwrap_or_else(|| home().join(".cargo/bin/cargo")),
        };
        let cargo = safe_path(&std::path::absolute(cargo)?)?;
        ensure!(is_executable(&cargo), "cargo executable missing");
        report["build_mode"] = json!("compile-and-package");
        report["cargo_version"] = json!(util::run_logged(&[util::display(&cargo), "--version".into()],
                                                         &out.join("cargo-version.log"), None, Some(&env))?.trim());
        report["rustc_version"] = json!(util::run_logged(&[util::display(&cargo.with_file_name("rustc")), "-Vv".into()],
                                                         &out.join("rustc-version.log"), None, Some(&env))?.trim());
        report["target_cc_version"] = json!(util::run_logged(
            &[util::display(&toolchain.join("bin/aarch64-openwrt-linux-musl-gcc")), "--version".into()],
            &out.join("target-cc-version.log"), None, None)?.trim());
        let adapter_root = if source.join("tools/mbx_cargo.sh").is_file() { source.clone() } else { root.clone() };
        let adapter = safe_path(&adapter_root.join("tools/mbx_cargo.sh"))?;
        ensure!(is_executable(&adapter), "mbx Cargo adapter missing");
        let adapter_sha = util::sha256_file(&adapter)?;
        report["build_adapter"] = json!({"path": util::display(&adapter), "sha256": adapter_sha});
        match input_map(&source_hashes).get("tools/mbx_cargo.sh") {
            Some(frozen) => {
                ensure!(adapter_sha == *frozen, "build adapter differs from frozen source identity");
                report["build_adapter_compatibility"] = json!("source-snapshot-bound");
            }
            None => report["build_adapter_compatibility"] =
                json!("legacy freeze has no adapter; current adapter identified separately"),
        }
        make_vars.push(format!("V1_CARGO={}", adapter.display()));
        make_vars.push(format!("V1_CARGO_HOME={}", safe_path(&home_dir(&env, "CARGO_HOME", ".cargo"))?.display()));
        make_vars.push(format!("V1_RUSTUP_HOME={}", safe_path(&home_dir(&env, "RUSTUP_HOME", ".rustup"))?.display()));
    }
    let _lock = util::FileLock::acquire(&sdk.join(".owrt-dnsmasq-build.lock"))?;
    let frozen = options.frozen_elf.is_some();
    let mut commands: Vec<Vec<String>> = Vec::new();
    report["commands"] = json!([]);
    let recipe = with_recipe(&sdk, &source.join(format!("packaging/openwrt/{RECIPE}")), out, report, |report| {
        let recipe_path = PathBuf::from(report["sdk_recipe_path"].as_str().unwrap_or_default());
        let recipe_target = util::display(recipe_path.strip_prefix(&sdk).unwrap_or(&recipe_path));
        report["make_recipe_target"] = json!(recipe_target);
        for stage in ["prepare", "compile"] {
            let mut command = vec!["make".to_owned(), format!("{recipe_target}/{stage}")];
            command.extend(make_vars.iter().cloned());
            commands.push(command.clone());
            util::run_logged(&command, &out.join(format!("{stage}.log")), Some(&sdk), Some(&env))?;
            util::check_interrupted("package build")?;
            if stage == "prepare" {
                let mut copied = Vec::new();
                for (name, expected) in &source_hashes {
                    if let Some(relative) = name.strip_prefix("components/") {
                        ensure!(util::sha256_file(&build.join(relative))? == *expected,
                                "SDK prepare copied stale source: {name}");
                        copied.push((relative.to_owned(), expected.clone()));
                    }
                }
                report["prepared_source_files"] = util::string_map(&copied);
                if frozen {
                    ensure!(util::sha256_file(&build.join("frozen-dnsmasq"))? == options.expected_elf,
                            "SDK prepare changed frozen ELF");
                }
            }
        }
        Ok(())
    });
    report["commands"] = json!(commands);
    recipe?;
    let artifact = output.join(format!("packages/{ARCH}/base/{PACKAGE}-{}.apk", package_id(&options.release)?));
    let candidates = find_apks(&output)?;
    ensure!(candidates == [artifact.clone()], "expected exactly the current package artifact; found {candidates:?}");
    let artifact_copy = out.join(artifact.file_name().unwrap());
    util::copy2(&artifact, &artifact_copy)?;
    let artifact = artifact_copy;
    let payload = out.join("payload");
    fs::create_dir(&payload)?;
    extract_apk(&apk, &artifact, &payload, &out.join("extract.log"))?;
    report["payload_files"] = input_value(&audit_payload(&payload)?);
    let elf = payload.join("usr/sbin/dnsmasq");
    report["elf_layout"] = audit_elf(&fs::read(&elf)?, &readelf_text(&readelf, &elf, &out.join("elf-readelf.log"))?)?;
    let metadata = util::run_logged(&[util::display(&apk), "adbdump".into(), util::display(&artifact)],
                                    &out.join("apk-metadata.log"), None, None)?;
    report["apk_metadata"] = audit_metadata(&metadata, &options.release)?;
    ensure!(input_map(&inputs(&root, version)?) == input_map(&source_hashes), "source changed while building; artifact is not current");
    if frozen {
        ensure!(util::sha256_file(&out.join("frozen-dnsmasq"))? == options.expected_elf, "frozen ELF snapshot changed while packaging");
        ensure!(input_value(&sdk_inputs(&sdk)?) == report["sdk"]["files"], "SDK inputs changed while packaging");
    }
    let (artifact_sha, elf_sha) = (util::sha256_file(&artifact)?, util::sha256_file(&elf)?);
    let name = util::display(Path::new(artifact.file_name().unwrap()));
    report["artifact"] = json!({"name": name, "sha256": artifact_sha, "size": fs::metadata(&artifact)?.len()});
    report["elf"] = json!({"sha256": elf_sha, "size": fs::metadata(&elf)?.len(), "install_path": "/usr/sbin/dnsmasq"});
    fs::write(out.join("SHA256SUMS"), format!("{artifact_sha}  {name}\n{elf_sha}  payload/usr/sbin/dnsmasq\n"))?;
    report["elf"]["source_commit"] = report["git_commit"].clone();
    report["elf"]["expected_sha256"] = json!(options.expected_elf);
    ensure!(elf_sha == options.expected_elf, "packaged ELF differs from the frozen ELF; retain artifact and investigate build inputs");
    report["artifact_identity_verified"] = json!(true);
    audit_sizes(report)
}

/// Every `dnsmasq-*.apk` below the SDK output, sorted.
pub fn find_apks(output: &Path) -> Result<Vec<PathBuf>> {
    if !output.exists() {
        return Ok(Vec::new());
    }
    Ok(util::walk_sorted(output)?
        .into_iter()
        .filter(|path| {
            path.file_name().map(|n| n.to_string_lossy().into_owned()).is_some_and(|n| n.starts_with("dnsmasq-") && n.ends_with(".apk"))
        })
        .collect())
}

pub fn extract_apk(apk: &Path, artifact: &Path, payload: &Path, log: &Path) -> Result<()> {
    util::run_logged(&[util::display(apk), "extract".into(), "--allow-untrusted".into(), "--no-network".into(),
                       "--no-chown".into(), "--destination".into(), util::display(payload), util::display(artifact)],
                     log, None, None)?;
    Ok(())
}

pub fn readelf_text(readelf: &Path, elf: &Path, log: &Path) -> Result<String> {
    let mut env = util::current_env();
    env.insert("LC_ALL".into(), "C".into());
    util::run_logged(&[util::display(readelf), "-W".into(), "-h".into(), "-l".into(), "-d".into(), util::display(elf)],
                     log, None, Some(&env))
}

pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

pub fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .and_then(|paths| std::env::split_paths(&paths).map(|dir| dir.join(name)).find(|path| is_executable(path)))
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from)
}

/// `$name` or `~/<default>`, resolved like Python `Path(...).resolve()`.
pub fn home_dir(env: &Env, name: &str, default: &str) -> PathBuf {
    let path = env.get(name).map_or_else(|| home().join(default), PathBuf::from);
    fs::canonicalize(&path).unwrap_or(path)
}

/// Runs `build` for a new task directory and always writes its manifest.
fn attempt(out: &Path, budget: &Path, build: impl FnOnce(&Path, &mut Value) -> Result<()>) -> Result<Value> {
    let root = util::repo();
    ensure!(out.starts_with(root.join("private")) && out != root.join("private"),
            "output must be a new task directory below private/");
    fs::create_dir_all(out.parent().unwrap())?;
    fs::create_dir(out)?; // Refuse reused outputs before touching SDK state.
    let mut report = json!({"package": PACKAGE, "recipe": RECIPE, "target": TARGET, "activation": "unvalidated-package",
                            "physical_router": false, "status": "building",
                            "scope": "APK build audit only; lifecycle and deployment acceptance are separate"});
    let result = read_budget(budget).and_then(|budget| {
        report["budget"] = budget;
        build(out, &mut report)
    });
    match result {
        Ok(()) => report["status"] = json!("built-and-audited"),
        Err(error) => {
            report["status"] = json!("failed");
            report["error"] = json!(error.to_string());
            eprintln!("{error}");
        }
    }
    let mut warnings = Vec::new();
    for log in crate::warnings::logs_in(out)? {
        for line in util::splitlines(&util::read_lossy(&log)?) {
            let lower = line.to_lowercase();
            if lower.contains("warning") || lower.contains("ld.so") {
                warnings.push(Value::String(line.to_owned()));
            }
        }
    }
    report["warnings"] = Value::Array(warnings);
    fs::write(out.join("manifest.json"), util::pretty_json(&report) + "\n")?;
    Ok(report)
}

/// `owrt-tools dnsmasq-build-package SDK OUT --budget B --expected-elf-sha256 H ...`
pub fn main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &["--openwrt-version", "--package-release", "--budget", "--source-commit",
                                  "--source-date-epoch", "--expected-source-digest", "--expected-elf-sha256",
                                  "--frozen-elf", "--freeze-manifest"], &[])?;
    let [sdk, out] = args.exact(&["SDK", "OUT"])?.try_into().expect("two positionals");
    let release = args.value("--package-release").unwrap_or(PACKAGE_RELEASE).to_owned();
    ensure!(matches!(release.as_str(), "2" | "3" | "4"), "--package-release must be 2, 3 or 4");
    let options = Options {
        sdk: PathBuf::from(sdk),
        version: args.value("--openwrt-version").unwrap_or("25.12.5").to_owned(),
        release,
        source_commit: args.value("--source-commit").map(str::to_owned),
        source_date_epoch: args.value("--source-date-epoch").map(str::to_owned),
        expected_source_digest: args.value("--expected-source-digest").map(str::to_owned),
        expected_elf: args.required("--expected-elf-sha256")?.to_owned(),
        frozen_elf: args.value("--frozen-elf").map(PathBuf::from),
        freeze_manifest: args.value("--freeze-manifest").map(PathBuf::from),
    };
    ensure!(options.frozen_elf.is_some() == options.freeze_manifest.is_some(),
            "--frozen-elf and --freeze-manifest must be supplied together");
    ensure!(options.frozen_elf.is_none() || options.source_commit.is_some(), "frozen ELF packaging requires --source-commit");
    ensure!(is_hex(&options.expected_elf, 64), "frozen ELF SHA256 must be 64 lowercase hex digits");
    let out = safe_path(&std::path::absolute(out)?)?;
    let budget = safe_path(&std::path::absolute(args.required("--budget")?)?)?;
    util::trap_interrupts();
    let report = attempt(&out, &budget, |out, report| audit_build(&options, out, report))?;
    let summary = json!({"status": report["status"], "package": report["package"], "activation": report["activation"]});
    println!("{}", util::line_json(&summary));
    Ok(i32::from(report["status"] != "built-and-audited"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    fn write(root: &Path, name: &str, text: &str) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn base_files(tooling: &[&str]) -> Vec<String> {
        let mut files = strings(["rust-toolchain.toml", "manifests/release-25.12.5.json",
                                 "packaging/openwrt/owrt-dnsmasq/Makefile", "components/dnsmasq/Cargo.lock"]);
        files.extend(tooling.iter().map(|name| (*name).to_owned()));
        for component in ["dnsmasq", "dnsmasq/platform", "ubus", "platform"] {
            files.push(format!("components/{component}/Cargo.toml"));
            files.push(format!("components/{component}/src/lib.rs"));
        }
        files
    }

    fn names(inputs: &Inputs) -> std::collections::BTreeSet<String> {
        inputs.iter().map(|(name, _)| name.clone()).collect()
    }

    #[test]
    fn platform_manifest_covers_source_but_not_local_build_output() {
        let temp = TempDir::new("inputs");
        let root = temp.path();
        let required = base_files(&[SELF_INPUT]);
        for name in required.iter().map(String::as_str).chain(["components/dnsmasq/platform/target/local-artifact",
                                                                 "components/platform/target/local-artifact"]) {
            write(root, name, name);
        }
        write(root, "components/dnsmasq/Cargo.toml", "[package]\nname = \"dnsmasq-rs\"\n");
        let expected: std::collections::BTreeSet<String> = required.iter().cloned().collect();
        assert_eq!(names(&inputs(root, "25.12.5").unwrap()), expected);
        write(root, "manifests/release-25.12.6.json", "verified new SDK identity");
        let current = names(&inputs(root, "25.12.6").unwrap());
        assert!(current.contains("manifests/release-25.12.6.json") && !current.contains("manifests/release-25.12.5.json"));
        assert!(inputs(root, "25.12.7").unwrap_err().to_string().contains("missing"));
        assert!(inputs(root, "../../other").unwrap_err().to_string().contains("invalid OpenWrt"));
        let source = root.join("components/dnsmasq/platform/src/lib.rs");
        let before = inputs(root, "25.12.5").unwrap();
        fs::write(&source, "changed platform implementation").unwrap();
        assert_ne!(inputs(root, "25.12.5").unwrap(), before);
        fs::remove_file(&source).unwrap();
        std::os::unix::fs::symlink(root.join("rust-toolchain.toml"), &source).unwrap();
        assert!(inputs(root, "25.12.5").unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn historical_trees_keep_the_python_builder_inputs() {
        let temp = TempDir::new("legacy");
        let root = temp.path();
        let required = base_files(&LEGACY_INPUTS);
        for name in &required {
            write(root, name, name);
        }
        write(root, "components/dnsmasq/Cargo.toml", "[package]\nname = \"dnsmasq-rs\"\n");
        write(root, SELF_INPUT, "not part of a legacy tree");
        let expected: std::collections::BTreeSet<String> = required.iter().cloned().collect();
        assert_eq!(names(&inputs(root, "25.12.5").unwrap()), expected);
        fs::remove_file(root.join(LEGACY_INPUTS[0])).unwrap();
        assert!(inputs(root, "25.12.5").unwrap_err().to_string().contains("missing"));
    }

    #[test]
    fn digest_matches_python_canonical_json() {
        let inputs = vec![("b".to_owned(), "2".to_owned()), ("a".to_owned(), "1".to_owned())];
        // sha256 of '{"a":"1","b":"2"}', as Python's json.dumps(sort_keys=True, separators=(",",":")).
        assert_eq!(input_digest(&inputs), util::sha256_bytes(br#"{"a":"1","b":"2"}"#));
    }

    #[test]
    fn executable_platform_adapters_are_snapshotted_and_missing_targets_fail() {
        let temp = TempDir::new("adapters");
        let root = temp.path().join("source");
        let adapters = ["platform/entry.rs", "platform/register.rs", "platform/tests/process_forks.rs",
                        "platform/tests/process_owner.rs", "platform/tests/panic_hook.rs",
                        "tests/process_forks.rs", "tests/process_owner.rs"];
        for name in base_files(&[SELF_INPUT]).iter().cloned().chain(adapters.iter().map(|a| format!("components/dnsmasq/{a}"))) {
            write(&root, &name, &name);
        }
        write(&root, "components/dnsmasq/Cargo.toml",
              "[package]\nname = \"dnsmasq-rs\"\n[[bin]]\nname = \"dnsmasq-rs\"\npath = \"platform/entry.rs\"\n\
               [[test]]\nname = \"process_forks\"\npath = \"platform/tests/process_forks.rs\"\n\
               [[test]]\nname = \"process_owner\"\npath = \"platform/tests/process_owner.rs\"\n");
        let expected = inputs(&root, "25.12.5").unwrap();
        let destination = temp.path().join("snapshot");
        snapshot(&root, &destination, &expected, "25.12.5").unwrap();
        for name in adapters {
            assert_eq!(fs::read(destination.join("components/dnsmasq").join(name)).unwrap(),
                       fs::read(root.join("components/dnsmasq").join(name)).unwrap());
        }
        for name in &adapters[..4] {
            let path = root.join("components/dnsmasq").join(name);
            let saved = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            assert!(inputs(&root, "25.12.5").unwrap_err().to_string().contains("missing"), "{name}");
            fs::write(&path, saved).unwrap();
        }
    }

    fn recipe_fixture() -> (TempDir, PathBuf, PathBuf) {
        let temp = TempDir::new("recipe");
        let active = temp.path().join("sdk/package/owrt-dnsmasq");
        fs::create_dir_all(&active).unwrap();
        fs::write(active.join("old"), "preserve").unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("Makefile"), "current").unwrap();
        (temp, active, source)
    }

    #[test]
    fn failed_build_restores_existing_recipe() {
        let (temp, active, source) = recipe_fixture();
        let sdk = temp.path().join("sdk");
        let mut report = json!({});
        let result: Result<()> = with_recipe(&sdk, &source, &temp.path().join("output"), &mut report, |_| {
            assert_eq!(fs::read_to_string(active.join("Makefile")).unwrap(), "current");
            assert_eq!(fs::read_to_string(sdk.join(".dnsmasq-backup-output/old")).unwrap(), "preserve");
            let listed: Vec<_> = fs::read_dir(sdk.join("package")).unwrap().map(|e| e.unwrap().file_name()).collect();
            assert_eq!(listed, ["owrt-dnsmasq"]);
            bail!("deliberate build failure")
        });
        assert!(result.unwrap_err().to_string().contains("deliberate build failure"));
        let listed: Vec<_> = fs::read_dir(&active).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(listed, ["old"]);
        assert_eq!(report["sdk_recipe_restored"], true);
    }

    #[test]
    fn failed_copy_restores_existing_recipe() {
        let (temp, active, _) = recipe_fixture();
        let missing = temp.path().join("missing-source");
        let result: Result<()> = with_recipe(&temp.path().join("sdk"), &missing, &temp.path().join("output"),
                                             &mut json!({}), |_| panic!("failed copy entered the build"));
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(active.join("old")).unwrap(), "preserve");
    }

    #[test]
    fn payload_rejects_extra_files_and_symlinks() {
        let temp = TempDir::new("payload");
        let root = temp.path();
        for relative in REPLACEMENT_FILES.iter().chain(PACKAGE_METADATA_FILES.iter()) {
            write(root, relative, "fixture");
        }
        write(root, "lib/apk/packages/dnsmasq.list", &(ownership_list().join("\n") + "\n"));
        let keep = root.join("lib/upgrade/keep.d/dnsmasq");
        fs::write(&keep, "/etc/dnsmasq.d/\n").unwrap();
        assert_eq!(audit_payload(root).unwrap().len(), REPLACEMENT_FILES.len() + PACKAGE_METADATA_FILES.len());
        fs::write(&keep, "/etc/dnsmasq.d/\n/etc/dnsmasq.d/\n").unwrap();
        assert!(audit_payload(root).unwrap_err().to_string().contains("upgrade keep file"));
        fs::write(&keep, "/etc/dnsmasq.d/\n").unwrap();
        write(root, "usr/libexec/extra", "unexpected");
        assert!(audit_payload(root).is_err());
        fs::remove_file(root.join("usr/libexec/extra")).unwrap();
        std::os::unix::fs::symlink("dnsmasq-rs", root.join("usr/libexec/extra")).unwrap();
        assert!(audit_payload(root).is_err());
    }

    #[test]
    fn make_path_rejects_shell_and_make_metacharacters() {
        for path in ["/tmp/a b", "/tmp/a;id", "/tmp/$(id)", "/tmp/a\nb", "/tmp/a#b", "relative"] {
            assert!(safe_path(Path::new(path)).is_err(), "{path:?}");
        }
        assert!(safe_path(Path::new("/home/ubuntu/sdk-1.2_x+y")).is_ok());
    }

    #[test]
    fn exceeded_size_targets_keep_both_measurements() {
        let mut report = json!({"artifact": {"size": 801_000}, "elf": {"size": 1_200_000},
                                "budget": {"apk_max_bytes": 800_000, "elf_max_bytes": 700_000}});
        let error = audit_sizes(&mut report).unwrap_err().to_string();
        assert!(error.contains("APK size 801000") && error.contains("ELF size 1200000"), "{error}");
        assert_eq!(report["budget_checks"], json!({"apk": false, "elf": false}));
        assert_eq!(report["failure_boundary"], "size-target");
    }

    #[test]
    fn user_size_exception_is_bound_to_one_elf_and_retains_original_miss() {
        let temp = TempDir::new("budget");
        let path = temp.path().join("budget.json");
        fs::write(&path, json!({"schema": 1, "elf_max_bytes": 1159280, "apk_max_bytes": 700000,
            "user_accepted_elf": {"bytes": 1159280, "sha256": "f".repeat(64), "original_target_bytes": 1000000,
                                  "reason": "User explicitly accepted measured option A"}}).to_string()).unwrap();
        let mut report = json!({"budget": read_budget(&path).unwrap(), "elf": {"size": 1159280, "sha256": "f".repeat(64)},
                                "artifact": {"size": 600000}});
        audit_sizes(&mut report).unwrap();
        assert_eq!(report["original_elf_target_met"], false);
        assert!(report["size_acceptance"].as_str().unwrap().contains("explicit-user-exception"));
        report["elf"]["sha256"] = json!("a".repeat(64));
        assert!(audit_sizes(&mut report).unwrap_err().to_string().contains("does not authorize"));
    }

    const METADATA: &str = "info:\n  name: dnsmasq\n  version: 2.93-r4\n  arch: aarch64_cortex-a53\n\
        \x20 depends: # 2 items\n    - libc\n    - libubus20251202\n  provides: # 1 items\n    - dnsmasq-any\n\
        scripts:\n  post-install: |\n  pre-deinstall: |\n  post-upgrade: |\n";

    #[test]
    fn candidate_metadata_requires_actual_lifecycle_scripts() {
        assert_eq!(audit_metadata(METADATA, "4").unwrap()["version"], "2.93-r4");
        for script in ["post-install", "pre-deinstall", "post-upgrade"] {
            let error = audit_metadata(&METADATA.replace(&format!("  {script}: |\n"), ""), "4").unwrap_err();
            assert!(error.to_string().contains(script));
        }
        assert!(audit_metadata(&METADATA.replace("    - libc\n", ""), "4").unwrap_err().to_string().contains("depends"));
        for dependency in ["libgcc", "libgcc1", "libgcc1>=14.3.0-r1"] {
            let changed = METADATA.replace("    - libubus20251202\n", &format!("    - libubus20251202\n    - {dependency}\n"));
            assert!(audit_metadata(&changed, "4").unwrap_err().to_string().contains("direct libgcc"), "{dependency}");
        }
        audit_metadata(&METADATA.replace("    - libubus20251202\n", "    - libubus20251202\n    - libmnl0\n"), "4").unwrap();
        assert!(audit_metadata(METADATA, "3").is_err());
    }

    fn pack(data: &mut [u8], offset: usize, bytes: &[u8]) {
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn elf_fixture() -> Vec<u8> {
        let mut data = vec![0u8; 512];
        pack(&mut data, 0, b"\x7fELF\x02\x01\x01");
        pack(&mut data, 16, &3u16.to_le_bytes());
        pack(&mut data, 18, &183u16.to_le_bytes());
        pack(&mut data, 32, &64u64.to_le_bytes());
        pack(&mut data, 54, &56u16.to_le_bytes());
        pack(&mut data, 56, &5u16.to_le_bytes());
        let interpreter = b"/lib/ld-musl-aarch64.so.1\0";
        let length = interpreter.len() as u64;
        let headers: [(u32, u32, [u64; 6]); 5] = [
            (1, 5, [0, 0, 0, 448, 448, 4096]),
            (1, 6, [448, 448, 448, 64, 64, 4096]),
            (0, 4, [384, 384, 384, length, length, 1]),
            (0x6474_e551, 6, [0, 0, 0, 0, 0, 16]),
            (0x6474_e552, 4, [448, 448, 448, 64, 64, 1]),
        ];
        for (index, (kind, flags, rest)) in headers.iter().enumerate() {
            let base = 64 + index * 56;
            pack(&mut data, base, &kind.to_le_bytes());
            pack(&mut data, base + 4, &flags.to_le_bytes());
            for (field, value) in rest.iter().enumerate() {
                pack(&mut data, base + 8 + field * 8, &value.to_le_bytes());
            }
        }
        pack(&mut data, 384, interpreter);
        data
    }

    #[test]
    fn pie_elf_gate_rejects_linkage_and_protection_regressions() {
        let data = elf_fixture();
        let dynamic = " 0x18 (BIND_NOW)\n 0x6ffffffb (FLAGS_1) Flags: NOW PIE\n";
        let result = audit_elf(&data, dynamic).unwrap();
        assert_eq!(result["needed"], json!([]));
        assert!(result["interpreter"].is_null());
        assert_eq!(result["runtime_protections_verified"], false);
        let unbound = dynamic.replace(" 0x18 (BIND_NOW)\n", "").replace("NOW PIE", "PIE");
        assert_eq!(audit_elf(&data, &unbound).unwrap()["bind_now"], false);
        let length = data.len() as u64;
        let mutations: [(&str, usize, Vec<u8>); 10] = [
            ("static ET_EXEC", 16, 2u16.to_le_bytes().to_vec()),
            ("wrong architecture", 18, 62u16.to_le_bytes().to_vec()),
            ("dynamic interpreter", 64 + 2 * 56, 3u32.to_le_bytes().to_vec()),
            ("executable stack", 64 + 3 * 56 + 4, 7u32.to_le_bytes().to_vec()),
            ("missing stack", 64 + 3 * 56, 0u32.to_le_bytes().to_vec()),
            ("missing RELRO", 64 + 4 * 56, 0u32.to_le_bytes().to_vec()),
            ("empty RELRO", 64 + 4 * 56 + 40, 0u64.to_le_bytes().to_vec()),
            ("WX load", 64 + 56 + 4, 7u32.to_le_bytes().to_vec()),
            ("truncated header table", 32, length.to_le_bytes().to_vec()),
            ("segment outside file", 64 + 56 + 32, length.to_le_bytes().to_vec()),
        ];
        for (label, offset, bytes) in mutations {
            let mut changed = data.clone();
            pack(&mut changed, offset, &bytes);
            assert!(audit_elf(&changed, dynamic).is_err(), "{label}");
        }
        for (label, changed) in [
            ("shared library", format!("{dynamic} 0x1 (NEEDED) Shared library: [libc.so]\n")),
            ("missing PIE", dynamic.replace("NOW PIE", "NOW")),
            ("text relocation", format!("{dynamic} 0x16 (TEXTREL)\n")),
            ("library search override", format!("{dynamic} 0x1d (RUNPATH) Library runpath: [/tmp]\n")),
        ] {
            assert!(audit_elf(&data, &changed).is_err(), "{label}");
        }
    }

    #[test]
    fn frozen_elf_requires_full_source_sdk_and_binary_identity() {
        let source: BTreeMap<String, String> = [("components/dnsmasq/src/main.rs", "a"), ("packaging/openwrt/owrt-dnsmasq/Makefile", "b"),
            ("tools/dnsmasq/build_package.py", "c")].iter().map(|(k, v)| ((*k).to_owned(), v.repeat(64))).collect();
        let sdk = json!({"archive_sha256": "d".repeat(64), "files": {"rules.mk": "e".repeat(64)}});
        let freeze = json!({"schema": 1, "frozen": true, "package_release": "4", "source_commit": "1".repeat(40),
            "source_date_epoch": 123, "rust_elf_sha256": "f".repeat(64), "source_files": source,
            "sdk_archive_sha256": sdk["archive_sha256"], "sdk_files": sdk["files"],
            "postprocess": {"mode": "none", "reason": "rustc strip=true; preserve qualified identity",
                            "input_sha256": "f".repeat(64), "output_sha256": "f".repeat(64)}});
        let check = |freeze: &Value| verify_freeze(freeze, &source, &sdk, &"1".repeat(40), "123", &"f".repeat(64), "4");
        check(&freeze).unwrap();
        let mut without_tools = freeze["source_files"].clone();
        without_tools.as_object_mut().unwrap().remove("tools/dnsmasq/build_package.py");
        let mut extra = freeze["source_files"].clone();
        extra["extra"] = json!("0".repeat(64));
        let mut changed_main = freeze["source_files"].clone();
        changed_main["components/dnsmasq/src/main.rs"] = json!("0".repeat(64));
        for (field, value) in [
            ("source_commit", json!("2".repeat(40))), ("rust_elf_sha256", json!("0".repeat(64))),
            ("source_date_epoch", json!(456)), ("frozen", json!(false)), ("pending", json!(["pressure"])),
            ("source_files", without_tools), ("source_files", extra), ("source_files", changed_main),
            ("sdk_archive_sha256", json!("0".repeat(64))), ("sdk_files", json!({"rules.mk": "0".repeat(64)})),
            ("postprocess", json!({"mode": "none", "reason": "identity changed unexpectedly",
                                   "input_sha256": "0".repeat(64), "output_sha256": "f".repeat(64)})),
            ("postprocess", json!({"mode": "sdk-sstrip", "input_sha256": "0".repeat(64), "output_sha256": "1".repeat(64)})),
        ] {
            let mut changed = freeze.clone();
            changed[field] = value.clone();
            assert!(check(&changed).is_err(), "{field}={value}");
        }
    }

    #[test]
    fn oversized_experiment_keeps_artifacts_and_failure_manifest() {
        let temp = TempDir::new("oversized");
        let budget = temp.path().join("budget.json");
        fs::write(&budget, r#"{"schema": 1, "elf_max_bytes": 700000, "apk_max_bytes": 800000}"#).unwrap();
        let out = util::repo().join("private").join(format!("owrt-tools-test-{}", std::process::id()));
        let report = attempt(&out, &budget, |output, report| {
            fs::write(output.join("dnsmasq.apk"), "artifact")?;
            report["artifact"] = json!({"size": 510000});
            report["elf"] = json!({"size": 980000});
            audit_sizes(report)
        })
        .unwrap();
        let written = util::read_json(&out.join("manifest.json")).unwrap();
        let retained = out.join("dnsmasq.apk").is_file();
        fs::remove_dir_all(&out).unwrap();
        assert_eq!(report, written);
        assert_eq!(written["status"], "failed");
        assert_eq!(written["failure_boundary"], "size-target");
        assert_eq!(written["budget_checks"], json!({"apk": true, "elf": false}));
        assert!(retained);
    }

    #[test]
    fn recipe_resolves_sdk_compiler_and_shell_linker_through_buildpackage_eval() {
        let temp = TempDir::new("makefile");
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::write(root.join("rules.mk"), "").unwrap();
        fs::write(root.join("package.mk"), "define BuildPackage\ncheck:\n\t$(Build/Compile)\nendef\n").unwrap();
        let binaries = root.join("bin");
        fs::create_dir(&binaries).unwrap();
        let compiler = binaries.join("aarch64-openwrt-linux-musl-gcc");
        fs::write(&compiler, "#!/bin/sh\nexit 99\n").unwrap();
        util::set_mode(&compiler, 0o755).unwrap();
        let captured = root.join("cargo-environment");
        let cargo = binaries.join("cargo");
        fs::write(&cargo, format!("#!/bin/sh\nprintf '%s\\n%s\\n' \"$DNSMASQ_STATIC_PIE_CC\" \
                                   \"$CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER\" > '{}'\n", captured.display())).unwrap();
        util::set_mode(&cargo, 0o755).unwrap();
        let recipe = util::repo().join("packaging/openwrt/owrt-dnsmasq/Makefile");
        let mut env = util::current_env();
        env.insert("PATH".into(), format!("{}:{}", binaries.display(), env.get("PATH").cloned().unwrap_or_default()));
        let status = util::command(&strings(["make", "--no-print-directory", "-f", &util::display(&recipe),
            &format!("TOPDIR={}", root.display()), &format!("INCLUDE_DIR={}", root.display()),
            &format!("PKG_BUILD_DIR={}", root.join("build").display()), &format!("V1_CARGO={}", cargo.display()),
            "TARGET_CC_NOCACHE=aarch64-openwrt-linux-musl-gcc", "TARGET_LINKER=bfd", "check"]),
            Some(recipe.parent().unwrap()), Some(&env)).output().unwrap();
        assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
        let text = fs::read_to_string(captured).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], util::display(&compiler));
        assert_eq!(lines[1], util::display(&recipe.parent().unwrap().join("static-pie-linker.sh")));
    }

    #[test]
    fn static_pie_linker_only_rewrites_pinned_startup_inputs() {
        let helper = util::repo().join(STATIC_PIE_LINKERS[0]);
        let temp = TempDir::new("linker");
        let root = temp.path();
        let crt = root.join("rustlib/aarch64-unknown-linux-musl/lib/self-contained");
        fs::create_dir_all(&crt).unwrap();
        for name in ["crt1.o", "crtbegin.o", "crtend.o", "rcrt1.o", "crtbeginS.o", "crtendS.o"] {
            fs::write(crt.join(name), "").unwrap();
        }
        fs::write(root.join("crt1.o"), "").unwrap();
        let compiler = root.join("sdk-gcc");
        fs::write(&compiler, "#!/bin/sh\nfor arg do printf '%s\\n' \"$arg\"; done\n").unwrap();
        util::set_mode(&compiler, 0o755).unwrap();
        let object = |name: &str| util::display(&crt.join(name));
        let args = vec![object("crt1.o"), object("crtbegin.o"), "in put.o".into(), "-static".into(), "-no-pie".into(),
                        "-static-libgcc".into(), "-Wl,-z,relro".into(), object("crtend.o")];
        let invoke = |arguments: &[String], cc: &Path| {
            let mut command = vec!["sh".to_owned(), util::display(&helper)];
            command.extend(arguments.iter().cloned());
            let mut env = util::current_env();
            env.insert("DNSMASQ_STATIC_PIE_CC".into(), util::display(cc));
            util::command(&command, None, Some(&env)).output().unwrap()
        };
        let result = invoke(&args, &compiler);
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        let passed: Vec<String> = String::from_utf8(result.stdout).unwrap().lines().map(str::to_owned).collect();
        assert_eq!(passed, [object("rcrt1.o"), object("crtbeginS.o"), "in put.o".into(), "-static-pie".into(),
                            "-static-libgcc".into(), "-Wl,-z,relro".into(), object("crtendS.o")]);
        let without = |skip: &str| args.iter().filter(|arg| *arg != skip).cloned().collect::<Vec<_>>();
        let with = |extra: &str| args.iter().cloned().chain([extra.to_owned()]).collect::<Vec<_>>();
        let mut unrecognized = args.clone();
        unrecognized[0] = util::display(&root.join("crt1.o"));
        for (label, changed) in [
            ("no static", without("-static")), ("duplicate static", with("-static")), ("dynamic PIE", with("-pie")),
            ("response file", with("@hidden-arguments")), ("missing startup", args[1..].to_vec()),
            ("duplicate startup", with(&object("crt1.o"))), ("unrecognized startup source", unrecognized),
        ] {
            assert!(!invoke(&changed, &compiler).status.success(), "{label}");
        }
        assert!(!invoke(&args, &helper).status.success(), "linker must not exec itself");
        assert!(!invoke(&args, Path::new("")).status.success());
        fs::remove_file(crt.join("rcrt1.o")).unwrap();
        assert!(!invoke(&args, &compiler).status.success());
    }

    #[test]
    fn frozen_recipe_never_calls_cargo_or_restrips() {
        let temp = TempDir::new("frozen-recipe");
        let root = temp.path();
        fs::write(root.join("rules.mk"), "").unwrap();
        fs::write(root.join("package.mk"), "").unwrap();
        fs::write(root.join("frozen-dnsmasq"), "already-validated-ELF-fixture").unwrap();
        let harness = root.join("harness.mk");
        fs::write(&harness, "check:\n\t$(Build/Compile)\n\ttest '$(RSTRIP)' = ':'\n\
                             \ttest '$(DNSMASQ_INSTALL_ELF)' = '$(PKG_BUILD_DIR)/frozen-dnsmasq'\n").unwrap();
        let recipe = util::repo().join("packaging/openwrt/owrt-dnsmasq/Makefile");
        let result = util::command(&strings(["make", "--no-print-directory", "-f", &util::display(&recipe), "-f",
            &util::display(&harness), &format!("TOPDIR={}", root.display()), &format!("INCLUDE_DIR={}", root.display()),
            &format!("PKG_BUILD_DIR={}", root.display()),
            &format!("OWRT_DNSMASQ_FROZEN_ELF={}", root.join("frozen-dnsmasq").display()),
            "V1_CARGO=/must-not-call-cargo", "check"]), None, None).output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    }
}
