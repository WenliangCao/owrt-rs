//! `owrt-tools native-image fetch|prepare|verify WORK SPEC APK`: assemble
//! and audit an explicitly selected native image. Never contacts a router.
//!
//! The existing SDK builds remain the binary provenance source. One APK owns
//! the standard paths using APK's explicit file-replacement metadata;
//! official packages supply their libraries, helpers and configuration. Two
//! precisely pinned dnsmasq integration files accompany its accepted SDK
//! binary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};

use crate::util::{self, ensure, is_hex, strings, Args, JsonExt, Result};

pub const STOCK: &str = "usr/libexec/owrt-stock";
pub const METADATA: &str = "usr/share/owrt-control-plane";
const LEGACY: [&str; 8] = [
    "uci",
    "reload-config",
    "logd",
    "httpd",
    "fw4",
    "rpcd",
    "switch",
    "ubusd",
];
const NATIVE_TEN: [(&str, [&str; 3]); 10] = [
    ("fw4", ["/sbin/fw4", "fw4-rs", "firewall4"]),
    ("httpd", ["/usr/sbin/uhttpd", "httpd-rs", "uhttpd"]),
    ("logd", ["/sbin/logd", "logd-rs", "logd"]),
    ("netifd", ["/sbin/netifd", "netifd-rs", "netifd"]),
    ("procd", ["/sbin/procd", "procd-rs", "procd"]),
    (
        "reload-config",
        ["/sbin/reload_config", "reload_config_rs", "procd"],
    ),
    ("rpcd", ["/sbin/rpcd", "rpcd-rs", "rpcd"]),
    ("ubusd", ["/sbin/ubusd", "ubusd-rs", "ubusd"]),
    ("uci", ["/sbin/uci", "uci-rs", "uci"]),
    ("dnsmasq", ["/usr/sbin/dnsmasq", "dnsmasq-rs", "dnsmasq"]),
];
const ODHCPD: (&str, [&str; 3]) = (
    "odhcpd",
    ["/usr/sbin/odhcpd", "odhcpd-rs", "odhcpd-ipv6only"],
);
pub const RPCD_COMPAT_PATH: &str = "/usr/share/rpcd/acl.d/owrt-rpcd-compat.json";
pub const RPCD_COMPAT_SHA256: &str =
    "12c2d5dc439b43786bfb44455b7aebbb25c9bde76ed4f1a612e1e9ce0c03c514";
const RPCD_COMPAT_MODE: u32 = 0o644;
const DNSMASQ_STOCK_DEFAULTS: [&str; 8] = [
    "etc/config/dhcp",
    "etc/dnsmasq.conf",
    "etc/hotplug.d/ntp/25-dnsmasqsec",
    "etc/uci-defaults/50-dnsmasq-migrate-ipset.sh",
    "etc/uci-defaults/50-dnsmasq-migrate-resolv-conf-auto.sh",
    "usr/lib/dnsmasq/dhcp-script.sh",
    "usr/share/dnsmasq/dhcpbogushostname.conf",
    "usr/share/dnsmasq/rfc6761.conf",
];

pub fn rpcd_compat_acl() -> Value {
    json!({"path": RPCD_COMPAT_PATH, "sha256": RPCD_COMPAT_SHA256, "mode": RPCD_COMPAT_MODE})
}

/// Only the two reviewed complete inventories are valid, not arbitrary counts.
pub fn native_layout(components: &Value) -> Result<&'static str> {
    let components = components
        .as_object()
        .ok_or_else(|| util::Error::new("components must be an object"))?;
    let names: BTreeSet<&str> = components.keys().map(String::as_str).collect();
    let ten: BTreeSet<&str> = NATIVE_TEN.iter().map(|(name, _)| *name).collect();
    let (expected, layout): (Vec<(&str, [&str; 3])>, _) = if names == ten {
        (NATIVE_TEN.to_vec(), "native-ten")
    } else {
        let eleven: Vec<_> = NATIVE_TEN.iter().copied().chain([ODHCPD]).collect();
        ensure!(
            names == eleven.iter().map(|(name, _)| *name).collect(),
            "unsupported native component inventory"
        );
        (eleven, "native-eleven")
    };
    for (name, identity) in expected {
        let item = &components[name];
        ensure!(
            ["path", "binary", "stock_package"]
                .iter()
                .zip(identity)
                .all(|(key, value)| item[*key] == value),
            "native path/binary/owner mismatch: {name}"
        );
    }
    Ok(layout)
}

fn sha(path: &Path) -> Result<String> {
    util::sha256_file(path)
}

fn run(args: &[String]) -> Result<String> {
    Ok(util::output(args, None, None)?.trim().to_owned())
}

fn arg(path: &Path) -> String {
    util::display(path)
}

fn file_mode(path: &Path) -> Result<u32> {
    Ok(fs::metadata(path)?.mode() & 0o7777)
}

fn exists_or_link(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Asks APK which package owns one path (seam for tests).
pub type Owner<'a> = dyn Fn(&Path, &str) -> Result<String> + 'a;

pub fn apk_owner(apk: &Path) -> impl Fn(&Path, &str) -> Result<String> + '_ {
    move |root, path| {
        run(&strings([
            arg(apk),
            "--root".into(),
            arg(root),
            "--no-network".into(),
            "info".into(),
            "--who-owns".into(),
            path.into(),
        ]))
    }
}

fn json_object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| util::Error::new("expected JSON object"))
}

/// Audits the FIT extracted from the final image against the pinned stock FIT.
pub fn verify_ax3000t_fit(kernel: &Path, original: &Path, metadata: &Value) -> Result<()> {
    let versions = util::read_json(&util::repo().join("packaging/image/ax3000t-fit-inputs.json"))?;
    // Historical 25.12.5 records predate the explicit version field.
    let version = metadata
        .get("openwrt")
        .and_then(Value::as_str)
        .unwrap_or("25.12.5");
    let inputs = versions
        .get(version)
        .ok_or_else(|| util::Error::new("unqualified OpenWrt version for the AX3000T FIT patch"))?;
    let mut expected = vec![
        ("change", json!("disable-absent-mt7531-and-quiet-console")),
        ("hardware_variant", json!("AN8855-only")),
        ("bootargs_append", json!(" loglevel=4")),
        ("node", json!("/soc/ethernet@15100000/mdio-bus/switch@1f")),
        ("status", json!("disabled")),
    ];
    for key in [
        "source_date_epoch",
        "kernel_payload_sha1",
        "original_dtb_sha256",
        "original_fit_sha256",
    ] {
        expected.push((key, inputs.field(key)?.clone()));
    }
    for (key, value) in expected {
        ensure!(
            metadata.get(key) == Some(&value),
            "AX3000T FIT manifest mismatch: {key}"
        );
    }
    ensure!(
        metadata["original_fit_sha256"] == sha(original)?.as_str(),
        "stock FIT identity drift"
    );
    ensure!(
        metadata["fit_sha256"] == sha(kernel)?.as_str(),
        "final image does not contain the repacked FIT"
    );
    let fdtget = |file: &Path, kind: &str, node: &str, property: &str| {
        run(&strings(["fdtget", "-t", kind, &arg(file), node, property]))
    };
    ensure!(
        fdtget(kernel, "u", "/", "timestamp")? == metadata["source_date_epoch"].to_string(),
        "FIT timestamp differs"
    );
    let temp = util::TempDir::try_new("ax3000t-fit")?;
    let files = temp.path();
    let [payload, dtb, original_dtb, original_payload, expected_dtb] = [
        "kernel.lzma",
        "final.dtb",
        "original.dtb",
        "original-kernel.lzma",
        "expected.dtb",
    ]
    .map(|name| files.join(name));
    for (part, output, input) in [
        ("0", &payload, kernel),
        ("1", &dtb, kernel),
        ("0", &original_payload, original),
        ("1", &original_dtb, original),
    ] {
        run(&strings([
            "dumpimage",
            "-T",
            "flat_dt",
            "-p",
            part,
            "-o",
            &arg(output),
            &arg(input),
        ]))?;
    }
    let payload_bytes = fs::read(&payload)?;
    ensure!(
        payload_bytes == fs::read(&original_payload)?,
        "Linux payload bytes changed in final FIT"
    );
    ensure!(
        metadata["kernel_payload_sha1"] == util::hex(&Sha1::digest(&payload_bytes)).as_str(),
        "Linux payload changed in final FIT"
    );
    ensure!(
        metadata["original_dtb_sha256"] == sha(&original_dtb)?.as_str(),
        "stock DTB identity drift"
    );
    ensure!(
        metadata["dtb_sha256"] == sha(&dtb)?.as_str(),
        "final FIT DTB identity mismatch"
    );
    fs::copy(&original_dtb, &expected_dtb)?;
    let node = metadata.str_field("node")?;
    run(&strings([
        "fdtput",
        "-t",
        "s",
        &arg(&expected_dtb),
        node,
        "status",
        "disabled",
    ]))?;
    run(&strings([
        "fdtput",
        "-t",
        "s",
        &arg(&expected_dtb),
        "/chosen",
        "bootargs-append",
        metadata.str_field("bootargs_append")?,
    ]))?;
    ensure!(
        fs::read(&dtb)? == fs::read(&expected_dtb)?,
        "unexpected DTB change in final FIT"
    );
    ensure!(
        fdtget(&dtb, "s", node, "compatible")? == "mediatek,mt7531",
        "unexpected switch node"
    );
    ensure!(
        fdtget(&dtb, "s", node, "status")? == "disabled",
        "switch node is not disabled"
    );
    ensure!(
        fdtget(&dtb, "s", "/chosen", "bootargs-append")? == "loglevel=4",
        "bootargs-append differs"
    );
    Ok(())
}

/// Installed packages of `root` by name.
pub fn packages(
    apk: &Path,
    root: &Path,
    fields: &str,
    names: &[String],
) -> Result<Map<String, Value>> {
    let mut command = strings([
        arg(apk),
        "--root".into(),
        arg(root),
        "--no-network".into(),
        "query".into(),
        "--from".into(),
        "installed".into(),
        "--format".into(),
        "json".into(),
        "--fields".into(),
        fields.into(),
    ]);
    command.extend(names.iter().cloned());
    let rows: Value = serde_json::from_str(&run(&command)?)?;
    let mut result = Map::new();
    for row in rows
        .as_array()
        .ok_or_else(|| util::Error::new("apk query did not return a list"))?
    {
        result.insert(row.str_field("name")?.to_owned(), row.clone());
    }
    Ok(result)
}

fn installed_packages(apk: &Path, root: &Path) -> Result<Map<String, Value>> {
    packages(apk, root, "name,version,license", &strings(["*"]))
}

pub fn install(source: &Path, target: &Path, mode: u32) -> Result<()> {
    fs::create_dir_all(target.parent().unwrap())?;
    fs::copy(source, target)
        .map_err(|error| util::Error::new(format!("{}: {error}", source.display())))?;
    util::set_mode(target, mode)
}

fn version_of<'a>(installed: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    installed
        .get(name)
        .ok_or_else(|| util::Error::new(format!("package not installed: {name}")))?
        .str_field("version")
}

/// Installs only the accepted init/ACL changes, preserving stock recovery.
pub fn integration_files(
    payload: &Path,
    base: &Path,
    dnsmasq: &Path,
    spec: &Value,
    owner: &Owner,
    installed: &Map<String, Value>,
) -> Result<Map<String, Value>> {
    let files = spec.obj_field("integration_files")?;
    let names: BTreeSet<&str> = files.keys().map(String::as_str).collect();
    ensure!(
        names == BTreeSet::from(["etc/init.d/dnsmasq", "usr/share/acl.d/dnsmasq_acl.json"]),
        "unexpected dnsmasq integration files"
    );
    let mut result = Map::new();
    for (path, item) in files {
        ensure!(
            item["path"] == format!("/{path}").as_str() && item["stock_package"] == "dnsmasq",
            "integration file identity differs: {path}"
        );
        let (original, candidate) = (base.join(path), dnsmasq.join(path));
        ensure!(
            item["stock_sha256"] == sha(&original)?.as_str(),
            "stock integration identity drift: {path}"
        );
        ensure!(
            item["replacement_sha256"] == sha(&candidate)?.as_str(),
            "accepted integration identity drift: {path}"
        );
        let mode = item.u64_field("mode")? as u32;
        ensure!(
            file_mode(&original)? == mode && file_mode(&candidate)? == mode,
            "integration file mode differs: {path}"
        );
        let found = owner(base, item.str_field("path")?)?;
        ensure!(
            found.ends_with(&format!(
                " is owned by dnsmasq-{}",
                version_of(installed, "dnsmasq")?
            )),
            "{found}"
        );
        install(&candidate, &payload.join(path), mode)?;
        install(&original, &payload.join(STOCK).join(path), mode)?;
        let mut record = item.clone();
        record["recovery_path"] = json!(format!("/{STOCK}/{path}"));
        result.insert(path.clone(), record);
    }
    // The SDK package is an intermediate, not an invitation to overwrite its
    // remaining defaults/helpers. They must equal the exact stock image.
    for path in DNSMASQ_STOCK_DEFAULTS {
        ensure!(
            fs::read(base.join(path))? == fs::read(dnsmasq.join(path))?,
            "{path}"
        );
    }
    Ok(result)
}

/// APK applies directory modes too. Match the original image instead of
/// letting the builder's umask silently change shared /usr or /etc paths.
pub fn preserve_directory_modes(payload: &Path, base: &Path) -> Result<()> {
    let mut paths = vec![payload.to_path_buf()];
    paths.extend(util::walk_sorted(payload)?);
    for path in paths {
        let reference = base.join(path.strip_prefix(payload).unwrap());
        if fs::symlink_metadata(&path)?.is_dir() && reference.is_dir() {
            util::set_mode(&path, file_mode(&reference)?)?;
        }
    }
    Ok(())
}

/// Adds the upstream resolved-mount ACL without replacing a stock file.
pub fn install_rpcd_compat_acl(repo: &Path, payload: &Path, base: &Path) -> Result<Value> {
    let path = RPCD_COMPAT_PATH.trim_start_matches('/');
    ensure!(
        !exists_or_link(&base.join(path)),
        "rpcd compatibility ACL collides with stock"
    );
    let source = repo.join("packaging/openwrt/owrt-rpcd/files/owrt-rpcd-compat.json");
    ensure!(
        source.is_file() && sha(&source)? == RPCD_COMPAT_SHA256,
        "rpcd compatibility ACL source drift"
    );
    install(&source, &payload.join(path), RPCD_COMPAT_MODE)?;
    Ok(rpcd_compat_acl())
}

pub fn verify_rpcd_compat_acl(
    root: &Path,
    before: &Path,
    manifest: &Value,
    spec: &Value,
    owner: &Owner,
) -> Result<()> {
    ensure!(
        manifest.get("rpcd_compat_acl") == Some(&rpcd_compat_acl()),
        "rpcd compatibility ACL metadata drift"
    );
    let path = RPCD_COMPAT_PATH.trim_start_matches('/');
    let (original, candidate) = (before.join(path), root.join(path));
    ensure!(
        !exists_or_link(&original),
        "rpcd compatibility ACL collides with stock"
    );
    ensure!(
        candidate.is_file() && !util::is_symlink(&candidate),
        "rpcd compatibility ACL must be a regular file"
    );
    ensure!(
        sha(&candidate)? == RPCD_COMPAT_SHA256,
        "rpcd compatibility ACL content drift"
    );
    ensure!(
        file_mode(&candidate)? == RPCD_COMPAT_MODE,
        "rpcd compatibility ACL mode drift"
    );
    let found = owner(root, RPCD_COMPAT_PATH)?;
    ensure!(
        found.ends_with(&format!(
            " is owned by {}-{}",
            spec.str_field("package")?,
            spec.str_field("version")?
        )),
        "{found}"
    );
    Ok(())
}

pub fn fetch(work: &Path, spec: &Value) -> Result<()> {
    native_layout(spec.field("components")?)?;
    let native = work.join("native");
    fs::create_dir(&native)?;
    let luci = format!("luci-{}.tar.gz", spec["luci_source"].str_field("revision")?);
    for (key, filename) in [
        (
            "stock_image",
            spec["stock_image"].str_field("file")?.to_owned(),
        ),
        ("luci_source", luci.clone()),
    ] {
        let source = spec.field(key)?;
        let target = work.join("dl").join(&filename);
        if !target.exists() {
            let partial = target.with_extension("part");
            util::run_checked(
                &strings([
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--location",
                    "--connect-timeout",
                    "90",
                    "--output",
                    &arg(&partial),
                    source.str_field("url")?,
                ]),
                None,
                None,
            )?;
            fs::rename(&partial, &target)?;
        }
        ensure!(
            source["sha256"] == sha(&target)?.as_str(),
            "immutable input mismatch: {key}"
        );
    }
    util::run_checked(
        &strings([
            "tar",
            "-xf",
            &arg(&work.join("dl").join(luci)),
            "-C",
            &arg(&native),
        ]),
        None,
        None,
    )
}

fn release_version(version: &str) -> Vec<u64> {
    version
        .split('-')
        .next()
        .unwrap_or_default()
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

/// Rebuilds of the other programs must equal their accepted ELFs.
pub fn verify_component_references(hashes: &Map<String, Value>, spec: &Value) -> Result<()> {
    let components: Vec<(&String, &Value)> = spec
        .obj_field("components")?
        .iter()
        .filter(|(name, _)| *name != "dnsmasq")
        .collect();
    // Historic native recipes did not carry separate accepted references.
    // v0.2.2 and later must bind every component; a partial map is never valid.
    let has_references = components
        .iter()
        .any(|(_, item)| item.get("reference_elf_sha256").is_some());
    if release_version(spec.str_field("version")?) < vec![0, 2, 2] && !has_references {
        return Ok(());
    }
    for (name, item) in components {
        let expected = item.get("reference_elf_sha256").and_then(Value::as_str);
        ensure!(
            expected.is_some_and(|value| is_hex(value, 64)),
            "missing accepted ELF identity: {name}"
        );
        ensure!(
            hashes.get(item.str_field("binary")?) == Some(&json!(expected)),
            "accepted ELF identity drift: {name}"
        );
    }
    Ok(())
}

/// Only an exact accepted use ELF may enter the native release payload.
pub fn verify_dnsmasq_reference(report: &Value, spec: &Value) -> Result<()> {
    ensure!(
        report["status"] == "built-and-audited",
        "dnsmasq build was not audited"
    );
    ensure!(
        report["source_digest"] == spec["source_digest"],
        "dnsmasq source digest differs"
    );
    ensure!(
        report["accepted_product_commit"] == spec["source_commit"],
        "dnsmasq product commit differs"
    );
    let elf = &report["elf"];
    ensure!(
        elf["matches_accepted_reference"] == true,
        "unqualified dnsmasq ELF"
    );
    ensure!(
        elf["reference_sha256"] == elf["sha256"] && elf["sha256"] == spec["reference_elf_sha256"],
        "dnsmasq reference hash differs"
    );
    ensure!(
        elf["size"] == spec["reference_elf_bytes"],
        "dnsmasq reference size differs"
    );
    ensure!(
        report.get("release_qualified") != Some(&json!(false)),
        "diagnostic candidate is not an accepted release"
    );
    if let Some(epoch) = spec.get("source_date_epoch") {
        ensure!(
            package_str(&report["source_date_epoch"]) == package_str(epoch),
            "dnsmasq product epoch differs"
        );
    }
    if let Some(frozen) = spec.get("pgo") {
        let pgo = &report["pgo"];
        ensure!(
            pgo["mode"] == "use"
                && pgo["profile_diagnostics"]
                    .as_array()
                    .is_some_and(Vec::is_empty),
            "invalid release PGO mode/diagnostics"
        );
        for key in [
            "profile_url",
            "profile_sha256",
            "profile_bytes",
            "build_slot",
            "training",
        ] {
            if let Some(value) = frozen.get(key) {
                ensure!(
                    pgo.get(key) == Some(value),
                    "dnsmasq PGO identity differs: {key}"
                );
            }
        }
    }
    Ok(())
}

/// Python `str()` of a JSON scalar.
fn package_str(value: &Value) -> String {
    crate::dnsmasq_package::python_str(value)
}

fn set_times(path: &Path, epoch: i64) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| util::Error::new("NUL in path"))?;
    let time = libc::timespec {
        tv_sec: epoch as libc::time_t,
        tv_nsec: 0,
    };
    // SAFETY: `name` is a valid NUL-terminated path and `times` two timespecs.
    let result =
        unsafe { libc::utimensat(libc::AT_FDCWD, name.as_ptr(), [time, time].as_ptr(), 0) };
    ensure!(
        result == 0,
        "utime {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn stamp_tree(root: &Path, epoch: i64) -> Result<()> {
    for path in util::walk_sorted(root)?.iter().chain([&root.to_path_buf()]) {
        set_times(path, epoch)?;
    }
    Ok(())
}

fn chown_root(path: &Path) -> Result<()> {
    util::run_checked(
        &strings(["sudo", "-n", "chown", "-R", "0:0", &arg(path)]),
        None,
        None,
    )
}

/// `"/relative"` names of every file below `root`, string-sorted.
fn file_listing(root: &Path) -> Result<String> {
    let mut names: Vec<String> = util::walk_sorted(root)?
        .into_iter()
        .filter(|path| path.is_file())
        .map(|path| format!("/{}", path.strip_prefix(root).unwrap().display()))
        .collect();
    names.sort();
    Ok(names.join("\n") + "\n")
}

fn merge(maps: &[&Value]) -> Result<Map<String, Value>> {
    let mut result = Map::new();
    for map in maps {
        result.extend(json_object(map)?.clone());
    }
    Ok(result)
}

pub fn prepare(work: &Path, spec: &Value, apk: &Path) -> Result<()> {
    ensure!(
        util::euid() == 0,
        "native image prepare requires root to verify protected stock configuration"
    );
    let repo = util::repo();
    let layout = native_layout(spec.field("components")?)?;
    let out = work.join("out");
    let root = work.join("native/base-rootfs");
    let binary_root = work.join("verify/rootfs");
    let image = util::read_json(&out.join("manifest.json"))?;
    let core = util::read_json(&out.join("core-manifest.json"))?;
    let dnsmasq = util::read_json(&out.join("dnsmasq/manifest.json"))?;
    ensure!(
        image["source_commit"] == core["source_commit"]
            && core["source_commit"] == dnsmasq["source_commit"],
        "source commits differ"
    );
    verify_dnsmasq_reference(&dnsmasq, spec.field("dnsmasq_build")?)?;
    ensure!(
        image["openwrt"] == core["openwrt"] && core["openwrt"] == spec["openwrt"],
        "OpenWrt versions differ"
    );
    ensure!(
        core["image_manifest_sha256"] == sha(&out.join("manifest.json"))?.as_str(),
        "core manifest names another image"
    );
    let hashes = merge(&[
        &image["binary_sha256"],
        &core["binary_sha256"],
        &dnsmasq["binary_sha256"],
    ])?;
    let components_spec = spec.obj_field("components")?;
    let binaries: BTreeSet<&str> = components_spec
        .values()
        .filter_map(|c| c["binary"].as_str())
        .collect();
    ensure!(
        hashes.keys().map(String::as_str).collect::<BTreeSet<_>>() == binaries,
        "binary inventory differs"
    );
    verify_component_references(&hashes, spec)?;
    let installed = installed_packages(apk, &root)?;
    let owners: BTreeSet<String> = components_spec
        .values()
        .filter_map(|c| c["stock_package"].as_str().map(str::to_owned))
        .collect();
    let owner = apk_owner(apk);
    let payload = work.join("native/payload");
    fs::create_dir_all(payload.parent().unwrap())?;
    fs::create_dir(&payload)?;
    let mut components = Map::new();
    let (mut rust_sums, mut stock_sums) = (String::new(), String::new());
    for (name, c) in components_spec {
        let path = c.str_field("path")?.trim_start_matches('/');
        let original = root.join(path);
        ensure!(
            c["stock_sha256"] == sha(&original)?.as_str(),
            "stock identity drift: {path}"
        );
        let package = c.str_field("stock_package")?;
        let found = owner(&root, c.str_field("path")?)?;
        ensure!(
            found.ends_with(&format!(
                " is owned by {package}-{}",
                version_of(&installed, package)?
            )),
            "{found}"
        );
        let binary = match name.as_str() {
            "dnsmasq" => out.join("dnsmasq/payload/usr/sbin/dnsmasq"),
            "procd" | "ubusd" | "netifd" | "odhcpd" => {
                out.join("core-binaries").join(c.str_field("binary")?)
            }
            _ => binary_root.join("usr/sbin").join(c.str_field("binary")?),
        };
        let binary_sha = sha(&binary)?;
        ensure!(
            hashes.get(c.str_field("binary")?) == Some(&json!(binary_sha)),
            "Rust identity drift: {name}"
        );
        install(&binary, &payload.join(path), 0o755)?;
        install(&original, &payload.join(STOCK).join(path), 0o755)?;
        let mut record = c.clone();
        record["rust_sha256"] = json!(binary_sha);
        record["rust_bytes"] = json!(fs::metadata(&binary)?.len());
        record["recovery_path"] = json!(format!("/{STOCK}/{path}"));
        components.insert(name.clone(), record);
        rust_sums += &format!("{binary_sha}  /{path}\n");
        stock_sums += &format!("{}  /{STOCK}/{path}\n", sha(&original)?);
    }
    let integration = integration_files(
        &payload,
        &root,
        &out.join("dnsmasq/payload"),
        spec,
        &owner,
        &installed,
    )?;
    for (path, item) in &integration {
        rust_sums += &format!("{}  /{path}\n", item.str_field("replacement_sha256")?);
        stock_sums += &format!(
            "{}  {}\n",
            item.str_field("stock_sha256")?,
            item.str_field("recovery_path")?
        );
    }
    let rpcd_compat = install_rpcd_compat_acl(&repo, &payload, &root)?;
    rust_sums += &format!("{RPCD_COMPAT_SHA256}  {RPCD_COMPAT_PATH}\n");
    let stock_packages: Map<String, Value> = owners
        .iter()
        .map(|name| (name.clone(), installed[name].clone()))
        .collect();
    let count = components.len();
    let manifest = json!({
        "schema": 2, "layout": layout, "source_commit": image["source_commit"],
        "openwrt": spec["openwrt"], "profile": spec["profile"],
        "package": spec["package"], "version": spec["version"],
        "components": components, "integration_files": integration, "rpcd_compat_acl": rpcd_compat,
        "stock_manifest_sha256": util::sha256_bytes(stock_sums.as_bytes()),
        "stock_image": spec["stock_image"], "luci_source": spec["luci_source"], "translations": spec["translations"],
        "stock_packages": stock_packages,
        "recovery": format!("owrt-recover-c stages all {count} stock programs and exact dnsmasq init/ACL; reboot separately"),
    });
    util::write_json(&payload.join(METADATA).join("release.json"), &manifest)?;
    fs::write(payload.join(METADATA).join("rust.sha256"), &rust_sums)?;
    fs::write(payload.join(METADATA).join("stock.sha256"), &stock_sums)?;
    let image_files = repo.join("packaging/image");
    install(
        &image_files.join("owrt-recover-c"),
        &payload.join("usr/sbin/owrt-recover-c"),
        0o755,
    )?;
    install(
        &image_files.join("05-owrt-native"),
        &payload.join("etc/uci-defaults/05-owrt-native"),
        0o755,
    )?;
    install(
        &image_files.join("06-owrt-log-settings"),
        &payload.join("etc/uci-defaults/06-owrt-log-settings"),
        0o755,
    )?;
    install(
        &image_files.join("owrt-log-settings.keep"),
        &payload.join("lib/upgrade/keep.d/owrt-log-settings"),
        0o644,
    )?;
    fs::write(
        payload.join("lib/upgrade/keep.d/owrt-control-plane"),
        "/etc/owrt-control-plane-layout\n",
    )?;
    // OpenWrt's conffile tooling also expects its package file list.
    let package_name = spec.str_field("package")?;
    let listing = payload
        .join("lib/apk/packages")
        .join(format!("{package_name}.list"));
    let text = file_listing(&payload)?;
    fs::create_dir_all(listing.parent().unwrap())?;
    fs::write(&listing, text)?;
    preserve_directory_modes(&payload, &root)?;
    // prepare runs as root while Actions' checkout belongs to the runner.
    // Trust only this invocation's repository, never a global wildcard.
    let epoch: i64 = run(&strings([
        "git",
        "-c",
        &format!("safe.directory={}", repo.display()),
        "-C",
        &arg(&repo),
        "show",
        "-s",
        "--format=%ct",
        image.str_field("source_commit")?,
    ]))?
    .parse()?;
    stamp_tree(&payload, epoch)?;
    // Explicit root ownership; the payload is disposable and contains no
    // machine configuration. Do not rely on the builder's uid leaking into APK.
    chown_root(&payload)?;
    let version = spec.str_field("version")?;
    let package = work
        .join("native")
        .join(format!("{package_name}-{version}.apk"));
    let mut dependencies: Vec<String> = owners
        .iter()
        .map(|name| format!("{name}={}", version_of(&installed, name).unwrap_or("")))
        .collect();
    let mut legacy: Vec<String> = LEGACY.iter().map(|name| format!("owrt-{name}")).collect();
    legacy.sort();
    dependencies.extend(legacy.into_iter().map(|name| format!("!{name}")));
    let licenses: BTreeSet<&str> = owners
        .iter()
        .filter_map(|name| installed[name]["license"].as_str())
        .collect();
    let mut license = vec!["(MIT OR Apache-2.0)"];
    license.extend(licenses);
    let info = json!({"name": package_name, "version": version, "arch": spec["architecture"],
                      "description": format!("{count} native Rust OpenWrt control-plane components"),
                      "license": license.join(" AND "), "origin": "owrt-control-plane-rs",
                      "url": "https://github.com/WenliangCao/owrt-control-plane-rs",
                      "depends": dependencies.join(" "), "replaces": owners.iter().cloned().collect::<Vec<_>>().join(" "),
                      "replaces-priority": "100"});
    let mut command = strings([
        arg(apk),
        "mkpkg".into(),
        "--files".into(),
        arg(&payload),
        "--output".into(),
        arg(&package),
    ]);
    for (key, value) in json_object(&info)? {
        command.extend([
            "--info".into(),
            format!("{key}:{}", value.as_str().unwrap_or_default()),
        ]);
    }
    util::run_checked(&command, None, None)?;
    // Match the four Chinese catalogs already in production, from the exact
    // LuCI source revision. Rolling feeds would silently upgrade unrelated code.
    let luci_source = spec.field("luci_source")?;
    let luci = work
        .join("native")
        .join(format!("luci-{}", luci_source.str_field("revision")?));
    let compiler = luci.join("modules/luci-base/src/po2lmo");
    util::run_checked(
        &strings(["make", "-C", &arg(compiler.parent().unwrap()), "po2lmo"]),
        None,
        None,
    )?;
    for (name, translation) in spec.obj_field("translations")? {
        let package_name = format!("luci-i18n-{name}-zh-cn");
        let files = work.join("native/translations").join(&package_name);
        let catalog = files
            .join("usr/lib/lua/luci/i18n")
            .join(format!("{name}.zh-cn.lmo"));
        fs::create_dir_all(catalog.parent().unwrap())?;
        let po = luci
            .join(translation.str_field("source")?)
            .join("po/zh_Hans")
            .join(format!("{name}.po"));
        run(&[arg(&compiler), arg(&po), arg(&catalog)])?;
        ensure!(
            translation["sha256"] == sha(&catalog)?.as_str(),
            "production translation drift: {name}"
        );
        let defaults = files.join("etc/uci-defaults").join(&package_name);
        fs::create_dir_all(defaults.parent().unwrap())?;
        fs::write(
            &defaults,
            "uci set luci.languages.zh_cn='简体中文 (Simplified Chinese)'; uci commit luci\n",
        )?;
        let listing = files
            .join("lib/apk/packages")
            .join(format!("{package_name}.list"));
        fs::create_dir_all(listing.parent().unwrap())?;
        fs::write(
            &listing,
            format!(
                "/{}\n/{}\n",
                defaults.strip_prefix(&files).unwrap().display(),
                catalog.strip_prefix(&files).unwrap().display()
            ),
        )?;
        preserve_directory_modes(&files, &root)?;
        stamp_tree(&files, epoch)?;
        chown_root(&files)?;
        let luci_version = luci_source.str_field("version")?;
        let owner_package = translation.str_field("package")?;
        run(&[
            arg(apk),
            "mkpkg".into(),
            "--files".into(),
            arg(&files),
            "--output".into(),
            arg(&work
                .join("native")
                .join(format!("{package_name}-{luci_version}.apk"))),
            "--info".into(),
            format!("name:{package_name}"),
            "--info".into(),
            format!("version:{luci_version}"),
            "--info".into(),
            "arch:noarch".into(),
            "--info".into(),
            format!("license:{}", translation.str_field("license")?),
            "--info".into(),
            format!("description:Chinese translation for {owner_package}"),
            "--info".into(),
            format!(
                "depends:libc {owner_package}={}",
                version_of(&installed, owner_package)?
            ),
        ])?;
    }
    util::write_json(
        &work.join("native/build-inputs.json"),
        &json!({"image": image, "core": core, "dnsmasq": dnsmasq,
                                                                      "package_metadata": info, "package_sha256": sha(&package)?}),
    )?;
    println!(
        "Prepared {}: {count} native paths, paired dnsmasq init/ACL, {} stock recovery files",
        package.file_name().unwrap().to_string_lossy(),
        count + integration.len()
    );
    Ok(())
}

/// Sorted entries of `directory` whose names satisfy `matches`.
fn entries(directory: &Path, matches: impl Fn(&str) -> bool) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    if let Ok(read) = fs::read_dir(directory) {
        for entry in read {
            let entry = entry?;
            if matches(&entry.file_name().to_string_lossy()) {
                found.push(entry.path());
            }
        }
    }
    found.sort();
    Ok(found)
}

/// `S[0-9][0-9]<service>` start link present.
fn has_start_link(rc: &Path, service: &str) -> Result<bool> {
    Ok(!entries(rc, |name| {
        let bytes = name.as_bytes();
        bytes.len() == 3 + service.len()
            && bytes[0] == b'S'
            && bytes[1].is_ascii_digit()
            && bytes[2].is_ascii_digit()
            && &name[3..] == service
    })?
    .is_empty())
}

fn identity_file(path: &Path) -> Result<Value> {
    Ok(
        json!({"file": path.file_name().unwrap().to_string_lossy(), "size": fs::metadata(path)?.len(), "sha256": sha(path)?}),
    )
}

pub fn verify(work: &Path, spec: &Value, apk: &Path) -> Result<()> {
    let root = work.join("native/rootfs");
    let before = work.join("native/base-rootfs");
    let inputs = util::read_json(&work.join("native/build-inputs.json"))?;
    let kernel = work.join("native/unpacked/sysupgrade-xiaomi_mi-router-ax3000t/kernel");
    verify_ax3000t_fit(
        &kernel,
        &work.join("native/base-image/sysupgrade-xiaomi_mi-router-ax3000t/kernel"),
        &inputs["image"]["ax3000t_fit"],
    )?;
    let manifest = util::read_json(
        &work
            .join("native/payload")
            .join(METADATA)
            .join("release.json"),
    )?;
    ensure!(
        util::read_json(&root.join(METADATA).join("release.json"))? == manifest,
        "installed release metadata differs"
    );
    let layout = native_layout(&manifest["components"])?;
    ensure!(
        manifest["layout"] == layout && layout == native_layout(spec.field("components")?)?,
        "native layout differs"
    );
    ensure!(
        manifest["stock_manifest_sha256"]
            == sha(&root.join(METADATA).join("stock.sha256"))?.as_str(),
        "stock manifest differs"
    );
    let (installed, previous) = (
        installed_packages(apk, &root)?,
        installed_packages(apk, &before)?,
    );
    let translations: BTreeSet<String> = spec
        .obj_field("translations")?
        .keys()
        .map(|name| format!("luci-i18n-{name}-zh-cn"))
        .collect();
    let package = spec.str_field("package")?;
    let mut expected: BTreeSet<String> = previous.keys().cloned().collect();
    expected.insert(package.to_owned());
    expected.extend(translations.iter().cloned());
    ensure!(
        installed.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "installed package set differs"
    );
    for (name, record) in &previous {
        ensure!(
            installed.get(name) == Some(record),
            "execution-plane package drift: {name}"
        );
    }
    let luci_version = &spec["luci_source"]["version"];
    for (name, translation) in spec.obj_field("translations")? {
        ensure!(
            translation["sha256"]
                == sha(&root
                    .join("usr/lib/lua/luci/i18n")
                    .join(format!("{name}.zh-cn.lmo")))?
                .as_str(),
            "translation catalog differs: {name}"
        );
        ensure!(
            installed[&format!("luci-i18n-{name}-zh-cn")]["version"] == *luci_version,
            "translation version differs: {name}"
        );
    }
    let owner = apk_owner(apk);
    let owned_by = format!(" is owned by {package}-{}", spec.str_field("version")?);
    for c in json_object(&manifest["components"])?.values() {
        ensure!(
            c["rust_sha256"]
                == sha(&root.join(c.str_field("path")?.trim_start_matches('/')))?.as_str(),
            "native file differs"
        );
        ensure!(
            c["stock_sha256"]
                == sha(&root.join(c.str_field("recovery_path")?.trim_start_matches('/')))?.as_str(),
            "recovery file differs"
        );
        let found = owner(&root, c.str_field("path")?)?;
        ensure!(found.ends_with(&owned_by), "{found}");
        ensure!(
            !root.join("usr/sbin").join(c.str_field("binary")?).exists(),
            "staging binary left in rootfs"
        );
    }
    for (path, item) in json_object(&manifest["integration_files"])? {
        ensure!(
            item["replacement_sha256"] == sha(&root.join(path))?.as_str(),
            "integration file differs: {path}"
        );
        ensure!(
            item["stock_sha256"]
                == sha(&root.join(item.str_field("recovery_path")?.trim_start_matches('/')))?
                    .as_str(),
            "integration recovery differs: {path}"
        );
        ensure!(
            u64::from(file_mode(&root.join(path))?) == item.u64_field("mode")?,
            "integration mode differs: {path}"
        );
        let found = owner(&root, item.str_field("path")?)?;
        ensure!(found.ends_with(&owned_by), "{found}");
    }
    verify_rpcd_compat_acl(&root, &before, &manifest, spec, &owner)?;
    ensure!(
        entries(&root.join("etc"), |n| n.starts_with("owrt-")
            && n.ends_with(".boot-enable"))?
        .is_empty(),
        "legacy boot-enable marker"
    );
    ensure!(
        entries(&root.join("etc/init.d"), |n| n.starts_with("owrt-"))?.is_empty(),
        "legacy owrt init script"
    );
    ensure!(
        entries(&root.join("etc/rc.d"), |n| n.contains("owrt-"))?.is_empty(),
        "legacy owrt rc link"
    );
    ensure!(
        fs::read_dir(root.join("root"))?.next().is_none(),
        "/root is not empty"
    );
    let rc = root.join("etc/rc.d");
    for service in ["log", "rpcd", "uhttpd", "network"] {
        ensure!(
            fs::read(root.join("etc/init.d").join(service))?
                == fs::read(before.join("etc/init.d").join(service))?,
            "init script differs: {service}"
        );
        ensure!(has_start_link(&rc, service)?, "{service}");
    }
    if manifest["components"].get("odhcpd").is_some() {
        for path in [
            "etc/init.d/odhcpd",
            "usr/sbin/odhcpd-update",
            "etc/uci-defaults/15_odhcpd",
        ] {
            ensure!(
                fs::read(root.join(path))? == fs::read(before.join(path))?,
                "{path}"
            );
        }
        ensure!(has_start_link(&rc, "odhcpd")?, "odhcpd");
    }
    ensure!(has_start_link(&rc, "dnsmasq")?, "dnsmasq");
    for name in ["shadow", "passwd"] {
        ensure!(
            fs::read(root.join("etc").join(name))? == fs::read(before.join("etc").join(name))?,
            "{name}"
        );
    }
    for path in entries(&before.join("etc/config"), |_| true)? {
        let name = path.file_name().unwrap();
        ensure!(
            fs::read(&path)? == fs::read(root.join("etc/config").join(name))?,
            "{}",
            name.to_string_lossy()
        );
    }
    // Compare the entire original filesystem, not another image assembled from
    // today's feed. Package versions alone do not prove unchanged content.
    let mut replaced: BTreeSet<String> = json_object(&manifest["components"])?
        .values()
        .filter_map(|c| {
            c["path"]
                .as_str()
                .map(|path| path.trim_start_matches('/').to_owned())
        })
        .collect();
    replaced.extend(json_object(&manifest["integration_files"])?.keys().cloned());
    let mut checked = 0;
    for source in util::walk_sorted(&before)? {
        let relative = util::display(source.strip_prefix(&before).unwrap());
        if replaced.contains(&relative)
            || relative == "etc/apk/world"
            || relative.starts_with("lib/apk/db/")
        {
            continue;
        }
        let target = root.join(&relative);
        let (src, dst) = (
            fs::symlink_metadata(&source)?,
            fs::symlink_metadata(&target)
                .map_err(|error| util::Error::new(format!("{relative}: {error}")))?,
        );
        ensure!(
            dst.mode() == src.mode() && (dst.uid(), dst.gid()) == (src.uid(), src.gid()),
            "{relative}"
        );
        if src.file_type().is_symlink() {
            ensure!(
                dst.file_type().is_symlink() && fs::read_link(&source)? == fs::read_link(&target)?,
                "{relative}"
            );
        } else if source.is_file() {
            ensure!(
                target.is_file() && sha(&source)? == sha(&target)?,
                "{relative}"
            );
            checked += 1;
        }
    }
    // Keep raw intermediate artifacts outside the final release directory.
    let output = work.join("native/out");
    fs::create_dir(&output)?;
    let image = entries(&work.join("native/bin"), |n| n.ends_with("-sysupgrade.bin"))?
        .into_iter()
        .next()
        .ok_or_else(|| util::Error::new("no sysupgrade image"))?;
    let apks = entries(&work.join("native"), |n| n.ends_with(".apk"))?;
    for source in std::iter::once(&image).chain(&apks) {
        util::copy2(source, &output.join(source.file_name().unwrap()))?;
    }
    let hashes: BTreeMap<String, Value> = json_object(&manifest["components"])?
        .values()
        .map(|c| {
            (
                c["binary"].as_str().unwrap_or_default().to_owned(),
                c["rust_sha256"].clone(),
            )
        })
        .collect();
    let mut packages_out = Map::new();
    let mut names: Vec<&String> = translations.iter().collect();
    let package_owned = package.to_owned();
    names.push(&package_owned);
    names.sort();
    for name in names {
        packages_out.insert(name.clone(), installed[name]["version"].clone());
    }
    let word = layout.trim_start_matches("native-");
    let mut apk_sha = Map::new();
    for path in &apks {
        apk_sha.insert(
            path.file_name().unwrap().to_string_lossy().into_owned(),
            json!(sha(path)?),
        );
    }
    let mut validation = Map::new();
    for (key, value) in [
        (format!("{word}_native_paths"), json!(true)),
        ("package_ownership".into(), json!(true)),
        ("stock_recovery_hashes".into(), json!(true)),
        (
            "stock_service_scripts_except_qualified_dnsmasq".into(),
            json!(true),
        ),
        ("qualified_dnsmasq_init_and_acl".into(), json!(true)),
        ("dnsmasq_source_recipe_identical".into(), json!(true)),
        ("rpcd_compatibility_acl_verified".into(), json!(true)),
        (
            "dnsmasq_reference_elf_identical".into(),
            inputs["dnsmasq"]["elf"]["matches_accepted_reference"].clone(),
        ),
        ("stock_config_defaults".into(), json!(true)),
        ("unchanged_execution_files".into(), json!(checked)),
        (
            "stock_package_versions_unchanged".into(),
            json!(previous.len()),
        ),
        (
            "production_Chinese_catalogs_identical".into(),
            json!(translations.len()),
        ),
        ("an8855_fit_verified".into(), json!(true)),
        ("kernel_payload_identical".into(), json!(true)),
        ("physical_boot_tested".into(), json!(false)),
    ] {
        validation.insert(key, value);
    }
    let mut result = json_object(&inputs["image"])?.clone();
    for (key, value) in [
        ("schema_version", json!(3)),
        ("deployment_layout", json!(layout)),
        ("packages", Value::Object(packages_out)),
        ("components", manifest["components"].clone()),
        ("integration_files", manifest["integration_files"].clone()),
        (
            "stock_manifest_sha256",
            manifest["stock_manifest_sha256"].clone(),
        ),
        ("rpcd_compat_acl", manifest["rpcd_compat_acl"].clone()),
        ("binary_sha256", json!(hashes)),
        ("stock_packages", manifest["stock_packages"].clone()),
        ("image", identity_file(&image)?),
        ("apk_sha256", Value::Object(apk_sha)),
        ("stock_image", spec["stock_image"].clone()),
        ("luci_source", spec["luci_source"].clone()),
        ("translations", spec["translations"].clone()),
        ("kernel_sha256", json!(sha(&kernel)?)),
        (
            "imagebuilder_args",
            json!({"assembly": "verified stock rootfs + offline APK install + official image tools",
                                     "rolling_feeds_used_for_final_rootfs": false}),
        ),
        ("validation", Value::Object(validation)),
        ("recovery", manifest["recovery"].clone()),
        ("flashed", json!(false)),
    ] {
        result.insert(key.into(), value);
    }
    let result = Value::Object(result);
    util::write_json(&output.join("manifest.json"), &result)?;
    util::write_json(&output.join("build-inputs.json"), &inputs)?;
    fs::write(
        output.join("binary-sha256.txt"),
        hashes
            .iter()
            .map(|(name, hash)| format!("{}  {name}\n", hash.as_str().unwrap_or_default()))
            .collect::<String>(),
    )?;
    let logs = |directory: &Path| entries(directory, |n| n.ends_with(".log"));
    for source in logs(&work.join("out"))? {
        util::copy2(&source, &output.join(source.file_name().unwrap()))?;
    }
    util::copy2(
        &work.join("out/dnsmasq/manifest.json"),
        &output.join("dnsmasq-build-manifest.json"),
    )?;
    for source in logs(&work.join("out/dnsmasq"))? {
        util::copy2(
            &source,
            &output.join(format!(
                "dnsmasq-{}",
                source.file_name().unwrap().to_string_lossy()
            )),
        )?;
    }
    for source in logs(&work.join("native"))? {
        util::copy2(&source, &output.join(source.file_name().unwrap()))?;
    }
    let mut sums = String::new();
    for path in entries(&output, |_| true)?
        .into_iter()
        .filter(|path| path.is_file())
    {
        sums += &format!(
            "{}  {}\n",
            sha(&path)?,
            path.file_name().unwrap().to_string_lossy()
        );
    }
    fs::write(output.join("SHA256SUMS"), sums)?;
    println!("{}", util::pretty_json(&result["validation"]));
    Ok(())
}

pub fn main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &[], &[])?;
    let [action, work, spec, apk] = args
        .exact(&["ACTION", "WORK", "SPEC", "APK"])?
        .try_into()
        .expect("four positionals");
    let work = std::path::absolute(&work)?;
    let spec = util::read_json(Path::new(&spec))?;
    let apk = std::path::absolute(&apk)?;
    match action.as_str() {
        "fetch" => fetch(&work, &spec)?,
        "prepare" => prepare(&work, &spec, &apk)?,
        "verify" => verify(&work, &spec, &apk)?,
        other => util::bail!("action must be fetch, prepare or verify, not {other:?}"),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsmasq_ci;
    use crate::dnsmasq_package as package;
    use crate::native_check;
    use crate::util::TempDir;

    fn spec_file(name: &str) -> Value {
        util::read_json(&util::repo().join(name)).unwrap()
    }

    fn next_spec() -> Value {
        spec_file("packaging/image/native-25.12.5.json")
    }

    /// Historical ten-component recovery using the same accepted inputs.
    fn spec() -> Value {
        let mut spec = next_spec();
        spec["version"] = json!("0.2.3-r1");
        spec["components"]
            .as_object_mut()
            .unwrap()
            .shift_remove("odhcpd");
        spec
    }

    fn files() -> PathBuf {
        util::repo().join("packaging/openwrt/owrt-dnsmasq/files")
    }

    fn fixed_owner(answer: String) -> impl Fn(&Path, &str) -> Result<String> {
        move |_, _| Ok(answer.clone())
    }

    fn rpcd_fixture(root: &Path) -> (PathBuf, PathBuf, Value) {
        let (base, payload) = (root.join("base"), root.join("payload"));
        fs::create_dir(&base).unwrap();
        fs::create_dir(&payload).unwrap();
        let descriptor = install_rpcd_compat_acl(&util::repo(), &payload, &base).unwrap();
        (base, payload, json!({"rpcd_compat_acl": descriptor}))
    }

    fn rpcd_verify(
        base: &Path,
        payload: &Path,
        manifest: &Value,
        owner: Option<&str>,
    ) -> Result<()> {
        let spec = spec();
        let answer = owner.map_or_else(
            || {
                format!(
                    "fixture is owned by {}-{}",
                    spec["package"].as_str().unwrap(),
                    spec["version"].as_str().unwrap()
                )
            },
            str::to_owned,
        );
        verify_rpcd_compat_acl(payload, base, manifest, &spec, &fixed_owner(answer))
    }

    #[test]
    fn only_existing_flash_read_group_gains_resolved_mounts() {
        let temp = TempDir::new("rpcd-acl");
        let (base, payload, manifest) = rpcd_fixture(temp.path());
        let path = payload.join(RPCD_COMPAT_PATH.trim_start_matches('/'));
        assert_eq!(
            util::read_json(&path).unwrap(),
            json!({"luci-mod-system-flash": {"read": {"file": {"/proc/*/mounts": ["read"]}}}})
        );
        assert_eq!(sha(&path).unwrap(), RPCD_COMPAT_SHA256);
        assert_eq!(file_mode(&path).unwrap(), 0o644);
        assert!(fs::read_dir(&base).unwrap().next().is_none());
        assert!(!payload.join(STOCK).exists());
        assert!(spec()["integration_files"]
            .get(RPCD_COMPAT_PATH.trim_start_matches('/'))
            .is_none());
        rpcd_verify(&base, &payload, &manifest, None).unwrap();
    }

    #[test]
    fn stock_file_or_dangling_symlink_collision_is_rejected() {
        for link in [false, true] {
            let temp = TempDir::new("rpcd-collision");
            let target = temp
                .path()
                .join("base")
                .join(RPCD_COMPAT_PATH.trim_start_matches('/'));
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            if link {
                std::os::unix::fs::symlink(temp.path().join("missing"), &target).unwrap();
            } else {
                fs::write(&target, "stock file").unwrap();
            }
            let error = install_rpcd_compat_acl(
                &util::repo(),
                &temp.path().join("payload"),
                &temp.path().join("base"),
            )
            .unwrap_err();
            assert!(error.to_string().contains("collides with stock"));
            assert!(!temp.path().join("payload").exists());
        }
    }

    #[test]
    fn source_drift_is_rejected_before_install() {
        let temp = TempDir::new("rpcd-drift");
        let source = temp
            .path()
            .join("packaging/openwrt/owrt-rpcd/files/owrt-rpcd-compat.json");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, "{\"unexpected\": {}}\n").unwrap();
        let error = install_rpcd_compat_acl(
            temp.path(),
            &temp.path().join("payload"),
            &temp.path().join("base"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("source drift"));
        assert!(!temp.path().join("payload").exists());
    }

    #[test]
    fn final_content_mode_symlink_and_manifest_drift_are_rejected() {
        for changed in ["content", "mode", "symlink", "manifest"] {
            let temp = TempDir::new("rpcd-final");
            let (base, payload, mut manifest) = rpcd_fixture(temp.path());
            let path = payload.join(RPCD_COMPAT_PATH.trim_start_matches('/'));
            match changed {
                "content" => fs::write(&path, "{\"unexpected\": {}}\n").unwrap(),
                "mode" => util::set_mode(&path, 0o666).unwrap(),
                "symlink" => {
                    let target = path.with_extension("target");
                    fs::rename(&path, &target).unwrap();
                    std::os::unix::fs::symlink(&target, &path).unwrap();
                }
                _ => manifest["rpcd_compat_acl"]["sha256"] = json!("0".repeat(64)),
            }
            assert!(
                rpcd_verify(&base, &payload, &manifest, None).is_err(),
                "{changed}"
            );
        }
    }

    #[test]
    fn final_acl_must_be_owned_by_the_native_package() {
        let temp = TempDir::new("rpcd-owner");
        let (base, payload, manifest) = rpcd_fixture(temp.path());
        assert!(rpcd_verify(
            &base,
            &payload,
            &manifest,
            Some("fixture is owned by luci-mod-system-1")
        )
        .is_err());
    }

    #[test]
    fn current_recipe_includes_the_qualified_odhcpd() {
        let mut expected = spec();
        expected["version"] = json!("0.3.2-r1");
        expected["components"]["odhcpd"] = json!({
            "path": "/usr/sbin/odhcpd", "binary": "odhcpd-rs", "stock_package": "odhcpd-ipv6only",
            "stock_sha256": "53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82",
            "reference_elf_sha256": "f6e4eecb8882522d304e13b2ccccc268743e4d267c4a3e41db63c62009752d39"});
        let next = next_spec();
        assert_eq!(next, expected);
        assert_eq!(next["version"], "0.3.2-r1");
        assert_eq!(
            next["dnsmasq_build"],
            spec_file("manifests/dnsmasq-pgo-frozen-v032.json")
        );
    }

    #[test]
    fn only_exact_ten_and_eleven_native_inventories_are_accepted() {
        assert_eq!(native_layout(&spec()["components"]).unwrap(), "native-ten");
        let next = next_spec()["components"].clone();
        assert_eq!(native_layout(&next).unwrap(), "native-eleven");
        let mut bad = Vec::new();
        for missing in ["fw4", "dnsmasq"] {
            let mut value = next.clone();
            value.as_object_mut().unwrap().shift_remove(missing);
            bad.push(value);
        }
        for (field, value) in [
            ("path", "/usr/sbin/odhcpd-rs"),
            ("binary", "another-rs"),
            ("stock_package", "odhcpd"),
        ] {
            let mut changed = next.clone();
            changed["odhcpd"][field] = json!(value);
            bad.push(changed);
        }
        let mut extra = next.clone();
        extra["extra"] = next["odhcpd"].clone();
        bad.push(extra);
        for components in bad {
            assert!(native_layout(&components).is_err(), "{components}");
        }
    }

    #[test]
    fn eleven_fixtures_include_stock_odhcpd_owner_and_reference_is_required() {
        let next = next_spec();
        let owners: BTreeSet<String> = native_check::stock_owners(&next)
            .unwrap()
            .into_iter()
            .collect();
        let expected: BTreeSet<String> = next["components"]
            .as_object()
            .unwrap()
            .values()
            .map(|c| c["stock_package"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(owners, expected);
        let mut hashes = Map::new();
        for item in next["components"].as_object().unwrap().values() {
            hashes.insert(
                item["binary"].as_str().unwrap().into(),
                item.get("reference_elf_sha256")
                    .cloned()
                    .unwrap_or(json!("0".repeat(64))),
            );
        }
        verify_component_references(&hashes, &next).unwrap();
        hashes.insert("odhcpd-rs".into(), json!("f".repeat(64)));
        assert!(verify_component_references(&hashes, &next)
            .unwrap_err()
            .to_string()
            .contains("identity drift: odhcpd"));
    }

    #[test]
    fn recovery_shell_accepts_only_complete_legacy_or_odhcpd_sets() {
        // Run the actual shell against owned temporary paths, replacing only its
        // fixed root-path bindings. No chroot, active executable or router is used.
        let source = util::read_text(&util::repo().join("packaging/image/owrt-recover-c")).unwrap();
        let spec = spec();
        for variant in [
            "ten",
            "eleven",
            "missing",
            "substituted",
            "duplicate",
            "unknown",
            "missing-odhcpd",
            "missing-odhcpd-rehashed",
            "bad-layout",
            "bad-digest",
        ] {
            let temp = TempDir::new("recover");
            let root = temp.path();
            let (stock, active) = (root.join("stock"), root.join("active"));
            fs::create_dir(&active).unwrap();
            let mut paths: Vec<String> = spec["components"]
                .as_object()
                .unwrap()
                .values()
                .chain(spec["integration_files"].as_object().unwrap().values())
                .map(|c| c["path"].as_str().unwrap().to_owned())
                .collect();
            if variant != "ten" {
                paths.push("/usr/sbin/odhcpd".into());
            }
            match variant {
                "missing" => paths.retain(|path| path != "/sbin/fw4"),
                "substituted" => paths.retain(|path| path != "/etc/init.d/dnsmasq"),
                "duplicate" => {
                    let first = paths[0].clone();
                    *paths.last_mut().unwrap() = first;
                }
                "unknown" => *paths.last_mut().unwrap() = "/usr/sbin/unknown".into(),
                _ => {}
            }
            let unique: BTreeSet<&String> = paths.iter().collect();
            for name in &unique {
                let file = stock.join(name.trim_start_matches('/'));
                fs::create_dir_all(file.parent().unwrap()).unwrap();
                fs::write(&file, format!("stock:{name}")).unwrap();
                util::set_mode(&file, 0o755).unwrap();
                let live = active.join(name.trim_start_matches('/'));
                fs::create_dir_all(live.parent().unwrap()).unwrap();
                fs::write(&live, format!("candidate:{name}")).unwrap();
            }
            let lines: Vec<String> = paths
                .iter()
                .map(|name| {
                    let file = stock.join(name.trim_start_matches('/'));
                    format!("{}  {}\n", sha(&file).unwrap(), file.display())
                })
                .collect();
            let manifest = root.join("stock.sha256");
            fs::write(&manifest, lines.concat()).unwrap();
            let mut metadata = json!({"layout": if variant == "ten" { "native-ten" } else { "native-eleven" },
                                      "stock_manifest_sha256": sha(&manifest).unwrap()});
            if variant.starts_with("missing-odhcpd") {
                fs::write(
                    &manifest,
                    lines
                        .iter()
                        .filter(|row| !row.ends_with("/usr/sbin/odhcpd\n"))
                        .cloned()
                        .collect::<String>(),
                )
                .unwrap();
            }
            match variant {
                "missing-odhcpd-rehashed" => {
                    metadata["stock_manifest_sha256"] = json!(sha(&manifest).unwrap())
                }
                "bad-layout" => metadata["layout"] = json!("native-unknown"),
                "bad-digest" => metadata["stock_manifest_sha256"] = json!("0".repeat(64)),
                _ => {}
            }
            let release = root.join("release.json");
            fs::write(&release, metadata.to_string()).unwrap();
            // The host unit fixture substitutes only JSON field extraction;
            // native-image-check uses the exact rootfs jsonfilter executable.
            let reader = root.join("jsonfilter");
            fs::write(&reader, "#!/bin/sh\n# jsonfilter -i FILE -e @.KEY for flat string fields\n\
                                key=${4#@.}\nsed -n \"s/.*\\\"$key\\\": *\\\"\\([^\\\"]*\\)\\\".*/\\1/p\" \"$2\"\n").unwrap();
            util::set_mode(&reader, 0o755).unwrap();
            let mounts = root.join("mountinfo");
            fs::write(&mounts, "").unwrap();
            let active_text = util::display(&active);
            let script = source
                .replace("base=/usr/libexec/owrt-stock", &format!("base={}", stock.display()))
                .replace("manifest=/usr/share/owrt-control-plane/stock.sha256", &format!("manifest={}", manifest.display()))
                .replace("release=/usr/share/owrt-control-plane/release.json", &format!("release={}", release.display()))
                .replace("/proc/self/mountinfo", &util::display(&mounts))
                .replace("    cp -p \"$source\"", &format!("    target=\"{active_text}$target\"\n    cp -p \"$source\""))
                .replace("    mv -f \"$target.owrt-recovery-new\"", &format!("    target=\"{active_text}$target\"\n    mv -f \"$target.owrt-recovery-new\""))
                .replace("rm -f \"${source#\"$base\"}", &format!("rm -f \"{active_text}${{source#\"$base\"}}"))
                .replace("\nsync\n", "\n: # fixture: no global sync\n");
            let path = format!(
                "{}:{}",
                root.display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let mut child = std::process::Command::new("sh")
                .arg("-eu")
                .env("PATH", path)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            std::io::Write::write_all(child.stdin.as_mut().unwrap(), script.as_bytes()).unwrap();
            let result = child.wait_with_output().unwrap();
            let accepted = matches!(variant, "ten" | "eleven");
            assert_eq!(
                result.status.success(),
                accepted,
                "{variant}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            for name in &unique {
                let expected = format!("{}{name}", if accepted { "stock:" } else { "candidate:" });
                assert_eq!(
                    fs::read_to_string(active.join(name.trim_start_matches('/'))).unwrap(),
                    expected,
                    "{variant}"
                );
            }
            assert!(!util::walk_sorted(root)
                .unwrap()
                .iter()
                .any(|p| p.to_string_lossy().ends_with(".owrt-recovery-new")));
        }
    }

    #[test]
    fn prepare_rejects_unprivileged_before_reading_or_mutating_files() {
        if util::euid() == 0 {
            return;
        }
        let temp = TempDir::new("prepare");
        let error = prepare(
            &temp.path().join("missing"),
            &spec(),
            Path::new("/unused-apk"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("requires root"));
        assert!(fs::read_dir(temp.path()).unwrap().next().is_none());
    }

    #[test]
    fn reinstall_fixtures_cover_every_original_package_owner() {
        let spec = spec();
        let owners: BTreeSet<&str> = spec["components"]
            .as_object()
            .unwrap()
            .values()
            .chain(spec["integration_files"].as_object().unwrap().values())
            .map(|c| c["stock_package"].as_str().unwrap())
            .collect();
        assert_eq!(
            native_check::STOCK_OWNERS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            owners
        );
        assert_eq!(native_check::STOCK_OWNERS.len(), owners.len());
    }

    fn dnsmasq_fixture(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let (base, candidate, payload) = (
            root.join("base"),
            root.join("candidate"),
            root.join("payload"),
        );
        let spec = spec();
        let replace = |data: &[u8], from: &[u8], to: &[u8]| -> Vec<u8> {
            let text = String::from_utf8(data.to_vec()).unwrap();
            let (from, to) = (
                std::str::from_utf8(from).unwrap(),
                std::str::from_utf8(to).unwrap(),
            );
            assert!(text.contains(from));
            text.replace(from, to).into_bytes()
        };
        let init = fs::read(files().join("dnsmasq.init")).unwrap();
        let stock_init = replace(
            &init,
            b"\tprocd_set_param file $CONFIGFILE $PROG\n",
            b"\tprocd_set_param file $CONFIGFILE\n",
        );
        let stock_init = replace(
            &stock_init,
            b"\t# Bind the socket directory so an ubusd restart can replace ubus.sock.\n\
              \t# The ubus jail shortcut pins the old socket inode until dnsmasq restarts.\n\
              \tprocd_add_jail dnsmasq log\n\tprocd_add_jail_mount /var/run/ubus\n",
            b"\tprocd_add_jail dnsmasq ubus log\n",
        );
        let acl = fs::read(files().join("dnsmasq_acl.json")).unwrap();
        let stock_acl = replace(
            &acl,
            b"\"publish\": [ \"dnsmasq\", \"dnsmasq.dns\" ]",
            b"\"publish\": [ \"dnsmasq\" ]",
        );
        for (name, original, replacement) in [
            ("etc/init.d/dnsmasq", &stock_init, &init),
            ("usr/share/acl.d/dnsmasq_acl.json", &stock_acl, &acl),
        ] {
            for (tree, content) in [(&base, original), (&candidate, replacement)] {
                let file = tree.join(name);
                fs::create_dir_all(file.parent().unwrap()).unwrap();
                fs::write(&file, content).unwrap();
                util::set_mode(
                    &file,
                    spec["integration_files"][name]["mode"].as_u64().unwrap() as u32,
                )
                .unwrap();
            }
        }
        for (source, target) in [
            ("dhcp.conf", "etc/config/dhcp"),
            ("dnsmasq.conf", "etc/dnsmasq.conf"),
            ("dnsmasqsec.hotplug", "etc/hotplug.d/ntp/25-dnsmasqsec"),
            (
                "50-dnsmasq-migrate-ipset.sh",
                "etc/uci-defaults/50-dnsmasq-migrate-ipset.sh",
            ),
            (
                "50-dnsmasq-migrate-resolv-conf-auto.sh",
                "etc/uci-defaults/50-dnsmasq-migrate-resolv-conf-auto.sh",
            ),
            ("dhcp-script.sh", "usr/lib/dnsmasq/dhcp-script.sh"),
            (
                "dhcpbogushostname.conf",
                "usr/share/dnsmasq/dhcpbogushostname.conf",
            ),
            ("rfc6761.conf", "usr/share/dnsmasq/rfc6761.conf"),
        ] {
            for tree in [&base, &candidate] {
                let file = tree.join(target);
                fs::create_dir_all(file.parent().unwrap()).unwrap();
                fs::copy(files().join(source), &file).unwrap();
            }
        }
        (payload, base, candidate)
    }

    fn integrate(paths: &(PathBuf, PathBuf, PathBuf), spec: &Value) -> Result<Map<String, Value>> {
        let installed = json!({"dnsmasq": {"version": "2.93-r1"}});
        integration_files(
            &paths.0,
            &paths.1,
            &paths.2,
            spec,
            &fixed_owner("fixture is owned by dnsmasq-2.93-r1".into()),
            installed.as_object().unwrap(),
        )
    }

    #[test]
    fn only_accepted_files_installed_with_paired_stock_modes() {
        let temp = TempDir::new("integration");
        let paths = dnsmasq_fixture(temp.path());
        let result = integrate(&paths, &spec()).unwrap();
        let (payload, base, candidate) = &paths;
        for (name, item) in &result {
            assert_eq!(
                fs::read(payload.join(name)).unwrap(),
                fs::read(candidate.join(name)).unwrap()
            );
            let recovery = payload.join(
                item["recovery_path"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches('/'),
            );
            assert_eq!(
                fs::read(&recovery).unwrap(),
                fs::read(base.join(name)).unwrap()
            );
            assert_eq!(
                u64::from(file_mode(&recovery).unwrap()),
                item["mode"].as_u64().unwrap()
            );
        }
        assert_eq!(
            util::walk_sorted(payload)
                .unwrap()
                .iter()
                .filter(|path| path.is_file())
                .count(),
            4
        );
    }

    #[test]
    fn stock_or_candidate_drift_rejected() {
        for side in [1, 2] {
            let temp = TempDir::new("integration-drift");
            let paths = dnsmasq_fixture(temp.path());
            let tree = if side == 1 { &paths.1 } else { &paths.2 };
            let file = tree.join("etc/init.d/dnsmasq");
            let mut data = fs::read(&file).unwrap();
            data.extend(b"# drift\n");
            fs::write(&file, data).unwrap();
            assert!(integrate(&paths, &spec())
                .unwrap_err()
                .to_string()
                .contains("identity drift"));
        }
    }

    #[test]
    fn defaults_and_helpers_must_remain_stock() {
        let temp = TempDir::new("integration-defaults");
        let paths = dnsmasq_fixture(temp.path());
        fs::write(
            paths.2.join("usr/lib/dnsmasq/dhcp-script.sh"),
            "changed helper\n",
        )
        .unwrap();
        assert!(integrate(&paths, &spec())
            .unwrap_err()
            .to_string()
            .contains("dhcp-script"));
    }

    #[test]
    fn extra_replacement_path_rejected() {
        let mut spec = spec();
        spec["integration_files"]["etc/config/dhcp"] = json!({});
        let temp = TempDir::new("integration-extra");
        assert!(integrate(&dnsmasq_fixture(temp.path()), &spec).is_err());
    }

    #[test]
    fn mode_change_rejected() {
        let temp = TempDir::new("integration-mode");
        let paths = dnsmasq_fixture(temp.path());
        util::set_mode(&paths.2.join("usr/share/acl.d/dnsmasq_acl.json"), 0o777).unwrap();
        assert!(integrate(&paths, &spec()).is_err());
    }

    #[test]
    fn all_nine_release_rebuilds_must_equal_the_accepted_binaries() {
        let mut spec = spec();
        spec["version"] = json!("0.2.2-r1");
        let mut hashes = Map::new();
        for (name, component) in spec["components"].as_object_mut().unwrap() {
            let value = util::sha256_bytes(name.as_bytes());
            hashes.insert(component["binary"].as_str().unwrap().into(), json!(value));
            if name != "dnsmasq" {
                component["reference_elf_sha256"] = json!(value);
            }
        }
        verify_component_references(&hashes, &spec).unwrap();
        for (name, component) in spec["components"].as_object().unwrap() {
            if name == "dnsmasq" {
                continue;
            }
            let mut changed = hashes.clone();
            changed.insert(
                component["binary"].as_str().unwrap().into(),
                json!("f".repeat(64)),
            );
            assert!(verify_component_references(&changed, &spec)
                .unwrap_err()
                .to_string()
                .contains("identity drift"));
            let mut incomplete = spec.clone();
            incomplete["components"][name]
                .as_object_mut()
                .unwrap()
                .shift_remove("reference_elf_sha256");
            assert!(verify_component_references(&hashes, &incomplete)
                .unwrap_err()
                .to_string()
                .contains("missing accepted"));
        }
        let mut legacy = spec.clone();
        legacy["version"] = json!("0.2.1-r1");
        for component in legacy["components"].as_object_mut().unwrap().values_mut() {
            component
                .as_object_mut()
                .unwrap()
                .shift_remove("reference_elf_sha256");
        }
        verify_component_references(&hashes, &legacy).unwrap();
        legacy["version"] = json!("0.2.2-r1");
        assert!(verify_component_references(&hashes, &legacy)
            .unwrap_err()
            .to_string()
            .contains("missing accepted"));
    }

    #[test]
    fn native_integration_rejects_unqualified_or_changed_dnsmasq() {
        let spec = json!({"source_commit": "a".repeat(40), "source_digest": "b".repeat(64),
                          "reference_elf_sha256": "c".repeat(64), "reference_elf_bytes": 1234, "source_date_epoch": 2345,
                          "pgo": {"profile_url": "https://example.invalid/frozen.profdata", "profile_sha256": "d".repeat(64),
                                  "profile_bytes": 10, "build_slot": "/fixed/product-slot", "training": {"receipt": "e".repeat(64)}}});
        let mut pgo = spec["pgo"].clone();
        pgo["mode"] = json!("use");
        pgo["profile_diagnostics"] = json!([]);
        let report = json!({"status": "built-and-audited", "source_digest": spec["source_digest"],
                            "accepted_product_commit": spec["source_commit"], "source_date_epoch": "2345",
                            "elf": {"sha256": "c".repeat(64), "reference_sha256": "c".repeat(64), "size": 1234,
                                    "matches_accepted_reference": true}, "pgo": pgo});
        verify_dnsmasq_reference(&report, &spec).unwrap();
        for (section, key, value) in [
            ("elf", "sha256", json!("f".repeat(64))),
            ("elf", "size", json!(1235)),
            ("elf", "matches_accepted_reference", json!(false)),
            ("pgo", "mode", json!("generate")),
            ("pgo", "build_slot", json!("/different/slot")),
            ("pgo", "profile_diagnostics", json!(["hash mismatch"])),
        ] {
            let mut changed = report.clone();
            changed[section][key] = value;
            assert!(
                verify_dnsmasq_reference(&changed, &spec).is_err(),
                "{section}.{key}"
            );
        }
        let mut diagnostic = report.clone();
        diagnostic["release_qualified"] = json!(false);
        assert!(verify_dnsmasq_reference(&diagnostic, &spec)
            .unwrap_err()
            .to_string()
            .contains("diagnostic"));
        let mut epoch = report.clone();
        epoch["source_date_epoch"] = json!(2346);
        assert!(verify_dnsmasq_reference(&epoch, &spec)
            .unwrap_err()
            .to_string()
            .contains("epoch"));
    }

    fn release_identity(spec: &Value) -> (usize, String, BTreeSet<String>) {
        let temp = TempDir::new("release-source");
        fs::create_dir(temp.path().join("out")).unwrap();
        let frozen = dnsmasq_ci::release_source(temp.path(), spec).unwrap();
        let (files, digest) = dnsmasq_ci::source_identity(spec, Some(&frozen)).unwrap();
        (
            files.len(),
            digest,
            files.into_iter().map(|(name, _)| name).collect(),
        )
    }

    #[test]
    fn release_source_is_the_frozen_product() {
        let spec = spec();
        let commit = crate::history::resolve_commit(
            &util::repo(),
            spec["dnsmasq_build"]["source_commit"].as_str().unwrap(),
        )
        .unwrap();
        let present = std::process::Command::new("git")
            .args([
                "-C",
                &util::display(&util::repo()),
                "cat-file",
                "-e",
                &format!("{commit}^{{commit}}"),
            ])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        if !present {
            eprintln!("shallow checkout lacks the accepted dnsmasq commit");
            return;
        }
        let (count, digest, _) = release_identity(&spec["dnsmasq_build"]);
        assert_eq!(count, 212);
        assert_eq!(
            digest,
            "c3daefd7b94be1e42120f6ae9cec7c56264ed2dc430639ceea5d63812d151725"
        );
    }

    #[test]
    fn source_drift_cannot_inherit_accepted_identity() {
        let mut frozen = spec()["dnsmasq_build"].clone();
        frozen["source_digest"] = json!("a".repeat(64));
        let error = dnsmasq_ci::source_identity(&frozen, None).unwrap_err();
        assert!(
            error.to_string().contains("differs from accepted"),
            "{error}"
        );
    }

    #[test]
    fn ten_component_inventory_does_not_change_original_nine() {
        // Canonical digest of these four fields at v0.1.1. No historical Git
        // objects are required in Actions' shallow checkout.
        let spec = spec();
        let mut previous = Map::new();
        for key in ["components", "stock_image", "luci_source", "translations"] {
            previous.insert(key.into(), spec[key].clone());
        }
        let components = previous["components"].as_object_mut().unwrap();
        components.shift_remove("dnsmasq");
        // New reference hashes bind the rebuilt implementations; the original
        // paths, stock identities, package owners and binary names stay fixed.
        for component in components.values_mut() {
            component
                .as_object_mut()
                .unwrap()
                .shift_remove("reference_elf_sha256");
        }
        assert_eq!(components.len(), 9);
        assert_eq!(
            util::canonical_digest(&Value::Object(previous)),
            "bac71f5c50f91dce84dcf7652cb353f1c5d92852118a13c7b5df24eb1e07d496"
        );
    }

    #[test]
    fn new_recipe_preserves_qualified_pgo_and_exact_stock_recovery() {
        let spec = spec_file("packaging/image/native-25.12.6.json");
        let frozen = spec_file("manifests/dnsmasq-pgo-frozen-v033.json");
        let intake = spec_file("manifests/ax3000t-stock-openwrt-25.12.6/intake.json");
        assert_eq!(
            (spec["openwrt"].as_str(), spec["version"].as_str()),
            (Some("25.12.6"), Some("0.3.3-r1"))
        );
        assert_eq!(spec["dnsmasq_build"], frozen);
        assert_eq!(
            frozen["reference_elf_sha256"],
            "b2192268615d7be8ec30397de2a4b67cc5efa292017237d03b47a55324e5aa41"
        );
        assert_eq!(
            spec["stock_image"]["sha256"],
            intake["artifacts"]["stock_image"]["sha256"]
        );
        assert_eq!(spec["components"].as_object().unwrap().len(), 11);
        for (name, component) in spec["components"].as_object().unwrap() {
            assert_eq!(
                component["stock_sha256"],
                intake["stock_replacement_paths"][name]["sha256"]
            );
        }
    }

    #[test]
    fn new_recipe_archives_the_actual_qualified_25126_source() {
        let spec = spec_file("packaging/image/native-25.12.6.json");
        let (count, digest, names) = release_identity(&spec["dnsmasq_build"]);
        assert_eq!(count, 231);
        assert_eq!(
            digest,
            "9d3c45da3a3f7a12073610f34de0868187eaca6472c148f1f3626ff22c207657"
        );
        assert!(names.contains("manifests/release-25.12.6.json"));
        assert!(!names.contains("manifests/release-25.12.5.json"));
        let _ = package::SELF_INPUT;
    }
}
