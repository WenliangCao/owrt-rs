//! Off-device native image qualification. Run as root on an aarch64 Linux
//! build host; every case uses a disposable image copy plus mount/network/PID
//! namespaces, never a physical router or live bus.
//!
//! * `native-image-check ROOTFS OUTPUT [--apk-dir D] [--image I]`: firmware
//!   configuration migration, C recovery, APK reinstall and fwtool checks.
//! * `native-package-reinstall-selftest ROOTFS APK_DIR OUTPUT`: reinstalls
//!   repair files, and successful no-op commands are rejected.
//! * `native-apk-fixtures STOCK_ROOTFS NATIVE_APK APK_TOOL OUTPUT [--spec S]`:
//!   unsigned exact-image payload fixtures for `--no-scripts` ownership tests.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::native_image::{self, native_layout, preserve_directory_modes};
use crate::util::{self, bail, ensure, strings, Args, JsonExt, Result};

pub const STOCK_OWNERS: [&str; 9] = ["procd", "ubusd", "netifd", "rpcd", "logd", "uhttpd", "firewall4", "uci", "dnsmasq"];

pub fn stock_owners(spec: &Value) -> Result<Vec<String>> {
    native_layout(spec.field("components")?)?;
    let mut owners = strings(STOCK_OWNERS);
    if spec["components"].get("odhcpd").is_some() {
        owners.push("odhcpd-ipv6only".into());
    }
    Ok(owners)
}

const NAMESPACE: &str = r#"
set -eu
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
# A fresh proc mount does not isolate the consuming kernel-log interface.
: > "$root/tmp/kmsg-empty"
mount --bind "$root/tmp/kmsg-empty" "$root/proc/kmsg"
test -f "$root/proc/kmsg" && test ! -s "$root/proc/kmsg"
test "$root/tmp/kmsg-empty" -ef "$root/proc/kmsg"
stat -c "%f %s" "$root/proc/kmsg" > "$root/tmp/kmsg-fixture-host.stat"
mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
exec chroot "$root" /bin/sh -eu
"#;

fn sha(path: &Path) -> Result<String> {
    util::sha256_file(path)
}

fn require_build_host() -> Result<()> {
    ensure!(util::euid() == 0 && util::is_linux(), "run as root on Linux");
    ensure!(std::env::consts::ARCH == "aarch64" && !Path::new("/etc/openwrt_release").exists(),
            "run on an aarch64 build host, never a router");
    Ok(())
}

/// Replaces the one APK reinstall of a negative-control stage with a
/// deliberately successful no-op.
pub fn skip_reinstall(script: &str) -> Result<String> {
    let mut lines: Vec<&str> = script.lines().collect();
    let commands: Vec<usize> = lines.iter().enumerate()
        .filter(|(_, line)| line.starts_with("apk ") && line.contains(" add --force-reinstall "))
        .map(|(index, _)| index).collect();
    ensure!(commands.len() == 1, "negative control did not locate the reinstall");
    lines[commands[0]] = ": # deliberately successful no-op reinstall";
    Ok(lines.join("\n") + "\n")
}

pub struct Check {
    source: PathBuf,
    out: PathBuf,
    manifest: Value,
    results: Map<String, Value>,
    /// Negative control: the reinstall stage to turn into a no-op.
    skip_stage: Option<&'static str>,
    skipped: u32,
}

impl Check {
    pub fn new(source: &Path, out: &Path) -> Result<Self> {
        fs::create_dir_all(out.parent().unwrap())?;
        fs::create_dir(out)?;
        let manifest = util::read_json(&source.join("usr/share/owrt-control-plane/release.json"))?;
        ensure!(manifest["layout"] == native_layout(&manifest["components"])?, "release layout differs from inventory");
        let paths: std::collections::BTreeSet<&str> = manifest.obj_field("integration_files")?.values()
            .filter_map(|item| item["path"].as_str()).collect();
        ensure!(paths == ["/etc/init.d/dnsmasq", "/usr/share/acl.d/dnsmasq_acl.json"].into(), "unexpected integration files");
        Ok(Self { source: source.to_path_buf(), out: out.to_path_buf(), manifest, results: Map::new(), skip_stage: None, skipped: 0 })
    }

    fn component_word(&self) -> String {
        self.manifest["layout"].as_str().unwrap_or_default().trim_start_matches("native-").to_owned()
    }

    fn version(&self) -> &str {
        self.manifest["version"].as_str().unwrap_or_default()
    }

    fn copy(&self, name: &str) -> Result<PathBuf> {
        let root = self.out.join(name);
        ensure!(!root.exists(), "fixture copy exists: {name}");
        util::run_checked(&strings(["cp", "-a", &util::display(&self.source), &util::display(&root)]), None, None)?;
        Ok(root)
    }

    fn shell(&mut self, name: &str, root: &Path, script: &str, success: bool) -> Result<()> {
        let mut script = script.to_owned();
        if self.skip_stage.is_some_and(|stage| name == format!("package-{stage}-reinstall")) {
            script = skip_reinstall(&script)?;
            self.skipped += 1;
        }
        for stale in ["kmsg-fixture-host.stat", "kmsg-fixture-runtime.check"] {
            let _ = fs::remove_file(root.join("tmp").join(stale));
        }
        let command = strings(["unshare", "--mount", "--net", "--pid", "--uts", "--ipc", "--fork", "--kill-child",
                               "/bin/sh", "-c", NAMESPACE, "sh", &util::display(root)]);
        let script = format!("test -f /proc/kmsg && test ! -s /proc/kmsg\n\
                              test /tmp/kmsg-empty -ef /proc/kmsg\n\
                              printf '%s\\n' regular-empty-same-file > /tmp/kmsg-fixture-runtime.check\n\
                              mkdir -p /var/lock /var/run /var/log /var/state\n{script}");
        let result = util::run_timeout(&command, Some(&script), Duration::from_secs(90))?;
        let code = result.code;
        let output = String::from_utf8_lossy(&[result.stdout, result.stderr].concat()).into_owned();
        fs::write(self.out.join(format!("{name}.log")), &output)?;
        let stat = util::read_text(&root.join("tmp/kmsg-fixture-host.stat"))?;
        let (mode, size) = stat.split_once(' ').ok_or_else(|| util::Error::new("malformed kmsg stat"))?;
        let (mode, size) = (mode.trim().to_owned(), size.trim().parse::<u64>()?);
        let regular = u32::from_str_radix(&mode, 16).is_ok_and(|bits| bits & libc::S_IFMT == libc::S_IFREG);
        ensure!(regular && size == 0, "{name}: kmsg fixture {mode} {size}");
        ensure!(util::read_text(&root.join("tmp/kmsg-fixture-runtime.check"))?.trim() == "regular-empty-same-file",
                "{name}: runtime kmsg check missing");
        util::write_json(&self.out.join(format!("{name}-isolation.json")), &json!({
            "mode_hex": mode, "bytes": size, "regular_file": true,
            "same_fixture_inode_and_device_checked_before_chroot_and_in_runtime": true}))?;
        ensure!((code == 0) == success, "{name}: exit {code}\n{output}");
        Ok(())
    }

    fn identities(&self, root: &Path, mode: &str) -> Result<()> {
        let key = format!("{mode}_sha256");
        for c in self.manifest.obj_field("components")?.values() {
            let path = c.str_field("path")?;
            ensure!(c[&key] == sha(&root.join(path.trim_start_matches('/')))?.as_str(), "{path}");
        }
        for c in self.manifest.obj_field("integration_files")?.values() {
            let path = c.str_field("path")?;
            let file = root.join(path.trim_start_matches('/'));
            let key = if mode == "stock" { "stock_sha256" } else { "replacement_sha256" };
            ensure!(c[key] == sha(&file)?.as_str(), "{path}");
            let original = self.source.join(c.str_field("recovery_path")?.trim_start_matches('/'));
            ensure!(fs::metadata(&file)?.mode() & 0o7777 == fs::metadata(&original)?.mode() & 0o7777, "{path}");
        }
        Ok(())
    }

    fn passed(&mut self, name: &str) -> Result<()> {
        self.results.insert(name.into(), json!(true));
        util::write_json(&self.out.join("result.json"), &Value::Object(self.results.clone()))?;
        println!("PASS: {name}");
        Ok(())
    }

    pub fn configuration(&mut self, native: bool) -> Result<()> {
        let case = if native { "native_upgrade" } else { "layered_migration" };
        let old = self.copy(&format!("{case}-old"))?;
        fs::write(old.join("etc/config/network"), "config interface 'lan'\n option proto 'static'\n option ipaddr '192.0.2.1'\n")?;
        fs::write(old.join("etc/config/wireless"), "config wifi-iface 'fixture'\n option ssid 'upgrade-fixture'\n option disabled '1'\n")?;
        fs::create_dir_all(old.join("etc/crontabs"))?;
        fs::write(old.join("etc/crontabs/root"), "# retained synthetic LED schedule\n")?;
        fs::write(old.join("etc/rc.local"), "# retained fixture\nexit 0\n")?;
        fs::write(old.join("etc/sysupgrade.conf"), "/etc/native-config-fixture\n")?;
        fs::write(old.join("etc/native-config-fixture"), "selected by sysupgrade.conf\n")?;
        let disable = if native {
            fs::write(old.join("etc/owrt-control-plane-layout"), "native-nine-v1\n")?;
            "uhttpd"
        } else {
            for c in ["uci", "reload-config", "logd", "httpd", "fw4", "rpcd"] {
                fs::write(old.join(format!("etc/owrt-{c}.boot-enable")), "")?;
            }
            "log rpcd uhttpd"
        };
        self.shell(&format!("{case}-backup"), &old,
                   &format!("\nfor s in {disable} cron; do /etc/init.d/$s disable; done\n/sbin/sysupgrade -b /tmp/native-config.tar.gz\n"), true)?;
        let archive = old.join("tmp/native-config.tar.gz");
        let mut disabled = None;
        let mut legacy_marker = false;
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(fs::File::open(&archive)?));
        for entry in tar.entries()? {
            let mut entry = entry?;
            let name = entry.path()?.to_string_lossy().trim_start_matches('/').to_owned();
            legacy_marker |= name.contains("owrt-") && name.ends_with(".boot-enable");
            if name == "etc/uci-defaults/10_disable_services" {
                let mut text = String::new();
                entry.read_to_string(&mut text)?;
                disabled = Some(text);
            }
        }
        let disabled = disabled.ok_or_else(|| util::Error::new("backup lacks 10_disable_services"))?;
        for service in disable.split(' ') {
            ensure!(disabled.contains(&format!("/etc/init.d/{service} disable")), "backup lost disabled {service}");
        }
        ensure!(!legacy_marker, "backup carries a legacy boot-enable marker");
        let new = self.copy(&format!("{case}-new"))?;
        util::copy2(&archive, &new.join("sysupgrade.tgz"))?;
        // Execute the exact image's restore implementation. Only hardware root
        // mounting and hook registration are stubbed inside this disposable fs.
        let uhttpd = if native { "if /etc/init.d/uhttpd enabled; then exit 1; fi\n" } else { "/etc/init.d/uhttpd enabled\n" };
        self.shell(&format!("{case}-restore"), &new, &format!("
mount_root() {{ :; }}
boot_run_hook() {{ :; }}
boot_hook_add() {{ :; }}
set +u
. /lib/preinit/80_mount_root
do_mount_root
set -u
/bin/sh /etc/uci-defaults/05-owrt-native
/bin/sh /etc/uci-defaults/10_disable_services
test \"$(cat /etc/owrt-control-plane-layout)\" = native-nine-v1
/etc/init.d/log enabled
/etc/init.d/rpcd enabled
if /etc/init.d/cron enabled; then exit 1; fi
{uhttpd}"), true)?;
        for relative in ["etc/config/network", "etc/config/wireless", "etc/crontabs/root", "etc/rc.local", "etc/sysupgrade.conf",
                         "etc/native-config-fixture", "etc/passwd", "etc/shadow"] {
            ensure!(fs::read(old.join(relative))? == fs::read(new.join(relative))?, "{relative}");
        }
        self.identities(&new, "rust")?;
        self.passed(&format!("{case}_configuration_and_service_policy"))
    }

    pub fn recovery(&mut self) -> Result<()> {
        let root = self.copy("recovery")?;
        for (name, relative) in [("netifd", "sbin/netifd"), ("dnsmasq", "usr/sbin/dnsmasq"), ("dnsmasq-init", "etc/init.d/dnsmasq"),
                                 ("dnsmasq-acl", "usr/share/acl.d/dnsmasq_acl.json")] {
            let original = root.join("usr/libexec/owrt-stock").join(relative);
            let good = fs::read(&original)?;
            let mut corrupt = good.clone();
            corrupt.extend(b"corrupt");
            fs::write(&original, corrupt)?;
            self.shell(&format!("recovery-corrupt-{name}"), &root, "/usr/sbin/owrt-recover-c\n", false)?;
            self.identities(&root, "rust")?;
            fs::write(&original, good)?;
        }
        self.passed("corrupt_program_init_or_ACL_rejected_before_any_replacement")?;
        let sums = root.join("usr/share/owrt-control-plane/stock.sha256");
        let valid = util::read_text(&sums)?;
        let leftovers = |root: &Path| -> Result<bool> {
            Ok(util::walk_sorted(root)?.iter().any(|path| path.to_string_lossy().ends_with(".owrt-recovery-new")))
        };
        if self.manifest["layout"] == "native-eleven" {
            let source = self.manifest["components"]["odhcpd"].str_field("recovery_path")?.to_owned();
            let rows: Vec<&str> = valid.lines().filter(|row| row.split_whitespace().nth(1) != Some(source.as_str())).collect();
            ensure!(rows.len() == 12, "unexpected eleven-component recovery rows");
            fs::write(&sums, rows.join("\n") + "\n")?;
            self.shell("recovery-missing-odhcpd", &root, "/usr/sbin/owrt-recover-c\n", false)?;
            self.identities(&root, "rust")?;
            ensure!(!leftovers(&root)?, "recovery left staged files");
            fs::write(&sums, &valid)?;
            self.passed("eleven_component_recovery_cannot_downgrade_to_ten_before_any_replacement")?;
        }
        // A correct hash of an active target must never be accepted as a
        // recovery original outside the pinned stock directory.
        let mut rows: Vec<String> = valid.lines().map(str::to_owned).collect();
        rows[0] = format!("{}  /sbin/procd", sha(&root.join("sbin/procd"))?);
        fs::write(&sums, rows.join("\n") + "\n")?;
        self.shell("recovery-outside-stock", &root, "/usr/sbin/owrt-recover-c\n", false)?;
        self.identities(&root, "rust")?;
        fs::write(&sums, &valid)?;
        self.passed("non_stock_recovery_source_rejected_before_any_replacement")?;
        self.shell("recovery-mounted", &root, "\nmount -o bind /sbin/uci /sbin/uci\n/usr/sbin/owrt-recover-c\n", false)?;
        self.identities(&root, "rust")?;
        self.passed("mounted_target_rejected_before_any_replacement")?;
        self.shell("recovery-mounted-init", &root, "\nmount -o bind /etc/init.d/dnsmasq /etc/init.d/dnsmasq\n/usr/sbin/owrt-recover-c\n", false)?;
        self.identities(&root, "rust")?;
        self.passed("mounted_dnsmasq_integration_target_rejected")?;
        self.shell("recovery-stage", &root, "/usr/sbin/owrt-recover-c\n", true)?;
        self.identities(&root, "stock")?;
        ensure!(!leftovers(&root)?, "recovery left staged files");
        self.shell("recovery-repeat", &root, "/usr/sbin/owrt-recover-c\n", true)?;
        self.identities(&root, "stock")?;
        for path in sorted_dir(&self.source.join("etc/config"))? {
            ensure!(fs::read(&path)? == fs::read(root.join("etc/config").join(path.file_name().unwrap()))?, "{}", path.display());
        }
        self.passed(&format!("all_{}_C_and_dnsmasq_init_ACL_staged_idempotently_with_configuration_unchanged", self.component_word()))
    }

    pub fn package_reinstall(&mut self, apk_dir: &Path) -> Result<()> {
        let root = self.copy("package-reinstall")?;
        let cache = root.join("tmp/native-apks");
        fs::create_dir(&cache)?;
        for source in sorted_dir(apk_dir)?.into_iter().filter(|p| p.extension().is_some_and(|e| e == "apk")) {
            util::copy2(&source, &cache.join(source.file_name().unwrap()))?;
        }
        let stock_packages = self.manifest.obj_field("stock_packages")?.clone();
        let mut owner_apks = Vec::new();
        for (name, info) in &stock_packages {
            owner_apks.push(format!("/tmp/native-apks/{name}-{}.apk", info.str_field("version")?));
        }
        // fix --reinstall may return success after skipping an unavailable
        // installed APK identity. Explicit payloads and missing-file repair
        // prove that every original owner fixture was actually extracted.
        // These disposable roots may live on tmpfs. APK's non-repository
        // persistence refusal does not apply to this no-reboot fixture; allow
        // only that condition, without changing ownership or integrity checks.
        let mut file_lists = Vec::new();
        for name in stock_packages.keys() {
            let path = root.join("lib/apk/packages").join(format!("{name}.list"));
            file_lists.push((path.clone(), fs::read(&path)?));
            fs::remove_file(&path)?;
        }
        let version = self.version().to_owned();
        let mut ownership = Vec::new();
        for c in self.manifest.obj_field("components")?.values().chain(self.manifest.obj_field("integration_files")?.values()) {
            let path = c.str_field("path")?;
            ownership.push(format!("apk info --who-owns {path} | grep -Fx '{path} is owned by owrt-control-plane-{version}'"));
        }
        let ownership = ownership.join("\n") + "\n";
        let apk = "apk --no-scripts --no-network --allow-untrusted --force-non-repository --repositories-file /dev/null add --force-reinstall";
        self.shell("package-stock-reinstall", &root, &format!(
            "\n{apk} {}\nsha256sum -c /usr/share/owrt-control-plane/rust.sha256\n{ownership}", owner_apks.join(" ")), true)?;
        ensure!(!util::read_lossy(&self.out.join("package-stock-reinstall.log"))?.contains("APK unavailable"), "APK unavailable");
        for (path, expected) in &file_lists {
            ensure!(fs::read(path).ok().as_ref() == Some(expected), "{}", path.display());
        }
        self.identities(&root, "rust")?;
        self.passed(&format!("stock_package_reinstall_preserves_{}_Rust_files_and_dnsmasq_integration", self.component_word()))?;
        let recovery = root.join("usr/libexec/owrt-stock/sbin/procd");
        fs::remove_file(&recovery)?;
        self.shell("package-native-reinstall", &root, &format!(
            "\n{apk} /tmp/native-apks/owrt-control-plane-{version}.apk\nsha256sum -c /usr/share/owrt-control-plane/rust.sha256\n\
             sha256sum -c /usr/share/owrt-control-plane/stock.sha256\n{ownership}"), true)?;
        ensure!(!util::read_lossy(&self.out.join("package-native-reinstall.log"))?.contains("APK unavailable"), "APK unavailable");
        ensure!(recovery.is_file() && self.manifest["components"]["procd"]["stock_sha256"] == sha(&recovery)?.as_str(),
                "native reinstall did not restore the procd recovery file");
        self.identities(&root, "rust")?;
        self.passed("native_package_reinstall_preserves_Rust_and_recovery_files")
    }

    pub fn firmware_metadata(&mut self, image: &Path) -> Result<()> {
        let root = self.copy("firmware-metadata")?;
        util::copy2(image, &root.join("tmp/native-image.bin"))?;
        self.shell("firmware-metadata", &root, "
set +u
. /lib/functions.sh
. /lib/upgrade/fwtool.sh
v() { echo \"$@\"; }
REQUIRE_IMAGE_METADATA=1
FORCE=0
SAVE_CONFIG=1
IGNORE_MINOR_COMPAT=0
mkdir -p /tmp/sysinfo
echo xiaomi,mi-router-ax3000t > /tmp/sysinfo/board_name
if ! fwtool_check_image /tmp/native-image.bin; then exit 1; fi
echo deliberately-wrong-board > /tmp/sysinfo/board_name
if fwtool_check_image /tmp/native-image.bin; then exit 1; fi
", true)?;
        self.identities(&root, "rust")?;
        self.passed("firmware_metadata_accepts_AX3000T_keep_config_and_rejects_wrong_board")
    }
}

fn sorted_dir(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(directory)?.map(|entry| entry.map(|e| e.path())).collect::<Result<_, _>>()?;
    paths.sort();
    Ok(paths)
}

fn absolute(path: &str) -> Result<PathBuf> {
    Ok(fs::canonicalize(path).or_else(|_| std::path::absolute(path))?)
}

/// `owrt-tools native-image-check ROOTFS OUTPUT [--apk-dir D] [--image I]`.
pub fn check_main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &["--apk-dir", "--image"], &[])?;
    let [rootfs, output] = args.exact(&["ROOTFS", "OUTPUT"])?.try_into().expect("two positionals");
    require_build_host()?;
    let mut check = Check::new(&absolute(&rootfs)?, &absolute(&output)?)?;
    check.configuration(false)?;
    check.configuration(true)?;
    check.recovery()?;
    if let Some(directory) = args.value("--apk-dir") {
        check.package_reinstall(&absolute(directory)?)?;
    }
    if let Some(image) = args.value("--image") {
        check.firmware_metadata(&absolute(image)?)?;
    }
    Ok(0)
}

/// `owrt-tools native-package-reinstall-selftest ROOTFS APK_DIR OUTPUT`.
pub fn reinstall_selftest_main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &[], &[])?;
    let [rootfs, apk_dir, output] = args.exact(&["ROOTFS", "APK_DIR", "OUTPUT"])?.try_into().expect("three positionals");
    require_build_host()?;
    let (source, apks, out) = (absolute(&rootfs)?, absolute(&apk_dir)?, absolute(&output)?);
    fs::create_dir_all(out.parent().unwrap())?;
    fs::create_dir(&out)?;
    let mut positive = Check::new(&source, &out.join("real-reinstalls"))?;
    positive.package_reinstall(&apks)?;
    let mut rows = Vec::new();
    for stage in ["stock", "native"] {
        for repeat in 1..=4 {
            let mut check = Check::new(&source, &out.join(format!("skip-{stage}-{repeat}")))?;
            check.skip_stage = Some(stage);
            let Err(error) = check.package_reinstall(&apks) else {
                bail!("successful no-op {stage} reinstall was accepted");
            };
            let root = check.out.join("package-reinstall");
            let missing: Vec<PathBuf> = if stage == "stock" {
                check.manifest.obj_field("stock_packages")?.keys().map(|name| root.join("lib/apk/packages").join(format!("{name}.list"))).collect()
            } else {
                vec![root.join("usr/libexec/owrt-stock/sbin/procd")]
            };
            ensure!(check.skipped == 1 && missing.iter().all(|path| !path.exists()), "negative control {stage} did not run as designed");
            let result = if stage == "stock" {
                format!("stock_package_reinstall_preserves_{}_Rust_files_and_dnsmasq_integration", check.component_word())
            } else {
                "native_package_reinstall_preserves_Rust_and_recovery_files".to_owned()
            };
            ensure!(!check.results.contains_key(&result), "negative control {stage} reported success");
            rows.push(json!({"stage": stage, "repeat": repeat, "rejected": true, "missing_files": missing.len(),
                             "error": error.to_string()}));
        }
    }
    let result = json!({"native_manifest_sha256": sha(&source.join("usr/share/owrt-control-plane/release.json"))?,
                        "real_reinstalls": positive.results, "negative_controls": rows, "physical_router_accessed": false});
    util::write_json(&out.join("result.json"), &result)?;
    println!("{}", util::pretty_json(&result));
    Ok(0)
}

/// `owrt-tools native-apk-fixtures STOCK_ROOTFS NATIVE_APK APK_TOOL OUTPUT [--spec S]`.
///
/// Old feed APKs need not remain online. These unsigned fixtures reproduce
/// the installed version, dependencies and file payload from the pinned stock
/// image; they are not original signed packages and contain no lifecycle
/// scripts. The gate explicitly uses --no-scripts, as does image construction.
pub fn apk_fixtures_main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &["--spec"], &[])?;
    let [stock_rootfs, native_apk, apk_tool, output] =
        args.exact(&["STOCK_ROOTFS", "NATIVE_APK", "APK_TOOL", "OUTPUT"])?.try_into().expect("four positionals");
    ensure!(util::euid() == 0 && !Path::new("/etc/openwrt_release").exists(), "run as root on a build host");
    let (root, out, apk) = (absolute(&stock_rootfs)?, absolute(&output)?, absolute(&apk_tool)?);
    let native_apk = PathBuf::from(native_apk);
    fs::create_dir_all(out.parent().unwrap())?;
    fs::create_dir(&out)?;
    let spec_path = args.value("--spec").map_or_else(|| util::repo().join("packaging/image/native-25.12.5.json"), PathBuf::from);
    let names = stock_owners(&util::read_json(&spec_path)?)?;
    let packages = native_image::packages(&apk, &root, "name,version,license,arch,depends,provides,origin", &names)?;
    ensure!(packages.keys().cloned().collect::<std::collections::BTreeSet<_>>() == names.iter().cloned().collect(),
            "stock owner packages differ");
    let mut provenance = Map::new();
    for package in packages.values() {
        let name = package.str_field("name")?;
        let files = out.join("payloads").join(name);
        let listing = root.join("lib/apk/packages").join(format!("{name}.list"));
        let mut paths: std::collections::BTreeSet<String> = util::read_text(&listing)?.lines().map(str::to_owned).collect();
        for path in sorted_dir(listing.parent().unwrap())? {
            if path.file_name().unwrap().to_string_lossy().starts_with(&format!("{name}.")) {
                paths.insert(format!("/{}", path.strip_prefix(&root).unwrap().display()));
            }
        }
        let mut hashes = Map::new();
        for relative in &paths {
            let (source, target) = (root.join(relative.trim_start_matches('/')), files.join(relative.trim_start_matches('/')));
            fs::create_dir_all(target.parent().unwrap())?;
            if util::is_symlink(&source) {
                std::os::unix::fs::symlink(fs::read_link(&source)?, &target)?;
            } else {
                ensure!(source.is_file(), "{relative}");
                util::copy2(&source, &target)?;
                hashes.insert(relative.clone(), json!(sha(&target)?));
            }
        }
        preserve_directory_modes(&files, &root)?;
        let version = package.str_field("version")?;
        let apk_output = out.join(format!("{name}-{version}.apk"));
        let mut command = strings([util::display(&apk), "mkpkg".into(), "--files".into(), util::display(&files),
                                   "--output".into(), util::display(&apk_output)]);
        for (key, value) in package.as_object().unwrap() {
            let text = match value {
                Value::Array(items) => items.iter().map(|item| item.as_str().unwrap_or_default()).collect::<Vec<_>>().join(" "),
                other => other.as_str().unwrap_or_default().to_owned(),
            };
            command.extend(["--info".into(), format!("{key}:{text}")]);
        }
        util::run_checked(&command, None, None)?;
        provenance.insert(name.into(), json!({"version": version, "payload_sha256": hashes, "apk_sha256": sha(&apk_output)?}));
    }
    util::copy2(&native_apk, &out.join(native_apk.file_name().unwrap()))?;
    util::write_json(&out.join("fixture-provenance.json"),
                     &json!({"purpose": "unsigned exact-image payload fixtures; --no-scripts tests only", "packages": provenance}))?;
    let mut command = strings([util::display(&apk), "--allow-untrusted".into(), "mkndx".into(), "--output".into(),
                               util::display(&out.join("packages.adb"))]);
    command.extend(sorted_dir(&out)?.into_iter().filter(|p| p.extension().is_some_and(|e| e == "apk")).map(|p| util::display(&p)));
    util::run_checked(&command, None, None)?;
    println!("Prepared {} original payload fixtures plus native APK and offline index", names.len());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reinstall_negative_controls_still_find_tmpfs_fixture_commands() {
        // Adding a global APK option must not bypass the no-op test.
        let script = "apk --no-scripts --no-network --allow-untrusted --force-non-repository \
                      --repositories-file /dev/null add --force-reinstall /tmp/native-apks/fixture.apk\n\
                      sha256sum -c /usr/share/owrt-control-plane/rust.sha256\n";
        let rewritten = skip_reinstall(script).unwrap();
        assert!(!rewritten.contains("add --force-reinstall"));
        assert!(rewritten.contains("sha256sum -c"));
        assert!(skip_reinstall("sha256sum -c x\n").is_err());
        assert!(skip_reinstall(&format!("{script}{script}")).is_err());
    }
}
