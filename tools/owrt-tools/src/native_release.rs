//! `owrt-tools native-release-prepare CANONICAL VALIDATION TAG EVIDENCE OUTPUT`:
//! prepare a GitHub Release from an already qualified native firmware
//! artifact (the historical nine-component tag contract).
//!
//! Never rebuilds firmware or contacts a router/GitHub. Publication is a
//! separate step after checking the complete asset set and annotated tag.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::util::{self, ensure, strings, Args, JsonExt, Result};

const REPO_URL: &str = "https://github.com/WenliangCao/owrt-rs";

pub fn release_version(tag: &str) -> Result<String> {
    let pattern = Regex::new(r"^ax3000t-rust9-v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$")?;
    let captures = pattern.captures(tag).ok_or_else(|| util::Error::new("expected stable tag ax3000t-rust9-vMAJOR.MINOR.PATCH"))?;
    Ok(captures[1].to_owned())
}

fn sha(path: &Path) -> Result<String> {
    util::sha256_file(path)
}

fn positive_count(value: &Value, what: &str) -> Result<u64> {
    value.as_u64().filter(|count| *count > 0).ok_or_else(|| util::Error::new(format!("{what} must be a positive integer")))
}

fn git(args: &[&str]) -> Result<String> {
    let mut command = strings(["git", "-C", &util::display(&util::repo())]);
    command.extend(args.iter().map(|arg| (*arg).to_owned()));
    util::output(&command, None, None)
}

fn archive(output: &Path, inputs: &[PathBuf]) -> Result<()> {
    let file = fs::File::create(output)?;
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(file, flate2::Compression::default()));
    let mut sums = String::new();
    for path in inputs {
        let name = path.file_name().unwrap();
        builder.append_path_with_name(path, name)?;
        sums += &format!("{}  {}\n", sha(path)?, name.to_string_lossy());
    }
    let mut header = tar::Header::new_gnu();
    header.set_size(sums.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, "SHA256SUMS", sums.as_bytes())?;
    builder.into_inner()?.finish()?;
    Ok(())
}

pub fn prepare(canonical: &Path, validation_path: &Path, tag: &str, evidence_commit: &str, out: &Path) -> Result<Value> {
    let manifest = util::read_json(&canonical.join("manifest.json"))?;
    let validation = util::read_json(validation_path)?;
    ensure!(manifest["deployment_layout"] == "native-nine", "not a native-nine artifact");
    ensure!(validation["status"] == "native_nine_firmware_qualified_and_cleaned", "firmware not qualified");
    ensure!(validation["firmware_source_commit"] == manifest["source_commit"], "validation names another source commit");
    ensure!(validation["firmware_sha256"] == manifest["image"]["sha256"], "validation names another firmware");
    ensure!(validation["scope"]["physical_power_cycle_tested"] == true, "power cycle not tested");
    ensure!(validation["cleanup"]["temporary_guard_removed"] == true, "temporary guard not removed");
    ensure!(validation["cleanup"]["C_fallback_occurred"] == false, "C fallback occurred");
    let version = release_version(tag)?;
    ensure!(manifest["profile"] == "xiaomi_mi-router-ax3000t", "wrong hardware profile");
    let openwrt = manifest.str_field("openwrt")?;
    ensure!(Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$")?.is_match(openwrt), "invalid OpenWrt version");
    let package_version = manifest["packages"].str_field("owrt-control-plane")?;
    let identity = &validation["firmware_identity"];
    let rom_files = positive_count(&identity["ROM_regular_file_hashes_match_canonical"], "ROM file count")?;
    let package_count = positive_count(&identity["installed_package_versions_match_canonical"], "package count")?;
    let config_count = &validation["configuration"]["config_files_unchanged"];
    let protected_count = &validation["configuration"]["other_protected_files_unchanged"];
    let source = manifest.str_field("source_commit")?;
    let evidence = git(&["rev-parse", &format!("{evidence_commit}^{{commit}}")])?.trim().to_owned();
    for line in util::read_text(&canonical.join("SHA256SUMS"))?.lines() {
        let (digest, name) = line.split_once(char::is_whitespace).ok_or_else(|| util::Error::new("malformed SHA256SUMS"))?;
        let name = name.trim_start();
        ensure!(Path::new(name).file_name().is_some_and(|n| n == name) && sha(&canonical.join(name))? == digest, "{name}");
    }
    fs::create_dir_all(out.parent().unwrap())?;
    fs::create_dir(out)?;
    let image = manifest.field("image")?;
    let filename = format!("owrt-rust9-v{version}-openwrt-{openwrt}-ax3000t-sysupgrade.bin");
    let firmware = out.join(&filename);
    util::copy2(&canonical.join(image.str_field("file")?), &firmware)?;
    ensure!(image["sha256"] == sha(&firmware)?.as_str(), "firmware copy differs");
    ensure!(image["size"] == fs::metadata(&firmware)?.len(), "firmware size differs");
    let mut components = Map::new();
    for (name, data) in manifest.obj_field("components")? {
        let cargo: toml::Value = toml::from_str(&git(&["show", &format!("{source}:components/{name}/Cargo.toml")])?)?;
        let package = &cargo["package"];
        let mut record = json!({"crate": package["name"].as_str(), "crate_version": package["version"].as_str()});
        for key in ["path", "rust_sha256", "rust_bytes", "stock_sha256", "stock_package", "recovery_path"] {
            record[key] = data.field(key)?.clone();
        }
        components.insert(name.clone(), record);
    }
    fs::write(out.join("components.sha256"), components.values()
        .map(|c| format!("{}  {}\n", c["rust_sha256"].as_str().unwrap_or_default(), c["path"].as_str().unwrap_or_default()))
        .collect::<String>())?;
    util::copy2(validation_path, &out.join("validation-summary.json"))?;
    // Preserve the canonical build metadata unchanged, including its original
    // filename and build-time flashed:false field. Actual acceptance is separate.
    let mut inputs: Vec<PathBuf> = ["manifest.json", "build-inputs.json", "binary-sha256.txt"].iter().map(|n| canonical.join(n)).collect();
    let mut apks: Vec<&String> = manifest.obj_field("apk_sha256")?.keys().collect();
    apks.sort();
    inputs.extend(apks.iter().map(|name| canonical.join(name)));
    archive(&out.join("build-inputs-and-packages.tar.gz"), &inputs)?;
    let canonical_run = &validation["canonical_run"];
    let run_url = format!("{REPO_URL}/actions/runs/{canonical_run}");
    let firmware_sha = sha(&firmware)?;
    let result = json!({
        "schema": 1, "release_tag": tag, "release_kind": "qualified native AX3000T firmware milestone",
        "build_source_commit": source, "tag_target_commit": source, "evidence_commit": evidence,
        "canonical_run_url": run_url,
        "firmware": {"file": filename, "canonical_filename": image["file"], "bytes": image["size"],
                     "sha256": firmware_sha, "rebuilt_for_release": false},
        "openwrt": openwrt, "profile": manifest["profile"], "layout": "native-nine",
        "unified_package": {"name": "owrt-control-plane", "version": package_version},
        "components": components, "stock_packages": manifest["stock_packages"],
        "stock_image": manifest["stock_image"], "kernel_sha256": manifest["kernel_sha256"], "toolchain": manifest["toolchain"],
        "qualification": {"keep_config_flash_passed": true, "ROM_files_verified": rom_files,
                          "installed_package_versions_verified": package_count,
                          "continuous_client_health_s": validation["continuous_client_health_s"],
                          "physical_power_trials_observed": validation["physical_retest"]["successful_trials_observed"],
                          "temporary_trial_tools_removed": true, "private_configuration_included": false},
    });
    fs::write(out.join("release-manifest.json"), util::pretty_json_unicode(&result) + "\n")?;
    let rows: Vec<String> = components.iter().map(|(name, c)| format!(
        "| {name} | {} | `{}` | `{}` |", c["crate_version"].as_str().unwrap_or_default(), c["path"].as_str().unwrap_or_default(),
        &c["rust_sha256"].as_str().unwrap_or_default()[..12])).collect();
    let rows = rows.join("\n");
    let size_mib = image["size"].as_f64().unwrap_or(0.0) / 1_048_576.0;
    let apk_count = manifest["apk_sha256"].as_object().map_or(0, Map::len);
    let notes = format!(r#"# AX3000T Rust9 v{version} · OpenWrt {openwrt}

完整九组件 Rust 固件回溯节点。已在 Xiaomi AX3000T 上保留配置刷入，客户端连续验收和用户断电/WAN 重接复测通过。发布镜像与真机已验收的文件逐字节相同。

**下载固件：`{filename}`（{size_mib:.2} MiB）。** 通常只需这个文件；其余附件用于核验、审计和恢复。

| 身份 | 固定值 |
|---|---|
| Release / Git 标签 | `{tag}` |
| 实际构建提交、标签目标 | [`{source}`]({REPO_URL}/commit/{source}) |
| 正式构建 | [release-image {canonical_run}]({run_url}) |
| 验收与发布工具提交 | [`{evidence}`]({REPO_URL}/commit/{evidence}) |
| 统一软件包 | `owrt-control-plane {package_version}` |
| 固件 SHA256 | `{firmware_sha}` |

内核、驱动和成熟执行面保留 OpenWrt {openwrt} 基底。九个 Rust 程序直接安装在标准路径，由统一软件包管理；没有逐组件绑定挂载。镜像不含个人网络配置、密码、私钥或试验采集工具。

| 组件 | crate 版本 | 安装路径 | ELF SHA256 前 12 位 |
|---|---|---|---|
{rows}

完整哈希和字节数在 `release-manifest.json`，可执行路径校验清单在 `components.sha256`。crate 版本来自构建提交中的 Cargo.toml，精确二进制身份以 SHA256 为准。

已核对真机 ROM 的 {rom_files} 个普通文件和 {package_count} 个软件包版本。{config_count} 份系统配置及 {protected_count} 份额外保护文件保持一致。完整验收项目、样本与边界见附件 `validation-summary.json`；其对应的证据提交为 [`{evidence}`]({REPO_URL}/commit/{evidence})。

回到此节点时，先保存当前配置，下载上述固件并核对 `SHA256SUMS`，再通过 LuCI 固件升级选择保留配置刷入。适用设备是原厂 bootloader 布局的 Xiaomi Mi Router AX3000T，profile 为 `xiaomi_mi-router-ax3000t`。个人配置独立于发布镜像保存。

`RECOVERY.md` 提供恢复说明；`build-inputs-and-packages.tar.gz` 保存原始构建 manifest、工具链输入和 {apk_count} 个镜像装配 APK。包用于归档与离线装配，日常安装入口为整份固件。

这个标签固定在实际构建提交上，不重新指向后续研究代码；后续固件使用新的发布版本。此次直接发布原有正式构建产物，没有重新构建镜像。
"#);
    fs::write(out.join("RELEASE_NOTES.md"), notes)?;
    let stock_url = manifest["stock_image"].str_field("url")?;
    let stock_sha = manifest["stock_image"].str_field("sha256")?;
    let recovery = format!(r#"# AX3000T Rust9 v{version} 恢复说明

回到已验证的九组件 Rust 固件：下载 `{filename}`，校验 SHA256 `{firmware_sha}`，保存当前配置后通过标准 sysupgrade/LuCI 保留配置刷入。

只将九组件恢复为镜像保存的原版实现时，SSH 登录后执行：

```sh
owrt-recover-c
# 确认工具成功准备全部九个原件后：
reboot
```

工具保留配置，先校验全部原件并准备副本，再替换标准入口。failsafe 中先 `mount_root`，恢复成功后使用 `reboot -f`。原件位于 `/usr/libexec/owrt-stock/`；本镜像的 `/rom/sbin/*` 已是 Rust，不是 C 恢复来源。

恢复出厂会清空个人配置，回到镜像内置的 Rust 默认栈。长期恢复整个官方系统可使用固定的官方 {openwrt} 镜像：

- [官方 AX3000T 固件]({stock_url})
- SHA256：`{stock_sha}`

按键、failsafe 和 TFTP 的离线步骤见[对应验收提交的恢复手册]({REPO_URL}/blob/{evidence}/docs/RUNBOOK_AX3000T_RECOVERY.md)。当前正式运行状态没有临时试验自动回退服务。
"#);
    fs::write(out.join("RECOVERY.md"), recovery)?;
    let mut entries: Vec<PathBuf> = fs::read_dir(out)?.map(|e| e.map(|e| e.path())).collect::<Result<_, _>>()?;
    entries.sort();
    let mut sums = String::new();
    for path in entries.iter().filter(|path| path.is_file()) {
        sums += &format!("{}  {}\n", sha(path)?, path.file_name().unwrap().to_string_lossy());
    }
    fs::write(out.join("SHA256SUMS"), sums)?;
    Ok(json!({"tag": tag, "build_source_commit": source, "evidence_commit": evidence, "firmware_sha256": firmware_sha,
              "assets": fs::read_dir(out)?.count()}))
}

pub fn main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &[], &[])?;
    let [canonical, validation, tag, evidence, output] =
        args.exact(&["CANONICAL", "VALIDATION", "TAG", "EVIDENCE_COMMIT", "OUTPUT"])?.try_into().expect("five positionals");
    let summary = prepare(&fs::canonicalize(&canonical)?, Path::new(&validation), &tag, &evidence, &std::path::absolute(&output)?)?;
    println!("{}", util::line_json(&summary));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    struct Fixture {
        _temp: TempDir,
        canonical: PathBuf,
        output: PathBuf,
        validation_path: PathBuf,
        source: String,
        manifest: Value,
        validation: Value,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = TempDir::new("release");
            let canonical = temp.path().join("canonical");
            fs::create_dir(&canonical).unwrap();
            let source = git(&["rev-parse", "HEAD"]).unwrap().trim().to_owned();
            let firmware = b"synthetic firmware fixture\n";
            fs::write(canonical.join("fixture.bin"), firmware).unwrap();
            let mut components = util::read_json(&util::repo().join("packaging/image/native-25.12.5.json")).unwrap()["components"].clone();
            let map = components.as_object_mut().unwrap();
            map.shift_remove("dnsmasq"); // This helper retains the historical Rust9 tag contract.
            for value in map.values_mut() {
                value["rust_sha256"] = json!("0".repeat(64));
                value["rust_bytes"] = json!(1);
                value["recovery_path"] = json!(format!("/usr/libexec/owrt-stock{}", value["path"].as_str().unwrap()));
            }
            let digest = util::sha256_bytes(firmware);
            let manifest = json!({
                "deployment_layout": "native-nine", "source_commit": source, "openwrt": "25.12.6",
                "profile": "xiaomi_mi-router-ax3000t", "packages": {"owrt-control-plane": "0.2.3-r4"},
                "image": {"file": "fixture.bin", "size": firmware.len(), "sha256": digest},
                "components": components, "apk_sha256": {}, "stock_packages": {},
                "stock_image": {"url": "https://example.invalid/fixture.bin", "sha256": "1".repeat(64)},
                "kernel_sha256": "2".repeat(64), "toolchain": {"fixture": true}});
            let validation = json!({
                "status": "native_nine_firmware_qualified_and_cleaned", "firmware_source_commit": source,
                "firmware_sha256": digest, "scope": {"physical_power_cycle_tested": true},
                "cleanup": {"temporary_guard_removed": true, "C_fallback_occurred": false}, "canonical_run": 123,
                "firmware_identity": {"ROM_regular_file_hashes_match_canonical": 923, "installed_package_versions_match_canonical": 167},
                "configuration": {"config_files_unchanged": 21, "other_protected_files_unchanged": 11},
                "continuous_client_health_s": 181, "physical_retest": {"successful_trials_observed": 2}});
            fs::write(canonical.join("build-inputs.json"), "{}\n").unwrap();
            fs::write(canonical.join("binary-sha256.txt"), "synthetic fixture\n").unwrap();
            let fixture = Self { output: temp.path().join("release"), validation_path: temp.path().join("validation.json"),
                                 canonical, _temp: temp, source, manifest, validation };
            fixture.save();
            fixture
        }

        fn save(&self) {
            fs::write(self.canonical.join("manifest.json"), self.manifest.to_string()).unwrap();
            fs::write(&self.validation_path, self.validation.to_string()).unwrap();
            let mut entries: Vec<PathBuf> = fs::read_dir(&self.canonical).unwrap().map(|e| e.unwrap().path())
                .filter(|p| p.file_name().unwrap() != "SHA256SUMS").collect();
            entries.sort();
            fs::write(self.canonical.join("SHA256SUMS"), entries.iter()
                .map(|p| format!("{}  {}\n", sha(p).unwrap(), p.file_name().unwrap().to_string_lossy())).collect::<String>()).unwrap();
        }

        fn run(&self, tag: &str) -> Result<Value> {
            prepare(&self.canonical, &self.validation_path, tag, &self.source, &self.output)
        }
    }

    #[test]
    fn next_release_uses_actual_versions_counts_and_image() {
        let fixture = Fixture::new();
        fixture.run("ax3000t-rust9-v0.2.3").unwrap();
        let out = &fixture.output;
        let release = util::read_json(&out.join("release-manifest.json")).unwrap();
        assert_eq!(release["unified_package"]["version"], "0.2.3-r4");
        assert_eq!(release["qualification"]["ROM_files_verified"], 923);
        assert_eq!(release["qualification"]["installed_package_versions_verified"], 167);
        let firmware = out.join("owrt-rust9-v0.2.3-openwrt-25.12.6-ax3000t-sysupgrade.bin");
        assert_eq!(fs::read(firmware).unwrap(), fs::read(fixture.canonical.join("fixture.bin")).unwrap());
        let notes = fs::read_to_string(out.join("RELEASE_NOTES.md")).unwrap();
        assert!(notes.contains("21 份系统配置及 11 份额外保护文件"));
        assert!(!notes.contains("v0.1.0") && !notes.contains("12.17 MiB"));
        for line in fs::read_to_string(out.join("SHA256SUMS")).unwrap().lines() {
            let (digest, name) = line.split_once("  ").unwrap();
            assert_eq!(sha(&out.join(name)).unwrap(), digest);
        }
    }

    #[test]
    fn mismatched_validation_source_is_rejected() {
        let mut fixture = Fixture::new();
        fixture.validation["firmware_source_commit"] = json!("f".repeat(40));
        fixture.save();
        assert!(fixture.run("ax3000t-rust9-v0.2.3").is_err());
        assert!(!fixture.output.exists());
    }

    #[test]
    fn corrupt_artifact_is_rejected() {
        let fixture = Fixture::new();
        fs::write(fixture.canonical.join("fixture.bin"), "corrupted").unwrap();
        assert!(fixture.run("ax3000t-rust9-v0.2.3").is_err());
        assert!(!fixture.output.exists());
    }

    #[test]
    fn wrong_hardware_profile_is_rejected() {
        let mut fixture = Fixture::new();
        fixture.manifest["profile"] = json!("unrelated-router");
        fixture.save();
        assert!(fixture.run("ax3000t-rust9-v0.2.3").is_err());
        assert!(!fixture.output.exists());
    }

    #[test]
    fn unexpected_tag_is_rejected() {
        let fixture = Fixture::new();
        assert!(fixture.run("v0.2.3").is_err());
        assert!(!fixture.output.exists());
    }
}
