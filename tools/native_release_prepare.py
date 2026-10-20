#!/usr/bin/env python3
"""Prepare a GitHub Release from an already qualified native firmware artifact.

Never rebuilds firmware or contacts a router/GitHub. Publication is a separate
step after checking the complete asset set and annotated source tag.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def release_version(tag):
    match = re.fullmatch(r"ax3000t-rust9-v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))", tag)
    if not match:
        raise ValueError("expected stable tag ax3000t-rust9-vMAJOR.MINOR.PATCH")
    return match[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("canonical", type=Path)
    parser.add_argument("validation", type=Path)
    parser.add_argument("tag")
    parser.add_argument("evidence_commit")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    canonical, out = args.canonical.resolve(), args.output.resolve()
    manifest = json.loads((canonical / "manifest.json").read_text())
    validation = json.loads(args.validation.read_text())
    assert manifest["deployment_layout"] == "native-nine"
    assert validation["status"] == "native_nine_firmware_qualified_and_cleaned"
    assert validation["firmware_source_commit"] == manifest["source_commit"]
    assert validation["firmware_sha256"] == manifest["image"]["sha256"]
    assert validation["scope"]["physical_power_cycle_tested"]
    assert validation["cleanup"]["temporary_guard_removed"]
    assert not validation["cleanup"]["C_fallback_occurred"]
    version = release_version(args.tag)
    assert manifest["profile"] == "xiaomi_mi-router-ax3000t"
    openwrt = manifest["openwrt"]
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", openwrt)
    package_version = manifest["packages"]["owrt-control-plane"]
    identity = validation["firmware_identity"]
    rom_files = identity["ROM_regular_file_hashes_match_canonical"]
    package_count = identity["installed_package_versions_match_canonical"]
    assert type(rom_files) is int and rom_files > 0
    assert type(package_count) is int and package_count > 0
    config_count = validation["configuration"]["config_files_unchanged"]
    protected_count = validation["configuration"]["other_protected_files_unchanged"]
    source = manifest["source_commit"]
    evidence = subprocess.check_output(["git", "rev-parse", args.evidence_commit + "^{commit}"], text=True).strip()
    for line in (canonical / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(None, 1)
        assert Path(name).name == name and sha(canonical / name) == digest, name
    out.mkdir(parents=True, exist_ok=False)
    filename = f"owrt-rust9-v{version}-openwrt-{openwrt}-ax3000t-sysupgrade.bin"
    shutil.copy2(canonical / manifest["image"]["file"], out / filename)
    assert sha(out / filename) == manifest["image"]["sha256"]
    assert (out / filename).stat().st_size == manifest["image"]["size"]
    components = {}
    for name, data in manifest["components"].items():
        cargo = tomllib.loads(subprocess.check_output(
            ["git", "show", f"{source}:components/{name}/Cargo.toml"], text=True))
        components[name] = {"crate": cargo["package"]["name"], "crate_version": cargo["package"]["version"],
                            **{key: data[key] for key in ("path", "rust_sha256", "rust_bytes", "stock_sha256", "stock_package", "recovery_path")}}
    (out / "components.sha256").write_text("".join(f"{c['rust_sha256']}  {c['path']}\n" for c in components.values()))
    shutil.copy2(args.validation, out / "validation-summary.json")
    # Preserve the canonical build metadata unchanged, including its original
    # filename and build-time flashed:false field. Actual acceptance is separate.
    inputs = [canonical / n for n in ("manifest.json", "build-inputs.json", "binary-sha256.txt")]
    inputs += [canonical / n for n in sorted(manifest["apk_sha256"])]
    with tarfile.open(out / "build-inputs-and-packages.tar.gz", "w:gz") as archive:
        for p in inputs:
            archive.add(p, arcname=p.name, recursive=False)
        sums = "".join(f"{sha(p)}  {p.name}\n" for p in inputs).encode()
        member = tarfile.TarInfo("SHA256SUMS")
        member.size, member.mode = len(sums), 0o644
        archive.addfile(member, io.BytesIO(sums))
    repo = "https://github.com/WenliangCao/owrt-rs"
    result = {"schema": 1, "release_tag": args.tag, "release_kind": "qualified native AX3000T firmware milestone",
              "build_source_commit": source, "tag_target_commit": source, "evidence_commit": evidence,
              "canonical_run_url": f"{repo}/actions/runs/{validation['canonical_run']}",
              "firmware": {"file": filename, "canonical_filename": manifest["image"]["file"],
                           "bytes": manifest["image"]["size"], "sha256": sha(out / filename), "rebuilt_for_release": False},
              "openwrt": manifest["openwrt"], "profile": manifest["profile"], "layout": "native-nine",
              "unified_package": {"name": "owrt-control-plane", "version": package_version},
              "components": components, "stock_packages": manifest["stock_packages"],
              "stock_image": manifest["stock_image"], "kernel_sha256": manifest["kernel_sha256"],
              "toolchain": manifest["toolchain"],
              "qualification": {"keep_config_flash_passed": True, "ROM_files_verified": rom_files,
                                "installed_package_versions_verified": package_count,
                                "continuous_client_health_s": validation["continuous_client_health_s"],
                                "physical_power_trials_observed": validation["physical_retest"]["successful_trials_observed"],
                                "temporary_trial_tools_removed": True, "private_configuration_included": False}}
    (out / "release-manifest.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    rows = "\n".join(f"| {name} | {c['crate_version']} | `{c['path']}` | `{c['rust_sha256'][:12]}` |" for name, c in components.items())
    notes = f'''# AX3000T Rust9 v{version} · OpenWrt {openwrt}

完整九组件 Rust 固件回溯节点。已在 Xiaomi AX3000T 上保留配置刷入，客户端连续验收和用户断电/WAN 重接复测通过。发布镜像与真机已验收的文件逐字节相同。

**下载固件：`{filename}`（{manifest['image']['size'] / 1048576:.2f} MiB）。** 通常只需这个文件；其余附件用于核验、审计和恢复。

| 身份 | 固定值 |
|---|---|
| Release / Git 标签 | `{args.tag}` |
| 实际构建提交、标签目标 | [`{source}`]({repo}/commit/{source}) |
| 正式构建 | [release-image {validation['canonical_run']}]({result['canonical_run_url']}) |
| 验收与发布工具提交 | [`{evidence}`]({repo}/commit/{evidence}) |
| 统一软件包 | `owrt-control-plane {package_version}` |
| 固件 SHA256 | `{result['firmware']['sha256']}` |

内核、驱动和成熟执行面保留 OpenWrt {openwrt} 基底。九个 Rust 程序直接安装在标准路径，由统一软件包管理；没有逐组件绑定挂载。镜像不含个人网络配置、密码、私钥或试验采集工具。

| 组件 | crate 版本 | 安装路径 | ELF SHA256 前 12 位 |
|---|---|---|---|
{rows}

完整哈希和字节数在 `release-manifest.json`，可执行路径校验清单在 `components.sha256`。crate 版本来自构建提交中的 Cargo.toml，精确二进制身份以 SHA256 为准。

已核对真机 ROM 的 {rom_files} 个普通文件和 {package_count} 个软件包版本。{config_count} 份系统配置及 {protected_count} 份额外保护文件保持一致。完整验收项目、样本与边界见附件 `validation-summary.json`；其对应的证据提交为 [`{evidence}`]({repo}/commit/{evidence})。

回到此节点时，先保存当前配置，下载上述固件并核对 `SHA256SUMS`，再通过 LuCI 固件升级选择保留配置刷入。适用设备是原厂 bootloader 布局的 Xiaomi Mi Router AX3000T，profile 为 `xiaomi_mi-router-ax3000t`。个人配置独立于发布镜像保存。

`RECOVERY.md` 提供恢复说明；`build-inputs-and-packages.tar.gz` 保存原始构建 manifest、工具链输入和 {len(manifest['apk_sha256'])} 个镜像装配 APK。包用于归档与离线装配，日常安装入口为整份固件。

这个标签固定在实际构建提交上，不重新指向后续研究代码；后续固件使用新的发布版本。此次直接发布原有正式构建产物，没有重新构建镜像。
'''
    (out / "RELEASE_NOTES.md").write_text(notes)
    recovery = f'''# AX3000T Rust9 v{version} 恢复说明

回到已验证的九组件 Rust 固件：下载 `{filename}`，校验 SHA256 `{result['firmware']['sha256']}`，保存当前配置后通过标准 sysupgrade/LuCI 保留配置刷入。

只将九组件恢复为镜像保存的原版实现时，SSH 登录后执行：

```sh
owrt-recover-c
# 确认工具成功准备全部九个原件后：
reboot
```

工具保留配置，先校验全部原件并准备副本，再替换标准入口。failsafe 中先 `mount_root`，恢复成功后使用 `reboot -f`。原件位于 `/usr/libexec/owrt-stock/`；本镜像的 `/rom/sbin/*` 已是 Rust，不是 C 恢复来源。

恢复出厂会清空个人配置，回到镜像内置的 Rust 默认栈。长期恢复整个官方系统可使用固定的官方 {openwrt} 镜像：

- [官方 AX3000T 固件]({manifest['stock_image']['url']})
- SHA256：`{manifest['stock_image']['sha256']}`

按键、failsafe 和 TFTP 的离线步骤见[对应验收提交的恢复手册]({repo}/blob/{evidence}/docs/RUNBOOK_AX3000T_RECOVERY.md)。当前正式运行状态没有临时试验自动回退服务。
'''
    (out / "RECOVERY.md").write_text(recovery)
    (out / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.name}\n" for p in sorted(out.iterdir()) if p.is_file()))
    print(json.dumps({"tag": args.tag, "build_source_commit": source, "evidence_commit": evidence,
                      "firmware_sha256": result["firmware"]["sha256"], "assets": len(list(out.iterdir()))}))


if __name__ == "__main__":
    main()
