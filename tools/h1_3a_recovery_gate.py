#!/usr/bin/env python3
"""Validate the offline-only H1.3a recovery candidate evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
BUILDROOT_COMMIT = "f0a60eee2fe051741c643ea6118718aae1ef17fb"
EXPECTED_FEEDS = {
    "packages": "5caa62e0bc9f7fb9b0c12a23267bceb7724214dd",
    "luci": "128a7812f4be233c5dd7f7466f534fd888785caf",
    "routing": "3d7d0dc7fa43d3eb09498417407e95a6552e5312",
    "telephony": "2618106d5846a4a542fdf5809f0d3ed228ce439b",
    "video": "094bf58da6682f895255a35a84349a79dab4bf95",
}
EXPECTED_PATCH_SHA256 = "e4e2051510864c6fdd18ff0db6b3aa792b75398d9fd1ca51e0b7bf1eeed9454e"
EXPECTED_FRAGMENT_SHA256 = "570242ff4fba6485b8a12b15834a38a52f3413ec4f680f58d13306aa256b39d2"
EXPECTED_RESOLVED_CONFIG_SHA256 = "b19c3ebb08e68c86d98bce271f5d5a0f6fb5f8bf5d7b65998ac5eeb7121afe4e"
EXPECTED_ARTIFACT_SHA256 = "c9ce88f597dea3e552c05cdcf9ed2d3f9683161731dc12747cc7627783247a5a"
EXPECTED_ARTIFACT_SIZE = 8762644
EXPECTED_NANDDUMP_SHA256 = "21d7c3daa9e792a9b892af956ce64c59c4588c99eb7084b93ef5ee6f4bd47b92"
EXPECTED_PROFILE_SYMBOL = "CONFIG_TARGET_mediatek_filogic_DEVICE_xiaomi_mi-router-ax3000t"
EXPECTED_BUILD_LOG_HASHES = {
    "final_build_log_sha256": "dc84ff7e2599e5f18c57902311f21e2090e2f2239d9acb610c585df497c8d06b",
    "repeat_build_log_sha256": "3bbc824b0206a56d5dc707004ccd510d1962b13a2aeef2d5c40616a04546ecb8",
    "target_install_log_sha256": "23ccddae6f3b5e12fb217dd0cfae06159a6aabdfed9a6585aab95e0b35c8ec6c",
}
EXPECTED_SOURCE_DIFF_PATHS = {
    "target/linux/generic/files/drivers/mtd/nand/mtk_bmt.c",
    "target/linux/generic/files/drivers/mtd/nand/mtk_bmt.h",
    "target/linux/generic/files/drivers/mtd/nand/mtk_bmt_nmbm.c",
    "target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t.dts",
    "target/linux/mediatek/image/filogic.mk",
}
EXPECTED_COMPILED_HASHES = {
    "mtk_bmt.o": "dbd88d739ca958f33030f7cf377438ad759e5ca63a45473f81ce5829cb43900f",
    "mtk_bmt_nmbm.o": "7ebaa9bce7d2567c88d73fd0b28468b584396368ee3cca09214256eb54205816",
    "vmlinux": "73fffdaa4444d29bc94c0ae1da27829eae8270eabbd93ff648d186b16b99242a",
}
EXPECTED_COMPILED_PATHS = {
    "mtk_bmt.o": "drivers/mtd/nand/mtk_bmt.o",
    "mtk_bmt_nmbm.o": "drivers/mtd/nand/mtk_bmt_nmbm.o",
    "vmlinux": "vmlinux",
}
EXPECTED_FIT_NODE_HASHES = {
    "kernel_sha256": "21ecd3cfdd065d29c3952085da6cc4c3215ceaa07f5d6ad71196869d68498cc8",
    "initrd_sha256": "33342a60726c7d080bcc90b241203d356ac5c76bfc4bcae2c76d1ebdaab15831",
    "dtb_sha256": "24baeee85660620f97323ad76b8fcb0527985c279bb8f26872bf67719a9d1717",
}
EXPECTED_OVERLAY_HASHES = {
    "etc/init.d/bootcount": "8885cf1df3ea8724a41dbddbe7bd14e5f534de56ace06631634fd78c7bcd07e7",
    "etc/init.d/done": "c12ef41bc3b2dcba6753d8844be456fb5dae39d268d91669c46e724b1009e1bf",
    "etc/init.d/ubihealthd": "ef0c9cb8d5d08f5db8a73598f9d8534ce0d4cfc45516491a2847ea96c752e5b6",
    "etc/uci-defaults/ubihealthd": "6d4021868f566c89c2fb4f2328d34f3983c22acd3b7a9fe679097fe0652bb4cb",
    "lib/preinit/07_trigger_fip_scrubbing": "ee91d8a8e4531acdc2c14ae25d1696374d41ededaeb254ed216dd19910fe57e0",
    "lib/preinit/80_mount_root": "cdb85e48bd14be15bf2a07594678b8f480d14252aed96f922c9b44ccdb1caab5",
}
EXPECTED_PARTITIONS = {
    "BL2",
    "Nvram",
    "Bdata",
    "Factory",
    "FIP",
    "crash",
    "crash_log",
    "ubi_kernel",
    "ubi",
    "KF",
}
EXPECTED_GUARDS = {
    "mtd_master_writeable_cleared_before_attach",
    "bmt_write_returns_erofs",
    "bmt_erase_returns_erofs",
    "bmt_markbad_returns_erofs",
    "bmt_read_remap_disabled",
    "bmt_badblock_remap_disabled",
    "bmt_debugfs_disabled",
    "nmbm_phys_write_disabled",
    "nmbm_phys_erase_disabled",
    "nmbm_phys_markbad_disabled",
    "nmbm_map_and_remap_disabled",
    "nmbm_attach_repair_disabled",
    "nmbm_create_fails_closed",
}
EXPECTED_FORBIDDEN_HELPERS = {
    "flash_erase",
    "nandbiterrs",
    "nandtest",
    "nandwrite",
}
EXPECTED_PRESENT_MUTATORS = {
    "sbin/mtd",
    "sbin/sysupgrade",
    "usr/sbin/ubiattach",
    "usr/sbin/ubidetach",
    "usr/sbin/ubiformat",
    "usr/sbin/ubimkvol",
    "usr/sbin/ubirename",
    "usr/sbin/ubirmvol",
    "usr/sbin/ubirsvol",
    "usr/sbin/ubiupdatevol",
}
EXPECTED_DISABLED_AUTOMATIC_PATHS = {
    "boot_environment_update",
    "persistent_overlay_mount",
    "mount_root_done",
    "ubi_health_scan",
    "fip_read_scrub",
}
FALSE_SCOPE = {
    "bootloader_commands",
    "device_contact",
    "device_execution",
    "device_transfer",
    "device_writes",
    "firmware_flash",
    "router_reboot",
}
FALSE_GATES = {
    "commands_authorized",
    "device_writes_allowed",
    "firmware_flash_allowed",
    "h1_2_private_backup",
    "h1_3b_ram_boot",
    "recovery_boot_verified",
    "router_contact_allowed",
    "router_reboot_allowed",
}
PATCH_MARKERS = (
    'of_property_read_bool(np, "mediatek,bmt-read-only")',
    "mtd->flags &= ~MTD_WRITEABLE;",
    "if (bmtd.read_only)\n+\t\treturn -EROFS;",
    "if (ni->protected)\n+\t\treturn false;",
    "Forced read-only mode; skipping info-table repair",
    "No valid info table in forced read-only mode",
    "mediatek,bmt-read-only;",
    "&wifi {",
    'status = "disabled";',
    "The H1 recovery build deliberately emits only the RAM-loadable initramfs.",
)
CONFIG_LINES = (
    "CONFIG_TARGET_mediatek=y",
    "CONFIG_TARGET_mediatek_filogic=y",
    "# CONFIG_TARGET_MULTI_PROFILE is not set",
    f"{EXPECTED_PROFILE_SYMBOL}=y",
    "CONFIG_TARGET_ROOTFS_INITRAMFS=y",
    "# CONFIG_TARGET_ROOTFS_SQUASHFS is not set",
    "# CONFIG_TARGET_ROOTFS_EROFS is not set",
    "CONFIG_PACKAGE_dropbear=y",
)
REPORT_MARKERS = (
    "passed_offline_static_only",
    "没有连接、重启或修改路由器",
    "attach 返回值被 SPI-NAND probe 忽略",
    "不是运行态零写入证明",
    "H1.3b",
)
RUNBOOK_MARKERS = (
    "H1.3a：离线只读 recovery candidate",
    "H1.3b：RAM boot 运行态验证",
    "recovery_boot_verified=false",
)


class GateError(RuntimeError):
    """Raised when an H1.3a claim is missing or widened."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--patch", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--overlay-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--runbook", required=True, type=Path)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    patch = args.patch.read_text(encoding="utf-8")
    config = args.config.read_text(encoding="utf-8")
    report = args.report.read_text(encoding="utf-8")
    runbook = args.runbook.read_text(encoding="utf-8")

    require(manifest.get("schema_version") == 1, "schema version mismatch")
    require(manifest.get("evidence_id") == IMAGE_ID, "evidence id mismatch")
    require(manifest.get("stage") == "H1.3a", "stage mismatch")
    require(manifest.get("status") == "passed_offline_static_only", "unsafe status")

    inputs = manifest.get("inputs", {})
    require(sha256_file(args.patch) == EXPECTED_PATCH_SHA256, "patch file hash mismatch")
    require(inputs.get("patch_sha256") == EXPECTED_PATCH_SHA256, "recorded patch hash mismatch")
    require(sha256_file(args.config) == EXPECTED_FRAGMENT_SHA256, "config fragment hash mismatch")
    require(inputs.get("config_fragment_sha256") == EXPECTED_FRAGMENT_SHA256,
            "recorded config fragment hash mismatch")
    require(inputs.get("resolved_config_sha256") == EXPECTED_RESOLVED_CONFIG_SHA256,
            "resolved config hash mismatch")
    require(inputs.get("overlay_sha256") == EXPECTED_OVERLAY_HASHES,
            "recorded recovery overlay hash set mismatch")
    require(config.splitlines() == list(CONFIG_LINES), "config fragment content mismatch")
    overlay_files = {
        path.relative_to(args.overlay_root).as_posix()
        for path in args.overlay_root.rglob("*")
        if path.is_file()
    }
    require(overlay_files == set(EXPECTED_OVERLAY_HASHES), "recovery overlay file set mismatch")
    for relative_path, expected_hash in EXPECTED_OVERLAY_HASHES.items():
        path = args.overlay_root / relative_path
        require(sha256_file(path) == expected_hash, f"overlay hash mismatch: {relative_path}")
        require(path.stat().st_mode & 0o777 == 0o755, f"overlay mode mismatch: {relative_path}")
    for marker in PATCH_MARKERS:
        require(marker in patch, f"patch guard missing: {marker}")

    source = manifest.get("source", {})
    require(source.get("buildroot_commit") == BUILDROOT_COMMIT, "buildroot commit mismatch")
    require(source.get("feeds") == EXPECTED_FEEDS, "feed revision set mismatch")
    require(source.get("release") == "25.12.5", "release mismatch")
    require(source.get("revision") == "r33051-f5dae5ece4", "revision mismatch")
    require(source.get("kernel") == "6.12.94", "kernel version mismatch")
    require(source.get("target") == "mediatek/filogic", "target mismatch")

    build = manifest.get("build", {})
    require(build.get("profile_symbol") == EXPECTED_PROFILE_SYMBOL, "stock profile mismatch")
    require(build.get("resolved_profile") == "DEVICE_xiaomi_mi-router-ax3000t",
            "resolved profile mismatch")
    require(build.get("initramfs") is True, "artifact is not initramfs")
    require(build.get("ubootmod_selected") is False, "ubootmod profile selected")
    require(build.get("kmod_mtd_rw") is False, "kmod-mtd-rw was selected")
    require(build.get("checkpatch_errors") == 0 and build.get("checkpatch_warnings") == 0,
            "patch style gate failed")
    require(build.get("clean_rebuild_exit_code") == 0, "clean target build did not pass")
    require(build.get("repeat_build_exit_code") == 0, "repeat build did not pass")
    require(set(build.get("source_diff_paths", [])) == EXPECTED_SOURCE_DIFF_PATHS,
            "source diff path set mismatch")
    for key, expected_hash in EXPECTED_BUILD_LOG_HASHES.items():
        require(build.get(key) == expected_hash, f"build log identity mismatch: {key}")

    artifact = manifest.get("artifact", {})
    filename = artifact.get("filename", "")
    require(filename.endswith("xiaomi_mi-router-ax3000t-initramfs-kernel.bin"),
            "unexpected artifact filename")
    require("ubootmod" not in filename and not filename.endswith(".itb"),
            "forbidden ubootmod artifact")
    require(artifact.get("sha256") == EXPECTED_ARTIFACT_SHA256, "artifact hash mismatch")
    require(artifact.get("size_bytes") == EXPECTED_ARTIFACT_SIZE, "artifact size mismatch")
    require(artifact.get("format") == "FIT", "artifact is not a FIT image")
    require(artifact.get("repeat_sha256") == EXPECTED_ARTIFACT_SHA256,
            "repeat build is not byte-identical")
    require(artifact.get("private_not_git") is True, "private artifact boundary missing")

    audit = manifest.get("static_audit", {})
    require(audit.get("fit_valid") is True, "FIT validation failed")
    require(audit.get("kernel_arch") == "AArch64", "kernel architecture mismatch")
    require(audit.get("kernel_version") == "6.12.94", "FIT kernel version mismatch")
    require(audit.get("load_address") == "0x48000000", "FIT load address mismatch")
    require(audit.get("entry_address") == "0x48000000", "FIT entry address mismatch")
    require(audit.get("compatible") == ["xiaomi,mi-router-ax3000t", "mediatek,mt7981"],
            "DTB compatible mismatch")
    require(audit.get("bmt_read_only") is True, "DTB lacks forced BMT read-only")
    require(audit.get("wifi_disabled") is True, "Wi-Fi is not disabled")
    require(set(audit.get("read_only_partitions", [])) == EXPECTED_PARTITIONS,
            "read-only partition set mismatch")
    require(audit.get("partition_count") == len(EXPECTED_PARTITIONS),
            "partition count mismatch")
    require(audit.get("nanddump_sha256") == EXPECTED_NANDDUMP_SHA256,
            "nanddump identity mismatch")
    require(set(audit.get("forbidden_helpers_absent", [])) == EXPECTED_FORBIDDEN_HELPERS,
            "forbidden helper audit mismatch")
    require(set(audit.get("potential_mutators_present_but_kernel_blocked", []))
            == EXPECTED_PRESENT_MUTATORS, "present mutator audit mismatch")
    require(set(audit.get("automatic_mutation_paths_disabled", []))
            == EXPECTED_DISABLED_AUTOMATIC_PATHS, "automatic path audit mismatch")
    require(set(audit.get("kernel_guards", [])) == EXPECTED_GUARDS,
            "kernel guard set mismatch")
    require(audit.get("guard_warning_in_vmlinux") is True,
            "compiled kernel guard marker missing")
    require(audit.get("ubootmod_strings_found") == 0, "ubootmod identity found in artifact")
    require(audit.get("flashable_device_artifacts_found") == 0,
            "flashable device artifact was emitted")
    require(audit.get("fit_config_links_exact_nodes") is True,
            "FIT configuration does not link the audited nodes")
    require(audit.get("compiled_sha256") == EXPECTED_COMPILED_HASHES,
            "compiled kernel object identity mismatch")
    require(audit.get("compiled_paths") == EXPECTED_COMPILED_PATHS,
            "compiled kernel object path mismatch")
    require(audit.get("fit_node_sha256") == EXPECTED_FIT_NODE_HASHES,
            "extracted FIT node identity mismatch")

    correction_items = manifest.get("method_corrections", [])
    corrections = {item.get("id") for item in correction_items}
    require(corrections == {
        "wrong-profile-symbol",
        "attach-error-fail-closed",
        "interrupted-generated-dependencies",
        "flashable-factory-recipe",
        "audit-tool-paths",
        "source-path-attestation",
    },
            "method correction set mismatch")
    require(
        len(correction_items) == len(corrections)
        and all(item.get("result") for item in correction_items),
        "method correction detail missing or duplicated",
    )

    scope = manifest.get("scope", {})
    require(scope.get("server_only") is True, "server-only scope missing")
    for key in FALSE_SCOPE:
        require(scope.get(key) is False, f"scope permits {key}")
    gates = manifest.get("gates", {})
    require(gates.get("h1_3a_offline_candidate") is True, "H1.3a gate is false")
    require(gates.get("candidate_eligible_for_separate_h1_3b") is True,
            "candidate not eligible for separate H1.3b")
    for key in FALSE_GATES:
        require(gates.get(key) is False, f"closed gate was opened: {key}")

    limitations = manifest.get("limitations", {})
    for key in (
        "bootloader_acceptance_unverified",
        "ram_boot_unverified",
        "runtime_zero_write_unverified",
        "uart_recovery_unverified",
    ):
        require(limitations.get(key) is True, f"limitation missing: {key}")
    for marker in REPORT_MARKERS:
        require(marker in report, f"report marker missing: {marker}")
    for marker in RUNBOOK_MARKERS:
        require(marker in runbook, f"runbook marker missing: {marker}")

    print("h1_3a_gate_passed=true")
    print("candidate_eligible_for_separate_h1_3b=true")
    print("recovery_boot_verified=false")
    print("device_contact=false")
    print("router_reboot=false")
    print("device_writes=false")
    print("commands_authorized=false")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"h1_3a_gate_passed=false: {error}") from error
