#!/usr/bin/env python3
"""Review private H1.5 runs and the redacted disabled-install conclusion."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import tarfile
from collections import Counter
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
APK_SHA256 = "02d0c977d68192c28d0ef537a704435d9814fb8e04763cd67d73e00e41e5d9b1"
APK_SIZE = 184_099
PREFLIGHT_SHA256 = "f9a1dd895eea13fbad1b6fade2a12b4a3fcb5305715bd76f1a12fd70f569e453"
HARNESS_SHA256 = "69ea54de29232d0f626d9ad9258b428e6362c7d92888721b25d77f2d7c2a1b69"
RUNNER_SHA256 = "f301b08cee3d5d18d5e750a6e7d3869fc88def21ca4f2d41c6922970449b49d1"
RUN_01_SHA256 = "5b2bf2199b751783c644a534beb0d60693b2a40c895a1c14108a6e68a116b77e"
RUN_02_SHA256 = "69e60ed3e6a1bda92ee703b8983613a8756cdc25e7d527ef883cfe0253a4e4ca"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
CANDIDATE_SHA256 = "b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75"
SWITCH_SHA256 = "ce7ef65892c69d1900ee0f626183bcae5a42b3ccd1f18f706ab496703b990bdf"
DISPATCHER_SHA256 = "f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15"
BASELINE_SHA256 = "b77e0e99672ee504d1ee1183f14b8ba8cfe92f6c546aa585f7efc784d2b0c163"
CONFIG_TREE_SHA256 = "c571059487c486dc8f255228f49ab558092a50ee22c0845c91ed4839a0ded44a"
PACKAGE_DB_BEFORE = "6149a91ae1efa348b3e56d08ef13f844ecee6288a78448749519682a9e8cb5fc"
PACKAGE_DB_AFTER = "442b79537bad77999f273ca6ea8442bf9ba4478f303566103bf6d8692225490d"
WORLD_BEFORE = "906eb5cf1013afd8e8ff97b486175fa77a97a2a2437d640a1c4fdc4dd9eab69b"
WORLD_AFTER = "3320ec84c2c7b1fd969dc8caa5da0b05a6afcb15448c62862ff34e9dc32d6419"
SCRIPTS_BEFORE = "4a5fd6b59a9eadd3b27dd31fd4d79b622083b0a11d966a8c2dd5916c1b945bfc"
SCRIPTS_ROLLBACK_CANONICAL = "9cf4b34384d30cf3628e626aa9f1b03ca8824bff75291a84cea0331c313f321e"
SCRIPTS_AFTER = "993b4360bd6e79f870c3db78e040430ec1a5b12757d881ffdc98dac4b6c21b7c"
RUN_01_INSTALL_SHA256 = "5aa4e866da2bb8b9ff73621be6c0ace384c310de86f465b1705dd38aa2085d06"
RUN_01_VERIFY_SHA256 = "73c1c5fd85b98acd5f1de8a16a45abdcb626f8a5134a5b7b609fa696728834f5"
RUN_02_IDENTITY_SHA256 = "bb791bf6d7b41475eb5adeb5d823d72e6c79ba42abf1a162c579e901e94e6b5a"
RUN_02_INSTALL_SHA256 = "5b2978c93d6c0f3ed1820ce6ff8168659d754165f70af260ed7d3789c67bf833"
RUN_02_VERIFY_SHA256 = "818a6bb1e8b82ba994fe81bf73a5e3e3b144b136fe5744a0c4f0b3a9f3e919d2"
DUPLICATES = {
    "urngd-2025.10.03~f17e33d9-r1.X1bec1fbed4e5fc945a33ccb0e940fedf04e3b4c2d.pre-deinstall",
    "urngd-2025.10.03~f17e33d9-r1.X1bec1fbed4e5fc945a33ccb0e940fedf04e3b4c2d.post-upgrade",
    "usign-2025.10.03~c4c72b1b-r1.X135aa2f333a0310436eb9a0551c187516dbee97f1.pre-deinstall",
    "usign-2025.10.03~c4c72b1b-r1.X135aa2f333a0310436eb9a0551c187516dbee97f1.post-upgrade",
    "wifi-scripts-1.0-r1.X140c51d1f782828658eee577e3ea845e6cf9d455a.pre-deinstall",
    "wifi-scripts-1.0-r1.X140c51d1f782828658eee577e3ea845e6cf9d455a.post-upgrade",
}


class ReviewError(RuntimeError):
    """Raised when private evidence and the public conclusion diverge."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def record_map(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item.get("name")): item for item in run.get("records", [])}


def require_markers(text: str, markers: tuple[str, ...], label: str) -> None:
    for marker in markers:
        require(marker in text, f"{label} marker missing: {marker}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--harness", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--runbook", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--readme", required=True, type=Path)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    require(manifest.get("schema_version") == 1, "schema version mismatch")
    require(manifest.get("evidence_id") == IMAGE_ID, "evidence id mismatch")
    require(manifest.get("stage") == "H1.5-disabled-install", "stage mismatch")
    require(manifest.get("status") == "complete_installed_disabled", "status mismatch")

    inputs = {
        "preflight": (args.preflight, PREFLIGHT_SHA256),
        "device_harness": (args.harness, HARNESS_SHA256),
        "runner": (args.runner, RUNNER_SHA256),
    }
    for name, (path, expected_hash) in inputs.items():
        require(sha256_file(path) == expected_hash, f"{name} input changed")
        require(manifest.get("inputs", {}).get(name, {}).get("sha256") == expected_hash,
                f"recorded {name} hash mismatch")
    require(sha256_file(args.apk) == APK_SHA256, "APK hash mismatch")
    require(args.apk.stat().st_size == APK_SIZE, "APK size mismatch")
    require(stat.S_IMODE(args.apk.stat().st_mode) == 0o400, "APK mode mismatch")
    require(manifest.get("inputs", {}).get("apk", {}).get("sha256") == APK_SHA256,
            "recorded APK hash mismatch")
    require(manifest.get("inputs", {}).get("apk", {}).get("size_bytes") == APK_SIZE,
            "recorded APK size mismatch")

    evidence_root = args.evidence_root.resolve()
    require(evidence_root.name == "h1-5-20260902", "private evidence root mismatch")
    run_01_dir = evidence_root / "run-01"
    run_02_dir = evidence_root / "run-02"
    require(sha256_file(run_01_dir / "run.json") == RUN_01_SHA256,
            "run-01 manifest changed")
    require(sha256_file(run_02_dir / "run.json") == RUN_02_SHA256,
            "run-02 manifest changed")

    run_01 = load_json(run_01_dir / "run.json")
    require(run_01.get("stage") == "H1.5-disabled-install-private", "run-01 stage mismatch")
    require(run_01.get("status") == "failed", "run-01 did not fail closed")
    require(run_01.get("installed_success") is False, "run-01 forged success")
    require(run_01.get("error") == "disabled install harness exited 1",
            "run-01 error mismatch")
    records_01 = record_map(run_01)
    require(records_01.get("install", {}).get("exit_status") == 1,
            "run-01 install boundary mismatch")
    for record in ("identity", "emergency_rollback", "cleanup", "verify"):
        require(records_01.get(record, {}).get("exit_status") == 0,
                f"run-01 {record} failed")
    run_01_install = (run_01_dir / "install.stdout").read_text(encoding="utf-8")
    require(sha256_file(run_01_dir / "install.stdout") == RUN_01_INSTALL_SHA256,
            "run-01 install stdout changed")
    require(sha256_file(run_01_dir / "verify.stdout") == RUN_01_VERIFY_SHA256,
            "run-01 verify stdout changed")
    require_markers(run_01_install, (
        "Executing owrt-reload-config-0.1.0-r1.post-install",
        "* disabled",
        "failed_step=installed-files",
        "rollback=passed",
        "cleanup=PASS",
    ), "run-01")
    require("stat: not found" in (run_01_dir / "install.stderr").read_text(encoding="utf-8"),
            "run-01 stat failure missing")
    require((run_01_dir / "verify.stdout").read_text(encoding="utf-8")
            == "post_rollback_verify=PASS\n", "run-01 rollback verification mismatch")

    archive_dir = evidence_root / "archive-analysis"
    rom_archive = archive_dir / "scripts-rom.tar.gz"
    canonical_archive = archive_dir / "scripts-current.tar.gz"
    require(sha256_file(rom_archive) == SCRIPTS_BEFORE, "immutable ROM archive changed")
    require(sha256_file(canonical_archive) == SCRIPTS_ROLLBACK_CANONICAL,
            "canonicalized archive changed")
    with tarfile.open(rom_archive, "r:gz") as archive:
        rom_names = [item.name for item in archive.getmembers()]
    with tarfile.open(canonical_archive, "r:gz") as archive:
        canonical_names = [item.name for item in archive.getmembers()]
    require(len(rom_names) == 333, "immutable ROM member count mismatch")
    require(len(canonical_names) == 327, "canonical member count mismatch")
    removed = Counter(rom_names) - Counter(canonical_names)
    require(set(removed) == DUPLICATES and all(count == 1 for count in removed.values()),
            "canonicalized duplicate set mismatch")
    require(not (Counter(canonical_names) - Counter(rom_names)),
            "canonicalized archive introduced members")

    run_02 = load_json(run_02_dir / "run.json")
    require(run_02.get("stage") == "H1.5-disabled-install-private", "run-02 stage mismatch")
    require(run_02.get("status") == "passed", "run-02 did not pass")
    require(run_02.get("installed_success") is True, "run-02 install not recorded")
    require(run_02.get("error") is None, "run-02 records an error")
    require(run_02.get("harness_sha256") == HARNESS_SHA256, "run-02 harness mismatch")
    expected_records = [
        "identity", "transfer_apk", "transfer_harness", "install", "cleanup", "verify"
    ]
    records_02 = run_02.get("records", [])
    require([item.get("name") for item in records_02] == expected_records,
            "run-02 record order mismatch")
    require(all(item.get("exit_status") == 0 for item in records_02),
            "run-02 record failed")
    require(all(item.get("stderr_sha256") == EMPTY_SHA256 for item in records_02),
            "run-02 stderr not empty")

    identity = (run_02_dir / "identity.stdout").read_text(encoding="utf-8")
    install = (run_02_dir / "install.stdout").read_text(encoding="utf-8")
    verify = (run_02_dir / "verify.stdout").read_text(encoding="utf-8")
    require(sha256_file(run_02_dir / "identity.stdout") == RUN_02_IDENTITY_SHA256,
            "run-02 identity stdout changed")
    require(sha256_file(run_02_dir / "install.stdout") == RUN_02_INSTALL_SHA256,
            "run-02 install stdout changed")
    require(sha256_file(run_02_dir / "verify.stdout") == RUN_02_VERIFY_SHA256,
            "run-02 verify stdout changed")
    require_markers(identity, (
        "DISTRIB_RELEASE='25.12.5'",
        "DISTRIB_REVISION='r33051-f5dae5ece4'",
        "DISTRIB_TARGET='mediatek/filogic'",
        "xiaomi,mi-router-ax3000t",
        "6.12.94",
        DISPATCHER_SHA256,
        BASELINE_SHA256,
        CONFIG_TREE_SHA256,
        PACKAGE_DB_BEFORE,
        WORLD_BEFORE,
        SCRIPTS_BEFORE,
    ), "run-02 identity")
    require_markers(install, (
        "h1_5_disabled_install=PASS",
        "version=0.1.0-r1",
        "arch=aarch64_cortex-a53",
        f"candidate_sha256={CANDIDATE_SHA256}",
        f"switch_sha256={SWITCH_SHA256}",
        f"package_db_sha256_after={PACKAGE_DB_AFTER}",
        f"world_sha256_after={WORLD_AFTER}",
        f"scripts_sha256_after={SCRIPTS_AFTER}",
        "switch_status=disabled",
        "switch_status_rc=3",
        "candidate_activation=false",
        "real_ubus_calls=0",
        "persistent_writes=package-only",
        "runtime_mount_changes=0",
        "cleanup=PASS",
    ), "run-02 install")
    require("failed_step=" not in install, "run-02 contains a failure step")
    require(verify == "post_install_verify=PASS\n", "run-02 final verification mismatch")

    public_attempts = manifest.get("attempts", [])
    require(len(public_attempts) == 2, "public attempt count mismatch")
    for attempt, expected_id, expected_hash, expected_status in (
        (public_attempts[0], "run-01", RUN_01_SHA256, "failed_closed"),
        (public_attempts[1], "run-02", RUN_02_SHA256, "passed"),
    ):
        require(attempt.get("id") == expected_id, f"{expected_id} public id mismatch")
        require(attempt.get("private_manifest_sha256") == expected_hash,
                f"{expected_id} public hash mismatch")
        require(attempt.get("status") == expected_status,
                f"{expected_id} public status mismatch")
        require(attempt.get("cleanup_verified") is True,
                f"{expected_id} cleanup not recorded")
        require(attempt.get("candidate_activation") is False,
                f"{expected_id} activation admitted")
    require(public_attempts[0].get("private_install_stdout_sha256") == RUN_01_INSTALL_SHA256,
            "run-01 public install hash mismatch")
    require(public_attempts[0].get("private_verify_stdout_sha256") == RUN_01_VERIFY_SHA256,
            "run-01 public verify hash mismatch")
    require(public_attempts[0].get("result") == "target_stat_command_absent",
            "run-01 public result mismatch")
    require(public_attempts[1].get("private_identity_stdout_sha256") == RUN_02_IDENTITY_SHA256,
            "run-02 public identity hash mismatch")
    require(public_attempts[1].get("private_install_stdout_sha256") == RUN_02_INSTALL_SHA256,
            "run-02 public install hash mismatch")
    require(public_attempts[1].get("private_verify_stdout_sha256") == RUN_02_VERIFY_SHA256,
            "run-02 public verify hash mismatch")
    require(public_attempts[1].get("result") == "exact_package_installed_disabled",
            "run-02 public result mismatch")

    require(manifest.get("device_identity") == {
        "board": "xiaomi,mi-router-ax3000t",
        "kernel": "6.12.94",
        "layout": "stock",
        "release": "25.12.5",
        "revision": "r33051-f5dae5ece4",
        "target": "mediatek/filogic",
    }, "public identity mismatch")
    package = manifest.get("package", {})
    require(package.get("name") == "owrt-reload-config", "package name mismatch")
    require(package.get("version") == "0.1.0-r1", "package version mismatch")
    require(package.get("arch") == "aarch64_cortex-a53", "package arch mismatch")
    require(package.get("installed_size_bytes") == 348_430, "installed size mismatch")
    require(package.get("origin") == "feeds/base/owrt-reload-config", "package origin mismatch")
    require(package.get("installed_file_list") == [
        "/lib/apk/packages/owrt-reload-config.list",
        "/usr/sbin/owrt-reload-config-switch",
        "/usr/sbin/reload_config_rs",
    ], "installed file list mismatch")
    require(package.get("package_list_sha256")
            == "af14000e540921eb9b9baeb504b25ca9e2806b62a62e5977c649ca0488ce4559",
            "package list hash mismatch")
    require(package.get("candidate", {}).get("path") == "/usr/sbin/reload_config_rs",
            "candidate path mismatch")
    require(package.get("candidate", {}).get("size_bytes") == 346_531,
            "candidate size mismatch")
    require(package.get("candidate", {}).get("sha256") == CANDIDATE_SHA256,
            "candidate hash mismatch")
    require(package.get("candidate", {}).get("metadata") == "-rwxr-xr-x:0:0",
            "candidate metadata mismatch")
    require(package.get("switch", {}).get("sha256") == SWITCH_SHA256,
            "switch hash mismatch")
    require(package.get("switch", {}).get("metadata") == "-rwxr-xr-x:0:0",
            "switch metadata mismatch")
    require(package.get("switch", {}).get("path") == "/usr/sbin/owrt-reload-config-switch",
            "switch path mismatch")
    require(package.get("switch", {}).get("size_bytes") == 1_836,
            "switch size mismatch")
    require(package.get("switch", {}).get("status") == "disabled",
            "switch not disabled")
    require(package.get("switch", {}).get("status_exit_code") == 3,
            "switch status code mismatch")

    invariants = manifest.get("live_invariants", {})
    for prefix, expected in (
        ("dispatcher", DISPATCHER_SHA256),
        ("baseline", BASELINE_SHA256),
        ("config_tree", CONFIG_TREE_SHA256),
        ("triggers", EMPTY_SHA256),
    ):
        require(invariants.get(f"{prefix}_sha256_before") == expected,
                f"{prefix} before mismatch")
        require(invariants.get(f"{prefix}_sha256_after") == expected,
                f"{prefix} after mismatch")
    require(invariants.get("package_db_sha256_before") == PACKAGE_DB_BEFORE,
            "package DB before mismatch")
    require(invariants.get("package_db_sha256_after") == PACKAGE_DB_AFTER,
            "package DB after mismatch")
    require(invariants.get("world_sha256_before") == WORLD_BEFORE, "world before mismatch")
    require(invariants.get("world_sha256_after") == WORLD_AFTER, "world after mismatch")
    require(invariants.get("scripts_sha256_before") == SCRIPTS_BEFORE,
            "scripts before mismatch")
    require(invariants.get("scripts_sha256_after") == SCRIPTS_AFTER,
            "scripts after mismatch")
    require(invariants.get("mount_count_before") == 0, "pre-install mount present")
    require(invariants.get("mount_count_after") == 0, "post-install mount present")
    require(invariants.get("overlay_available_kib_before_run_02") == 58_692,
            "pre-install overlay space mismatch")
    require(invariants.get("overlay_available_kib_after") == 58_480,
            "post-install overlay space mismatch")

    effects = manifest.get("device_effects", {})
    require(effects == {
        "candidate_activation": False,
        "candidate_installed": True,
        "device_contact": True,
        "device_execution": True,
        "device_transfer": True,
        "firmware_flash": False,
        "overlay_writes": True,
        "package_database_changed": True,
        "package_install": True,
        "persistent_writes": "package-only",
        "real_ubus_calls": 0,
        "router_reboot": False,
        "runtime_mount_changes": 0,
        "tmpfs_artifacts_remaining": 0,
    }, "device effects mismatch")
    gates = manifest.get("gates", {})
    require(set(gates) == {
        "artifact_identity", "candidate_activation", "config_tree_unchanged",
        "default_disabled", "dispatcher_unchanged", "failure_recovery_exact",
        "h1_5_disabled_install", "h1_6_canary", "installed_files_exact",
        "live_baseline_unchanged", "real_ubus_calls", "runtime_mount_unchanged",
        "temporary_cleanup", "triggers_unchanged",
    }, "gate field set mismatch")
    require(gates.get("h1_5_disabled_install") is True, "H1.5 gate is false")
    require(gates.get("h1_6_canary") is False, "H1.6 gate opened")
    for gate in (
        "artifact_identity", "config_tree_unchanged", "default_disabled",
        "dispatcher_unchanged", "failure_recovery_exact", "installed_files_exact",
        "live_baseline_unchanged", "runtime_mount_unchanged", "temporary_cleanup",
        "triggers_unchanged",
    ):
        require(gates.get(gate) is True, f"gate is false: {gate}")
    require(gates.get("candidate_activation") is False, "activation gate opened")
    require(gates.get("real_ubus_calls") is False, "real ubus gate opened")

    archive = manifest.get("archive_recovery", {})
    require(archive.get("immutable_rom_sha256") == SCRIPTS_BEFORE,
            "public ROM archive hash mismatch")
    require(archive.get("canonicalized_sha256") == SCRIPTS_ROLLBACK_CANONICAL,
            "public canonical archive hash mismatch")
    require(archive.get("immutable_rom_tar_members") == 333,
            "public ROM member count mismatch")
    require(archive.get("canonicalized_tar_members") == 327,
            "public canonical member count mismatch")
    require(set(archive.get("duplicate_members_removed", [])) == DUPLICATES,
            "public duplicate set mismatch")
    require(archive.get("exact_pre_state_restored") is True,
            "exact recovery not recorded")
    require(archive.get("private_rom_archive_path")
            == "private/h1-5-20260902/archive-analysis/scripts-rom.tar.gz",
            "public ROM archive path mismatch")
    require(archive.get("private_canonicalized_archive_path")
            == "private/h1-5-20260902/archive-analysis/scripts-current.tar.gz",
            "public canonical archive path mismatch")

    authorization = manifest.get("authorization", {})
    require(authorization.get("h1_5_disabled_install_authorized") is True,
            "H1.5 authorization missing")
    require(authorization.get("package_only_persistent_writes_authorized") is True,
            "package write authorization missing")
    require(authorization.get("candidate_activation_authorized") is False,
            "activation authorization forged")
    require(authorization.get("h1_6_authorized") is False,
            "H1.6 authorization forged")
    next_stage = manifest.get("next_stage", {})
    require(next_stage.get("id") == "H1.6-bind-mount-canary", "next stage mismatch")
    require(next_stage.get("status") == "blocked_not_authorized", "H1.6 status mismatch")
    require(next_stage.get("requires_separate_explicit_authorization") is True,
            "H1.6 separate authorization missing")
    require("network drift" in next_stage.get("blocker", ""), "network drift blocker missing")
    require(manifest.get("scope_limit") == (
        "This gate passes only for the exact image, device and observed configuration; "
        "it proves installed-but-disabled state, not active replacement behaviour."
    ), "scope limit mismatch")

    report = args.report.read_text(encoding="utf-8")
    runbook = args.runbook.read_text(encoding="utf-8")
    plan = args.plan.read_text(encoding="utf-8")
    readme = args.readme.read_text(encoding="utf-8")
    require_markers(report, (
        "complete_installed_disabled", "H1.5 已通过", "status=disabled",
        "333 个成员规范化为 327 个", "h1_5_disabled_install=true",
        "h1_6_canary=false", "在解决 drift 的测试设计并取得新的明确授权之前",
    ), "report")
    require("H1.5 已完成；精确 package 已安装并保持 disabled" in runbook,
            "runbook status missing")
    require("H1.5 已完成，精确 package 已安装并保持 disabled" in plan,
            "plan status missing")
    require("H1.5 默认禁用安装\n已经完成" in readme,
            "README status missing")

    print("h1_5_review=true")
    print("h1_5_disabled_install=true")
    print("package_installed=true")
    print("switch_status=disabled")
    print("candidate_activation=false")
    print("real_ubus_calls=0")
    print("runtime_mount_changes=0")
    print("failure_recovery_exact=true")
    print("h1_6_canary=false")


if __name__ == "__main__":
    try:
        main()
    except (ReviewError, OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as error:
        raise SystemExit(f"h1_5_review=false: {error}") from error
