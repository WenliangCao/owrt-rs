#!/usr/bin/env python3
"""Validate H1.5 authorization, artifact identity and disabled-install plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
APK_SHA256 = "02d0c977d68192c28d0ef537a704435d9814fb8e04763cd67d73e00e41e5d9b1"
APK_SIZE = 184_099
H1_4_SHA256 = "b4ab763ddea8357af777cfb360d7d41c2284f2b91df33496c7cb0ec7ea69dc26"
V1_SHA256 = "7acd6d3cd26cec7aa7be32e71b6e617bbc739b0fbc1c9c0a4b4a8ae0ba62fb8d"
HARNESS_SHA256 = "69ea54de29232d0f626d9ad9258b428e6362c7d92888721b25d77f2d7c2a1b69"
RUNNER_SHA256 = "f301b08cee3d5d18d5e750a6e7d3869fc88def21ca4f2d41c6922970449b49d1"
REMOTE_PATHS = {
    "/tmp/owrt-h1-5-r1.apk",
    "/tmp/owrt-h1-5-disabled-install.sh",
    "/tmp/owrt-h1-5-install-20260902",
}
FALSE_SCOPE = {
    "candidate_activation",
    "device_transfer",
    "firmware_flash",
    "host_network_changes",
    "overlay_writes",
    "package_database_writes",
    "package_install",
    "persistent_writes",
    "real_ubus_calls",
    "router_reboot",
    "runtime_mount_changes",
}


class GateError(RuntimeError):
    """Raised when H1.5 preflight is incomplete or wider than authorized."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--h1-4", required=True, type=Path)
    parser.add_argument("--v1", required=True, type=Path)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--harness", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--runbook", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    h1_4 = load_json(args.h1_4)
    v1 = load_json(args.v1)
    report = args.report.read_text(encoding="utf-8")
    runbook = args.runbook.read_text(encoding="utf-8")
    plan = args.plan.read_text(encoding="utf-8")

    require(manifest.get("schema_version") == 1, "schema version mismatch")
    require(manifest.get("evidence_id") == IMAGE_ID, "evidence id mismatch")
    require(manifest.get("stage") == "H1.5-preflight", "stage mismatch")
    require(manifest.get("status") == "passed_ready_for_authorized_disabled_install",
            "preflight status mismatch")

    require(sha256_file(args.h1_4) == H1_4_SHA256, "H1.4 input changed")
    require(manifest.get("inputs", {}).get("h1_4_observations", {}).get("sha256")
            == H1_4_SHA256, "recorded H1.4 hash mismatch")
    require(h1_4.get("gates", {}).get("h1_4_device_run") is True, "H1.4 did not pass")
    require(h1_4.get("gates", {}).get("h1_5_disabled_install") is False,
            "H1.5 was forged complete in H1.4")
    require(sha256_file(args.v1) == V1_SHA256, "V1 input changed")
    require(manifest.get("inputs", {}).get("v1_validation", {}).get("sha256") == V1_SHA256,
            "recorded V1 hash mismatch")
    require(v1.get("gate", {}).get("passed") is True, "V1 gate is false")
    require(v1.get("packages", {}).get("r1", {}).get("sha256") == APK_SHA256,
            "V1 APK identity mismatch")

    apk = manifest.get("inputs", {}).get("apk", {})
    require(sha256_file(args.apk) == APK_SHA256, "private APK hash mismatch")
    require(args.apk.stat().st_size == APK_SIZE, "private APK size mismatch")
    require(stat.S_IMODE(args.apk.stat().st_mode) == 0o400, "private APK mode mismatch")
    require(apk.get("sha256") == APK_SHA256, "recorded APK hash mismatch")
    require(apk.get("size_bytes") == APK_SIZE, "recorded APK size mismatch")
    require(apk.get("local_private_mode") == "0400", "recorded APK mode mismatch")

    require(sha256_file(args.harness) == HARNESS_SHA256, "device harness changed")
    require(sha256_file(args.runner) == RUNNER_SHA256, "runner changed")
    require(stat.S_IMODE(args.harness.stat().st_mode) == 0o755, "harness mode mismatch")
    require(stat.S_IMODE(args.runner.stat().st_mode) == 0o755, "runner mode mismatch")
    require(manifest.get("scripts", {}).get("device_harness", {}).get("sha256")
            == HARNESS_SHA256, "recorded harness hash mismatch")
    require(manifest.get("scripts", {}).get("runner", {}).get("sha256") == RUNNER_SHA256,
            "recorded runner hash mismatch")

    authorization = manifest.get("authorization", {})
    require(authorization.get("h1_5_disabled_install_authorized") is True,
            "H1.5 authorization missing")
    require(authorization.get("persistent_package_writes_authorized") is True,
            "package write authorization missing")
    require(authorization.get("separate_h1_6_authorization_required") is True,
            "H1.6 authorization was inherited")
    require(authorization.get("scope_limit")
            == "install the exact r1 APK offline and leave it disabled",
            "authorization scope widened")

    snapshot = manifest.get("device_snapshot", {})
    require(snapshot.get("candidate_package_absent") is True, "candidate already installed")
    require(snapshot.get("candidate_files_absent") is True, "candidate files already exist")
    require(snapshot.get("mount_count") == 0, "candidate mount already exists")
    require(snapshot.get("overlay_available_kib", 0) >= 4096, "insufficient overlay space")
    require(snapshot.get("dependencies_installed") == ["libc", "procd", "uci", "ubus"],
            "dependency set changed")
    require(snapshot.get("dispatcher_sha256")
            == "f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15",
            "dispatcher snapshot mismatch")
    require(snapshot.get("baseline_sha256")
            == "b77e0e99672ee504d1ee1183f14b8ba8cfe92f6c546aa585f7efc784d2b0c163",
            "baseline snapshot mismatch")

    execution = manifest.get("execution", {})
    require(set(execution.get(key) for key in ("remote_apk", "remote_harness", "remote_run_root"))
            == REMOTE_PATHS, "remote path set changed")
    require(execution.get("ssh_alias") == "openwrt", "SSH target widened")
    require(execution.get("install_timeout_seconds") == 180, "install timeout changed")
    require(execution.get("simulation_command")
            == "/usr/bin/apk --no-network add --simulate --allow-untrusted /tmp/owrt-h1-5-r1.apk",
            "simulation command changed")
    require(execution.get("actual_command")
            == "/usr/bin/apk --no-network add --allow-untrusted /tmp/owrt-h1-5-r1.apk",
            "install command changed")
    rollback = manifest.get("rollback", {})
    require(rollback.get("command") == "/usr/bin/apk --no-network del owrt-reload-config",
            "rollback command changed")
    require("immutable /rom scripts archive restored" in rollback.get("required_result", ""),
            "exact scripts archive rollback missing")

    corrections = manifest.get("method_corrections", [])
    require(len(corrections) == 1, "run-01 correction missing")
    correction = corrections[0]
    require(correction.get("attempt") == "run-01", "correction attempt mismatch")
    require(correction.get("failed_step") == "installed-files",
            "correction failure boundary mismatch")
    require(correction.get("package_install_reached_disabled_state") is True,
            "disabled install observation missing")
    require(correction.get("candidate_activation") is False,
            "correction admits candidate activation")
    require("333 tar members to 327" in correction.get("scripts_archive_observation", ""),
            "scripts archive canonicalization missing")

    post = manifest.get("required_postconditions", {})
    require(post.get("package_version") == "0.1.0-r1", "package version changed")
    require(post.get("switch_status") == "disabled", "switch postcondition changed")
    require(post.get("switch_status_exit_code") == 3, "switch status code changed")
    require(post.get("mount_count") == 0, "mount postcondition changed")
    require(post.get("candidate_activation") is False, "candidate activation admitted")
    require(post.get("real_ubus_calls") == 0, "real ubus admitted")
    for key in ("baseline_unchanged", "config_tree_unchanged", "dispatcher_unchanged"):
        require(post.get(key) is True, f"postcondition missing: {key}")

    gates = manifest.get("gates", {})
    for key in (
        "artifact_identity",
        "device_state_frozen",
        "h1_5_preflight",
        "rollback_frozen",
        "target_busybox_ash_syntax",
    ):
        require(gates.get(key) is True, f"preflight gate is false: {key}")
    require(gates.get("h1_5_disabled_install") is False, "install forged complete")
    require(gates.get("h1_6_canary") is False, "canary gate opened")

    scope = manifest.get("scope", {})
    require(scope.get("device_contact") is True, "read-only device preflight missing")
    require(scope.get("device_execution") is True, "read-only commands not recorded")
    require(scope.get("h1_5_read_only_preflight") is True, "preflight scope missing")
    require(scope.get("server_read_and_private_copy") is True, "private APK copy missing")
    for key in FALSE_SCOPE:
        require(scope.get(key) is False, f"preflight scope permits {key}")

    harness = args.harness.read_text(encoding="utf-8")
    runner = args.runner.read_text(encoding="utf-8")
    for marker in (
        '"$APK_TOOL" --no-network add --simulate --allow-untrusted "$APK_PATH"',
        '"$APK_TOOL" --no-network add --allow-untrusted "$APK_PATH"',
        '"$APK_TOOL" --no-network del "$PACKAGE"',
        'LC_ALL=C ls -ldn "$1"',
        "restore_scripts_archive",
        "switch_status=disabled",
        "candidate_activation=false",
        "runtime_mount_changes=0",
    ):
        require(marker in harness, f"harness marker missing: {marker}")
    require('["scp", "-O", *SSH_OPTIONS' in runner, "legacy SCP mode missing")
    require('args.ssh_target != "openwrt"' in runner, "SSH alias guard missing")
    require("ROLLBACK_COMMAND" in runner and "VERIFY_ROLLBACK_COMMAND" in runner,
            "runner rollback missing")
    combined = (harness + runner).lower()
    for forbidden in (
        "--update-cache",
        "--force",
        "apk upgrade",
        "sysupgrade",
        "ubiformat",
        "ubiupdatevol",
        "mtd write",
        "mtd erase",
    ):
        require(forbidden not in combined, f"forbidden operation present: {forbidden}")
    for command in ("enable", "reboot", "poweroff"):
        pattern = rf"(?<![a-z0-9_]){command}(?![a-z0-9_])"
        require(re.search(pattern, combined) is None, f"forbidden command present: {command}")
    for forbidden_ubus in ("ubus call", "/bin/ubus", "/sbin/ubus"):
        require(forbidden_ubus not in combined,
                f"forbidden ubus execution present: {forbidden_ubus}")
    require("mount -o" not in combined and "umount " not in combined,
            "runtime mount command present")

    for marker in (
        "passed_ready_for_authorized_disabled_install",
        "首轮 fail-closed 实证与修正",
        "333 个 tar 成员变为 327 个",
        "安装结束时保持 disabled",
        "不允许 enable",
        "h1_6_canary=false",
    ):
        require(marker in report, f"report marker missing: {marker}")
    for marker in ("H1.5：默认禁用安装", "H1.5 preflight 已完成"):
        require(marker in runbook, f"runbook marker missing: {marker}")
    require("H1.5 preflight 已完成" in plan, "plan marker missing")

    print("h1_5_preflight=true")
    print("h1_5_disabled_install=false")
    print("h1_5_authorized=true")
    print("candidate_activation=false")
    print("real_ubus_calls=false")
    print("runtime_mount_changes=false")
    print("router_reboot=false")
    print("firmware_flash=false")
    print("h1_6_canary=false")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"h1_5_preflight=false: {error}") from error
