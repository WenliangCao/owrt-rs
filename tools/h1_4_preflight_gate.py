#!/usr/bin/env python3
"""Validate the frozen H1.4 tmpfs-only device-run preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
CANDIDATE_SHA256 = "b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75"
CANDIDATE_SIZE = 346_531
INPUT_HASHES = {
    "contract": "10c9f7de0e517e734e4cb4e6ccd44c832f4cae207303211a72ae02c7786a5318",
    "h1_no_disassembly_policy": (
        "e0d4cfac65fcd2c16fe79bc527aa4aaaac5431eebc8da06a1b7ff5b8ed5e1393"
    ),
    "v1_validation": "7acd6d3cd26cec7aa7be32e71b6e617bbc739b0fbc1c9c0a4b4a8ae0ba62fb8d",
    "harness": "1e187b214cd2529bfd04c2edca9b9c45e996493b2c6b8ef5ed1d42211f4eee39",
    "runner": "6e77b7aeef28365183d827b11583d9b0ae5be19fe18a74fef70d299a80fe6c78",
}
REMOTE_PATHS = [
    "/tmp/owrt-r05-shadow-20260901",
    "/tmp/owrt-h1-4-reload-config-rs",
    "/tmp/owrt-h1-4-shadow.sh",
]
FALSE_PREFLIGHT_SCOPE = {
    "device_contact",
    "device_execution",
    "device_transfer",
    "firmware_flash",
    "host_network_changes",
    "package_install",
    "persistent_device_writes",
    "real_ubus_calls",
    "router_reboot",
    "runtime_mount_changes",
}
EXPECTED_STOP_CONDITIONS = {
    "identity or candidate hash mismatch",
    "original dispatcher, live baseline, package database, config tree or UCI tree changes",
    "any real ubus call",
    "any runtime mount change",
    "any unexpected event or baseline result",
    "cleanup cannot remove all three exact tmpfs paths",
}
REPORT_MARKERS = (
    "passed_offline_ready_for_authorized_device_run",
    "新建 `h1_shadow_probe`：仍然零事件",
    "不安装 APK",
    "不执行 bind mount",
    "不调用真实 ubus",
    "授权不延伸到 H1.5",
)
RUNBOOK_MARKERS = (
    "H1.4：下一条可执行路径——tmpfs shadow",
    "run2-creation-silent",
    "run3-modification-event",
    "H1.5 默认禁用 APK 安装（需另行授权）",
)


class GateError(RuntimeError):
    """Raised when H1.4 preflight evidence is incomplete or widened."""


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
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--v1", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--harness", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--runbook", required=True, type=Path)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    policy = load_json(args.policy)
    v1 = load_json(args.v1)
    report = args.report.read_text(encoding="utf-8")
    runbook = args.runbook.read_text(encoding="utf-8")

    require(manifest.get("schema_version") == 1, "schema version mismatch")
    require(manifest.get("evidence_id") == IMAGE_ID, "evidence id mismatch")
    require(manifest.get("stage") == "H1.4-preflight", "stage mismatch")
    require(
        manifest.get("status") == "passed_offline_ready_for_authorized_device_run",
        "preflight status mismatch",
    )

    files = {
        "contract": args.contract,
        "h1_no_disassembly_policy": args.policy,
        "v1_validation": args.v1,
        "harness": args.harness,
        "runner": args.runner,
    }
    for key, path in files.items():
        actual = sha256_file(path)
        require(actual == INPUT_HASHES[key], f"{key} input changed")
        if key in {"harness", "runner"}:
            recorded = manifest.get("scripts", {}).get(key, {})
        else:
            recorded = manifest.get("inputs", {}).get(key, {})
        require(recorded.get("sha256") == actual, f"{key} recorded hash mismatch")

    require(policy.get("stage") == "H1-no-disassembly-replan", "policy stage mismatch")
    require(policy.get("physical_access_policy", {}).get("status") == "fixed",
            "physical policy is not fixed")
    prohibited = set(policy.get("physical_access_policy", {}).get("prohibited", []))
    require({"case-disassembly", "usb-uart", "firmware-flash"} <= prohibited,
            "physical prohibition weakened")
    require(v1.get("status") == "complete", "V1 is incomplete")
    require(v1.get("gate", {}).get("passed") is True, "V1 gate is false")
    require(v1.get("installed_binary", {}).get("sha256") == CANDIDATE_SHA256,
            "V1 candidate mismatch")

    candidate = manifest.get("candidate", {})
    require(sha256_file(args.candidate) == CANDIDATE_SHA256, "candidate hash mismatch")
    require(args.candidate.stat().st_size == CANDIDATE_SIZE, "candidate size mismatch")
    require(stat.S_IMODE(args.candidate.stat().st_mode) == 0o500, "candidate mode mismatch")
    require(candidate.get("sha256") == CANDIDATE_SHA256, "recorded candidate hash mismatch")
    require(candidate.get("size_bytes") == CANDIDATE_SIZE, "recorded candidate size mismatch")
    require(candidate.get("local_private_mode") == "0500", "recorded candidate mode mismatch")
    require(candidate.get("local_private_path") == "private/h1-4-20260901/reload_config_rs",
            "private candidate path mismatch")

    for key in ("harness", "runner"):
        path = args.harness if key == "harness" else args.runner
        require(stat.S_IMODE(path.stat().st_mode) == 0o755, f"{key} mode mismatch")
    require(manifest.get("scripts", {}).get("harness", {}).get("path")
            == "tools/h1_4_shadow_device.sh", "harness path mismatch")
    require(manifest.get("scripts", {}).get("runner", {}).get("path")
            == "tools/h1_4_run.py", "runner path mismatch")

    expected_sequence = [
        ("run1-shared-baseline", [], "byte-identical"),
        ("run2-creation-silent", [], "advanced-in-shadow"),
        ("run3-modification-event", ["h1_shadow_probe"], None),
    ]
    sequence = manifest.get("contract_sequence", [])
    observed_sequence = [
        (item.get("id"), item.get("expected_events"), item.get("required_baseline_result"))
        for item in sequence
    ]
    require(observed_sequence == expected_sequence, "contract sequence changed")
    require(sequence[2].get("required_delivery") == "one exact fake-ubus call",
            "modification delivery requirement changed")

    plan = manifest.get("remote_plan", {})
    require(plan.get("ssh_alias") == "openwrt", "SSH target widened")
    require(plan.get("cleanup_paths") == REMOTE_PATHS, "cleanup targets changed")
    require(plan.get("run_root") == REMOTE_PATHS[0], "run root changed")
    require(plan.get("harness_path") == REMOTE_PATHS[2], "remote harness path changed")
    require(plan.get("identity_timeout_seconds") == 30, "identity timeout changed")
    require(plan.get("transfer_timeout_seconds") == 60, "transfer timeout changed")
    require(plan.get("execution_timeout_seconds") == 120, "execution timeout changed")

    authorization = manifest.get("authorization", {})
    require(set(authorization) == {
        "basis",
        "device_contact_authorized",
        "device_execution_authorized",
        "device_transfer_authorized",
        "h1_4_device_run_authorized",
        "scope_limit",
        "separate_h1_5_authorization_required",
    }, "authorization fields changed")
    for key in (
        "device_contact_authorized",
        "device_execution_authorized",
        "device_transfer_authorized",
        "h1_4_device_run_authorized",
        "separate_h1_5_authorization_required",
    ):
        require(authorization.get(key) is True, f"authorization missing: {key}")
    require(
        authorization.get("scope_limit")
        == "H1.4 fixed-path SSH transfer and tmpfs shadow execution only",
        "authorization scope widened",
    )

    gates = manifest.get("gates", {})
    require(set(gates) == {
        "candidate_identity",
        "cleanup_frozen",
        "contract_sequence_review",
        "exact_busybox_ash_syntax",
        "h1_4_device_run",
        "h1_4_offline_preflight",
        "router_contact_during_preflight",
        "script_identity",
    }, "gate fields changed")
    for key in (
        "candidate_identity",
        "cleanup_frozen",
        "contract_sequence_review",
        "exact_busybox_ash_syntax",
        "h1_4_offline_preflight",
        "script_identity",
    ):
        require(gates.get(key) is True, f"preflight gate is false: {key}")
    require(gates.get("h1_4_device_run") is False, "device run forged complete")
    require(gates.get("router_contact_during_preflight") is False,
            "preflight contacted router")

    validation = manifest.get("preflight_validation", {})
    require(set(validation) == {
        "candidate_hash_and_size_matched",
        "candidate_kept_out_of_git",
        "runner_python_compiled",
        "shell_local_syntax_passed",
        "shell_target_busybox_ash_syntax_passed",
        "target_rootfs",
    }, "preflight validation fields changed")
    require(all(validation.get(key) is True for key in (
        "candidate_hash_and_size_matched",
        "candidate_kept_out_of_git",
        "runner_python_compiled",
        "shell_local_syntax_passed",
        "shell_target_busybox_ash_syntax_passed",
    )), "offline validation incomplete")
    require("exact OpenWrt 25.12.5" in validation.get("target_rootfs", ""),
            "target BusyBox syntax context missing")

    scope = manifest.get("scope", {})
    require(set(scope) == FALSE_PREFLIGHT_SCOPE | {
        "preflight_server_read_and_ephemeral_syntax_check"
    }, "preflight scope fields changed")
    require(scope.get("preflight_server_read_and_ephemeral_syntax_check") is True,
            "server syntax check missing")
    for key in FALSE_PREFLIGHT_SCOPE:
        require(scope.get(key) is False, f"preflight scope permits {key}")
    require(set(manifest.get("stop_conditions", [])) == EXPECTED_STOP_CONDITIONS,
            "stop conditions changed")

    harness = args.harness.read_text(encoding="utf-8")
    runner = args.runner.read_text(encoding="utf-8")
    for marker in (
        "run1_shared_baseline",
        "run2_creation_silent",
        "run3_modification_event",
        "real_ubus_calls=0",
        "persistent_writes=0",
        "runtime_mount_changes=0",
        "cleanup=PASS",
    ):
        require(marker in harness, f"harness marker missing: {marker}")
    require('args.ssh_target != "openwrt"' in runner, "runner SSH alias guard missing")
    require("StrictHostKeyChecking=yes" in runner, "strict host-key check missing")
    require("if transferred:" in runner, "emergency cleanup missing")
    combined_scripts = (harness + runner).lower()
    for forbidden in (
        "sysupgrade",
        "ubiformat",
        "ubiupdatevol",
        "mtd write",
        "mtd erase",
        "apk add",
        "apk del",
    ):
        require(forbidden not in combined_scripts,
                f"forbidden operation present: {forbidden}")
    for forbidden_command in ("reboot", "poweroff"):
        pattern = rf"(?<![a-z0-9_]){forbidden_command}(?![a-z0-9_])"
        require(re.search(pattern, combined_scripts) is None,
                f"forbidden operation present: {forbidden_command}")

    for marker in REPORT_MARKERS:
        require(marker in report, f"report marker missing: {marker}")
    for marker in RUNBOOK_MARKERS:
        require(marker in runbook, f"runbook marker missing: {marker}")

    print("h1_4_offline_preflight=true")
    print("h1_4_device_run=false")
    print("device_contact_during_preflight=false")
    print("candidate_identity=true")
    print("target_busybox_ash_syntax=true")
    print("real_ubus_calls=false")
    print("persistent_device_writes=false")
    print("runtime_mount_changes=false")
    print("package_install=false")
    print("router_reboot=false")
    print("firmware_flash=false")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"h1_4_offline_preflight=false: {error}") from error
