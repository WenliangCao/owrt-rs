#!/usr/bin/env python3
"""Review private H1.4 runs and the redacted device-shadow conclusion."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
CANDIDATE_SHA256 = "b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75"
HARNESS_SHA256 = "cfe8bc2754f37fbd644f74c456728aa1ebb5350a9a441cd6a358473852e420e0"
RUNNER_SHA256 = "b3f517e740c398684f11d958fdbf9dc340e6c2b352a5e3684b227eebbafdceeb"
PREFLIGHT_SHA256 = "94ed9d5e099ee132320d071c94668a082d172312fb1f65240b9c1f6142a87e0a"
CONTRACT_SHA256 = "10c9f7de0e517e734e4cb4e6ccd44c832f4cae207303211a72ae02c7786a5318"
DISPATCHER_SHA256 = "f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15"
BASELINE_SHA256 = "b77e0e99672ee504d1ee1183f14b8ba8cfe92f6c546aa585f7efc784d2b0c163"
CONFIG_TREE_SHA256 = "c571059487c486dc8f255228f49ab558092a50ee22c0845c91ed4839a0ded44a"
PACKAGE_DATABASE_SHA256 = "6149a91ae1efa348b3e56d08ef13f844ecee6288a78448749519682a9e8cb5fc"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ATTEMPTS = [
    ("run-01", "run", "981322f948aba4469862fe849ed7ffe54dd6d216c9c295995dffc9aaa38bf2a2", "failed"),
    ("run-02", "run-02", "e0c9422e045a89dfd630bc006782c387283abc46a393a1e2801afb196731822d", "failed"),
    ("run-03", "run-03", "67489da4a00ee034bd53b12fad03309a35f43d5152e3cfa8b5f7ed8bcae03418", "failed"),
    ("run-04", "run-04", "2fa6614cea50b8b01c6f827ddfaf2743a3b81636a5e6e5ddf7379d1800d5a589", "failed"),
    ("run-05", "run-05", "50b66225f92c1376d9b86d8f2810ba789bff752b3bd3efffa474f54a16f32ec0", "failed"),
    ("run-06", "run-06", "fe845cb7a0e83bcdf046f9b4be44a1ae2436f49ed25f20ef348c673aa1cbd271", "passed"),
]
FINAL_RECORDS = [
    "identity",
    "transfer_candidate",
    "transfer_harness",
    "shadow",
    "cleanup",
    "verify",
]
DOTTED_PACKAGES = {
    "dhcp.bak-codex-disable-ipv6-20260425",
    "dhcp.bak-codex-nextdns-doq-20260516-200927",
    "dhcp.bak-codex-rollback-dns-20260517-144734",
    "dnsproxy.bak-codex-rollback-dns-20260517-144734",
    "dnsproxy.disabled-codex-rollback-20260517-144902",
    "network.bak-codex-disable-ipv6-20260425",
    "wireless.bak-codex-after-reset-default-20260422",
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


def block(text: str, name: str) -> list[str]:
    lines = text.splitlines()
    begin = f"{name}_begin"
    end = f"{name}_end"
    begin_indexes = [index for index, line in enumerate(lines) if line == begin]
    end_indexes = [index for index, line in enumerate(lines) if line == end]
    require(len(begin_indexes) == 1 and len(end_indexes) == 1,
            f"block mismatch: {name}")
    require(begin_indexes[0] < end_indexes[0], f"block order mismatch: {name}")
    return lines[begin_indexes[0] + 1:end_indexes[0]]


def trace(text: str, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in block(text, f"trace_{name}")]


def comparison(items: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [item for item in items if item.get("kind") == "comparison"]
    require(len(matches) == 1, "comparison trace count mismatch")
    return matches[0]


def verify_trace(
    items: list[dict[str, Any]],
    compared: int,
    changed: list[str],
    new_count: int,
    delivery: str | None,
) -> None:
    normalizations = [item for item in items if item.get("kind") == "normalization"]
    require(len(normalizations) == 7, "dotted normalization count mismatch")
    require({item.get("package") for item in normalizations} == DOTTED_PACKAGES,
            "dotted normalization package set mismatch")
    require(all(item.get("status") == "exit_1" for item in normalizations),
            "dotted normalization result changed")
    observed = comparison(items)
    require(observed.get("compared_count") == compared, "compared count mismatch")
    require(observed.get("changed_entries") == changed, "changed entries mismatch")
    require(observed.get("new_baseline_count") == new_count, "new baseline count mismatch")
    deliveries = [item for item in items if item.get("kind") == "delivery"]
    if delivery is None:
        require(deliveries == [], "unexpected delivery trace")
    else:
        require(len(deliveries) == 1, "delivery trace count mismatch")
        require(deliveries[0].get("package") == delivery, "delivery package mismatch")
        require(deliveries[0].get("outcome") == "success", "delivery did not succeed")
        require(deliveries[0].get("status") == 0, "delivery status mismatch")
    complete = [item for item in items if item.get("kind") == "complete"]
    require(len(complete) == 1, "completion trace count mismatch")
    require(complete[0].get("baseline_rewritten") is True, "baseline was not rewritten")
    require(complete[0].get("delivery_failures") == 0, "delivery failure observed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--harness", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--runbook", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    require(manifest.get("schema_version") == 1, "schema version mismatch")
    require(manifest.get("evidence_id") == IMAGE_ID, "evidence id mismatch")
    require(manifest.get("stage") == "H1.4-device-shadow", "stage mismatch")
    require(manifest.get("status") == "complete_passed_with_live_baseline_drift",
            "status mismatch")

    files = {
        "preflight": (args.preflight, PREFLIGHT_SHA256),
        "contract": (args.contract, CONTRACT_SHA256),
        "candidate": (args.candidate, CANDIDATE_SHA256),
        "harness": (args.harness, HARNESS_SHA256),
        "runner": (args.runner, RUNNER_SHA256),
    }
    for key, (path, expected) in files.items():
        require(sha256_file(path) == expected, f"{key} input changed")
        require(manifest.get("inputs", {}).get(key, {}).get("sha256") == expected,
                f"recorded {key} hash mismatch")
    require(args.candidate.stat().st_size == 346_531, "candidate size mismatch")
    require(manifest.get("inputs", {}).get("candidate", {}).get("size_bytes") == 346_531,
            "recorded candidate size mismatch")

    require(args.evidence_root.name == "h1-4-20260901", "private evidence root mismatch")
    public_attempts = manifest.get("attempts", [])
    require(len(public_attempts) == len(ATTEMPTS), "attempt count mismatch")
    for index, (attempt_id, dirname, expected_hash, expected_status) in enumerate(ATTEMPTS):
        run_dir = args.evidence_root / dirname
        run_path = run_dir / "run.json"
        require(sha256_file(run_path) == expected_hash, f"{attempt_id} manifest changed")
        private = load_json(run_path)
        require(private.get("stage") == "H1.4-device-run-private",
                f"{attempt_id} stage mismatch")
        require(private.get("status") == expected_status, f"{attempt_id} status mismatch")
        require(private.get("candidate_sha256") == CANDIDATE_SHA256,
                f"{attempt_id} candidate mismatch")
        records = {item.get("name"): item for item in private.get("records", [])}
        require(records.get("identity", {}).get("exit_status") == 0,
                f"{attempt_id} identity failed")
        require(records.get("verify", {}).get("exit_status") == 0,
                f"{attempt_id} post-cleanup verification failed")
        verify_text = (run_dir / "verify.stdout").read_text(encoding="utf-8")
        require("post_cleanup=PASS" in verify_text, f"{attempt_id} cleanup marker missing")
        require(DISPATCHER_SHA256 in verify_text and BASELINE_SHA256 in verify_text,
                f"{attempt_id} post-cleanup identity mismatch")
        scope = private.get("scope", {})
        for key in (
            "firmware_flash",
            "package_install",
            "persistent_writes",
            "real_ubus_calls",
            "router_reboot",
            "runtime_mount_changes",
        ):
            require(scope.get(key) is False, f"{attempt_id} scope permits {key}")
        public = public_attempts[index]
        require(public.get("id") == attempt_id, f"{attempt_id} public order mismatch")
        require(public.get("private_manifest_sha256") == expected_hash,
                f"{attempt_id} public hash mismatch")
        require(public.get("cleanup_verified") is True, f"{attempt_id} cleanup not recorded")
        require(public.get("status") == ("passed" if expected_status == "passed"
                                         else "failed_closed"),
                f"{attempt_id} public status mismatch")

    final_dir = args.evidence_root / "run-06"
    final = load_json(final_dir / "run.json")
    require(final.get("error") is None, "successful run records an error")
    records = final.get("records", [])
    require([item.get("name") for item in records] == FINAL_RECORDS,
            "successful record order mismatch")
    require(all(item.get("exit_status") == 0 for item in records), "successful record failed")
    require(all(item.get("stderr_sha256") == EMPTY_SHA256 for item in records),
            "successful stderr is not empty")
    for record in records:
        require((final_dir / f"{record['name']}.stderr").stat().st_size == 0,
                f"{record['name']} stderr has bytes")

    identity_text = (final_dir / "identity.stdout").read_text(encoding="utf-8")
    for marker in (
        "DISTRIB_RELEASE='25.12.5'",
        "DISTRIB_REVISION='r33051-f5dae5ece4'",
        "DISTRIB_TARGET='mediatek/filogic'",
        "xiaomi,mi-router-ax3000t",
        "6.12.94",
        DISPATCHER_SHA256,
        BASELINE_SHA256,
    ):
        require(marker in identity_text, f"identity marker missing: {marker}")

    shadow_path = final_dir / "shadow.stdout"
    shadow_text = shadow_path.read_text(encoding="utf-8")
    for marker in (
        "h1_4_shadow=PASS",
        "run0_shared_drift_network=PASS",
        "run1_steady_state=PASS",
        "run2_creation_silent=PASS",
        "run3_modification_event=PASS",
        "real_ubus_calls=0",
        "persistent_writes=0",
        "runtime_mount_changes=0",
        "cleanup=PASS",
    ):
        require(marker in shadow_text, f"shadow marker missing: {marker}")
    require("failed_step=" not in shadow_text, "successful run has failed step")
    verify_trace(trace(shadow_text, "run0_shared_drift"), 19, ["network"], 19, "network")
    verify_trace(trace(shadow_text, "run1_steady_state"), 19, [], 19, None)
    verify_trace(trace(shadow_text, "run2_creation_silent"), 19, [], 20, None)
    verify_trace(
        trace(shadow_text, "run3_modification_event"),
        20,
        ["h1_shadow_probe"],
        20,
        "h1_shadow_probe",
    )
    require(block(shadow_text, "drift_fake_ubus") == [
        'call\tservice\tevent\t{ "type": "config.change", "data": { "package": "network" } }'
    ], "drift fake-ubus call mismatch")
    require(block(shadow_text, "fake_ubus") == [
        'call\tservice\tevent\t{ "type": "config.change", "data": { "package": "h1_shadow_probe" } }'
    ], "synthetic fake-ubus call mismatch")

    successful = manifest.get("private_successful_run", {})
    require(successful.get("identity_stdout_sha256") == sha256_file(final_dir / "identity.stdout"),
            "identity stdout hash mismatch")
    require(successful.get("shadow_stdout_sha256") == sha256_file(shadow_path),
            "shadow stdout hash mismatch")
    require(successful.get("verify_stdout_sha256") == sha256_file(final_dir / "verify.stdout"),
            "verify stdout hash mismatch")
    require(successful.get("stderr_all_empty") is True, "stderr result mismatch")

    observations = manifest.get("observations", {})
    require(observations.get("dotted_normalization_exit_count_each_run") == 7,
            "public dotted count mismatch")
    expected_observations = {
        "run0_shared_drift": (19, ["network"], 19, 1),
        "run1_steady_state": (19, [], 19, 0),
        "run2_creation_silent": (19, [], 20, 0),
        "run3_modification_event": (20, ["h1_shadow_probe"], 20, 1),
    }
    for key, (compared, changed, new_count, deliveries) in expected_observations.items():
        item = observations.get(key, {})
        require(item.get("passed") is True, f"public observation failed: {key}")
        require(item.get("compared_count") == compared, f"public compared mismatch: {key}")
        require(item.get("changed_entries") == changed, f"public changed mismatch: {key}")
        require(item.get("new_baseline_count") == new_count,
                f"public baseline count mismatch: {key}")
        require(item.get("fake_deliveries") == deliveries,
                f"public delivery count mismatch: {key}")

    require(manifest.get("device_identity") == {
        "board": "xiaomi,mi-router-ax3000t",
        "kernel": "6.12.94",
        "layout": "stock",
        "release": "25.12.5",
        "revision": "r33051-f5dae5ece4",
        "target": "mediatek/filogic",
    }, "public device identity changed")
    require(manifest.get("live_invariants") == {
        "baseline_sha256": BASELINE_SHA256,
        "config_tree_sha256": CONFIG_TREE_SHA256,
        "dispatcher_sha256": DISPATCHER_SHA256,
        "mount_count": 0,
        "package_database_sha256": PACKAGE_DATABASE_SHA256,
        "uci_tree_sha256": "absent",
    }, "public live invariants changed")
    for marker in (
        f"live_config_tree_sha256={CONFIG_TREE_SHA256}",
        "live_uci_tree_sha256=absent",
        f"live_baseline_sha256={BASELINE_SHA256}",
        f"package_db_sha256={PACKAGE_DATABASE_SHA256}",
        "mount_count=0",
    ):
        require(marker in shadow_text, f"live invariant marker missing: {marker}")

    effects = manifest.get("device_effects", {})
    require(effects == {
        "candidate_installed": False,
        "device_contact": True,
        "device_execution": True,
        "device_transfer": True,
        "firmware_flash": False,
        "package_database_changed": False,
        "package_install": False,
        "persistent_writes": False,
        "real_ubus_calls": 0,
        "router_reboot": False,
        "runtime_mount_changes": 0,
        "tmpfs_writes": True,
    }, "public device effects changed")
    gates = manifest.get("gates", {})
    require(set(gates) == {
        "candidate_hardware_abi",
        "cleanup_verified",
        "config_tree_unchanged",
        "contract_shadow_sequence",
        "h1_4_device_run",
        "h1_5_disabled_install",
        "h1_6_canary_ready",
        "live_baseline_unchanged",
        "package_database_unchanged",
        "real_delivery_exercised",
        "runtime_mount_unchanged",
    }, "public gate fields changed")
    for key in (
        "candidate_hardware_abi",
        "cleanup_verified",
        "config_tree_unchanged",
        "contract_shadow_sequence",
        "h1_4_device_run",
        "live_baseline_unchanged",
        "package_database_unchanged",
        "runtime_mount_unchanged",
    ):
        require(gates.get(key) is True, f"public gate is false: {key}")
    for key in ("h1_5_disabled_install", "h1_6_canary_ready", "real_delivery_exercised"):
        require(gates.get(key) is False, f"closed public gate opened: {key}")
    next_stage = manifest.get("next_stage", {})
    require(next_stage.get("id") == "H1.5-disabled-install", "next stage mismatch")
    require(next_stage.get("status") == "not_authorized", "H1.5 authority widened")
    require("network baseline drift" in next_stage.get("blocker", ""),
            "canary drift blocker missing")

    report = args.report.read_text(encoding="utf-8")
    runbook = args.runbook.read_text(encoding="utf-8")
    plan = args.plan.read_text(encoding="utf-8")
    for marker in (
        "complete_passed_with_live_baseline_drift",
        "真实 baseline 没有被“顺手修复”",
        "h1_4_device_run=true",
        "h1_6_canary_ready=false",
        "H1.5",
    ):
        require(marker in report, f"report marker missing: {marker}")
    for marker in ("H1.4 tmpfs shadow run（已完成", "H1.5 默认禁用 APK 安装（需另行授权）"):
        require(marker in runbook, f"runbook marker missing: {marker}")
    for marker in ("H1.4 tmpfs-only shadow run 已完成", "H1.5 disabled install 尚未授权"):
        require(marker in plan, f"plan marker missing: {marker}")

    print("h1_4_device_run=true")
    print("candidate_hardware_abi=true")
    print("contract_shadow_sequence=true")
    print("live_baseline_drift=network")
    print("real_ubus_calls=0")
    print("persistent_writes=0")
    print("runtime_mount_changes=0")
    print("cleanup_verified=true")
    print("h1_5_disabled_install=false")
    print("h1_6_canary_ready=false")


if __name__ == "__main__":
    try:
        main()
    except (ReviewError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"h1_4_device_run=false: {error}") from error
