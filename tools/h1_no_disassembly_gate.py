#!/usr/bin/env python3
"""Validate the offline no-disassembly H1 policy without contacting a router."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
CANDIDATE_SHA256 = "b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75"
INPUT_HASHES = {
    "replacement_boundary": "9bf838a7d6a913384cdb40118289c249f28eac0d75f865ec0bd6d3e7739fc92b",
    "v1_validation": "7acd6d3cd26cec7aa7be32e71b6e617bbc739b0fbc1c9c0a4b4a8ae0ba62fb8d",
    "h1_2_preflight": "7b1ffa8b087e4f6e9c2134540cc30177c9df36f6d0842bcb77711b77790d5b58",
    "h1_3b_preflight": "3da993dea02b1f48b06ff63064fd5a5ad94f8c0881abd7b3a7d377a74741dd42",
}
PERMITTED_ACCESS = {"ethernet", "wifi", "existing-openwrt-ssh"}
PROHIBITED_ACCESS = {
    "case-disassembly",
    "mainboard-test-points",
    "soldering",
    "usb-uart",
    "tftp-bootloader",
    "raw-nand-read",
    "firmware-flash",
}
DO_NOT_TOUCH = {"R01", "R03", "R08", "R12", "R17"}
FALSE_GATES = {
    "device_contact",
    "device_writes",
    "firmware_flash",
    "h1_2_raw_backup",
    "h1_3b_ram_boot",
    "h1_4_device_run",
    "h1_5_disabled_install",
    "h1_6_canary",
    "router_reboot",
}
FALSE_SCOPE = {
    "bootloader_commands",
    "device_contact",
    "device_execution",
    "device_transfer",
    "device_writes",
    "firmware_flash",
    "host_network_changes",
    "package_install",
    "router_reboot",
    "runtime_mount_change",
}
EXPECTED_DISPOSITIONS = {
    "H1.2-private-backup": "not_applicable_under_no_disassembly_policy",
    "H1.3b-ram-boot": "not_applicable_under_no_disassembly_policy",
}
REQUIRED_MARKERS = {
    "decision": (
        "实体设备验证采用无拆机路径",
        "普通“继续”不能恢复 UART/刷机路径",
    ),
    "report": (
        "complete_offline_policy_only",
        "项目不因用户拒绝拆机而阻塞",
        "H1.4-preflight",
    ),
    "runbook": (
        "不拆机执行边界",
        "H1.3b：历史记录，按无拆机边界不再执行",
        "H1.4：下一条可执行路径",
    ),
    "plan": (
        "H1 无拆机边界重规划",
        "H1.4 offline preflight",
        "not_applicable_under_no_disassembly_policy",
    ),
}


class GateError(RuntimeError):
    """Raised when the policy is inconsistent or widens device authority."""


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
    parser.add_argument("--replacement-boundary", required=True, type=Path)
    parser.add_argument("--v1", required=True, type=Path)
    parser.add_argument("--h1-2", required=True, type=Path)
    parser.add_argument("--h1-3b", required=True, type=Path)
    parser.add_argument("--decision", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--runbook", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    replacement = load_json(args.replacement_boundary)
    v1 = load_json(args.v1)
    h1_2 = load_json(args.h1_2)
    h1_3b = load_json(args.h1_3b)

    require(manifest.get("schema_version") == 1, "schema version mismatch")
    require(manifest.get("evidence_id") == IMAGE_ID, "evidence id mismatch")
    require(manifest.get("stage") == "H1-no-disassembly-replan", "stage mismatch")
    require(
        manifest.get("status") == "complete_offline_policy_only",
        "policy status widened",
    )

    input_paths = {
        "replacement_boundary": args.replacement_boundary,
        "v1_validation": args.v1,
        "h1_2_preflight": args.h1_2,
        "h1_3b_preflight": args.h1_3b,
    }
    for key, path in input_paths.items():
        actual = sha256_file(path)
        require(actual == INPUT_HASHES[key], f"{key} input changed")
        recorded = manifest.get("inputs", {}).get(key, {})
        require(recorded.get("sha256") == actual, f"{key} recorded hash mismatch")

    classifications = {
        item.get("id"): item.get("category") for item in replacement.get("classification", [])
    }
    require(classifications.get("R05") == "rust-replace", "R05 is not the replacement slice")
    require(
        {key for key, value in classifications.items() if value == "do-not-touch"}
        == DO_NOT_TOUCH,
        "do-not-touch responsibility set changed",
    )
    r05 = next(item for item in replacement["classification"] if item.get("id") == "R05")
    require("no persistent state" in r05.get("rationale", ""), "R05 state boundary changed")

    require(v1.get("status") == "complete", "V1 is not complete")
    require(v1.get("gate", {}).get("passed") is True, "V1 gate is false")
    require(v1.get("lifecycle", {}).get("install_default_disabled") is True,
            "V1 default-disabled property lost")
    require(v1.get("lifecycle", {}).get("reboot_volatile") is True,
            "V1 reboot-volatile property lost")
    require(v1.get("installed_binary", {}).get("sha256") == CANDIDATE_SHA256,
            "candidate identity mismatch")

    require(h1_2.get("stage") == "H1.2-preflight", "H1.2 input stage mismatch")
    require(h1_2.get("scope", {}).get("device_contact") is False,
            "H1.2 contacted the device")
    require(h1_2.get("gates", {}).get("h1_2_private_backup") is False,
            "H1.2 backup was forged complete")
    require(h1_3b.get("stage") == "H1.3b-preflight", "H1.3b input stage mismatch")
    require(h1_3b.get("gates", {}).get("h1_3b_ram_boot") is False,
            "H1.3b RAM boot was forged complete")
    require(h1_3b.get("scope", {}).get("device_contact") is False,
            "H1.3b contacted the device")

    policy = manifest.get("physical_access_policy", {})
    require(policy.get("source") == "explicit-user-constraint", "policy source mismatch")
    require(policy.get("status") == "fixed", "physical policy is not fixed")
    require(set(policy.get("permitted", [])) == PERMITTED_ACCESS, "permitted access widened")
    require(set(policy.get("prohibited", [])) == PROHIBITED_ACCESS,
            "prohibited access set changed")

    candidate = manifest.get("candidate_scope", {})
    require(candidate.get("allowed_responsibilities") == ["R05"], "candidate scope widened")
    require(candidate.get("candidate_sha256") == CANDIDATE_SHA256,
            "recorded candidate mismatch")
    require(candidate.get("persistent_state") is False, "persistent state admitted")
    require(candidate.get("switch") == "reboot-volatile bind mount", "switch changed")

    dispositions = manifest.get("historical_disposition", [])
    observed_dispositions = {item.get("stage"): item.get("disposition") for item in dispositions}
    require(observed_dispositions == EXPECTED_DISPOSITIONS, "historical disposition changed")
    require(all(item.get("device_execution") is False for item in dispositions),
            "historical device execution was forged")

    next_stage = manifest.get("next_stage", {})
    require(next_stage.get("id") == "H1.4-preflight", "next stage mismatch")
    require(next_stage.get("status") == "ready_for_offline_preflight_only",
            "next stage authority widened")
    require(next_stage.get("commands") == [], "device commands admitted")
    require(next_stage.get("device_authorization_inherited") is False,
            "device authorization was inherited")

    authorization = manifest.get("authorization", {})
    require(authorization.get("policy_replan_authorized") is True,
            "policy replan authorization missing")
    for key in (
        "device_contact_authorized",
        "device_execution_authorized",
        "device_transfer_authorized",
        "router_reboot_authorized",
    ):
        require(authorization.get(key) is False, f"authorization widened: {key}")

    gates = manifest.get("gates", {})
    require(gates.get("no_disassembly_policy_review") is True, "policy review gate is false")
    require(gates.get("h1_4_offline_preflight_ready") is True,
            "H1.4 offline preflight is not ready")
    for key in FALSE_GATES:
        require(gates.get(key) is False, f"closed gate opened: {key}")
    scope = manifest.get("scope", {})
    for key in FALSE_SCOPE:
        require(scope.get(key) is False, f"scope widened: {key}")

    recovery = manifest.get("recovery_alignment", {})
    require(recovery.get("uart_required_for_current_candidate") is False,
            "UART was restored as an R05 prerequisite")
    require(set(recovery.get("excluded_failure_layers", [])) == {
        "bootloader", "kernel", "ubi", "raw-nand", "network-ownership"
    }, "excluded failure layers changed")

    texts = {
        "decision": args.decision.read_text(encoding="utf-8"),
        "report": args.report.read_text(encoding="utf-8"),
        "runbook": args.runbook.read_text(encoding="utf-8"),
        "plan": args.plan.read_text(encoding="utf-8"),
    }
    for key, markers in REQUIRED_MARKERS.items():
        for marker in markers:
            require(marker in texts[key], f"{key} marker missing: {marker}")

    print("no_disassembly_policy_review=true")
    print("h1_4_offline_preflight_ready=true")
    print("h1_4_device_run=false")
    print("device_contact=false")
    print("device_writes=false")
    print("firmware_flash=false")
    print("next_stage=H1.4-preflight")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, ValueError, KeyError, StopIteration, json.JSONDecodeError) as error:
        raise SystemExit(f"no_disassembly_policy_review=false: {error}") from error
