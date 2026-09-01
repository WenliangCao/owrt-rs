#!/usr/bin/env python3
"""Validate an H1.1b private run and emit a redacted boot-branch manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
COMMAND_ID = "H1-RO-11"
COMMAND_SHA256 = "cbf3b3ad9b3e22685cbf5e1ef2a1e35891aee2daa1cfd8c7d92b7018bfaeab48"
BUILDROOT_COMMIT = "f0a60eee2fe051741c643ea6118718aae1ef17fb"
BOOTCOUNT_SHA256 = "fe6e18a37531de608315c592b39f36da1a9c68e9f108aa5f5af152a42e9b27e3"
PLATFORM_SH_SHA256 = "72c75ab0ee140e4f543fa0c30becb265f529ec87657961803f981bbf96f3dc7f"
VARIABLES = [
    "boot_wait",
    "uart_en",
    "flag_boot_rootfs",
    "flag_last_success",
    "flag_boot_success",
    "flag_ota_reboot",
    "flag_try_sys1_failed",
    "flag_try_sys2_failed",
]


class EvidenceError(RuntimeError):
    """Raised when the run differs from the authorized H1.1b boundary."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def load_json(file_name: Path) -> dict[str, Any]:
    return json.loads(file_name.read_text(encoding="utf-8"))


def sha256_file(file_name: Path) -> str:
    digest = hashlib.sha256()
    with file_name.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_entry(command_plan: dict[str, Any]) -> dict[str, Any]:
    entries = [
        entry
        for batch in command_plan.get("batches", [])
        for entry in batch.get("commands", [])
        if entry.get("id") == COMMAND_ID
    ]
    require(len(entries) == 1, "H1-RO-11 is not unique in the command plan")
    entry = entries[0]
    observed_hash = hashlib.sha256(entry.get("command", "").encode("utf-8")).hexdigest()
    require(observed_hash == COMMAND_SHA256, "H1-RO-11 command hash mismatch")
    require(entry.get("expected_status") == 0, "H1-RO-11 expected status changed")
    return entry


def validate_authorization(
    authorization: dict[str, Any], command_plan_file: Path, h1_1a_file: Path,
    source_baseline_file: Path,
) -> None:
    require(authorization.get("evidence_id") == IMAGE_ID, "authorization evidence id mismatch")
    require(authorization.get("stage") == "H1.1b", "authorization stage mismatch")
    require(authorization.get("authorization", {}).get("status") == "approved",
            "H1.1b was not approved")
    require(authorization.get("authorization", {}).get("single_run") is True,
            "authorization is not single-run")
    require(authorization.get("approved_command_ids") == [COMMAND_ID],
            "authorization includes an unexpected command")
    require(authorization.get("variables") == VARIABLES, "variable whitelist changed")
    require(authorization.get("command", {}).get("sha256") == COMMAND_SHA256,
            "authorized command hash mismatch")
    require(
        authorization.get("command_plan", {}).get("sha256") == sha256_file(command_plan_file),
        "authorized command-plan hash mismatch",
    )
    prerequisites = authorization.get("preconditions", {})
    require(prerequisites.get("h1_1a_passed") is True, "H1.1a precondition is false")
    require(prerequisites.get("h1_1b_layout_precondition_passed") is True,
            "H1.1b layout precondition is false")
    require(
        prerequisites.get("h1_1a_observations", {}).get("sha256") == sha256_file(h1_1a_file),
        "H1.1a observation hash mismatch",
    )
    require(
        prerequisites.get("source_baseline", {}).get("sha256")
        == sha256_file(source_baseline_file),
        "source-baseline hash mismatch",
    )
    scope = authorization.get("scope", {})
    require(scope.get("boot_environment_read") is True, "boot environment read not authorized")
    require(scope.get("approved_variable_count") == 8, "approved variable count mismatch")
    for key in (
        "complete_environment_read", "device_writes", "firmware_flash", "package_install",
        "package_transfer", "raw_mtd_payload_read", "router_reboot", "service_or_network_change",
    ):
        require(scope.get(key) is False, f"authorization permits {key}")


def validate_preconditions(h1_1a: dict[str, Any], source_baseline: dict[str, Any]) -> None:
    require(h1_1a.get("evidence_id") == IMAGE_ID, "H1.1a evidence id mismatch")
    require(h1_1a.get("status") == "passed_read_only", "H1.1a did not pass")
    gates = h1_1a.get("gates", {})
    require(gates.get("h1_1a_read_only_observation") is True, "H1.1a gate is false")
    require(gates.get("h1_1b_layout_precondition") is True, "layout precondition is false")
    require(h1_1a.get("scope", {}).get("device_writes") is False,
            "H1.1a scope contains device writes")
    require(source_baseline.get("evidence_id") == IMAGE_ID, "source evidence id mismatch")
    require(source_baseline.get("buildroot", {}).get("commit") == BUILDROOT_COMMIT,
            "exact buildroot commit mismatch")
    require(source_baseline.get("device", {}).get("compatible") == "xiaomi,mi-router-ax3000t",
            "source board mismatch")
    require(source_baseline.get("device", {}).get("layout") == "stock",
            "source layout mismatch")


def validate_status(evidence_dir: Path) -> dict[str, Any]:
    status = load_json(evidence_dir / "exit-status.json")
    require(status.get("command_count") == 1, "collector command count is not one")
    entries = status.get("commands", [])
    require(len(entries) == 1 and entries[0].get("id") == COMMAND_ID,
            "collector command id mismatch")
    require(entries[0].get("command_sha256") == COMMAND_SHA256,
            "collector command hash mismatch")
    require(entries[0].get("exit_status") == 0, "H1-RO-11 failed")
    return entries[0]


def parse_values(stdout: str, stderr: str) -> dict[str, str]:
    require(stderr == "", "H1-RO-11 produced stderr")
    lines = stdout.splitlines()
    require(len(lines) == 8, "H1-RO-11 did not return exactly eight lines")
    values: dict[str, str] = {}
    order: list[str] = []
    for line in lines:
        match = re.fullmatch(r"([a-z0-9_]+)=(\S+)", line)
        require(bool(match), "malformed fw_printenv output")
        name, observed = match.groups()
        require(name not in values, f"duplicate variable: {name}")
        values[name] = observed
        order.append(name)
    require(order == VARIABLES, "variable output order or whitelist mismatch")
    return values


def validate_contract(values: dict[str, str]) -> dict[str, Any]:
    require(values["boot_wait"] == "on", "boot_wait is not enabled")
    require(values["uart_en"] == "1", "uart_en is not enabled")
    require(values["flag_boot_rootfs"] in {"0", "1"}, "rootfs flag is outside slot domain")
    require(values["flag_boot_rootfs"] == "0", "rootfs flag disagrees with observed firmware=0")
    require(values["flag_last_success"] in {"0", "1"}, "last-success flag is invalid")
    require(values["flag_boot_success"] in {"0", "1"}, "boot-success flag is invalid")
    require(values["flag_ota_reboot"] in {"0", "1"}, "OTA reboot flag is invalid")
    require(values["flag_try_sys1_failed"].isdigit(), "system-1 counter is not numeric")
    require(values["flag_try_sys2_failed"].isdigit(), "system-2 counter is not numeric")
    require(values["flag_try_sys2_failed"] == "8", "bootcount early-exit sentinel is absent")
    sys1_matches_source_writes = values["flag_try_sys1_failed"] in {"0", "8"}
    return {
        "all_whitelisted_variables_present": True,
        "unapproved_variables_observed": False,
        "boot_wait_enabled": True,
        "uart_enabled": True,
        "active_rootfs_slot": 0,
        "active_rootfs_matches_kernel_command_line": True,
        "last_success_asserted": values["flag_last_success"] == "1",
        "boot_success_asserted": values["flag_boot_success"] == "1",
        "ota_reboot_clear": values["flag_ota_reboot"] == "0",
        "bootcount_early_exit_branch": True,
        "system_2_counter_matches_openwrt_sentinel": True,
        "system_1_counter_numeric": True,
        "system_1_counter_matches_openwrt_written_values": sys1_matches_source_writes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--command-plan", required=True, type=Path)
    parser.add_argument("--h1-1a", required=True, type=Path)
    parser.add_argument("--source-baseline", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    authorization = load_json(args.authorization)
    command_plan = load_json(args.command_plan)
    h1_1a = load_json(args.h1_1a)
    source_baseline = load_json(args.source_baseline)
    validate_authorization(
        authorization, args.command_plan, args.h1_1a, args.source_baseline
    )
    command_entry(command_plan)
    validate_preconditions(h1_1a, source_baseline)
    status = validate_status(args.evidence)

    stdout_file = args.evidence / "raw" / "H1-RO-11.txt"
    stderr_file = args.evidence / "raw" / "H1-RO-11.stderr"
    require(stdout_file.is_file(), "H1-RO-11 stdout missing")
    require(stderr_file.is_file(), "H1-RO-11 stderr missing")
    values = parse_values(
        stdout_file.read_text(encoding="utf-8"), stderr_file.read_text(encoding="utf-8")
    )
    contract = validate_contract(values)

    manifest = {
        "schema_version": 1,
        "evidence_id": IMAGE_ID,
        "stage": "H1.1b",
        "status": "passed_with_open_question",
        "recorded_at": args.recorded_at,
        "authorization": {
            "approved": True,
            "single_run_consumed": True,
            "command_id": COMMAND_ID,
            "command_sha256": COMMAND_SHA256,
            "authorization_manifest_sha256": sha256_file(args.authorization),
            "command_plan_sha256": sha256_file(args.command_plan),
        },
        "collection": {
            "started_at": status["started_at"],
            "ended_at": status["ended_at"],
            "command_count": 1,
            "successful_commands": 1,
            "stdout_sha256": sha256_file(stdout_file),
            "stderr_sha256": sha256_file(stderr_file),
            "stderr_empty": True,
            "raw_evidence_committed": False,
        },
        "source_contract": {
            "buildroot_commit": BUILDROOT_COMMIT,
            "bootcount_path": "target/linux/mediatek/filogic/base-files/etc/init.d/bootcount",
            "bootcount_sha256": BOOTCOUNT_SHA256,
            "bootcount_lines": "6-24",
            "platform_path": "target/linux/mediatek/filogic/base-files/lib/upgrade/platform.sh",
            "platform_sha256": PLATFORM_SH_SHA256,
            "platform_lines": "48-90",
            "openwrt_reads": ["flag_try_sys2_failed"],
            "openwrt_writes": VARIABLES,
            "counter_values_written_by_openwrt": [0, 8],
        },
        "observations": contract,
        "open_questions": [
            {
                "id": "H1-OQ-01",
                "statement": (
                    "The system-1 failure counter is numeric but outside the values written by "
                    "the exact OpenWrt source. No exact-source OpenWrt caller reads this variable; "
                    "bootloader ownership and transition semantics remain unknown."
                ),
                "raw_value_committed": False,
                "blocks": ["boot-flag mutation", "slot switching", "firmware upgrade"],
                "does_not_block": ["H1.2 read-only private backup preparation"],
                "status": "open_scoped",
            }
        ],
        "gates": {
            "h1_1a_read_only_observation": True,
            "h1_1b_boot_environment_read": True,
            "h1_1b_whitelist_complete": True,
            "boot_branch_explained_for_openwrt_callers": True,
            "bootloader_counter_semantics_complete": False,
            "h1_2_private_backup": False,
            "h1_3_recovery_rehearsal": False,
            "h1_4_tmpfs_shadow": False,
            "h1_5_disabled_install": False,
            "h1_6_canary": False,
            "device_writes_allowed": False,
            "firmware_flash_allowed": False,
        },
        "scope": {
            "device_contact": True,
            "boot_environment_values_read": True,
            "complete_environment_read": False,
            "device_writes": False,
            "raw_mtd_payload_read": False,
            "package_transfer": False,
            "package_install": False,
            "router_reboot": False,
            "runtime_mount_change": False,
            "service_or_network_change": False,
            "firmware_flash": False,
        },
        "redaction": {
            "approved_variable_names_committed": True,
            "raw_values_committed": False,
            "raw_output_location": "private evidence outside Git",
            "asserted": True,
        },
    }
    rendered = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    for name in VARIABLES:
        require(f"{name}=" not in rendered, f"raw value leaked for {name}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(json.dumps({
        "h1_1b_gate_passed": True,
        "open_questions": 1,
        "device_writes": False,
        "raw_values_committed": False,
        "output": str(args.output),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except EvidenceError as error:
        raise SystemExit(f"H1.1b gate failed: {error}") from error
