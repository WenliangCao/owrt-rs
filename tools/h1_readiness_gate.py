#!/usr/bin/env python3
"""Validate the H1.0 offline plan without contacting a physical router.

The gate deliberately passes only the offline-planning stage.  It proves that
the exact image/V1 inputs, staged authorization boundary, reviewed read-only
commands and recovery runbook agree.  It must keep every physical-device gate
closed until a later, separately authorized evidence run replaces the pending
prerequisites.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
EXPECTED_IMAGE = {
    "compatible": "xiaomi,mi-router-ax3000t",
    "layout": "stock",
    "version": "25.12.5",
    "revision": "r33051-f5dae5ece4",
    "target": "mediatek/filogic",
    "kernel": "6.12.94",
    "sha256": "a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea",
}
EXPECTED_V1 = {
    "candidate_sha256": "b49b054fb1eaf75a767356ec12270e11a9949777e4a59168a0cfb3aa60515f75",
    "apk_sha256": "02d0c977d68192c28d0ef537a704435d9814fb8e04763cd67d73e00e41e5d9b1",
}
EXPECTED_BACKUP_TOOL = {
    "index_sha256": "92a21556949408177649e0030f303cbc2771d98386cfe1d5e11a6c200ebc1f72",
    "apk_sha256": "a889a18c410b464dd0ec1538b0595d0566c921a16bd3dbeaf2b7f75a6efbcbca",
    "binary_sha256": "21d7c3daa9e792a9b892af956ce64c59c4588c99eb7084b93ef5ee6f4bd47b92",
}
EXPECTED_CONTROL_IDS = {
    "exact_image_pinned",
    "stock_layout_exclusion",
    "v1_gate_passed",
    "stage_authorization_boundary",
    "read_only_commands_reviewed",
    "private_evidence_boundary",
    "stop_and_rollback_defined",
    "recovery_scope_separated",
    "backup_tool_prepared",
}
EXPECTED_PENDING_IDS = {
    "physical_variant_and_sku",
    "fresh_runtime_identity",
    "storage_geometry_and_nmbm",
    "overlay_headroom",
    "boot_environment_branch",
    "known_good_artifacts_offline",
    "private_device_backups",
    "independent_backup_copies",
    "wired_independent_management",
    "power_cycle_rehearsal",
    "failsafe_rehearsal",
    "tmpfs_shadow",
    "disabled_install",
    "canary_window",
}
EXPECTED_STAGES = [
    "H1.0",
    "H1.1a",
    "H1.1b",
    "H1.2",
    "H1.3",
    "H1.4",
    "H1.5",
    "H1.6",
]
EXPECTED_COMMAND_IDS = {f"H1-RO-{number:02d}" for number in range(12)}
EXPECTED_COMMAND_SHA256 = {
    "H1-RO-00": "912ff740fbb643ca8ea1fcb9d8603c98270fc27c5970520de48a0c6cd867a78d",
    "H1-RO-01": "73599403bbe60b01816f5eafd4b121973389ffa7c28a764aec6076a58f1c7cca",
    "H1-RO-02": "d87ad9a63922b615dfa32e4c064982e8b1a68854e3c0de21c38b9baf7c27832b",
    "H1-RO-03": "76dae5d694e38dc9ebc32554d712de3fe0c826395d470ea0b35daf2098834d45",
    "H1-RO-04": "10d8d9d0805da468d3351ca3115c4670781a5c1796c612531d15d4abc40f2f3e",
    "H1-RO-05": "e56dfabe2e4c729510d44a3089565a043213459e4f435debb9dbe3b70aeab671",
    "H1-RO-06": "d1adcfd319acd02918a905e082c9bf95262b90559a49e92193ca191f6fc7fad1",
    "H1-RO-07": "99c20ad247526b6e9ae094665e93b7d79106c659e7b40328ef66ff689f65fb24",
    "H1-RO-08": "f30d2edbff3fd3b75f1866c38b90e2c75084388d2255913c9908e7d831d69ae5",
    "H1-RO-09": "add76de5adb585a586f968858159e2f159183edee401618dc5bc6c98e5762a9a",
    "H1-RO-10": "eb85fa3897dda9ed42903fa2c878dc8d67b525d3d3d571540ba81104fc7bd71a",
    "H1-RO-11": "cbf3b3ad9b3e22685cbf5e1ef2a1e35891aee2daa1cfd8c7d92b7018bfaeab48",
}
REQUIRED_RUNBOOK_MARKERS = (
    "H1.0 离线准入设计（当前完成）",
    "H1.1a 只读身份/存储元数据",
    "H1.6 短时 bind-mount canary",
    "全 H1 永久禁止",
    "不因 canary 失败自动进入 TFTP、UART、sysupgrade 或 raw flash",
)
REQUIRED_READ_ONLY_MARKERS = (
    "当前没有可执行 collector，也没有已批准命令",
    "H1.1a：只读身份与元数据",
    "H1.1b：白名单 U-Boot 环境读取",
    "明确不在本计划内",
)
MUTATING_COMMANDS = re.compile(
    r"(?:^|[;&|\n]\s*)(?:"
    r"mount|umount|mtd|ubiformat|ubiupdatevol|ubidetach|ubiattach|"
    r"fw_setenv|nvram|reboot|firstboot|jffs2reset|factoryreset|"
    r"sysupgrade|nanddump|dd|cp|mv|rm|touch|mkdir|tee"
    r")\b"
)
APK_MUTATION = re.compile(r"\bapk\s+(?:add|del|upgrade|update)\b")
SERVICE_MUTATION = re.compile(
    r"\b(?:service|network|wifi|firewall)\b.*\b(?:start|stop|restart|reload|up|down)\b"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def expect(condition: bool, message: str, problems: list[str]) -> None:
    if not condition:
        problems.append(message)


def validate_input_hash(
    readiness: dict[str, Any], key: str, path: Path, problems: list[str]
) -> None:
    recorded = readiness.get("inputs", {}).get(key, {})
    expect(recorded.get("sha256") == sha256_file(path), f"{key} hash mismatch", problems)


def validate_commands(commands: dict[str, Any], problems: list[str]) -> None:
    authorization = commands.get("authorization", {})
    for key in (
        "collector_approved",
        "device_access_approved",
        "h1_1a_approved",
        "h1_1b_approved",
    ):
        expect(authorization.get(key) is False, f"read-only {key} must be false", problems)
    method = commands.get("method", {})
    expect(method.get("contacts_device") is False, "command plan contacted device", problems)
    expect(method.get("device_writes") is False, "command plan permits writes", problems)
    expect(
        method.get("emits_runnable_collector") is False,
        "H1.0 must not emit a runnable collector",
        problems,
    )

    entries = [entry for batch in commands.get("batches", []) for entry in batch.get("commands", [])]
    ids = {entry.get("id") for entry in entries}
    expect(ids == EXPECTED_COMMAND_IDS, f"unexpected command ids: {sorted(ids)}", problems)
    expect(len(entries) == 12, f"expected 12 commands, found {len(entries)}", problems)
    expect(commands.get("counts", {}).get("commands") == 12, "command count mismatch", problems)
    expect(
        commands.get("counts", {}).get("approved_commands") == 0,
        "H1.0 must approve zero commands",
        problems,
    )

    for entry in entries:
        command = entry.get("command", "")
        identifier = entry.get("id", "unknown")
        expect(bool(entry.get("review")), f"{identifier} lacks source review", problems)
        expect(
            hashlib.sha256(command.encode("utf-8")).hexdigest()
            == EXPECTED_COMMAND_SHA256.get(identifier),
            f"{identifier} differs from the reviewed command",
            problems,
        )
        expect(
            not MUTATING_COMMANDS.search(command),
            f"{identifier} contains a mutating command position",
            problems,
        )
        expect(not APK_MUTATION.search(command), f"{identifier} invokes APK mutation", problems)
        expect(
            not SERVICE_MUTATION.search(command),
            f"{identifier} invokes service mutation",
            problems,
        )
        expect("dmesg -c" not in command, f"{identifier} clears dmesg", problems)
        expect(
            not re.search(r"(?:^|\s)(?:>|>>)(?!\s*/dev/null)", command),
            f"{identifier} redirects output to a file",
            problems,
        )
        expect(
            "$(" not in command and "`" not in command,
            f"{identifier} contains hidden command substitution",
            problems,
        )

    ubus_calls = [entry["command"] for entry in entries if "ubus call" in entry["command"]]
    expect(
        ubus_calls == [entries[0]["command"]]
        and "ubus call system board" in ubus_calls[0],
        "only ubus call system board is allowed",
        problems,
    )
    env_entries = [entry for entry in entries if "fw_printenv" in entry["command"]]
    expect(len(env_entries) == 2, "expected tool-discovery and one boot-env command", problems)
    expect(
        commands.get("batches", [{}])[-1].get("id") == "H1.1b"
        and [entry.get("id") for entry in commands["batches"][-1].get("commands", [])]
        == ["H1-RO-11"],
        "boot environment read must remain isolated in H1.1b",
        problems,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readiness", required=True, type=Path)
    parser.add_argument("--commands", required=True, type=Path)
    parser.add_argument("--backup-tool", required=True, type=Path)
    parser.add_argument("--intake", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--v1", required=True, type=Path)
    parser.add_argument("--runbook", required=True, type=Path)
    parser.add_argument("--read-only-plan", required=True, type=Path)
    args = parser.parse_args()

    readiness = load_json(args.readiness)
    commands = load_json(args.commands)
    backup_tool = load_json(args.backup_tool)
    intake = load_json(args.intake)
    runtime = load_json(args.runtime)
    v1 = load_json(args.v1)
    runbook = args.runbook.read_text(encoding="utf-8")
    read_only_plan = args.read_only_plan.read_text(encoding="utf-8")
    problems: list[str] = []

    expect(readiness.get("schema_version") == 1, "unexpected readiness schema", problems)
    expect(readiness.get("stage") == "H1.0", "unexpected readiness stage", problems)
    expect(
        readiness.get("status") == "complete_offline_only",
        "readiness status is not complete_offline_only",
        problems,
    )
    expect(readiness.get("evidence_id") == IMAGE_ID, "readiness evidence id mismatch", problems)
    expect(commands.get("evidence_id") == IMAGE_ID, "commands evidence id mismatch", problems)

    for key, path in (
        ("intake", args.intake),
        ("runtime", args.runtime),
        ("v1", args.v1),
        ("commands", args.commands),
        ("backup_tool", args.backup_tool),
        ("runbook", args.runbook),
        ("read_only_plan", args.read_only_plan),
    ):
        validate_input_hash(readiness, key, path, problems)

    firmware = intake.get("firmware", {})
    device = intake.get("device", {})
    for key in ("version", "revision", "target", "kernel", "sha256"):
        expect(firmware.get(key) == EXPECTED_IMAGE[key], f"intake {key} mismatch", problems)
    expect(
        device.get("compatible") == EXPECTED_IMAGE["compatible"],
        "intake compatible mismatch",
        problems,
    )
    expect(device.get("layout") == EXPECTED_IMAGE["layout"], "intake layout mismatch", problems)
    expect(
        intake.get("excluded_image", {}).get("filename", "").endswith(".itb"),
        "ubootmod exclusion missing",
        problems,
    )

    identity = runtime.get("identity", {})
    expect(identity.get("matched") is True, "prior runtime identity did not match", problems)
    expect(
        runtime.get("method", {}).get("device_writes") is False,
        "prior runtime evidence contains device writes",
        problems,
    )
    expect(v1.get("gate", {}).get("passed") is True, "V1 gate is not passed", problems)
    expect(
        v1.get("scope", {}).get("device_access") is False
        and v1.get("scope", {}).get("device_writes") is False,
        "V1 physical-device scope changed",
        problems,
    )
    expect(
        v1.get("installed_binary", {}).get("sha256") == EXPECTED_V1["candidate_sha256"],
        "V1 candidate identity mismatch",
        problems,
    )
    expect(
        v1.get("packages", {}).get("r1", {}).get("sha256") == EXPECTED_V1["apk_sha256"],
        "V1 APK identity mismatch",
        problems,
    )

    expect(backup_tool.get("evidence_id") == IMAGE_ID, "backup tool evidence id mismatch", problems)
    expect(
        backup_tool.get("status") == "prepared_not_authorized_for_device",
        "backup tool status mismatch",
        problems,
    )
    expect(
        backup_tool.get("repository", {}).get("index_sha256")
        == EXPECTED_BACKUP_TOOL["index_sha256"]
        and backup_tool.get("repository", {}).get("package_entry_present") is True,
        "backup tool signed repository evidence mismatch",
        problems,
    )
    expect(
        backup_tool.get("package", {}).get("sha256") == EXPECTED_BACKUP_TOOL["apk_sha256"]
        and backup_tool.get("package", {}).get("version") == "2.3.0-r1",
        "backup tool package identity mismatch",
        problems,
    )
    expect(
        backup_tool.get("artifact", {}).get("sha256")
        == EXPECTED_BACKUP_TOOL["binary_sha256"]
        and backup_tool.get("artifact", {}).get("size_bytes") == 28677,
        "nanddump identity mismatch",
        problems,
    )
    expect(
        backup_tool.get("extraction", {}).get("repository_install_passed") is True
        and backup_tool.get("extraction", {}).get("repository_install_allow_untrusted") is False
        and backup_tool.get("extraction", {}).get("package_file_entry_hash_matched") is True,
        "backup tool extraction trust boundary mismatch",
        problems,
    )
    backup_scope = backup_tool.get("scope", {})
    expect(
        backup_scope.get("device_execution") is False
        and backup_scope.get("device_transfer") is False
        and backup_scope.get("device_writes") is False,
        "backup tool was admitted to the physical device",
        problems,
    )

    controls = readiness.get("offline_controls", [])
    control_ids = {item.get("id") for item in controls}
    expect(control_ids == EXPECTED_CONTROL_IDS, "offline control set mismatch", problems)
    expect(
        all(item.get("status") == "verified" and item.get("evidence") for item in controls),
        "offline controls are not all evidenced and verified",
        problems,
    )

    pending = readiness.get("open_prerequisites", [])
    pending_ids = {item.get("id") for item in pending}
    expect(pending_ids == EXPECTED_PENDING_IDS, "open prerequisite set mismatch", problems)
    expect(
        all(item.get("status") == "pending" and item.get("required_for") for item in pending),
        "an H1 prerequisite was closed without later-stage evidence",
        problems,
    )

    authorizations = readiness.get("authorizations", {})
    expect(set(authorizations) == set(EXPECTED_STAGES), "authorization stage set mismatch", problems)
    expect(
        authorizations.get("H1.0", {}).get("status") == "completed",
        "H1.0 authorization is not recorded",
        problems,
    )
    expect(
        all(
            authorizations.get(stage, {}).get("status") == "not_authorized"
            for stage in EXPECTED_STAGES[1:]
        ),
        "a physical stage is authorized in the H1.0 manifest",
        problems,
    )

    scope = readiness.get("scope", {})
    for key in (
        "device_contact",
        "device_writes",
        "router_reboot",
        "package_transfer",
        "package_install",
        "runtime_mount_change",
        "firmware_flash",
    ):
        expect(scope.get(key) is False, f"H1.0 scope permits {key}", problems)

    validate_commands(commands, problems)
    for marker in REQUIRED_RUNBOOK_MARKERS:
        expect(marker in runbook, f"runbook marker missing: {marker}", problems)
    for marker in REQUIRED_READ_ONLY_MARKERS:
        expect(marker in read_only_plan, f"read-only marker missing: {marker}", problems)

    derived_gates = {
        "h1_0_offline_planning": not problems,
        "h1_1a_read_only_observation": False,
        "h1_1b_boot_environment_read": False,
        "h1_2_private_backup": False,
        "h1_3_recovery_rehearsal": False,
        "h1_4_tmpfs_shadow": False,
        "h1_5_disabled_install": False,
        "h1_6_canary": False,
        "device_writes_allowed": False,
        "firmware_flash_allowed": False,
    }
    expect(readiness.get("gates") == derived_gates, "recorded gates differ from derived gates", problems)

    output = {
        "h1_0_gate_passed": not problems,
        "physical_device_admitted": False,
        "approved_device_commands": 0,
        "open_prerequisites": len(pending),
        "problems": problems,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    if problems:
        raise SystemExit("H1.0 readiness gate failed")


if __name__ == "__main__":
    main()
