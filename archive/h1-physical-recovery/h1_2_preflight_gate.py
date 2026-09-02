#!/usr/bin/env python3
"""Fail closed unless H1.2 stopped before the source-proven NMBM write risk."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
BUILDROOT_COMMIT = "f0a60eee2fe051741c643ea6118718aae1ef17fb"
EXPECTED_HASHES = {
    "h1_1a": "f6f51c1c8f675b8fc4fdd992b232ad27bc238e2b4d61d53a563f3a3d89a7e1b9",
    "h1_1b": "1fa992a121be28d2c86d3df7e2031497389e9a1cf8cd6e8f0951a2bab0efc087",
    "backup_tool": "38496e4a1d1b526a4c9a1b15370baf567a836ca4db3f33d309c73dd382a64ec6",
    "source_baseline": "0601e0a2f160a2deadce26f4453ac3d0307bec8f0aeebb26dbcd69e40adfdc1d",
    "firmware": "a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea",
    "nanddump": "21d7c3daa9e792a9b892af956ce64c59c4588c99eb7084b93ef5ee6f4bd47b92",
    "nanddump_source": "825e761d54f43aff729025b35c952a2625117d652ddad70c2f7a659fec144135",
    "mtd_utils_tar": "2db102908b232406ccb20719c0f43b61196aef4534493419fbf98a273c598c10",
    "dts": "d53b906ef826a5e6065643e115211da1a8f1d97abcc9ba61888082e523ac6632",
    "mtk_bmt": "39420c4d7e5c99ce144dff039aed141b00533594c89f098167c871bb1af0b639",
    "nmbm": "3643fed920f6f26c07bdc1c5618a20aa147fc11e066d3533ab72fa4507d55249",
}
FALSE_SCOPE = {
    "config_backup_read",
    "device_contact",
    "device_execution",
    "device_transfer",
    "device_writes",
    "firmware_flash",
    "raw_mtd_payload_read",
    "router_reboot",
}
FALSE_GATES = {
    "device_writes_allowed",
    "firmware_flash_allowed",
    "h1_2_private_backup",
    "h1_3_recovery_rehearsal",
    "h1_4_tmpfs_shadow",
    "h1_5_disabled_install",
    "h1_6_canary",
}
EXPECTED_TRIGGERS = {
    "negative read result that is not a bitflip status",
    "corrected bitflips reach mtd->bitflip_threshold",
    "the wrapped bad-block query reports a bad block",
}
EXPECTED_FLASH_ACTIONS = {
    "mark old mapped block bad",
    "allocate a spare mapping",
    "erase the new physical block",
    "copy the old block when copy_len is positive",
    "persist NMBM information tables",
}
REPORT_MARKERS = (
    "H1.2 不能在当前授权下执行",
    "blocked_before_device_contact",
    "没有连接路由器",
    "mtk_bmt_remap_block",
    "不是零写入保证",
)


class GateError(RuntimeError):
    """Raised when a preflight claim is missing or widened."""


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
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--h1-1a", required=True, type=Path)
    parser.add_argument("--h1-1b", required=True, type=Path)
    parser.add_argument("--backup-tool", required=True, type=Path)
    parser.add_argument("--source-baseline", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    preflight = load_json(args.preflight)
    h1_1a = load_json(args.h1_1a)
    h1_1b = load_json(args.h1_1b)
    backup_tool = load_json(args.backup_tool)
    source_baseline = load_json(args.source_baseline)
    report = args.report.read_text(encoding="utf-8")

    require(preflight.get("schema_version") == 1, "schema version mismatch")
    require(preflight.get("evidence_id") == IMAGE_ID, "evidence id mismatch")
    require(preflight.get("stage") == "H1.2-preflight", "stage mismatch")
    require(preflight.get("status") == "blocked_before_device_contact", "unsafe status")

    files = {
        "h1_1a": args.h1_1a,
        "h1_1b": args.h1_1b,
        "backup_tool": args.backup_tool,
        "source_baseline": args.source_baseline,
    }
    for key, path in files.items():
        require(sha256_file(path) == EXPECTED_HASHES[key], f"{key} input hash mismatch")

    require(h1_1a.get("status") == "passed_read_only", "H1.1a did not pass")
    require(h1_1a.get("gates", {}).get("nmbm_attached") is True, "NMBM not observed")
    require(h1_1b.get("status") == "passed_with_open_question", "H1.1b status mismatch")
    require(backup_tool.get("status") == "prepared_not_authorized_for_device",
            "backup tool scope changed")
    require(source_baseline.get("buildroot", {}).get("commit") == BUILDROOT_COMMIT,
            "buildroot commit mismatch")
    require(source_baseline.get("device", {}).get("layout") == "stock", "layout mismatch")

    inputs = preflight.get("inputs", {})
    require(inputs.get("h1_1a", {}).get("manifest_sha256") == EXPECTED_HASHES["h1_1a"],
            "recorded H1.1a hash mismatch")
    require(inputs.get("h1_1b", {}).get("manifest_sha256") == EXPECTED_HASHES["h1_1b"],
            "recorded H1.1b hash mismatch")
    require(inputs.get("backup_tool", {}).get("manifest_sha256")
            == EXPECTED_HASHES["backup_tool"], "recorded backup-tool hash mismatch")
    require(inputs.get("source_baseline", {}).get("manifest_sha256")
            == EXPECTED_HASHES["source_baseline"], "recorded source hash mismatch")
    require(inputs.get("known_good_firmware", {}).get("sha256")
            == EXPECTED_HASHES["firmware"], "firmware hash mismatch")
    require(inputs.get("known_good_firmware", {}).get("available_offline") is True,
            "known-good firmware is unavailable")
    require(inputs.get("backup_tool", {}).get("nanddump_sha256")
            == EXPECTED_HASHES["nanddump"], "nanddump hash mismatch")

    nanddump = preflight.get("nanddump_review", {})
    require(nanddump.get("mtd_utils_source_sha256") == EXPECTED_HASHES["nanddump_source"],
            "nanddump source hash mismatch")
    require(nanddump.get("mtd_utils_tar_sha256") == EXPECTED_HASHES["mtd_utils_tar"],
            "mtd-utils tar hash mismatch")
    require(nanddump.get("semantics", {}).get("open_mode") == "O_RDONLY",
            "nanddump open mode mismatch")

    source = preflight.get("source_review", {})
    require(source.get("device_tree", {}).get("sha256") == EXPECTED_HASHES["dts"],
            "DTS hash mismatch")
    require("mediatek,nmbm" in source.get("device_tree", {}).get("facts", []),
            "DTS no longer selects NMBM")
    require(source.get("mtk_bmt", {}).get("sha256") == EXPECTED_HASHES["mtk_bmt"],
            "mtk_bmt source hash mismatch")
    triggers = {
        item.get("condition")
        for item in source.get("mtk_bmt", {}).get("conditional_read_side_mutations", [])
    }
    require(triggers == EXPECTED_TRIGGERS, "read-side remap trigger set mismatch")
    require(source.get("nmbm", {}).get("sha256") == EXPECTED_HASHES["nmbm"],
            "NMBM source hash mismatch")
    require(set(source.get("nmbm", {}).get("remap_flash_actions", []))
            == EXPECTED_FLASH_ACTIONS, "remap flash action set mismatch")

    authorization = preflight.get("authorization", {})
    require(authorization.get("approved") is True, "H1.2 authorization not recorded")
    require(authorization.get("stage") == "H1.2", "authorization widened")
    require(authorization.get("scope_satisfied") is False,
            "source risk was incorrectly admitted")
    decision = preflight.get("decision", {})
    require(decision.get("status") == "blocked_before_device_contact", "decision mismatch")
    require(decision.get("zero_flash_write_guarantee") is False,
            "zero-write guarantee was forged")
    require(decision.get("collector_emitted") is False, "collector must not exist")
    require(decision.get("exact_nanddump_flags_approved") is False,
            "nanddump flags must remain unapproved")
    require(decision.get("next_authorization_required") is True,
            "new authorization boundary missing")

    scope = preflight.get("scope", {})
    require(scope.get("server_only_source_review") is True, "server-only review missing")
    for key in FALSE_SCOPE:
        require(scope.get(key) is False, f"preflight scope permits {key}")
    gates = preflight.get("gates", {})
    require(gates.get("h1_1a_read_only_observation") is True, "H1.1a gate lost")
    require(gates.get("h1_1b_boot_environment_read") is True, "H1.1b gate lost")
    require(gates.get("h1_2_preflight_review") is True, "preflight gate is false")
    for key in FALSE_GATES:
        require(gates.get(key) is False, f"closed gate was opened: {key}")
    for marker in REPORT_MARKERS:
        require(marker in report, f"report marker missing: {marker}")

    print("h1_2_preflight_passed=true")
    print("h1_2_private_backup=false")
    print("device_contact=false")
    print("device_writes=false")
    print("next_authorization_required=true")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"h1_2_preflight_passed=false: {error}") from error
