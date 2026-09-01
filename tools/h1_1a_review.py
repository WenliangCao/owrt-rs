#!/usr/bin/env python3
"""Validate an H1.1a private run and emit a redacted observation manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
EXPECTED_IDS = [f"H1-RO-{number:02d}" for number in range(11)]
EXPECTED_IDENTITY = {
    "release": "25.12.5",
    "revision": "r33051-f5dae5ece4",
    "target": "mediatek/filogic",
    "architecture": "aarch64_cortex-a53",
    "board_name": "xiaomi,mi-router-ax3000t",
    "model": "Xiaomi Mi Router AX3000T",
    "kernel": "6.12.94",
    "rootfs_type": "squashfs",
}
EXPECTED_DISPATCHER_SHA256 = (
    "f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15"
)
EXPECTED_MTD = [
    ("mtd0", "BL2", 0x00100000),
    ("mtd1", "Nvram", 0x00040000),
    ("mtd2", "Bdata", 0x00040000),
    ("mtd3", "Factory", 0x00200000),
    ("mtd4", "FIP", 0x00200000),
    ("mtd5", "crash", 0x00040000),
    ("mtd6", "crash_log", 0x00040000),
    ("mtd7", "KF", 0x00040000),
    ("mtd8", "ubi_kernel", 0x02200000),
    ("mtd9", "ubi", 0x04E00000),
]
EXPECTED_ERASESIZE = 0x20000
EXPECTED_WRITESIZE = 2048
EXPECTED_ADDED_PACKAGES = {
    "luci-i18n-attendedsysupgrade-zh-cn",
    "luci-i18n-base-zh-cn",
    "luci-i18n-firewall-zh-cn",
    "luci-i18n-package-manager-zh-cn",
}
EXPECTED_FW_ENV_CONFIG = "/dev/mtd1 0x0 0x10000 0x20000"
EXPECTED_BUILDROOT_COMMIT = "f0a60eee2fe051741c643ea6118718aae1ef17fb"
EXPECTED_IMAGE_REVISION_COMMIT = "f5dae5ece4805730c5e2850f8aa84765af2f6b32"
EXPECTED_FW_ENV_SOURCE_SHA256 = (
    "bad297e3e28eb25f5cea937cdc6dd1d685511bf02fd149aaa175f216e94f3e9f"
)
MIN_OVERLAY_AVAILABLE_KIB = 8192
SENSITIVE_PATTERNS = {
    "IPv4 address": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "MAC address": re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])"),
    "UUID": re.compile(
        r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])"
    ),
    "private evidence path": re.compile(r"(?:^|[\"\s])(?:/[^\"\s]+)*/private/"),
}


class EvidenceError(RuntimeError):
    """Raised when private evidence does not satisfy the frozen H1.1a gate."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def raw_text(evidence: Path, identifier: str) -> str:
    path = evidence / "raw" / f"{identifier}.txt"
    require(path.is_file(), f"missing stdout for {identifier}")
    return path.read_text(encoding="utf-8")


def parse_identity(text: str) -> dict[str, str]:
    release: dict[str, str] = {}
    for key, value in re.findall(r"^DISTRIB_([A-Z]+)='([^']*)'$", text, re.MULTILINE):
        release[key] = value
    json_start = text.find("{")
    require(json_start >= 0, "H1-RO-00 lacks ubus JSON")
    board = json.loads(text[json_start:])
    lines = text[:json_start].splitlines()
    require(len(lines) >= 10, "H1-RO-00 metadata prefix is incomplete")
    observed = {
        "release": release.get("RELEASE", ""),
        "revision": release.get("REVISION", ""),
        "target": release.get("TARGET", ""),
        "architecture": release.get("ARCH", ""),
        "board_name": board.get("board_name", ""),
        "model": board.get("model", ""),
        "kernel": board.get("kernel", ""),
        "rootfs_type": board.get("rootfs_type", ""),
    }
    require(observed == EXPECTED_IDENTITY, f"runtime identity mismatch: {observed}")
    require(lines[-3:] == [observed["board_name"], observed["model"], observed["kernel"]],
            "sysinfo metadata disagrees with ubus identity")
    return observed


def parse_dispatcher(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    require(len(lines) == 3, "dispatcher output implies an unexpected bind mount or file")
    match = re.fullmatch(r"([0-9a-f]{64})  /sbin/reload_config", lines[0])
    require(bool(match), "dispatcher hash line is malformed")
    require(match.group(1) == EXPECTED_DISPATCHER_SHA256, "dispatcher hash changed")
    require(lines[1:] == [
        "/usr/sbin/reload_config_rs absent",
        "/usr/sbin/owrt-reload-config-switch absent",
    ], "candidate or switch is already present")
    return {
        "original_path": "/sbin/reload_config",
        "original_sha256": match.group(1),
        "bind_mount_active": False,
        "candidate_present": False,
        "switch_present": False,
    }


def parse_proc(text: str) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    lines = text.splitlines()
    require(len(lines) >= 14, "H1-RO-02 is incomplete")
    cmdline = lines[0]
    mtd: list[dict[str, Any]] = []
    mount_start = None
    for index, line in enumerate(lines[2:], start=2):
        match = re.fullmatch(
            r"(mtd\d+): ([0-9a-f]{8}) ([0-9a-f]{8}) \"([^\"]+)\"", line
        )
        if match:
            mtd.append({
                "device": match.group(1),
                "name": match.group(4),
                "size_bytes": int(match.group(2), 16),
                "erase_size_bytes": int(match.group(3), 16),
            })
        elif line.startswith("/dev/root "):
            mount_start = index
            break
    require(mount_start is not None, "mount table not found")
    expected = [
        {
            "device": device,
            "name": name,
            "size_bytes": size,
            "erase_size_bytes": EXPECTED_ERASESIZE,
        }
        for device, name, size in EXPECTED_MTD
    ]
    require(mtd == expected, "runtime MTD label/size set differs from stock expectation")
    mounts = lines[mount_start:]
    require(any(line.startswith("/dev/root /rom squashfs ro,") for line in mounts),
            "read-only SquashFS /rom mount missing")
    require(any(line.startswith("/dev/ubi0_1 /overlay ubifs rw,") for line in mounts),
            "writable UBIFS overlay mount missing")
    require(any(line.startswith("overlayfs:/overlay / overlay rw,") for line in mounts),
            "writable overlayfs root mount missing")
    return cmdline, mtd, {
        "rom": {"filesystem": "squashfs", "read_only": True},
        "overlay": {"source": "/dev/ubi0_1", "filesystem": "ubifs", "read_write": True},
        "root": {"filesystem": "overlay", "read_write": True},
    }


def parse_sysfs(text: str, proc_mtd: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocks = text.strip().split("mtd=")[1:]
    observed: list[dict[str, Any]] = []
    for block in blocks:
        values: dict[str, str] = {}
        lines = block.splitlines()
        values["device"] = lines[0]
        for line in lines[1:]:
            key, value = line.split("=", 1)
            values[key] = value
        observed.append({
            "device": values["device"],
            "name": values["name"],
            "size_bytes": int(values["size"]),
            "erase_size_bytes": int(values["erasesize"]),
            "write_size_bytes": int(values["writesize"]),
            "type": values["type"],
        })
    require(len(observed) == len(EXPECTED_MTD), "unexpected sysfs MTD entry count")
    for proc_entry, sysfs_entry in zip(proc_mtd, observed, strict=True):
        require(
            {key: sysfs_entry[key] for key in proc_entry} == proc_entry,
            f"proc/sysfs MTD mismatch for {sysfs_entry['device']}",
        )
        require(sysfs_entry["write_size_bytes"] == EXPECTED_WRITESIZE,
                f"unexpected NAND write size for {sysfs_entry['device']}")
        require(sysfs_entry["type"] == "nand", f"unexpected MTD type for {sysfs_entry['device']}")
    return observed


def value(pattern: str, text: str, label: str) -> int:
    match = re.search(pattern, text, re.MULTILINE)
    require(bool(match), f"missing UBI field: {label}")
    return int(match.group(1))


def parse_ubi(text: str) -> dict[str, Any]:
    require("Count of UBI devices:           1" in text, "expected exactly one UBI device")
    require("Present UBI devices:            ubi0" in text, "ubi0 is not the attached UBI device")
    require("Volumes count:                           2" in text, "unexpected UBI volume count")
    require(text.count("State:       OK") == 2, "a UBI user volume is not OK")
    volume_sections = re.split(r"(?=Volume ID:\s+\d+ \(on ubi0\))", text)
    volume_sections = [section for section in volume_sections if section.startswith("Volume ID:")]
    require(len(volume_sections) == 2, "unexpected UBI volume section count")
    expected_volumes = [(0, "rootfs", 41), (1, "rootfs_data", 558)]
    for section, (identifier, name, lebs) in zip(volume_sections, expected_volumes, strict=True):
        require(re.search(rf"^Volume ID:\s+{identifier} \(on ubi0\)$", section, re.MULTILINE) is not None,
                f"UBI volume {identifier} missing")
        require(re.search(rf"^Size:\s+{lebs} LEBs ", section, re.MULTILINE) is not None,
                f"unexpected size for UBI volume {identifier}")
        require(re.search(rf"^Name:\s+{re.escape(name)}$", section, re.MULTILINE) is not None,
                f"unexpected name for UBI volume {identifier}")
        require(re.search(r"^State:\s+OK$", section, re.MULTILINE) is not None,
                f"UBI volume {identifier} is not OK")
    result = {
        "device": "ubi0",
        "attached_mtd": "mtd9",
        "attached_mtd_name": "ubi",
        "logical_eraseblock_size_bytes": value(
            r"Logical eraseblock size:\s+(\d+) bytes", text, "logical eraseblock size"
        ),
        "total_logical_eraseblocks": value(
            r"Total amount of logical eraseblocks:\s+(\d+)", text, "total LEBs"
        ),
        "available_logical_eraseblocks": value(
            r"Amount of available logical eraseblocks:\s+(\d+)", text, "available LEBs"
        ),
        "bad_physical_eraseblocks": value(
            r"Count of bad physical eraseblocks:\s+(\d+)", text, "bad PEBs"
        ),
        "reserved_physical_eraseblocks": value(
            r"Count of reserved physical eraseblocks:\s+(\d+)", text, "reserved PEBs"
        ),
        "maximum_erase_counter": value(
            r"Current maximum erase counter value:\s+(\d+)", text, "erase counter"
        ),
        "volumes": [
            {"id": identifier, "name": name, "logical_eraseblocks": lebs, "state": "OK"}
            for identifier, name, lebs in expected_volumes
        ],
    }
    require(result["logical_eraseblock_size_bytes"] == 126976, "unexpected UBI LEB size")
    require(result["total_logical_eraseblocks"] == 624, "unexpected UBI total LEBs")
    require(result["bad_physical_eraseblocks"] == 0, "UBI reports bad PEBs")
    return result


def parse_hardware(drivers: str, dmesg: str) -> dict[str, Any]:
    required_driver_markers = (
        "/bus/mdio_bus/drivers/an8855",
        "/bus/mdio_bus/drivers/Airoha AN8855 internal PHY",
        "/bus/spi/drivers/spi-nand",
    )
    for marker in required_driver_markers:
        require(marker in drivers, f"runtime driver missing: {marker}")
    required_dmesg_markers = (
        "FORESEE SPI NAND was found.",
        "128 MiB, block size: 128 KiB, page size: 2048, OOB size: 64",
        "NMBM management region starts at block 960 [0x07800000]",
        "NMBM has been successfully attached",
        'attached mtd9 (name "ubi", size 78 MiB)',
        "good PEBs: 624, bad PEBs: 0, corrupted PEBs: 0",
        "UBIFS (ubi0:1): recovery needed",
        "UBIFS (ubi0:1): recovery completed",
    )
    for marker in required_dmesg_markers:
        require(marker in dmesg, f"kernel evidence missing: {marker}")
    require(dmesg.index("recovery needed") < dmesg.index("recovery completed"),
            "UBIFS recovery completion ordering is invalid")
    return {
        "nand": {
            "manufacturer_string": "FORESEE SPI NAND",
            "capacity_mib": 128,
            "erase_block_kib": 128,
            "page_size_bytes": 2048,
            "oob_size_bytes": 64,
            "driver": "spi-nand",
        },
        "nmbm": {
            "management_region_start_block": 960,
            "management_region_start_hex": "0x07800000",
            "attached": True,
        },
        "switch": {"driver": "an8855", "phy_driver": "Airoha AN8855 internal PHY"},
        "ubi_kernel_scan": {"good_pebs": 624, "bad_pebs": 0, "corrupted_pebs": 0},
        "ubifs_boot_recovery": {"needed": True, "completed": True, "current_error_observed": False},
    }


def parse_df(text: str) -> dict[str, dict[str, int]]:
    rows: dict[str, dict[str, int]] = {}
    for line in text.splitlines()[1:]:
        fields = line.split()
        require(len(fields) == 6, f"malformed df row: {line}")
        rows[fields[5]] = {
            "total_kib": int(fields[1]),
            "used_kib": int(fields[2]),
            "available_kib": int(fields[3]),
            "capacity_percent": int(fields[4].rstrip("%")),
        }
    require(set(rows) == {"/overlay", "/tmp"}, "df did not return overlay and tmp")
    require(rows["/overlay"]["available_kib"] >= MIN_OVERLAY_AVAILABLE_KIB,
            "overlay free space is below the H1 threshold")
    return rows


def parse_tools(text: str) -> dict[str, Any]:
    tools: dict[str, Any] = {}
    for line in text.splitlines():
        name, location = line.split("=", 1)
        tools[name] = None if location == "absent" else location
    require(set(tools) == {"ubinfo", "nanddump", "fw_printenv", "sha256sum", "tar", "sysupgrade"},
            "tool inventory set mismatch")
    require(tools["nanddump"] is None, "unexpected on-device nanddump")
    require(all(tools[name] for name in ("ubinfo", "fw_printenv", "sha256sum", "tar", "sysupgrade")),
            "required metadata/recovery tool is missing")
    return tools


def parse_apk_db(text: str) -> dict[str, str]:
    packages: dict[str, str] = {}
    for block in text.strip().split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) >= 3 and line[1] == ":":
                fields[line[0]] = line[2:]
        if "P" in fields and "V" in fields:
            require(fields["P"] not in packages, f"duplicate APK package: {fields['P']}")
            packages[fields["P"]] = fields["V"]
    return packages


def compare_packages(
    runtime_text: str, image_packages: dict[str, Any], prior_runtime: dict[str, Any]
) -> dict[str, Any]:
    runtime = parse_apk_db(runtime_text)
    image = {entry["name"]: entry["version"] for entry in image_packages["packages"]}
    added = sorted(set(runtime) - set(image))
    removed = sorted(set(image) - set(runtime))
    changed = [
        {"name": name, "image_version": image[name], "device_version": runtime[name]}
        for name in sorted(set(runtime) & set(image))
        if runtime[name] != image[name]
    ]
    require(len(image) == 159, "image package inventory count changed")
    require(len(runtime) == 163, "device package count changed from the reviewed runtime")
    require(set(added) == EXPECTED_ADDED_PACKAGES, "device has unexpected added packages")
    require(not removed and not changed, "device package set/version no longer matches the reviewed drift")
    prior = prior_runtime.get("packages", {})
    require(prior.get("device_count") == len(runtime), "prior runtime package count disagrees")
    require(set(prior.get("added", [])) == set(added), "prior runtime added-package set disagrees")
    require(prior.get("removed") == [], "prior runtime package removal record disagrees")
    require(prior.get("version_changed") == [], "prior runtime version record disagrees")
    return {
        "image_count": len(image),
        "device_count": len(runtime),
        "added": [{"name": name, "version": runtime[name]} for name in added],
        "removed": removed,
        "version_changed": changed,
        "matches_prior_runtime_drift": True,
    }


def validate_run(evidence: Path) -> tuple[dict[str, Any], dict[str, str]]:
    statuses = load_json(evidence / "exit-status.json")
    entries = statuses.get("commands", [])
    require(statuses.get("command_count") == 11, "collector command count is not 11")
    require([entry.get("id") for entry in entries] == EXPECTED_IDS, "collector command order differs")
    require(all(entry.get("exit_status") == 0 for entry in entries), "a collector command failed")
    output_hashes: dict[str, str] = {}
    for identifier in EXPECTED_IDS:
        stdout = evidence / "raw" / f"{identifier}.txt"
        stderr = evidence / "raw" / f"{identifier}.stderr"
        require(stdout.is_file(), f"missing stdout for {identifier}")
        require(stderr.is_file() and stderr.stat().st_size == 0, f"non-empty stderr for {identifier}")
        output_hashes[identifier] = sha256_file(stdout)
    return statuses, output_hashes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--command-plan", required=True, type=Path)
    parser.add_argument("--intake", required=True, type=Path)
    parser.add_argument("--image-packages", required=True, type=Path)
    parser.add_argument("--prior-runtime", required=True, type=Path)
    parser.add_argument("--source-baseline", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    authorization = load_json(args.authorization)
    command_plan = load_json(args.command_plan)
    intake = load_json(args.intake)
    source_baseline = load_json(args.source_baseline)
    require(authorization.get("evidence_id") == IMAGE_ID, "authorization evidence id mismatch")
    require(authorization.get("stage") == "H1.1a", "authorization stage mismatch")
    require(authorization.get("authorization", {}).get("status") == "approved",
            "H1.1a was not explicitly approved")
    require(authorization.get("approved_command_ids") == EXPECTED_IDS,
            "authorization command list mismatch")
    require(authorization.get("excluded_command_ids") == ["H1-RO-11"],
            "H1.1b command was not excluded")
    auth_scope = authorization.get("scope", {})
    for key in (
        "boot_environment_read", "device_writes", "firmware_flash", "package_install",
        "package_transfer", "raw_mtd_payload_read", "router_reboot", "service_or_network_change",
    ):
        require(auth_scope.get(key) is False, f"authorization permits {key}")
    require(authorization.get("command_plan", {}).get("sha256") == sha256_file(args.command_plan),
            "authorized command-plan hash mismatch")
    require(command_plan.get("evidence_id") == IMAGE_ID, "command-plan evidence id mismatch")

    firmware = intake.get("firmware", {})
    device = intake.get("device", {})
    require(firmware.get("version") == EXPECTED_IDENTITY["release"], "intake release mismatch")
    require(firmware.get("revision") == EXPECTED_IDENTITY["revision"], "intake revision mismatch")
    require(firmware.get("target") == EXPECTED_IDENTITY["target"], "intake target mismatch")
    require(firmware.get("kernel") == EXPECTED_IDENTITY["kernel"], "intake kernel mismatch")
    require(device.get("compatible") == EXPECTED_IDENTITY["board_name"], "intake board mismatch")
    require(device.get("layout") == "stock", "intake layout is not stock")
    require(source_baseline.get("evidence_id") == IMAGE_ID, "source-baseline evidence id mismatch")
    require(source_baseline.get("buildroot", {}).get("commit") == EXPECTED_BUILDROOT_COMMIT,
            "exact buildroot commit mismatch")
    require(
        source_baseline.get("buildroot", {}).get("image_revision_commit")
        == EXPECTED_IMAGE_REVISION_COMMIT,
        "image revision commit mismatch",
    )
    source_device = source_baseline.get("device", {})
    require(source_device.get("compatible") == EXPECTED_IDENTITY["board_name"],
            "source-baseline board mismatch")
    require(source_device.get("layout") == "stock", "source-baseline layout mismatch")

    statuses, output_hashes = validate_run(args.evidence)
    identity = parse_identity(raw_text(args.evidence, "H1-RO-00"))
    dispatcher = parse_dispatcher(raw_text(args.evidence, "H1-RO-01"))
    cmdline, proc_mtd, mounts = parse_proc(raw_text(args.evidence, "H1-RO-02"))
    mtd = parse_sysfs(raw_text(args.evidence, "H1-RO-03"), proc_mtd)
    ubi = parse_ubi(raw_text(args.evidence, "H1-RO-04"))
    hardware = parse_hardware(
        raw_text(args.evidence, "H1-RO-05"), raw_text(args.evidence, "H1-RO-06")
    )
    filesystems = parse_df(raw_text(args.evidence, "H1-RO-07"))
    tools = parse_tools(raw_text(args.evidence, "H1-RO-08"))
    packages = compare_packages(
        raw_text(args.evidence, "H1-RO-09"),
        load_json(args.image_packages),
        load_json(args.prior_runtime),
    )
    fw_env_config = raw_text(args.evidence, "H1-RO-10").strip()
    require(fw_env_config == EXPECTED_FW_ENV_CONFIG, "fw_env.config differs from exact source")
    require("firmware=0" in cmdline and "mtd=ubi" in cmdline, "unexpected stock boot command line")

    started_at = min(entry["started_at"] for entry in statuses["commands"])
    ended_at = max(entry["ended_at"] for entry in statuses["commands"])
    manifest = {
        "schema_version": 1,
        "evidence_id": IMAGE_ID,
        "stage": "H1.1a",
        "status": "passed_read_only",
        "recorded_at": args.recorded_at,
        "authorization": {
            "approved": True,
            "single_run_consumed": True,
            "approved_command_ids": EXPECTED_IDS,
            "excluded_command_ids": ["H1-RO-11"],
            "authorization_manifest_sha256": sha256_file(args.authorization),
            "command_plan_sha256": sha256_file(args.command_plan),
        },
        "collection": {
            "started_at": started_at,
            "ended_at": ended_at,
            "command_count": 11,
            "successful_commands": 11,
            "stderr_files_nonempty": 0,
            "stdout_sha256": output_hashes,
            "raw_evidence_committed": False,
        },
        "identity": {**identity, "matched_exact_image_identity": True, "layout": "stock"},
        "dispatcher": dispatcher,
        "storage": {
            "command_line_boot_branch": {"firmware": 0, "mtd": "ubi"},
            "mtd": mtd,
            "mtd_index_is_not_physical_offset": True,
            "ubi": ubi,
            **hardware,
        },
        "mounts": mounts,
        "filesystems": {
            "overlay": filesystems["/overlay"],
            "tmp": filesystems["/tmp"],
            "overlay_minimum_available_kib": MIN_OVERLAY_AVAILABLE_KIB,
        },
        "tools": tools,
        "packages": packages,
        "boot_environment_layout": {
            "fw_env_config": EXPECTED_FW_ENV_CONFIG,
            "matched_exact_source": True,
            "source_buildroot_commit": EXPECTED_BUILDROOT_COMMIT,
            "image_revision_commit": EXPECTED_IMAGE_REVISION_COMMIT,
            "source_path": "package/boot/uboot-tools/uboot-envtools/files/mediatek_filogic",
            "source_lines": "164-168",
            "source_file_sha256": EXPECTED_FW_ENV_SOURCE_SHA256,
            "source_baseline_sha256": sha256_file(args.source_baseline),
            "h1_1b_layout_precondition_passed": True,
            "environment_values_read": False,
        },
        "method_corrections": authorization.get("corrections", []),
        "gates": {
            "h1_1a_read_only_observation": True,
            "fresh_runtime_identity": True,
            "stock_storage_layout": True,
            "nmbm_attached": True,
            "ubi_metadata_healthy": True,
            "overlay_headroom": True,
            "dispatcher_pristine": True,
            "package_drift_unchanged": True,
            "h1_1b_layout_precondition": True,
            "h1_1b_boot_environment_read": False,
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
            "device_writes": False,
            "raw_mtd_payload_read": False,
            "boot_environment_values_read": False,
            "package_transfer": False,
            "package_install": False,
            "router_reboot": False,
            "runtime_mount_change": False,
            "service_or_network_change": False,
            "firmware_flash": False,
        },
        "redaction": {
            "raw_output_location": "private evidence outside Git",
            "device_addresses_omitted": True,
            "mac_addresses_omitted": True,
            "filesystem_uuid_omitted": True,
            "device_hostname_omitted": True,
            "asserted": True,
        },
    }
    rendered = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    for label, pattern in SENSITIVE_PATTERNS.items():
        require(not pattern.search(rendered), f"redacted manifest contains {label}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(json.dumps({
        "h1_1a_gate_passed": True,
        "commands": 11,
        "device_writes": False,
        "h1_1b_layout_precondition_passed": True,
        "output": str(args.output),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except EvidenceError as error:
        raise SystemExit(f"H1.1a gate failed: {error}") from error
