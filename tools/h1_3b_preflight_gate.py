#!/usr/bin/env python3
"""Keep H1.3b blocked until physical RAM-boot recovery controls exist."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
from pathlib import Path
from typing import Any


IMAGE_ID = "ax3000t-stock-openwrt-25.12.5"
H1_3A_MANIFEST_SHA256 = "e1d21793e0235656f1ff1d40ec52b9ebe08572f15573bcc5f0e455f265a25c66"
H1_3A_PATCH_SHA256 = "e4e2051510864c6fdd18ff0db6b3aa792b75398d9fd1ca51e0b7bf1eeed9454e"
CANDIDATE_NAME = "openwrt-mediatek-filogic-xiaomi_mi-router-ax3000t-initramfs-kernel.bin"
CANDIDATE_SHA256 = "c9ce88f597dea3e552c05cdcf9ed2d3f9683161731dc12747cc7627783247a5a"
CANDIDATE_SIZE = 8762644
PRIVATE_CANDIDATE_PATH = f"private/h1-3b-20260901/tftp/{CANDIDATE_NAME}"
INPUT_HASHES = {
    "host_preflight": "344d26bc6c724dbe2bc37b72cf7e2e9683ea8315c1d80f0176a1b41f398e17ee",
    "official_device_page": "113cb5ac44d1611a7a670bdeaac71b36f186cad2e51115b97df3d13fecbb97f6",
    "official_techdata": "23a57ea45ce9e7e86abb42af7f9b597a0fc0ff41c27127ca452b486573205067",
    "official_uart_photo": "5cfdbd542b03acf7ac11f76ec5629f471c496fd686a72c9c4b5a3f7c40de2784",
}
EXPECTED_COMMANDS = [
    ("H1-3B-OBS-00", "version"),
    ("H1-3B-OBS-01", "bdinfo"),
    ("H1-3B-OBS-02", "help tftpboot"),
    ("H1-3B-OBS-03", "help bootm"),
    ("H1-3B-OBS-04", "help iminfo"),
    ("H1-3B-OBS-05", "help setenv"),
    ("H1-3B-OBS-06", "printenv ipaddr serverip loadaddr bootfile"),
    ("H1-3B-LOAD-00", "setenv ipaddr 192.168.1.1"),
    ("H1-3B-LOAD-01", "setenv serverip 192.168.1.254"),
    ("H1-3B-LOAD-02", f"tftpboot 0x46000000 {CANDIDATE_NAME}"),
    ("H1-3B-LOAD-03", "printenv filesize"),
    ("H1-3B-LOAD-04", "iminfo 0x46000000"),
    ("H1-3B-BOOT-00", "bootm 0x46000000"),
]
EXPECTED_BLOCKERS = {
    "usb-uart-not-present",
    "wired-link-not-active",
    "management-would-not-survive-wifi-disabled-boot",
    "controlled-power-unverified",
    "stock-uboot-capabilities-unobserved",
    "host-command-plan-not-frozen",
}
EXPECTED_CORRECTIONS = {
    "official-export-raw",
    "address-role-distinction",
    "candidate-mode-negative-test-variable",
}
FALSE_PRECONDITIONS = {
    "controlled_power_verified",
    "exact_bootloader_commands_frozen",
    "host_tftp_plan_frozen",
    "independent_internet_available",
    "independent_wired_management_active",
    "physical_operator_present",
    "stock_bootloader_bootm_help_observed",
    "stock_bootloader_identity_observed",
    "stock_bootloader_setenv_volatile_semantics_observed",
    "stock_bootloader_tftp_help_observed",
    "uart_3v3_adapter_connected",
    "uart_console_observed",
}
FALSE_GATES = {
    "bootloader_commands_authorized",
    "candidate_transfer_to_router",
    "device_writes_allowed",
    "firmware_flash_allowed",
    "h1_2_private_backup",
    "h1_3b_ram_boot",
    "host_network_change_allowed",
    "recovery_boot_verified",
    "router_contact_allowed",
    "router_reboot_allowed",
}
FALSE_SCOPE = {
    "device_contact",
    "device_execution",
    "device_transfer",
    "device_writes",
    "firmware_flash",
    "host_network_changes",
    "router_reboot",
}
REPORT_MARKERS = (
    "authorized_but_blocked_before_device_contact",
    "没有连接、重启或修改路由器",
    "USB-UART",
    "0x46000000",
    "0x48000000",
    "commands_authorized=false",
    "router_reboot=false",
)
RUNBOOK_MARKERS = (
    "H1.3b preflight：已授权但被现场恢复条件阻断",
    "commands_authorized=false",
    "router_reboot=false",
    CANDIDATE_SHA256,
)


class GateError(RuntimeError):
    """Raised when blocked H1.3b evidence is missing or widened."""


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
    parser.add_argument("--h1-3a", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--host-preflight", required=True, type=Path)
    parser.add_argument("--official-device-page", required=True, type=Path)
    parser.add_argument("--official-techdata", required=True, type=Path)
    parser.add_argument("--official-uart-photo", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--runbook", required=True, type=Path)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    h1_3a = load_json(args.h1_3a)
    host = load_json(args.host_preflight)
    report = args.report.read_text(encoding="utf-8")
    runbook = args.runbook.read_text(encoding="utf-8")

    require(manifest.get("schema_version") == 1, "schema version mismatch")
    require(manifest.get("evidence_id") == IMAGE_ID, "evidence id mismatch")
    require(manifest.get("stage") == "H1.3b-preflight", "stage mismatch")
    require(
        manifest.get("status") == "authorized_but_blocked_before_device_contact",
        "unsafe preflight status",
    )

    inputs = manifest.get("inputs", {})
    require(sha256_file(args.h1_3a) == H1_3A_MANIFEST_SHA256, "H1.3a input changed")
    require(
        inputs.get("h1_3a_manifest", {}).get("sha256") == H1_3A_MANIFEST_SHA256,
        "recorded H1.3a hash mismatch",
    )
    require(inputs.get("h1_3a_patch_sha256") == H1_3A_PATCH_SHA256, "patch hash mismatch")
    require(h1_3a.get("status") == "passed_offline_static_only", "H1.3a did not pass")
    require(
        h1_3a.get("artifact", {}).get("sha256") == CANDIDATE_SHA256,
        "H1.3a candidate mismatch",
    )

    files = {
        "host_preflight": args.host_preflight,
        "official_device_page": args.official_device_page,
        "official_techdata": args.official_techdata,
        "official_uart_photo": args.official_uart_photo,
    }
    for key, path in files.items():
        require(sha256_file(path) == INPUT_HASHES[key], f"{key} file hash mismatch")
    require(
        inputs.get("host_preflight", {}).get("sha256") == INPUT_HASHES["host_preflight"],
        "recorded host snapshot hash mismatch",
    )
    require(
        inputs.get("host_preflight", {}).get("path")
        == "private/h1-3b-20260901/host-preflight.json",
        "recorded host snapshot path mismatch",
    )
    require(
        inputs.get("official_device_page", {}).get("raw_sha256")
        == INPUT_HASHES["official_device_page"],
        "recorded device-page hash mismatch",
    )
    require(
        inputs.get("official_techdata", {}).get("raw_sha256")
        == INPUT_HASHES["official_techdata"],
        "recorded techdata hash mismatch",
    )
    require(
        inputs.get("official_uart_photo", {}).get("sha256")
        == INPUT_HASHES["official_uart_photo"],
        "recorded UART-photo hash mismatch",
    )
    device_facts = inputs.get("official_device_page", {}).get("facts", {})
    require(
        device_facts
        == {
            "ram_load_command_buffer": "0x46000000",
            "ram_start_address_reference": "0x48000000",
            "serial": "115200 8N1 3.3V",
            "stock_bootloader_uart_initramfs_documented": True,
        },
        "official device-page fact set mismatch",
    )
    uart_facts = inputs.get("official_uart_photo", {}).get("facts", {})
    require(
        uart_facts == {
            "pin_order_top_to_bottom": ["VCC", "RX", "GND", "TX"],
            "vcc_must_not_be_connected": True,
        },
        "UART pinout fact set mismatch",
    )

    candidate = manifest.get("candidate", {})
    require(args.candidate.name == CANDIDATE_NAME, "candidate filename mismatch")
    require(sha256_file(args.candidate) == CANDIDATE_SHA256, "private candidate hash mismatch")
    require(args.candidate.stat().st_size == CANDIDATE_SIZE, "private candidate size mismatch")
    require(stat.S_IMODE(args.candidate.stat().st_mode) == 0o444, "private candidate mode mismatch")
    require(candidate.get("filename") == CANDIDATE_NAME, "recorded candidate filename mismatch")
    require(candidate.get("local_private_path") == PRIVATE_CANDIDATE_PATH, "private path mismatch")
    require(candidate.get("sha256") == CANDIDATE_SHA256, "recorded candidate hash mismatch")
    require(candidate.get("size_bytes") == CANDIDATE_SIZE, "recorded candidate size mismatch")
    require(candidate.get("local_private_copy") is True, "private copy missing")
    require(candidate.get("local_private_mode") == "0444", "recorded candidate mode mismatch")

    address = manifest.get("address_model", {})
    buffer_start = int(address.get("fit_buffer_start", "0"), 16)
    buffer_end = int(address.get("fit_buffer_end_exclusive", "0"), 16)
    kernel_load = int(address.get("fit_kernel_load", "0"), 16)
    require(buffer_start == 0x46000000, "TFTP buffer address mismatch")
    require(buffer_end == buffer_start + CANDIDATE_SIZE, "TFTP buffer end mismatch")
    require(kernel_load == 0x48000000, "FIT kernel load address mismatch")
    require(address.get("fit_kernel_entry") == "0x48000000", "FIT entry mismatch")
    require(address.get("fit_buffer_kernel_gap_bytes") == kernel_load - buffer_end,
            "buffer gap mismatch")
    require(address.get("overlap") is False and buffer_end < kernel_load,
            "TFTP buffer overlaps kernel load region")

    require(host.get("schema_version") == 1, "host snapshot schema mismatch")
    require(host.get("usb_uart_adapter_present") is False, "host snapshot has USB-UART")
    require(host.get("candidate_serial_nodes") == [], "candidate serial node exists")
    require(host.get("ethernet") == {"en2": "inactive", "en3": "inactive"},
            "wired-link snapshot mismatch")
    require(host.get("management_transport") == "wifi", "management transport mismatch")
    require(host.get("tftp_daemon_configured") is False, "TFTP was configured")
    require(host.get("tftp_udp_69_listening") is False, "TFTP port is listening")
    require(host.get("controlled_power_verified") is False, "power control was forged")
    require(host.get("physical_operator_confirmed") is False, "operator presence was forged")

    observed = manifest.get("host_observation", {})
    require(observed.get("usb_uart_adapter_present") is False, "USB-UART gate widened")
    require(observed.get("candidate_serial_nodes") == [], "serial-node claim mismatch")
    require(observed.get("ethernet_link_active") is False, "wired link gate widened")
    require(observed.get("management_transport") == "wifi", "management claim mismatch")
    require(observed.get("ethernet_devices") == ["en2", "en3"], "Ethernet set mismatch")
    require(observed.get("serial_clients") == ["/usr/bin/cu", "/usr/bin/screen"],
            "serial-client set mismatch")
    require(observed.get("tftp_daemon") == "/usr/libexec/tftpd", "host tftpd path mismatch")
    require(observed.get("tftp_daemon_present") is True, "host tftpd is unavailable")
    require(observed.get("tftp_daemon_configured") is False, "host tftpd was configured")
    require(observed.get("tftp_udp_69_listening") is False, "host TFTP listener exists")
    require(
        observed.get("independent_management_survives_candidate_boot") is False,
        "management-survival gate widened",
    )
    require(observed.get("controlled_power_verified") is False,
            "controlled-power gate widened")
    require(observed.get("physical_operator_confirmed") is False,
            "physical-operator gate widened")

    authorization = manifest.get("authorization", {})
    require(authorization.get("requested_stage") == "H1.3b", "authorization stage mismatch")
    require(authorization.get("preflight_authorized") is True, "preflight authorization missing")
    require(authorization.get("status") == "approved_pending_preconditions",
            "authorization status mismatch")
    require(authorization.get("consumed") is False, "authorization was consumed")
    require(authorization.get("commands_authorized") is False, "commands were authorized")
    require(authorization.get("router_reboot_admitted") is False, "router reboot was admitted")

    commands = manifest.get("proposed_bootloader_commands", [])
    observed_commands = [(item.get("id"), item.get("command")) for item in commands]
    require(observed_commands == EXPECTED_COMMANDS, "proposed command set or order changed")
    require(all(item.get("status") == "not_authorized" for item in commands),
            "a proposed bootloader command was authorized")
    joined_commands = "\n".join(command for _, command in observed_commands).lower()
    for forbidden in (
        "saveenv",
        "env save",
        "nand ",
        "mtd ",
        "ubi ",
        "sysupgrade",
        "erase",
        "write",
        "flash",
    ):
        require(forbidden not in joined_commands, f"persistent command present: {forbidden}")

    preconditions = manifest.get("preconditions", {})
    require(preconditions.get("h1_3a_offline_candidate_passed") is True, "H1.3a gate lost")
    require(preconditions.get("candidate_hash_matched") is True, "candidate hash gate lost")
    require(preconditions.get("candidate_private_copy_ready") is True, "private copy gate lost")
    for key in FALSE_PRECONDITIONS:
        require(preconditions.get(key) is False, f"unmet precondition was closed: {key}")

    decision = manifest.get("decision", {})
    require(decision.get("status") == "blocked_missing_physical_recovery_controls",
            "unsafe decision")
    require(set(decision.get("reason_ids", [])) == EXPECTED_BLOCKERS, "blocker set mismatch")
    require(decision.get("commands_executed") is False, "bootloader command was executed")

    correction_items = manifest.get("method_corrections", [])
    correction_ids = {item.get("id") for item in correction_items}
    require(correction_ids == EXPECTED_CORRECTIONS, "method correction set mismatch")
    require(
        len(correction_items) == len(correction_ids)
        and all(item.get("result") for item in correction_items),
        "method correction detail missing or duplicated",
    )

    gates = manifest.get("gates", {})
    require(gates.get("h1_3b_preflight_review") is True, "preflight review gate is false")
    for key in FALSE_GATES:
        require(gates.get(key) is False, f"closed gate was opened: {key}")
    scope = manifest.get("scope", {})
    require(scope.get("candidate_copied_server_to_local_private_storage") is True,
            "private candidate copy not recorded")
    require(scope.get("local_host_read_only_inventory") is True, "host inventory missing")
    require(scope.get("server_read") is True, "server read missing")
    for key in FALSE_SCOPE:
        require(scope.get(key) is False, f"scope permits {key}")

    for marker in REPORT_MARKERS:
        require(marker in report, f"report marker missing: {marker}")
    for marker in RUNBOOK_MARKERS:
        require(marker in runbook, f"runbook marker missing: {marker}")

    print("h1_3b_preflight_review=true")
    print("h1_3b_ram_boot=false")
    print("recovery_boot_verified=false")
    print("commands_authorized=false")
    print("router_contact=false")
    print("router_reboot=false")
    print("device_writes=false")
    print("firmware_flash=false")
    print("blocked_reason=missing_physical_recovery_controls")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"h1_3b_preflight_review=false: {error}") from error
