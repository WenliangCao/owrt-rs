#!/usr/bin/env python3
"""Build a redacted manifest resolving OQ-01 and OQ-07.

The input configuration files are private evidence collected outside Git.  The
output contains only structural UCI differences, option names, booleans and
counts.  No address, policy value, secret, hostname or interface identifier is
copied into the manifest.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any


EXPECTED_IDENTITY = {
    "release": "25.12.5",
    "revision": "r33051-f5dae5ece4",
    "target": "mediatek/filogic",
    "board_name": "xiaomi,mi-router-ax3000t",
}

SECRET_PATTERNS = (
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"),
    re.compile(r"\b(?:password|passphrase|psk|secret|token)\b", re.I),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_uci(path: Path) -> dict[str, dict[str, Any]]:
    """Parse the small declarative subset used by /etc/config files."""
    sections: dict[str, dict[str, Any]] = {}
    anonymous_count: dict[str, int] = {}
    current: dict[str, Any] | None = None
    pending = ""
    for raw in path.read_text(encoding="utf-8", errors="strict").splitlines():
        line = pending + raw.strip()
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        pending = ""
        try:
            words = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise ValueError(f"{path.name}: invalid UCI line: {raw!r}") from exc
        if not words:
            continue
        if words[0] == "config" and len(words) in (2, 3):
            section_type = words[1]
            if len(words) == 3:
                key = f"{section_type}:{words[2]}"
            else:
                index = anonymous_count.get(section_type, 0)
                anonymous_count[section_type] = index + 1
                key = f"{section_type}:@{index}"
            current = {"type": section_type, "options": {}}
            sections[key] = current
            continue
        if words[0] in ("option", "list") and len(words) == 3 and current is not None:
            current["options"].setdefault(words[1], []).append(words[2])
            continue
        raise ValueError(f"{path.name}: unsupported UCI syntax: {raw!r}")
    if pending:
        raise ValueError(f"{path.name}: unterminated continuation")
    return sections


def semantic_diff(
    expected: dict[str, dict[str, Any]], actual: dict[str, dict[str, Any]]
) -> dict[str, list[str]]:
    expected_paths = {
        f"{section}.{option}": values
        for section, data in expected.items()
        for option, values in data["options"].items()
    }
    actual_paths = {
        f"{section}.{option}": values
        for section, data in actual.items()
        for option, values in data["options"].items()
    }
    return {
        "sections_added": sorted(set(actual) - set(expected)),
        "sections_removed": sorted(set(expected) - set(actual)),
        "options_added": sorted(set(actual_paths) - set(expected_paths)),
        "options_removed": sorted(set(expected_paths) - set(actual_paths)),
        "options_changed": sorted(
            key
            for key in set(expected_paths) & set(actual_paths)
            if expected_paths[key] != actual_paths[key]
        ),
    }


def expected_post_firstboot_dhcp(image: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    expected = copy.deepcopy(image)
    lan = expected["dhcp:lan"]["options"]
    lan.update(
        {
            "dhcpv4": ["server"],
            "dhcpv6": ["server"],
            "ra": ["server"],
            "ra_slaac": ["1"],
            "ra_flags": ["managed-config", "other-config"],
        }
    )
    expected["odhcpd:odhcpd"] = {
        "type": "odhcpd",
        "options": {
            "maindhcp": ["0"],
            "leasefile": ["/tmp/odhcpd.leases"],
            "leasetrigger": ["/usr/sbin/odhcpd-update"],
            "loglevel": ["4"],
            "piodir": ["/tmp/odhcpd-piodir"],
            "hostsdir": ["/tmp/hosts"],
        },
    }
    return expected


def assert_redacted(payload: dict[str, Any]) -> None:
    rendered = json.dumps(payload, sort_keys=True)
    findings = [pattern.pattern for pattern in SECRET_PATTERNS if pattern.search(rendered)]
    if findings:
        raise SystemExit(f"redaction assertion failed for {len(findings)} pattern(s)")


def as_bool(value: str) -> bool:
    if value not in ("true", "false"):
        raise ValueError(f"expected boolean, got {value!r}")
    return value == "true"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--image-config", required=True, type=Path)
    parser.add_argument("--boot-chain", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    evidence_dir = args.evidence.resolve()
    device_dir = evidence_dir / "device"
    runtime = json.loads((evidence_dir / "runtime-summary.json").read_text())
    identity_matches = {
        key: runtime.get(key) == value for key, value in EXPECTED_IDENTITY.items()
    }
    if not all(identity_matches.values()):
        raise SystemExit(f"device identity mismatch: {identity_matches}")

    image_dhcp = parse_uci(args.image_config / "dhcp")
    image_firewall = parse_uci(args.image_config / "firewall")
    device_dhcp = parse_uci(device_dir / "dhcp")
    device_firewall = parse_uci(device_dir / "firewall")
    expected_dhcp = expected_post_firstboot_dhcp(image_dhcp)

    backup_disable = parse_uci(device_dir / "dhcp.bak-codex-disable-ipv6-20260425")
    backup_nextdns = parse_uci(device_dir / "dhcp.bak-codex-nextdns-doq-20260516-200927")
    backup_rollback = parse_uci(device_dir / "dhcp.bak-codex-rollback-dns-20260517-144734")
    firewall_diff = semantic_diff(image_firewall, device_firewall)
    dhcp_diff = semantic_diff(expected_dhcp, device_dhcp)
    rollback_diff = semantic_diff(backup_rollback, device_dhcp)

    boot_chain = json.loads(args.boot_chain.read_text())
    scheduling = boot_chain["rcS_scheduling"]
    if scheduling["max_running_tasks"] != 1:
        raise SystemExit("unexpected rcS concurrency; OQ-01 cannot be closed")

    firewall_expected_delta = {
        "defaults:@0.flow_offloading",
        "defaults:@0.flow_offloading_hw",
    }
    firewall_only_expected_delta = (
        set(firewall_diff["options_added"]) == firewall_expected_delta
        and not any(
            firewall_diff[key]
            for key in (
                "sections_added",
                "sections_removed",
                "options_removed",
                "options_changed",
            )
        )
    )
    dns_override_load_bearing = (
        as_bool(runtime["dns_noresolv_present"])
        or int(runtime["dns_server_values"]) > 0
        or int(runtime["dnsproxy_processes"]) > 0
        or as_bool(runtime["dnsproxy_active_config_present"])
        or not as_bool(runtime["dns_resolvfile_is_image_default"])
    )
    software_flow_load_bearing = (
        runtime["firewall_flow_offloading"] == "1"
        and int(runtime["rendered_flowtable_mentions"]) > 0
        and int(runtime["active_flowtable_mentions"]) > 0
    )

    payload = {
        "schema_version": 1,
        "stage": "I0 follow-up",
        "status": "complete",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "method": {
            "device_access": "approved read-only SSH",
            "device_writes": False,
            "raw_config_location": "private evidence directory outside Git",
            "redaction_asserted": True,
        },
        "identity_gate": {"matched": all(identity_matches.values()), "fields": identity_matches},
        "resolved_questions": {
            "OQ-01": {
                "status": "resolved",
                "rcs_is_strictly_serial": True,
                "max_running_tasks": scheduling["max_running_tasks"],
                "ordinary_nonzero_exit_continues": True,
                "pre_spawn_pipe_or_fork_failure_stalls_queue": True,
                "exact_boot_duration_observed": False,
                "residual_question": "OQ-09 (non-blocking exact boot-duration baseline)",
            },
            "OQ-07": {
                "status": "resolved",
                "oracle_use_allowed": True,
                "oracle_input": "reviewed current configuration, never the image defaults",
                "historical_actor_fully_reconstructable": False,
                "actor_provenance_required_for_oracle": False,
            },
        },
        "boot_review": {
            "uptime_days_floor": int(float(runtime["uptime_seconds"]) // 86400),
            "retained_log_lines": int(runtime["log_lines"]),
            "pstore_entries": int(runtime["pstore_entries"]),
            "pid1_is_plain_procd": runtime["pid1_cmdline"].strip() == "/sbin/procd",
            "pid1_dbglvl_present": as_bool(runtime["pid1_dbglvl_present"]),
            "retained_rcs_debug_lines": int(runtime["procd_rcs_debug_lines"]),
            "source_contract": {
                "ordering": scheduling["ordering"],
                "ordinary_exit_status_policy": scheduling["ordinary_exit_status_policy"],
                "pre_spawn_failure_policy": scheduling["pre_spawn_failure_policy"],
                "timing_log": scheduling["timing_log"],
            },
        },
        "config_review": {
            "dhcp": {
                "matches_image_plus_15_odhcpd_semantics": not any(dhcp_diff.values()),
                "old_disable_ipv6_backup_matches_current_semantics": backup_disable == device_dhcp,
                "old_nextdns_backup_matches_current_semantics": backup_nextdns == device_dhcp,
                "rollback_backup_delta_to_current": rollback_diff,
                "current_uses_image_default_resolver_path": as_bool(
                    runtime["dns_resolvfile_is_image_default"]
                ),
                "current_has_noresolv": as_bool(runtime["dns_noresolv_present"]),
                "current_custom_server_value_count": int(runtime["dns_server_values"]),
                "dnsproxy_process_count": int(runtime["dnsproxy_processes"]),
                "active_dnsproxy_config_present": as_bool(
                    runtime["dnsproxy_active_config_present"]
                ),
                "historical_dnsproxy_backups_byte_identical": sha256_file(
                    device_dir / "dnsproxy.bak-codex-rollback-dns-20260517-144734"
                )
                == sha256_file(
                    device_dir / "dnsproxy.disabled-codex-rollback-20260517-144902"
                ),
                "historical_dns_override_still_load_bearing": dns_override_load_bearing,
            },
            "firewall": {
                "semantic_delta_from_image": firewall_diff,
                "only_expected_reviewed_delta": firewall_only_expected_delta,
                "software_flow_offloading_enabled": runtime["firewall_flow_offloading"] == "1",
                "hardware_flow_offloading_enabled": runtime["firewall_flow_offloading_hw"] == "1",
                "rendered_flowtable_present": int(runtime["rendered_flowtable_mentions"]) > 0,
                "active_flowtable_present": int(runtime["active_flowtable_mentions"]) > 0,
                "software_flow_offloading_is_load_bearing": software_flow_load_bearing,
            },
            "reload_config_scope": {
                "historical_backup_files_are_inert_to_dns_firewall_consumers": True,
                "historical_backup_files_remain_visible_to_reload_config_scan": True,
                "c1_fixture_must_preserve_this_observed_file_set": True,
            },
        },
    }

    if not payload["config_review"]["dhcp"]["matches_image_plus_15_odhcpd_semantics"]:
        raise SystemExit("DHCP contains an unexplained semantic delta")
    if not firewall_only_expected_delta:
        raise SystemExit("firewall contains an unexplained semantic delta")
    if dns_override_load_bearing:
        raise SystemExit("historical DNS override is still load-bearing")
    if not software_flow_load_bearing:
        raise SystemExit("software flow offloading is not active in both rendered and loaded state")
    assert_redacted(payload)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "resolved_questions": sorted(payload["resolved_questions"]),
                "oracle_use_allowed": True,
                "redaction_findings": 0,
                "output_sha256": sha256_file(args.output),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
