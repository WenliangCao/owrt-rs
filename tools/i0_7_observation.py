#!/usr/bin/env python3
"""Derive the I0.7 redacted observation manifest from raw collector output.

Input is the raw output directory written by the approved read-only command
list; it stays outside Git.  Output is a redacted, structural manifest: object
and method names, counts, flags and static-versus-runtime comparisons.  No
addresses, MAC addresses, keys, hostnames, SSIDs or session tokens are copied
into it.

The tool asserts its own redaction: the finished manifest is scanned for
address- and secret-shaped strings and the run fails if any survive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SECRET_PATTERNS = [
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IPv4 address"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "MAC address"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){4,}[0-9a-fA-F]{0,4}\b"), "IPv6 address"),
    (re.compile(r"\$[0-9a-z]\$[A-Za-z0-9./]{6,}"), "password hash"),
    (re.compile(r"\b(?:psk|key|passphrase|password)\s*[=:]\s*\S+", re.I), "credential"),
]

# Addresses that ship in the public image and carry no device information.
REDACTION_ALLOWLIST = {"127.0.0.1", "0.0.0.0", "255.255.255.0", "192.168.1.1", "192.168.1.255"}

EXPECTED_RAW_FILES = {
    "Q00_release.txt": ("Q00", 0),
    "Q00_sysinfo.txt": ("Q00", 1),
    "Q00_systemboard.txt": ("Q00", 2),
    "Q01_cmdline.txt": ("Q01", 0),
    "Q02_failsafe.txt": ("Q02", 1),
    "Q02_logread.txt": ("Q02", 0),
    "Q03_firstboot.txt": ("Q03", 0),
    "Q04_boardjson.txt": ("Q04", 0),
    "Q04_genconfigs.txt": ("Q04", 1),
    "Q05_ubuslist.txt": ("Q05", 0),
    "Q05_ubuslistv.txt": ("Q05", 1),
    "Q06_servicelist.txt": ("Q06", 0),
    "Q07_devstatus.txt": ("Q07", 1),
    "Q07_ifdump.txt": ("Q07", 0),
    "Q08_nftruleset.txt": ("Q08", 0),
    "Q09_dhcpobj.txt": ("Q09", 1),
    "Q09_dnsmasqobj.txt": ("Q09", 0),
    "Q10_udebug.txt": ("Q10", 0),
    "Q11_privproc.txt": ("Q11", 0),
    "Q12_ucidelta.txt": ("Q12", 0),
    "Q13_confighashes.txt": ("Q13", 0),
    "Q13_uhttpdrpcd.txt": ("Q13", 1),
    "Q14_apkdb.txt": ("Q14", 0),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def body(raw: Path, name: str) -> str:
    """Strip the collector's command header and exit footer."""
    lines = (raw / name).read_text(errors="replace").splitlines()
    if len(lines) < 2 or not lines[0].startswith("### command:"):
        raise ValueError(f"{name}: missing collector command header")
    if not lines[-1].startswith("### exit:"):
        raise ValueError(f"{name}: missing collector exit footer")
    return "\n".join(lines[1:-1])


def command_header(raw: Path, name: str) -> str:
    first = (raw / name).read_text(errors="replace").splitlines()[0]
    return first.removeprefix("### command:").strip()


def exit_code(raw: Path, name: str) -> int | None:
    for line in reversed((raw / name).read_text(errors="replace").splitlines()):
        if line.startswith("### exit:"):
            return int(line.split(":", 1)[1])
    return None


def validate_raw(raw: Path, runtime_questions: dict[str, Any]) -> dict[str, Any]:
    present = {path.name for path in raw.glob("*.txt")}
    expected = set(EXPECTED_RAW_FILES)
    missing = sorted(expected - present)
    unexpected = sorted(present - expected)
    command_mismatches = []
    exit_mismatches = []
    questions = {item["id"]: item for item in runtime_questions["questions"]}
    declared_commands = {
        (question_id, command_index)
        for question_id, question in questions.items()
        for command_index, _ in enumerate(question["commands"])
    }
    mapped_commands = set(EXPECTED_RAW_FILES.values())
    if mapped_commands != declared_commands:
        raise ValueError(
            "collector mapping does not cover the I0.6 command list exactly: "
            f"unmapped={sorted(declared_commands - mapped_commands)}, "
            f"undeclared={sorted(mapped_commands - declared_commands)}"
        )
    for name, (question_id, command_index) in EXPECTED_RAW_FILES.items():
        if name not in present:
            continue
        try:
            declaration = questions[question_id]["commands"][command_index]
            declared = declaration["expected_status"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError(f"{name}: no matching I0.6 command declaration") from exc
        allowed = {declared} if isinstance(declared, int) else set(declared)
        # body() validates the framing even for inputs not otherwise parsed.
        body(raw, name)
        observed_command = command_header(raw, name)
        if observed_command != declaration["command"]:
            command_mismatches.append(
                {
                    "file": name,
                    "declared": declaration["command"],
                    "observed": observed_command,
                }
            )
        observed = exit_code(raw, name)
        if observed not in allowed:
            exit_mismatches.append(
                {"file": name, "observed": observed, "allowed": sorted(allowed)}
            )
    if missing or unexpected or command_mismatches or exit_mismatches:
        raise ValueError(
            f"collector input invalid: missing={missing}, unexpected={unexpected}, "
            f"command_mismatches={command_mismatches}, "
            f"exit_mismatches={exit_mismatches}"
        )
    return {
        "required_files": len(expected),
        "missing_files": missing,
        "unexpected_files": unexpected,
        "command_mismatches": command_mismatches,
        "exit_status_mismatches": exit_mismatches,
        "passed": True,
    }


def parse_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip("'\"")
    return values


def parse_identity(raw: Path, manifests: Path) -> dict[str, Any]:
    intake = json.loads((manifests / "intake.json").read_text())
    expected_firmware = intake["firmware"]
    expected_device = intake["device"]
    release = parse_release(body(raw, "Q00_release.txt"))
    sysinfo_lines = body(raw, "Q00_sysinfo.txt").splitlines()
    board = json.loads(body(raw, "Q00_systemboard.txt"))
    checks = {
        "release": release.get("DISTRIB_RELEASE") == expected_firmware["version"],
        "revision": release.get("DISTRIB_REVISION") == expected_firmware["revision"],
        "target": release.get("DISTRIB_TARGET") == expected_firmware["target"],
        "board_name": bool(sysinfo_lines)
        and sysinfo_lines[0] == expected_device["compatible"]
        and board.get("board_name") == expected_device["compatible"],
        "kernel": board.get("kernel") == expected_firmware["kernel"],
        "rootfs_type": board.get("rootfs_type") == expected_firmware["filesystem"],
    }
    if not all(checks.values()):
        raise ValueError(f"device identity gate failed: {checks}")
    return {
        "matched": True,
        "checks": checks,
        "release": expected_firmware["version"],
        "revision": expected_firmware["revision"],
        "target": expected_firmware["target"],
        "board_name": expected_device["compatible"],
        "kernel": expected_firmware["kernel"],
        "rootfs_type": expected_firmware["filesystem"],
    }


def parse_ubus_verbose(text: str) -> dict[str, dict[str, Any]]:
    objects: dict[str, dict[str, Any]] = {}
    current = None
    for line in text.splitlines():
        head = re.match(r"^'([^']+)'\s+@", line)
        if head:
            current = head.group(1)
            objects.setdefault(current, {"methods": {}})
            continue
        method = re.match(r'^\s+"([^"]+)":(\{.*\})\s*$', line)
        if method and current:
            try:
                signature = json.loads(method.group(2))
            except json.JSONDecodeError:
                signature = {}
            objects[current]["methods"][method.group(1)] = dict(sorted(signature.items()))
    return objects


def parse_apk_db(text: str) -> dict[str, str]:
    packages: dict[str, str] = {}
    name = None
    for line in text.splitlines():
        if line.startswith("P:"):
            name = line[2:].strip()
        elif line.startswith("V:") and name:
            packages[name] = line[2:].strip()
            name = None
    return packages


def parse_privileges(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        if line.startswith("== "):
            if current:
                records.append(current)
            current = {"namespaces": {}}
            continue
        if current is None:
            continue
        if ":" in line and line.split(":")[0] in (
            "Name", "Uid", "Gid", "CapEff", "NoNewPrivs", "Seccomp"
        ):
            key, value = line.split(":", 1)
            current[key] = value.strip().split()[0] if key in ("Uid", "Gid") else value.strip()
        elif "->" in line and ":[" in line:
            parts = line.split()
            current["namespaces"][parts[-3]] = parts[-1]
    if current:
        records.append(current)
    # pid is device-run detail, not structure; drop it and key on the process name
    return [
        {
            "name": item.get("Name"),
            "uid": item.get("Uid"),
            "gid": item.get("Gid"),
            "cap_eff": item.get("CapEff"),
            "no_new_privs": item.get("NoNewPrivs"),
            "seccomp": item.get("Seccomp"),
            "namespaces": item["namespaces"],
        }
        for item in records
        if item.get("Name")
    ]


def build(raw: Path, manifests: Path) -> dict[str, Any]:
    runtime_questions = json.loads((manifests / "runtime-questions.json").read_text())
    collector_validation = validate_raw(raw, runtime_questions)
    identity = parse_identity(raw, manifests)
    ipc = json.loads((manifests / "ipc-catalog.json").read_text())
    services_static = json.loads((manifests / "service-graph.json").read_text())
    configs_static = json.loads((manifests / "config-flow.json").read_text())
    packages_static = json.loads((manifests / "packages.json").read_text())

    # --- ubus ---------------------------------------------------------------
    runtime_objects = parse_ubus_verbose(body(raw, "Q05_ubuslistv.txt"))
    listed = [line.strip() for line in body(raw, "Q05_ubuslist.txt").splitlines() if line.strip()]
    object_lists_match = set(runtime_objects) == set(listed)
    if not object_lists_match:
        raise ValueError(
            "plain and verbose ubus inventories differ: "
            f"plain_only={sorted(set(listed) - set(runtime_objects))}, "
            f"verbose_only={sorted(set(runtime_objects) - set(listed))}"
        )

    static_literal = (
        {o["object_name"] for o in ipc["ubus_objects"] if o["object_name"]}
        | {o["object_name"] for o in ipc["ubus_objects_from_deployed_ucode"] if o["name_is_literal"]}
        | {n["object_name"] for p in ipc["rpcd"]["ucode_plugins"] for n in p["registered_objects"]}
    )
    # Match runtime names against the rules the catalog declares, rather than
    # against prefixes retyped here: a rule added upstream must show up in this
    # comparison without editing this tool.
    dynamic_rules = [
        (rule["name_rule"], re.compile(rule["name_pattern"]))
        for rule in ipc["ubus_dynamic_objects"]
        if rule.get("name_pattern")
    ]
    matched_by_rule = {
        obj: [name for name, pattern in dynamic_rules if pattern.match(obj)] for obj in listed
    }
    predicted_dynamic = sorted(o for o in listed if matched_by_rule[o])
    unpredicted = sorted(
        o for o in listed if o not in static_literal and not matched_by_rule[o]
    )

    # build-gated methods the recipes said this build should not have
    gated = {
        (o["object_name"] or o["component"], name): cond
        for o in ipc["ubus_objects"]
        for name, cond in (o.get("conditional_methods") or {}).items()
    }
    gating_checks = []
    for (obj, method), condition in sorted(gated.items()):
        probe = "dnsmasq" if obj == "dnsmasq" else obj
        present = method in runtime_objects.get(probe, {}).get("methods", {})
        gating_checks.append(
            {
                "object": probe,
                "method": method,
                "source_condition": condition,
                "recipe_prediction": "absent",
                "observed_present": present,
                "prediction_held": not present,
            }
        )

    # --- services -----------------------------------------------------------
    runtime_services = json.loads(body(raw, "Q06_servicelist.txt"))
    static_by_name = {s["name"]: s for s in services_static["services"]}
    service_rows = []
    for name in sorted(runtime_services):
        instances = runtime_services[name].get("instances") or {}
        static = static_by_name.get(name)
        service_rows.append(
            {
                "service": name,
                "has_init_script": static is not None,
                "declared_instances": len(static["instances"]) if static else None,
                "runtime_instances": len(instances),
                "running": sorted(k for k, v in instances.items() if v.get("running")),
                "not_running": sorted(k for k, v in instances.items() if not v.get("running")),
                "runtime_triggers": len(runtime_services[name].get("triggers") or []),
            }
        )

    # --- packages -----------------------------------------------------------
    device_packages = parse_apk_db(body(raw, "Q14_apkdb.txt"))
    image_packages = {p["name"]: p["version"] for p in packages_static["packages"]}
    package_diff = {
        "device_count": len(device_packages),
        "image_count": len(image_packages),
        "added": sorted(set(device_packages) - set(image_packages)),
        "removed": sorted(set(image_packages) - set(device_packages)),
        "version_changed": sorted(
            n for n in set(device_packages) & set(image_packages)
            if device_packages[n] != image_packages[n]
        ),
    }

    # --- shipped config drift ----------------------------------------------
    image_config_hashes = {
        Path(c["path"]).name: c["sha256"] for c in configs_static["deployed_configs"]
    }
    device_config_hashes = {}
    for line in body(raw, "Q13_confighashes.txt").splitlines():
        parts = line.split()
        if len(parts) == 2:
            device_config_hashes[Path(parts[1]).name] = parts[0]
    config_drift = [
        {
            "config": name,
            "matches_image": device_config_hashes.get(name) == image_config_hashes[name],
        }
        for name in sorted(image_config_hashes)
    ]

    # --- boot ---------------------------------------------------------------
    cmdline = body(raw, "Q01_cmdline.txt").strip()
    rootfs_mount_options = [t for t in cmdline.split() if t.startswith("rootfs_mount_options.")]

    firstboot = body(raw, "Q03_firstboot.txt")
    uci_defaults_listing = firstboot.split("/etc/uci-defaults/:", 1)[-1]
    uci_defaults_entries = [
        line
        for line in uci_defaults_listing.splitlines()
        if line.startswith("-") and not line.rstrip().endswith((" .", " .."))
    ]

    log_text = body(raw, "Q02_logread.txt")
    boot_markers = [
        marker
        for marker in ("procd: - early -", "procd: - init -", "procd: - init complete -")
        if marker in log_text
    ]

    # --- other redacted structural observations ----------------------------
    interface_dump = json.loads(body(raw, "Q07_ifdump.txt"))
    device_status = json.loads(body(raw, "Q07_devstatus.txt"))
    nft_text = body(raw, "Q08_nftruleset.txt")

    baseline_paths = [
        line.strip()
        for line in body(raw, "Q12_ucidelta.txt").splitlines()
        if line.startswith("/var/run/config.check/")
    ]
    rpc_http = body(raw, "Q13_uhttpdrpcd.txt")
    http_rpc_surface = {
        "uhttpd_ubus_prefix_is_slash_ubus": bool(
            re.search(r"option\s+ubus_prefix\s+['\"]?/ubus['\"]?", rpc_http)
        ),
        "uhttpd_no_ubusauth_set": bool(re.search(r"option\s+no_ubusauth\b", rpc_http)),
        "uhttpd_ubus_cors_set": bool(re.search(r"option\s+ubus_cors\b", rpc_http)),
        "rpcd_socket_is_default": "/var/run/ubus/ubus.sock" in rpc_http,
        "rpcd_timeout_is_30": bool(re.search(r"option\s+timeout\s+['\"]?30['\"]?", rpc_http)),
        "login_read_scope_is_wildcard": bool(re.search(r"list\s+read\s+['\"]\*['\"]", rpc_http)),
        "login_write_scope_is_wildcard": bool(re.search(r"list\s+write\s+['\"]\*['\"]", rpc_http)),
        "password_value_copied": False,
    }

    # --- privilege ----------------------------------------------------------
    privileges = parse_privileges(body(raw, "Q11_privproc.txt"))
    host_ns = {}
    for record in privileges:
        if record["name"] in ("ash", "logd"):
            host_ns = record["namespaces"]
            break
    for record in privileges:
        record["isolated_namespaces"] = sorted(
            key for key, value in record["namespaces"].items() if host_ns.get(key) != value
        )
        del record["namespaces"]

    return {
        "identity": identity,
        "ubus": {
            "runtime_object_count": len(listed),
            "runtime_objects": listed,
            "plain_and_verbose_inventories_match": object_lists_match,
            "objects_predicted_by_static_literal": sorted(o for o in listed if o in static_literal),
            "objects_matching_a_dynamic_rule": {
                obj: matched_by_rule[obj] for obj in predicted_dynamic
            },
            "dynamic_rules_with_no_instance": sorted(
                name
                for name, _ in dynamic_rules
                if not any(name in rules for rules in matched_by_rule.values())
            ),
            "objects_not_predicted": unpredicted,
            "static_literals_not_registered": sorted(static_literal - set(listed)),
            "build_gating_checks": gating_checks,
            "method_signatures": {
                name: {
                    method: signature
                    for method, signature in sorted(data["methods"].items())
                }
                for name, data in sorted(runtime_objects.items())
            },
        },
        "services": {
            "runtime_service_count": len(runtime_services),
            "static_init_script_count": len(static_by_name),
            "services_without_init_script": [
                r["service"] for r in service_rows if not r["has_init_script"]
            ],
            "rows": service_rows,
        },
        "packages": package_diff,
        "shipped_config_drift": config_drift,
        "boot": {
            "kernel_cmdline_tokens": sorted(cmdline.split()),
            "rootfs_mount_options_tokens": rootfs_mount_options,
            "failsafe_marker_present": body(raw, "Q02_failsafe.txt").strip() == "0",
            "uci_defaults_remaining_count": len(uci_defaults_entries),
            "board_json_present": "/etc/board.json" in firstboot,
            "rc_local_present": "/etc/rc.local" in firstboot,
            "retained_log_lines": len(log_text.splitlines()),
            "retained_boot_markers": boot_markers,
        },
        "network_state": {
            "interface_count": len(interface_dump.get("interface") or []),
            "device_count": len(device_status),
            "addresses_copied": False,
        },
        "firewall_state": {
            "table_count": len(re.findall(r"^table\s+", nft_text, flags=re.MULTILINE)),
            "chain_count": len(re.findall(r"^\s*chain\s+", nft_text, flags=re.MULTILINE)),
            "flowtable_count": len(
                re.findall(r"^\s*flowtable\s+", nft_text, flags=re.MULTILINE)
            ),
            "rules_copied": False,
        },
        "config_baseline": {
            "tracked_file_count": len(baseline_paths),
            "historical_backup_count": sum("bak-codex-" in path for path in baseline_paths),
            "dnsproxy_remnant_count": sum("dnsproxy" in path for path in baseline_paths),
            "tracked_paths_copied": False,
        },
        "http_rpc_surface": http_rpc_surface,
        "privileges": privileges,
        "collector": {
            "commands_run": sorted(p.name for p in raw.glob("*.txt")),
            "nonzero_exit": {
                p.name: exit_code(raw, p.name)
                for p in sorted(raw.glob("*.txt"))
                if exit_code(raw, p.name) not in (0, None)
            },
            "validation": collector_validation,
        },
    }


def assert_redacted(payload: dict[str, Any]) -> list[str]:
    text = json.dumps(payload)
    findings = []
    for pattern, label in SECRET_PATTERNS:
        for match in pattern.findall(text):
            value = match if isinstance(match, str) else match[0]
            if value in REDACTION_ALLOWLIST:
                continue
            findings.append(f"{label}: {value}")
    return sorted(set(findings))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--manifests", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    payload = build(args.raw.resolve(), args.manifests.resolve())
    leaks = assert_redacted(payload)
    if leaks:
        for leak in leaks:
            print(f"FAIL redaction: {leak}")
        raise SystemExit(f"{len(leaks)} unredacted value(s); manifest not written")

    manifest = {
        "schema_version": 1,
        "stage": "I0.7",
        "status": "complete",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "method": {
            "source": "approved read-only command list from runtime-questions.json",
            "raw_output_location": "private evidence directory outside Git",
            "device_writes": False,
            "redaction_asserted": True,
        },
        "scope_limit": (
            "One observation of one device at one moment. It does not describe untested "
            "timing, failure states, or any boot other than the one running."
        ),
        **payload,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "ubus_objects": manifest["ubus"]["runtime_object_count"],
                "objects_not_predicted": manifest["ubus"]["objects_not_predicted"],
                "static_literals_not_registered": manifest["ubus"]["static_literals_not_registered"],
                "build_gating_all_held": all(
                    c["prediction_held"] for c in manifest["ubus"]["build_gating_checks"]
                ),
                "services_without_init_script": manifest["services"]["services_without_init_script"],
                "packages": manifest["packages"],
                "redaction_findings": 0,
                "output_sha256": sha256_file(args.output),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
