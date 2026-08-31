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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def body(raw: Path, name: str) -> str:
    """Strip the collector's command header and exit footer."""
    lines = (raw / name).read_text(errors="replace").splitlines()
    return "\n".join(lines[1:-1])


def exit_code(raw: Path, name: str) -> int | None:
    for line in reversed((raw / name).read_text(errors="replace").splitlines()):
        if line.startswith("### exit:"):
            return int(line.split(":", 1)[1])
    return None


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
            objects[current]["methods"][method.group(1)] = sorted(signature)
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
    ipc = json.loads((manifests / "ipc-catalog.json").read_text())
    services_static = json.loads((manifests / "service-graph.json").read_text())
    configs_static = json.loads((manifests / "config-flow.json").read_text())
    packages_static = json.loads((manifests / "packages.json").read_text())

    # --- ubus ---------------------------------------------------------------
    runtime_objects = parse_ubus_verbose(body(raw, "Q05_ubuslistv.txt"))
    listed = [line.strip() for line in body(raw, "Q05_ubuslist.txt").splitlines() if line.strip()]

    static_literal = (
        {o["object_name"] for o in ipc["ubus_objects"] if o["object_name"]}
        | {o["object_name"] for o in ipc["ubus_objects_from_deployed_ucode"] if o["name_is_literal"]}
        | {n["object_name"] for p in ipc["rpcd"]["ucode_plugins"] for n in p["registered_objects"]}
    )
    dynamic_prefixes = ("network.interface.", "hotplug.", "odhcp6c.", "wpa_supplicant.", "hostapd.")
    # names a dynamic rule predicts exactly rather than by prefix
    dynamic_defaults = {"dnsmasq"}
    predicted_dynamic = sorted(
        o for o in listed if o.startswith(dynamic_prefixes) or o in dynamic_defaults
    )
    unpredicted = sorted(
        o
        for o in listed
        if o not in static_literal
        and o not in dynamic_defaults
        and not o.startswith(dynamic_prefixes)
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
        "ubus": {
            "runtime_object_count": len(listed),
            "runtime_objects": listed,
            "objects_predicted_by_static_literal": sorted(o for o in listed if o in static_literal),
            "objects_matching_a_dynamic_rule": predicted_dynamic,
            "objects_not_predicted": unpredicted,
            "static_literals_not_registered": sorted(static_literal - set(listed)),
            "build_gating_checks": gating_checks,
            "method_signatures": {
                name: sorted(data["methods"]) for name, data in sorted(runtime_objects.items())
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
            "uci_defaults_remaining": [
                line.split()[-1]
                for line in body(raw, "Q03_firstboot.txt").splitlines()
                if line.startswith("-") and "uci-defaults" in line
            ],
        },
        "privileges": privileges,
        "collector": {
            "commands_run": sorted(p.name for p in raw.glob("*.txt")),
            "nonzero_exit": {
                p.name: exit_code(raw, p.name)
                for p in sorted(raw.glob("*.txt"))
                if exit_code(raw, p.name) not in (0, None)
            },
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
