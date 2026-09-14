#!/usr/bin/env python3
"""Verify R92 private evidence and export only allowlisted derived records.

No deployment actions. Artifact bytes, raw replies, process IDs, configuration,
keys and backups never enter the output. Deployment completion is separate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

from r92_recovery_probe import CASES, CHECKS, ORIGINAL_DIFFERENCES
from r92_compat_probe import CASES as COMPAT_CASES


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(base):
    deployment = read(base / "deployment-r92/manifest.json")
    commit = deployment["fix_commit"]
    source = base / "canonical" / ("owrt-image-25.12.5-" + commit)
    image = read(source / "manifest.json")
    core = read(source / "core-manifest.json")
    assert image["source_commit"] == core["source_commit"] == commit
    assert core["image_manifest_sha256"] == sha(source / "manifest.json")
    assert core["toolchain_identity_sha256"] == sha(source / "core-toolchain.log")
    artifacts = dict(image["apk_sha256"])
    artifacts[image["image"]["file"]] = image["image"]["sha256"]
    artifacts[core["archive"]["file"]] = core["archive"]["sha256"]
    assert len(image["apk_sha256"]) == 7
    for name, digest in artifacts.items():
        assert Path(name).name == name and sha(source / name) == digest
    binaries = image["binary_sha256"] | core["binary_sha256"]
    assert len(binaries) == 9
    for name, digest in binaries.items():
        assert sha(base / "bins" / name) == digest
    with tarfile.open(source / core["archive"]["file"]) as archive:
        found = {}
        for member in archive:
            if member.isfile():
                name = Path(member.name).name
                assert name in core["binary_sha256"] and name not in found
                found[name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
        assert found == core["binary_sha256"]
    assert {c["rust"]["binary"]: c["rust"]["sha256"] for c in deployment["components"].values()} == binaries
    return {"source_commit": commit, "release_workflow": deployment["canonical_build"]["run_id"],
            "workflow_conclusion": deployment["canonical_build"]["conclusion"],
            "openwrt": image["openwrt"], "profile": image["profile"], "artifact_sha256": artifacts,
            "image_manifest_sha256": sha(source / "manifest.json"),
            "core_manifest_sha256": sha(source / "core-manifest.json"), "binary_sha256": binaries,
            "original_binary_sha256": {name: c["original"]["sha256"] for name, c in deployment["components"].items()},
            "binary_bytes": {name: (base / "bins" / name).stat().st_size for name in binaries},
            "toolchain": image["toolchain"], "generated_image_flashed": False,
            "verification": "Seven APKs, generated image, core archive, manifest chain and all nine standalone binary identities verified; deployment is attested separately."}


def validation(base, canonical):
    raw = base / "oracle-evidence/raw"
    effective = read(base / "validation-effective.json")
    assert effective["source_commit"] == canonical["source_commit"]
    assert effective["passed"] and len(effective["gates"]) == effective["gate_count"] == 69
    assert len({r["name"] for r in effective["gates"]}) == 69
    assert sum(r["required"] for r in effective["gates"]) == effective["required_passed"] == 68
    for row in effective["attempts"]:
        path = raw / row["source"] / (row["name"] + ".log")
        assert path.resolve().is_relative_to(raw.resolve()) and sha(path) == row["log_sha256"]
    units = {}
    for row in effective["gates"]:
        assert row in effective["attempts"] and (not row["required"] or row["exit"] == 0)
        if row["name"].endswith("-unit"):
            log = (raw / row["source"] / (row["name"] + ".log")).read_text()
            names = re.findall(r"^test (.*?) \.\.\. ok$", log, re.M)
            count = sum(int(n) for n in re.findall(r"test result: ok\. (\d+) passed;", log))
            assert len(names) == count and count > 0
            units[row["name"].removesuffix("-unit")] = {"executions": count, "distinct_names": len(set(names))}
    assert sum(c["executions"] for c in units.values()) == 450
    assert sum(c["distinct_names"] for c in units.values()) == 449
    offline = []
    for folder, count in (("offline-switch-01", 5), ("offline-apk-upgrade-03", 4)):
        log = raw / folder / "test.log"
        assert (log.parent / "COMPLETE").exists()
        names = re.findall(r"^PASS: (.*)$", log.read_text(), re.M)
        assert len(names) == count
        offline.append({"suite": folder, "passed": count, "checks": names, "log_sha256": sha(log)})
    fuzz = read(raw / "canonical-validation-01/httpd-fuzz/summary.json")
    assert fuzz["cases"] == len(fuzz["checks"]) == 133 and all(fuzz["checks"].values())
    assert fuzz["candidate_sha256"] == canonical["binary_sha256"]["httpd-rs"]
    assert sorted(fuzz["candidate_changes"]) == ["chunked-huge-size", "header-ctrl"]
    network = raw / "canonical-validation-01/netifd-suite.log"
    assert "SUITE: 31 of 31 run -- 31 passed, 0 failed, 0 not selected" in network.read_text()
    hotplug = raw / "canonical-validation-01/procd-r71-hotplug.log"
    command = next(r["command"] for r in read(raw / "canonical-validation-01/results.json")["results"]
                   if r["name"] == "procd-r71-hotplug")
    assert "R90_HOTPLUG_PROBE=1" in command and "r71: ok" in hotplug.read_text()
    return {**effective, "rust_tests": units, "rust_distinct_tests": 449, "rust_test_executions": 450,
            "repeated_test": "rpcd wake_tests::saturated_wake_pipe_keeps_signal_handling_live is compiled into both library and binary targets.",
            "offline": offline, "httpd_fuzz": fuzz,
            "netifd_suite": {"scenarios": 31, "passed": 31, "skipped": 0, "log_sha256": sha(network)},
            "hotplug": {"specialized_mode": True, "passed": True, "log_sha256": sha(hotplug)},
            "scope": "Formal runtime hashes are fixed; corrected helper/environment/collector gates keep all earlier failed attempts."}


def focused(base, canonical):
    raw = base / "oracle-evidence/raw/canonical-completion-03"
    recovery_file = raw / "r92-recovery/results.json"
    recovery = read(recovery_file)
    assert len(recovery) == 2 * len(CASES) == 20
    identities = read(raw / "r92-recovery/binaries.json")
    for component, pair in identities.items():
        assert pair["candidate"] == canonical["binary_sha256"][component + "-rs"]
        assert pair["original"] == canonical["original_binary_sha256"][component]
    rows = []
    allowed = {"cpu_seconds_in_0_8s", "before", "after", "elapsed_seconds", "status", "request_bytes",
               "projected_response_bytes", "rss_before_kib", "rss_after_kib", "rss_peak_kib", "slow_bytes"}
    for row in recovery:
        expected = ORIGINAL_DIFFERENCES.get(row["case"], {}) if row["side"] == "original" else {}
        assert row["passed"] and row["exit"] == 0 and CHECKS[row["case"]] <= row["checks"].keys()
        assert all(v == expected.get(k, True) for k, v in row["checks"].items())
        rows.append({k: row[k] for k in ("side", "case", "exit", "checks", "expected_original_failures", "passed")} |
                    {"observations": {k: v for k, v in row["observations"].items() if k in allowed}})
    compat_file = raw / "r92-compat/results.json"
    compat = read(compat_file)
    assert len(compat) == 34 and all(r["passed"] and r["exit"] == 0 for r in compat)
    compat_rows = []
    for row in compat:
        assert row["checks"] and all(c["passed"] for c in row["checks"].values())
        component, _, required = COMPAT_CASES[row["case"]]
        assert required <= row["checks"].keys()
        identity = (row["observations"]["binary_sha256"] if row["case"] == "uci_rename"
                    else row["checks"]["identity"]["actual"])
        assert identity == (canonical["original_binary_sha256"][component] if row["side"] == "original"
                            else canonical["binary_sha256"][component + "-rs"])
        compat_rows.append({"side": row["side"], "case": row["case"], "passed": True,
                            "assertions": sorted(row["checks"]), "subject_sha256": identity})
    firewall_file = raw / "r92-fw4/results.json"
    firewall = read(firewall_file)
    assert len(firewall) == 16 and all(r["passed"] for r in firewall)
    firewall_rows = []
    for row in firewall:
        firewall_rows.append({"case": row["case"], "passed": True, "sides": {
            side: {k: value[k] for k in ("binary_sha256", "exit", "diagnostic_ok", "stdout_sha256", "stderr_sha256")}
            for side, value in row["observations"].items()}})
    red_file = base / "oracle-evidence/raw/plugin-red-09/results.json"
    red = []
    for row in read(red_file):
        if row["case"] not in ("rpcd_lease_boundary", "rpcd_features"):
            continue
        identity = row["checks"]["identity"]
        assert identity["passed"] and row["passed"] == (row["side"] == "original")
        red.append({"side": "r89" if row["side"] == "candidate" else "original", "case": row["case"],
                    "exit": row["exit"], "passed": row["passed"], "subject_sha256": identity["actual"]})
    return {"recovery": rows, "recovery_identities": identities, "compatibility": compat_rows,
            "fw4": firewall_rows, "r89_plugin_crash_controls": red,
            "source_sha256": {"recovery": sha(recovery_file), "compatibility": sha(compat_file),
                              "fw4": sha(firewall_file), "r89_plugin_controls": sha(red_file)},
            "meaning_of_passed": "Matched that row's explicit contract. Original adverse invariants remain false and are never waived for the candidate."}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("private_root", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    canonical = build(a.private_root)
    outputs = {"canonical_build": canonical, "validation": validation(a.private_root, canonical),
               "recovery_compatibility": focused(a.private_root, canonical)}
    a.output.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        with (a.output / (name + ".json")).open("x") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
    print(json.dumps({"verified": True, "required_gates": 68, "rust_distinct_tests": 449}))


if __name__ == "__main__":
    main()
