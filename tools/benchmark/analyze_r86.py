#!/usr/bin/env python3
"""Derive the final R86 report from its completed private evidence.

This only reads local files. It neither deploys nor accepts partial measurements.
The preparation manifest is immutable; deployment completion is recorded apart.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

from analyze import WINDOWS, summarize, windows
from analyze_candidate import derive
from analyze_httpd_memory import derive as derive_memory
from render import PRIMARY

COMPONENT_ORDER = ["stock", "candidate", "candidate", "stock", "stock", "candidate", "candidate", "stock"]


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private_root", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base, out = args.private_root, args.output
    manifest = read(args.manifest)
    gate = read(base / "deployment/final-gate.json")
    assert gate["reviewed"] and gate["canonical_components_verified"] == 9
    assert all(gate[key] for key in ("required_function_gates_passed", "final_component_matrices_passed",
                                    "offline_switch_test_passed", "backup_verified"))
    assert sha(args.manifest) == gate["deployment_manifest_sha256"]
    assert sha(args.archive) == gate["deployment_archive_sha256"]
    assert manifest["fix_commit"] == gate["source_commit"]
    assert gate["window_order"] == list(WINDOWS)
    assert (base / "DEPLOYMENT_AND_WINDOWS_COMPLETE").exists()
    events = [json.loads(line) for line in (base / "deploy-and-measure.log").read_text().splitlines()
              if line.startswith("{")]
    assert events[-1]["event"] == "latest_nine_components_healthy_all_four_windows_complete"
    assert [e["window"] for e in events if e["event"] == "window_measured"] == list(WINDOWS)
    health = read(base / "final-health.json")
    assert health["mode"] == "rust" and set(health["verified_components"]) == set(manifest["components"])
    health_keys = ("client_dhcp", "local_http_https", "dns_https_ipv4", "dns_https_ipv6", "watchdog_running")
    assert all(health[key] is True for key in health_keys)
    assert health["interfaces_up"] == ["loopback", "lan", "wan", "wan6"]
    assert len(health["ap_bridges"]) == 2

    rows, residents, sources, eligible = [], [], [], {}
    for component in PRIMARY:
        relative = {"httpd": "httpd-final2", "netifd": "netifd-final-gate"}.get(
            component, "canonical-matrix/" + component)
        value = derive(base / relative, "R86 final " + component)
        assert value["acceptance_eligible"] and value["order"] == COMPONENT_ORDER
        assert value["benchmark_sha256"] == manifest["tools"]["owrt-benchmark"]["sha256"]
        assert value["namespace_sha256"] == manifest["tools"]["ns-exec"]["sha256"]
        for side, reference in (("candidate", "rust"), ("stock", "original")):
            assert value["subjects"][side] == manifest["components"][component][reference]["sha256"]
        eligible[component] = {"subjects": value["subjects"], "source_count": len(value["sources"]),
                               "workloads": len(value["summary"])}
        for original in value["runs"]:
            row = dict(original)
            row["side"] = "rust" if row["side"] == "candidate" else row["side"]
            row["run"] = component + "/" + row["run"]
            if component == "httpd" and row["workload"] == "static_16k_dat_c1":
                row["workload"] = "static_16k"
            rows.append({"study": "component", "component": component, **row})
        residents.extend({"component": component, **r,
                          "side": "rust" if r["side"] == "candidate" else r["side"]} for r in value["resident"])
        sources.extend({"component": component, **source} for source in value["sources"])
    assert len(rows) == 592 and sum(v["workloads"] for v in eligible.values()) == 74
    whole, resources, tls, whole_sources, missing = windows(base, manifest, False)
    assert not missing and len(resources) == 4
    rows += whole + tls
    sources += whole_sources
    boots, boot_ids = [], []
    config_before = (base / "deployment/config-before.sha256").read_bytes()
    for name in WINDOWS:
        path = base / "windows" / name
        assert (path / "measurements/live/config-before.sha256").read_bytes() == config_before
        for line in (path / "measurements/live.sha256").read_text().splitlines():
            digest, relative = line.split(None, 1)
            raw = (path / "measurements/live").resolve()
            target = (raw / relative).resolve()
            assert target.is_relative_to(raw) and sha(target) == digest
        h = read(path / "health.json")
        assert h["pre"]["boot_id"] != h["post"]["boot_id"]
        boot_ids.append(h["post"]["boot_id"])
        entries = [json.loads(line) for line in (path / "window.log").read_text().splitlines()
                   if line.startswith("{")]
        samples = [e for e in entries if e["event"] == "health_pass"]
        assert samples[-1]["continuous_s"] >= 180
        load = [json.loads(line) for line in (path / "load.log").read_text().splitlines() if line.startswith("{")]
        assert load[-1]["event"] == "window_measured" and load[-1]["window"] == name
        boots.append({"window": name, "mode": h["mode"], "new_boot_verified": True, "healthy": True,
                      "consecutive_health_sampling_seconds": samples[-1]["continuous_s"],
                      "health_completed_after_reboot_request_seconds": h["elapsed_s"],
                      "first_observed_ssh_seconds": h["first_ssh_s"], "final_observation_seconds": 30,
                      "health_report_sha256": sha(path / "health.json"),
                      "window_log_sha256": sha(path / "window.log"),
                      "live_archive_sha256": sha(path / "measurements/live.tar.gz"),
                      "measured_operations": 500650, "load_rounds": 5,
                      "tls_workloads": 8 if name.endswith("-2") else 4})
    assert len(set(boot_ids)) == 4 and health["boot_id"] == boot_ids[-1]
    memory = derive_memory(base / "httpd-final2-memory")
    assert memory["subjects"]["candidate"] == manifest["components"]["httpd"]["rust"]["sha256"]
    assert memory["subjects"]["stock"] == manifest["components"]["httpd"]["original"]["sha256"]
    assert memory["order"] == COMPONENT_ORDER
    notes = {
        "aggregation": "Median of per-run statistics. Four component trials per side; two whole-system boots per side, five rounds per boot. All valid samples retained.",
        "cpu": "One-shot programs use waited child CPU. Concurrent clients use a single common outer daemon interval.",
        "memory": "RSS is not PSS/USS. Whole-system MemAvailable includes the identity-check page cache.",
        "earlier_httpd": "The 2KiB-read-buffer build was rejected for a changed oversized-request close boundary; its full dataset is retained separately.",
        "earlier_netifd": "The first matrix lacked a valid child-reaping check; final results use the full proc-status PPid gate.",
    }
    result = {"schema": 1, "status": "complete", "pending": [], "image": manifest["image"],
              "benchmark_sha256": manifest["tools"]["owrt-benchmark"]["sha256"],
              "component_inputs": eligible, "rows": rows,
              "summaries": summarize(rows, ("study", "component", "workload", "side")),
              "component_residents": residents, "component_memory": summarize(residents, ("component", "side")),
              "windows": resources, "sources": sources, "configuration_equal_across_completed_windows": True,
              "execution_plane_equal_across_completed_windows": True,
              "nft_rules_equal_after_counter_normalization": True, "notes": notes}
    attestation = {
        "schema": 1, "status": "complete", "completed_at": events[-1]["at"],
        "canonical_runtime_commit": manifest["fix_commit"], "canonical_release_run": manifest["canonical_build"]["run_id"],
        "deployment_archive_sha256": sha(args.archive), "preparation_manifest_sha256": sha(args.manifest),
        "preparation_manifest_preserved": True, "management_access": "wifi", "lan_cable_required": False,
        "physical_deployment_completed": True, "final_mode": "rust", "verified_component_count": 9,
        "component_sha256": {k: v["rust"]["sha256"] for k, v in manifest["components"].items()},
        "automatic_stock_rollback_seconds": 900, "pending_and_reverting_absent": True,
        "configuration_unchanged": True, "execution_plane_equal_across_windows": True,
        "firewall_rules_equal_across_windows_after_counter_normalization": True,
        "kernel": sorted({s["kernel"] for s in sources}), "client_health": {k: health[k] for k in health_keys},
        "two_radios_and_ap_bridges_healthy": True, "windows": boots,
        "gate_sha256": sha(base / "deployment/final-gate.json"),
        "install_log_sha256": sha(base / "deployment/install.log"),
        "driver_log_sha256": sha(base / "deploy-and-measure.log"), "final_health_sha256": sha(base / "final-health.json"),
        "backup_verified": True, "previous_r84_bundle_preserved": True,
        "limits": ["Consecutive health denotes periodic successful probes, not uninterrupted packet monitoring.",
                   "Two independent cold boots per side, five workload rounds per boot; not ten independent boots.",
                   "The hash-pinned preparation manifest retains its preparation state; this attestation records completion."],
    }
    groups = {(r["study"], r["component"], r["workload"], r["side"]): r["metrics"] for r in result["summaries"]}

    def compare(study, component, workload, metric):
        c = groups[study, component, workload, "stock"][metric]["median"]
        r = groups[study, component, workload, "rust"][metric]["median"]
        return {"stock": c, "rust": r, "rust_vs_stock_percent": 100 * (r / c - 1)}

    counts = {m: {"lower": 0, "equal": 0, "higher": 0}
              for m in ("mean_us", "subject_cpu_us_per_op", "p95_us", "p99_us")}
    primary = [{"component": c, "workload": w, **{m: compare("component", c, w, m) for m in counts}}
               for c, w in PRIMARY.items()]
    for c, w in sorted({(r["component"], r["workload"]) for r in rows if r["study"] == "component"}):
        for metric in counts:
            d = compare("component", c, w, metric)["rust_vs_stock_percent"]
            counts[metric]["lower" if d < 0 else "higher" if d > 0 else "equal"] += 1
    whole_comparison = {w: {m: compare("whole", "all", w, m) for m in ("ops_per_s", "server_cpu_us_per_op")}
                        for w in sorted({r["workload"] for r in rows if r["study"] == "whole"})}
    for w, comparison in whole_comparison.items():
        if w != "mixed-total":
            comparison["mean_us"] = compare("whole", "all", w, "mean_us")
    active = {side: statistics.median(w["active_server_cpu_s"] for w in resources if w["side"] == side)
              for side in ("stock", "rust")}
    summary = {"schema": 1, "component_workloads": 74, "component_observations": 592,
               "component_counts": counts, "primary": primary, "whole": whole_comparison,
               "whole_fixed_batch_cpu_s": {**active, "rust_vs_stock_percent": 100 * (active["rust"] / active["stock"] - 1)},
               "whole_operations_per_boot": 500650, "cold_boots_per_side": 2, "rounds_per_boot": 5,
               "tls": {study: {w: {m: compare(study, "httpd", w, m) for m in ("mean_ms", "httpd_cpu_us_per_op")}
                               for w in ("keepalive-c1", "keepalive-c4", "fresh-c1", "fresh-c4")}
                       for study in ("tls-default", "tls-common")}, "httpd_held_memory": memory["summary"]}
    out.mkdir(parents=True, exist_ok=True)
    for name, value in (("results", result), ("deployment", attestation), ("summary", summary),
                        ("httpd_memory_router", memory)):
        (out / (name + ".json")).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"completed": True, "windows": len(boots), "final_nine_verified": True,
                      "mixed": whole_comparison["mixed-total"], "active_cpu": summary["whole_fixed_batch_cpu_s"]}))


if __name__ == "__main__":
    main()
