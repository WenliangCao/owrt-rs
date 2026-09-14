#!/usr/bin/env python3
"""Attest complete R92 acceptance and export only derived, publishable evidence.

Requires all four cold windows, nine three-way matrices, affinity and separate
diagnostics, wireless controls and final device cleanup. No partial acceptance.
Private replies, addresses, process IDs and configuration are never exported.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import r92_publish_validation as formal  # noqa: E402
import r92_wireless_compare as wireless  # noqa: E402
from r92_finalize_device import STAGES  # noqa: E402
from analyze import COMPONENT_WORK, WINDOWS, SYSTEM_MEMORY_KEYS, native, stats, summarize, timing, windows  # noqa: E402
from analyze_candidate import derive as component_derive  # noqa: E402
from analyze_diagnostics import derive as diagnostic_derive, syscalls  # noqa: E402


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_files(root, manifest):
    """Require exact file membership as well as every downloaded byte hash."""
    root = root.resolve()
    verified = set()
    for line in manifest.read_text().splitlines():
        digest, name = line.split(None, 1)
        path = (root / name).resolve()
        assert not Path(name).is_absolute() and ".." not in Path(name).parts
        assert re.fullmatch(r"[a-f0-9]{64}", digest) and path.is_relative_to(root)
        assert path not in verified and not (root / name).is_symlink()
        assert sha(path) == digest, "downloaded file changed"
        verified.add(path)
    assert verified == {p.resolve() for p in root.rglob("*") if p.is_file()}, "download membership differs"
    assert verified
    return {"verified_files": len(verified), "hash_manifest_sha256": sha(manifest)}


def verified_archive(archive, root):
    """Recheck extracted diagnostic data against the retained original archive."""
    root = root.resolve()
    files = set()
    with tarfile.open(archive) as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            if parts and parts[0] == root.name:
                parts = parts[1:]
            assert parts and ".." not in parts and not Path(*parts).is_absolute()
            path = root.joinpath(*parts).resolve()
            assert path.is_relative_to(root) and path not in files
            assert hashlib.sha256(tar.extractfile(member).read()).hexdigest() == sha(path)
            files.add(path)
    assert files == {p.resolve() for p in root.rglob("*") if p.is_file()}, "archive membership differs"
    return {"archive_sha256": sha(archive), "verified_files": len(files)}


def expected_subjects(manifest, baseline, component):
    return {"stock": manifest["components"][component]["original"]["sha256"],
            "r89": baseline["components"][component]["rust"]["sha256"],
            "candidate": manifest["components"][component]["rust"]["sha256"]}


def health_ok(value, boot, mode="rust"):
    assert value["boot_id"] == boot and value["mode"] == mode
    assert len(set(value["verified_components"])) == 9
    assert all(value[k] is True for k in ("client_dhcp", "watchdog_running", "local_http_https",
                                         "dns_https_ipv4", "dns_https_ipv6"))
    assert set(value["interfaces_up"]) == {"loopback", "lan", "wan", "wan6"}
    assert len(value["ap_bridges"]) >= 2


def cold_windows(device, manifest):
    rows, resources, tls, sources, missing = windows(device, manifest, partial=False)
    assert not missing
    boots = set()
    for name in WINDOWS:
        root = device / "windows" / name
        record = read(root / "health.json")
        boot = record["post"]["boot_id"]
        assert boot not in boots and record["pre"]["boot_id"] != boot
        boots.add(boot)
        health_ok(record["post"], boot, name.split("-")[0])
        events = [json.loads(line) for line in (root / "window.log").read_text().splitlines()
                  if line.startswith("{")]
        good = [e for e in events if e.get("event") == "health_pass"]
        assert good and good[-1]["continuous_s"] >= 180
        assert record["elapsed_s"] - good[-1]["elapsed_s"] >= 30
        if name.startswith("rust"):
            assert any(e.get("event") == "confirmed" for e in events)
        download = verified_files(root / "measurements/live", root / "measurements/live.sha256")
        next(source for source in sources if source["run"] == name).update(download)
    assert len(rows) == 260 and len(tls) == 24 and len(boots) == 4
    return {"schema": 1, "status": "complete", "benchmark_sha256": manifest["tools"]["owrt-benchmark"]["sha256"],
            "rows": rows + tls, "summaries": summarize(rows + tls, ("study", "component", "workload", "side")),
            "windows": resources, "sources": sources,
            "method": {"cold_boots": 4, "continuous_health_seconds": 180, "final_observation_seconds": 30,
                "whole_rounds_per_boot": 5, "idle_seconds_per_phase": 120,
                "cpu": "Whole-server own counters plus one-shot children; mixed uses one outer interval.",
                "rss": "Summed RSS is not PSS or USS. Idle-after includes raw tmpfs output.",
                "tls": "Fresh connections capped at 20/s. Common cipher has one boot per implementation."}}


def component_matrices(device, manifest, baseline):
    outputs = {}
    for category, names in (("components", COMPONENT_WORK), ("affinity", ("ubusd", "procd"))):
        for name in names:
            root = device / category / name
            data = component_derive(root, "R92 " + category + " " + name)
            assert data["acceptance_eligible"] and data["baseline_label"] == "r89"
            assert data["subjects"] == expected_subjects(manifest, baseline, name)
            assert all(data["order"].count(side) == 4 for side in ("stock", "r89", "candidate"))
            assert data["benchmark_sha256"] == manifest["tools"]["owrt-benchmark"]["sha256"]
            for index, side in enumerate(data["order"], 1):
                run = root / f"{index:02d}-{side}"
                download = verified_files(run / "raw", run / "raw.sha256")
                next(s for s in data["sources"] if s["run"] == run.name).update(download)
            outputs[category + "/" + name + "/results"] = data
    return outputs


def file_pages(device):
    output = []
    for window in WINDOWS:
        root = device / "windows" / window / "file-pages"
        verified_files(root / "raw", root / "raw.sha256")
        raw = root / "raw"
        groups = {}
        for group in ("active", "mapped", "bundle"):
            values = {}
            for line in (raw / (group + ".tsv")).read_text().splitlines():
                dev, inode, size, pages, resident, page_size, path = line.split("\t")
                value = {"file_bytes": int(size), "pages": int(pages), "resident_pages": int(resident),
                         "page_size": int(page_size), "current_bundle": path.startswith("/root/r84/bins/")}
                assert 0 <= value["resident_pages"] <= value["pages"] and value["page_size"] == 4096
                identity = (dev, inode)
                if identity in values:
                    assert values[identity] == value
                values[identity] = value
            groups[group] = values
        assert len(groups["active"]) == 9 and len(groups["bundle"]) == 27
        groups["current_bundle"] = {k: v for k, v in groups["bundle"].items() if v["current_bundle"]}
        assert len(groups["current_bundle"]) == 9
        union = groups["active"] | groups["mapped"] | groups["bundle"]
        resident = lambda group: sum(v["resident_pages"] * v["page_size"] // 1024 for v in group.values())
        snapshot = read(raw / "snapshot-before.json")
        deleted = raw / "deleted-mappings.txt"
        # rust-1 used the original collector; its map list has no deleted files.
        if not deleted.exists():
            assert window == "rust-1" and "(deleted)" not in (raw / "mapped-paths.txt").read_text()
        output.append({"window": window, "groups": {name: {"unique_files": len(group),
            "resident_kib": resident(group), "file_page_extent_kib": sum(v["pages"] * 4 for v in group.values())}
            for name, group in groups.items()}, "deduplicated_union_resident_kib": resident(union),
            "active_current_bundle_common_inodes": len(groups["active"].keys() & groups["current_bundle"].keys()),
            "mapped_active_common_inodes": len(groups["mapped"].keys() & groups["active"].keys()),
            "deleted_mappings_not_measured": len(deleted.read_text().splitlines()) if deleted.exists() else 0,
            "system_memory_kib": {k: snapshot["memory_kib"][k] for k in SYSTEM_MEMORY_KEYS},
            "archive_sha256": sha(root / "raw.tar.gz")})
    return {"schema": 1, "windows": output, "method": "mmap(PROT_NONE) + mincore; deduplicate by dev/inode.",
            "limitations": ["File-page residency is not exclusive process memory and must not be added to RSS.",
                "Unlinked udebug mappings in C are recorded separately and cannot be measured by pathname.",
                "Normal identity checks read active files and reference copies; cache state is part of the result."]}


def diagnostic_records(root, kind, expected, benchmark=None, manifest=None):
    """Revalidate self-contained build-host TLS/bridge records, excluding trace timing."""
    assert (root / "COMPLETE").exists()
    rows = read(root / "results.json")
    for row in rows:
        raw = root / row["name"] / "raw"
        assert (raw / "COMPLETE").exists() and sha(raw / "result.json") == row["result_sha256"]
        source = read(raw / "result.json")
        assert all(row[k] == v for k, v in source.items())
        assert row["diagnostic_only"] and row["subject_sha256"] == expected[row["side"]]
        if kind == "tls":
            assert row["successful"] == 80 and row["warmup"] == 8 and row["clients"] == 4
            if row["protocol"] == "https":
                assert row["tls_versions"] == ["TLSv1.2"]
                assert row["tls_ciphers"] == ["ECDHE-ECDSA-AES256-GCM-SHA384"]
        else:
            assert row["benchmark_sha256"] == benchmark
            for component, digest in row["dependency_sha256"].items():
                assert digest == manifest["components"][component]["original" if row["dependencies"] == "original" else "rust"]["sha256"]
            assert [r["method"] for r in row["rows"]] == ["uci.configs", "uci.get"]
            assert all(r["successful"] == (400 if row["traced"] else 10000) for r in row["rows"])
        if row["traced"]:
            assert "mean_ms" not in row and "mean_us" not in row
            assert all("mean_us" not in r for r in row.get("rows", []))
            assert row["syscalls"] == syscalls(raw / "syscalls.txt")
    assert len(rows) == (60 if kind == "tls" else 15)
    return {"schema": 1, "settings": read(root / "settings.json"), "rows": rows,
            "limitations": ["Build-host diagnostic; not a router performance score.",
                            "Tracing groups export syscall counts separately from untraced timing."]}


def diagnostics(base, manifest, baseline):
    device = base / "device"
    expected = expected_subjects(manifest, baseline, "httpd")
    outputs = {}
    for name, folder, count in (("http_diagnostics_oracle", "http-diagnostics-canonical-01", 66),
                               ("http_memory_extended_oracle", "http-memory-extended-02", 6),
                               ("tls_delay_oracle", "tls-delay-canonical-01", 60),
                               ("http_bridge_oracle", "http-bridge-01", 15)):
        root = base / "oracle-evidence/raw" / folder
        archive = verified_archive(base / "oracle-evidence" / (folder + ".tar.gz"), root)
        if name.startswith("http_diagnostics") or name.startswith("http_memory"):
            data = diagnostic_derive(root)
            assert data["subject_sha256"] == expected
        else:
            data = diagnostic_records(root, "tls" if name.startswith("tls") else "bridge", expected,
                                      manifest["tools"]["owrt-benchmark"]["sha256"], manifest)
        assert len(data["rows"]) == count
        outputs[name] = data | archive
    root = device / "http-diagnostics"
    router = diagnostic_derive(root)
    assert router["subject_sha256"] == expected and len(router["rows"]) == 42
    for row in router["rows"]:
        verified_files(root / row["name"], root / (row["name"] + ".sha256"))
    outputs["http_diagnostics_router"] = router
    root = device / "tail-traces"
    assert (root / "COMPLETE").exists()
    traces = []
    for run in read(root / "runs.json"):
        raw = root / run["name"]
        verified_files(raw, root / (run["name"] + ".sha256"))
        assert run["exit"] == 0 and (raw / "TRACE_DIAGNOSTIC").exists()
        expected_hash = expected_subjects(manifest, baseline, run["component"])[run["side"]]
        assert (raw / "subject-sha256.txt").read_text().split()[0] == expected_hash
        traces.append({"component": run["component"], "side": run["side"], "subject_sha256": expected_hash,
                       "syscalls": syscalls(raw / "syscalls.txt"), "archive_sha256": sha(root / (run["name"] + ".tar.gz"))})
    assert len(traces) == 6
    outputs["tail_syscalls_router"] = {"schema": 1, "rows": traces,
        "limitations": ["Separate traced workload; no traced timing is a performance matrix sample.",
                        "Syscall counts do not uniquely identify scheduler or IRQ causes of tail latency."]}
    cache = device / "reference-cache"
    assert (cache / "COMPLETE").exists()
    outputs["reference_cache_router"] = read(cache / "summary.json")
    assert outputs["reference_cache_router"]["active_inodes_excluded"]
    assert outputs["reference_cache_router"]["files_and_configuration_unchanged"]
    assert len(outputs["reference_cache_router"]["phases"]) == 5
    for phase in outputs["reference_cache_router"]["phases"]:
        assert sha(cache / (phase["phase"] + ".jsonl")) == phase["source_sha256"]
        samples = [json.loads(line) for line in (cache / (phase["phase"] + ".jsonl")).read_text().splitlines()]
        assert len(samples) == phase["samples"] == 31
        for key, value in phase["system_memory_kib"].items():
            assert value == stats(s["memory_kib"][key] for s in samples)
        phase["additional_memory_accounting_kib"] = {
            key: stats(s["memory_kib"][key] for s in samples)
            for key in ("Active(file)", "Inactive(file)", "KReclaimable", "AnonPages", "Unevictable")}
        phase["available_minus_free_kib"] = stats(
            s["memory_kib"]["MemAvailable"] - s["memory_kib"]["MemFree"] for s in samples)
    live = device / "http-live-pair"
    assert (live / "COMPLETE").exists()
    settings = read(live / "settings.json")
    assert settings["subjects"] == expected | {"live": expected["candidate"]}
    assert settings["benchmark_sha256"] == manifest["tools"]["owrt-benchmark"]["sha256"]
    rows = read(live / "results.json")
    assert len(rows) == 32
    assert len(settings["order"]) == 16 and all(settings["order"].count(side) == 4 for side in settings["subjects"])
    for index, side in enumerate(settings["order"], 1):
        folder = live / f"{index:02d}-{side}"
        verified_files(folder / "raw", folder / "raw.sha256")
        assert (folder / "raw/identity.txt").read_text().split()[0] == settings["subjects"][side]
        for method in ("configs", "get"):
            data = native(folder / "raw" / (method + ".json"))
            assert data["successful"] == 10000 and data["warmup"] == 30
            row = next(r for r in rows if r["run"] == folder.name and r["method"] == "uci." + method)
            assert all(row[k] == v for k, v in timing(data).items())
            assert len(data["daemon_cpu"]) == 3
            assert data["daemon_cpu"][0]["pid"] == int((folder / "raw/subject.pid").read_text())
            assert row["cpu_us_per_op"] == {
                name: process["cpu_s"] * 1e6 / data["successful"]
                for name, process in zip(("httpd", "rpcd", "ubusd"), data["daemon_cpu"])}
            assert row["archive_sha256"] == sha(folder / "raw.tar.gz")
    outputs["http_live_pair_router"] = {"schema": 1, "settings": settings, "rows": rows,
        "limitations": ["All four HTTP servers use the same live R92 ubusd/rpcd, configuration and session.",
                        "Fresh temporary servers and the running server have different process histories.",
                        "Diagnostic pairs are separate from the cold-window and isolation matrices."]}
    return outputs


def historical_comparison(current, history):
    rows = []
    for record in current["summaries"]:
        if record["side"] != "rust":
            continue
        key = (record["study"], record["component"], record["workload"])
        previous = next((r for r in history["summaries"] if r["side"] == "rust" and
                         (r["study"], r["component"], r["workload"]) == key), None)
        if not previous:
            continue
        metrics = {}
        for metric, sample in record["metrics"].items():
            if metric in previous["metrics"] and metric not in ("successful", "cpu_bracket_successful"):
                old = previous["metrics"][metric]["median"]
                new = sample["median"]
                metrics[metric] = {"r89": old, "r92": new, "r92_vs_r89_pct": (new / old - 1) * 100 if old else None}
        rows.append({"study": key[0], "component": key[1], "workload": key[2], "metrics": metrics})
    return {"schema": 1, "baseline": "Published formal R89 cold windows", "rows": rows,
        "limitations": ["Different dates and boots; the same frozen client is verified but router activity is not identical.",
            "R92 wireless observations prewarm plugin/parser paths; historical RSS is not an identical prewarm experiment.",
            "Whole log-read uses the latest 100 real entries. Their content is not fixed across releases.",
            "Isolated HTTP jsonrpc uses uci configs; whole-window HTTP uses uci get network."]}


def process_cpu_comparison(base, manifest, baseline):
    rows, sources = [], []
    configurations, network_inputs = set(), set()
    for release, parent, mode, expected in (
        ("R89", base.parent / "r89", "rust", baseline),
        ("R92", base / "device", "rust", manifest),
        ("C", base / "device", "stock", manifest),
    ):
        for index in (1, 2):
            name = mode + "-" + str(index)
            root = parent / "windows" / name / "measurements"
            raw = root / "live"
            download = verified_files(raw, root / "live.sha256")
            assert (raw / "benchmark-sha256.txt").read_text().split()[0] == manifest["tools"]["owrt-benchmark"]["sha256"]
            names = {}
            for line in (raw / "running-hashes.txt").read_text().splitlines():
                component, pid, digest = line.split()
                assert digest == expected["components"][component]["original" if mode == "stock" else "rust"]["sha256"]
                if pid != "-":
                    names[int(pid)] = component
            configurations.add((raw / "config-before.sha256").read_bytes())
            network_inputs.add((raw / "expected-uci.bytes").read_bytes())
            for repeat in range(1, 6):
                for work in ("http-jsonrpc", "log"):
                    data = native(raw / f"{repeat}-{work}.json")
                    assert data["successful"] == 10000
                    rows.append({"release": release, "window": name, "repeat": repeat, "workload": work,
                        "process_cpu_us_per_op": {names[p["pid"]]: p["cpu_s"] * 100 for p in data["daemon_cpu"]}})
            sources.append({"release": release, "window": name, "archive_sha256": sha(root / "live.tar.gz"), **download})
    assert len(configurations) == len(network_inputs) == 1
    summary = []
    for release in ("C", "R89", "R92"):
        for work in ("http-jsonrpc", "log"):
            group = [r for r in rows if r["release"] == release and r["workload"] == work]
            assert len(group) == 10
            summary.append({"release": release, "workload": work, "process_cpu_us_per_op": {
                name: stats(r["process_cpu_us_per_op"][name] for r in group) for name in group[0]["process_cpu_us_per_op"]}})
    return {"schema": 1, "rows": rows, "summary": summary, "sources": sources,
        "same_configuration_and_network_export": True,
        "limitations": ["Historical log bodies were not frozen or captured by the timing client.",
                        "Identical configuration does not imply identical runtime process history or scheduling.",
                        "CPU medians for different processes need not sum exactly to the median total."]}


def derive(base, history_root, final):
    device = base / "device"
    assert all((device / stage).exists() for stage in STAGES)
    assert (final / "COMPLETE").exists(), "final device attestation missing"
    manifest = read(base / "deployment-r92/manifest.json")
    baseline = read(device / "recovery-01/r89-before-r90.manifest.json")
    historical = read(history_root / "r89_canonical_build.json")
    assert {c["rust"]["binary"]: c["rust"]["sha256"] for c in baseline["components"].values()} == (
        historical["packaged_binary_sha256"] | historical["core_binary_sha256"])
    canonical = formal.build(base)
    output = {"canonical_build": canonical, "validation": formal.validation(base, canonical),
              "recovery_compatibility": formal.focused(base, canonical)}
    tooling = read(base / "derived/tool-validation.json")
    for name, log in (("tools_syntax_and_harnesses", "final-tools-check.log"),
                      ("benchmark_python", "final-benchmark-python.log")):
        assert tooling["checks"][name]["passed"] and tooling["checks"][name]["log_sha256"] == sha(base / log)
    assert tooling["harness_tests"] == 21 and tooling["benchmark_python_tests"] == 33
    output["tool_validation"] = tooling
    uci_sources = read(base / "derived/uci-reference-sha256.json")
    assert set(uci_sources) == {"util.c", "list.c", "file.c", "delta.c", "libuci.c", "cli.c"}
    assert all(sha(base.parent / "stage6/src/uci" / name) == value for name, value in uci_sources.items())
    output["uci_reference"] = {"upstream_revision": "66127cd76c5d0bd46d5a90302cc6110f53a4e2f8", "source_sha256": uci_sources,
        "reviewed_boundaries": ["package cache invalidation", "delta replay", "file transactions",
                                "fast and general parser", "invalid-name failure atomicity"],
        "regression_gates": ["uci-unit", "uci-r16", "uci-r24", "uci-r83"],
        "scope": "Focused internal review and runtime regression; not a formal proof of every libuci path."}
    output["whole_system"] = cold_windows(device, manifest)
    output.update(component_matrices(device, manifest, baseline))
    output["file_pages_router"] = file_pages(device)
    output.update(diagnostics(base, manifest, baseline))
    for name in ("host-hints-01", "scan-ie-01"):
        verified_archive(base / "oracle-evidence" / (name + ".tar.gz"), base / "oracle-evidence/raw" / name)
    live = device / "host-hints-live"
    verified_files(live / "raw", live / "raw.sha256")
    output["wireless"] = wireless.derive(device)
    output["historical_r89_comparison"] = historical_comparison(output["whole_system"], read(history_root / "results.json"))
    output["whole_process_cpu"] = process_cpu_comparison(base, manifest, baseline)
    final_data = read(final / "summary.json")
    boot = read(device / "windows/rust-2/health.json")["post"]["boot_id"]
    health_ok(read(final / "health-after.json"), boot)
    assert final_data["source_commit"] == canonical["source_commit"]
    assert all(final_data[k] is True for k in ("client_health_passed", "same_final_cold_boot", "configuration_unchanged",
        "execution_plane_unchanged", "firewall_rules_unchanged", "original_and_installed_artifacts_verified",
        "no_pending_rollback_or_canary", "no_task_temporary_directory"))
    assert final_data["active_component_sha256"] == {n: c["rust"]["sha256"] for n, c in manifest["components"].items()}
    assert not final_data["firmware_flashed"]
    transport = read(device / "components/rpcd/05-r89/transport-recovery.json")
    assert transport["ssh_exit"] == 255 and transport["validated_workloads"] == 18
    assert transport["raw_archive_sha256"] == sha(device / "components/rpcd/05-r89/raw.tar.gz")
    assert transport["original_run_log_sha256"] == sha(device / "components/rpcd/05-r89/run.log")
    gate = read(device / "recovery-01/gate.json")
    install = read(device / "install.json")
    hints_failure = device / "host-hints-live-failed-01"
    hints_download = verified_files(hints_failure / "raw", hints_failure / "raw.sha256")
    hints_archive = verified_archive(hints_failure / "raw.tar.gz", hints_failure / "raw")
    assert "sleep: invalid number '0.1'" in (hints_failure / "driver.log").read_text()
    assert read(hints_failure / "cleanup.json")["removed"]
    http_failure = device / "http-live-pair-failed-01"
    http_cleanup = read(http_failure / "cleanup.json")
    assert http_cleanup["empty_verified"] and http_cleanup["removed"]
    assert http_cleanup["session_destroy_returned_success_without_data"]
    assert read(device / "http-live-pair/session-cleanup.json")["destroy_succeeded"]
    output["deployment"] = {"schema": 1, "status": "accepted", "source_commit": canonical["source_commit"],
        "recovery": {k: gate[k] for k in ("offline_backup_verified", "configuration_matches_backup", "archives",
            "recovery_image_sha256", "retained_on_device", "automatic_rollback_seconds", "candidate_archive_sha256",
            "candidate_manifest_sha256", "canonical_required_gates")}, "installation": install, "final": final_data,
        "cold_windows": [{k: row[k] for k in ("window", "first_ssh_s", "health_confirmed_s", "successful")}
                         for row in output["whole_system"]["windows"]],
        "collector_incidents": [{"case": "C deleted udebug mapping", "action": "Retained failed capture; record deleted mappings separately and collect only openable file pages."},
                                  {"case": "rpcd run 05-r89 SSH timeout", **transport},
                                  {"case": "HostHints fractional sleep unsupported by exact device",
                                   "action": "Failed before any HostHints call; preserved and verified failure files, removed only its owned directory, then passed three exact JSON pairs with bounded integer sleeps.",
                                   "failure_log_sha256": sha(hints_failure / "driver.log"), **hints_download, **hints_archive},
                                  {"case": "Live HTTP setup parsed an empty successful ubus status as JSON",
                                   "action": "No HTTP workload ran; session destroy succeeded. Preserved failure log and verified empty owned directory before removal. Allow empty successful grant/destroy replies; create still requires JSON.",
                                   "failure_log_sha256": sha(device / "http-live-pair.log")}],
        "scope": "Exact nine-component runtime accepted; known differences and finite performance limits remain explicit."}
    output["provenance"] = {"schema": 1, "runtime_source_commit": canonical["source_commit"],
        "baseline_source_commit": historical["source_commit"], "analyzer_sha256": sha(Path(__file__)),
        "formal_validation_analyzer_sha256": sha(Path(formal.__file__)),
        "wireless_analyzer_sha256": sha(Path(wireless.__file__)),
        "final_attestation_sha256": sha(final / "summary.json"),
        "private_root_required": True, "raw_data_published": False,
        "note": "Tooling and documentation may have later commits; deployed binaries remain pinned to the runtime commit."}
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("private_root", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--history", type=Path, required=True)
    p.add_argument("--final", type=Path, required=True)
    a = p.parse_args()
    assert not a.output.exists(), "refusing to mix evidence releases"
    output = derive(a.private_root, a.history, a.final)
    a.output.mkdir(parents=True)
    for name, value in output.items():
        path = a.output / (name + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"accepted": True, "derived_files": len(output), "required_gates": 68,
                      "component_measurements": sum(len(v["runs"]) for k, v in output.items() if k.startswith("components/"))}))


if __name__ == "__main__":
    main()
