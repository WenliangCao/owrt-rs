#!/usr/bin/env python3
"""Recompute derived C1/Rust/C2 metrics from verified private trial records."""
import argparse
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import statistics
import tarfile

WINDOWS = ("stock-1", "rust-1", "stock-2")
LIVE = ("network", "rpcd", "procd", "log", "uci", "fw4", "http-static", "http-jsonrpc", "mixed-total")


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def timing(d):
    n = d["successful"]
    raw = d["latency_ns"]
    assert d["errors"] == 0 and len(raw) == n and n > 0
    assert all(type(x) is int and x >= 0 for x in raw)
    ordered = sorted(raw)
    # Native Rust uses round-half-up for positive ranks; the Python LAN
    # client uses Python's round-to-even. Preserve each recorded definition.
    def rank(q):
        position = (n - 1) * (q / 100)
        return math.floor(position + 0.5) if "mean_us" in d else round(position)
    derived = {"mean_us": statistics.mean(raw) / 1000,
               **{f"p{q}_us": ordered[rank(q)] / 1000 for q in (50, 95, 99)},
               "ops_per_s": n / d["wall_s"]}
    for key, value in derived.items():
        stored = d.get(key, d.get(key.replace("_us", "_ms"), 0) * 1000)
        assert math.isclose(value, stored, rel_tol=1e-9, abs_tol=1e-6), key
    return derived


def clock_delta(before, after):
    assert (before["pid"], before["start_ticks"]) == (after["pid"], after["start_ticks"])
    delta = after["process_cpu_ns"] - before["process_cpu_ns"]
    assert delta >= 0
    return delta


def native(d, roles, mixed=False, command=False):
    t = timing(d)
    count = d["successful"]
    if mixed:
        count = mixed
        t = {"ops_per_s": count / d["wall_s"]}
    cpu = {}
    reaped = 0
    assert {x["pid"] for x in d["daemon_cpu"]} == set(roles)
    for row in d["daemon_cpu"]:
        delta = clock_delta(row["before"], row["after"])
        assert delta == row["cpu_clock_ns"]
        cpu[roles[row["pid"]] + "_cpu_us"] = delta / 1000 / count
        reaped += row["child_cpu_s"] * 1e6 / count
    caller = clock_delta(d["client_before"], d["client_after"])
    assert caller == d["client_cpu_clock_ns"]
    child = 0
    for field in ("rusage_children_user_us", "rusage_children_system_us"):
        delta = d["client_after"][field] - d["client_before"][field]
        assert delta >= 0
        child += delta
    own = sum(cpu.values())
    return {**t, **cpu, "count": count, "daemon_cpu_us": own,
            "command_tree_cpu_us": child / count if command else 0,
            "control_accounted_cpu_us": own + (child / count if command else 0),
            "driver_cpu_us": caller / 1000 / count + (child / count if mixed else 0),
            "daemon_reaped_child_tick_cpu_us": reaped}


def system_cost(before, after, count):
    hz = before["clock_ticks_per_second"]
    assert hz == after["clock_ticks_per_second"]
    delta = [a - b for b, a in zip(before["system_cpu_ticks"][:8], after["system_cpu_ticks"][:8])]
    assert len(delta) == 8 and all(x >= 0 for x in delta)
    busy = sum(delta[i] for i in (0, 1, 2, 5, 6, 7))
    return {"system_busy_cpu_us": busy / hz * 1e6 / count,
            "system_busy_pct": 100 * busy / sum(delta) if sum(delta) else 0,
            "system_boundary_wall_s": after["uptime_s"] - before["uptime_s"]}


def lan(d, server, roles):
    row = timing(d)
    n = server["successful_including_warmup"]
    before = {p["pid"]: p for p in server["before"]["processes"]}
    assert set(before) == set(roles)
    assert {p["pid"] for p in server["after"]["processes"]} == set(roles)
    own = 0
    for proc in server["after"]["processes"]:
        cpu = clock_delta(before[proc["pid"]], proc) / 1000 / n
        row[roles[proc["pid"]] + "_cpu_us"] = cpu
        own += cpu
    row.update(system_cost(server["before"], server["after"], n))
    row.update(daemon_cpu_us=own, count=d["successful"], cipher=d["tls_ciphers"], errors=0)
    return row


def verified_directory(out, kind):
    root = (out / kind).resolve()
    files = set()
    for line in (out / (kind + ".sha256")).read_text().splitlines():
        digest, name = line.split(None, 1)
        p = (root / name).resolve()
        assert re.fullmatch(r"[a-f0-9]{64}", digest) and p.is_relative_to(root) and p not in files
        assert sha(p) == digest
        files.add(p)
    assert files == {p.resolve() for p in root.rglob("*") if p.is_file()}
    with tarfile.open(out / (kind + ".tar.gz")) as tar:
        archived = set()
        for member in tar:
            if member.isfile():
                p = (root / member.name).resolve()
                assert p in files and p not in archived
                assert hashlib.sha256(tar.extractfile(member).read()).hexdigest() == sha(p)
                archived.add(p)
        assert archived == files
    return len(files)


def stats(values):
    return {"median": statistics.median(values), "min": min(values), "max": max(values), "rounds": values}


def memory_accounting(memory):
    file_lru = memory["Active(file)"] + memory["Inactive(file)"]
    slab = memory["SReclaimable"]
    # Observed half-cache accounting, with 4 KiB page rounding. This is an
    # empirical accounting check for this image, not a universal RAM model.
    predicted = memory["MemFree"] - 24576 + file_lru - (file_lru // 8) * 4 + slab - (slab // 8) * 4
    return {"file_LRU": file_lru,
            "used_excluding_free_file_LRU_reclaimable_slab": memory["MemTotal"] - memory["MemFree"] - file_lru - slab,
            "available_model_error_kib": predicted - memory["MemAvailable"]}


def idle_resources(samples, roles):
    values = {}
    for sample in samples:
        for key in ("MemTotal", "MemFree", "MemAvailable", "Cached", "Buffers", "Active(file)", "Inactive(file)",
                    "Mapped", "AnonPages", "Shmem", "Slab", "SReclaimable", "SUnreclaim"):
            values.setdefault(key, []).append(sample["memory_kib"][key])
        for key, value in memory_accounting(sample["memory_kib"]).items():
            values.setdefault(key, []).append(value)
        values.setdefault("summed_daemon_RSS", []).append(sum(p["VmRSS"] for p in sample["processes"]))
        values.setdefault("temperature_millic", []).append(sample["temperature_millic"])
        assert {p["pid"] for p in sample["processes"]} == set(roles)
        for proc in sample["processes"]:
            for key in ("VmRSS", "RssAnon", "RssFile", "RssShmem", "fds", "Threads"):
                values.setdefault(roles[proc["pid"]] + "/" + key, []).append(proc[key])
    result = {key: stats(value) for key, value in values.items()}
    result["sample_count"] = len(samples)
    result["available_model_exact_samples"] = values["available_model_error_kib"].count(0)
    result["system_idle_busy_pct"] = system_cost(samples[0], samples[-1], 1)["system_busy_pct"]
    before = {p["pid"]: p for p in samples[0]["processes"]}
    cpu_s = sum(clock_delta(before[p["pid"]], p) for p in samples[-1]["processes"]) / 1e9
    machine_s = sum(a - b for a, b in zip(samples[-1]["system_cpu_ticks"][:8], samples[0]["system_cpu_ticks"][:8])) / samples[0]["clock_ticks_per_second"]
    result["daemon_idle_machine_capacity_pct"] = 100 * cpu_s / machine_s
    result["daemon_idle_one_core_pct"] = 100 * cpu_s / (samples[-1]["uptime_s"] - samples[0]["uptime_s"])
    return result


def tls_tail(rows):
    for row in rows: timing(row)
    raw = [x for row in rows for x in row["latency_ns"]]
    return {"requests": len(raw), "over_12ms": sum(x > 12000000 for x in raw),
            "pooled_median_us": statistics.median(raw) / 1000,
            "round_p99_us": [row["p99_ms"] * 1000 for row in rows],
            "ciphers": sorted({cipher for row in rows for cipher in row["tls_ciphers"]})}


def normalize_recorded_fw4(text):
    # Retrospective comparison of the stored reference renders only. The
    # future device gate is fw4_output.rs, exercised against these same files.
    pattern = r"(define \w+_subnets = \{ )([^}\n]*)( \})"
    def ordered(match):
        members = [x.strip() for x in match[2].split(',')]
        for member in members: ipaddress.ip_network(member, strict=False)
        return match[1] + ', '.join(sorted(members)) + match[3]
    return re.sub(pattern, ordered, text)


def storage(path):
    rows = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) == 6 and fields[-1] in ("/overlay", "/tmp"):
            rows[fields[-1]] = dict(zip(("total_kib", "used_kib", "available_kib"), map(int, fields[1:4])))
    assert set(rows) == {"/overlay", "/tmp"}
    return rows


def derive(base, allow_missing_c2=False):
    assert (base / "RESTORED").is_file()
    complete = (base / "COMPLETE").is_file()
    if not complete:
        assert allow_missing_c2 and (base / "FINISHED_WITH_INVALID_C2").is_file()
        assert not (base / "windows/stock-2/measurements/COMPLETE").exists()
    window_names = WINDOWS if complete else WINDOWS[:2]
    restored = read(base / "restoration.json")
    assert all(restored[key] is True for key in (
        "stock_verified", "configuration_matches_initial", "rc_targets_match_initial",
        "package_versions_match_initial", "prior_bundle_all_files_match",
        "prior_installed_binaries_verified", "temporary_service_and_config_removed",
        "trial_and_boot_canaries_removed"))
    assert restored["firmware_flashed"] is False
    plan = read(base / "frozen-plan.json")
    manifest = read(base / "bundle/manifest.json")
    canonical = read(base / "bundle/canonical-manifest.json")
    core = read(base / "bundle/canonical-core-manifest.json")
    assert canonical["source_commit"] == core["source_commit"] == plan["runtime_source"]
    assert sha(base / "bundle/canonical-manifest.json") == core["image_manifest_sha256"]
    formal_binaries = {**canonical["binary_sha256"], **core["binary_sha256"]}
    for component in manifest["components"].values():
        assert component["rust"]["sha256"] == formal_binaries[component["rust"]["binary"]]
    result = {"schema": 1, "status": "complete" if complete else "partial", "windows": {}, "comparisons": {}, "source_sha256": {},
              "canonical_source": canonical["source_commit"], "runtime_elf_sha256": formal_binaries,
              "canonical_manifest_sha256": sha(base / "bundle/canonical-manifest.json"),
              "core_manifest_sha256": sha(base / "bundle/canonical-core-manifest.json")}
    result["provenance"] = {
        "frozen_plan_sha256": sha(base / "frozen-plan.json"),
        "measurement_tool_sha256": plan["tool_sha256"],
        "deployment_archive_sha256": sha(base / "deployment.tar.gz"),
        "canonical_run": 36491554447,
        "legacy_bundle_labels": {key: manifest[key] for key in ("canonical_build", "fix_commit", "validation_tools_commit")},
        "legacy_component_builders": sorted({c["rust"]["builder"] for c in manifest["components"].values()}),
        "identity_authority": "Actual nine running hashes, the two canonical manifests and frozen measurement-tool hashes. Legacy labels in the template manifest are not current build evidence; the original archive is preserved.",
        "analysis_tool_sha256": sha(Path(__file__)),
    }
    result["restoration"] = {k: v for k, v in restored.items() if isinstance(v, bool)}
    result["artifact_bytes"] = {
        side: {name: component[side]["bytes"] for name, component in manifest["components"].items()}
        for side in ("original", "rust")}
    result["artifact_bytes"]["scope"] = "Executable or wrapper files only; original shared libraries/interpreted code, compression, package contents and retained recovery copies are not included. Not firmware or flash savings."
    boots = set()
    reference_config = None
    normalized_rules = []
    for name in window_names:
        window = base / "windows" / name
        out = window / "measurements"
        assert (out / "COMPLETE").is_file()
        health = read(window / "health.json")
        assert health["status"] == "healthy" and health["pre"]["boot_id"] != health["post"]["boot_id"]
        boot = health["post"]["boot_id"]
        assert boot not in boots
        boots.add(boot)
        boot_events = [json.loads(line) for line in (window / "boot.log").read_text().splitlines() if line.startswith('{')]
        held = [event for event in boot_events if event.get("event") == "health_pass"]
        assert held[-1]["continuous_s"] >= 180
        assert health["elapsed_s"] - held[-1]["elapsed_s"] >= 30
        if name == "rust-1": assert any(event.get("event") == "confirmed" for event in boot_events)
        settings = read(out / "settings.json")
        for key in ("iterations", "repeats", "idle", "client_iterations", "cycle_count"):
            assert settings[key] == plan[key]
        for record in (health["post"], read(out / "health-before.json"), read(out / "health-after.json")):
            assert record["boot_id"] == boot and len(record["verified_components"]) == 9
            for key in ("client_dhcp", "local_http_https", "dns_ipv4", "dns_ipv6", "router_internet_https", "watchdog_running"):
                assert record[key] is True
        config = (out / "config-before.sha256").read_bytes()
        assert config == (out / "config-after.sha256").read_bytes()
        if reference_config is None: reference_config = config
        assert config == reference_config == (base / "recovery/config-before.sha256").read_bytes()
        for period in ("before", "after"):
            text = (out / f"nft-ruleset-{period}.txt").read_text()
            text = re.sub(r"packets \d+ bytes \d+", "packets N bytes N", text)
            normalized_rules.append(re.sub(r"(expires|timeout) [0-9smhd]+", r"\1 T", text))
        ids = [line.split() for line in (out / "running-hashes.txt").read_text().splitlines()]
        assert {row[0] for row in ids} == set(manifest["components"])
        side = "rust" if name == "rust-1" else "original"
        for component, _, digest in ids:
            assert digest == manifest["components"][component][side]["sha256"]
        roles = {int(pid): component for component, pid, _ in ids if pid != "-"}
        records = {}
        verified = sum(verified_directory(out, kind) for kind in ("live", "cycle"))
        assert (out / "live/benchmark-sha256.txt").read_text().split()[0] == manifest["tools"]["owrt-benchmark"]["sha256"]
        for kind in ("live", "cycle"):
            assert (out / kind / "running-hashes.txt").read_bytes() == (out / kind / "final-running-hashes.txt").read_bytes() == (out / "running-hashes.txt").read_bytes()
        for r in range(1, plan["repeats"] + 1):
            for lane in LIVE:
                d = read(out / "live" / f"{r}-{lane}.json")
                mixed = lane == "mixed-total"
                if mixed:
                    for member in ("procd", "network", "rpcd", "http"):
                        inner = read(out / "live" / f"{r}-mixed-{member}.json")
                        timing(inner)
                        assert inner["successful"] == plan["iterations"]
                expected = 1 if mixed else 100 if lane == "uci" else 30 if lane == "fw4" else plan["iterations"]
                assert d["successful"] == expected
                row = native(d, roles, 4 * plan["iterations"] if mixed else False, lane in ("uci", "fw4"))
                row.update(system_cost(read(out / "live" / f"{r}-{lane}-system-before.json"),
                                       read(out / "live" / f"{r}-{lane}-system-after.json"),
                                       row["count"] + (0 if mixed else d["warmup"])))
                records.setdefault("live/" + lane, []).append(row)
            for lane in ("unchanged", "cycle"):
                d = read(out / "cycle" / f"{r}-{lane}.json")
                assert d["successful"] == (20 if lane == "unchanged" else plan["cycle_count"])
                row = native(d, roles, command=True)
                row.update(system_cost(read(out / "cycle" / f"{r}-{lane}-before.json"),
                                       read(out / "cycle" / f"{r}-{lane}-after.json"), d["successful"] + d["warmup"]))
                records.setdefault("config/" + lane, []).append(row)
            for path in sorted(out.glob(f"lan-{r}-*.json")):
                if path.name.endswith("-server.json"): continue
                d = read(path)
                assert d["successful"] == (100 if "fresh" in path.name else plan["client_iterations"])
                server = read(path.with_name(path.stem + "-server.json"))
                row = lan(d, server, roles)
                records.setdefault("lan/" + path.stem.split("-", 2)[2], []).append(row)
        deliveries = [int(x) for x in (out / "cycle/deliveries.txt").read_text().splitlines()]
        expected_cycles = plan["repeats"] * (plan["cycle_count"] + 1)
        assert deliveries == list(range(1, expected_cycles + 1))
        journal = [json.loads(line) for line in (out / "cycle/config-cycle.jsonl").read_text().splitlines()]
        assert [x["value"] for x in journal] == deliveries
        assert read(out / "cycle/service-after.json") == {}
        stage = {}
        for r in range(plan["repeats"]):
            rows = journal[r * (plan["cycle_count"] + 1) + 1:(r + 1) * (plan["cycle_count"] + 1)]
            for key in ("commit_ns", "dispatch_ns", "completion_ns"):
                stage.setdefault(key.replace("_ns", "_us"), []).append(statistics.mean(x[key] for x in rows) / 1000)
        resources = {}
        for period in ("before", "after"):
            samples = [json.loads(line) for line in (out / "live" / f"idle-{period}.jsonl").read_text().splitlines()]
            assert len(samples) == plan["idle"] + 1
            resources[period] = idle_resources(samples, roles)
        summaries = {lane: {key: stats([row[key] for row in rows]) for key, value in rows[0].items()
                           if isinstance(value, (int, float))} for lane, rows in records.items()}
        expected_lan = {"lan/" + lane for lane in ("http-static-c1", "https-static-c1", "https-static-c4", "https-rpc-c1", "https-rpc-c4", "https-fresh-c1", "https-common-c1")}
        assert set(records) == {"live/" + lane for lane in LIVE} | {"config/unchanged", "config/cycle"} | expected_lan
        assert all(len(rows) == plan["repeats"] for rows in records.values())
        result["windows"][name] = {"rows": records, "summaries": summaries, "resources": resources,
                                  "config_stages": {k: stats(v) for k, v in stage.items()},
                                  "verified_downloaded_files": verified, "verified_config_deliveries": len(deliveries),
                                  "first_ssh_s": health["first_ssh_s"], "boot_health_completed_s": health["elapsed_s"]}
        result["windows"][name]["storage"] = {period: storage(out / f"storage-{period}.txt") for period in ("before", "after")}
        result["windows"][name]["measured_successful_operations"] = sum(row["count"] for rows in records.values() for row in rows)
        result["windows"][name]["fixed_native_accounted_cpu_s"] = sum(row["control_accounted_cpu_us"] * row["count"] / 1e6
            for lane, rows in records.items() if not lane.startswith("lan/") for row in rows)
        result["source_sha256"][name] = {str(p.relative_to(window)): sha(p) for p in window.rglob("*") if p.is_file()}
    result["nft_rules_equal_after_counter_timeout_normalization"] = len(set(normalized_rules)) == 1
    for baseline in (name for name in window_names if name != "rust-1"):
        comparison = {}
        for lane, values in result["windows"]["rust-1"]["summaries"].items():
            comparison[lane] = {}
            for metric, value in values.items():
                candidate = value["median"]
                original = result["windows"][baseline]["summaries"][lane][metric]["median"]
                comparison[lane][metric] = {"baseline": original, "rust": candidate,
                    "difference": candidate - original, "percent": (candidate / original - 1) * 100 if original else None}
        result["comparisons"][baseline] = comparison
    excluded = []
    for window in sorted((base / "windows").glob("*-failed-*")):
        assert not (window / "measurements/COMPLETE").exists()
        health = read(window / "health.json")
        boots.add(health["post"]["boot_id"])
        verified = verified_directory(window / "measurements", "live")
        assert "benchmark INVALID: child stdout failed byte validation" in (window / "measurements/live.log").read_text()
        out = window / "measurements"
        ids = [line.split() for line in (out / "running-hashes.txt").read_text().splitlines()]
        assert {c: h for c, _, h in ids} == {c: v["original"]["sha256"] for c, v in manifest["components"].items()}
        assert (out / "live/running-hashes.txt").read_bytes() == (out / "running-hashes.txt").read_bytes()
        assert read(out / "health-before.json")["boot_id"] == health["post"]["boot_id"] == (out / "live/boot-id.txt").read_text().strip()
        roles = {int(pid): component for component, pid, _ in ids if pid != "-"}
        observations = {}
        # Preserve every fully recorded lane before the failure as explicitly
        # partial evidence. Never merge these into a complete C2 or total score.
        for path in sorted(out.glob("lan-*.json")):
            if path.name.endswith("-server.json"): continue
            d = read(path)
            assert d["successful"] == (100 if "fresh" in path.name else plan["client_iterations"])
            row = lan(d, read(path.with_name(path.stem + "-server.json")), roles)
            observations.setdefault("lan/" + path.stem.split("-", 2)[2], []).append(row)
        for r in range(1, plan["repeats"] + 1):
            for lane in LIVE:
                path = out / "live" / f"{r}-{lane}.json"
                if not path.is_file() or path.stat().st_size == 0: continue
                assert lane != "mixed-total", "a later failure needs mixed member validation too"
                d = read(path)
                assert d["successful"] == (100 if lane == "uci" else 30 if lane == "fw4" else plan["iterations"])
                row = native(d, roles, command=lane in ("uci", "fw4"))
                observations.setdefault("live/" + lane, []).append(row)
        excluded.append({"name": window.name, "reason": "fw4 child stdout failed exact byte validation",
                         "actual_failing_child_stdout_retained": False,
                         "verified_downloaded_files": verified,
                         "partial_observations": observations,
                         "source_sha256": {str(p.relative_to(window)): sha(p) for p in window.rglob("*") if p.is_file()}})
    if excluded:
        recovered = base / "restoration-after-failed-c2"
        assert read(recovered / "restoration.json")["stock_verified"]
        boots.add(read(recovered / "final-health.json")["boot_id"])
        result["retry"] = read(base / "c2-retry-decision.json")
        result["failure_diagnostic"] = read(base / "c2-failure-diagnostic/repeated/diagnostic-analysis.json")
    result["excluded_windows"] = excluded
    review = {"windows": {}, "scope": "Reanalysis of unchanged historical samples; no new device run", "power_cycles_tested": 0}
    normalized = []
    for name in (*window_names, *(w["name"] for w in excluded)):
        out = base / "windows" / name / "measurements"
        ids = [line.split() for line in (out / "running-hashes.txt").read_text().splitlines()]
        roles = {int(pid): c for c, pid, _ in ids if pid != "-"}
        resources = {}
        for period in ("before", "after"):
            path = out / "live" / f"idle-{period}.jsonl"
            if path.is_file():
                samples = [json.loads(line) for line in path.read_text().splitlines()]
                assert len(samples) == plan["idle"] + 1
                resources[period] = {
                    key: {k: v for k, v in value.items() if k != "rounds"} if isinstance(value, dict) else value
                    for key, value in idle_resources(samples, roles).items()}
        tail = {lane: tls_tail([read(out / f"lan-{r}-{lane}.json") for r in range(1, plan["repeats"] + 1)])
                for lane in ("https-common-c1", "https-static-c1")}
        network = read(out / "live/network.json")
        lan_status = next(i for i in network["interface"] if i["interface"] == "lan")
        def address_class(address):
            return "ULA" if ipaddress.IPv6Address(address) in ipaddress.IPv6Network("fc00::/7") else "GUA"
        order = [f"{address_class(p['address'])}/{p['mask']}" for p in lan_status["ipv6-prefix-assignment"]]
        assert not lan_status["ipv6-address"]
        first = lan_status["ipv6-prefix-assignment"][0]["local-address"]["address"]
        printed = normalize_recorded_fw4((out / "live/expected-fw4.bytes").read_text())
        normalized.append(printed)
        review["windows"][name] = {"resources": resources, "tls_tail": tail, "lan_prefix_order": order,
                                   "network_get_ipaddr6_fallback_class": address_class(first),
                                   "normalized_stored_fw4_sha256": hashlib.sha256(printed.encode()).hexdigest()}
    review["stored_fw4_references_equal_after_subnet_ordering"] = len(set(normalized)) == 1
    review["idle_samples"] = sum(r["sample_count"] for w in review["windows"].values() for r in w["resources"].values())
    review["available_model_exact_samples"] = sum(r["available_model_exact_samples"] for w in review["windows"].values() for r in w["resources"].values())
    review["memory_model"] = "F - 24576 + L - 4*floor(L/8) + S - 4*floor(S/8), KiB; L=Active(file)+Inactive(file), S=SReclaimable; 4 KiB pages"
    review["partial_c_mean_drift_pct"] = {w["name"]: {
        lane: (statistics.median(row["mean_us"] for row in rows) / result["windows"]["stock-1"]["summaries"][lane]["mean_us"]["median"] - 1) * 100
        for lane, rows in w["partial_observations"].items() if lane.startswith("live/")} for w in excluded}
    result["review"] = review
    result["observed_new_boots"] = len(boots)
    if not complete: assert len(excluded) == 2
    result["valid_windows"] = len(window_names)
    result["measured_successful_operations"] = sum(w["measured_successful_operations"] for w in result["windows"].values())
    result["source_sha256"]["trial"] = {name: sha(base / name) for name in (
        "frozen-plan.json", "recovery-gate.json", "execute.log", "restoration.json", "final-health.json",
        "final-packages.txt", "final-rc-targets.txt", "final-mounts.txt", "final-storage.txt")}
    for name in ("retry-c2.log", "c2-retry-decision.json", "final-audit.json"):
        if (base / name).is_file(): result["source_sha256"]["trial"][name] = sha(base / name)
    if (base / "final-audit.json").is_file():
        audit = read(base / "final-audit.json")
        result["final_audit"] = audit["checks"]
        result["final_audit_at"] = audit["at"]
        result["verified_original_root_files"] = audit["root_files_verified"]
        assert all(value is True for value in result["final_audit"].values())
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("private_root", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--allow-missing-c2", action="store_true",
                   help="Explicitly report valid C1/Rust and both preserved invalid C2 attempts; never mark the trial complete")
    a = p.parse_args()
    data = derive(a.private_root, a.allow_missing_c2)
    a.output.write_text(json.dumps(data, indent=2) + "\n")
    print("Verified", data["valid_windows"], "valid windows across", data["observed_new_boots"], "observed new boots; status", data["status"], "; derived",
          sum(len(w["rows"]) for w in data["windows"].values()), "window/lane groups")


if __name__ == "__main__":
    main()
