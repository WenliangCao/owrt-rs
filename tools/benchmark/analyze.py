#!/usr/bin/env python3
"""Derive an allowlisted, publishable summary from private R84 measurements.

No response bodies, configuration hashes, addresses, tokens or device logs are
copied to the output. By default all four boots and all 72 component runs must
be complete. --partial is for private progress inspection only.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import statistics

COMPONENT_WORK = {
    "uci": ("export_network", "export_64", "set_commit_get"),
    "reload-config": ("unchanged_config",),
    "fw4": ("print", "check"),
    "logd": ("syslog_128", "log_read_100"),
    "httpd": ("static_16k", "cgi", "jsonrpc"),
    "rpcd": ("uci_configs", "uci_get_network", "file_stat", "session_access"),
    "procd": ("service_list_32", "system_info"),
    "ubusd": ("lookup", "lookup_all_64", "invoke"),
    "netifd": ("interface_dump", "lan_status", "device_status", "wireless_status"),
}
ORDER = ("c", "rs", "rs", "c", "rs", "c", "c", "rs")
WINDOWS = ("rust-1", "stock-1", "stock-2", "rust-2")
SERIAL = ("network", "rpcd", "procd", "log", "uci", "fw4", "http-static", "http-jsonrpc")
MEMORY_KEYS = ("VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM", "VmPTE", "Threads", "fds")


def read_json(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stats(values):
    values = list(values)
    assert values and all(math.isfinite(v) for v in values)
    return {"n": len(values), "median": statistics.median(values),
            "mean": statistics.mean(values), "min": min(values), "max": max(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0}


def native(path):
    data = read_json(path)
    n = data["successful"]
    assert n > 0 and data["errors"] == 0 and len(data["latency_ns"]) == n, path
    assert data["wall_s"] > 0
    assert math.isclose(data["mean_us"], statistics.mean(data["latency_ns"]) / 1000,
                        rel_tol=1e-8, abs_tol=1e-6), path
    for process in data["daemon_cpu"]:
        assert process["before"]["start_ticks"] == process["after"]["start_ticks"], path
        assert process["cpu_s"] >= 0 and process["child_cpu_s"] >= 0, path
    return data


def timing(data):
    return {key: data[key] for key in ("successful", "wall_s", "ops_per_s", "mean_us",
                                       "p50_us", "p95_us", "p99_us")}


def memory(process):
    return {key: process[key] for key in MEMORY_KEYS}


def components(root, manifest, partial):
    rows, residents, sources, missing = [], [], [], []
    for component, workloads in COMPONENT_WORK.items():
        for index, implementation in enumerate(ORDER, 1):
            name = f"{component}/{index:02d}-{implementation}"
            run = root / "components" / name
            if not (run / "COMPLETE").exists():
                missing.append("component:" + name)
                continue
            raw = run / "raw"
            assert (raw / "COMPLETE").exists(), run
            meta = read_json(raw / "meta.json")
            assert (meta["component"], meta["implementation"], meta["iterations"]) == (component, implementation, 10000)
            expected = manifest["components"][component]["rust" if implementation == "rs" else "original"]["sha256"]
            assert (raw / "binary-sha256.txt").read_text().split()[0] == expected
            assert (raw / "benchmark-sha256.txt").read_text().split()[0] == manifest["tools"]["owrt-benchmark"]["sha256"]
            sources.append({"run": name, "archive_sha256": digest(run / "raw.tar.gz"),
                            "subject_sha256": expected, "kernel": (raw / "kernel.txt").read_text().strip()})
            side = "rust" if implementation == "rs" else "stock"
            subject = meta["subject_pid"]
            for workload in workloads:
                data = native(raw / (workload + ".json"))
                n = data["successful"]
                expected_count = (100 if component == "fw4" else
                                  500 if component in ("uci", "reload-config") or workload == "cgi" else
                                  100000 if workload == "syslog_128" else 10000)
                assert n == expected_count, (name, workload, n)
                one_shot = subject is None
                own = next((p for p in data["daemon_cpu"] if p["pid"] == subject), None)
                assert one_shot or own is not None
                subject_cpu = data["child_cpu_s"] if one_shot else own["cpu_s"] + own["child_cpu_s"]
                dependencies = sum(p["cpu_s"] for p in data["daemon_cpu"] if p["pid"] != subject)
                rows.append({"study": "component", "component": component, "workload": workload,
                             "side": side, "run": name, **timing(data),
                             "subject_cpu_us_per_op": subject_cpu * 1e6 / n,
                             "dependency_cpu_us_per_op": dependencies * 1e6 / n,
                             "client_cpu_us_per_op": data["client_cpu_s"] * 1e6 / n,
                             "clock_ticks_per_second": data["clock_ticks_per_second"]})
            if subject is not None:
                sample = read_json(raw / "resident.json")
                process = next(p for p in sample["processes"] if p["pid"] == subject)
                residents.append({"component": component, "side": side, "run": name,
                                  **memory(process), "temperature_millic": sample["temperature_millic"]})
    assert partial or not missing, missing
    return rows, residents, sources, missing


def idle(path, names):
    samples = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(samples) == 121
    before, after = samples[0], samples[-1]
    elapsed = after["uptime_s"] - before["uptime_s"]
    assert 119 <= elapsed <= 122
    hz = before["clock_ticks_per_second"]
    ticks = [b - a for a, b in zip(before["system_cpu_ticks"], after["system_cpu_ticks"])]
    total = sum(ticks[:8])
    result = {"samples": len(samples), "elapsed_s": elapsed,
              "system_busy_capacity_pct": (total - ticks[3] - ticks[4]) / total * 100,
              "memory_available_kib": stats(s["memory_kib"]["MemAvailable"] for s in samples),
              "summed_daemon_rss_kib": stats(sum(p["VmRSS"] for p in s["processes"]) for s in samples),
              "summed_daemon_anon_kib": stats(sum(p["RssAnon"] for p in s["processes"]) for s in samples),
              "temperature_millic": stats(s["temperature_millic"] for s in samples), "processes": {}}
    total_daemon_ticks = 0
    for pid, name in names.items():
        group = [next(p for p in s["processes"] if p["pid"] == pid) for s in samples]
        assert group[0]["start_ticks"] == group[-1]["start_ticks"]
        cpu_ticks = group[-1]["cpu_ticks"] - group[0]["cpu_ticks"]
        total_daemon_ticks += cpu_ticks
        result["processes"][name] = {**{key: stats(p[key] for p in group) for key in MEMORY_KEYS},
                                     "cpu_one_core_pct": cpu_ticks / hz / elapsed * 100}
    result["daemon_cpu_one_core_pct"] = total_daemon_ticks / hz / elapsed * 100
    return result


def windows(root, manifest, partial):
    rows, resources, tls_rows, sources, missing = [], [], [], [], []
    configs, execution_planes = [], []
    for name in WINDOWS:
        window = root / "windows" / name
        out = window / "measurements"
        if not (out / "COMPLETE").exists():
            missing.append("window:" + name)
            continue
        raw = out / "live"
        assert (raw / "COMPLETE").exists()
        meta = read_json(raw / "meta.json")
        side = name.split("-")[0]
        assert meta == {"mode": side, "iterations": 10000, "repeats": 5, "idle_seconds": 120, "mixed_lanes": 4}
        assert (raw / "benchmark-sha256.txt").read_text().split()[0] == manifest["tools"]["owrt-benchmark"]["sha256"]
        assert (raw / "config-before.sha256").read_bytes() == (raw / "config-after.sha256").read_bytes()
        assert (raw / "running-hashes.txt").read_bytes() == (raw / "final-running-hashes.txt").read_bytes()
        configs.append((raw / "config-before.sha256").read_bytes())
        execution_planes.append({(v[0], v[2]) for line in (raw / "execution-plane.txt").read_text().splitlines()
                                 if (v := line.split())})
        names = {}
        for line in (raw / "running-hashes.txt").read_text().splitlines():
            component, pid, actual = line.split()
            assert actual == manifest["components"][component]["rust" if side == "rust" else "original"]["sha256"]
            if pid != "-":
                names[int(pid)] = component
        assert set(names.values()) == {"procd", "ubusd", "netifd", "rpcd", "logd", "httpd"}
        health = read_json(window / "health.json")
        assert health["status"] == "healthy" and health["post"]["mode"] == side
        assert (raw / "boot-id.txt").read_text().strip() == health["post"]["boot_id"]
        sources.append({"run": name, "archive_sha256": digest(out / "live.tar.gz"),
                        "kernel": (raw / "kernel.txt").read_text().strip()})
        total_ops, total_server_cpu = 0, 0
        for repeat in range(1, 6):
            for workload in SERIAL:
                data = native(raw / f"{repeat}-{workload}.json")
                n = 100 if workload == "uci" else 30 if workload == "fw4" else 10000
                assert data["successful"] == n
                program_cpu = data["child_cpu_s"] if workload in ("uci", "fw4") else 0
                server_cpu = sum(p["cpu_s"] for p in data["daemon_cpu"]) + program_cpu
                rows.append({"study": "whole", "component": "all", "workload": workload,
                             "side": side, "run": f"{name}/{repeat}", **timing(data),
                             "server_cpu_us_per_op": server_cpu * 1e6 / n,
                             "client_cpu_us_per_op": data["client_cpu_s"] * 1e6 / n})
                total_ops += n
                total_server_cpu += server_cpu
            # One non-overlapping CPU bracket covers all four concurrent
            # clients. Their individual daemon CPU counters must not be added.
            data = native(raw / f"{repeat}-mixed-total.json")
            assert data["successful"] == 1
            n = 40000
            server_cpu = sum(p["cpu_s"] for p in data["daemon_cpu"])
            rows.append({"study": "whole", "component": "all", "workload": "mixed-total",
                         "side": side, "run": f"{name}/{repeat}", "successful": n,
                         "wall_s": data["wall_s"], "ops_per_s": n / data["wall_s"],
                         "server_cpu_us_per_op": server_cpu * 1e6 / n,
                         "client_cpu_us_per_op": (data["client_cpu_s"] + data["child_cpu_s"]) * 1e6 / n})
            total_ops += n
            total_server_cpu += server_cpu
            for lane in ("procd", "network", "rpcd", "http"):
                lane_data = native(raw / f"{repeat}-mixed-{lane}.json")
                assert lane_data["successful"] == 10000
                rows.append({"study": "mixed-lane", "component": "all", "workload": lane,
                             "side": side, "run": f"{name}/{repeat}", **timing(lane_data)})
        assert total_ops == 500650
        resources.append({"window": name, "side": side, "successful": total_ops,
                          "active_server_cpu_s": total_server_cpu,
                          "first_ssh_s": health["first_ssh_s"],
                          "health_confirmed_s": health["elapsed_s"],
                          "idle_before": idle(raw / "idle-before.jsonl", names),
                          "idle_after": idle(raw / "idle-after.jsonl", names),
                          "raw_live_bytes": sum(p.stat().st_size for p in raw.rglob("*") if p.is_file())})
        prefixes = ("tls", "tls-common") if name.endswith("-2") else ("tls",)
        for prefix in prefixes:
            for connection in ("keepalive", "fresh"):
                for concurrency in (1, 4):
                    label = f"{prefix}-{connection}-c{concurrency}"
                    data = read_json(out / (label + ".json"))
                    assert data["successful"] == len(data["latency_ns"]) == 1000 and data["errors"] == 0
                    assert data["tls_versions"] == ["TLSv1.2"]
                    assert data["request_rate_limit_per_s"] == (20 if connection == "fresh" else None)
                    bracket = read_json(out / (label + "-server.json"))
                    before, after = bracket["before"], bracket["after"]
                    hz = before["clock_ticks_per_second"]
                    cpu = {}
                    for process in before["processes"]:
                        final = next(p for p in after["processes"] if p["pid"] == process["pid"])
                        assert final["start_ticks"] == process["start_ticks"]
                        cpu[names[process["pid"]]] = (final["cpu_ticks"] - process["cpu_ticks"]) / hz
                    count = bracket["successful_including_warmup"]
                    assert count == 1000 + 10 * concurrency
                    tls_rows.append({"study": "tls-common" if prefix == "tls-common" else "tls-default",
                                     "component": "httpd", "workload": f"{connection}-c{concurrency}",
                                     "side": side, "run": name, "successful": 1000,
                                     **{key: data[key] for key in ("wall_s", "ops_per_s", "mean_ms", "p50_ms", "p95_ms", "p99_ms")},
                                     "cpu_bracket_successful": count, "httpd_cpu_us_per_op": cpu["httpd"] * 1e6 / count,
                                     "ciphers": data["tls_ciphers"], "resumed_handshakes": data["resumed_tls_handshakes"]})
    assert partial or not missing, missing
    assert not configs or all(c == configs[0] for c in configs), "configuration drift between boots"
    assert not execution_planes or all(p == execution_planes[0] for p in execution_planes), "execution-plane drift"
    return rows, resources, tls_rows, sources, missing


def summarize(rows, keys):
    groups = defaultdict(list)
    for row in rows:
        groups[tuple(row[key] for key in keys)].append(row)
    result = []
    for group, items in sorted(groups.items()):
        metrics = sorted(set.intersection(*(set(row) for row in items)))
        result.append({**dict(zip(keys, group)), "runs": len(items),
                       "metrics": {metric: stats(row[metric] for row in items) for metric in metrics
                                   if metric not in keys and isinstance(items[0][metric], (int, float))}})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private_root", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--partial", action="store_true")
    args = parser.parse_args()
    manifest = read_json(args.manifest)
    component_rows, residents, component_sources, component_missing = components(args.private_root, manifest, args.partial)
    whole_rows, resources, tls_rows, window_sources, window_missing = windows(args.private_root, manifest, args.partial)
    final_missing = []
    component_root = args.private_root / "components"
    if (component_root / "COMPLETE").exists():
        assert (component_root / "config-before.sha256").read_bytes() == (component_root / "config-after.sha256").read_bytes()
    else:
        final_missing.append("component-host-final-verification")
    final_health = args.private_root / "final-health.json"
    if final_health.exists():
        health = read_json(final_health)
        assert health["mode"] == "rust" and len(health["verified_components"]) == 9
        assert health["boot_id"] == read_json(args.private_root / "windows/rust-2/health.json")["post"]["boot_id"]
    else:
        final_missing.append("final-rust-health")
    assert args.partial or not final_missing, final_missing
    rows = component_rows + whole_rows + tls_rows
    result = {"schema": 1, "status": "partial" if component_missing or window_missing or final_missing else "complete",
              "image": manifest["image"], "benchmark_sha256": manifest["tools"]["owrt-benchmark"]["sha256"],
              "notes": {"aggregation": "median of per-run means; ranges and individual runs retained",
                        "component_cpu": "subject plus waited children; dependencies and client reported separately",
                        "whole_cpu": "six daemon own counters plus one-shot program children; mixed outer interval only",
                        "tls_cpu": "HTTP daemon; entire invocation includes counted warm-up and SSH sampling",
                        "rss": "not PSS/USS; shared mappings can be counted more than once",
                        "idle_after_memory": "includes raw output on tmpfs; use idle-before for main memory comparison",
                        "common_tls": "one boot per implementation; measured after primary samples"},
              "pending": component_missing + window_missing + final_missing,
              "rows": rows, "summaries": summarize(rows, ("study", "component", "workload", "side")),
              "component_residents": residents,
              "component_memory": summarize(residents, ("component", "side")),
              "windows": resources, "sources": component_sources + window_sources,
              "configuration_equal_across_completed_windows": True,
              "execution_plane_equal_across_completed_windows": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"status": result["status"], "component_runs": len(component_sources),
                      "windows": len(resources), "workload_rows": len(rows), "pending": len(result["pending"])}))


if __name__ == "__main__":
    main()
