#!/usr/bin/env python3
"""Publish derived component timings, resource counts and executable hashes."""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import statistics

from analyze import COMPONENT_WORK, memory, native, stats, timing

STATIC = ("static_512_dat", "static_16k_dat", "static_16k_css",
          "static_image_css", "static_64k_dat", "static_1m_dat")
RPCD_EXTRA = ("uci_get_64", "uci_get_authorized", "session_access_granted", "file_list", "session_access_64")
PROCD_EXTRA = ("service_list_128", "service_list_named_128")
UBUSD_EXTRA = ("lookup_prefix_64", "lookup_all_128")
METRICS = ("mean_us", "p50_us", "p95_us", "p99_us", "ops_per_s",
           "subject_cpu_us_per_op", "dependency_cpu_us_per_op", "client_cpu_us_per_op")


def read(path):
    return json.loads(path.read_text())


def serial(path, subject):
    data = native(path)
    own = next(p for p in data["daemon_cpu"] if p["pid"] == subject)
    count = data["successful"]
    return {**timing(data), "warmup": data["warmup"],
            "subject_cpu_us_per_op": (own["cpu_s"] + own["child_cpu_s"]) * 1e6 / count,
            "dependency_cpu_us_per_op": sum(p["cpu_s"] for p in data["daemon_cpu"]
                                            if p["pid"] != subject) * 1e6 / count,
            "client_cpu_us_per_op": data["client_cpu_s"] * 1e6 / count}


def parallel(path, subject):
    group = read(path / "group.json")
    assert group["clients"] == 4
    clients = [native(path / f"client-{i}.json") for i in range(1, 5)]
    assert all(c["successful"] == group["iterations_per_client"] and
               c["warmup"] == group["warmup_per_client"] for c in clients)
    samples = sorted(v for c in clients for v in c["latency_ns"])
    count = len(samples)
    warm = sum(c["warmup"] for c in clients)
    before, after = read(path / "before.json"), read(path / "after.json")
    hz = before["clock_ticks_per_second"]
    assert hz == after["clock_ticks_per_second"] and hz > 0
    elapsed = after["uptime_s"] - before["uptime_s"]
    assert elapsed > 0
    old = {p["pid"]: p for p in before["processes"]}
    new = {p["pid"]: p for p in after["processes"]}
    assert old.keys() == new.keys() and subject in old
    cpu = {}
    for pid, p in new.items():
        assert p["start_ticks"] == old[pid]["start_ticks"]
        own = p["cpu_ticks"] - old[pid]["cpu_ticks"]
        child = p["child_cpu_ticks"] - old[pid]["child_cpu_ticks"]
        assert own >= 0 and child >= 0
        cpu[pid] = (own + child) / hz
    # The native client's rounded (n - 1) index, pooled within one
    # run only. Each run remains one independent observation in the summary.
    quantile = lambda p: samples[math.floor((len(samples) - 1) * p + .5)] / 1000
    return {"successful": count, "warmup": warm, "wall_s": elapsed,
            "ops_per_s": count / elapsed, "mean_us": statistics.mean(samples) / 1000,
            "p50_us": quantile(.50), "p95_us": quantile(.95), "p99_us": quantile(.99),
            "subject_cpu_us_per_op": cpu[subject] * 1e6 / (count + warm),
            "dependency_cpu_us_per_op": sum(v for pid, v in cpu.items() if pid != subject) * 1e6 / (count + warm),
            "client_cpu_us_per_op": sum(c["client_cpu_s"] for c in clients) * 1e6 / count}


def derive(root, label):
    assert (root / "COMPLETE").exists(), "collector did not complete its host gates"
    order, subjects = read(root / "order.json"), read(root / "subjects.json")
    settings = read(root / "settings.json")
    assert not settings.get("rpc_client_diagnostic"), "RPC client diagnostics cannot be published as performance-matrix results"
    component = settings.get("component", "httpd")
    assert component in ("httpd", "rpcd", "procd", "ubusd", "netifd")
    measured_sides = tuple(side for side in ("stock", "r84", "candidate") if side in order)
    assert {"stock", "candidate"}.issubset(measured_sides)
    assert len({order.count(side) for side in measured_sides}) == 1
    before, after = read(root / "health-before.json"), read(root / "health-after.json")
    assert before["boot_id"] == after["boot_id"]
    assert (root / "config-before.sha256").read_bytes() == (root / "config-after.sha256").read_bytes()
    rows, residents, sources = [], [], []
    identities = set()
    fixtures = set()
    matrix = read(root / "settings.json")["matrix"]
    workloads = list(COMPONENT_WORK[component])
    if matrix and component == "httpd":
        workloads = ([f"{name}_{clients}" for name in STATIC for clients in ("c1", "c4")]
                     + ["cgi", "jsonrpc", "cgi_c4", "jsonrpc_c4"])
    elif matrix and component == "rpcd":
        workloads += [name + "_c4" for name in COMPONENT_WORK[component]]
        workloads += [name + suffix for name in RPCD_EXTRA for suffix in ("", "_c4")]
    elif matrix and component == "procd":
        workloads += [name + "_c4" for name in COMPONENT_WORK[component]]
        workloads += [name + suffix for name in PROCD_EXTRA for suffix in ("", "_c4")]
    elif matrix and component == "ubusd":
        workloads += [name + "_c4" for name in COMPONENT_WORK[component]]
        workloads += [name + suffix for name in UBUSD_EXTRA for suffix in ("", "_c4")]
    else:
        assert not matrix, "unsupported workload matrix"
    for index, side in enumerate(order, 1):
        local = root / f"{index:02d}-{side}"
        raw = local / "raw"
        assert (local / "COMPLETE").exists() and (raw / "COMPLETE").exists()
        meta = read(raw / "meta.json")
        assert meta["component"] == component and meta["dependencies"] == "original OpenWrt"
        subject = meta["subject_pid"]
        assert (raw / "boot-id.txt").read_text().strip() == before["boot_id"]
        for file in ("binary-sha256.txt", "subject-sha256.txt"):
            assert (raw / file).read_text().split()[0] == subjects[side]
        identity = tuple(line.split()[0] for line in (raw / "benchmark-sha256.txt").read_text().splitlines())
        identity += ((raw / "harness-sha256.txt").read_text().split()[0],)
        identities.add(identity)
        if matrix:
            fixture_file = {"httpd": "static-fixtures.sha256", "rpcd": "rpc-fixtures.sha256",
                            "procd": "procd-fixtures.sha256", "ubusd": "ubusd-fixtures.sha256"}[component]
            fixtures.add((raw / fixture_file).read_text())
            if component == "ubusd":
                for count in (64, 128):
                    expected_paths = [f"bench.filler{i:04d}" for i in range(1, count)] + ["bench.target"]
                    for phase in ("before", "after"):
                        assert (raw / f"objects-{count}-{phase}.txt").read_text().splitlines() == expected_paths
        sources.append({"run": local.name, "subject_sha256": subjects[side],
                        "archive_sha256": hashlib.sha256((local / "raw.tar.gz").read_bytes()).hexdigest(),
                        "kernel": (raw / "kernel.txt").read_text().strip()})
        for name in workloads:
            data = parallel(raw / name, subject) if name.endswith("_c4") else serial(raw / (name + ".json"), subject)
            expected = max(1, meta["iterations"] // (20 if name.startswith("cgi") else 10 if name.startswith(("static_1m", "uci_get_64")) else 1))
            if name.endswith("_c4"):
                expected = max(1, expected // 4) * 4
            assert data["successful"] == expected, (name, data["successful"], expected)
            rows.append({"run": local.name, "side": side, "workload": name, **data})
        resident = read(raw / "resident.json")
        process = next(p for p in resident["processes"] if p["pid"] == subject)
        residents.append({"run": local.name, "side": side, **memory(process),
                          "temperature_millic": resident["temperature_millic"]})
    assert len(identities) == 1 and (not matrix or len(fixtures) == 1), "clients/harness/fixtures changed between sides"
    groups = defaultdict(list)
    for row in rows:
        groups[(row["workload"], row["side"])].append(row)
    summary = {}
    for name in workloads:
        sides = {side: {metric: stats(r[metric] for r in groups[(name, side)]) for metric in METRICS}
                 for side in measured_sides}
        sides["candidate_vs_stock_pct"] = {
            metric: (sides["candidate"][metric]["median"] / sides["stock"][metric]["median"] - 1) * 100
            for metric in METRICS if sides["stock"][metric]["median"] > 0}
        summary[name] = sides
    client, namespace, harness = next(iter(identities))
    return {"schema_version": 1, "label": label, "component": component, "matrix": matrix, "subjects": subjects,
            "benchmark_sha256": client, "namespace_sha256": namespace, "harness_sha256": harness,
            "order": order, "host_gates_passed": True, "runs": rows, "summary": summary,
            "measured_sides": measured_sides,
            "resident": residents, "sources": sources,
            "method": "Medians of per-run statistics; c4 CPU uses one outer interval divided by successful plus warm-up operations. c4 outer throughput includes warm-up/startup and uses /proc/uptime resolution. Client validation runs on the same router CPUs."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    result = derive(args.private, args.label)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    lines = [f"# {args.label}：{result['component']} 实机对照", "",
             "单位：延迟和 CPU 为 µs/请求；数值是逐轮统计的中位数。负百分比表示开销下降。", "",
             "| 负载 | 原版延迟 | R84 延迟 | 候选延迟 | 候选比原版 | 原版 CPU | 候选 CPU | 候选比原版 |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, sides in result["summary"].items():
        v = lambda side, metric: sides[side][metric]["median"]
        delta = sides["candidate_vs_stock_pct"]
        r84 = f"{v('r84', 'mean_us'):.2f}" if "r84" in sides else "—"
        lines.append(f"| {name} | {v('stock', 'mean_us'):.2f} | {r84} | "
                     f"{v('candidate', 'mean_us'):.2f} | {delta['mean_us']:+.2f}% | "
                     f"{v('stock', 'subject_cpu_us_per_op'):.2f} | {v('candidate', 'subject_cpu_us_per_op'):.2f} | "
                     f"{delta['subject_cpu_us_per_op']:+.2f}% |")
    lines += ["", "每侧运行次数：" + str(len(result["order"]) // len(result["measured_sides"])) + "。所列完整运行的请求均成功，原版依赖和正式运行栈保持相同。",
              "", "c4 的 CPU 包含并计数每客户端 20 次预热，使用唯一外层区间；吞吐包括预热和启动，",
              "计时精度来自 /proc/uptime。客户端校验也使用路由器 CPU，不能把这里的吞吐视为服务端极限。",
              "", "逐轮均值、p50/p95/p99、CPU、内存、离散程度及产物身份见 [results.json](results.json)。", ""]
    (args.output / "results.md").write_text("\n".join(lines))
    print(f"{args.label}: {len(result['runs'])} workload measurements verified")


if __name__ == "__main__":
    main()
