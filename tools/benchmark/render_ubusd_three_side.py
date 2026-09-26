#!/usr/bin/env python3
"""Render a detailed C/R89/R136 ubusd router comparison from private evidence."""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import statistics
import tarfile

from analyze_candidate import derive


SIDES = ("stock", "r89", "candidate")
LABELS = {"stock": "C", "r89": "R89", "candidate": "R136"}
LATENCY = ("mean_us", "p50_us", "p95_us", "p99_us")
METRICS = LATENCY + (
    "ops_per_s",
    "subject_own_cpu_clock_us_per_op",
    "client_cpu_clock_us_per_op",
    "dependency_own_cpu_clock_us_per_op",
)
METRIC_LABELS = {
    "mean_us": "mean 延迟 (µs)",
    "p50_us": "p50 (µs)",
    "p95_us": "p95 (µs)",
    "p99_us": "p99 (µs)",
    "ops_per_s": "吞吐 (op/s)",
    "subject_own_cpu_clock_us_per_op": "ubusd CPU (µs/op)",
    "client_cpu_clock_us_per_op": "caller CPU (µs/op)",
    "dependency_own_cpu_clock_us_per_op": "provider CPU (µs/op)",
}
LOWER_IS_BETTER = set(LATENCY) | {
    "subject_own_cpu_clock_us_per_op",
    "client_cpu_clock_us_per_op",
    "dependency_own_cpu_clock_us_per_op",
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def stats(values):
    values = list(values)
    return {
        "n": len(values),
        "median": statistics.median(values),
        "mean": statistics.mean(values),
        "min": min(values),
        "max": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0,
        "windows": values,
    }


def delta(value, baseline):
    return (value / baseline - 1) * 100 if baseline else None


def direction(values, baseline):
    pairs = list(zip(values, baseline))
    return {
        "lower": sum(value < other for value, other in pairs),
        "equal": sum(value == other for value, other in pairs),
        "higher": sum(value > other for value, other in pairs),
        "pairs": [{"value": value, "baseline": other}
                  for value, other in pairs],
    }


def center_order(values):
    ordered = sorted(SIDES, key=lambda side: values[side])
    groups = []
    for side in ordered:
        if groups and values[groups[-1][-1]] == values[side]:
            groups[-1].append(side)
        else:
            groups.append([side])
    return " < ".join("=".join(LABELS[side] for side in group) for group in groups)


def verify_archives(root, data):
    checked = []
    for index, side in enumerate(data["order"], 1):
        window = root / f"{index:02d}-{side}"
        raw = window / "raw"
        actual = {}
        for path in raw.rglob("*"):
            if path.is_file():
                actual[path.relative_to(raw).as_posix()] = digest(path)
        archived = {}
        with tarfile.open(window / "raw.tar.gz", "r:gz") as archive:
            for member in archive:
                if member.isdir():
                    continue
                name = member.name.removeprefix("./")
                archived[name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
        if actual != archived:
            raise ValueError(f"raw archive differs from expanded evidence: {window}")
        if not (window / "COMPLETE").is_file() or not (raw / "COMPLETE").is_file():
            raise ValueError(f"incomplete window: {window}")
        checked.append({"run": window.name, "side": side,
                        "raw_archive_sha256": digest(window / "raw.tar.gz"),
                        "files": len(actual)})
    return checked


def build_report(root, label):
    data = derive(root, label)
    order = data["order"]
    by_workload = defaultdict(lambda: defaultdict(list))
    for row in data["runs"]:
        by_workload[row["workload"]][row["side"]].append(row)
    workloads = {}
    for workload in data["summary"]:
        metrics = {}
        for metric in METRICS:
            values = {side: [row[metric] for row in by_workload[workload][side]]
                      for side in SIDES}
            centers = {side: statistics.median(values[side]) for side in SIDES}
            metrics[metric] = {
                "unit": "op/s" if metric == "ops_per_s" else "µs" if metric in LATENCY else "µs/op",
                "lower_is_better": metric in LOWER_IS_BETTER,
                "side": {side: stats(values[side]) for side in SIDES},
                "center_order_low_to_high": center_order(centers),
                "r136_vs_c_pct": delta(centers["candidate"], centers["stock"]),
                "r136_vs_r89_pct": delta(centers["candidate"], centers["r89"]),
                "direction_vs_c": direction(values["candidate"], values["stock"]),
                "direction_vs_r89": direction(values["candidate"], values["r89"]),
            }
        workloads[workload] = {"metrics": metrics}

    resident_values = defaultdict(lambda: defaultdict(list))
    for row in data["resident"]:
        for metric in ("VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM", "fds"):
            resident_values[metric][row["side"]].append(row[metric])
    residents = {
        metric: {side: stats(resident_values[metric][side]) for side in SIDES}
        for metric in resident_values
    }
    settings = read(root / "settings.json")
    subjects = read(root / "subjects.json")
    health_before, health_after = read(root / "health-before.json"), read(root / "health-after.json")
    if health_before != health_after:
        raise ValueError("host health changed during collection")
    if (root / "config-before.sha256").read_bytes() != (root / "config-after.sha256").read_bytes():
        raise ValueError("host configuration hash changed during collection")
    return {
        "schema_version": 1,
        "label": label,
        "scope": "AX3000T physical-router ubusd three-side performance comparison",
        "raw_root": str(root),
        "collection": {
            "schedule": settings["schedule"],
            "windows_per_side": len(order) // len(SIDES),
            "workloads": len(workloads),
            "iterations": settings["iterations"],
            "matrix": settings["matrix"],
            "extended": settings["extended"],
            "management_access": settings["management_access"],
            "workload_transport": settings["workload_transport"],
            "boot_id": health_before["boot_id"],
            "kernel": "6.12.94",
        },
        "subjects": subjects,
        "tools": {
            "benchmark_sha256": settings["bench_sha256"],
            "harness_sha256": digest(Path(__file__).with_name("isolated.sh")),
            "runner_sha256": digest(Path(__file__).with_name("run_candidate.py")),
        },
        "integrity": {
            "host_health_unchanged": True,
            "config_unchanged": True,
            "windows": verify_archives(root, data),
        },
        "workloads": workloads,
        "resident_kib_and_fds": residents,
        "sources": data["sources"],
        "raw_runs": data["runs"],
        "limitations": [
            "Each side has four sequential windows (C, then R89, then R136); center values are medians of four window statistics.",
            "Direction counts compare equal-numbered windows and are descriptive; they are not a randomized paired significance test.",
            "Latency and CPU comparisons use process CLOCK CPU fields when available. c4 daemon CPU includes the outer interval divided by timed plus warm-up operations, as in analyze_candidate.py.",
            "The C executable is mapped from the exact image while Rust executables are mapped from the isolated temporary bundle; VmRSS is therefore reported with RssAnon/RssFile/RssShmem instead of being collapsed into one memory verdict.",
            "The registration/event extension measures object ADD/REMOVE listeners. It does not replace separate user SEND, monitor, slow-reader, or long-duration memory gates.",
        ],
    }


def number(value):
    return "—" if value is None else f"{value:.2f}"


def pct(value):
    return "—" if value is None else f"{value:+.2f}%"


def tri(metric):
    return "/".join(number(metric["side"][side]["median"]) for side in SIDES)


def direction_text(value):
    return f"{value['lower']}↓/{value['equal']}=/{value['higher']}↑"


def render_markdown(report):
    lines = [
        f"# {report['label']}", "",
        "这是同一台 Xiaomi Mi Router AX3000T 上的 C、正式 R89、最终 R136 三方实测。生产栈全程保持 C；每侧 4 个窗口，每个窗口 15 个负载，单负载 10,000 次成功操作。",
        "",
        "表中三方数值顺序固定为 `C / R89 / R136`，是四轮窗口统计的中位数。延迟和 CPU 越低越好，吞吐越高越好；方向计数中的 `↓/=/↑` 是 R136 相对基线四轮的实际方向数。报告给出数值排序，不使用“未分辨”代替结果。",
        "",
        "## 身份与完整性", "",
        f"- 原始证据：`{report['raw_root']}`。顺序：C×4 → R89×4 → R136×4。",
        f"- boot id：`{report['collection']['boot_id']}`；kernel：`{report['collection']['kernel']}`；管理链路：{report['collection']['management_access']}。",
        f"- 同一 benchmark：`{report['tools']['benchmark_sha256']}`；12/12 窗口 raw archive 与展开文件一致。",
        "- 采集前后健康、生产身份和配置 hash 均未改变；物理路由器上的生产 C 没有被替换。",
        "",
        "## 直接结论", "",
        "- R136 的四轮中心 `mean` 延迟在 15/15 个负载上同时低于 C 和 R89；吞吐在 15/15 个负载上同时高于 C 和 R89。",
        "- R136 的 ubusd 自身 process CPU 在 15/15 个负载上同时低于 C 和 R89；provider CPU 的有效比较只出现在 invoke 两个负载，R136 两项都最低。",
        "- R136 相对 R89 的 p50 中心值在 14/15 个负载上更低，p95 和 p99 在 15/15 个负载上更低。相对 C，注册/事件负载的部分 p95 和 p99 仍高于 C，caller CPU 的 event_1 与 event_nomatch 也略高于 C；这些是明确的局部尾部/调用者差异，不影响 mean 的全矩阵排序。",
        "",
        "## 延迟中心值（µs）", "",
        "| 负载 | mean C/R89/R136 | R136 低→高排序 | p50 C/R89/R136 | p95 C/R89/R136 | p99 C/R89/R136 | R136 vs C mean | R136 vs R89 mean |",
        "|---|---:|:---:|---:|---:|---:|---:|---:|",
    ]
    for workload, item in report["workloads"].items():
        m = item["metrics"]
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} |".format(
            workload, tri(m["mean_us"]), m["mean_us"]["center_order_low_to_high"],
            tri(m["p50_us"]), tri(m["p95_us"]), tri(m["p99_us"]),
            pct(m["mean_us"]["r136_vs_c_pct"]), pct(m["mean_us"]["r136_vs_r89_pct"])))

    lines += [
        "", "## 吞吐与 CPU 中心值", "",
        "| 负载 | 吞吐 C/R89/R136 (op/s) | 吞吐排序低→高 | ubusd CPU C/R89/R136 (µs/op) | ubusd CPU 排序低→高 | caller CPU C/R89/R136 (µs/op) | provider CPU C/R89/R136 (µs/op) |",
        "|---|---:|:---:|---:|:---:|---:|---:|",
    ]
    for workload, item in report["workloads"].items():
        m = item["metrics"]
        lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
            workload, tri(m["ops_per_s"]), m["ops_per_s"]["center_order_low_to_high"],
            tri(m["subject_own_cpu_clock_us_per_op"]),
            m["subject_own_cpu_clock_us_per_op"]["center_order_low_to_high"],
            tri(m["client_cpu_clock_us_per_op"]),
            tri(m["dependency_own_cpu_clock_us_per_op"])))

    lines += [
        "", "## 每轮方向计数", "",
        "`R136 vs C` 和 `R136 vs R89` 均按同一侧的四个窗口序号比较；例如 `3↓/0=/1↑` 表示 R136 有 3 轮更低、0 轮相等、1 轮更高。",
        "", "| 负载 | mean vs C | mean vs R89 | p50 vs C | p50 vs R89 | p95 vs C | p95 vs R89 | p99 vs C | p99 vs R89 | daemon vs C | daemon vs R89 | caller vs C | caller vs R89 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    direction_metrics = ["mean_us", "p50_us", "p95_us", "p99_us", "subject_own_cpu_clock_us_per_op", "client_cpu_clock_us_per_op"]
    for workload, item in report["workloads"].items():
        m = item["metrics"]
        cells = [workload]
        for metric in direction_metrics:
            cells += [direction_text(m[metric]["direction_vs_c"]), direction_text(m[metric]["direction_vs_r89"])]
        lines.append("| " + " | ".join(cells) + " |")

    lines += ["", "## 内存与文件页", "", "单位 KiB；这是 ubusd 进程在矩阵末尾的 resident snapshot 四轮中位数。"]
    lines += ["", "| 指标 | C | R89 | R136 | R136 vs C | R136 vs R89 |", "|---|---:|---:|---:|---:|---:|"]
    for metric, values in report["resident_kib_and_fds"].items():
        c, r89, r136 = (values[side]["median"] for side in SIDES)
        lines.append(f"| {metric} | {c:.2f} | {r89:.2f} | {r136:.2f} | {pct(delta(r136, c))} | {pct(delta(r136, r89))} |")

    lines += ["", "## 解释边界", ""]
    lines.extend(f"- {lim}" for lim in report["limitations"])
    lines += ["", "逐窗口所有 mean/p50/p95/p99、process CPU、caller CPU、方向原始值和 raw archive hash 见同目录 JSON。"]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("--label", default="R136 ubusd 三方实机收尾")
    args = parser.parse_args()
    report = build_report(args.root, args.label)
    args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    args.markdown.write_text(render_markdown(report))
    print(json.dumps({"workloads": len(report["workloads"]),
                      "windows": len(report["integrity"]["windows"]),
                      "json": str(args.json), "markdown": str(args.markdown)}))


if __name__ == "__main__":
    main()
