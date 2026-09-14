#!/usr/bin/env python3
"""Render R92 tables and exportable SVG/PDF figures from public derived JSON only.

The plotting dependency is matplotlib; runtime/build dependencies are unchanged.
Every reported delta is computed from per-run medians, without dropping outliers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

LABELS = {"stock": "C", "r89": "R89", "candidate": "R92", "live": "R92 live"}
COLORS = {"stock": "#7a7a7a", "r89": "#3974b2", "candidate": "#c76128"}


def read(path):
    return json.loads(path.read_text())


def median(values):
    return statistics.median(values)


def delta(new, old):
    return (new / old - 1) * 100


def md(path, lines):
    path.write_text("\n".join(lines) + "\n")


def component_tables(root):
    counts = {}
    for path in sorted(root.glob("*/**/results.json")):
        data = read(path)
        if "component" not in data:
            continue
        name = data["component"]
        lines = [f"# R92 {path.parts[-3]}：{name}", "",
            "三侧同一启动、相同夹具，各四轮。数值是逐轮统计的中位数，延迟和 CPU 单位均为 µs/请求。",
            "逐轮范围、p50/p95/p99、依赖/客户端 CPU、RSS 和身份见 [results.json](results.json)。", ""]
        for metric, label in (("mean_us", "平均延迟"), ("subject_cpu_us_per_op", "被测组件 CPU"), ("p99_us", "p99 延迟")):
            lines += [f"## {label}", "", "| 负载 | C | R89 | R92 | R92/C | R92/R89 |",
                      "|---|---:|---:|---:|---:|---:|"]
            for work, sides in data["summary"].items():
                c, old, new = [sides[side][metric]["median"] for side in ("stock", "r89", "candidate")]
                lines.append(f"| {work} | {c:.2f} | {old:.2f} | {new:.2f} | {delta(new,c):+.2f}% | {delta(new,old):+.2f}% |")
            lines.append("")
        lines += ["c4 的 CPU 使用唯一外层区间，分母计入每客户端 20 次预热。外层吞吐包含启动/预热，",
                  "且受 /proc/uptime 分辨率影响。客户端也运行在路由器上，吞吐不是服务端极限。",
                  "微小正差值仍保留，但四轮数据不足以把每个差值认定为代码回退。"]
        if data["cpu_affinity"]:
            lines += ["", "本组是 CPU " + data["cpu_affinity"] + " affinity 诊断，同时限制客户端及服务端；不替代正常双核矩阵。"]
        md(path.with_suffix(".md"), lines)
        if path.parts[-3] == "components":
            counts[name] = {"workloads": len(data["summary"]), "measurements": len(data["runs"]),
                "positive_deltas_vs_c": {metric: sum(s["candidate_vs_stock_pct"][metric] > 0 for s in data["summary"].values())
                                         for metric in ("mean_us", "subject_cpu_us_per_op", "p99_us")},
                "positive_deltas_vs_r89": {metric: sum(s["candidate_vs_baseline_pct"][metric] > 0 for s in data["summary"].values())
                                           for metric in ("mean_us", "subject_cpu_us_per_op", "p99_us")}}
    return counts


def tables(root):
    counts = component_tables(root)
    data = read(root / "whole_system.json")
    summary = {(r["study"], r["workload"], r["side"]): r["metrics"] for r in data["summaries"]}
    lines = ["# R92 整机测量", "", "同批 C/R92 各两个冷启动，每窗口五轮；单次 lane N=10000，UCI=100、fw4=30。", "",
             "| 负载 | C 平均 µs | R92 平均 µs | 延迟差 | C CPU µs/op | R92 CPU µs/op | CPU 差 |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for work in ("network", "rpcd", "procd", "log", "uci", "fw4", "http-static", "http-jsonrpc"):
        c, new = [summary[("whole", work, side)] for side in ("stock", "rust")]
        a, b = c["mean_us"]["median"], new["mean_us"]["median"]
        x, y = c["server_cpu_us_per_op"]["median"], new["server_cpu_us_per_op"]["median"]
        lines.append(f"| {work} | {a:.3f} | {b:.3f} | {delta(b,a):+.2f}% | {x:.3f} | {y:.3f} | {delta(y,x):+.2f}% |")
    lines += ["", "| 窗口 | 首次 SSH s | 健康确认 s | 固定整批 CPU s | idle-before RSS KiB | MemAvailable KiB |",
              "|---|---:|---:|---:|---:|---:|"]
    totals = {}
    for row in data["windows"]:
        idle = row["idle_before"]
        lines.append(f"| {row['window']} | {row['first_ssh_s']:.3f} | {row['health_confirmed_s']:.3f} | "
                     f"{row['active_server_cpu_s']:.3f} | {idle['summed_daemon_rss_kib']['median']:.0f} | {idle['memory_available_kib']['median']:.0f} |")
    for side in ("stock", "rust"):
        windows = [r for r in data["windows"] if r["side"] == side]
        totals[side] = {"active_server_cpu_s": median(r["active_server_cpu_s"] for r in windows),
            "idle_before_rss_kib": median(r["idle_before"]["summed_daemon_rss_kib"]["median"] for r in windows),
            "idle_before_mem_available_kib": median(r["idle_before"]["memory_available_kib"]["median"] for r in windows),
            "idle_before_daemon_cpu_pct": median(r["idle_before"]["daemon_cpu_one_core_pct"] for r in windows)}
    lines += ["", "每窗口 500650 次被测操作；mixed 四路用一个不重叠 CPU 区间，不把 lane 的进程计数重复相加。",
              "RSS 不等于 PSS/USS；idle-after 含 tmpfs 原始输出，不用来替代空闲前内存比较。", "",
              "| Mixed | C | R92 | 差值 |", "|---|---:|---:|---:|"]
    for metric in ("ops_per_s", "server_cpu_us_per_op"):
        old, new = [summary[("whole", "mixed-total", side)][metric]["median"] for side in ("stock", "rust")]
        lines.append(f"| {metric} | {old:.3f} | {new:.3f} | {delta(new,old):+.2f}% |")
    lines += ["", "## TLS", "", "fresh lane 限速 20/s，不比较吞吐；common cipher 只有每侧一个窗口。",
              "CPU 包含并计入预热；延迟单位为 ms。", "",
              "| 组/负载 | C mean ms | R92 mean ms | 延迟差 | C HTTPD CPU µs/op | R92 HTTPD CPU µs/op | CPU 差 |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for study in ("tls-default", "tls-common"):
        for work in ("keepalive-c1", "keepalive-c4", "fresh-c1", "fresh-c4"):
            c, new = [summary[(study, work, side)] for side in ("stock", "rust")]
            a, b = c["mean_ms"]["median"], new["mean_ms"]["median"]
            x, y = c["httpd_cpu_us_per_op"]["median"], new["httpd_cpu_us_per_op"]["median"]
            lines.append(f"| {study}/{work} | {a:.3f} | {b:.3f} | {delta(b,a):+.2f}% | {x:.3f} | {y:.3f} | {delta(y,x):+.2f}% |")
    md(root / "whole_system.md", lines)
    tail = ["# c4 尾延迟与 CPU affinity", "", "p99 是每轮 p99 的中位数，括号为四轮最小—最大；单位 µs。",
            "CPU 0 同时限制客户端、原版依赖与被测进程，不是只固定服务端的控制。", "",
            "| 组件/负载 | affinity | 侧 | mean | p99（范围） | 组件 CPU/op |", "|---|---|---|---:|---:|---:|"]
    for component in ("ubusd", "procd"):
        for category in ("components", "affinity"):
            d = read(root / category / component / "results.json")
            for work, sides in d["summary"].items():
                if not work.endswith("_c4"):
                    continue
                for side in ("stock", "r89", "candidate"):
                    s = sides[side]
                    q = s["p99_us"]
                    tail.append(f"| {component}/{work} | {d['cpu_affinity'] or '0,1'} | {LABELS[side]} | {s['mean_us']['median']:.2f} | "
                                f"{q['median']:.2f} ({q['min']:.2f}–{q['max']:.2f}) | {s['subject_cpu_us_per_op']['median']:.2f} |")
    md(root / "tail_latency.md", tail)
    result = {"component_counts": counts, "whole_totals": totals,
              "aggregation": "Per-run medians; positive-delta counts are arithmetic, not significance tests."}
    (root / "metrics_summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def figures(root):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
                         "svg.hashsalt": "r92", "figure.dpi": 130})
    output = root / "figures"
    output.mkdir(exist_ok=True)

    def save(fig, name):
        svg = output / (name + ".svg")
        fig.savefig(svg, bbox_inches="tight", metadata={"Date": None})
        # Matplotlib's path lines carry trailing blanks; normalize for Git.
        svg.write_text("\n".join(line.rstrip() for line in svg.read_text().splitlines()) + "\n")
        fig.savefig(output / (name + ".pdf"), bbox_inches="tight", metadata={"CreationDate": None, "ModDate": None})
        plt.close(fig)

    data = read(root / "http_memory_extended_oracle.json")["rows"]
    fig, ax = plt.subplots(figsize=(8, 4))
    for side in COLORS:
        group = [r for r in data if r["side"] == side]
        assert len(group) == 2 and all(r["cycles"] == 500 for r in group)
        values = [[s["VmRSS"] - r["initial"]["VmRSS"] for s in r["post_close_samples"]] for r in group]
        x = range(1, 501)
        ax.plot(x, [median(v) for v in zip(*values)], color=COLORS[side], label=LABELS[side])
        ax.fill_between(x, [min(v) for v in zip(*values)], [max(v) for v in zip(*values)], color=COLORS[side], alpha=.16)
    ax.set(xlabel="Completed cycles (64 connections, 2 requests each)", ylabel="RSS after close - initial RSS (KiB)",
           title="Build host: 500 connection cycles; band spans two runs")
    ax.legend(); ax.grid(alpha=.2)
    fig.tight_layout(); save(fig, "http-memory-500")

    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharex=True)
    for ax, name, title in zip(axes, ("http_diagnostics_oracle", "http_diagnostics_router"), ("Build host", "AX3000T")):
        data = read(root / (name + ".json"))["rows"]
        for side in COLORS:
            x = [0, 20, 40, 60, 80]
            y = [median(r["subject_cpu_us_per_op"] for r in data if r["side"] == side and r["kind"] == "gap" and r["value"] == gap) for gap in x]
            ax.plot(x, y, "o-", color=COLORS[side], label=LABELS[side])
        ax.axvline(50, color="black", linestyle="--", alpha=.4, label="50 ms parking boundary")
        ax.set(xlabel="Inter-request gap (ms), not RTT", ylabel="HTTPD CPU (us/request)", title=title)
        ax.grid(alpha=.2)
    axes[0].legend(fontsize=8)
    fig.tight_layout(); save(fig, "http-parking")

    phases = read(root / "reference_cache_router.json")["phases"]
    fig, axes = plt.subplots(2, 1, figsize=(8, 5), sharex=True)
    x = range(len(phases))
    axes[0].plot(x, [p["reference_resident_kib_after"] for p in phases], "o-", color=COLORS["candidate"])
    axes[0].set(ylabel="Inactive copy pages (KiB)", title="AX3000T: advice and reread of nine inactive reference copies")
    memory = [p["system_memory_kib"]["MemAvailable"] for p in phases]
    axes[1].errorbar(list(x), [m["median"] for m in memory],
                     yerr=[[m["median"]-m["min"] for m in memory], [m["max"]-m["median"] for m in memory]], fmt="o-", color=COLORS["r89"])
    axes[1].set(ylabel="MemAvailable (KiB)", xlabel="30-second phases; error bars show observed min/max")
    axes[1].set_xticks(list(x), [p["phase"] for p in phases])
    for ax in axes: ax.grid(alpha=.2)
    fig.tight_layout(); save(fig, "inactive-reference-cache")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("derived", type=Path)
    a = p.parse_args()
    assert read(a.derived / "deployment.json")["status"] == "accepted"
    result = tables(a.derived)
    figures(a.derived)
    (a.derived / "rendering.json").write_text(json.dumps({"renderer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "input": "Public allowlisted JSON only", "formats": ["Markdown", "SVG", "PDF"]}, indent=2) + "\n")
    print(json.dumps({"rendered": True, **result}))


if __name__ == "__main__":
    main()
