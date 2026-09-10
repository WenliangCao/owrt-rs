#!/usr/bin/env python3
"""Render complete, sanitized R84 results as Markdown tables and a figure."""
import argparse
import json
from pathlib import Path
import statistics

PRIMARY = {"uci": "export_network", "reload-config": "unchanged_config", "fw4": "print",
           "logd": "syslog_128", "httpd": "static_16k", "rpcd": "uci_get_network",
           "procd": "service_list_32", "ubusd": "invoke", "netifd": "interface_dump"}


def number(value):
    return f"{value:,.2f}" if value is not None else "—"


def ratio(rust, stock):
    return rust / stock if stock > 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = json.loads(args.results.read_text())
    assert data["status"] == "complete" and not data["pending"]
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    groups = {(r["study"], r["component"], r["workload"], r["side"]): r["metrics"] for r in data["summaries"]}

    def value(study, component, workload, side, metric):
        return groups[study, component, workload, side][metric]["median"]

    def pair(study, component, workload, metric):
        return [value(study, component, workload, side, metric) for side in ("stock", "rust")]

    table = ["# 单组件完整结果", "", "每侧四次独立运行；表中为每次运行统计值的中位数。延迟单位 µs。",
             "CPU 包含被测程序及其等待回收的子进程，依赖进程和客户端 CPU 分开保存在 results.json。", "",
             "syslog_128 的延迟是约128字节数据报的发送耗时，含队列背压；总吞吐和CPU区间等待最终消息被读取。",
             "它不表示逐条日志的落盘或端到端处理延迟。", "",
             "| 组件 / 负载 | 原版平均 | Rust 平均 | Rust/原版 | 原版 p95 | Rust p95 | 原版 CPU µs/次 | Rust CPU µs/次 |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    component_keys = sorted({key[1:3] for key in groups if key[0] == "component"})
    for component, workload in component_keys:
        c, r = pair("component", component, workload, "mean_us")
        cp, rp = pair("component", component, workload, "p95_us")
        cc, rc = pair("component", component, workload, "subject_cpu_us_per_op")
        table.append(f"| {component} / {workload} | {number(c)} | {number(r)} | {number(ratio(r,c))}× | {number(cp)} | {number(rp)} | {number(cc)} | {number(rc)} |")
    table += ["", "## 常驻进程", "", "运行全部单组件负载后的采样；RSS 含共享映射，不是 PSS/USS。CLI 峰值内存未测。", "",
              "| 组件 | 原版 RSS KiB | Rust RSS KiB | 原版匿名 RSS KiB | Rust 匿名 RSS KiB |", "|---|---:|---:|---:|---:|"]
    mem = {(r["component"], r["side"]): r["metrics"] for r in data["component_memory"]}
    for component in sorted({key[0] for key in mem}):
        c, r = mem[component, "stock"], mem[component, "rust"]
        table.append(f"| {component} | {number(c['VmRSS']['median'])} | {number(r['VmRSS']['median'])} | {number(c['RssAnon']['median'])} | {number(r['RssAnon']['median'])} |")
    (out / "component_results.md").write_text("\n".join(table) + "\n")

    table = ["# 整体替换结果", "", "每侧两次冷启动，每次五轮；数字为十轮统计值的中位数。", "",
             "| 负载 | 原版平均 µs | Rust 平均 µs | Rust/原版 | 原版吞吐 次/s | Rust吞吐 次/s | 原版控制面 CPU µs/次 | Rust控制面 CPU µs/次 |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for workload in sorted({key[2] for key in groups if key[0] == "whole"}):
        c, r = pair("whole", "all", workload, "mean_us") if workload != "mixed-total" else (None, None)
        co, ro = pair("whole", "all", workload, "ops_per_s")
        cc, rc = pair("whole", "all", workload, "server_cpu_us_per_op")
        multiplier = number(ratio(r, c)) + "×" if c is not None else "—"
        table.append(f"| {workload} | {number(c)} | {number(r)} | {multiplier} | {number(co)} | {number(ro)} | {number(cc)} | {number(rc)} |")
    table += ["", "混合负载每轮共 40,000 次操作；表中没有把整个批次耗时当作单次请求延迟。",
              "CPU 来自一个共同外层采样区间，不相加各并发客户端重叠的进程 CPU 计数。", "",
              "## 各启动窗口", "", "RSS/匿名 RSS 为六个常驻控制面进程合计，采用预热后、主负载前的 120 秒采样中位数。", "",
              "| 窗口 | SSH恢复 s | RSS KiB | 匿名RSS KiB | MemAvailable KiB | 空闲控制面 CPU 单核% | 空闲整机 CPU 双核容量% | 温度 °C |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for window in data["windows"]:
        m = window["idle_before"]
        table.append(f"| {window['window']} | {number(window['first_ssh_s'])} | {number(m['summed_daemon_rss_kib']['median'])} | {number(m['summed_daemon_anon_kib']['median'])} | {number(m['memory_available_kib']['median'])} | {number(m['daemon_cpu_one_core_pct'])} | {number(m['system_busy_capacity_pct'])} | {number(m['temperature_millic']['median']/1000)} |")
    table += ["", "SSH恢复时间是客户端以约十秒间隔轮询得到的观测值，包含重启/bootloader时间。",
              "负载后 MemAvailable 还受到 tmpfs 中原始样本文件的影响；完整前后数据见 results.json。"]
    table += ["", "## 混合负载的启动间变化", "",
              "每个启动窗口有五轮；吞吐范围和中位数用于展示重复性，不是置信区间。",
              "固定整套负载CPU涵盖该窗口的500,650次正式操作，包含fw4等一次性命令，未包含TLS或空闲采样。", "",
              "| 窗口 | 混合吞吐中位数 次/s | 五轮吞吐范围 次/s | 混合控制面CPU中位数 µs/次 | 固定整套负载CPU s |",
              "|---|---:|---:|---:|---:|"]
    for window in data["windows"]:
        mixed = [row for row in data["rows"] if row["study"] == "whole" and row["workload"] == "mixed-total"
                 and row["run"].startswith(window["window"] + "/")]
        rates = [row["ops_per_s"] for row in mixed]
        cpu = statistics.median(row["server_cpu_us_per_op"] for row in mixed)
        table.append(f"| {window['window']} | {number(statistics.median(rates))} | {number(min(rates))}–{number(max(rates))} | {number(cpu)} | {number(window['active_server_cpu_s'])} |")
    table += ["", "实际路由器仍承载背景网络活动，空闲整机CPU会随窗口变化；上面的进程CPU与整机CPU分别报告。",
              "只有两次冷启动/侧，结果限定于本设备、配置和负载，不把十轮视为十次独立启动。"]
    table += ["", "## 整机内存分类", "", "单位 KiB；使用同一负载前采样窗口。", "",
              "| 窗口 | 文件缓存 Cached | 全机匿名页 AnonPages | 文件映射页 Mapped | 不可回收 Slab |",
              "|---|---:|---:|---:|---:|"]
    for window in data["windows"]:
        m = window["idle_before"]["system_memory_kib"]
        table.append(f"| {window['window']} | {number(m['Cached']['median'])} | {number(m['AnonPages']['median'])} | {number(m['Mapped']['median'])} | {number(m['SUnreclaim']['median'])} |")
    table += ["", "完整性核验会读取完整可执行文件及参照副本，形成不同的文件缓存状态。",
              "MemAvailable 是该条件下的可用内存估计；RSS 合计也重复计算共享页。两者均不是独占物理内存或 PSS。"]
    (out / "system_results.md").write_text("\n".join(table) + "\n")

    table = ["# LAN HTTPS", "", "TLS 1.2，每次 1,000 个成功请求。fresh 统一限速20次/s，延迟不计入主动限速等待。",
             "CPU 包括每个客户端10次预热及SSH采样开销，除以包含预热的成功请求数。", ""]
    for study, title in (("tls-default", "默认协商：每侧两次启动"), ("tls-common", "相同 AES256-GCM 套件：每侧一次启动，主采样结束后测量")):
        table += ["", "## " + title, "", "| 负载 | 原版平均 ms | Rust平均 ms | 原版 p95 ms | Rust p95 ms | 原版 httpd CPU µs/次 | Rust httpd CPU µs/次 |",
                  "|---|---:|---:|---:|---:|---:|---:|"]
        for workload in ("keepalive-c1", "keepalive-c4", "fresh-c1", "fresh-c4"):
            c, r = pair(study, "httpd", workload, "mean_ms")
            cp, rp = pair(study, "httpd", workload, "p95_ms")
            cc, rc = pair(study, "httpd", workload, "httpd_cpu_us_per_op")
            table.append(f"| {workload} | {number(c)} | {number(r)} | {number(cp)} | {number(rp)} | {number(cc)} | {number(rc)} |")
    table += ["", "默认协商：原版 ECDHE-ECDSA-CHACHA20-POLY1305；Rust ECDHE-ECDSA-AES256-GCM-SHA384。",
              "受控组双方均为 ECDHE-ECDSA-AES256-GCM-SHA384；实际套件与会话复用次数逐次保存在 results.json。"]
    (out / "tls_results.md").write_text("\n".join(table) + "\n")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    labels = ["uci · network export", "reload-config · no changes", "fw4 · print",
              "logd · ~128 B submit", "httpd · 16 KiB static", "rpcd · uci.get",
              "procd · list 32 services", "ubusd · invoke", "netifd · interface dump"]
    latency, cpu = [], []
    for component, workload in PRIMARY.items():
        c, r = pair("component", component, workload, "mean_us")
        latency.append(r / c)
        c, r = pair("component", component, workload, "subject_cpu_us_per_op")
        cpu.append(r / c if c else float("nan"))
    fig, axes = plt.subplots(1, 3, figsize=(15.5, 6), gridspec_kw={"width_ratios": [1.25, 1.25, 1]})
    for ax, values, title in zip(axes[:2], (latency, cpu), ("Component latency", "Component CPU")):
        ax.barh(labels, values, color="#2563eb", height=.65)
        ax.axvline(1, color="#374151", linestyle="--", linewidth=1)
        ax.invert_yaxis()
        ax.set_title(title, loc="left", fontweight="bold")
        ax.set_xlabel("Rust / original OpenWrt (lower is better)")
        ax.grid(axis="x", alpha=.18)
        for i, v in enumerate(values):
            ax.text(v + .025, i, f"{v:.2f}x", va="center", fontsize=9)
        ax.set_xlim(0, max(max(values) * 1.2, 1.65))
    axes[1].set_yticklabels([])
    c, r = pair("whole", "all", "mixed-total", "ops_per_s")
    axes[2].bar(("OpenWrt", "Rust"), (c, r), color=("#64748b", "#2563eb"), width=.55)
    axes[2].set_title("Whole-system mixed load", loc="left", fontweight="bold")
    axes[2].set_ylabel("Successful operations / second")
    axes[2].set_ylim(0, max(c, r) * 1.22)
    for i, (side, value_) in enumerate((("stock", c), ("rust", r))):
        axes[2].text(i, value_ * 1.03, f"{value_:,.0f}", ha="center")
        for window in (w for w in data["windows"] if w["side"] == side):
            values = [row["ops_per_s"] for row in data["rows"] if row["study"] == "whole"
                      and row["workload"] == "mixed-total" and row["run"].startswith(window["window"] + "/")]
            axes[2].scatter(i, statistics.median(values), s=35, facecolors="white", edgecolors="black", zorder=3)
    for ax in axes:
        ax.spines[["top", "right"]].set_visible(False)
    fig.suptitle("AX3000T: original OpenWrt 25.12.5 vs latest Rust", fontsize=15, fontweight="bold")
    fig.text(.04, .035, "Physical router | 4 component runs per side | 2 system boots per side | CPU: subject + waited children | dots: per-boot medians", fontsize=9, color="#4b5563")
    fig.tight_layout(rect=(0, .07, 1, .94), w_pad=2)
    fig.savefig(out / "benchmark.svg", metadata={"Date": None})
    fig.savefig(out / "benchmark.png", dpi=180)
    plt.close(fig)


if __name__ == "__main__":
    main()
