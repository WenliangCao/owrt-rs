#!/usr/bin/env python3
"""Render the derived whole-stack result without private responses/identifiers."""
import argparse
import json
from pathlib import Path
import statistics

WINDOWS = ("stock-1", "rust-1", "stock-2")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("derived", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    d = json.loads(a.derived.read_text())
    assert d["status"] in ("complete", "partial")
    windows = d["windows"]
    names = tuple(name for name in WINDOWS if name in windows)
    labels = {"stock-1": "C₁", "rust-1": "Rust", "stock-2": "C₂"}
    title = "C₁ / Rust / C₂" if d["status"] == "complete" else "C₁ / Rust（C₂ 未完成）"

    def columns(first):
        return ["| " + first + " | " + " | ".join(labels[n] for n in names) + " |",
                "|---|" + "---:|" * len(names)]

    lines = ["# 最终九组件整栈对照：" + title, "",
             f"共观察到{d['observed_new_boots']}次软件重启，取得{len(names)}个完整测量窗口、各三轮固定负载。C为精确镜像原版；Rust为试验时的九个正式组件共同运行。断电恢复未测。",
             "采集结束后已恢复原版、原 APK/启动状态和原保留包，临时配置、服务及回退设施已清理。",
             "所有数字是每个启动窗口内三轮统计量的中位数；完整范围和逐轮值见同名JSON。", "",
             "这是一次整栈工程对照，包含一个Rust启动窗口。请求、轮次和独立启动分别计数；C₂已完成的部分用于观察基线漂移。", "",
             "原计划、失败与重试说明、九组件剩余边界见[结论与收尾](STACK_20260929_ASSESSMENT.md)。", ""]
    if d["excluded_windows"]:
        lines += [f"有{len(d['excluded_windows'])}个C₂窗口在fw4输出字节校验处中止，整窗不并入正式比较；第一次失败后完成一次恢复启动，并且只补采一次C₂。",
                  "只读复查捕捉到原版WAN IPv6地址集合变化，fw4仅wan_subnets定义随之改变。失败瞬间的子进程输出未保留，故其精确差异仍未知。",
                  "一次补采沿用原工具、负载及完整字节校验，没有修改网络配置，也没有再次部署Rust。", ""]
    if d["status"] == "partial":
        lines += ["完整C₂缺失，三窗口计划状态为partial。C₁/Rust的完整结果与两个C₂已完成的部分分别展示；缺口没有改变这些已完成负载的性能排序。", ""]
    lines += ["## 完成与恢复", "",
             f"{len(names)}个有效窗口共{d['measured_successful_operations']:,}次计入统计的成功操作，预热和失败窗口另计；有效请求错误数为0。", "",
             "| 窗口 | 首次SSH可达（秒） | 完整启动健康门（秒） | 下载文件哈希校验 | 配置回调数（含预热） |",
             "|---|---:|---:|---:|---:|"]
    for name in names:
        w = windows[name]
        lines.append(f"| {name} | {w['first_ssh_s']:.2f} | {w['boot_health_completed_s']:.2f} | {w['verified_downloaded_files']} | {w['verified_config_deliveries']} |")
    lines += ["", f"{2 * len(names)}份有效窗口的运行中 nft 规则在计数器/期限归一化后完全一致：**{d['nft_rules_equal_after_counter_timeout_normalization']}**。",
              "九组件实际身份、原配置、客户端 DHCP、双频 AP、WAN/WAN6、DNS、HTTP/HTTPS、watchdog 的前后检查通过。", ""]

    def val(window, lane, metric):
        return windows[window]["summaries"][lane][metric]["median"]

    def change(rust, original):
        return f"{(rust / original - 1) * 100:+.2f}%" if original else "—"

    def table(title, lanes, metric, unit):
        baselines = [name for name in names if name != "rust-1"]
        lines.extend(["## " + title, "", f"单位：{unit}。Δ为Rust相对对应C窗口。", "",
                      "| 负载 | " + " | ".join([labels[n] for n in names] + ["Δ " + labels[n] for n in baselines]) + " |",
                      "|---|" + "---:|" * (len(names) + len(baselines))])
        for lane in lanes:
            values = [f"{val(name, lane, metric):.3f}" for name in names]
            values += [change(val("rust-1", lane, metric), val(name, lane, metric)) for name in baselines]
            lines.append("| " + lane + " | " + " | ".join(values) + " |")
        lines.append("")

    live = [lane for lane in windows["rust-1"]["summaries"] if lane.startswith(("live/", "config/"))]
    lan = [lane for lane in windows["rust-1"]["summaries"] if lane.startswith("lan/")]
    table("本机负载：控制面可计CPU", live, "control_accounted_cpu_us", "µs/操作")
    lines += ["查询与混合负载计六个守护进程自身CPU；UCI/fw4/reload/配置周期另加被测命令树getrusage。",
              "该口径不包括未独立精确计量的daemon后代；其粗粒度计数另存JSON。混合负载的测量客户端CPU单列，未加入控制面。", ""]
    table("本机负载：平均完成时间", [x for x in live if x != "live/mixed-total"], "mean_us", "µs/操作")
    table("本机负载：p99", [x for x in live if x != "live/mixed-total"], "p99_us", "µs/操作")
    table("混合负载吞吐", ["live/mixed-total"], "ops_per_s", "操作/秒；4客户端统一外窗")
    table("混合负载测量客户端CPU", ["live/mixed-total"], "driver_cpu_us", "µs/操作；不计入上面的控制面CPU")
    lines += ["## 固定本机负载总成本", "", "这是本次固定任务配比的总和，不代表生产流量的加权平均；其中fw4和重载次数会影响总降幅。", "",
              *columns("控制面可计CPU（秒）"),
              "| 全部本机查询、混合及配置负载 | " + " | ".join(f"{windows[name]['fixed_native_accounted_cpu_s']:.3f}" for name in names) + " |", ""]
    table("Wi-Fi客户端：平均延迟", lan, "mean_us", "µs/请求")
    table("Wi-Fi客户端：p99", lan, "p99_us", "µs/请求")
    lines += ["同AES负载的p99 +20.24%保留为原始观察值；复核同窗口相同套件和离群请求数后，撤回将其定性为稳定退步的结论。下方给出复核样本。", ""]
    table("Wi-Fi客户端：吞吐", lan, "ops_per_s", "请求/秒；新连接受20 starts/s限速")
    table("整机CPU观察", ["live/mixed-total", "config/cycle", "lan/https-rpc-c4"], "system_busy_cpu_us", "µs/操作")
    lines += ["整机CPU包含测量客户端、预热、进程启动和快照边界内的其它系统活动；原生主体CPU排除预热，两者不是同一计量边界。",
              "TLS统一1.2；默认协商和指定AES256-GCM分别报告。默认协商的C为CHACHA20-POLY1305，Rust为AES256-GCM，因此默认TLS差值也包含套件选择的影响。",
              "所有LAN请求均核对回复。实际日志、服务表使用各栈真实状态，正文/条目差异可能影响成本。", "",
              "## 真实配置重载阶段", "", "每轮十次真实持久化变更，等待测试服务回调实际读到新值；默认1000ms触发延迟保留。", "",
              *columns("阶段均值的轮间中位数（µs）")]
    for key in ("commit_us", "dispatch_us", "completion_us"):
        values = [windows[name]["config_stages"][key]["median"] for name in names]
        lines.append("| " + key + " | " + " | ".join(f"{x:.3f}" for x in values) + " |")
    lines += ["", "commit覆盖UCI set+commit；dispatch覆盖reload_config命令；completion从set开始到回调可见，含5ms轮询量化。各阶段不冒充纯组件内部耗时。", "",
              "## 整机内存与空闲CPU", "", "内存单位KiB，temperature_millic单位为毫摄氏度。下面给每段121次快照的中位数；RSS合计含共享页重复，不能等同独占物理内存。",
              "before/after指原生主负载前后；LAN负载此前已完成，真实配置变更周期在这两段采样后另测。", "",
              *columns("时点/指标")]
    for phase in ("before", "after"):
        for metric in ("MemAvailable", "Cached", "file_LRU", "Inactive(file)", "Mapped",
                       "used_excluding_free_file_LRU_reclaimable_slab", "AnonPages", "Shmem", "Slab", "summed_daemon_RSS", "temperature_millic"):
            values = [windows[name]["resources"][phase][metric]["median"] for name in names]
            lines.append("| " + phase + "/" + metric + " | " + " | ".join(f"{x:.1f}" for x in values) + " |")
        values = [windows[name]["resources"][phase]["system_idle_busy_pct"] for name in names]
        lines.append("| " + phase + "/idle busy % | " + " | ".join(f"{x:.3f}" for x in values) + " |")
        values = [windows[name]["resources"][phase]["daemon_idle_machine_capacity_pct"] for name in names]
        lines.append("| " + phase + "/six daemons % of machine capacity | " + " | ".join(f"{x:.4f}" for x in values) + " |")
    review = d["review"]
    lines += ["", "file_LRU = Active(file) + Inactive(file)。used_excluding_free_file_LRU_reclaimable_slab 为总内存减空闲、文件LRU和可回收slab后的余额；它是整机口径，不等于某一组件的独占或永久不可回收内存。",
              f"4 KiB页取整模型在全部{review['idle_samples']}个快照中有{review['available_model_exact_samples']}个精确吻合：", "",
              "`MemAvailable = MemFree − 24576 + L − 4×floor(L/8) + S − 4×floor(S/8)`（KiB；L=file_LRU，S=SReclaimable）。", "",
              "在这些快照对应的水位分支，空闲页转成1 MiB文件缓存会使MemAvailable减少约0.5 MiB。Rust测前多14.81 MiB文件LRU，其中12.10 MiB为Inactive(file)，足以解释原报告的可用内存差额。",
              "身份校验读取ELF是缓存增长的合理来源推测，数据没有记录逐页来源。撤回把MemAvailable差额定性为Rust内存退步的结论。", "",
              "## 四个窗口的内存与空闲CPU复核", "", "各窗口原生负载前121次快照的中位数；CPU为同一空闲段累计值，分母为整机两核容量。", "",
              "| 窗口 | MemAvailable KiB | 文件LRU KiB | 扣除空闲/文件LRU/可回收slab后 KiB | Mapped KiB | 六守护进程 CPU % | 整机忙 % |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for name, window in review["windows"].items():
        r = window["resources"]["before"]
        values = [r[key]["median"] for key in ("MemAvailable", "file_LRU", "used_excluding_free_file_LRU_reclaimable_slab", "Mapped")]
        lines.append("| " + name + " | " + " | ".join(f"{x:.0f}" for x in values) + f" | {r['daemon_idle_machine_capacity_pct']:.4f} | {r['system_idle_busy_pct']:.3f} |")
    lines += ["", "## TLS尾部复核", "", "每项合并3轮、1200个请求；中位数为合并样本中位数。12 ms是事后诊断阈值，不是冻结计划的通过门槛。", "",
              "| 窗口/负载 | 套件 | 请求数 | >12 ms次数 | 合并中位数 ms | 三轮p99 ms |", "|---|---|---:|---:|---:|---|"]
    for name, window in review["windows"].items():
        for lane, tail in window["tls_tail"].items():
            cipher = "AES256-GCM" if "AES256" in tail["ciphers"][0] else "CHACHA20"
            p99 = ", ".join(f"{x / 1000:.2f}" for x in tail["round_p99_us"])
            lines.append(f"| {name}/{lane} | {cipher} | {tail['requests']} | {tail['over_12ms']} | {tail['pooled_median_us'] / 1000:.3f} | {p99} |")
    lines += ["", "Rust两项单并发静态负载使用同一服务器和AES套件，p99仍明显不同；超12 ms次数在各窗口相近。样本支持链路/调度波动解释，尚不能把离群点逐个确认为Wi-Fi重传。", ""]
    lines += ["", "## 六个常驻组件负载后资源", "", "每格：RSS / 匿名页 KiB；fd / 线程。", "",
              *columns("组件")]
    for component in ("procd", "ubusd", "netifd", "rpcd", "logd", "httpd"):
        cells = []
        for name in names:
            r = windows[name]["resources"]["after"]
            get = lambda key: r[component + "/" + key]["median"]
            cells.append(f"{get('VmRSS'):.0f} / {get('RssAnon'):.0f}; {get('fds'):.0f} / {get('Threads'):.0f}")
        lines.append("| " + component + " | " + " | ".join(cells) + " |")
    lines += ["", "全机内存包含临时回退设施、验证读入的文件缓存及测量文件；不把差额全部归因于Rust。",
              "Rust采样前，两个回退计时器对应四个存活进程，合计RSS 4016 KiB、匿名页356 KiB；RSS含共享页，不能直接从MemAvailable差额中扣除。C₂采样前已解除并回收独立计时器。",
              "边界与每秒空闲快照不能证明活动期瞬时峰值或长期无泄漏。既有历史包/备份始终保留；C终态恢复到本轮开始时的原版运行状态。", "",
              "## 文件与存储开销", "", "可执行文件/脚本入口的原始字节数如下。原版大量逻辑在共享库、ucode及shell工具中，Rust为静态ELF；不能据此算完整固件增量。", "",
              "| 组件 | 原版入口字节 | Rust ELF字节 |", "|---|---:|---:|"]
    for component in d["artifact_bytes"]["original"]:
        lines.append(f"| {component} | {d['artifact_bytes']['original'][component]:,} | {d['artifact_bytes']['rust'][component]:,} |")
    totals = [sum(d["artifact_bytes"][side].values()) for side in ("original", "rust")]
    lines += [f"| 合计 | {totals[0]:,} | {totals[1]:,} |", "",
              *columns("实测已用空间 KiB")]
    for phase in ("before", "after"):
        for mount in ("/overlay", "/tmp"):
            values = [windows[name]["storage"][phase][mount]["used_kib"] for name in names]
            lines.append(f"| {phase} {mount} | " + " | ".join(str(v) for v in values) + " |")
    lines += ["", "这些空间读数包含历史Rust包、恢复副本、当前测量包及文件系统分配变化；各窗口没有清缓存或删除历史材料，不是最小安装体积。没有测量功耗或flash写入寿命。", "",
              "完整逐轮正负值、角色CPU、测量边界和原始文件SHA索引保存在派生JSON；原始回复、配置、标识和会话只保存在private目录。", ""]
    lines += ["## 兼容性复核", "",
              "| 窗口 | LAN前缀分配顺序 | network_get_ipaddr6回退选择 |", "|---|---|---|"]
    for name, window in review["windows"].items():
        lines.append(f"| {name} | {' → '.join(window['lan_prefix_order'])} | {window['network_get_ipaddr6_fallback_class']} |")
    lines += ["", "这是真实的netifd兼容差异；后续源码已按C的头插和续租顺序修复并添加回归测试，原测量ELF和原始数据保留。",
              f"四个窗口保存的fw4参考输出仅对子网集合成员排序后相等：**{review['stored_fw4_references_equal_after_subnet_ordering']}**。旧Rust窗口的参考来自Rust自身；这是事后参考输出核对，不是当时每个调用都经过C oracle。",
              "新采集器每轮用/rom/sbin/fw4前后夹取原版参考，仅归一化子网集合顺序，保留成员/规则差异并保存每次实际stdout/stderr；前后C输出变化单独标记INVALID_ENV。", ""]
    for excluded in d["excluded_windows"]:
        lines += ["## 失败窗口的已完成负载：" + excluded["name"], "",
                  "以下仅为失败前已完整记录且校验通过的负载。没有后续完整健康门或整窗完成标记，不计入正式比较，也不提供拼接的总分。",
                  "每项取所列已完成轮数的中位数，CPU为守护进程自身CPU（UCI另加命令树）。保留这些读数以呈现环境漂移。", "",
                  "| 负载 | 完成轮数 | mean µs | p99 µs | CPU µs/操作 |", "|---|---:|---:|---:|---:|"]
        for lane, rows in excluded["partial_observations"].items():
            med = lambda key: statistics.median(row[key] for row in rows)
            cpu_key = "daemon_cpu_us" if lane.startswith("lan/") else "control_accounted_cpu_us"
            lines.append(f"| {lane} | {len(rows)} | {med('mean_us'):.3f} | {med('p99_us'):.3f} | {med(cpu_key):.3f} |")
        lines.append("")
    a.output.write_text("\n".join(lines))


if __name__ == "__main__":
    main()
