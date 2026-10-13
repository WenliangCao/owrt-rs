# 最终 SDK 的独立三方性能复核

本轮覆盖内没有发现足以阻止合并的新增性能问题。这个判断只覆盖下列负载，不是完整替换验收或路由器性能结论。

## 身份与方法

被审产品是 `3e2c7b17b03cdd4c0005419b447db2cf0eda9d92`，被审原 HEAD 是 `f93b6b269acb16f495b292ae7a1409c372db8b45`。178 个产品输入逐一与 HEAD Git blob 相同；main 的 172 个输入逐一与 `be531cee49e366bb5044443d473944dbea45b87e` 相同。见 [local-source-check.json](local-source-check.json)。新增审计提交没有改变产品。

| 实现 | 实测 ELF SHA-256 |
| --- | --- |
| c | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| main | `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863` |
| current | `55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca` |

current 是真实 SDK payload。此前 after/ordinary/type-absent 性能测量使用 `006002bb` 的 `cf94126f…`；它也是 static PIE，但不是最终 SDK，不能直接作为最终身份的性能证明。见 [historical-identity.json](historical-identity.json)。本轮没有把旧结果冒称为最终结果，也没有重编产品。

Oracle 是 4 核 AArch64 Neoverse-N1、Linux 6.17.0-1020-oracle，具体环境见 [environment.json](environment.json)。63 窗采用三个 Latin-square 顺序 C/main/current、main/current/C、current/C/main；7 个场景每个 3 轮三方，配置、随机种子、负载和 CPU 绑核相同。每窗 1,000 QPS、20 clients、3 秒预热、15 秒测量，TCP 每连接 100 次查询后重连。daemon/upstream/load/controller 分别固定 CPU 0/1/2/3。

每窗先逐一证明 4,096 个 A 缓存名字，raw 场景另在 UDP/TCP 证明配置记录；随后禁用上游回答，测量期上游请求数为 0。TYPE65401 使用原 `abcd` RDATA。CPU 是服务 cgroup 的增量，包括 C 的 TCP 子进程。表中指标均为三个窗口指标的中位数；p95 是实际发送至完成，不是将三轮样本合并后的 p95。

所有 63 窗均保留，无重试或剔除；预热加正式测量共 1,134,000 scheduled=sent=correct，wrong/timeout/transport_error/skipped 全为 0。正式测量 945,000 次均在测量窗内完成；108 个 raw 直接回答独立逐字验证 AA；21 组三方配置哈希一致；630 个节流采样均为 0。见 [plan](plan.json)、[run](run.json)、[summary](summary.json)、[counter-check](counter-check.json) 和 [独立复核](independent-check.json)。

另直接从原始 cgroup 边界、二进制 latency/send-lag 记录独立复算 CPU、实际发送至完成和计划发送至完成的 p50/p95/p99，并重哈希 1,243 份 timing/proof/resource/启动证据及全部冻结资产，全部通过：[raw-recheck.json](raw-recheck.json)、[复核工具](recheck_raw.py)。原始二进制、包、rootfs、完整运行文件留在 Oracle private 目录。

## DNS 结果

| 配置 | CPU µs/正确：C / main / SDK | SDK/C | SDK/main | p95 µs：C / main / SDK | PSS KiB：C / main / SDK |
| --- | --- | ---: | ---: | --- | --- |
| 普通 TCP，无 raw | 47.405 / 30.680 / 32.956 | -30.48% | +7.42% | 103.000 / 79.241 / 80.161 | 6795 / 4876 / 5020 |
| TCP，100 个 raw A | 48.674 / 32.364 / 34.824 | -28.45% | +7.60% | 101.201 / 79.241 / 81.800 | 6902 / 5180 / 5284 |
| TCP，1,000 个 raw A | 77.450 / 32.255 / 43.541 | -43.78% | +34.99% | 145.561 / 78.841 / 90.281 | 7031 / 7456 / 7568 |
| UDP，100 个 raw A | 21.963 / 32.534 / 25.521 | +16.20% | -21.56% | 70.000 / 82.400 / 70.280 | 1672 / 3364 / 3412 |
| UDP，1,000 个 raw A | 45.337 / 106.412 / 24.242 | -46.53% | -77.22% | 105.401 / 207.762 / 70.480 | 1768 / 3744 / 3844 |
| TCP，100 个 TYPE65401 | 55.414 / 30.823 / 33.891 | -38.84% | +9.95% | 103.601 / 78.160 / 82.601 | 6948 / 5176 / 5296 |
| TCP，1,000 个 TYPE65401 | 57.201 / 32.786 / 33.568 | -41.32% | +2.39% | 111.480 / 80.681 / 80.841 | 7012 / 7460 / 7568 |

**P3，优化建议，分支新增的 TCP 本地检查成本。** 普通及 raw TCP 的 SDK CPU/尾延迟均低于同窗 C，不能因为高于 main 就沿用旧 N4 阻断。main 的 TCP cache-first 跳过本地记录选择；本分支 `daemon.rs:1803–1833` 的共享入口补上 C 所要求的 local/CNAME/cache 顺序。`local.rs:1334` 的 raw 扫描先检查类型，再作不分配内存的大小写比较；TYPE 缺失使用类型摘要跳过扫描。精确 C 也逐条先比较类型再比较名称，见 [原 C 源码依据](../../../20261013/fix4_repairs/performance/source-review.json)。普通 TCP 的 +7.42% main 比值与 raw A/1,000 的 +34.99% 都是描述性中位数，不归因于单个改动；C 的 fork/连接成本也包含在绝对差异内。

**P3，main 已有的 UDP/小 raw 配置 CPU 差距，分支已改善。** UDP/A100 的 SDK 比 C 多 3.558 µs/正确响应（+16.20%），但比 main 少 7.013 µs（−21.56%）。三个 C/main/SDK CPU 数组分别为：

{'c': [21.153333333333332, 22.5806, 21.962666666666667], 'main': [31.828866666666666, 32.53366666666667, 33.376933333333334], 'current': [26.090466666666668, 22.8738, 25.520666666666667]}

它不能算作本分支新增退步。UDP/A1,000 的 SDK 则同时快于 C 和 main。两组 UDP 的中位数差不能解释成“记录更多反而算法成本为负”，也不足以定位小配置差距的函数根因。

噪声没有被隐藏：普通 TCP 的 C CPU 相对范围为 20.11%，TYPE65401/100 的 C 为 22.22%，UDP/A100 SDK 为 12.60%。完整逐轮数组与相对范围都在 summary；三轮短窗不能证明统计等价。本轮普通 TCP 是 3/15 秒控制，不是旧 30/120 秒控制的同长度复跑。

## N3 与启动内存

追加实验复用 [fix3 startup_resources.py](../../../20261012/fix3/build/startup_resources.py)，文件 SHA 与本次收据一致。0/1,000/10,000/50,000 个正常 `host-record=nNNNNN.test,192.0.2.1` 配置，各三轮三方，共 36 次启动，所有进程与控制器固定 CPU 0。观察首次 `cleared cache` 日志后读进程 CPU，验证一次 UDP 回答，再取五次空闲 RSS/PSS；全通过且同配置回答逐字一致。

| host-record 数 | 观察日志 ms：C / main / SDK | ready CPU s：C / main / SDK | VmHWM KiB：C / main / SDK | 稳定 PSS KiB：C / main / SDK |
| ---: | --- | --- | --- | --- |
| 0 | 6.530 / 6.722 / 5.519 | 0.00 / 0.00 / 0.00 | 1120 / 1860 / 1972 | 1112 / 1852 / 1964 |
| 1,000 | 5.505 / 6.629 / 5.508 | 0.00 / 0.00 / 0.00 | 1328 / 2772 / 2928 | 1320 / 2764 / 2920 |
| 10,000 | 72.853 / 27.464 / 37.201 | 0.06 / 0.02 / 0.02 | 3120 / 10696 / 10760 | 3112 / 10268 / 10388 |
| 50,000 | 1829.184 / 130.097 / 179.177 | 1.79 / 0.11 / 0.17 | 11088 / 45632 / 45720 | 11080 / 42048 / 42148 |

**P3，分支新增机制，非阻断优化建议。** `main.rs:884` 构建 configured hosts，`main.rs:3571` 的 EVENT_INIT 又经 `read_hosts_with_notices`（6813）重建。50,000 条时相对 main 的观察时间多 49.08 ms、CPU 多 0.06 s，但当前 SDK 仍远快于精确 C 的 1.829 s / 1.79 s。按本次标准，旧 N3 不能作为合并阻断。没有通过 profile 把全部差值归给这一函数，也未修改产品作消融实验。

**P3，资源成本与既有内存差距。** DNS 各场景 SDK 的 PSS 比 main 多 48–144 KiB；启动 VmHWM 比 main 多 64–156 KiB，50,000 条时仅多 88 KiB。未复现旧 R5 随配置量扩大的暂态峰值增量。50,000 条稳定 PSS 的 C/main/SDK 是 11,080/42,048/42,148 KiB，主要 Rust/C 差距在 main 已有；小幅新增成本保留为资源优化建议，未观察到 OOM 或启动失败。不能把本次五个空闲采样解释为长期无泄漏证明。

启动 wall 以 5 ms 轮询日志，CPU tick 为 10 ms；0/1,000 条不足以得出精细 CPU/延迟结论。这不是整体开机或首次客户端响应耗时。原探针的 `main_level`/256 KiB 仅保留为历史诊断，本轮没有传 `--require-main-level`，不把它当新的验收标准。完整结果见 [startup.json](startup.json)。

## 重现与边界

在保留的 Oracle 环境中运行以下命令，使用全新的 private 输出目录。SDK/C/main、旧测量工具及输入均会按冻结身份校验；不需要构建产品。

```sh
AUDIT_ROOT=/home/ubuntu/dnsmasq-audit-fix4-20261014
python3 "$AUDIT_ROOT/performance/sdk_three_way.py" prepare --output "$AUDIT_ROOT/private/performance-sdk-rerun"
sudo -n python3 "$AUDIT_ROOT/performance/sdk_three_way.py" run --output "$AUDIT_ROOT/private/performance-sdk-rerun"
```

启动复现的完整 argv 在 startup.json，外层为 `sudo -n taskset -c 0 bash /home/ubuntu/dnsmasq-fix4-repair-20261013/source-final/tools/dnsmasq/run_isolated.sh`，随后原 startup_resources.py 参数；需将 `--out` 和 `--performance-status` 改为新的配对目录。只依赖保留环境，不会触及物理路由器。

独占期按协调停止其他构建/功能任务；runner 取得全局构建锁，每窗前无匹配实验负载。期间仅有 CPU 3 上的小型状态读取，不声称云宿主绝对无噪声。结束后无匹配任务残留、构建锁可取得并已释放：[release.json](release.json)。之后交还 Oracle 运行其他功能探针，本报告不把它们算入性能窗口。

未覆盖物理路由器/Cortex-A53、WAN/Wi-Fi、饱和吞吐与并发扫描、全部 DNS 组合、DHCP 稳态性能、缓存未命中/混合/失败负载、长期 soak、完整内存限制/OOM、所有配置规模，也未满足完整 PERFORMANCE_PROTOCOL 的全部目标和时长。PSS 是采样进程树峰值，不是 USS；没有把文件/ELF 大小当作运行内存。

plan 的 `baseline_product_commit=74c6b453` 是复用控制器留下的历史基线标签；本次实际 current 由 `candidate_commit=3e2c7b17`、`groups.current` 和每窗 `/proc/PID/exe` SHA 共同绑定为最终 SDK，未运行这个历史基线产物。
