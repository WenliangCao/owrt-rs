# dnsmasq-rs M6b 最终报告

最终 opt3 已完成精确镜像 C 对照的完整功能、资源与压力验收、135 个正式窗口、性能保护门，以及 r3 APK 的安装／升级／卸载／回滚。原始 Rust 的 UDP 调度瓶颈消除，TCP cache/miss 的 CPU、延迟和内存明显改善；全部普通窗口错误为零。**M6b 的收益成立，但与 C 的全部成本目标仍有差距**，不能把通过功能验收写成全面替代结论。

本报告的最终源码是 `889fe4f5`，opt3 是 `791a7c33…`、同源 s 是 `d8d3c1ea…`。最初冻结 `284376c4` 后，main 合入的 `16ac3cea` health 热修复没有触及 dnsmasq 源码或构建输入，旧冻结当时继续有效；之后用户授权 UDP／TFTP 修复才改变 ELF，因此从第 1 步完整重跑，旧13步没有导入新资格。后续 main 的工具／文档提交也不改变最终产品身份。[完整冻结](audits/M6B_FINAL_FREEZE.md)

结论仅代表同一 AArch64 Oracle 与 OpenWrt 25.12.5 精确镜像 rootfs。最终功能、资源、guard、APK 均绑定 feature-off opt3；s 只完成同源性能对照，不继承 opt3 的完整功能／包资格。物理路由器未安装、未操作；**M7 真机与延期第 4 包未执行**。

`E = private/dnsmasq-rewrite/evidence`，`F = E/M6B/final-889fe4f5`。原始证据、ELF、APK、源导出和完整元数据归档全在 ignored/private；Git 仅存工具、无秘密身份清单与派生报告。135 全部首次 attempt，控制器与 watcher 均退出0，窗口期间无并行构建／测试，未因生成器受限扩容或复跑。

## 性能、内存与保留差距

最终 feature-off opt3（下称 R3）解决了原始 Rust 的 UDP 调度瓶颈，并显著降低 TCP cache/miss 的 CPU、延迟和内存。它没有达到镜像 C 的全部成本水平：UDP-hit 的 CPU 与 p95、DHCP 的 CPU、reload 的 CPU 与 p95 均比 C 更差；TCP-local 稳态 CPU 也比原始 Rust 增加 19.65%。TCP-miss 稳态峰值 PSS 仍是 C 的 **3.386 倍**，opt3 ELF 是 C 的 **7.301 倍**。这些差距属于最终结果，不能由其他场景的收益抵消。

本节只报告 Oracle 上的观测。最终 135 是九场景 × C/R3/Rs × 五轮，全部采用 attempt-1；state 为 complete，135 窗均方法有效。wrong answer、transport error、普通场景 timeout 均为零；upstream-fault 的每个窗口有 600 个预期 timeout，仅发生在 30 秒故障段。完整归档共 3,832,502,072 B、103,517 项，均完成全 SHA 和 metadata 验证。正式窗口未启用 diagnostics feature、wake sidecar、perf 或 strace。

## 身份与比较口径

最终源码身份是 `889fe4f5c59da514529e31173d346ec93bae03a9`，不是报告编写时的 main HEAD。原始 Rust 指 M6a 的 `dc1b740d7973838e2ae7f098d0726b0484e55074`，按相同优化级别分别比较 R3/原始 opt3、Rs/原始 s；它不指 readiness 修复后的无 A 基线或 CPU45 候选。初始冻结 `284376c4` 的旧 13 步在修复改变 ELF 后没有沿用；无关的 `16ac3cea` health 热修复不是重新冻结的原因。

| 产品 | ELF 字节 | SHA256 |
| --- | ---: | --- |
| 精确镜像 C | 269,305 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 最终 R3 | 1,966,120 | `791a7c33987fbb21887c51041f27722b9cc1bd8bd4cffab0fc03a292517fb10f` |
| 最终 Rs | 1,642,536 | `d8d3c1ea2ed0a3c29ab260aea21534e6c326a371342a15442a540d62cd3539dc` |
| 原始 opt3 | 1,929,256 | `37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b` |
| 原始 s | 1,613,864 | `8427b9ab9718e3645137db4670ef3afcb8d983a2b88bb997127224de39988a2a` |

下表是五轮中位数。QPS 用阶段内正确完成数，CPU 用相同阶段 cgroup usage 增量除以该正确数；C 的 TCP 子进程已包含在 cgroup 内，不重复相加。p95 用该阶段发出且最终正确的请求；峰值 PSS 是每窗阶段树峰值再对五轮取中位数。DHCP 一单位是一个 DORA＋renew＋release cycle。故障段零正确，CPU/正确请求和延迟没有定义，写“—”。

分类遵守事前 W/4-of-5 规则：变化幅度严格超过两组 `W=(max−min)/median` 的较大者，且至少四个同编号轮次同方向；吞吐收益至少 10%、退步至少 5%；CPU/请求与 p95 的变化至少 10%；内存还要求绝对变化至少 64 KiB。未满足规则的实测中位差异写“无显著差异”，不等于已经证明相等。前后批次属于同 Oracle、同负载配方的前后观测，并非同时对照。

生成器受限的饱和吞吐只记 **≥X（生成器受限）**。实际标记是 UDP-hit 的 C 五轮、TCP-local 的 R3 四轮、TCP-cache 的 R3/Rs 各五轮；涉及这些组的吞吐比较不声称精确服务上限或倍数，未扩大生成器、未因此复跑。UDP-hit 的 Rust 两组本身没有该标记，其相对 C 的饱和吞吐比较仍受限。

## 九场景实际值

每格依次为 **C / R3 / Rs**；吞吐单位为正确请求/s（DHCP 为 cycle/s），CPU 为 µs/正确请求（DHCP 为 µs/cycle），p95 为 ms，PSS 为 KiB。

| 场景 / 阶段 | 正确吞吐 C / R3 / Rs | CPU C / R3 / Rs | p95 C / R3 / Rs | 峰 PSS C / R3 / Rs |
| --- | --- | --- | --- | --- |
| udp-hit / 稳态 | 9,998.11 / 9,997.99 / 9,997.58 | 11.965 / 16.744 / 18.305 | 0.021640 / 0.026561 / 0.027920 | 1,624 / 3,292 / 3,104 |
| udp-hit / 饱和 | ≥146,065.47（生成器受限） / 107,859.33 / 94,193.27 | 6.842 / 9.266 / 10.604 | 0.149121 / 0.197521 / 0.225082 | 1,624 / 3,292 / 3,104 |
| udp-miss / 稳态 | 9,979.33 / 9,986.52 / 9,987.84 | 92.076 / 79.546 / 86.411 | 0.199682 / 0.122841 / 0.139162 | 1,656 / 3,712 / 3,504 |
| udp-miss / 饱和 | 12,693.87 / 17,296.33 / 15,291.43 | 78.159 / 57.219 / 64.786 | 1.710694 / 1.274531 / 1.425892 | 1,656 / 3,720 / 3,524 |
| dns-mixed / 稳态 | 9,996.10 / 9,996.40 / 9,995.81 | 30.856 / 32.122 / 34.414 | 0.129961 / 0.098761 / 0.104841 | 1,656 / 3,580 / 3,500 |
| dns-mixed / 饱和 | 42,735.53 / 46,711.97 / 41,846.30 | 23.222 / 21.288 / 23.781 | 0.561165 / 0.488084 / 0.535844 | 1,660 / 3,584 / 3,524 |
| upstream-fault / 故障前 | 1,000.00 / 1,000.00 / 1,000.00 | 158.094 / 121.629 / 114.059 | 0.259922 / 0.214122 / 0.166042 | 1,660 / 3,688 / 3,624 |
| upstream-fault / 故障 | 0.00 / 0.00 / 0.00 | — / — / — | — / — / — | 1,736 / 4,036 / 3,912 |
| upstream-fault / 恢复 | 992.58 / 992.68 / 992.43 | 258.110 / 197.739 / 179.888 | 0.365003 / 0.300682 / 0.257482 | 1,736 / 4,048 / 3,924 |
| tcp-local / 稳态 | 9,997.07 / 9,996.92 / 9,997.82 | 28.255 / 24.097 / 24.838 | 0.114241 / 0.040760 / 0.036560 | 3,931 / 3,812 / 3,620 |
| tcp-local / 饱和 | 37,465.67 / ≥86,621.10（生成器受限） / 76,574.10 | 26.632 / 11.524 / 13.054 | 0.829367 / 0.389723 / 0.444723 | 2,961 / 3,812 / 3,620 |
| tcp-cache / 稳态 | 9,995.10 / 9,997.43 / 9,998.22 | 33.578 / 19.878 / 20.984 | 0.174201 / 0.035480 / 0.032040 | 8,285 / 4,756 / 4,564 |
| tcp-cache / 饱和 | 31,085.30 / ≥120,974.37（生成器受限） / ≥111,868.27（生成器受限） | 32.107 / 8.261 / 8.933 | 1.113129 / 0.289163 / 0.311483 | 5,110 / 4,756 / 4,564 |
| tcp-miss / 稳态 | 4,404.58 / 9,979.51 / 9,969.68 | 226.837 / 97.502 / 99.967 | 3.435949 / 0.665565 / 1.069528 | 5,527 / 18,712 / 18,532 |
| tcp-miss / 饱和 | 4,644.30 / 12,091.97 / 10,770.13 | 215.121 / 82.548 / 92.743 | 3.580670 / 2.135178 / 2.317099 | 4,010 / 18,732 / 18,548 |
| dhcp-lease / 稳态 | 20.00 / 20.00 / 20.00 | 476.925 / 739.639 / 755.397 | 3.219426 / 3.349228 / 3.359068 | 1,668 / 2,312 / 2,060 |
| reload-concurrent / 稳态 | 1,000.00 / 1,000.00 / 1,000.00 | 20.756 / 37.529 / 38.023 | 0.065161 / 0.089321 / 0.087481 | 1,652 / 2,380 / 2,128 |

UDP-hit 稳态 p50 为 C/R3/Rs **0.019760 / 0.023720 / 0.024841 ms**，最终 R3 达到施加的约 10,000 QPS 和 p50≤1 ms 保护线；这不改变其 CPU 与 p95 相对 C 的退步。DHCP 每窗只有 2,400 个正确 cycle，按既定样本数合同不报 p99。其余 p50/p99、每轮值、min/max/W 与 FD/thread/child 均在同一分析 JSON/CSV 中保留。

## 相对本轮镜像 C

每格依次为 **R3 / Rs** 的中位变化；“益/退”表示原分类的有收益/变差，“无”表示无显著差异；负 CPU、p95、PSS 为更低。完整五轮/W/方向计数以派生 JSON 为准。

| 场景 / 阶段 | 吞吐 | CPU/正确单位 | p95 | 峰 PSS |
| --- | --- | --- | --- | --- |
| udp-hit / 稳态 | -0.00% 无 / -0.01% 无 | +39.95% 退 / +52.99% 退 | +22.74% 退 / +29.02% 退 | +102.71% 退 / +91.13% 退 |
| udp-hit / 饱和 | 受限 / 受限 | +35.44% 退 / +55.00% 退 | +32.46% 退 / +50.94% 退 | +102.71% 退 / +91.13% 退 |
| udp-miss / 稳态 | +0.07% 无 / +0.09% 无 | -13.61% 益 / -6.15% 无 | -38.48% 益 / -30.31% 无 | +124.15% 退 / +111.59% 退 |
| udp-miss / 饱和 | +36.26% 益 / +20.46% 益 | -26.79% 益 / -17.11% 益 | -25.50% 益 / -16.65% 益 | +124.64% 退 / +112.80% 退 |
| dns-mixed / 稳态 | +0.00% 无 / -0.00% 无 | +4.10% 无 / +11.53% 退 | -24.01% 益 / -19.33% 益 | +116.18% 退 / +111.35% 退 |
| dns-mixed / 饱和 | +9.30% 无 / -2.08% 无 | -8.33% 无 / +2.40% 无 | -13.02% 益 / -4.51% 无 | +115.90% 退 / +112.29% 退 |
| upstream-fault / 故障前 | +0.00% 无 / +0.00% 无 | -23.07% 益 / -27.85% 无 | -17.62% 无 / -36.12% 无 | +122.17% 退 / +118.31% 退 |
| upstream-fault / 故障 | +0.00% 无 / +0.00% 无 | — / — | — / — | +132.49% 退 / +125.35% 退 |
| upstream-fault / 恢复 | +0.01% 无 / -0.02% 无 | -23.39% 无 / -30.31% 益 | -17.62% 无 / -29.46% 无 | +133.18% 退 / +126.04% 退 |
| tcp-local / 稳态 | -0.00% 无 / +0.01% 无 | -14.72% 益 / -12.09% 益 | -64.32% 益 / -68.00% 益 | -3.03% 无 / -7.91% 无 |
| tcp-local / 饱和 | 受限 / +104.38% 益 | -56.73% 益 / -50.98% 益 | -53.01% 益 / -46.38% 益 | +28.74% 退 / +22.26% 退 |
| tcp-cache / 稳态 | +0.02% 无 / +0.03% 无 | -40.80% 益 / -37.51% 益 | -79.63% 益 / -81.61% 益 | -42.60% 益 / -44.91% 益 |
| tcp-cache / 饱和 | 受限 / 受限 | -74.27% 益 / -72.18% 益 | -74.02% 益 / -72.02% 益 | -6.93% 无 / -10.68% 无 |
| tcp-miss / 稳态 | +126.57% 益 / +126.35% 益 | -57.02% 益 / -55.93% 益 | -80.63% 益 / -68.87% 益 | +238.56% 退 / +235.30% 退 |
| tcp-miss / 饱和 | +160.36% 益 / +131.90% 益 | -61.63% 益 / -56.89% 益 | -40.37% 益 / -35.29% 益 | +367.13% 退 / +362.54% 退 |
| dhcp-lease / 稳态 | +0.00% 无 / +0.00% 无 | +55.08% 退 / +58.39% 退 | +4.03% 无 / +4.34% 无 | +38.61% 退 / +23.50% 退 |
| reload-concurrent / 稳态 | +0.00% 无 / +0.00% 无 | +80.81% 退 / +83.19% 退 | +37.08% 退 / +34.25% 退 | +44.07% 退 / +28.81% 退 |

## 相对原始 Rust（同优化级别）

每格依次为 **R3 / Rs** 的中位变化；“益/退”表示原分类的有收益/变差，“无”表示无显著差异；负 CPU、p95、PSS 为更低。完整五轮/W/方向计数以派生 JSON 为准。

| 场景 / 阶段 | 吞吐 | CPU/正确单位 | p95 | 峰 PSS |
| --- | --- | --- | --- | --- |
| udp-hit / 稳态 | +2049.08% 益 / +2050.27% 益 | -81.23% 益 / -80.07% 益 | -99.94% 益 / -99.94% 益 | -6.48% 无 / -6.84% 无 |
| udp-hit / 饱和 | 益（不报服务上限倍数） / 益（不报服务上限倍数） | -89.45% 益 / -88.40% 益 | -99.54% 益 / -99.48% 益 | -6.48% 无 / -6.84% 无 |
| udp-miss / 稳态 | +2136.07% 益 / +2139.04% 益 | -56.14% 益 / -52.67% 益 | -99.73% 益 / -99.69% 益 | -3.83% 无 / -6.11% 无 |
| udp-miss / 饱和 | +3769.71% 益 / +3325.76% 益 | -68.29% 益 / -64.73% 益 | -97.20% 益 / -96.87% 益 | -3.63% 无 / -5.57% 无 |
| dns-mixed / 稳态 | +2071.09% 益 / +2073.16% 益 | -71.48% 益 / -70.04% 益 | -99.77% 益 / -99.76% 益 | +0.56% 无 / +3.80% 无 |
| dns-mixed / 饱和 | +10048.16% 益 / +9000.32% 益 | -81.50% 益 / -79.62% 益 | -98.89% 益 / -98.79% 益 | +0.67% 无 / +4.76% 无 |
| upstream-fault / 故障前 | +123.73% 益 / +124.01% 益 | -31.45% 益 / -37.23% 无 | -99.51% 益 / -99.62% 益 | -4.26% 无 / -2.79% 无 |
| upstream-fault / 故障 | +0.00% 无 / +0.00% 无 | — / — | — / — | -6.40% 无 / -6.59% 无 |
| upstream-fault / 恢复 | +129.75% 益 / +129.69% 益 | -18.90% 益 / -26.36% 益 | -99.33% 益 / -99.43% 益 | -6.21% 无 / -6.57% 无 |
| tcp-local / 稳态 | +23.03% 益 / +24.13% 益 | +19.65% 退 / +17.33% 退 | -98.27% 益 / -98.46% 益 | -66.37% 益 / -67.92% 益 |
| tcp-local / 饱和 | 受限 / +848.43% 益 | -43.27% 益 / -38.03% 益 | -85.81% 益 / -84.01% 益 | -66.37% 益 / -67.90% 益 |
| tcp-cache / 稳态 | +31.06% 益 / +32.56% 益 | -29.42% 益 / -29.31% 益 | -98.86% 益 / -98.99% 益 | -80.90% 益 / -81.53% 益 |
| tcp-cache / 饱和 | 受限 / 受限 | -70.90% 益 / -69.89% 益 | -92.42% 益 / -91.96% 益 | -80.90% 益 / -81.53% 益 |
| tcp-miss / 稳态 | +243.65% 益 / +247.17% 益 | -29.75% 益 / -29.95% 益 | -93.07% 益 / -89.24% 益 | -44.26% 益 / -44.70% 益 |
| tcp-miss / 饱和 | +316.40% 益 / +282.49% 益 | -40.72% 益 / -38.03% 益 | -79.20% 益 / -78.60% 益 | -44.20% 益 / -44.65% 益 |
| dhcp-lease / 稳态 | +0.00% 无 / +0.00% 无 | -92.12% 益 / -92.13% 益 | -71.87% 益 / -71.77% 益 | -4.93% 无 / -2.65% 无 |
| reload-concurrent / 稳态 | +115.67% 益 / +115.66% 益 | -60.73% 益 / -60.47% 益 | -99.79% 益 / -99.79% 益 | -0.67% 无 / -0.75% 无 |

## 逐场景解释与机制证据

| 场景 | 人可读结论与机制 |
| --- | --- |
| UDP hit | 相对原始两组，稳态正确吞吐从约 465 提至约 9,998 QPS，CPU 降约 80–81%，p95 从约 43 ms 降到约 0.027 ms；内存变化未达到分类幅度。相对本轮 C，R3/Rs CPU 多 39.95%/52.99%、p95 多 22.74%/29.02%、PSS 多 102.71%/91.13%，均为退步。源码把网络与 file fd 放入共同 poll/deadline，复用接收缓冲，每 listener 16 包预算并推进 completion/让出其他服务；它解释原调度瓶颈被去除，不证明剩余 CPU 差距的具体函数占比。[M6B_PROTOCOL.md §第1项](M6B_PROTOCOL.md)、最终冻结 source `main.rs::SinglePoll::wait_for_files/step/step_udp`。 |
| UDP miss | 相对原始两组，稳态吞吐约 446→9,987 QPS，CPU 降 56.14%/52.67%，p95 降 99.73%/99.69%；饱和也有吞吐、CPU、p95 收益。相对 C，R3 稳态 CPU/p95 有收益，Rs 中位值较低但未满足分类；两组饱和有收益，PSS 仍约 C 的 2.1–2.2 倍。readiness 消除了无就绪空工作，上游 source socket、随机 ID、匹配、提取和发布仍有成本；[旧 syscall 归因](audits/M6B_UDP_MISS_KERNEL_ATTRIBUTION.md)证实逐 miss 的额外随机数读取和 socket 设置，但其旧身份/ptrace 不能量化最终 CPU，也不能把全部 system CPU 差归给这三次调用。 |
| DNS mixed | 相对原始两组，吞吐与 CPU/p95 均有收益，PSS 无显著变化。相对 C，两组稳态 p95 有收益，但 R3 CPU 无显著差异、Rs CPU 增 11.53%；饱和仅 R3 p95 有收益，吞吐/CPU 未分类；PSS 都增加逾一倍。机制是有界 UDP batch、completion 和 TCP/DHCP/TFTP/reload 共用公平调度；性能数值不证明无限 drain 可接受，相关健康资格由完整服务/资源门提供。最终 `main.rs::step`、[协议公平性合同](M6B_PROTOCOL.md)。 |
| Upstream fault | 每窗故障前/恢复无 timeout；30 秒故障段两组及 C 均零正确、各 600 timeout，CPU/正确和延迟为“—”。相对原始两组，故障前/恢复吞吐、p95 有收益；CPU 除 Rs 故障前因波动未分类外均有收益；PSS 无显著差异。相对 C，R3 故障前 CPU 和 Rs 恢复 CPU 有收益，其他 CPU/p95 中位差未通过 W；三段 PSS 均更高。ready/deadline 保留 retry/timeout/恢复边界，不能把故障段平均进健康吞吐。最终 `dns/upstream.rs` owner deadline/complete、正式 `upstream-fault` 分段 raw。 |
| TCP local | 相对 C，两组稳态 CPU/p95 有收益；饱和 CPU/p95 也有收益，但 R3 吞吐受限，且两组饱和 PSS 分别多 28.74%/22.26%。相对原始两组，稳态吞吐、p95、PSS 有收益，**CPU 增 19.65%/17.33%，属退步**；饱和 CPU/p95/PSS 则有收益。accept 固定 local/routing/lease/clock 视图，并共享不可变 cache 内容根，仍保留元数据与快照成本。这里不能把 M6a 原 CPU 20.139 µs 替换成 readiness 后 R3_new 作为“原始 Rust”；CPU45 用新基线的合入门单独成立。最终 `step_tcp_accept/tcp_cache_view`、[A CPU45](audits/M6B_A_7D3_CPU45.md)。 |
| TCP cache | 相对原始两组，稳态 CPU 降约 29.3%、p95 降约 99%、峰 PSS 降约 81%，吞吐提高到施加的约 10,000 QPS；饱和 CPU/p95/PSS 也有收益，吞吐仅记下限。相对 C，稳态 CPU/p95/PSS 均有收益；饱和 CPU/p95 有收益，PSS 虽较低但波动未达分类。共享 64-slot 内容块、canonical-name shard、有序索引，命中更新连接私有 LRU；写入/轮转 detach 保留父子隔离。最终 `dns/cache.rs/cache_name_index.rs`、[A 服务与资源合同](audits/M6B_TCP_A_SERVICE_RESOURCE_GATE.md)，完整最终资源资格由其独立收据证明。 |
| TCP miss | 相对 C，稳态两组吞吐约增 126%、CPU 降约 56–57%、p95 降 68.87–80.63%；相对原始两组 CPU 降约 30%、p95 降 89.24–93.07%、PSS 降约 44%，饱和同样有收益。**内存仍明显不足：R3 稳态 18,712 KiB / C 5,527 KiB＝3.386 倍，Rs＝3.353 倍；饱和 R3 为 C 的 4.671 倍。**新记录和父 churn 触发块/索引写时复制，老连接固定视图，导回按当前 owner local 发布检查冲突；这是机制说明，没有 allocator 栈证据时不能把残余 PSS 分摊到某个对象。原第4包没有执行。最终 `Cache` mutator、`ParentDns::import_tcp_cache_transfer`、独立 companion 容量/十批余额及 S8 收据。 |
| DHCP lease | 三组都保持 20 cycle/s、release 末态 leasefile 为空。相对原始两组，CPU 降约 92.13%、p95 降约 71.8%，PSS 未达收益幅度；相对 C，CPU 多 55.08%/58.39%、PSS 多 38.61%/23.50%，p95 无显著差异。每包 fresh 接口视图及 ACK 前 DNS-name 发布合同保留；事件分派去除周期空工作。[旧 DHCP trace](audits/M6B_DHCP_SYSCALL_GAP.md)只证明旧 `6f3bed3d` 的重复接口 ioctl/snapshot 计数，不能把已撤除周期扫描算作最终热点，或声称已把最终 262.7 µs/cycle 余差全部归因。 |
| Reload concurrent | 相对原始两组，吞吐约 464→1,000 QPS，CPU 降约 60.5–60.7%、p95 降约 99.79%，PSS 无显著差异。相对 C，CPU 多 80.81%/83.19%、p95 多 37.08%/34.25%、PSS 多 44.07%/28.81%，均退步。每组五轮各 11 次 reload、共 55 次全部正确，观测 publication 最大值 C/R3/Rs 11.962/12.027/12.726 ms；这是 10 ms probe 间隔加 controller gap 的上界，不是精确发布时间或 p99。共同 owner 先发布小文件再准入新 UDP/TCP，保留旧连接视图、大文件有界让出；额外 CPU 的具体比例未完全归因。最终 hosts/reload publication、`ParentDns` current-local 边界及正式 `reloads.json`。 |

波动规则确实影响结论：Rs 的 UDP-miss 稳态 p95 中位数比 C 低 30.31%，但 C 的 W 是 34.11%，所以仍是“无显著差异”；R3 恢复 CPU 比 C 低 23.39%，但 C 的 W 是 23.98%，也未分类。Rs 故障前 CPU 相对原始 s 低 37.23%，候选 W 38.07%，仍未分类。TCP-cache 饱和 Rs PSS 低于 C 10.68%，C W 30.43%，同样不宣称收益。没有更改工具原判词来抹去这些限制。

恢复段最大 success gap 五轮中位数为 C/R3/Rs **380.735 / 348.746 / 376.704 ms**；这是阶段内的描述指标，不新增显著性门，也不当成独立精确故障恢复延迟。

## RSS、FD 与执行形态


每格依次 C / R3 / Rs，均为各窗阶段峰值的五轮中位数。RSS 合计会重复计算 C 子进程共享页，因此总内存比较以前面的树 PSS 为准；树 thread 数包含各子进程线程，不能把 C 的多进程形态误写成单进程的多线程。


| 场景 / 阶段 | 树峰 RSS KiB | 峰 FD | 树 thread | child processes |
| --- | --- | --- | --- | --- |
| udp-hit / 稳态 | 1,632 / 3,300 / 3,112 | 11 / 12 / 12 | 1 / 1 / 1 | 0 / 0 / 0 |
| udp-hit / 饱和 | 1,632 / 3,300 / 3,112 | 11 / 12 / 12 | 1 / 1 / 1 | 0 / 0 / 0 |
| udp-miss / 稳态 | 1,664 / 3,720 / 3,512 | 15 / 18 / 13 | 1 / 1 / 1 | 0 / 0 / 0 |
| udp-miss / 饱和 | 1,664 / 3,728 / 3,532 | 19 / 14 / 14 | 1 / 1 / 1 | 0 / 0 / 0 |
| dns-mixed / 稳态 | 1,664 / 3,588 / 3,508 | 12 / 13 / 13 | 1 / 1 / 1 | 0 / 0 / 0 |
| dns-mixed / 饱和 | 1,668 / 3,592 / 3,532 | 12 / 13 / 13 | 1 / 1 / 1 | 0 / 0 / 0 |
| upstream-fault / 故障前 | 1,668 / 3,696 / 3,632 | 12 / 13 / 13 | 1 / 1 / 1 | 0 / 0 / 0 |
| upstream-fault / 故障 | 1,744 / 4,044 / 3,920 | 211 / 212 / 212 | 1 / 1 / 1 | 0 / 0 / 0 |
| upstream-fault / 恢复 | 1,744 / 4,056 / 3,932 | 211 / 212 / 212 | 1 / 1 / 1 | 0 / 0 / 0 |
| tcp-local / 稳态 | 30,228 / 3,820 / 3,628 | 631 / 32 / 32 | 21 / 1 / 1 | 20 / 0 / 0 |
| tcp-local / 饱和 | 18,804 / 3,820 / 3,628 | 324 / 32 / 32 | 14 / 1 / 1 | 13 / 0 / 0 |
| tcp-cache / 稳态 | 29,816 / 4,764 / 4,572 | 639 / 32 / 32 | 21 / 1 / 1 | 20 / 0 / 0 |
| tcp-cache / 饱和 | 23,792 / 4,764 / 4,572 | 465 / 32 / 32 | 17 / 1 / 1 | 16 / 0 / 0 |
| tcp-miss / 稳态 | 20,388 / 18,720 / 18,540 | 286 / 52 / 52 | 15 / 1 / 1 | 14 / 0 / 0 |
| tcp-miss / 饱和 | 13,440 / 18,740 / 18,556 | 165 / 52 / 52 | 11 / 1 / 1 | 10 / 0 / 0 |
| dhcp-lease / 稳态 | 1,676 / 2,320 / 2,068 | 53 / 58 / 58 | 1 / 1 / 1 | 0 / 0 / 0 |
| reload-concurrent / 稳态 | 1,660 / 2,388 / 2,136 | 13 / 16 / 14 | 1 / 1 / 1 | 0 / 0 / 0 |

## 真正 idle 与负载后保留量

135 个窗口都在负载前独立做了无负载 60 秒 idle；C/R3/Rs 的 daemon cgroup CPU 增量记录均为 **0 µs**，proc 交叉核对也为 0 tick（100 Hz）。这是实际账户记录，不表示数学上 CPU 消耗精确为零。三组均能长等待，未见周期空扫描耗 CPU；原始 M6a 没有同口径 idle 60 秒，因此相对原始 Rust 的 idle 改善百分比写“未测”。下面 idle PSS/FD 是五轮中位数，顺序仍为 C/R3/Rs；每组空载均一线程、零子进程。

| 场景 | idle 60 秒 CPU µs C / R3 / Rs | idle PSS KiB C / R3 / Rs | idle FD C / R3 / Rs |
| --- | --- | --- | --- |
| udp-hit | 0 / 0 / 0 | 1,624 / 3,292 / 3,104 | 11 / 12 / 12 |
| udp-miss | 0 / 0 / 0 | 1,648 / 2,148 / 2,024 | 11 / 12 / 12 |
| dns-mixed | 0 / 0 / 0 | 1,656 / 1,104 / 2,112 | 11 / 12 / 12 |
| upstream-fault | 0 / 0 / 0 | 1,656 / 2,148 / 1,016 | 11 / 12 / 12 |
| tcp-local | 0 / 0 / 0 | 1,656 / 2,152 / 2,024 | 11 / 12 / 12 |
| tcp-cache | 0 / 0 / 0 | 1,644 / 3,292 / 2,096 | 11 / 12 / 12 |
| tcp-miss | 0 / 0 / 0 | 1,652 / 824 / 1,144 | 11 / 12 / 12 |
| dhcp-lease | 0 / 0 / 0 | 1,668 / 1,648 / 1,348 | 53 / 58 / 58 |
| reload-concurrent | 0 / 0 / 0 | 1,652 / 2,376 / 2,124 | 13 / 14 / 14 |

负载发生器退出后，测量器等待“无存活子进程且 daemon FD 数回到负载前 idle 数”，连续三次样本稳定后记录 barrier。**实际采样锚点是 barrier 完成时刻**，下表 0/1/5/60 秒均从该时刻计，而非严格从 loadgen 结束计；barrier 自身额外等待保留在每窗 result 中。本批 barrier 等待范围为 0.040808–0.062306 秒。feature-off 产品的 clients/view/pending/pins/live-requested-bytes 没有导出，不能声称这些逻辑计数已实测归零；正式窗口实际使用的是 FD 数稳定后备判据。资源 companion 的计数资格另按其独立 SHA 和收据报告。15 秒没有采样，不由 5/60 秒插值。

| 场景 | 0 秒 PSS C / R3 / Rs | 1 秒 PSS C / R3 / Rs | 5 秒 PSS C / R3 / Rs | 15 秒 | 60 秒 PSS C / R3 / Rs | 0/1/5/60 秒 FD C / R3 / Rs |
| --- | --- | --- | --- | --- | --- | --- |
| udp-hit | 1,624 / 3,292 / 3,104 | 1,624 / 3,292 / 3,104 | 1,624 / 3,292 / 3,104 | 未采 | 1,624 / 3,292 / 3,104 | 11 / 12 / 12 |
| udp-miss | 1,656 / 3,720 / 3,524 | 1,656 / 3,720 / 3,524 | 1,656 / 3,720 / 3,524 | 未采 | 1,656 / 3,720 / 3,524 | 11 / 12 / 12 |
| dns-mixed | 1,660 / 3,584 / 3,524 | 1,660 / 3,584 / 3,524 | 1,660 / 3,584 / 3,524 | 未采 | 1,660 / 3,584 / 3,524 | 11 / 12 / 12 |
| upstream-fault | 1,736 / 3,980 / 3,916 | 1,736 / 3,980 / 3,916 | 1,736 / 3,980 / 3,916 | 未采 | 1,736 / 3,976 / 3,916 | 11 / 12 / 12 |
| tcp-local | 1,660 / 2,292 / 2,100 | 1,660 / 2,292 / 2,100 | 1,660 / 2,292 / 2,100 | 未采 | 1,660 / 2,292 / 2,100 | 11 / 12 / 12 |
| tcp-cache | 1,648 / 3,256 / 3,064 | 1,648 / 3,256 / 3,064 | 1,648 / 3,256 / 3,064 | 未采 | 1,648 / 3,256 / 3,064 | 11 / 12 / 12 |
| tcp-miss | 1,656 / 11,140 / 11,144 | 1,656 / 11,140 / 11,144 | 1,656 / 11,140 / 11,144 | 未采 | 1,656 / 11,140 / 11,144 | 11 / 12 / 12 |
| dhcp-lease | 1,668 / 2,304 / 2,052 | 1,668 / 2,304 / 2,052 | 1,668 / 2,304 / 2,052 | 未采 | 1,668 / 2,240 / 2,052 | 53 / 58 / 58 |
| reload-concurrent | 1,652 / 2,380 / 2,128 | 1,652 / 2,380 / 2,128 | 1,652 / 2,380 / 2,128 | 未采 | 1,652 / 2,320 / 2,128 | 13 / 14 / 14 |

这些后置点各组均一线程、零子进程，FD 已稳定回到对应 idle 数。TCP-cache 的 R3/Rs 保留 PSS 为 3,256/3,064 KiB；TCP-miss 为 **11,140/11,144 KiB**，60 秒也没有降到 3–6 MiB 的断连目标范围。TCP-miss 稳态峰值 18,712/18,532 KiB 也超过 8–16 MiB 目标。目标未达到和 FD 回收通过须同时保留，不能把后者当成内存目标已经关闭。

原始 M6a 的所谓“排空后”12–29 MiB 使用旧 child-count 判据，Rust 没有 C 的 TCP 子进程，故只算“负载后、排空证明前”读数；本轮不能拿这些旧值算新的排空改善百分比。allocator 未知余量未由正式产品直接测量，不能把 PSS 与 companion live bytes 的差额全部命名为 allocator 碎片。

## 体积与是否切换 s

s 比 opt3 小 **323,584 B（16.46%）**，但仍是 C 的 **6.099 倍**。相对原始 M6a，opt3 增加 36,864 B（1.91%）、s 增加 28,672 B（1.78%）。这是 ELF 体积，APK 压缩容器与 payload 大小另列，不混为一项。

最终五轮不支持把 s 作为整体性能改善：相对 opt3，s 在 UDP-hit 饱和 CPU/p95 增 14.44%/13.95%，正确吞吐降 12.67%；UDP-miss 饱和 CPU/p95 增 13.23%/11.88%、吞吐降 11.59%；DNS-mixed 饱和 CPU 增 11.71%、吞吐降 10.42%；TCP-local 饱和 CPU/p95 增 13.27%/14.11%；TCP-miss 稳态 p95 增 **60.70%**，饱和 CPU 增 12.35%、吞吐降 10.93%，这些按同批 W/4-of-5 规则均为退步。s 的 DHCP/reload 峰 PSS 分别降低 10.90%/10.59%而有收益，其余内存变化多未达分类幅度。

从性能取舍看，交付默认保留 opt3 更合适；完整功能、资源、APK 资格分别以统一验收的最终收据为准。s 是同源体积/性能对照，没有单独跑完整功能资格；若用户更重视少 316 KiB 的 ELF，切换取舍还需明确接受上述延迟/CPU 代价。本轮不自动切换 s，不进入 M7 真机，也没有执行第 4 包的进一步瘦身。

## 机制诊断与未测边界

原始每轮每 listener 一次 `step_udp`、单包接收和新 65,535 B Vec 来自固定旧源码；Linux 原来已有网络 fd，不把非 Linux 的 `park_timeout(2ms)` 当成 Linux 真实原因。原始 465 QPS 与约 43 ms p95 是真实正式观测；用户取消了旧版本仅加计数构建，因此旧 loop/poll/wait/batch/allocation counters **未实测**。

修后历史独立诊断 `diag-6f3bed3d` 有 27 个已归档 strace 窗口，按 warmup＋load＋稳定 drain 的正确数摊销；其 syscall 完成数保留 unfinished/resumed 与精确 errno。UDP-hit C/R3 calls/correct 为 3.000/2.214，TCP-local 3.519/2.372，reload 3.559/5.036，DHCP 81.176/317.012；两 TCP 场景 Rust 的 EAGAIN 为 0。这些只用于旧修后机制归因，不属于最终 `889fe4f5` 的未插桩 CPU/延迟。旧 DHCP 的周期扫描随后已撤除，不能把旧 71,145 次额外 ioctl/snapshot 或 88.73% 调用占比写成最终 CPU 分布。其 scope 与身份见 [trace 合同](audits/M6B_TRACE_CONTRACT.md)、[DHCP 余差](audits/M6B_DHCP_SYSCALL_GAP.md)。

最终 135 的 `wake_counters.available=false`，正式产品没有 loop/poll/wait/batch/allocation counter、perf 栈或 strace；缺失写未测，不能从 QPS 推算后冒称计数实测。最终同源资源 companion 的容量/live bytes/对象余额证据可解释内存结构，但仍不能替代产品 CPU/latency。剩余 UDP-hit、reload CPU 和 TCP-miss 保留内存的完整函数/allocator归因未完成；这里的源码机制说明及旧 trace 线索不声称这些余差已经解决。

## 可追溯索引

`E = private/dnsmasq-rewrite/evidence`。正式五轮原始入口统一为 `E/M6B/final-889fe4f5/formal135/archives/r{01..05}-<profile>-{c,r3,rs}/attempt-1/plain/formal/`；逐阶段数值由 `analysis.json.windows[].phases[]` 给出，各窗口 `input_sha256` 绑定原始输入，归档索引再绑定 tar、manifest 及 metadata 核验。原始 M6a 有效 attempt 只按其 state 选，十五个首轮 TCP/DHCP/reload 窗选择 attempt-2，其余 attempt-1；没有挑最快 attempt。

| 索引 | SHA256 |
| --- | --- |
| 最终 `formal135/analysis.json`（C/R3/Rs、663 比较） | `9bdbdb9aa6f145220e353f505a0568439a45bdfc3ab6543aaa7362df6a042b52` |
| 最终 `formal135/original-rust-comparisons.json`（272 同 opt 前后比较） | `4bbc3f79ff65004b202fd8619d6fb8070bbe5b8c7bdf91fadba3124250550da6` |
| 最终 `formal135/manifest.json` | `667f6bd2e1f72b8ba22c908af3e06810eaca8074f5c0e4c61210a5d2e80a6099` |
| 最终 `formal135/state.json` | `dab725c0244e37f0e67178e6a8d1dbdd02e64d641c5041d4bec87d4c8efd2aef` |
| 最终 `formal135/archive-final-index.json` | `63d39a96b5216123485c25365fdb32fda0d51e9085952bc2f67f91d609cd22c1` |
| 原始 `E/M6A/freeze-c3402ba6/final-analysis.json` | `1f7184f9ca29fca6d9151db612de802ad9e2427ea6f680e87216e50ca7c8eeed` |
| 原始 `E/M6A/freeze-c3402ba6/manifest.json` | `885d7eda6fcec0e7b057682c7798a09dda67a9dfc2300b8d898cfb15c3d50f40` |
| 原始 `E/M6A/freeze-c3402ba6/state.json` | `1c6b74ad73156ff3a4529b28240f8653d2d6c0e991983ffca76dd8a3b4361fc0` |

旧诊断、A CPU45 和各次产品失败/作废的具体索引沿用相应审计文档；它们均不换绑到最终 ELF。最终功能、资源、guard、APK 和清理收据见下文。

## 功能与 targeted 的统一资格

最终 feature-off opt3（源码 `889fe4f5c59da514529e31173d346ec93bae03a9`，ELF `791a7c33987fbb21887c51041f27722b9cc1bd8bd4cffab0fc03a292517fb10f`）从第 1 步完整重跑，44 族、68 步、169 选项 CLI/file 形式全部闭合。完整 M2 的十个 jobs 通过：七种 DNS profiles、四种 DHCP profiles 作为一项套件、C/R 各一项生命周期。独立 targeted 十六 jobs 全通过，包含 route basic/clears、accept snapshot、feature-off lease-held-import 各 C/R/compare，以及 same-wake、interface-idle、membership fault、interface ACL。无新增产品差异；普通与 targeted 实际使用同一个最终 ELF，旧 `284376c4` 的十三步没有沿用。族级完整收据见 `acceptance-archives/m6b-final-hosts/plain/aggregates/families/result.json` 与 `completed.json`，独立关闭依据为 `preflight/functional-completion-01.json`。

方法原红没有改绿：INFORM 600/599 秒用 pre-request raw expiry 与各侧请求整数秒见证，只归一 option51；hosts 大文件完成以新记录发布且当前 FD 关闭为准，保留 1 MiB、8 秒及 while-open 健康合同；AArch64 membership 注入原工具把跳过后的 x0 错认成 -ENOSYS，修订后严查 syscall200→-1 的实际 regset 读回及 `actual_result=entry_x0=fd`，EPERM 同 fd group-zero bind/getsockname 成功，EINVAL 无 fallback 且 startup 退出5。各项原红、唯一原参确认和独立工具 fresh 整族/两侧两 errno 结果全部保存，冻结产品未修改。新功能收据显式引用旧 post status SHA，不把旧失败 status 覆写成通过。详见 `audits/M6B_FINAL_METHOD_CORRECTIONS.md`。

## 完整资源矩阵和压力

资源控制器全部 **43 jobs** 返回0并 passed；15个 collector（public1、内部9、交错3、S8两项）各自规定的资格都通过。这里的43包含构建、controls、执行和收集，不是43种压力场景。public 的 `qualified=false/internal_balance_qualification=false` 是公开观察无法导出内部余额的范围标记：真正 public 门 `public_resource_gates_passed=true`，11 profiles 无缺项、零语义差异。内部、交错、S8 的资格来自同源独立 diagnostic ELF `91e44adaab18b552531f9389c00aed1e0df150d53c27fec99fd8bf0e97f9a0aa`，不能拿它的 CPU/PSS 充当 feature-off 产品数据。

固定范围实际完成如下：public11 × C/最终opt3；reconnect容量0/1/150/4096/16384、half4096、multi-RR4096、limit30/150，各warm＋10批；pin150/150单项；三个交错profile各C/companion配对并warm＋10批；S8 recover warm＋10批与独立TERM；目标musl layout与六方法controls；canonical mixed300/fullcache300与两侧ENOSPC/EMFILE。没有额外600秒、reconnect-count归因或旧m3_pressure_exact。

### 最终 feature-off 产品：公开 TCP 的真实排空

public11 覆盖100-query关闭、半帧、RST导回、upstream EOF、慢写、慢读、20/30连接、约150秒旧根存活以及容量0/150/4096的十批重连。每侧检查答案/正常退出和自身确认的 idle FD 集合；不能把“Rust无子进程”当排空充分条件。下表为树PSS（KiB），各五点顺序严格为 **0/1/5/15/60秒**，没有插值。峰值仅指这些固定资源夹具实际采样，不是正式性能上限。

| public profile | 采样峰PSS C / Rust | 排空PSS C（0/1/5/15/60） | 排空PSS Rust（同序） | 排空FD C / Rust |
| --- | ---: | --- | --- | ---: |
| 100-query | 758 / 1,940 | 758/758/758/758/758 | 1940/1940/1940/1940/1940 | 13 / 11 |
| half-frame | 758 / 1,876 | 758/758/758/758/758 | 1876/1876/1876/1876/1876 | 13 / 11 |
| rst-forward-import | 762 / 1,940 | 762/762/762/762/762 | 1940/1940/1940/1940/1940 | 13 / 11 |
| upstream-eof | 762 / 1,948 | 762/762/762/762/762 | 1948/1948/1948/1948/1948 | 13 / 11 |
| slow-write | 722 / 1,940 | 722/722/722/722/722 | 1940/1940/1940/1940/1940 | 13 / 11 |
| slow-read | 1,007 / 2,252 | 814/814/814/814/814 | 2144/2144/2144/2144/2144 | 13 / 11 |
| capacity-20-30 | 2,536 / 2,140 | 760/760/760/760/760 | 2036/2036/2036/2036/2036 | 15 / 13 |
| idle-pin-150 | 720 / 2,000 | 720/720/720/720/720 | 2000/2000/2000/2000/2000 | 13 / 11 |
| reconnect-0 | 1,988 / 2,056 | 728/728/728/728/728 | 2000/2000/2000/2000/2000 | 13 / 11 |
| reconnect-150 | 2,023 / 2,252 | 756/756/756/756/756 | 2176/2176/2176/2176/2176 | 13 / 11 |
| reconnect-4096 | 2,507 / 4,696 | 1258/1258/1258/1258/1258 | 3364/3364/3364/3364/2724 | 13 / 11 |

11项均在排空后回自身idle FD集合，0子进程、单线程；容量20/30的idle集合是C15/Rust13，其他是C13/Rust11。Rust重连4096从空闲2,224 KiB，经十批采样峰4,696 KiB，最后0–15秒3,364 KiB、60秒2,724 KiB；C对应空闲1,254、峰2,507、排空1,258 KiB。FD回收与较慢的驻留页回落分别报告，不据PSS残留直接判内存泄漏，也不由内部余额相等推断allocator已返还全部页。

### 同源 companion：warm 后的十批余额

先经过一批结构warm，之后每一批真正关闭连接、排空，再与warm后的固定父状态逐项相等。内部8组×10批的live requested bytes（扣observer registry）、live object、content/index root版本及各缓冲容量都精确回基线；final同样相等。所有排空点client/view/DNS work、pending transfer、旧pinned roots和private roots为0；trace无missing hook、balance error或alloc failure。不能把非零父cache根数写成泄漏，也不能声称整个进程的bytes归零。

| 内部 profile / capacity | 实际批次 | warm/final live B（扣registry） | live objects | content/index版本 | 每批和final余额 |
| --- | --- | ---: | ---: | --- | --- |
| reconnect-0 | warm＋10 批 | 174,992 | 176 | 0/64 | 相等 |
| reconnect-1 | warm＋10 批 | 178,791 | 210 | 1/64 | 相等 |
| reconnect-150 | warm＋10 批 | 219,062 | 847 | 3/64 | 相等 |
| reconnect-4096 | warm＋10 批 | 1,359,216 | 16,755 | 64/64 | 相等 |
| reconnect-16384 | warm＋10 批 | 4,986,288 | 66,291 | 256/64 | 相等 |
| half-4096 | warm＋10 批 | 944,656 | 8,563 | 64/64 | 相等 |
| multi-rr-4096 | warm＋10 批 | 1,262,096 | 18,803 | 64/64 | 相等 |
| limit30-150 | warm＋10 批 | 219,318 | 847 | 3/64 | 相等 |
| pin150-150 | warm＋pin 149.999s / 140 次父替换 | 219,062 | 847 | 3/64 | 相等 |

pin150是一个独立约150秒场景，**不是10批**：149.999秒、140次父记录替换期间，旧连接保持1个view及旧content根；自然到期后排空，live/object/root余额回warm基线。limit30每批确实同时保留30个独立view并验证第31连接边界；其余常规内部批是20连接。

表中live仅是同源diagnostic里的系统分配请求计数扣去observer registry，不是最终产品PSS。registry有效capacity只是插入容量下界；实际请求bytes和对象/root数才是余额合同。每个collector保留损坏证据负控；六个实际controls验证System alloc/realloc/free、failed realloc保留原对象、registry分配作用域、snapshot/detach跟踪、漏hook检测和地址复用creation stamp。目标musl layout匹配。allocator内部碎片/保留页以及C的同类内部计数均未测，不用`PSS-live`倒算精确allocator余量。

### 交错：held upstream 与 parent publication

lease-held-import、reload-held-import、staggered-conflicts都实际配对C报文，每组warm＋10批。held时pending transaction、旧view/root确实仍存活；随后租约/reload/current-parent冲突判定、老连接固定视图、新连接可见性和导回顺序均按固定合同检验。每一批最后live/object/root/capacity都回warm基线，没有选择最快或最干净的批。

| 交错profile | warm/final live B（扣registry） | live objects | content/index版本 | 最后0/1/5/15/60秒live B |
| --- | ---: | ---: | --- | --- |
| lease-held-import | 139,104 | 227 | 3/64 | 139096/139104/139104/139104/139104 |
| reload-held-import | 108,498 | 189 | 3/64 | 108918/108498/108498/108498/108498 |
| staggered-conflicts | 116,543 | 190 | 3/64 | 116543/116543/116543/116543/116543 |

交错lease的0秒比稳定基线少8B、reload的0秒多420B，是采样时刻的短暂scratch分配差；从1秒开始以及十批关闭markers均精确回基线。各0/1/5/15/60点的逻辑owner工作与pins已归零，不能把“工作已排空”改写为“每个采样时刻所有临时bytes完全相同”。companion在这些夹具的PSS只作诊断上下文，不给最终产品内存资格。

### S8：DNS owner先释放，日志槽后释放

recover实际warm＋10批，不是把包括warm的11个记录称为11批。满FIFO时每轮从一个DNS活view进入仅日志槽：clients/G保留1，DNS work/view/pending/pinned/private roots已归零。扣registry的log-only live为117,537 B，日志payload容量1,024 B、queue容量160 B；放行sink后live恢复116,353 B、对象/root/capacity回warm基线。最后0/1/5/15/60秒owner均归零且live同为116,353 B。

独立TERM在sink从未释放且真实FIFO仍满时正常有界退出，五个0/1/5/15/60秒post-exit观察均无运行进程/FD。进程退出后没有heap样本：不能把它写成“live bytes测得0”。S8采用同源诊断并保留已知非阻塞FIFO差异，它不是C配对的feature-off产品CPU/PSS或功能替代门。

### canonical300和故障恢复

mixed300双方同seed、20clients实际各满300秒，工作计数完全相同：20 DORA、41 renew、44 rebind、20 release、1 decline、164 UDP DNS、51 TCP DNS。expiry/static/ethers/restart/failover此短窗口计数为0，不宣称它们在本窗口被执行。两侧停止后daemon/ubusd退出、leasefile为空、DHCP/TCP/UDP sockets关闭。末四分之一RSS C1,688/Rust2,488 KiB；Rust第三至第四分位中位数增加12 KiB，五分钟没有资格证明长期无增长。FD分别17/19、单线程、无子进程。

fullcache300固定4,096条短名字单A、TTL3600；禁用upstream回答后，初末两次完整scan均4,096正确命中且upstream请求0，300秒各完成19,200查询。C empty→filled RSS1,564→1,568 KiB；Rust2,160→3,288 KiB，末窗口RSS3,032 KiB，仍为C **1.934倍**，差1,464 KiB。Q3/Q4 RSS中位数均无增长，Rust的-256KiB变化全部对应file RSS，anon RSS保持1,572 KiB。停止双方正常exit0、不需forced kill。工具accepted只覆盖收集、满cache证明和清理，`resource_review_required=true`没有被抹掉；上述驻留差距明确保留。按RSS差/4096得到的填充增量不是单entry实际allocator bytes，C预分配成本也不能因此宣称只有1B/entry。长名字、复杂RR、CNAME和negative不在这个canonical单A内存合同内。

ENOSPC与EMFILE都分别在C和最终opt3实际通过：16KiB受限空间满时DHCP仍ACK、无durable lease；空间释放后重试恢复租约，C60.041秒/Rust60.290秒。EMFILE把soft limit设为各侧当时open数C13/Rust18，服务保持活着、压力下无回复，解除后回答恢复。四个故障run停止后exit0、无daemon/pid/lease残留。参数300秒是**每侧deadline**，不是故障暴露时长；本批总elapsed122.331秒，绝不能写成两侧各连续施压300秒。没有新增门或扩大压力边界。

## 历史修复：为什么169/0之后仍会发现回退

UDP回退首次引入main **`e8b1d6c411fba324888e3e202c0c133156afbed4`**，属于M6b循环改造的live-ingress caller批，非方案A共享cache。旧`admit`已实现接口限制非空时隐式允许loopback；新`udp_acl_name`旁路旧规则，`interface=lan`时丢弃未显式列出的127.0.0.2。C按`network.c:501`把loopback加入允许集。原M5 169/0与listeners绿属于旧真实caller；新caller测试仅`interface=lo`，没有覆盖其他接口列表下的隐式允许。第一次冻结284376c4在listeners第14步发现14 profiles/28 failures，原参只确认一次，先停才获授权修复。

`3492bbde`从已有admit提取共用`name_allowed`，selected、UDP live-name、TCP和旧admit复用；实际main UDP读取flags，真实`step_udp`收包/回答测试覆盖其他接口列表、空条目、明确地址及显式排除，保留真正failed-ACL的alias collector续步。

随后跨协议检查确认普通TFTP IPv6纯改名缺陷：`port=0/interface=lan`、wildcard、非loopback、普通enable-tftp、无dedicated名字列表，`lan→retired0`且地址/index不变后，C拒绝、旧Rust按快照lan继续DATA。名字来源最初不一致在M5 **`86e31143`**，M6b **`2c28df782c88799d2da297fd2a2aa136ba2738e6`**删除周期owner扫描且没有link触发，使旧代持续。既有`tftp-static-renamed`只测静态IPv4 cached-owner/dedicated的有意兼容分支，因此漏掉普通IPv6。历史归因来自逐提交源码因果核对，**未做历史ELF bisect**。

用户授权一并修TFTP，只准复用现有共享owner collector且1小时止损。`8bd80024`复用live-name准入、原包单槽和既有`enumerate_interfaces(true)`收集续步，完成后继续原MAC/dispatch；`889fe4f5`只修新测试Rust字节转义。授权17:52:45 UTC，18:05:52 UTC已完成Linux真实caller及精确C/新opt3改名配对，约13分钟，未触发UDP-only止损。Linux main74、lib753、新TFTP main caller3、既有TFTP socket3通过；20 ignored不计。最终同ELF普通/targeted完整验收再关闭运行资格。DNS-TCP、DHCP检查未见同类路径不一致；依用户要求没有继续扩大跨协议审查。

无关health合并`16ac3cea`没有修改dnsmasq输入，旧冻结284本应继续有效；真正更改产品、要求重验收的是之后授权的UDP/TFTP修复。最终报告保留284停点，统一产品身份889，而不是后来只含工具/文档改动的HEAD。

## 证据入口

下列路径相对F。完整资源raw在`acceptance-archives/resources-final-02/plain/`，每个internal/交错/S8目录含markers、trace、run receipt和`*-result.json`collector；公开product数据在public C/R目录及public-comparison。canonical/压力在`acceptance-archives/m6b-final-hosts/plain/runs/{resources,pressure}/attempt-1`。所有10个前置acceptance archive都已完整metadata验证，原tar/manifest/local-verification/prune保留；plain为可离线读的实际归档数据，不是准备计划。

| 证据 | 路径 | SHA256 |
| --- | --- | --- |
| 功能完整关闭 | `preflight/functional-completion-01.json` | `262354cecafd2443ad8d17c4a795dffd138ffe551e98406070e7ebec85d0667a` |
| 资源43 jobs | `acceptance-archives/resources-final-02/plain/controller-status.json` | `05036cb7769c655583ee941621fde31eb6ab6036a5607baa329e76fd23a4d45e` |
| public11 C/R 比较 | `acceptance-archives/resources-final-02/plain/public-comparison.json` | `61ea938060e8d6db652aba17f0861bffd1f4048b8f77f140a75c9dfc5e6743f0` |
| 六方法 controls | `acceptance-archives/resource-method-controls/plain/controls.json` | `a23b788f574abb7b3e116108fc2a369e2fe14450a7612ab03294e16378e1717a` |
| mixed300 | `acceptance-archives/m6b-final-hosts/plain/runs/resources/attempt-1/mixed-300/result.json` | `4913195fcefaca5db701cb4cb070acd960b4b7a6785e5f738e46db98553f078e` |
| fullcache300 | `acceptance-archives/m6b-final-hosts/plain/runs/resources/attempt-1/full-cache-300/result.json` | `376763d30251d32275bcd29c05a7d1316e23f69ee994e6b8f9cc3ae3aa2ac094` |
| ENOSPC/EMFILE | `acceptance-archives/m6b-final-hosts/plain/runs/pressure/attempt-1/enospc-emfile/result.json` | `7053bbf44cfccf9c3b974d09efe5f9ea04094d162d81d9176175a93ac5102cb4` |
| 归档总索引 | `preflight/acceptance-archives-index.json` | `3bf70f428aeb7e1765b4d3bab0aecb8c9248e7dee51841db1f351f5c3c0f297d` |

修复历史/范围依据：`audits/M6B_UDP_LOOPBACK_REGRESSION_HISTORY.md`、`M6B_INTERFACE_ADMISSION_REVIEW.md`、`M6B_FINAL_FREEZE.md`；旧284失败归档与UDP/TFTP修复raw保留于各原身份private根。方法详情及原红入口：`M6B_FINAL_METHOD_CORRECTIONS.md`。10个归档总字节279,446,557，其中resources-final-02 archive45,156,366 B、117,555 entries，manifest SHA `9f40a72e4b584535b64037c14a4cd53e11b74b4966d7f5ba58aed38d4de4fc42`，archive SHA `c261299e86afb0a276e5eb6c87aa31b73ca88b36333a86ea2ab63e890fcd2b6f`；只留已验证证据后才退役原目录。


## 性能保护门与可替换 APK

在读取135结果前，以文档提交 `5e9fb5bc` 固定阈值算法，避免见红后提高 cap：UDP p50保持1 ms；idle取最终R3五轮60秒 cgroup增量高点加 `max(25%,10 ms)`、向上到1 ms；TCP cache取五轮steady树PSS高点加 `max(25%,256 KiB)`、向上到64 KiB。实际高点为idle 0和PSS4880 KiB。最终计划SHA为 `c074047addae2f6cf9f714b38ca9d06871b308ad7995569f56a25898dd82ad28`，已写入 [工具冻结计划](../../tools/dnsmasq/m6b_perf_guard.final.json)。这只是低成本保护线，不替代正式W/4-of-5判定。

| guard | 最终 cap | 实际观测 | 判定 |
| --- | ---: | ---: | --- |
| 20客户端UDP hit p50 | 1,000,000 ns | 23,480 ns | 通过 |
| 独立无负载60秒CPU | 0.010 s | 0 s | 通过 |
| 确定hold20及短窗峰PSS取较大者 | 6144 KiB | 4880 KiB（hold20为4872） | 通过 |

实际warm/load回答全部正确、20客户端二进制latency覆盖、4096动态A逐名cache证明、FD+20、单线程无子进程、稳定排空和正常退出均通过。plan晚绑定到原功能manifest，没有修改已冻结工具树或产品；完整结果在 `F/acceptance-archives-final/m6b-final-hosts/plain/runs/perf-guard/attempt-1/`。

最终可替换包为 **dnsmasq-2.93-r3.apk，1,085,625 B**，SHA256 `8df2e454151ac09aad64630bf4d8b5f95fcf415c6f65a96a010e923ad0c59a01`。[APK](../../private/dnsmasq-rewrite/evidence/M6B/final-889fe4f5/apk/dnsmasq-2.93-r3.apk)。实际 `/usr/sbin/dnsmasq` 载荷SHA逐字等于最终opt3，打包不重新codegen或strip，SDK recipe已恢复。builder因原预算ELF≤1,000,000 B、APK≤700,000 B返回原红 `size-target`；其身份资格通过，外层仅允许继续生命周期，不把体积目标改绿，也不授予用户接受新增体积。APK比原M5 r2增加20,554 B（1.93%）；本轮实际stock C APK为155,123 B，最终APK是其6.998倍，多930,502 B，大小与SHA由实际生命周期输入归档核验。

镜像rootfs实际完成以下14阶段，执行的是安装后的 `/usr/sbin/dnsmasq`，不是辅助Rust路径。每个安装状态均核APK数据库、实际ELF、UID/GID453、文件权限／配置、stock init/procd/ujail调用和DNS回答；升级后明确operator restart，不冒称post-upgrade自动重启。

| 序号 | 生命周期 |
| ---: | --- |
| 1–4 | stock r1→r3升级、r3同版reinstall、卸载保留修改配置、fresh安装／账户重建 |
| 5–8 | 再卸载、移除后stock回滚、再升级r3、直接stock降级 |
| 9–11 | stock→原M5 r2、原r2→r3真实升级、直接降回原r2 |
| 12–14 | 原r2→r3、卸载r3、移除后原M5回滚 |

原M5 r2 APK固定SHA `bfed44ea…`、原ELF `37f85d22…`、原源码 `dc1b740d`，没有重建旧包。两variant与五依赖仅做互斥solver模拟，不安装；数据库不变、最终退出／unmount／cleanup均通过。七阶段统一summary为 `functional_validation_passed=true`、`missing_phases=[]`；独立135已完成，不以功能summary的范围字段代替性能证据。

## 体积、未达标项与未执行范围

- 最终opt3 ELF **1,966,120 B，是C269,305 B的7.3007倍**，比原Rust opt3增加36,864 B（1.91%）。同源s为1,642,536 B，仍是C的6.0992倍；比opt3少323,584 B（16.46%），比原s增加28,672 B（1.78%）。ELF与APK都未达到原体积目标。
- **TCP未命中稳态峰PSS约C的3倍**：R3 18,712／C5,527 KiB＝3.386倍；饱和为4.671倍。cache峰满足4–7 MiB目标，miss未落入8–16 MiB目标；miss真实排空后R3仍11,140 KiB，60秒不降，断连3–6 MiB目标也未达到。第4包没有在本轮继续实施。
- 相对C，UDP-hit的CPU／p95、DHCP CPU、reload CPU／p95退步；相对原始Rust，TCP-local稳态CPU增加19.65%。fullcache300的末Q4 RSS为Rust3032／C1568 KiB，保留 `resource_review_required=true`；300秒内后半程无增长不能外推长期稳定。
- s节省体积并降低部分PSS，但多场景CPU和饱和吞吐落后opt3；其较低p95中位数常未通过W分类。s没有完整功能／APK资格，本报告不直接授权切换。

保留行为差异包括单owner未排空FIFO／有界PCAP、TFTP scoped link-local IPv6、第二空conf-file安全诊断、version的Rust归属、log-malloc只接受/startup/--test而未复刻地址／函数／尺寸日志，以及超范围TFTP/PXE、无效synth PTR、负IPv6 prefix的安全拒绝。各项C参考位置与理由仍以 [M5行为差异](M5_BEHAVIOR_DIFFERENCES.md) 和原族报告为准，不把故意差异写成新增普通回退。异常collector晚期error未运行注入；C内部view/pins/requested计数、原Rust同口径idle60／真实排空、最终产品loop/poll/wait/batch/allocation counters、完整allocator栈归因均未测。**M7真机、第4包未执行**，不作生产部署结论。

## 失败、归档与退役

两个普通产品缺陷均先停止、取得用户授权后修复并重新冻结。UDP/TFTP提交归因、实际caller测试与1小时止损结果见上文。方法红包括INFORM整数秒相位、hosts结束观察、AArch64注入返回值预期及归档恢复清单E2BIG，原红与唯一原参数确认全部保留；修订后fresh跑受影响完整范围，不挑最快／最好的attempt。APK体积红为真实未达标，不复跑。见 [完整方法记录](audits/M6B_FINAL_METHOD_CORRECTIONS.md)。

前置10目录250,884条目、279,446,557 B，正式135原tar共3,832,502,072 B，全部本地SHA与类型／mode／uid/gid／纳秒mtime／链接／device／xattr验证通过；plain只是普通文件副本，原PAX tar保留。最终guard／APK／生命周期及控制器收尾另保存在 `F/acceptance-archives-final/`；最终索引将同时绑定所有归档及summary。

**清理已经完成：43棵worktree、9条任务分支退役。** 包括32棵10/01 detached旧树、5棵route、4棵A、2棵其他detached；每个exact tip先保存为 `archive/dnsmasq/m6b-final/20261009/<tree>-<sha12>` tag。全部ignored/private与四个target缓存以43个PAX归档保全，共36,621条目、1,482,019,483 B；每个文件SHA、类型、mode、uid/gid、纳秒mtime、symlink／hardlink均核验，xattr以base64保存在manifest与PAX扩展中，不跟随外部链接。源未变才删除原树；pycache单列可重建缓存。Git剩6棵受保护树、18条branch，既有archive refs保持。

四棵dirty树 `stale-work`、`resume-send-retry-20261001`、`m6b-resource-measurement-counters`、`owrt-m2-integration` 的HEAD／status／修改内容SHA保持；`hotfix/health-20261008-r3` 与 `owrt-health-r3` 未动，11项prompts内容SHA不变。原始资料全在private，物理路由器与Oracle常驻服务未操作。

| 最终收尾证据 | SHA256 |
| --- | --- |
| [全部交付／归档总索引](../../private/dnsmasq-rewrite/evidence/M6B/final-889fe4f5/final-delivery-index.json) | `81ea618a1c5ed5d5d8ecdce379ad30f82930dbc2becd51a0e3b9588d455dfc59` |
| [43树保全与tag退役索引](../../private/dnsmasq-rewrite/evidence/M6B/final-889fe4f5/cleanup-archives/retirement-index.json) | `f7008b55bdeb21a29e983a6f60d87e666b34f09c943656a1ace77f35e38c1293` |
| [清理后的保护对象核验](../../private/dnsmasq-rewrite/evidence/M6B/final-889fe4f5/preflight/cleanup-final-closeout.json) | `7d9f50ce22ecccd850af5ce7761dba24211b7a00e248ee1337468c8b88a8c54f` |
| [七阶段统一summary](../../private/dnsmasq-rewrite/evidence/M6B/final-889fe4f5/final-summary/summary.json) | `f0d71182b5ad4460667f12deef7e7a8877c272bf594ecf35d1aa36ebefd53a1b` |
| [最终归档后Oracle依赖与现场核验](../../private/dnsmasq-rewrite/evidence/M6B/final-889fe4f5/preflight/final-oracle-closeout.json) | `178b8ec4a27b380604d7c6bdddcb88416eca2bad8742f3df5f243060f74a6fa0` |

后置门实际再次核对最终产品／所有输入assets以及families、M2、guard、资源、压力、package、lifecycle七阶段的完整收据，全部通过。可替换APK与报告已经交付；本轮不进行s切换、M7或第4包，后续范围等待用户另行决定。
