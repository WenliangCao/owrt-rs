# LOGD 下一轮研究与收尾

日期：2026-09-28。源码提交：`386771659d127c20386b59614d3a82e0406f1e84`。

本轮从 R94 的现有实现开始。R94 已有 arena 环、模板帧、批量 pipe、burst-spin 和有界慢读者队列；AX3000T 上两条固定输入已经证明 C/R89/R94 的局部收益，但没有覆盖多读者和真实 kmsg。最高价值假设是 `ring::normalize` 的 `<N>` 解析仍做多次扫描、UTF-8 校验和 `str::parse`，而这一工作发生在每个 syslog 数据报的热路径。

## 算法研究和选择

候选把优先级解析改成一次 ASCII 扫描：在找到 `>` 前累加十进制数字，非数字保留原消息，溢出保持既有 `parse::<u32>().unwrap_or(0)` 映射；LOCAL7 过滤、时间戳去除、LF/空白归一化和原始字节保持不变。候选只改 `components/logd/src/ring.rs`，并增加空、最大值、溢出和坏格式回归测试。独立 worktree 的 2,000,000 个随机输入逐样本与旧实现相同；交错 release 微基准中位数 82.71 ms 对 86.73 ms（约 -4.6%），这是函数级证据，不能替代设备计时。

另外审阅了三个方向：

* `Client::queue` 每次 `drain(..sent)` 会搬移剩余积压；上游 ustream 只在消费过半等阈值才搬移。延迟压缩候选会改变队列容量和预算边界，本轮没有在没有独立设备证据时引入。
* `Ring::add` 可以为无 LF 输入增加复制快路径，但 C 同样先扫描整条输入，预期收益小于解析候选，未实现。
* `handle_read` 的长度统计和编码存在双遍，kmsg 可改为一次唤醒内 drain-to-EAGAIN；两者都涉及交付公平性或边界语义，当前 R94 证据不足以证明值得增加复杂度。

## 正式构建和身份

GitHub canonical `release-image` run `36479358153` 成功，使用 Rust 1.98.1、aarch64-unknown-linux-musl 和 OpenWrt GCC 14.3.0；APK、sysupgrade image、离线内容检查、manifest 和 binary SHA 均通过。候选发货 ELF SHA256 为 `c45ad7d8e69e66b81f833330597e4ffb8cdce0c0b42ba416b0a820bd3a8a2f75`，镜像 SHA256 为 `957906e862d20c563a50eaa9fe03b8030c66699360f46838beb64627f7216a2f`。CI manifest 和原始构建日志保存在 ignored 的 `private/logd-next-20260928/ci-artifact/`。

四侧身份如下：

| 侧 | ELF SHA256 | 身份 |
|---|---|---|
| C | `894c81b683662b57756e0462f66d12c1a3a5c0255863e645d9210e122e9b7a89` | 精确镜像 `/sbin/logd` |
| R89 | `a6f738144c561047bdd34188b084888ca5050ef01a7b7105a2b9f8d9152b975f` | `/root/r89-before-r90` 正式 ELF |
| R94 | `08c833fd36e591724068e94c0389d7428809e95b6bce591cb01957b742b1af5d` | `private/r94/final-sdk/logd-rs`，诊断历史侧 |
| 最终候选 | `c45ad7d8e69e66b81f833330597e4ffb8cdce0c0b42ba416b0a820bd3a8a2f75` | 本轮 canonical CI ELF |

## AX3000T 隔离实测

设备只读核验为 Xiaomi Mi Router AX3000T，DT compatible 为 `xiaomi,mi-router-ax3000t`/`mediatek,mt7981`，OpenWrt 25.12.5 r33051-f5dae5ece4，Linux 6.12.94，aarch64。正式实验前后的 boot ID 都是 `75a17130-62f9-43f8-bd28-7bbbb44ad5c8`；生产始终是九组件 C 栈。Wi-Fi 管理、双频 AP、DHCP、wan/wan6、DNS、HTTP/HTTPS 和 watchdog 前后通过。恢复门绑定当前 boot，引用离线备份和 900 秒自动回退证据；本轮 gate SHA256 为 `fc0c448e9ce2e4eb6ffe054c517b9b133e22b0f5de409d61f45e895cd8ed7fd8`。候选 correctness smoke 的 `same_boot`、`same_config`、`same_production_identity`、`same_host_mounts` 和清理均为真。

16 个正式窗口按随机块串行执行，每侧 4 次；namespace 使用现有空 held FIFO 代替 `/proc/kmsg`，私有 `/dev/log`、ubus socket 和 tmpfs，未读取生产 kmsg/watchdog。所有窗口错误数为 0。

单位为 µs/op；延迟为客户端逐样本 mean/p50/p95/p99 的轮间中位数，CPU 为 logd 进程 CPU。候选相对三基线的百分比为 `(candidate-base)/base`。

| 负载/指标 | C | R89 | R94 | 最终候选 |
|---|---:|---:|---:|---:|
| syslog_128 CPU | 31.95 | 8.45 | 5.65 | **5.65** |
| syslog_128 mean | 28.437 | 4.996 | 2.991 | **2.781** |
| syslog_128 p50 | 27.738 | 2.847 | 2.423 | **2.385** |
| syslog_128 p95 | 31.662 | 10.772 | 2.808 | **2.693** |
| syslog_128 p99 | 63.209 | 14.196 | 17.697 | **17.081** |
| log_read_100 CPU | 807.0 | 420.5 | 122.5 | **117.0** |
| log_read_100 mean | 1145.206 | 690.761 | 439.807 | **411.796** |
| log_read_100 p50 | 1089.887 | 626.887 | 368.246 | **365.206** |
| log_read_100 p95 | 1538.960 | 983.822 | 746.378 | **679.900** |
| log_read_100 p99 | 1852.653 | 1304.517 | 1146.786 | **953.044** |

候选的相对差：

| 负载 | 对 C CPU / mean / p95 | 对 R89 CPU / mean / p95 | 对 R94 CPU / mean / p95 |
|---|---:|---:|---:|
| syslog_128 | -82.32% / -90.22% / -91.49% | -33.14% / -44.33% / -75.00% | 0.00% / -7.00% / -4.10% |
| log_read_100 | -85.50% / -64.04% / -55.82% | -72.18% / -40.39% / -30.89% | -4.49% / -6.37% / -8.91% |

四侧逐轮范围和原始样本在 ignored 的 `private/logd-next-20260928/performance-final/`；pilot 在同目录的 `performance-pilot/`。候选 syslog CPU 与 R94 完全重叠，log_read CPU 有约 4.5% 的中位数差但需按低 tick 分辨率和轮间变化理解，不能把它归因成 parser 单点收益。

资源中位数（KiB）：

| 负载/侧 | C RSS/Anon/HWM | R89 RSS/Anon/HWM | R94 RSS/Anon/HWM | 候选 RSS/Anon/HWM |
|---|---:|---:|---:|---:|
| syslog_128 | 926/152/926 | 454/122/454 | 492/96/492 | **500/104/500** |
| log_read_100 | 1014/240/1054 | 506/174/520 | 516/120/516 | **524/128/524** |

用户态队列和 daemon RSS 已记录；当前夹具没有直接暴露每个 pipe 的 `F_GETPIPE_SZ` 和驻留物理页占用，内核 pipe 使用量报告为缺测，不能由 RSS 反推。源码和 unit gate 仍保持 256 KiB best-effort pipe、单流 1 MiB、总 4 MiB、64 流和慢读淘汰合同。

## 验证、缺口和停止理由

候选通过 logd release unit 17/17、`cargo clippy --all-targets --locked -- -D warnings`、Python 工具语法检查、canonical CI、AX3000T correctness smoke 及 16 个正式隔离窗口。既有 `tools/test_logd_stream_recovery.py`、r15/r21/r25/r28/r83/r92 合同门覆盖的流恢复、重连、环回绕、超限读取、字节和背压语义未被本轮代码改动；本轮没有把旧 Oracle 五场景或历史 R94 诊断 ELF 冒充新的设备实测。R93 Oracle 的 `no_subscriber`、`follow_1`、`follow_8`、`trim_heavy`、`backlog_600` 仍是多读者/慢读者机制证据，但 follow_8 曾相对 C 有 CPU 反例，不能宣称全面胜出。

保留本轮候选，因为它是单点、易审计、逐样本等价且没有可见功能或资源回退；设备 syslog CPU 未分辨出超出 R94 的稳定收益。停止继续调参：队列延迟压缩、LF 快路径、history 单遍和 kmsg drain 都需要新的独立机制证据，且当前主要实际负载已经有充足的 C/R89/R94 优势。该结果是工程收尾和验证交付，不是生产部署；生产仍保持精确 C 镜像。
