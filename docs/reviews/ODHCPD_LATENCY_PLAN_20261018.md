# odhcpd 单批首包与内存隔离门：事前计划

本轮只在 Oracle 私有 namespace 中比较精确 C 与最终指定 Rust ELF。
不访问物理路由器，不改全机 cache/governor/affinity，不做 PGO，不挑最快样本。
正式批次等待主线程给出候选 SHA；工具自检不启动 C/Rust odhcpd。

依据：[首次隔离对照与固定预案](ODHCPD_PROTOTYPE_20261018.md)。工具是
[odhcpd_latency.py](../../tools/odhcpd_latency.py)，复用 `odhcpd_baseline.Fixture`
的私有 rootfs、veth 客户端、ubusd、provider、配置和包编码。
不修改 baseline 工具；开批前复制两个 Python 工具、C helper 和两个 ELF 到新输出目录，
记录 SHA，随后各实例只用这份冻结副本。

## 模型与事前预测

首主动 RA ≈ 固定 1 秒 timer + exec/配置/socket/调度；首次 RS 和 DHCP 回复 ≈
客户端调度/内核收发 + 协议处理，Request 另有租约文件与 trigger 成本。
此前单点 C/R 的主动 RA 为 1005.182/1004.608 ms，RS 为 0.210/0.160 ms，
Solicit 为 0.664/0.140 ms，Request 为 0.358/0.096 ms。这些只用于预测范围，
不是门槛，也不混入本批样本。

预测：主动 RA 仍约 1 秒、两者差异主要是调度；RS/DHCP 在毫秒以内，Rust 不会
出现超过实测 C/C 噪声的变慢。同阶段 Rust RSS 预计为 C 的 0.7–1.0 倍，门仍为
不超过两倍。任意首包场景超过噪声，或任一同阶段 RSS 超过两倍，就推翻本轮
通过判断并报告；不追加样本或围绕结果优化。

真实 UDP 最小 echo 是内核收发和两端调度的地板观测，不是产品代理指标。
它在四个阶段之后运行，以免提前预热首 DHCP 的邻居路径。保留每次收发时间和
64 字节 payload；不减去地板，不用它排除样本。该地板有暖邻居缓存，不能当作
首次冷包的精确可扣除成本。

## 固定次序与仪器

1. 三对 C/C 冷进程启动校准：`C1,C2` 各三组。
2. 三对 C/R 正式比较：`C,R`、`R,C`、`C,R`。
3. 共十二个全新私有实例，不重用进程、配置或网络 namespace。每个实例 setup
   完成后静默 1 秒，之后固定相同动作次序。每实例硬上限 120 秒；错误/超时
   保存原件并停止整批，不替换失败实例。正常批次完成固定配对后统一分析。

[C helper](../../tools/odhcpd_latency_floor.c) 仅有三个可单独调用的 libc 接口：

```text
helper clock
helper launch ROOT MARKER COMMAND [ARG...]
helper echo DEVICE PORT COUNT
```

`launch` 在私有 chroot 完成后、execv 前读取 CLOCK_MONOTONIC；时间包含随后一次
marker write/close 与 execv，不包含 namespace 创建、chroot 和 Python Popen。
marker 必须不存在。客户端使用同主机的 `time.monotonic_ns()` 记录真正 sendto
前和 recvmsg 后时刻，跨 namespace 不改变该时钟。保留 C/Python clock 分辨率。
helper 无 Rust、ubus 或第三方依赖，可在 Linux 静态编译供后续设备驱动复用。

测量顺序为首主动 RA、首 RS、零租约快照、首 Solicit/Advertise、首 Request/Reply。
随后补齐三 NA 加一 PD；替换前缀并续租；重启私有 ubus/provider，原 daemon 和
租约保留；最后三次 UDP echo。四个 RSS/RssAnon 阶段分别是零租约、三 NA 加一 PD、
前缀变化、ubus 恢复等待 1.2 秒后。C 的已知 ubus 对象不恢复照实记录，仍取同一
进程 RSS；Rust 必须恢复对象。两个组件都须仍能回复 RS。

## 判定与输出

每个时延场景独立计算：

```text
Q = 2 × max(C/Python CLOCK_MONOTONIC resolution)
N = max(三对 C/C 的 |第二次 − 第一次|, Q)
正式差值 = Rust − 同对 C
```

两倍分辨率是两次耗时相减的时钟量化界，未设置固定微秒门。任一正式差值 `> N`
判为变慢并停止后续推进；`[-N,N]` 写作本轮不可分辨。逐对保留数值、顺序与分类；
中位数只作展示，不冲销失败。RSS 对每一对、每一阶段分别判断 `Rust <= 2 × C`，
不使用时延噪声放宽内存门。

输出目录必须新建。`batch.json` 保留固定日程与所有实例状态，实例 `results.json`
保存包、时间和内存原件，`analysis.json` 从原件提取值判定；`--summarize` 只输出
重算结果，不覆写证据。timeout/不完整结果为无效批次，不当作产品通过。

工具自检只在独立 loopback namespace 中验证 UDP payload、clock、exec marker、
拒绝覆写，以及合成数据的正负差、边界、顺序和两倍 RSS 判定。它不是额外一轮
产品性能试验。Oracle 通过仅是隔离门；路由器最终验收需要另行使用静态 helper
和 shell/客户端仪器，不能声称 Python Oracle 数据代表路由器启动性能。

待最终 ELF 确认后的命令模板：

```sh
sudo -n python3 tools/odhcpd_latency.py \
  --rootfs EXACT_ROOTFS --candidate FINAL_ELF --candidate-sha FINAL_SHA \
  --floor-helper BUILT_HELPER --out NEW_BATCH_DIRECTORY
```

## 仪器自检结果（正式批次之前）

Oracle `cc -O2 -static -Wall -Wextra -Werror` 编译通过，helper 为静态 AArch64 ELF，
SHA-256 `4c588c67626765cb0cdb3ed94ca97dc2c6df3ca3745940c23f277a8e50842adf`。
Python 语法检查通过；`selftest-01` 的 3 个真实 UDP echo、exec marker 时间顺序与
拒绝覆盖、7 个合成分析边界均通过。C/Python 的单调时钟声明分辨率均为 1 ns，
这不代表端到端测量精度为 1 ns。

原件在 Oracle `/home/ubuntu/odhcpd-latency-instrument-20261018/selftest-01/`；
副本在 ignored `private/odhcpd-20261018/latency-instrument/selftest-01/`。
该自检未启动任何 C/Rust odhcpd，不构成候选性能筛选或验收样本。

## 正式结果：首主动 RA 未过门，停止推进

首主动 RA 的三对 Rust−C 差值为 **+0.976408、+1.005448、+2.264978 ms**，
全部超过冻结噪声 **N=0.327403 ms**。本批判定 `stop_and_report`：停止上机和
后续性能样本，不修改产品、不补样、不改变门槛。首 RS、Solicit 和 Request
均通过时延门；四阶段 RSS 全部低于 C，不能用这些结果抵消首 RA 失败。

正式 SDK ELF SHA-256：
`79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55`。
C ELF SHA-256：
`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
工具提交 `d9be8ae0`，复用 baseline 提交 `c5e9ad53`。两位并行代理明确确认
Oracle 无自测/构建在运行并暂停新负载后才启动首样本。12 个预定实例全部完成，
没有超时、无效实例或替换样本；正式顺序为 CR、RC、CR。

| 场景 | 正式 C 中位数 ms | 正式 Rust 中位数 ms | N ms | 第 1 对 R−C ms | 第 2 对 R−C ms | 第 3 对 R−C ms |
|---|---:|---:|---:|---:|---:|---:|
| exec 前标记→首主动 RA | 1002.664408 | 1003.684256 | 0.327403 | +0.976408 | +1.005448 | +2.264978 |
| 首 RS→RA | 0.250682 | 0.167322 | 0.065281 | −0.079481 | −0.099201 | −0.083360 |
| 首 Solicit→Advertise | 0.431123 | 0.179721 | 0.181681 | −0.249761 | −0.375444 | −0.257402 |
| 首 Request→Reply | 0.427283 | 0.141482 | 0.067881 | −0.358002 | −0.232081 | −0.198121 |

噪声来自以下 C/C 配对差值（第二次减第一次），单位 ms：

| 场景 | 校准第 1 对 | 校准第 2 对 | 校准第 3 对 |
|---|---:|---:|---:|
| 首主动 RA | −0.164521 | +0.327403 | −0.153162 |
| 首 RS | −0.043600 | −0.065281 | +0.013399 |
| 首 Solicit | +0.173121 | −0.181681 | +0.157241 |
| 首 Request | +0.067881 | +0.002480 | −0.029281 |

C/Python clock 分辨率各为 1 ns，配对量化界为 2 ns，四项 N 都由真实 C/C 波动
决定。首 RA 第三对 C 的绝对值为 1001.664200 ms，比前两对更快；此有效样本
照常保留。即使只看前两对，Rust 仍超过冻结噪声，不存在由一个样本决定失败的情况。

RSS 单位 KiB。括号内保留三对 C→Rust 原值，范围不是替代逐对判定：

| 阶段 | C RSS 范围 | Rust RSS 范围 | 三对 C→Rust |
|---|---:|---:|---|
| 零租约 | 1116–1124 | 812–816 | 1116→812；1124→816；1124→812 |
| 三 NA 加一 PD | 1120–1132 | 816–820 | 1120→816；1128→820；1132→816 |
| 前缀变化后 | 1120–1132 | 812–816 | 1120→812；1128→816；1132→812 |
| ubus 重启后 | 1120–1132 | 816–820 | 1120→816；1128→820；1132→816 |

12 个同阶段 Rust/C RSS 比值为 0.7173–0.7286，均满足两倍上限。
RssAnon 在正式样本中 C 为 108–116 KiB、Rust 为 84–92 KiB。
三对 C 均未恢复 ubus `dhcp` 对象，三对 Rust 均恢复；两者 RS 服务保持可用，
没有为 C 重启 daemon 或清空租约来改变内存阶段。

UDP 最小 echo 的正式样本每侧 9 次（每实例 3 次），单位 ms：

| 背景 daemon | 最小值 | 中位数 | 最大值 |
|---|---:|---:|---:|
| C | 0.028400 | 0.047600 | 0.183082 |
| Rust | 0.034680 | 0.057241 | 0.178002 |

每实例第一次 echo 为 0.161321–0.183082 ms，后两次为
0.028400–0.066121 ms；所有原始收发时间、payload 和校准阶段 echo 亦保留。
地板未从时延中扣除，也未用于重新定义噪声或排除样本。

原件：Oracle
`/home/ubuntu/odhcpd-latency-instrument-20261018/sdk79f1349e-once-01/`。
本地 ignored 副本：`private/odhcpd-20261018/latency-sdk79f1349e-once-01/`，
包含冻结工具/ELF、全部包与结果，未重复下载每实例 rootfs。
用冻结 `analyze()` 对 `batch.json` 重算与 `analysis.json` 完全一致。

当前模型需要修正：主动 RA 的 1 秒 timer 解释绝大部分等待，但不能把剩余启动
差异都归为噪声；本批 Rust 在该路径稳定更慢。首次请求路径更快，尚不能据此
确定启动差异来自哪一步。本轮在此停止，不追加定位实验或优化；Oracle 结果也
不代替路由器首包验收。
