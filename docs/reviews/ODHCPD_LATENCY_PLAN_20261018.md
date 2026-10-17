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

## 仪器自检结果（未运行正式批次）

Oracle `cc -O2 -static -Wall -Wextra -Werror` 编译通过，helper 为静态 AArch64 ELF，
SHA-256 `4c588c67626765cb0cdb3ed94ca97dc2c6df3ca3745940c23f277a8e50842adf`。
Python 语法检查通过；`selftest-01` 的 3 个真实 UDP echo、exec marker 时间顺序与
拒绝覆盖、7 个合成分析边界均通过。C/Python 的单调时钟声明分辨率均为 1 ns，
这不代表端到端测量精度为 1 ns。

原件在 Oracle `/home/ubuntu/odhcpd-latency-instrument-20261018/selftest-01/`；
副本在 ignored `private/odhcpd-20261018/latency-instrument/selftest-01/`。
该自检未启动任何 C/Rust odhcpd，不构成候选性能筛选或验收样本。
