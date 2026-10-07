# M6b 第 1b 项：主循环固定开销审查与剖析方案

状态：只读审查和实施建议；基线为 UDP-only M6b 候选 `386fa821`（不含
TCP 方案 A）。本文件不改变产品代码，也不把诊断构建或诊断计数器当作
交付性能结果。性能结论只能来自同一 Oracle 构建机。

## 结论先行

UDP 修复把 Linux owner loop 从每轮至多收一个包改成了可批量运行；当
loop 以数千次每秒转动时，原来每轮都执行的固定工作成为每个 TCP、UDP、
reload 和 DHCP 请求的共同成本。源码审查确认这些工作位于热循环中：

| 工作 | 位置（`components/dnsmasq/src/main.rs`） | 当前行为 | 预期固定成本 |
| --- | --- | --- | --- |
| 主 owner 调度 | `1603–1618` | 每轮先做文件/ARP检查，再无条件 `step()` | 每轮一次，即使没有对应事件 |
| UBus/metrics | `3730–3736` 的 `Poll::step` | 每轮生成 `Metrics` 并调用 `ParentEvents::process_ubus` | `Metrics`快照、DHCP/provider 借用和一次非阻塞接收尝试 |
| UDP 完成前的 UBus | `4161–4177` `process_udp`；`4394–4410` `poll_udp_completions` | 每个 UDP 包或完成轮再次生成快照并调用 `process_ubus` | 包速率越高越显眼；没有请求时也走 `incoming_if_complete()` |
| loop 尾部 UBus | `1837–1838` | `step()` 后再次无条件生成快照/处理 UBus | 每轮重复一次 |
| poll 描述符 | `3477–3630` `wait_for_files` | 每轮 `Vec::new()`，重新 append 文件、网络、client、UBus、DHCP、helper、TFTP、neighbor、collector | 向量增长、写入和 fd/event 组装；拓扑不变时都是重复工作 |
| 日志/诊断 | `step` 中的 `early_logger.flush_ready()`、`logger.flush_ready()`；`3700–3730` `log_dns_diagnostics` | 每轮 flush；每轮调用 dump step 和多个 `take_*` | 空队列也反复检查；诊断 drain 可能创建临时 Vec |
| script-arp 特殊路径 | `1606`、`5332–5413` `observe_arp_activity` | 启用 `script-arp` 时每轮重建另一套 fd Vec 并执行 `poll(...,0)` | 仅该配置启用时出现；与公共 poll 重复观察同一 fd |

`ParentEvents::process_ubus` 在 `components/dnsmasq/src/main.rs:375–433` 内
调用 `UbusService::process_one`。后者在
`components/dnsmasq/src/ubus_service.rs:119–157` 调用
`Connection::incoming_if_complete()`；该函数即使没有已完成帧也会走非阻塞
`recv_into`（`components/ubus/src/conn.rs:1045–1090`）。UBus fd 已加入
`wait_for_files` 的 poll 集合，但 readiness 当前只在本地 Vec 中使用后丢弃，
所以 owner 下一轮无法据此跳过这次尝试。

这解释了中间窗口里 UDP 命中、TCP 和 reload 的每请求 CPU 同时上升：它们
共享 owner loop 的 `metrics`、UBus、fd Vec 和日志检查。源码证据还不能单独
证明每一项的周期比例，必须用下面的 perf 和 M6b wake 计数交叉验证。

## 先做的剖析（不改产品）

剖析使用与窗口完全相同的 AArch64 Oracle、CPU 绑定和 namespace。正式窗口
期间不运行构建、测试或 fuzz；下面的符号构建只能在独立的 pilot 时段完成。
UDP-only 归因必须绑定 source `386fa821`，不能使用含 `56f66c2f` 的候选。

1. **短 pilot 计数。** 使用已启用 `m6b-diagnostics` 的诊断副本，记录
   `loop_rounds/s`、`poll_calls/s`、`wait_durations_ns`、wait reason、每个
   listener 的 `step_udp_calls`、`udp_packets`、`max_batch` 和
   `budget_yields`。用 20 客户端 UDP hit、TCP、DHCP、reload 各跑一个短段，
   回答内容逐项抽查；这些计数只用来解释机制，不能替代正式性能窗口。
   计算：
   `packets_per_loop = udp_packets / loop_rounds`、
   `polls_per_loop = poll_calls / loop_rounds`、
   `cycles_per_loop = cycles / loop_rounds`（后者来自 perf）。修复前
   `polls_per_loop` 接近 1、`packets_per_loop` 在 UDP hit 接近批量上限时，
   仍可表明每轮固定成本；若两者偏离，应保留实际值，不按假设归因。

2. **生产 ELF 的 perf stat。** 被测 daemon 绑定 CPU0，原生上游 CPU1，
   loadgen CPU2，controller/采样 CPU3；daemon 的 cgroup CPU 仍是请求 CPU
   的主分母。对每个 profile 先预热，再在同一阶段运行 30–60 秒：

   ```sh
   # PID 已由同一 M6b harness 启动并确认 affinity=0；只读采样
   perf stat -p "$DAEMON_PID" -o "$OUT/perf.stat" \
     -e task-clock,cycles,instructions,branches,branch-misses,\
   context-switches,cpu-migrations,cache-misses,page-faults -- sleep 60
   ```

   `perf stat` 的 CPU/指令数与 harness 的 cgroup `cpu.stat`、正确完成请求
   对齐；保存 perf 版本、`perf list`、`/proc/$PID/status`、affinity 和
   daemon ELF SHA。若 PMU 不提供某事件，记录事件不可用并保留其余项，不能
   用另一事件冒充。

3. **系统调用计数（短 pilot）。** 先检查
   `perf list | grep -E 'sys_enter_(poll|ppoll|recvmsg|sendmsg)'`。事件可用时
   单独记录 10 秒，避免把 tracepoint 开销混入正式 CPU：

   ```sh
   perf stat -p "$DAEMON_PID" -o "$OUT/perf.syscalls.stat" \
     -e syscalls:sys_enter_poll,syscalls:sys_enter_ppoll,\
   syscalls:sys_enter_recvmsg,syscalls:sys_enter_sendmsg -- sleep 10
   ```

   若 tracepoint 不可用，保存 `perf list` 证据并以 M6b counters 的 poll/loop
   和 UDP receive 计数为准；`strace -cf` 只能作为非正式 smoke，不能进入 CPU
   对照表。

4. **符号调用图（独立诊断副本）。** 交付 ELF 的 profile 已 strip。要把
   采样地址解析到 `Poll::wait_for_files`、`Poll::metrics`、
   `ParentEvents::process_ubus`、`Logger::flush_ready` 等函数，针对同一
   source 在 pilot 时段构建保留 DWARF/帧指针的副本；保持 opt-level、LTO、
   linker、target 和配置不变，只改变诊断符号，不把它的绝对 CPU/RSS 当作
   交付数值。建议使用 `CARGO_PROFILE_RELEASE_STRIP=none`、
   `CARGO_PROFILE_RELEASE_DEBUG=2`，并额外加入
   `-Cforce-frame-pointers=yes`。采样命令：

   ```sh
   perf record -p "$DAEMON_PID" -F 997 --call-graph dwarf \
     --no-buildid-cache -o "$OUT/perf.data" -- sleep 30
   perf report --stdio --percent-limit 0.5 --sort symbol,dso \
     > "$OUT/perf.report.txt"
   perf script -i "$OUT/perf.data" > "$OUT/perf.script"
   ```

   保存诊断 ELF、其 SHA、source/build manifest、`perf.data` 和报告。若静态
   链接器或 PMU 不支持 DWARF，退回 frame-pointer 或 `perf report` 地址+link
   map；注明符号解析边界，不把无法解析的 `[unknown]` 归给某函数。

5. **归因判定。** 至少有一个空闲段、UDP hit 段和 TCP/DHCP 段。只有同时满足
   以下证据才把“固定 loop 开销”列为已证实：

   * UDP/TCP/DHCP 段中 `poll_calls/loop_rounds` 和相应 `metrics`/UBus 调用
     次数都随 loop 线性增长；无请求段仍有相同调用比例；
   * perf 调用图把显著 self/children 周期归到上述固定路径，且
     `cycles/loop` 在不同请求类型相近，而 `cycles/request` 随请求速率变化；
   * 减去 daemon cgroup 的 idle CPU 后，固定路径增量能解释约
     TCP 46 µs、C 29 µs以及 UDP/DHCP 相对 C 的 2–3 倍方向。数值未达到这三
     条时，只报告“候选”，不声称根因已证实。

## 第 1b 实施建议（通过剖析后再改）

### A. UBus/metrics 只在请求或需要回调时运行

* 在 `Poll` 增加 `ubus_ready`，`wait_for_files` 读取 UBus slot 的 `revents`
  后保存它；下一轮只在 `ubus_ready || ubus.has_pending()` 时调用
  `process_ubus`，处理完清除 ready。`has_pending` 仍保留对已缓冲完整帧的处理，
  不能仅凭一次 poll 事件丢掉部分帧。
* `ParentEvents::process_ubus` 在连接断开时还负责重连。增加 owner-only 的
  `ubus_retry_due`/deadline（初始启动和每次 disconnect 都置 due，并纳入公共
  poll deadline）；不能单纯依赖 fd readiness，否则 `ubus=None` 后永远不会重试，
  也会改变 C 的重连与 notice 顺序。
* 删除主循环尾部、`Poll::step` 和每包 completion 路径的无条件
  `metrics()+process_ubus`；合并成一个 `process_ubus_if_ready`。UBus 请求
  到达时仍先于本轮 DHCP/DNS 处理，保持 C 的订阅与 metrics 顺序。
* 缓存一个 owner-only `Metrics` 快照和 dirty 位。只在 UBus metrics 请求或
  DNS doctor 回调前刷新；DHCP/DNS/本地 answered/TCP active 的变更置 dirty。
  不跨持有 `RefCell` 的借用缓存引用，只缓存 30 个 `u32` 值。
* 每个正式回归必须验证：metrics 请求看到最新累计值；subscribe/unsubscribe
  立即生效；doctor 回调仍看到该 C 调用点的 counters；UBus 断连和重连日志
  顺序不变。

### B. 复用 poll fd 数组，并把拓扑变化与事件变化分开

* `Poll` 持有一个 `Vec<PollFd>` scratch，第一次建立时 reserve；后续至少
  用 `clear()` 保留 capacity，消除每轮分配。并记录 file/network 起始索引、
  signal/UBus slot 和各动态 client slot。
* 通过 `poll_layout_generation` 只在 listener、client、UBus、logger、DHCP、
  helper、TFTP、neighbor 或 interface collector 的 fd 集合变化时重建布局；
  没变化时只更新 fd/events、deadline 和 `revents=0`，deadline 仍每轮重新计算。
  不能缓存过期的 timer 或 client phase。
* listener/client 变化时在同一 owner turn 使 generation 递增；重建完成后再
  调 poll。为每个 slot 保存语义标签，避免依赖脆弱的裸数组下标；统一 poll
  返回的 `revents` 也要驱动 `ubus_ready`、logger/dump ready 和 network ready。
* `wait_during_probe` 与 `observe_arp_activity` 有各自的临时 fd 集合。先以
  scratch Vec 做低风险修复；若 perf 显示 script-arp 路径占比，再把它们接入
  同一布局，不能在无对应配置时扩大改动面。

### C. 日志和诊断按 dirty/readiness 驱动

* 给 `Logger` 提供只读 `has_pending_output()`（队列、echo 队列或到期的 FIFO
  retry），仅在该值或 poll 的 `POLLOUT` ready 时调用 `flush_ready`。`emit` 仍
  保持现有立即尝试，保证错误和 FIFO 行为；等待文件的重试 deadline 必须加入
  公共 timer。
* `DumpHandle` 提供 `has_pending()`；无写队列时不调用 `DumpHandle::step()`。
  `log_dns_diagnostics` 仅在 dump/logger/daemon notice dirty 或对应 poll ready
  时 drain；已有 notice 时要一次性排空，避免重复分配。
* `script-arp` 开启时优先把 `observe_arp_activity` 的零超时 poll 合并进公共
  readiness；没有该配置的 UDP/TCP/DHCP路径不引入 neighbors 逻辑。

## 低风险交付顺序和回归门

1. 先提交本文件和 perf/pilot 证据，确认固定开销归因；本阶段不改产品。
2. 只实现 A（UBus gating + metrics cache），跑 UBus metrics/subscription/doctor、
   M5 受影响 DNS/TCP/DHCP/reload 回归；若 CPU 无改善，保留证据并撤回。
3. 再实现 B（scratch Vec 复用），跑 M6b UDP/TCP/DHCP/reload pilot；拓扑变化、
   signal/reload、helper/TFTP/client churn 必须覆盖。只有 perf 显示收益才继续
   stable-slot 缓存。
4. 最后实现 C（日志/诊断 gating），跑日志 FIFO、dump、HUP、错误恢复；FIFO
   读取和日志队列语义不可因跳过空 flush 改变。
5. 每一步都记录 source/ELF SHA、体积、cgroup CPU、正确请求、p50/p95、idle
   CPU、poll/loop/wait counters。若任一正确性门失败，保留失败证据，撤回该步，
   不把不同实验的最佳窗口拼成通过。

本审查不改变 M6b 的阈值和方案 A 的 TCP 门。方案 A 的 TCP CPU 门应以第 1b
修复后的新 opt3 基线重新测量；在第 1b 完成前，不用 M6a 的约 20 µs 旧基线
否决或接受方案 A。
