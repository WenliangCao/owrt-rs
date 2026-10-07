# M6b UDP 主循环审查与测量计划

日期：2026-10-07。本文是 M6b 第 0 步的只读审查结果；不改产品代码，不启动 Oracle 正式窗口。M6b 协议冻结前先以此处的调用链和计数定义验证等待来源，避免把静态推断当成测量结论。

## 结论先行

在普通 Linux 主循环中，`wait_for_files()` 的确只装配文件/日志/管道类 fd，随后以最多 2 ms 的 timeout 调用 `poll_fds`。DNS UDP/TCP listener 没有进入这一等待。网络 fd 出现在 `observe_arp_activity()`（仅 `script_arp` 开启时，timeout=0，且只设置 `arp_awake`）以及 DHCP 冲突探测专用的 `wait_during_probe()`，不等于主循环的网络等待。因此“Linux 普通主循环已把网络 fd 纳入阻塞 poll”尚未成立；需以新增计数核实每轮实际 poll 来源。

此外，普通 `step()` 对每个 listener 只调用一次 `step_udp(index)`；`step_udp` 每次新建 65,535 字节 `Vec`，只调用一次 `DnsSocket::receive`（Linux `DatagramSocket::receive` 的一次 `recvmsg`）。这两个事实均由源码确认。单监听器、20 个闭环客户端的 M6a 命中结果 465.211 QPS、p50 41.909 ms 与“约一包/轮、约 2 ms 轮间隔”的量级吻合，但尚不能单凭结果证明轮速或等待来源。

## 精确调用链（冻结源码 dc1b740d）

### 普通 Linux 服务循环

```text
run/serve loop (main.rs:1557)
  -> observe_arp_activity()                 [main.rs:1560, cfg linux+64]
       -> append_file_fds(..., false)       [main.rs:4841]
       -> append UDP/TCP listener POLLIN    [main.rs:4842-4856]
       -> poll_fds(..., 0)                  [main.rs:4909]
          （只把 ready 转为 arp_awake；不消费 DNS listener revents）
  -> step_dhcp_files / step_dns_files / step_hosts_files
  -> Poll::step()                           [main.rs:1570]
       -> for each listener exactly once    [main.rs:3284-3288]
            -> step_udp(index)
                 -> Vec<u8> 65,535           [main.rs:3482]
                 -> udp.receive(&mut query)  [main.rs:3483]
                      -> DatagramSocket::receive -> one recvmsg
                 -> process/admit/forward/reply
            -> step_tcp_accept(index)
       -> TCP clients, DHCP, neighbors, EDNS, TFTP, diagnostics
  -> poll.wait_for_files()                  [main.rs:1794]
       -> append_file_fds(..., true)        [main.rs:3188-3182]
       -> poll_fds(file_fds, runnable ? 0 : 2) [main.rs:3200]
```

`append_file_fds` 收集 interface collector、logger/dump 输出、DHCP file provider、DNS/hosts readers 和 route watch；它没有把 `self.listeners[*].udp` 或 `tcp` 加入该 fd 数组。普通 Linux 路径因此在无文件事件时最多等待 2 ms；非 Linux 另有 `park_timeout(2 ms)`，本轮只测 Linux。

`wait_during_probe()`（`main.rs:4247-4395`）是 DHCP 冲突探测的嵌套等待。它会把 UDP/TCP listener、DNS upstream、TFTP、neighbors 等 fd 置入同一 poll，并按最近 deadline 计算 timeout；这条路径不代表普通主循环，计数时必须单独归类，不能与 `wait_for_files` 合并。

### C 参考调用链

镜像 C 的 `dnsmasq.c:1105-1219` 每轮先 `poll_reset`，通过 `poll_listen` 注册 DHCP、inotify、netlink、signal pipe、helper 等 fd；`set_dns_listeners()` 在同一 poll 集合登记 DNS listener。`do_poll(timeout)`（`poll.c:71-79`）按 `fast_retry`/TFTP/DAD 最近期限阻塞，未设固定 2 ms。poll 返回后 `check_dns_listeners()`（`dnsmasq.c:1928-2009`）按优先级处理一个就绪事件并立即回到下一轮；`receive_query()`（`forward.c:1581-1656`）每次一个 `recvmsg`。C 的“一次一事件”是公平性基线，但其等待由同一 poll 驱动，并不等价于 Rust 当前分离文件 poll。

## 待测假设和可证伪预测

| 编号 | 假设 | 计数支持/反证 |
| --- | --- | --- |
| H1 | 普通 Linux 轮间等待主要来自 `wait_for_files` 的 2 ms timeout，而不是网络 fd 阻塞。 | `wait_files_calls`、`wait_files_timeout_2ms`、`wait_files_ready`、`main_network_poll_calls`；若普通主循环出现带网络 fd 的阻塞 poll，H1 需改写。 |
| H2 | 每轮每 listener 最多成功接收一个 UDP 包；单 listener 时 `udp_packets/step_calls <= 1`。 | `loop_iterations`、`udp_step_calls{listener}`、`udp_recv_success{listener}`、`udp_packets_per_loop`、`udp_budget_exhausted`。 |
| H3 | 465 QPS 窗口中主循环速率与成功 UDP 包速率接近，且每轮等待约 2 ms。 | 以同一 monotonic 窗口报 `loops/s`、`udp_packets/s`、`poll_calls/s`、实际 poll wait p50/p95；`loops/s ≈ 465`、空闲 wait≈2 ms 支持 H2/H1。若 loops/s 显著高于 QPS，则瓶颈在单包处理/其他阶段。 |
| H4 | 65,535 字节 Vec 的每次分配是普通命中路径的额外成本，但不是 42 ms 尾延迟的唯一来源。 | `udp_buffer_allocs`、`udp_buffer_reuses`、分配字节；修复试验需在同一 workload 下比较 CPU/延迟，不能由静态 64 KiB 直接估算收益。 |
| H5 | 批量 drain 必须有全局/每 socket 预算，避免 UDP 饿死 DHCP、TFTP、TCP、reload。 | 计数 `budget_yields`、各服务 step 次数、最老 DHCP/TFTP/TCP/reload ready age；负载下不得出现服务事件饥饿。 |

M6a 数量级交叉核对：465.211 QPS × 41.909 ms ≈ 19.5 个在途请求，接近冻结的 20 客户端闭环上限；这支持“每轮约 2 ms、20 轮一周”的解释，但仍是推断，正式结论只能引用上述计数。

## 诊断计数合同

计数只用于 M6b 诊断/回归构建，必须使用 monotonic `Instant`，以固定窗口导出一行 JSON；不记录客户端内容或地址。计数器按主循环和嵌套 probe 分开，避免重复计算：

1. **主循环/等待**：`loop_iterations`、`step_duration_ns`、`wait_for_files_calls`、`wait_for_files_poll_calls`、`wait_for_files_poll_timeout_0/2`、`wait_for_files_poll_ready`、`wait_for_files_wait_ns`（总量与 p50/p95/p99）；`main_network_poll_calls` 应为 0（除 `script_arp` 观察的 timeout=0 计数，单独字段）。
2. **网络观察**：`observe_arp_poll_calls`、`observe_arp_ready`、`observe_arp_wait_ns`（应接近 0，不能把 timeout=0 叫阻塞等待）；`wait_during_probe_poll_calls`、`wait_during_probe_wait_ns` 单列。
3. **UDP 每 listener**：`udp_step_calls`、`udp_receive_attempts`、`udp_recv_success`、`udp_recv_would_block`、`udp_recv_error`、`udp_bytes`、`udp_packets_per_loop_histogram`、`udp_budget_yields`、`udp_buffer_allocs_bytes`、`udp_buffer_reuses`。每次成功接收必须能与正确/错误/丢弃结果对账；错误回答不计为正确吞吐。
4. **公平性/其他服务**：`tcp_accept_steps`、`tcp_client_steps`、`dhcp_steps`、`tftp_steps`、`reload_steps`、`ubus_steps`，以及每类 ready-to-service age 的 max/p95。批量 UDP 试验每轮后先执行一次有界的 TCP/DHCP/TFTP/reload，再继续同 socket，预算耗尽必须计数。
5. **资源关联**：每窗口 daemon cgroup CPU、正确完成数、FD/thread/child；缓冲计数仅作归因，不替代正式 CPU/RSS/PSS 指标。

若为保持交付 ELF 零开销而采用诊断 feature，必须记录诊断 ELF 的源码/构建身份，并只用计数验证根因；正式性能窗口仍要使用无计数生产构建。低成本性能回归门可保留编译后极少数原子计数，但须实测其普通路径开销并写入 M6B 报告。

## M6b 修复后 UDP 低成本回归门（候选，协议冻结时写死）

- 功能/正确性：M5 UDP、DHCP、TFTP、TCP、reload 场景回答内容/成功数/错误数与 C 合同一致；无新普通差异。
- 命中稳态：20 客户端、cache-size 4096、相同 C/R 配置及原生负载器；施加 10,000 QPS，正确吞吐不得低于负载且错误为 0；p50 < 1 ms 是目标门，若 C p50 在同窗口不可达则以 C 同数量级并保留绝对值。
- 等待/唤醒：网络与文件 fd 必须在同一主 poll；空闲时实际等待至最近 timer deadline，不固定睡 2 ms。计数中 `poll_wait_ns` 不应出现 2 ms 人为平台；每秒 poll 调用数应随事件/定时器变化，而非固定 500 次。
- 公平性：在 10,000 QPS UDP 命中＋DHCP/TFTP/TCP/reload 混合负载下，DHCP/TFTP/TCP/reload 的最大 ready age 不得超过协议冻结的 C 对应值；不能以 UDP 吞吐换取服务饥饿。
- CPU：无负载 60 s CPU 接近 C；DHCP 每 cycle CPU 相对 M6a 显著下降。最终收益/变差仍使用 M6a 已冻结阈值（吞吐±10%、CPU/正确请求或 p95±10%、RSS/PSS ≥10%且≥64 KiB，错误数直接判变差），不得看结果改阈值。
- 批处理：每 socket 有明确 packet budget（初始值作为协议参数冻结），记录预算耗尽/让出次数；不得以无限 drain 忙等。
- 分配：复用接收缓冲，`udp_buffer_allocs` 在稳态不随请求数增长；复用不改变最大 EDNS 接收界限（仍拒绝截断/超限包）。

## 测量顺序与停止条件

1. 先在无负载和低速（例如 100 QPS）短 pilot 运行计数，校验 `udp_recv_success`、客户端完成数、正确 wire、poll fd 分类和 cleanup；pilot 失败即作废，不进入正式窗口。
2. 在 465 QPS 复现负载下测至少 10 s，保存每秒 counters；同时抽查 UDP wire、DHCP DORA、TFTP block、TCP/reload 健康。该诊断窗口不改变 M6a正式结果。
3. 若 H1/H2 得到计数支持，才实施同一 poll、有限批量 drain、buffer reuse 的产品修复；若反证，先更新账本根因和方案，不凭用户描述强行改调度。
4. 修复后重新冻结源码/ELF，按 M6b 协议做完整正式 9 profile × 3 组 × 5 轮；UDP opt3/s 只有在瓶颈修复且计数确认后才具备切换意义。

## 限制

- `wait_during_probe` 的网络 poll、`observe_arp_activity` 的 timeout=0 观察、以及脚本/文件 reload 的内部 poll 不能并入普通主循环唤醒率。
- 仅凭 `Vec` 大小不能给出 RSS 节省；须用 cgroup CPU 与 smaps/PSS 交叉验证。
- 所有性能结论只代表 4 核 Oracle 构建机，不能外推物理路由器；本计划不触碰物理设备。
