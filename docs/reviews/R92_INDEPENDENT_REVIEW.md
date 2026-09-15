# R92 独立复核：修复有效性与性能回退

日期：2026-09-15。结论：**多数修复有真实效果，整机控制面仍优于精确 C 原版；但存在未闭合的恢复/流客户端问题，以及已经实测的明显局部性能回退。不能给出“全部修好、全面不退步”的结论。**

## 范围与方法

- 当前工作目录 `main=39e5d89` 停在 R89。最新成果在 `codex/r92-recovery-compat=6bb1226`，包含 R90、R91、R92，共八个未合入 main 的提交。
- 从 R84 `bb25ab9` 回溯优化来源，重点审查上述八个提交。正式运行时为 `ca1a912`；其后的组件源码差异仅为一处 iwinfo 注释。
- 审查使用独立 detached worktree；没有修改生产代码、切换 main、合并或提交，没有连接或改动物理路由器。历史报告里的部署授权不视为本次部署授权。
- 三路并行审计源码、精确上游参考与故障证据；另行从本地 private 原始数据重新运行 R92 发布分析器。新导出的 **31 份 JSON 与已提交内容全部相同**，覆盖 **888 条组件测量、四个冷启动及 68 个必需历史门**。
- 哈希及重新导出证明留存数据与报告一致，不等于本次重新运行过 Linux 故障门或真机性能测试。

证据摘要：[summary.json](r92-independent-evidence/summary.json)。以下源码位置均指 **6bb1226**；main 上的同名文件行号可能不同。

## 可行动发现

### F1 · P2：logd 用旧 poll 下标误断开健康读者

位置：`components/logd/src/main.rs:439–449`；相关列表删除在 `:163–174`。

两个日志流 A、B 已被加入 poll。A 断开，同一轮又有新的日志；`add()` 的 `retain_mut()` 删除 A，将 B 移到前面。主循环最后仍按旧位置读取 `fds[client_base + current]`，把 A 的 `POLLHUP` 套到 B，错误关闭 B。用户看到的是健康 `logread -f` 流无故 EOF。

本次用真实 UnixStream pair 和 poll，以及原样生产 `Client`、`add()`、主循环末尾保留逻辑复现；主审再次独立执行得到：

```text
after log dispatch: healthy B still present; stale A revents = 16
after exact run_connected retention: healthy B incorrectly removed
B received 116 frame bytes and then EOF
```

这是 **R89 已存在、R92 仍未修的正确性问题**，不是 R92 首次引入。新增预算淘汰也会使下标错位，但单纯超预算不一定带来 HUP，不能把两种触发混为一谈。精确 C 的 ustream 回调绑定具体 stream，不依赖压缩后数组的旧位置。

建议先处理旧 poll 结果再执行可删除客户端的分派，或用稳定 fd/ID 对应事件；加入双读者“断开与写日志同轮到达”回归。[最小复现](r92-independent-evidence/run_logd_probe.py)。

### F2 · P2：HTTPD H-11 只修复同监听器唤醒

位置：`components/httpd/src/main.rs:946–952`；共享限额检查 `:852–866`。

HTTP、HTTPS、IPv4/IPv6 等监听器共享 `connections/-N`，但分别持有自己的 wake pipe。满额时各监听器都退出就绪集合；某连接释放后只通知它所属的监听器，其余仍靠最多 50 ms 的轮询重新检查。多监听器是实际部署会用到的配置，因此不能把 H-11 标成完整闭合。

本次两监听器、`-N 1`、每类 20 次实验：释放后，同监听器响应中位 **0.453 ms**，另一监听器 **34.967 ms**，另一侧范围 **23.589–45.408 ms**。

该实验运行于 macOS 的 R92 源码副本，仅适配 fcntl 常量与 Linux accept 不继承非阻塞的语义；就绪层走 fallback poll。它证实通知范围遗漏，**这些毫秒数不是路由器实测成绩**。原版 `uh_poll_listeners` 统一恢复监听器。修复应通知所有因共享限额停放的监听器，并覆盖超时关闭等释放路径。

### F3 · P2：ubusd 的 accept 防空转修复缺少独立恢复入口

位置：`components/ubusd/src/main.rs:175–197,233–258`。

`accept_all()` 对所有 accept 错误返回 false，随后移除监听器。恢复只存在于“某个已接受客户端被断开”的分支；循环没有重试 deadline。已有连接一直活着时，即使错误已消失，新的 ubus 连接仍无法被处理。

可达的源码链：客户端通过 SCM_RIGHTS 交给 ubusd 的 fd 可在未完成消息中暂存（`client.rs:290–302`），造成 EMFILE；新连接触发停放。已有客户端补完 PING 后，`server.rs:197–201` 会丢弃附带 fd，释放容量却不关闭总线连接，监听器仍不会恢复。EINTR/ECONNABORTED 也被错误地归入永久停放；精确 C 明确重试这两类错误。

这是 **R89 修复引入、R92 沿用的恢复遗漏**。本次确认了控制流及 fd 生命周期，尚未在 Linux 隔离环境注错重现，证据强度低于 F1/F2。建议区分暂态错误，并给资源不足设置有界退避重试；不能仅依赖某个连接恰好断开。

### F4 · P2：50 ms HTTP 停放策略留下显著局部性能代价

位置：`components/httpd/src/main.rs:435–440,933–945`。恢复停放连接会重新创建线程。

重新从实机原始数据核算，四客户端、每侧两轮、每轮 800 请求：

| 请求间隔 | C CPU µs/请求 | R92 CPU µs/请求 | CPU 增幅 | C 平均延迟 µs | R92 平均延迟 µs | 延迟增幅 |
|---|---:|---:|---:|---:|---:|---:|
| 60 ms | 293.75 | 612.50 | **+108.51%** | 459.219 | 737.337 | **+60.56%** |
| 80 ms | 300.00 | 668.75 | **+122.92%** | 465.428 | 770.835 | **+65.62%** |

两轮同侧 CPU 与延迟范围均不与 C 重叠。独立追踪在 gap 80 ms 时记录 800 请求、804 次 clone；gap 0 为 4 次。不是只凭微小中位差推断回退。

这是 **R87 设计引入、R89/R92 均保留且报告已经承认的取舍**；不是 R92 新增的翻倍开销。请求间隔不是 RTT，CPU 每请求翻倍也不表示整机 CPU 利用率翻倍。相同诊断夹具足以证明这个局部负载比原版差，连续紧密请求矩阵不能替代它。

建议把有间隔的 keep-alive 工作负载纳入正式性能门；评估有界工作线程复用或事件驱动处理，同时保留连接内存约束。不要仅提高停放阈值来让当前测量避开边界。

## 修复有效性

以下结论来自代码、精确参考和已重验身份的专项证据；不意味着所有异常组合都被穷尽。

| 范围 | 核验结论 |
|---|---|
| procd 只读洪流维护饥饿 | 维护截止时间锚定上次实际维护；R87 反例与 R89/R92 通过证据一致 |
| procd state(false)、断连日志、非 PID1 喂狗 | halt 判断、断连排空、独立 reconnect deadline 与 pump 位置正确；对应反例存在 |
| hotplug 存活 | 专项确实延迟 ubusd/coldplug，后续 uevent 执行；不是只看到 daemon 活着 |
| ubusd 半关闭慢读 | EOF 后取消读兴趣，排空输出后关闭；历史 R89 在 0.8 s 消耗约 0.79 CPU s，候选不再空转 |
| ubusd 遍历时删除 | owned 路径下界避免删除游标引起重复；完整回复及继续服务门通过 |
| HTTP batch 放大 | 改为逐项序列化并 flush，写失败停止后续调用；仍需保留单个 RPC 回复大小的边界 |
| netifd 生命周期与 R91 日志 | 旧 teardown 配置保留、claim 释放、日志级别过滤与固定格式串正确 |
| netlink overflow | ENOBUFS/截断触发扩容和重同步；失败 dump 保留重试标志 |
| rpcd、UCI、logd 字节与 panic | fnmatch flags 对齐精确 libc 语义；raw value 保留，rename 先验证后修改，Unicode 切片崩溃有旧版反例 |
| UCI 缓存 | 每次重开、锁定并完整读取文件，按内容/名称/flags 匹配；delta 重新读取，未找到 stale 配置或跨 session 复用泄漏 |
| fw4 / reload-config | wrapper 行为、真实 errno、数值真值和取消/转义路径成立；4096 上限为明确的有意差异 |

## 性能总体判断

同批四冷启动 C/R92：

| 指标 | C | R92 | 变化 |
|---|---:|---:|---:|
| 固定整批控制面 CPU | 389.645 s | 298.495 s | **−23.39%** |
| 混合吞吐 | 1144.125 op/s | 1282.019 op/s | **+12.05%** |
| 混合 CPU/操作 | 785.875 µs | 674.250 µs | **−14.20%** |
| idle-before daemon RSS 中位数之和 | 9606 KiB | 5320 KiB | −4286 KiB |
| 整机 MemAvailable | 137296 KiB | 130830 KiB | **−6466 KiB** |

RSS 不等于独占物理内存，MemAvailable 的下降不能用 RSS 下降抵消，也尚不能直接认定为泄漏。

相对历史 R89，R92 **mixed 吞吐 −3.73%、mixed CPU/操作 +4.35%、HTTP lane CPU +9.38%、log lane CPU +29.49%**。这些是两批实际观察的差额；日志输入及进程历史未完全冻结，不能全部归因于新代码。同机临时 HTTPD 的 R92/R89 自身 CPU 差约 +1.42%/+1.66%，固定日志语料未复现整机日志增幅，所以也不能用历史差额断言所有日志处理都慢了 29%。

74 个同批组件负载对 C：平均延迟 **67 降/7 升**，组件 CPU **72 降/1 平/1 升**，p99 **65 降/9 升**。对 R89：平均延迟 42 降/32 升，组件 CPU 39 降/7 平/28 升，p99 46 降/28 升。均为算术符号计数，不是显著性检验。

HTTP JSON-RPC c4 的 HTTPD 自身 CPU 比 C 高 **5.74%**，但包括依赖的总服务端 CPU 低约 **4.73%**、平均延迟低 **25.26%**；须明确所说的是哪个成本。procd 未发现大倒退，八种查询的平均延迟与 CPU 都低于 C。

额外内存边界：logd 的 4 MiB 预算只约束待写 payload；Vec 排空后保留 capacity，多读者先后积压可保留超过 4 MiB 的堆容量。合同已说明这一点，不能把它称为 4 MiB RSS 硬限制；本次没有把未实测的极端容量当成实机内存结果。

## 本次执行与限制

- shell/Python 语法、21 个 harness 测试、33 个 benchmark Python 测试全部通过。
- macOS/Rust 1.98.1：HTTPD 34、ubusd 23、readiness 3、rpcd binary 52、fw4 14、logd 5 个测试通过；UCI library 16、fidelity 16、cache 2、listing 2 通过；reload-config 11 通过。
- UCI listing/reload-config 各有 1 个夹具失败：APFS 拒绝非法 UTF-8 文件名，尚未到被测逻辑，不计作 Linux 回归，也没有写成“全绿”。
- procd all-targets check 通过，watchdog mock 五分支通过；完整 procd 测试在 macOS 缺 Linux sysinfo 链接符号。Linux ABI、命名空间及 epoll 故障测试依赖已留存历史证据。
- 未测试内核转发吞吐，不能把控制面收益表述为上网/无线吞吐提升；四窗口每侧仅两个 boot，不能保证任意长期负载。

处置建议：保留已验证的修复，优先补 F1/F3 恢复与正确性门、F2 多监听器门，并将 F4 作为正式性能待办。无需因为这些局部问题回退全部成果，但目前不应将九组件概括为无条件优于原版。
