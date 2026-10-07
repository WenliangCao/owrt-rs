# M6b 修复、优化与复测协议

2026-10-07 冻结。M6b 先修正测量合同，再冻结本协议；产品改动必须在本文件提交后进行。M6a 的原始数据和报告不改，所有 M6b 结果与 M6a 身份分开保存。性能结论只代表同一 Oracle 构建机，不外推到物理路由器。

## 身份、顺序和共同资格

基线是 M6a 的 C `097a9e21…cab87`、Rust opt3 `37f85d22…7f7b`（源码 `dc1b740d`）和同源 opt-s `8427b9ab…88a2a`。每个候选产品先生成新的 source/ELF/build manifest；C、候选 opt3、候选 s 在同一精确镜像 rootfs、同一 SDK 和同一 4 核 Oracle 中运行。所有新证据置于 `private/dnsmasq-rewrite/evidence/M6b/`，每次窗口保留命令、identity、原始 latency/lag/wire、smaps、cgroup CPU、FD、清理、archive manifest 和本地 SHA/metadata verification。

M6a 的 9 profile、3 组、5 轮、30 秒预热＋120 秒测量、CPU0 daemon／CPU1 upstream／CPU2 generator／CPU3 controller、20 客户端、100-query TCP 重连合同和交错组顺序全部沿用。M6b 先跑短 pilot，pilot 不计正式资格；正式复测仍为 135 个窗口。错误回答、普通 timeout、transport error、reload 发布失败和 DHCP 非空 leasefile 保留为真实行为结果，错误不计正确吞吐；只有工具、环境污染、采样、归档或清理失败才作方法无效并 fresh 重跑。判定阈值不因结果调整。

M6a 的收益/回退规则继续适用：组内 `W=(max-min)/median`，差异须超过两组 W 的较大者且至少 4/5 同轮方向；吞吐收益≥10%、CPU/正确请求或 p95 降低≥10%；吞吐回退≥5%、CPU/正确请求或 p95 增加≥10%；RSS/PSS 变化≥10%且绝对≥64 KiB。新增错误直接为回退。M6b 的候选还须满足下面的预算硬门。

## 第 0 步：测量合同修正与新增指标

Rust 没有 C 的 TCP 子进程，排空不能用 child count==0 作为充分条件。测量器必须等待：所有 client/view/pending transaction/pinned root 计数归零；若某计数不可导出，至少所有受测 listener FD 回到经过空载确认的 idle 集合并连续稳定，且 loadgen 已关闭。固定在负载结束后的 0、1、5、60 秒保存 process tree、FD/thread/child、RSS/PSS、cgroup CPU、live requested bytes（若实验构建可读）和计数器。`after-drain` 只在合同满足后命名；原 M6a 12–29 MiB 列保留原始数值，但解释更正为排空前读数；设计复测的实际排空约 cache 3.8 MiB、miss 8.7 MiB，另列原始与新测量来源。

每组额外测量一个无负载 60 秒 idle 窗口：daemon 独立 cgroup `cpu.stat usage_usec`、proc CPU、RSS/PSS/FD/thread/child；CPU 为 60 秒增量，报告相对 C 和 M6a opt3。正式 profile 仍保留工作负载 CPU。

每轮保存唤醒指标：主循环轮数、每秒轮数；poll 调用次数、每次实际等待纳秒的 min/p50/p95/p99/max；wait 原因（network/file/timer/timeout/runnable）；每个 listener 每轮 `step_udp` 次数、每次实际收包数、批量大小、分配/复用缓冲计数；DHCP/TFTP/TCP/reload 服务事件和被让出次数。计数器本身必须来自产品观测或不改变调度的诊断构建，不能从 QPS 反推后冒称 syscall 实测。Linux 网络 fd 是否进入公共 poll、2 ms timeout 的实际来源由这些计数定案；非 Linux `park_timeout(2ms)` 与 Linux 结果分开。

## 第 1 项：UDP 主循环

先用未修复 opt3 在 M6a 465 QPS／约42 ms p50 的固定 hit 负载采集上面计数，回答每秒主循环、poll、wait 原因和每轮收包。源码已知事实（不等于 Linux 根因已证）是 `main.rs:3282–3289` 每 listener 每轮一次 `step_udp`，`3469–3498` 单次 `recvmsg` 和新 `vec![0; 65,535]`；Linux 网络 fd 路径与文件等待要由计数验证，非 Linux 2 ms park 在 `3202–3203` 单独记录。

修复候选必须把网络 socket 和文件 fd 放入同一 poll/deadline 体系，空闲按最近 timer 到期等待；每 listener 每轮在固定 packet budget 内批量收包，处理每个包后运行 completion/公平性步骤，并明确让出 DHCP、TFTP、TCP、reload 的上限；接收缓冲复用且不读取未初始化字节。C 的 `check_dns_listeners` 单事件返回和服务公平性是参考边界，不能用无限 drain 饿死其他服务。

第 1 项预算硬门：UDP hit 稳态目标是施加的 10,000 QPS，p50 与 C 同数量级（候选回归门 p50≤1 ms 作为低成本保护线），正确答案/TTL/上游计数和 M5 169 项零新增差异；idle CPU 明显接近 C，DHCP 每 cycle CPU 不得新增回退。修复后必须以同一 9×3×5 协议重测；修复前 opt3/s UDP CPU、p95、吞吐机械差异保留但不用于切换建议。

## 第 2 项：TCP 方案 A

严格按 `M6B_TCP_MEMORY_DESIGN.md` 第 5 节第 2–6 步，在独立 worktree 实施方案 A：共享不可变内容块和规范名/索引分片，每连接仅独立小型 LRU；逐一覆盖 `Cache::snapshot/new/clear/start_insert/insert/remove/CNAME/negative/reverse/lease/policy/commit/import`、`tcp_cache_view`、accept/client/drop 和所有 mutator。S1–S8 合同必须保持：accept 固定快照、accept clock、子私有 LRU/删除/轮转/generation、原导出集合与顺序、即时导回、冲突/失败前缀、stale refresh、100-query/150s、日志/FD/退出边界。

顺序固定为：精确 C primitive/视图隔离门（含故意漏 detach、共享 LRU、CNAME 顺序错误负控）→服务合同门（父 UDP 新数据不可见、同连接自写可见、后连接可见、TTL/reload/lease/writeback/stale/EDNS）→资源和生命周期门（慢读写、RST/半帧、上游 EOF、日志 FIFO、TERM、100-query）→新增压力（20/上限连接、空/半满/4096、随机多 RR、100-query 重连、150s idle pin、父 churn、冲突和 interleaved reload/lease）→同一最终 ELF 的正式 135 窗口。

TCP 硬门：S1–S8 零新增差异、错误/FD leak=0；TCP 每正确请求 CPU 相对当前 M6a opt3 **不得劣化超过5%**，且必须保持相对镜像 C 的 CPU 优势（设计文档的硬门）；TCP 吞吐和 p95 不得回退超过5%。20 连接 cache 目标 PSS 4–7 MiB、miss 8–16 MiB、断连 3–6 MiB 是目标范围而非承诺，必须同时报告 0/1/5/15/60 秒排空值、live requested bytes、父/子 family PSS、reconnect 和未知 allocator 余量。方案 A 达不到 TCP CPU 硬门或任一语义门，保留失败证据并停止，不拼接 B/C 或不同实验的最好结果。

## 第 3 项及以后

只有第 1、2 项全部通过才允许评估缓存条目瘦身（规范名、单元素 Vec、HashMap 桶、小 RDATA）和 DHCP lease/DNS 发布副本；每项单独冻结、回归、实测和提交。无收益即撤回。任何 allocator/arena 也必须是独立候选，不能在 M6b 直接替换全局分配器。

## 回归、最终验收和报告

每次产品候选先跑新增低成本保护线：20 客户端 UDP cache hit p50≤1 ms、无负载 60 秒 CPU 上限按 M6b 首次修复后的 C/R 基线冻结、TCP 20 连接峰值 PSS 上限按复测后的 C/R 目标冻结；保护线只防明显回归，不能替代 135 窗口。随后跑受影响 M5 全部族、完整 M2、资源试跑、ENOSPC/EMFILE 和 APK 安装/升级/卸载/回滚生命周期；169 项不能新增差异。

最终报告 `M6B_REPORT.md` 必须包括：每项机制和 C/R 语义合同、M6a→候选→C 的吞吐/CPU/延迟/RSS/PSS/FD/thread/idle CPU/wake 对比、0/1/5/15/60 秒排空表、UDP 根因计数与修复前后、TCP A 全部 gates、体积变化、所有失败/作废/重跑、仍未解决差距，以及 opt3/s 是否值得切换。所有结果只代表 Oracle 构建机。报告提交后停止，等待用户决定是否切换 s 或进入 M7；物理路由器不碰。
