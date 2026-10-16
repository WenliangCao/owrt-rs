# dnsmasq-rs UDP 命中性能研究：旁观专家诊断（2026-10-16）

只读诊断。未改代码、未提交、未碰路由器和 oracle。所有数字均取自
`/Users/USER/Developer/owrt-perf-opt-20261015`（分支 `perf/dnsmasq-20261015`，
HEAD `e8792a64`）下的文件、各实验工作树的源码，以及 `~/.codex/sessions/2026/10/15-16`
的会话记录。下文路径若无说明，相对于该工作树的 `docs/dnsmasq/`。

每条结论标注 **[证据]**（文件里直接可查）或 **[推测]**（我的推断，附验证办法）。

## 0. 一句话结论

**方向走偏了：研究一直在压缩「回答路径的指令数和分配」，而真机证据和 oracle 证据
一致指向「每次查询在冷缓存的 A53 上触碰了多少代码行和数据行」。** G 之后四个候选
各只省 2–4 tick，不是因为没效果，而是因为它们优化的变量不是主导变量；同时 10 ms
tick 的 CPU 计量加上「单次必须 >8 tick」的门槛，把所有 3–8% 的真实收益当成噪声丢掉，
使小收益无法累积。最便宜的一轮真机实验（速率扫描 + C 骨架参照）可以在 10 分钟内
裁决这个模型，然后应当集中做一条「触碰缓存行最少」的 UDP 命中专用快路径。

## 1. 当前状态核对

| 项目 | 数值 | 出处 |
| --- | --- | --- |
| 真机基线（10-15）C / v0.2.0 UDP 命中 CPU | 82 / 138 µs/query | `PERF_OPT_20261015.md` 基线表 |
| E 对 v0.2.0 | 不可区分（E ≈ 138–146） | `audits/perf-opt-20261015/C_E_HIT_DIAGNOSTIC.md`：C 84，E 146 |
| G（源 `185db90c`）对 E，110 窗 | 138 → 116（−15.9%，11 tick，5/5） | `audits/perf-opt-20261015/loop/A53_CACHED_ZERO_FRAME_FULL_DEVICE_RESULT.md` |
| C 对 G 直接十窗 | 82 → 114（+39.0%） | `…/loop/A53_IMAGE_C_ZERO_FRAME_DEVICE_RESULT.md` |
| C 对 G（分段诊断同轮） | 86 → 126（+46.5%） | `…/loop/A53_G_UDP_STAGE_DEVICE_RESULT.md` |
| G 分段：full → receive | 124 → 74（−25 tick） | 同上 |
| G 分段：full → before-answer | 122 → 94（−14 tick） | 同上 |
| G 分段：full → skip-local | 116 → 110（3 tick，不可区分） | 同上 |
| G 命中分配 | 5200 次查询 1 次 128 B 分配 | `…/loop/G_UDP_ALLOCATION_DEVICE_RESULT.md` |
| G 之后：6ab / 5c / 1df / 9e / 803(opt2) | 3 / 4 / 2 / 2 tick 变快，803 反而 2 tick 变慢 | 各自 `…/loop/A53_*_DEVICE_RESULT.md` |
| F 对 F+idle-batch（去掉 EAGAIN 空读）真机十窗 | 126 → 126，0/5 | `…/loop/A53_UDP_IDLE_BATCH_DEVICE_RESULT.md` |
| oracle：G 对 C 用户态指令 / 周期 | −14.0% / +30.9%，IPC 0.664 → 0.437 | `…/loop/C185_HIT_STAT_CYCLES_RESULT.md` |
| oracle：G 对 C 内核态指令 / 周期 | +11.0% / +1.1% | 同上 |

用户摘要里的数字与文件一致。补充三点文件里有但摘要没提的事实：

- **同一个 G 二进制在不同轮次里测得 114、116、118、122、124、126 µs**（上表各轮），
  轮间漂移约 10%，大于轮内 W。这意味着跨轮比较不可信（研究已正确避免），也意味着
  5 对窗的轮内 W 低估了真实噪声。[证据]
- E 的分段诊断里 **C 完整路径 80 µs，E 的 receive 骨架 70 µs**；G 轮里 C 86，G 骨架 74
  （`…/loop/A53_UDP_STAGE_DEVICE_RESULT.md`、`…/loop/A53_G_UDP_STAGE_DEVICE_RESULT.md`）。
  即 **Rust 只收发包不处理，就已经花掉 C 完整处理成本的 86–88%**。[证据]
- oracle owner32 里 G 在 200 qps 时用户态 17.5k 周期/查询，饱和负载时 3.5k；IPC 0.44 对
  1.57；CPU 26 µs 对 4.3 µs（`…/dns/CACHED_ZERO_FRAME_OWNER32_RESULT.md`）。同一代码在
  乱序大核上，低速率时每查询用户态周期是饱和时的 5 倍。native hot15 探针的 IPC 约 2.63
  （`…/dns/LAYOUT_NATIVE_RESULT.md`）。[证据] 这是全套数据里最重要却没被当成线索的数字。

## 2. 对已做工作的评价

### 2.1 站得住的部分

- 证据纪律极好：冻结身份、哈希、独立复核、不选择性重跑。G 是真实的、完整验收过的
  16% 真机收益，TCP/DHCP/生命周期无可辨退化（上表来源）。[证据]
- 10-15 的 syscall/PMU 对账是整个研究里最有价值的两页：C 每查询 3 个 syscall
  （ppoll/recvmsg/sendmsg），E 多一次返回 EAGAIN 的 recvmsg，且多收 32 B `IP_PKTINFO`
  控制数据；两边 ppoll 都是 6 个 fd、无限超时；回答包都是 48/60 B
  （`…/loop/IMAGE_C_E_HIT_SYSCALLS.md`）。这把内核侧差异收窄到「一次失败 recvmsg +
  cmsg」；F 起已关闭静态 IPv4 的 cmsg，G 只剩那一次失败读。[证据]
- 分段截断诊断在没有 PMU 的路由器上是正确的思路，50 窗全部有效。[证据]
- G 的零分配结论可信（计数窗口）。[证据]

### 2.2 可能有误或被过度解读的结论

1. **「骨架 74 µs、处理 50 µs、其中构造回答 28 µs」不能直接和 C 比。** 没有测 C 的
   骨架。Rust 的 receive 模式仍包含多出的 EAGAIN 读、`SinglePoll::step`
   每次唤醒遍历约 15 个子系统的检查、`wait_for_files` 重建 pollfd 集合（源码
   `components/dnsmasq/src/main.rs` 4586–4700、4157–4300）。oracle 自采样里
   `wait_for_files`+`step`+`process_udp` 合计约 15% 用户周期
   （`…/loop/C185_HIT_STAT_CYCLES_RESULT.md`）。所以 74 里有多少是不可压缩的内核成本，
   多少是 Rust 自己的循环开销，目前**未知**。[证据+推测]
2. **「opt2 更小的二进制没带来收益，所以代码体积不重要」是错误推论。** 803 整体 .text
   少 98 KB 但热函数只缩几百字节（`…/loop/803_ACTUAL_SDK_CODEGEN.md`）。冷缓存下重要的
   是**每次查询实际触碰的行数**，不是文件总大小。[证据+推测]
3. **用 native 热循环筛掉布局原型是反向的。** reply-layout 因 native 的 configured-CNAME
   +7.2% 被「退役」（`…/dns/LAYOUT_SDK_RESULT.md`）。native 探针 IPC 2.6，是热缓存
   体制；布局改动的目的恰恰是冷缓存体制。用热体制否决冷体制的手段，等于在错的地方打转。
4. **「2–4 tick 未过门槛」被当成「无效」处理。** 5c（5/5 同向）、6ab（5/5）、fresh-address
   （5/5，变化恰等于 W）大概率是真实的 3–6% 收益，只是仪器看不见。它们没被叠加进任何
   后续候选（6ab 只合并了用户态微改动，不含 EAGAIN 修复和布局）。[证据]
5. **owner32 的 send-lag「退化」反复阻止 promotion**（9e、5c、185 自己）。send-lag p50
   0.68 → 2.76 µs 是饱和闭环里负载生成器的发送滞后，不是用户可见指标，不该作为门。
   [证据：`…/dns/CACHED_ZERO_FRAME_OWNER32_RESULT.md`]

### 2.3 方向性盲点与过早否定

| 方向 | 发生了什么 | 我的判断 |
| --- | --- | --- |
| 去掉每查询一次 EAGAIN 空读 | read-one 低负载 28→24 µs（oracle，−14%，内核周期 −16%），因高负载 +29% 被否；idle/busy 变体（源 `1b934951`）oracle 上 EAGAIN 5000→1、高负载中性；真机对 F 十窗 126→126，0/5（`…/loop/A53_UDP_IDLE_BATCH_DEVICE_RESULT.md`） | 这是用户 10-15 17:33 点名的最大项，**真机结果是零**。合理的空结果，但有保留：该轮没核实 1 ms 等待提示在慢得多的 A53 上是否真的消除了空读。G 源码 `main.rs:4957` 仍保留「speculative final WouldBlock receive」 |
| 静态绑定 IPv4 socket 的 `IP_PKTINFO` | F（`3a3d8e3e`）起已对静态 IPv4 listener 跳过 setsockopt（`net.rs:545`），G 继承 | 已对齐 C，无需再做；10-15 的 strace 是 E 时代的数据 |
| PGO | smoke3 成功、11 场景训练成功、use 产物建出；因 ELF 2,288,419 > 2,200,000 预算**从未运行**（`…/dns/PGO_TRAINING_RESULT.md`） | 用打包预算否决一个未测的 5–15% 量级实验。预算是策略不是物理约束，且有 `-pgso`/hot-cold-split 可压体积 |
| `-Ctarget-cpu=cortex-a53` | 本机 .text +8.7%，排到后面，未测（`…/loop/185_A53_LOCAL.md`） | SDK 的 C 用 A53 调度模型，Rust 用 generic。顺序核对调度敏感，值得一测，但优先级低于足迹 |
| 热代码分段聚类（c95） | 本机 rust-lld 不聚类，等 SDK GNU map，停在准备阶段 | 没试 GNU ld 2.43+ 的 `--section-ordering-file` 或 linker script；PGO 本身就做 `.text.hot/.text.unlikely` |
| C 骨架参照 / 内核地板 | 没做 | 一轮 10 窗就能把 74 µs 拆成「内核地板」和「Rust 循环开销」 |
| 速率扫描 | 没在真机做 | oracle 已证明 200 qps 时 80% 用户周期是冷启动开销；真机一轮即可验证 |
| oracle 缓存事件计数 | 只采了 instructions/cycles，没采 L1I/L1D/iTLB/branch-miss | 零成本的 perf stat 事件，直接给足迹数字 |

### 2.4 测量方法是否在限制进展：是

- **精度。** 真机 CPU 来自 `/proc/pid/stat` 的 100 Hz tick
  （`…/loop/A53_EXISTING_CPU_OBSERVATION_SCOPE.md`）。5000 次查询下 1 tick = 2 µs/query。
  同一二进制轮内 stage-full 在 116–124 之间（`A53_G_UDP_STAGE_DEVICE_RESULT.json`
  50 个窗），说明仪器本底噪声约 ±2 tick。门槛要求 >8 tick（16 µs，约 G 的 14%）在这个
  仪器下是合理的，**但仪器本身是可以换掉的**：路由器内核虽然 `perf_event_open` 返回
  ENOSYS、`schedstat` 不可用（`docs/reviews/R137_REGISTRATION_PHASE_RESULT.md:18`，主仓库），
  但 `clock_getcpuclockid(pid)` + `clock_gettime` 读的是调度器的 `sum_exec_runtime`，
  纳秒精度，任何 Linux 都有，不依赖 tick 记账。[证据+推测：机制是内核通用事实，未在该设备验证]
  另一条路是每窗查询数提高 10 倍（200 qps 跑 250 s，或 1000 qps 跑 50 s）。
- **门槛设计。** 「单个候选必须 >8 tick 且 >W 且 4/5 同向」加上「不过门不叠加」，结构上
  排除了任何小于剩余差距三分之一的单项改进。这不是统计谨慎，是把累积改进的路堵死了。
- **oracle 与 A53 的差异。** 筛选漏斗是 native hot15（热循环，IPC 2.6）→ owner32
  （oracle 200 qps，IPC 0.44）→ A53 十窗。前两级和 A53 的相关性很弱：9e 在 owner32
  高负载有收益、A53 不可区分；803 在 native/owner 中性、A53 反而 +2 tick。顺序核 A53
  无法用乱序隐藏缓存缺失，每次缺失完整暴露；oracle 即便在 200 qps 也只是「部分冷」。
  用 oracle 指令数筛选，等于用错的代价函数做梯度下降。
- **W 的定义。** W = 两侧相对全距的最大值，5 个样本的全距是极不稳定的噪声估计
  （p95 的 W 常达 200–400%，永远不可区分）。配对差值的符号检验或简单的配对置信区间更有力。

### 2.5 过程成本（供用户判断投入产出）

| 指标 | 数值 | 来源 |
| --- | --- | --- |
| 分支自 10-15 起的提交 | 835（docs 511、test 202、perf 58、fix 29、chore 16、feat 8） | `git log main..HEAD` |
| 触及产品源码的提交 | 33 | 同上 |
| docs 新增 / 产品源码变更 | +738k 行（1088 文件） / 约 2.3k 行 | `git diff --stat main..HEAD` |
| 工作树 / perf 分支 | 约 100 / 约 50 | `git worktree list` |
| 长驻代理 | 主线程 + 4 子代理，各约 29 小时 | `~/.codex/sessions` |
| 主线程工具调用 | 2507，其中 send_message 491、followup_task 192、sleep 160；压缩 10 次 | 同上 |
| 全部会话 token | 输入约 36.7 亿（绝大部分缓存命中）、输出约 736 万 | 同上 |
| E 之后的真机探索轮次 | 约 12 轮十窗、2 轮五十窗、2 轮计数窗；只有 zero-frame（即 G）被接受，G 之后净接受 0 | `…/loop/*DEVICE_RESULT.md` |

每个候选走「本机原型 → native240 → owner32 → 965 测试 → SDK → 两三轮独立复核 →
真机十窗 → 独立审计 → 多篇 docs」，约 4–6 小时换一个 2–4 tick 的结果。真机十窗本身
只要约 5 分钟。提交记录里大量「retain / bind / freeze …」类文档提交，和用户记忆里
「避免 gate-script 和 status-prose 膨胀」的要求相悖。

## 3. 剩余差距的来源：按可能性排序

真机差距：G 114–126 对 C 82–86，约 32–40 µs。内核路径种类相同（见 2.1），所以差距
只能来自 (a) 多一次 EAGAIN syscall，(b) Rust 用户态在 A53 上的周期。真机上去掉空读
的一轮是 0 tick，所以 (a) 至多是噪声量级；oracle 已证明 Rust 用户态**指令更少**，
所以 (b) 是周期/指令比，即停顿。差距几乎全在用户态停顿上。

### H1 冷缓存足迹（最可能，oracle 证据直接支持，A53 上为推断）

论点：200 qps 下相邻两次查询间隔 5 ms，期间负载生成器、上游、观察器和内核在同样两个
核上运行，L1（32 KB 级）必然被冲掉，L2 部分被冲掉。每次查询的成本由「触碰的不同
代码行 + 数据行 + TLB 项数 × 缺失延迟」主导，而不是指令数。顺序核 A53 不能重叠缺失。

依据：
- oracle 同一 G，200 qps 用户周期 17.5k，饱和时 3.5k；IPC 0.44 对 1.57（§1）。[证据]
- G 比 C 指令少 14%、周期多 31%；E 比 C 指令多 7%、周期多 55%
  （`…/dns/IMAGE_C_E_PMU.md`）。[证据]
- G 热路径分布在很多大函数里：SDK map 中 `step` 17,608 B、`wait_for_files` 7,304 B、
  `process_udp` 4,672 B、`answer_local_records` 12,132 B、`answer_records_general`
  13,364 B、`run_inner` 30,368 B（`…/loop/OWNER_READY_FRAMES_ACTUAL_SDK_CODEGEN.md`、
  `…/loop/803_ACTUAL_SDK_CODEGEN.md`、`…/dns/PGO_USE_SIZE.md`）。一次命中要穿过
  `step → step_udp → admit_udp → process_admitted_udp → process_udp →
  answer_udp_prepared_with_local → answer_local_or_cached → 本地回答器 →
  answer_fresh_address → writer → send`，并且 `udp_query::inspect`、`query_metadata`、
  `interface_forward_name`、`Question::parse` 对同一个包解析 3–4 次（`main.rs` 5171–5330，
  `dns/daemon.rs` 960–1009）。C 的 `-Os` 路径是 `receive_query → answer_request →
  send_from` 三个紧凑函数。[证据：源码；推测：行数差异的大小]
- 减指令数的微优化在真机只有 2–4 tick（§1）。[证据]

最低成本验证：
1. **真机速率扫描**：用现有工具把 200 qps 换成 1000–2000 qps，C 和 G 各五对，一轮
   约 3 分钟。模型预测两边每查询 CPU 都大幅下降，且 C/G 差距明显收窄。顺带每窗查询数
   提高 5–10 倍，tick 精度问题同时缓解。
2. **oracle `perf stat`** 加 `L1-icache-load-misses, L1-dcache-load-misses,
   iTLB-load-misses, dTLB-load-misses, branch-misses`，C 对 G，200 qps。只读计数，
   不是负载。缺失计数近似等于足迹行数。
3. **进程内分段计时**：aarch64 用户态可直接读 `cntvct_el0`（vDSO 就用它），在
   10–15 个段边界累加，一次运行给出 A53 全路径分段，替代 50 窗截断诊断。[推测：
   计数器频率和分辨率需在设备确认]

### H2 多一次 EAGAIN syscall（证据指向量级很小）

每查询一次 EAGAIN recvmsg：oracle 内核指令 +11%，read-one 低负载内核周期 −16%
（`…/loop/UDP_READ_ONE_RESULT.md`）。但真机 F 对 F+idle-batch 十窗 126 → 126、0/5
（`…/loop/A53_UDP_IDLE_BATCH_DEVICE_RESULT.md`）。[证据] 两种解释：A53 上一次失败的
recvmsg 确实只值 1–2 µs（低于 tick 分辨率）；或 1 ms 等待提示在 A53 上没触发，空读
并未消除（该轮未 strace、未计数）。两者都意味着它不是主因。验证成本：把
`m6b-diagnostics` 的 `would_block` 计数器（`main.rs:4977`）在真机开一次即可裁决。
`IP_PKTINFO` 已在 F 起对静态 IPv4 listener 关闭，不再是差异。

### H3 事件循环骨架开销（证据部分支持，量级未知）

`step()` 每次唤醒检查 ubus、DHCP 重绑定、接口收集、两个 logger、诊断信号、接口刷新、
所有 listener 的 UDP+TCP、上游、邻居、TCP 客户端、DHCP、EDNS 等待、TFTP、dump
（`main.rs` 4586–4700）；`process_udp` 每查询先做一次完整 `metrics()` 快照，包括借用
DHCP provider 读租约/消息计数（`main.rs` 4511–4527、5181–5198），而这个快照只在有
ubus 订阅者时才用。每项都便宜，但每项都碰自己的缓存行。oracle 自采样约 15% 用户周期
在循环函数里。[证据：源码与采样；推测：A53 量级 5–10 µs]
验证：C 骨架参照（给精确 C 打一个「recvmsg 后立即回固定应答」的诊断补丁，或写一个
60 行的 C echo 守护进程用同样 socket 选项测内核地板），一轮十窗。

### H4 数据结构指针追逐（H1 的子项，量级小）

命中查找链：`names` 分片 `Vec<Arc<NameIndex>>` → SipHash `HashMap<Arc<[u8]>,
SlotIndices>` → 槽索引 → `slots` → `content` 块 `Arc<ContentBlock>` → `Entry` →
`Arc<Record>`（`dns/cache.rs` 143–340）。约 8–12 次依赖加载；C 是桶链 → 内联名字和
地址的 `crec`。1df 把地址内联只换来 2 tick，说明数据链不是大头。[证据+推测]

### H5 内核侧参数差异（基本可排除）

65,535 B 的 iovec 不产生拷贝；oracle 内核周期 C/G 相差 1%。[证据]

### H6 分支预测冷启动（推测，低优先）

顺序核预测器小，冷启动后每个 Result/Option/边界检查分支都可能误预测。归入 H1 一并由
`branch-misses` 计数验证。

### 不是差距来源、但限制发现的因素

轮间 10% 漂移（§1）、无 cpufreq 策略目录、温度未记录。不改变结论，但意味着任何
<10% 的效应都需要配对且需要更精的仪器。

## 4. 未来最有希望的方向

按预期收益排序。收益数字都是 **[推测]**，以 G ≈ 120 µs 为基数，互相重叠不可相加。

### D1 UDP 命中专用快路径（架构级，预期 −20 到 −30 µs）

在 `recvmsg` 之后，用一个紧凑、非泛型、冷分支全部 `#[cold]`/`#[inline(never)]`
外提的函数处理最常见情形：单问题、A/AAAA、无 EDNS 或只有空 OPT、无查询日志/dump/
ubus 订阅/loop-detect/MAC 需求/接口规则、缓存里有未过期正记录。像 C 一样**原地**
在接收缓冲区写回答（翻 header 标志、追加 `0xc00c` 指针 RR、拷地址、按到期时间算 TTL）
然后 `sendmsg`。不满足任一条件立即回落到现有通用路径。目标：快路径触碰 <3 KB 代码、
<1 KB 查询外数据。

- 依据：分段诊断里 before-answer→full 28 µs、receive→before-answer 20 µs 几乎都在这
  条路径上；H1 成立时收益主要来自足迹缩减而非指令。
- 风险：语义等价。必须保留 C 在 `cache_find_by_name` 里的 LRU 触碰、过期判断、stale
  策略、计数器更新、`name_revision` 失效。现有 44 族差分和 1100 条 corpus 是现成的
  护栏；快路径的准入条件要保守，宁可少走。
- 代价：1–2 个工程日，加完整门。这是唯一能一次跨过 8 tick 门槛的方向。

### D2 单就绪 fd 的快速唤醒（预期 −5 到 −10 µs）

ppoll 返回恰好一个就绪 fd、它是 DNS UDP listener、且没有到期的 deadline 时，直接
进入该 listener 的 `step_udp`，跳过 `step()` 其余子步骤；`metrics()` 快照只在有订阅
者时计算。风险：公平性和「runnable」逻辑已在 `wait_for_files` 里计算，需要保证跳过
的子步骤确实都有各自的就绪条件；中等。代价：小。

### D3 去掉 EAGAIN 空读（预期 0 到 −3 µs，风险低，只作叠加项）

idle/busy 批读（`1b934951`）在 oracle 上消除空读、真机上 0 tick。不值得单独再测；
先用计数器确认它在 A53 上真的生效，然后作为行为等价的小项并入 D1 的候选。

### D4 为冷缓存做代码布局（预期 −5 到 −15 µs，风险低、流程成本中）

- 先把已经建好的 PGO use 产物（oracle `dns/private/pgo-train1`）放到真机测一轮，
  不管预算，先知道收益大小。PGO 自动做 `.text.hot/.text.unlikely` 分离，正是足迹模型
  要的。
- 体积：`-Cllvm-args=-pgso`（profile 引导的冷代码按大小优化）、`-hot-cold-split`、
  或冷 crate 用 `opt-level="s"`；都在主线程日志里查过的 LLVM 22 选项范围内。
  2.2 MB 预算本身是策略，AX3000T 闪存有余量，可由用户决定是否放宽 5%。
- GNU ld ≥ 2.43 的 `--section-ordering-file` 可把 D1 的快路径和它的 callee 放到连续
  页，解决 c95 卡住的问题。[推测：需确认 SDK binutils 版本]
- `-Ctarget-cpu=cortex-a53` 单因素测一次即可；它让热函数变大，足迹模型下可能为负。
- 整体 `opt-level="s"` 未测过（只测了 2）。OpenWrt 默认给 C 用 `-Os` 不是偶然；顺序核
  上密排代码的 iTLB（A53 一级 iTLB 只有十几项）收益可能超过展开的损失。

### D5 预序列化应答（9e 方向，预期单独 −2 到 −5 µs，与 D1 合并后更大）

把正记录的应答 RR 字节和到期时间存在条目旁，命中时 memcpy + 修 TTL。单独做只值
2 tick（已测）；放进 D1 的快路径里，它决定快路径的数据足迹是 1–2 行还是 10 行。

### D6 仪器升级（不是优化，但决定上面任何一项能否被看见）

1. 资源探针加 `clock_getcpuclockid` 纳秒 CPU 列，tick 列保留以兼容冻结协议；按 10-15
   用户批准补充协议的先例，写一份补充条款。
2. 研究筛选窗改为 1000 qps × 50 s 或 200 qps × 250 s，查询数提高 10 倍。
3. 门槛改为「配对差的方向 + 纳秒精度下的 W」，并允许**叠加后再过门**：小改动以组合
   候选上真机，而不是逐个否决。
4. 砍掉 native hot15 和 owner32 作为 A53 改动的前置筛选；只保留测试门 + SDK + 真机。

### 不建议的方向

recvmmsg/sendmmsg（200 qps 下没有批可打，已正确否决）、io_uring（OpenWrt 内核大概率
未启用，且不减少每包内核工作）、换分配器（命中已零分配；只对未命中有意义，且被冻结
协议禁止）、busy-poll（增加 CPU）。

## 5. 如果只给一条建议

**先用一轮 3 分钟的真机速率扫描（C 和 G 各五对，200 qps 对 1000–2000 qps）验证
「冷缓存足迹」模型；验证成立后，把全部精力放到 D1 这一条触碰缓存行最少的 UDP 命中
快路径上；同时把 CPU 读数换成纳秒时钟，让 5 µs 的收益可见。**

理由：现在每轮都在用热缓存指标筛、用 10 ms tick 判、在回答路径里省指令；这三件事
互相强化，使 40 小时的研究在 G 之后净接受为零。换掉代价函数和仪器，比再做十个
2 tick 的原型更重要。

## 6. 给 Codex 会话的具体操作建议（补充）

1. 停止为每个候选写「retain/bind/freeze」文档；每轮只留一份结果文件和一份计划文件。
2. 主代理按用户 10-15 17:35 的要求做工程，不做睡眠轮询和消息中继（主线程 160 次
   sleep、491 次 send_message）。
3. 清理约 100 个工作树和约 50 个分支，只留 G 标签、idle-batch、PGO 产物和当前研究树。
4. 把 send-lag 从 promotion 判据里拿掉。
5. 下一轮真机顺序：速率扫描（C/G）→ C 骨架或 echo 地板 → PGO use 产物十窗 →
   带 `cntvct_el0` 段计时的 G 诊断版一轮。四轮加起来约 25 分钟真机时间，能把 §3 的
   H1–H3 全部定量化，然后再动手写 D1。

## 附：本诊断读过的主要文件

- `PERF_OPT_20261015.md`、`PERF_OPT_20261015_PROGRESS.md`、`PERF_DEVICE_20261014.md`
- `audits/perf-opt-20261015/FROZEN.md`、`measurement-tools.json`、`experiments.json`、
  `candidate-g-acceptance.json`
- `audits/perf-opt-20261015/loop/`：`A53_G_UDP_STAGE_DEVICE_{PLAN,RESULT}.{json,md}`、
  `A53_UDP_STAGE_DEVICE_RESULT.md`、`A53_IMAGE_C_ZERO_FRAME_DEVICE_RESULT.md`、
  `A53_CACHED_ZERO_FRAME_FULL_DEVICE_RESULT.md`、`A53_CACHED_HIT_9E_DEVICE_RESULT.md`、
  `A53_UDP_THREAD_LOCAL_HANDLES_DEVICE_RESULT.md`、`A53_OWNER_READY_FRAMES_DEVICE_RESULT.md`、
  `A53_FRESH_ADDRESS_DEVICE_RESULT.md`、`A53_CACHED_ZERO_FRAME_DEVICE_RESULT.md`、
  `A53_UDP_IDLE_BATCH_DEVICE_RESULT.md`、
  `G_UDP_ALLOCATION_DEVICE_RESULT.md`、`C185_HIT_STAT_CYCLES_RESULT.md`、
  `C185_DEVICE_CPU_COMPONENTS.md`、`IMAGE_C_E_HIT_SYSCALLS.md`、`UDP_READ_ONE_RESULT.md`、
  `UDP_IDLE_BATCH_RESULT.md`、`PPOLL_CARDINALITY_RESULT.md`、`185_A53_LOCAL.md`、
  `185_OPT2_LOCAL.md`、`803_ACTUAL_SDK_CODEGEN.md`、`HOT_TEXT_SECTIONS_LOCAL.md`、
  `CONTIGUOUS_QUERY_NAME_LOCAL.md`、`A53_EXISTING_CPU_OBSERVATION_SCOPE.md`、
  `A53_CLOCK_READONLY_CAPABILITY.json`、`A53_CPUFREQ_IDLE_CAPABILITY.json`
- `audits/perf-opt-20261015/dns/`：`IMAGE_C_E_PMU.md`、`CACHED_ZERO_FRAME_OWNER32_RESULT.md`、
  `LAYOUT_NATIVE_RESULT.md`、`LAYOUT_SDK_RESULT.md`、`LOCAL_CACHE_LAYOUT_SCREEN.md`、
  `PGO_*.md`、`INLINE_ADDRESS_DETAILS_LOCAL.md`、`POST185_*.md`
- `audits/perf-opt-20261015/C_E_HIT_DIAGNOSTIC.md`、`C_E_HIT_SOURCE_ACCOUNTING.md`
- 源码（G 工作树 `owrt-perf-cached-zero-frame-20261016`，`185db90c`）：
  `components/dnsmasq/src/main.rs`、`net.rs`、`listeners.rs`、`metrics.rs`、
  `dns/daemon.rs`、`dns/cache.rs`、`dns/udp_query.rs`；诊断树
  `owrt-diagnostic-g-udp-stages-20261016` 的 `dns/udp_stage_diagnostic.rs`
- 主仓库 `docs/reviews/R137_REGISTRATION_PHASE_{PLAN,RESULT}.md`（路由器 perf 能力）
- Codex 会话：主线程 `01a13e93-9cf4` 及四个子代理的 jsonl（统计口径见 §2.5）
