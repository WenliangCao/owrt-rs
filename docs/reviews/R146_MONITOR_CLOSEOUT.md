# R146：monitor scatter/gather 实验未通过性能门，保留 R136

唯一候选通过正确性检查，但未通过预先冻结的延迟主门，**不晋级、不合入基线**。
monitor 平均延迟相对 R136 的配对比值中位数为 0.991788，仅下降 0.82%，
且只有 4/6 个区组下降；要求为严格低于 0.97，并至少 5/6 个区组下降。
daemon CPU 下降 11.20%、大包 VmHWM 降低 1536 KiB 均不能替代该门。
本次按停止条件结束，没有追加性能采样、调整阈值或启动第二个候选。

完整脱敏证据与独立审计见 [结果 JSON](r146-monitor-closeout-results.json)。
以下假设、范围和筛选规则在计时前冻结；完成结果及偏差在其后单列。

Baseline: generic R136, source `195e45f` (unchanged runtime at `6d2b22e`),
release SHA-256 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`.
This work does not deploy or run on the physical router. R136's four lifecycle
tail losses and R142's prior screening rejection remain valid.

## Hypothesis and scope

R145's fixed Oracle profile completed after correcting the collector's perf
ACK framing. Both R136 phases place allocator functions among the largest user
self-sample groups. This supports testing the source-visible per-mirror
allocation/copy costs; flat samples do not attribute every allocation to mirror.

One candidate changes only `ubusd/src/server.rs` and `ubusd/src/client.rs`:

- Assemble the fixed 48-byte monitor blob envelope on the stack.
- Send the wire header/envelope, borrowed original body and zero padding with
  the existing `sendmsg_three`, at each original mirror send boundary.
- Traverse the unique monitor list directly in registration order.
- On short writes or an existing queue, own the complete blob and retain the
  original offset, per-frame cap, silent drop, sequence and FD rules.

No persistent monitor scratch, cross-message batching, syscall wrapper,
dependency, caller change, compiler flag change or registration optimization.
The new candidate is not stacked on R142's persistent-buffer implementation.

## Validation and fixed screening rules

Before timing: reconstruct exact R136 at the canonical source path, build the
candidate once, run the same SDK/musl unit recipe plus monitor regressions,
wire/FD/recovery and independent monitor/native helper checks on its release ELF.
Keep source/build hashes, failures, raw output and cleanup evidence in `private`.

Reuse the existing R142 three-subject screen and **unchanged** policy:
C/R136/candidate, all six subject permutations, grouped/interleaved/monitor,
2,000 cycles per case with the original helper and 20 warmups. Total 54 cases,
108,000 cycles. Caller CPU0, daemon CPU1, fresh daemon per case. No concurrent
build, profile or other performance job, and no extension or discarded windows.

The primary gate remains monitor mean/candidate-to-R136 median ratio strictly
below 0.97 with at least 5/6 decreases. Any of the nine mode/mean-p95-p99 ratios
strictly above 1.03 with at least 5/6 increases vetoes the candidate. Report
daemon CPU, caller CPU, their within-case sum, p50 and all C comparisons; these
do not override the latency gate. A failed screen ends this candidate, without
new threshold or code variants. Passing only permits separate device validation.

Additional independent large-message residency and queue checks assess the
absence of persistent monitor capacity; large-message gains cannot stand in
for the small-message primary lane. Oracle results do not settle A53 costs or
the separate unmonitored registration/object-event tails.

## 构建、正确性与执行偏差

候选仅修改 [mirror](../../components/ubusd/src/server.rs) 与
[Client 发送路径](../../components/ubusd/src/client.rs)，没有新增运行时依赖。
栈上封装与借用正文消除了完整直写时的用户态镜像正文复制；短写或已有队列仍拥有完整帧。
监视器遍历从快照后反复查找改为原注册顺序的一次遍历，但本次小包 helper
只有一个 monitor，不能用这次结果量化多 monitor 的复杂度收益。

冻结候选经历两次构建：source-01 后独立审查发现一个新测试缺少 Linux cfg，
source-02 修正 cfg，并补充边界测试。两次变化仅涉及测试，两个最终 release ELF
**逐字节相同**；两次控制重建也均复现原 R136。所有性能计时均在 source-02
正确性检查完成后进行，没有用测试修正挑选性能版本。原计划的“build once”
因此发生了测试修正所需的重建，不能表述为只执行过一次编译。

| 检查 | 完成结果 |
|---|---|
| SDK/musl release 单元测试 | 62 通过、0 失败；测试 ELF 与 release 分列身份 |
| wire 协议场景 | 8 种、24 份 transcript，C/R136/候选逐场景一致 |
| FD 场景 | 每侧 6 种，C/R131/候选共 18 例满足各自既有契约，差异如下 |
| recovery | 候选通过 2 种；C 复现 2 种已知缺陷，分类核对通过 |
| 原生 helper 功能检查 | C/R131/候选各 4 例，共 12 例通过 |
| 独立 monitor 边界检查 | C/R136/候选各 2 例，共 6 例通过 |
| 内存诊断 | 3 个 daemon、48 个快照；helper 留存每例 10 个完整镜像字节校验、FD 恢复与清理通过记录 |
| 性能筛选 | 固定 54 例、108000 个测量周期全部完成；结论为拒绝 |

新增回归覆盖不对齐正文、队列上限、借用源被覆盖后的数据所有权、实际大包短写及
后续帧 FIFO、header/envelope/body/padding 内部恢复偏移、超大帧零写丢弃后的小帧直写、
多 monitor 独立序号与慢读者，以及 monitor 兼任 event owner 的 `M1,E1,M2,E2` 顺序。
部分微小偏移用既有队列恢复状态建模，另有真实 socket 短写测试，不能混称为全部
偏移都由内核实际产生。正确性通过仅覆盖上述场景，不构成所有状态的形式证明。

FD 的三个正常发送端 framing 场景与 C 一致；另外三个手工 framing 场景符合候选
既有 read-ahead 契约，**三例的 FD 归属均不与 C 相同**，不能声称全量 C 等价。
FD 和原生 helper 的额外历史控制是 R131，只有 wire 与专门 monitor 检查使用 R136；
归档原生 helper 的历史目录名 `r134` 实际指本次候选，身份按 ELF 哈希判断。
C recovery 的半关闭未给出完整回复；lookup-delete 未继续服务且进程退出 −11。
两者是留存的已知缺陷，分类检查通过不能把它们变成 C 行为通过。

复用了原 R142 筛选器与 policy，仅新增
[R146 manifest 绑定工具](../../tools/r146/make_screen_manifest.py)，将源文件、构建、
62 项单元测试和正确性证据绑定到该 release。主线程在本地重算的完整筛选 JSON
与远端结果一致，866 个筛选证据文件哈希全部通过；原分析器的 5 项回归通过。
未更改 R142 policy 中保留的历史 scope 字符串。

独立审计另外直接从原始整数重算 378 个指标、42 组原比较和 6 组合计 CPU 比较，
复核 54 对前后身份、54 个独立 daemon 与清理记录，以及 240 项功能原始记录哈希。
归档内 1502 个普通文件与展开文件逐字节一致。原生/monitor/内存的完整 payload
校验依据是 helper 留存的断言结果；归档未保存全部镜像帧，未宣称进行了离线字节重放。

## 性能结果

各项为六个区组内 candidate/reference 比值的中位数变化百分比；括号为
**下降区组数 / 6**，不是置信区间。均值、分位数分别先在每例内计算，不能把
各例拼接后重算当作本表。所有严格阈值使用原始整数与精确分数判定，表内仅做显示舍入。
按冻结口径，±1% 内标为未分辨，不能解释为等价或已证实改善。

相对 R136：

| 模式 | mean | p50 | p95 | p99 | wall/op | daemon CPU/op | caller CPU/op |
|---|---:|---:|---:|---:|---:|---:|---:|
| grouped | +0.25% (2/6) | −0.15% (3/6) | +0.76% (2/6) | +0.98% (3/6) | +0.25% (2/6) | −0.07% (3/6) | +0.35% (2/6) |
| interleaved | +0.55% (1/6) | +0.25% (2/6) | +0.65% (2/6) | −0.75% (3/6) | +0.55% (1/6) | −0.60% (4/6) | +1.16% (1/6) |
| monitor | **−0.82% (4/6)** | −0.83% (4/6) | −0.50% (4/6) | **+2.08% (2/6)** | −0.82% (4/6) | **−11.20% (6/6)** | **+5.26% (0/6)** |

相对精确 C：

| 模式 | mean | p50 | p95 | p99 | wall/op | daemon CPU/op | caller CPU/op |
|---|---:|---:|---:|---:|---:|---:|---:|
| grouped | −7.94% (6/6) | −8.07% (6/6) | −7.96% (6/6) | −8.45% (6/6) | −7.93% (6/6) | −20.62% (6/6) | −1.21% (4/6) |
| interleaved | −1.70% (6/6) | −2.49% (6/6) | −1.55% (6/6) | −1.55% (4/6) | −1.70% (6/6) | −12.98% (6/6) | +3.65% (1/6) |
| monitor | **+1.58% (1/6)** | +1.72% (1/6) | +1.05% (1/6) | **+3.03% (1/6)** | +1.58% (1/6) | −9.03% (6/6) | +5.03% (0/6) |

九个 candidate/R136 延迟 veto 均未触发，**主门失败本身已足以拒绝候选**。
相对 C 的 monitor p99 虽超过 3%，C 比较不在这次硬门内，不能事后将它改写成
触发 veto 的理由，也不能因为未触发 veto 就称为通过。

daemon 与 caller 合计 CPU 必须先在每例内相加，再进行相同区组配对；
不能把两列百分比相加，或用 daemon 的节省替代链路总节省：

| 模式 | 合计 CPU/op 相对 R136 | 合计 CPU/op 相对 C |
|---|---:|---:|
| grouped | +0.06% (2/6) | −10.53% (6/6) |
| interleaved | +0.27% (1/6) | −4.50% (6/6) |
| monitor | **−1.94% (5/6)** | **−0.88% (4/6)** |

caller CPU 在 monitor 的六个区组均上升，这是必须保留的代价。
现有采样不能证明 CPU 工作从 daemon “转移”给了 caller，也不能确定调度、轮询、
缓存或验证各自的因果份额。原 helper 把 caller 的接收、poll 与校验计入延迟；
其结果说明 daemon 的局部成本降低没有转化成预定的端到端改善。

## 大包内存诊断

使用原 monitor-memory helper 的 sample 模式，C/R136/候选各启动一个新 daemon，
保留 1 秒和 5 秒快照。下表“大包后”是 768 KiB 输入之后的观测值，
在停止 monitor 和断开连接的后续快照中相同，单位 KiB：

| 指标 / 阶段 | C | R136 | 候选 |
|---|---:|---:|---:|
| 空闲 VmHWM | 920 | 500 | 500 |
| 大包后 / 停止 / 断开 VmHWM | 3096 | 3508 | 1972 |
| 空闲 RssAnon | 72 | 44 | 44 |
| 大包后 / 停止 / 断开 RssAnon | 844 | 44 | 44 |
| 空闲 VmData | 44 | 48 | 48 |
| 大包后 / 停止 / 断开 VmData | 816 | 48 | 48 |

候选的 VmHWM 比 R136 低 1536 KiB，本 fixture 未观察到相对 R136 新增的持续匿名驻留。
每个 subject 仅一个 daemon；这些数据是描述性诊断，不能包装成多次重复的统计结论。
VmHWM 是内核暴露的进程驻留高水位，不是分配器精确峰值；1 秒/5 秒快照也不能
捕获全部瞬态驻留。它支持本候选的大包空间收益，不能替代小包延迟主门。

内存 workload 的完成记录早于第一个性能身份记录约 49.22 秒，未与筛选并发。
远端 driver 退出 0、原始 COMPLETE 与清理记录均存在。随后单独关闭一个滞留的
本地 SSH transport（transport 退出 255）；关闭前确认无对应远端进程或命名空间挂载。
该传输层清理与已经成功结束的 workload 分开记录，未重跑内存或性能测试。

## 身份、归档与结论边界

| 产物 / 证据 | SHA-256 |
|---|---|
| 精确 C | `cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88` |
| 原 R136 / 两次控制重建 | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` |
| R146 source-01 / source-02 最终 release | `963b7c6ed777c0d94f97b116a8c1f1af87ee66242f6a8fe039a31b68b651c266` |
| source-02 单元测试 ELF | `c69804cdaf46922430ee81a1095c504cb54bd99b2c73b216dd9d1d8206aedc89` |
| 原 monitor helper | `1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499` |
| 原 R142 policy | `e97f8070957a7602e380b2847facae3d60ec19a31e33f7954a0dca85b2d05899` |
| R146 完整留存归档 | `953eb8727c0070f0f075bd41335b0b53e3c90e5160bf35b4258562891018b5e5` |

原始源快照、构建/测试 ELF、输出和采集证据保存在忽略目录
`private/r146/evidence-01.tar.gz`（5969199 字节）及展开目录；传输清理记录单列于
`private/r146/local-transport-cleanup.json`。Git 仅留代码、工具和脱敏派生报告。
R145 profile-01 的 ACK 失败、修正后的固定 profile-02 与归档身份另见
[R145 报告](R145_MONITOR_PROFILE_RESULT.md)，没有从该失败中丢弃有效 helper 样本。

这个结果缩小了后续解释空间：本实现确实存在可降低的 monitor 局部成本，但移除这些
分配/复制不足以通过本次端到端门。它不证明 Rust 天生慢于 C，也不能承诺靠继续
减少某个局部操作就能收尾。跨镜像合批仍受
[同 socket 顺序与队列语义反例](R145_MONITOR_BATCH_BOUNDARY.md) 约束。

R136 继续作为基线；实验仅保留在 `codex/ubusd-closeout` 分支。
R136 的 [四项生命周期尾延迟负项](R136_UBUSD_COMPLETION_RESULT.md)、
[R142 的既有拒绝](R142_SCREEN_RESULT.md) 以及
[R143 实机 monitor 的未分辨结果](R143_MONITOR_RESULT.md) 均未被本实验解决。
Oracle 也不能替代 A53 的候选验证。所有 ubusd 工作负载仅在 Oracle aarch64 测试服务器执行，未访问或修改物理路由器，
不触发设备验证、不修改验收口径、不声明 ubusd 已完成收尾。
