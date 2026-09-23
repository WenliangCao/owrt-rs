# R138 Oracle：silent REMOVE 省 CPU，主延迟未分辨，按冻结规则停止

**本轮候选不进入路由器性能确认；保留 R136。** 两组互不重叠的 split CPU 对的 register-1 端到端 mean 变化为 −0.53% 和 −0.32%，均只有 2/4 块下降，未达到预先冻结的 −3%／至少 3/4 门槛。daemon CPU 分别下降 4.23% 和 3.55%，两对均 4/4 下降；CPU 节省不能替代主延迟门。

候选仅在没有 monitor、targets、subscribers，且对象无路径或没有事件 pattern 时，将 REMOVE 的 DATA／STATUS 合并发送；其他情况保留原路径。运行时代码只存在于独立候选快照，没有合入主线。完整 [240 条派生记录、60 个分层、所有有符号变化与证据哈希](r138-ubusd-oracle-results.json) 同时保留 C 和 R136 对照。

固定路径构建先完成：R136 逐字重现 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`，候选为 `85ea7b0ae1861001ad81360ca78d5dbbea916df788dbe4191f7cacbbbc2c83e2`，两者都是 514771 字节。两个源码快照只差 `ubusd/src/server.rs`，均由不变 R135 recipe 在 R137 私有 namespace 的同一 canonical 源码路径构建。同一候选源码的单元测试，以及精确 release 的 wire、FD 和恢复门完成后才开始计时；没有构建、诊断或另一性能任务与计时重叠。

[筛选政策](../../tools/r138/screen-policy.json) 随工具提交 `1866b4e` 在计时前冻结，并嵌入实际 manifest。沿用 R136 runner：C／R136／候选，daemon:caller 为 `1:0,3:2`，四个正反顺序块，每项 10,000 周期／20 预热，五负载、两种亲和性，共 240 项。两 CPU 对各自报告，不池化，不追加、删除或重跑窗口。

下表为候选相对 R136 的配对中位变化；CPU 对写作 caller／daemon。只有 split register-1 的 mean 和 daemon CPU 是主门。

| CPU 对 | caller 亲和性 | register-1 mean | register-1 daemon CPU | register-16 mean | register-16 daemon CPU |
|---|---|---:|---:|---:|---:|
| 0／1 | split | −0.53% | −4.23% | −1.68% | −4.82% |
| 2／3 | split | −0.32% | −3.55% | −0.38% | −4.45% |
| 0／1 | pair-allowed | −0.66% | −4.83% | +0.35% | −4.04% |
| 2／3 | pair-allowed | −3.38% | −5.60% | +0.34% | −3.48% |

所有五负载、两亲和性、两 CPU 对的 mean／p95／p99 均检查了预定退步否决：配对中位超过 +3%，且 4/4 块上升。没有触发否决，**不等于证明无回归**。例如 no-match 在 0／1 对的 p99 为 split +3.47%、pair-allowed +4.24%，两者均 3/4 上升；这些正项和逐块数值完整保留。三个具名 object-event 负载原本就应走 fallback。

计时结束后，六个固定 strace 案例确认 1／16 方法的每个 ADD／REMOVE 周期都是 **R136 3 次、候选 2 次 `sendmsg`**。请求、阶段和 EAGAIN／epoll 归属复用 R135 原解析器，没有把 tracing 的延迟或 CPU 纳入筛选。

另用原 R132 caller 控制 perf enable／ACK 和 disable／ACK，收集十二个固定窗口：三个受测版本、两方法数、两个相反顺序，每窗 10,000 周期／200 预热。全部计数器运行比例 100%，daemon migration 为 0。用户态指令每注册周期如下；这是用户态计数，不包含内核工作，不能把 PMU cycles 当作注册周期。

| 方法数 | R136 用户态指令／周期 | 候选用户态指令／周期 | 配对中位变化 |
|---|---:|---:|---:|
| 1 | 8091.58 | 7547.63 | −6.72% |
| 16 | 18086.11 | 17542.25 | −3.01% |

原始数据位于 ignored `private/r138/{build-01,screen-01,perf-01,syscalls-01}/`，完整下载归档为 `private/r138/oracle-01/raw.tar.gz`。远端与本地完整计时验证一致，另一次独立审计重算全部 240 项并核对 940 个归档文件及 24 次清理，结论一致；syscall trace 和 PMU 原始计数也逐案例重解析。没有访问路由器或新增候选。本结果只支持 Oracle CPU／指令及 syscall 节省，主端到端 mean 仍未分辨；它不能证明路由器不可能获益，也不能证明达到语言极限。
