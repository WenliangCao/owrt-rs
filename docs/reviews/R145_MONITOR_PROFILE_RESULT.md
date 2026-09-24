# R145：原 monitor helper 的 Oracle 平坦采样

profile-02 的固定四阶段 C/R136/R136/C 全部完成，留存证据审计通过。R136 分配器 family 的 **459 个 self 样本占全部样本 14.08%、用户态样本 56.11%**；这是后续源码审查线索，不是分配次数、调用链成本或可获得的性能提升。完整脱敏计数与身份见 [结果 JSON](r145-monitor-profile-results.json)，采集约束见 [冻结方案](R145_MONITOR_PROFILE_PLAN.md)。

每阶段独立 daemon、10 次原 helper，每次 monitor n=5000/warmup=20；共 40 次调用、200000 个测量周期、800 次预热。只有一个 monitor；八个 handler 共用一个 owner，另有 sender，共三条连接。记录 cpu-clock 499 Hz、strict-freq、8 MiB buffer、CLOCK_MONOTONIC，无 callgraph；daemon CPU1、caller CPU0、采集器 CPU2–3。

**严格为 whole invocation。** 原 helper 没有 perf 握手；daemon enable/disable ACK 包围整次启动与完成，caller 也包含 launcher/loader。样本覆盖初始化、建连、注册、预热、计时循环、校验、拆除和输出，不能标作只覆盖 5000 次循环。daemon 的 ACK 窗口还包含启动器/recorder 的边界开销。perf 的 daemon 元数据另列自动 dummy:u 事件，实际全部 PC 样本均来自 cpu-clock。

| 阶段 / daemon | daemon 全部 | daemon 用户态 | daemon 未知用户态 / 占用户态 | caller 全部 | caller 用户态 | caller 未知用户态 / 占用户态 |
|---|---:|---:|---:|---:|---:|---:|
| 1 / C | 1603 | 317 | 163 / 51.42% | 2286 | 377 | 242 / 64.19% |
| 2 / R136 | 1632 | 446 | 0 / 0.00% | 2300 | 405 | 267 / 65.93% |
| 3 / R136 | 1628 | 372 | 0 / 0.00% | 2313 | 347 | 212 / 61.10% |
| 4 / C | 1598 | 258 | 127 / 49.22% | 2296 | 365 | 229 / 62.74% |

四个 daemon 都超过预冻结的 1000 样本下限，没有补采。R136 合计 3260 个样本，其中内核态 2442、用户态 818，后者全部落在匹配符号范围；这不表示所有内联路径都有单独归属。C 合计 3201 个样本、用户态 575，其中 **290 / 575（50.43%）未知**：libc 187、libubox 103，均为 no_function_range，不能当作零成本。

分配器 family 按精确符号名计数，包含下表六个 musl 内部成员及公开 malloc/calloc/realloc/free；每个互不重叠的 PC 范围只计一次，别名不重复计数。分母分别为全部样本、全部用户态样本，未知样本保留在分母中。合计先加样本数，再计算比例。

| 范围 | family self 样本 | 全部样本 | 用户态样本 | 占全部 | 占用户态 |
|---|---:|---:|---:|---:|---:|
| phase 2 daemon | 244 | 1632 | 446 | 14.95% | 54.71% |
| phase 3 daemon | 215 | 1628 | 372 | 13.21% | 57.80% |
| R136 daemon 合计 | 459 | 3260 | 818 | 14.08% | 56.11% |
| phase 2 caller（10 次） | 0 | 2300 | 405 | 0.00% | 0.00% |
| phase 3 caller（10 次） | 0 | 2313 | 347 | 0.00% | 0.00% |
| R136 两阶段 caller 合计 | 0 | 4613 | 752 | 0.00% | 0.00% |

| R136 family 成员 | phase 2 | phase 3 | 合计 |
|---|---:|---:|---:|
| `__libc_malloc_impl` | 70 | 60 | 130 |
| `__libc_free` | 61 | 46 | 107 |
| `__libc_realloc` | 31 | 34 | 65 |
| `alloc_slot` | 38 | 43 | 81 |
| `nontrivial_free` | 40 | 32 | 72 |
| `__malloc_alloc_meta` | 4 | 0 | 4 |

RawVec 增长包装函数另有 13/20、合计 33 个 self 样本，未混入上述 musl family；memcpy、memset、锁/原子操作、blob 构建与内核样本也未纳入。平坦采样不能把分配器的 self 样本进一步归给 mirror 或其他调用者，不能用 family 占比推导消除分配后的速度变化。

caller 的同口径 family 命中为 0，但 R136 两阶段 caller 有 **479 / 752（63.70%）未知用户态样本**；C 两阶段 caller 为 471 / 742（63.48%），同样没有已解析 family 命中。动态库隐藏符号、无匹配映射等仍保留未知，所以不能断言 caller 没有分配开销。40 份 caller 中的 5 个快照前用户态样本全部保留为未知，未用后来的映射反推。

审计核对了四阶段顺序、40 份 helper 结果和样本数组形状、44 份 raw/detail/stats/report/符号汇总、48 份身份快照、44 个互异目标进程、80 个 ACK、4 份清理记录。合计 **15656 个样本**，所有 LOST、LOST_SAMPLES、THROTTLE、UNTHROTTLE 和未解析文本行均为 0。每次 helper 都收到并校验 40000 个事件及 40000 个匹配镜像，handler 删除、FD 基线恢复、caller/perf 退出通过；daemon 退出 0，daemon perf 正常 SIGINT 退出 −2，清理错误为空。ACK 全部为 `61636b0a00`（`ack\n\0`），顺序与采样/身份时刻交叉检查通过。

profile-01 **继续保持 FAILED**：旧 ACK 比较错误拒绝含终止 NUL 的回应，在首个 helper 启动前停止，完成调用数为 0；清理通过，其数据未进入 profile-02。修正后的 runner 精确读取五字节 ACK。两份计划的 28 项输入内容中只有 runner 改变，其余 27 项相同，部分路径迁移不算内容变化；daemon、helper、库与符号身份沿用原值。

| 产物 / 证据 | SHA-256 |
|---|---|
| 精确 C | `cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88` |
| 原 generic R136 / 控制重建 / 带 map 重建的最终 release | `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330` |
| 原 monitor helper | `1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499` |
| profile-02 plan | `6aa61bb7cd59288608073561b1c437485fed7b59588d9b50f479fbdda3133480` |
| 完整留存归档（含 01 失败） | `9754d0230b3985e8202378c26e07f5ac1be928bc9d0c8f66dd69f3c7c6ec918b` |

归档内 **1189 个文件与展开文件逐字一致**。本地另核对 runner、recorder、symbolizer 三个脚本的冻结 SHA。28 项采集后输入检查的依据是哈希匹配的 runner 在全部报告完成后逐项复查，再写 passed results 和 COMPLETE；留存两者均存在，工具没有另写逐输入后验日志。此采集归档不含全部 ELF/构建/符号输入，完整 ELF 同一性和 C 62/R136 908 个符号范围沿用冻结构建门及 live 身份记录；本次没有重建、重新符号化或在本地复读全部远端输入。

这是 Oracle aarch64 的描述性 self PC 分布，不能移植为 Cortex-A53/实机占比；不是 inclusive 成本、等待时间、因果归因或性能验收。高未知覆盖尤其限制 C/caller 与静态 R136 的函数占比比较。R142 拒绝及 R136/R143 已有性能负项不变；独立留存证据审计没有访问路由器、修改采集器或新增采样。

主线程在采集 profile-02 前修正了 ACK 解析，`tools/r145/test_monitor_profile.py` 的四项回归在本地和 Oracle 均通过，覆盖终止 NUL、连续 ACK、分片、错误/提前关闭和超时。未改 daemon/helper、采样频率、阶段顺序或调用预算。
