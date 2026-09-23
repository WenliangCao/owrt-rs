# R137 注册慢尾：分相探索与扰动校准

本计划在诊断测量前记录。只构建独立 Rust `owrt_ubus::Connection` caller，复用
`register-cycle` 的路径、方法签名、ADD/REMOVE 调用和完整签名检查。精确 C 与
R136 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`
daemon 不重编译；不替换 `85dd537…` 正式 benchmark，不改变运行时代码。

同一个诊断 ELF 提供三个模式：`cycle-wall` 仅周期两端读 wall；`phase-wall`
增加 ADD 完成边界，分别记录 ADD/REMOVE；`phase-cpu` 在周期前、ADD 后、REMOVE
后三处各读取 wall/caller CPU/daemon CPU/wall。CPU 模式的中间采样会延迟 REMOVE，
这是可能改变唤醒与尾部的干预，必须单独校准并公开。

每个 CPU 快照保留两端 wall、两个 CPU 原值。ADD wall 从第一快照结束到第二快照
开始，REMOVE wall 从第二快照结束到第三快照开始；完整 cycle wall 包含中间采样。
CPU 差值覆盖自身两次读之间的区间，含部分采样开销，不冒充精确请求执行 CPU。
同一进程的 wall-CPU 只能近似说明非 CPU 部分；两核 caller/daemon 可重叠，
**不得将 wall−caller CPU−daemon CPU 称为阻塞或调度等待**。

## 固定探索范围

- 先 Oracle 做 C/R136 × 三模式 × 1/16 方法的 n=100、warmup=20 正确性 smoke，
  不作性能排名。完整签名检查、末尾空对象检查、单线程、PID/starttime/亲和性不变均必需。
- 实机由主线程既有恢复/健康保护器独占执行，预定两个相反顺序窗口；每窗
  C/R136 × 三模式 × 1/16 方法，各 n=2,000、warmup=200。caller/daemon 的 CPU
  亲和性沿用本轮冻结正式条件，并记录；不以换亲和性撤销旧慢尾结论。
- 每 case 预先分配并触碰全部采样空间；计时内不打印、不写文件、不读取 `/proc`。
  正式循环前统一记录 256 组 wall、caller CPU、跨进程 daemon CPU 与组合快照的空读
  wall 括号，之后才预热。保留全部原始值，不把空读中位数从请求数据中相减。
- 按 case 报 cycle mean/p50/p95/p99、两相相同指标、CPU 和采样括号。
  `phase-wall/cycle-wall` 衡量拆相干预；`phase-cpu/phase-wall` 衡量多时钟干预。
  保留所有模式与正反窗口，不删慢样本、不追加窗口；探索没有候选采纳门。
- 对每 case 自己的 cycle p95 尾集合，同时列 ADD、REMOVE、各相 CPU 与其余样本，
  只作共现线索。尾部主要在哪相、有无 CPU 同涨决定下一次研究问题，不据此直接改 runtime。
  任一模式若改变慢尾形状或 C/R136 相对方向，CPU 模式不能代表原 formal 尾部。

## tracing 能力与解释边界

主线程只读观察：router 无 `perf`；`/proc/self/schedstat`、schedstats/perf sysctl、
tracefs 事件目录及 PMU event_source 均不可用；文件系统列表含 debugfs、不含 tracefs。
不能仅据工具缺失断言内核配置。镜像 revision `f5dae5e` 的 generic 配置禁用
PERF_EVENTS/FTRACE/SCHEDSTATS，但 filogic 配置又启用 PERF_EVENTS，仍需最终配置或
小型 `perf_event_open` 能力探针裁决。本 caller 仅对自身打开 disabled 的 software
task-clock + context_switch event，立即关闭，输出成功或原始 errno；不开始计数、
不改 sysctl、不挂载 tracing。打开成功只证明接口接受配置，不等于已经验证记录可用。

Linux 6.12.94 的 [proc 源码](https://github.com/gregkh/linux/blob/v6.12.94/fs/proc/base.c)
表明 schedstat 受 CONFIG_SCHED_INFO 控制，统计关闭时会返回全零；文件存在也不足以
证明运行队列统计有效。[sched 统计源码](https://github.com/gregkh/linux/blob/v6.12.94/kernel/sched/stats.h)
在调入/出队更新 run_delay，所以逐请求读也有边界滞后，不能直接当连续时间轨迹。

如果 perf syscall 可用，后续可用小型 recorder 直接打开 software dummy event，设置
context_switch/sample_id_all/use_clockid，记录两目标线程的切出/切入，无需 perf CLI
或 tracefs。匹配 [UAPI](https://github.com/gregkh/linux/blob/v6.12.94/include/uapi/linux/perf_event.h)
提供切出抢占标志，但没有 wakeup 时间：睡眠切出到切入仍混合阻塞与唤醒后的排队。
要精确拆开两者仍需有效 schedstat 或 sched_wakeup + sched_switch 轨迹，不能宣称
仅有 context-switch 记录就完成三分归因。当前最小方案只定位 phase 与 CPU 共现。

R135 探索与确认的 ELF 布局混杂、R136 同路径身份复现结论保持不变；不盲试新的
收发控制流。源码暂未发现比已采纳 path/Entry/字符串优化更直接且能解释慢尾的低复杂度修复。
