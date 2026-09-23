# R137 注册分相诊断结果

**两窗共 24 例完成并通过证据校验，但未确定慢尾根因。** 每例 2,000 周期、200 预热，覆盖 C/R136 × 1/16 方法 × 三种 mode；完整签名、空对象、PID/starttime、亲和性、全部时钟边界、原始 archive 与展开文件一致性，以及保护器健康／清理检查均通过。root 与独立分析 JSON 逐字相同。

诊断 caller 的 `cycle-wall` 本身也没有复现原 formal 的单方法 p95 劣势：candidate/C 在两窗分别为 −5.10%、−11.37%。因此这些样本不能替代原 formal，**原 formal 尾部负项不撤销**。

16 方法 cycle p95 的 candidate/C 差异随 mode／窗口改变：

| 窗口 | cycle-wall | phase-wall | phase-cpu |
|---|---:|---:|---:|
| 0 | +24.47% | +16.21% | +18.83% |
| 1 | −18.29% | +74.64% | +6.40% |

窗 1 candidate 的 `phase-wall` 相比自身 `cycle-wall`，p95 增加 79.96%；增加 CPU 采样后，相比 `phase-wall` 又下降 31.33%。中间 CPU 快照平均约 3.02–3.14 µs，确实干预 REMOVE 的开始时间；**两窗不足证明这些翻转由采样单独导致**，也不能把 CPU 模式当作原 formal 尾部的替身。

16 方法 candidate 的 `phase-wall` 自身 p95 尾集合中，ADD／REMOVE 分别占周期时间的 52.0%／48.0%（窗 0）、54.3%／45.7%（窗 1）；两相都变慢。CPU 模式也观察到尾集 CPU 共涨，但这不能确认 ADD 或 REMOVE 根因，更不能用 wall 减两进程 CPU 推导阻塞或调度等待。REMOVE 生命周期可列为后续研究问题，本轮没有证明额外优化潜力。

24 例 disabled self `perf_event_open` 能力探针均返回 **ENOSYS（38）**；未启动计数或 tracing。

首次分析把 `window-0.log`／`window-1.log` 误算为窗口，失败记录已保留；`a49ec19` 只修正目录筛选，额外窗口目录仍被拒绝。未改原始证据、未重测。

[完整脱敏派生 JSON](r137-registration-phase-results.json) 保留全部 24 例统计、mode 校准、两窗比较、tail/rest 相位贡献、CPU 与采样括号，以及证据文件哈希；去除了绝对路径、PID、starttime 和设备身份值。原始证据与初次分析失败保留在 `private/r137-phase/`。
