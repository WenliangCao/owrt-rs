# R142：单个 monitor 候选的 Oracle 筛选

在候选计时前冻结以下规则；候选只含 [monitor scratch 改动](R142_MONITOR_PLAN.md)，不叠加 PGO 或 A53。构建控制必须逐字节复现 R136 `ce3d1aa…`，正式 manifest 随后绑定唯一候选 ELF、源码/构建/正确性证据、原 helper、精确 C/runtime libraries 与全部工具 SHA。

复用原 R131 helper `1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499` 和既有 [Oracle identity/fixture 校验器](../../tools/r134/ubusd_stress_oracle.py)，不改 caller。固定 caller CPU 0、daemon CPU 1，串行执行 C/R136/candidate 的六个全排列；每个 subject 依次 grouped、interleaved、monitor，每 case 新 daemon。每 case 2,000 周期、20 预热，共 **6 × 3 × 3 = 54 case、108,000 个测量周期**。mode 顺序不轮换；六排列使每个 subject 在三个位置各出现两次。无并发构建、训练或其他计时工作。

- 主门：monitor mean(candidate/R136) 的六 block 比值中位数严格 **<0.97**，且至少 **5/6 下降**。
- 否决：三模式各 mean/p95/p99 共 **9 项**，任一比值中位数严格 **>1.03** 且至少 **5/6 上升**即拒绝。
- 对 C 和 R136 的所有延迟、wall、daemon/caller CPU 指标完整报告。CPU 与对 C 比较不另设硬门；包含边界的 ±1% 记未分辨，不能称等效。
- 原始整数重算指标，精确分数计算比值及中位数。恰好 0.97 不通过主门，恰好 1.03 不触发否决。
- 一个固定候选、54 case 全纳入，不挑 block、不补窗或重试挽救。大消息及空闲保留内存另立 guard，不进入性能样本。

每 case 记录原始 JSONL、完整命令、daemon PID/starttime/实际 affinity、进程映射及 ELF/library hash、前后状态与退出清理，核对 payload、目标、序号、交付/镜像数、handler 移除与 FD 基线恢复。helper 源码内部成功设置 caller CPU 0 并核验 daemon CPU 1；保留其原工具能力，不把结果中的固定 CPU 字段解释为逐操作调度轨迹。

原 helper 的 monitor 模式只开一个 monitor，使用小 payload；延迟含 caller 逐 owner 的 poll、收包和验证，latency 数组未预触页。此结果只能比较相同工具下的三个模式，不能当纯 daemon 延迟、多个 monitor、大消息、长期内存或完整实机结论，也不能修复或抵销无 monitor 注册慢尾。旧 R131 的历史 monitor 结果不代替本轮 R136 控制。

[机器规则](../../tools/r142/screen-policy.json) 在 manifest 中逐字节绑定。通过仅是考虑独立实机验证的前提；正确性和大消息/闲置保留内存必须另行通过，生产仍为 C。
