# R141：单一 generic PGO 候选的 Oracle 筛选规则

本规则在候选性能数据产生前冻结。只比较一个预先锁定训练记录与 profdata 的
profile-use ELF；控制仍为精确 C 和 R136 `ce3d1aa…`，不叠加 A53 编译参数。
构建控制须逐字节复现 R136，两侧源码相同，有效 flags 仅增加 profile-use 与缺失
profile 警告选项。训练完成后绑定 ELF、profdata、训练结果/计划与构建 proof 的 SHA。

直接复用 [R136 collector](../../tools/r136/oracle_batch.py)，不重写采集器或 caller。
caller 固定为 R135 原有 ELF `85dd537a070e39373a4a21a6bf982da9359bc70e61e53cdf93516b9c34684b1d`。
两个不重叠 CPU 对各运行四个正反顺序 block；每个 subject/block 用新 daemon，
其内覆盖 split/pair_allowed × register_1/register_16/event_1/event_8/event_nomatch，
每 case 10,000 周期、20 预热。总计 **2 × 4 × 2 × 3 × 5 = 240 case**。
两个 worker 并行但每个 CPU 对内部顺序执行，仍共享宿主资源，不能当独立机器重复。

对每个 CPU 对**分别**应用以下规则，不能跨 CPU 对合并掩盖失败：

- 主门仅看 split：每 block 先对五负载 mean(PGO/R136) 比值等权取几何均值。
  四 block 几何均值中位数严格小于 **0.99**，且至少 **3/4 block 小于 1**。
  **两个 CPU 对都必须通过。**
- 延迟否决覆盖两 CPU 对、两放置、五负载的 mean/p95/p99 共 **60 项**：任何一项
  四 block 比值中位数严格大于 **1.03**，且 **4/4 上升**，就拒绝候选。
- CPU 完整报告，不设硬门。落在包含边界的 ±1% 带内只能记未分辨，不能称明确
  幅度或等效。等权是工程筛选选择，不代表真实流量，也不把 wall 减 CPU 当等待。

个体比值从原始样本/时钟差算精确分数；几何均值采用 60 位十进制、保留 30 位
小数后做中位数与严格边界判断。恰好 0.99 不通过主门，恰好 1.03 不触发否决。
[机器规则](../../tools/r141/screen-policy.json) 与 manifest 中的规则及 SHA 必须一致。

全部 240 case、六个延迟/CPU 指标、两控制、所有逐 block 比较、60 项否决检查与
两组主指标完整输出；验证 hashes、原样本、CPU clocks、caller/daemon 身份、实际
affinity、命令和清理。冻结一个 profile，不据筛选结果重训、换 profile、挑 block、
补样本或追加候选。**筛选未过就停止这条 PGO 方向，不为路由器挽救它。**

通过也只是考虑独立实机验证的前提；后续仍须 PGO 自己的精确 ELF 功能门、独立
七负载性能与资源观察。R140 的功能、内存和性能证据均不得移植到 PGO。

[manifest adapter](../../tools/r141/make_screen_manifest.py) 只核验已完成的 use build、
八类训练/一次合并、原 C/caller/library 身份并绑定规则；不训练或测量。
[分析器](../../tools/r141/analyze_screen.py) 直接复用既有全量读取器，再应用本次门。
已有 Oracle 路径可访问时，正式 collector 固定参数为
`--pairs 1:0,3:2 --repeats 4 --iterations 10000 --warmup 20`，禁止 `--subjects` 筛掉控制。
