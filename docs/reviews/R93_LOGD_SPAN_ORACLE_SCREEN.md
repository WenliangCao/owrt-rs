# R93 logd span：Oracle 四侧筛查

2026-09-15。五场景、四侧、四轮共 **80/80** 完整通过。所有输入、完整帧/字段/正文/ID/顺序、保留环和清理检查保持开启。
独立 deadline、父进程 SIGKILL、watchdog 自身 SIGKILL 三个 Linux 故障门通过；普通与 setsid 后代全部回收。此前单轮小量 pilot 20/20 通过，明确不作为性能数据。

## 结论

**span 在大量尾随空格输入上有可重复的 CPU 收益；八读者路径仍明显输 C，无订阅者交付 wall 又比 control 更高，没有达到全面胜双基线。** 无订阅者 wall 退步是当前不能认可合入的重要疑点。候选保持私有，未部署。

CPU 中位数，单位 µs/输入；每侧每格四次。

| 场景 | C | R89 | source05 control | span |
|---|---:|---:|---:|---:|
| no_subscriber | 2.550 | 2.050 | 2.000 | 1.975 |
| follow_1 | 4.578 | 5.188 | 4.883 | 4.425 |
| follow_8 | 15.869 | 22.125 | 21.667 | 21.362 |
| trim_heavy | 3.575 | 4.825 | 4.550 | 3.100 |

trim-heavy 的 span CPU 比 control/R89/C 中位数分别低 **31.9% / 35.8% / 13.3%**。四轮原始 ticks：

- c: [73, 73, 69, 70]
- r89: [92, 97, 98, 96]
- control: [92, 90, 88, 96]
- candidate: [62, 62, 54, 64]

八读者 span CPU 比 C 中位数高 **34.6%**；该差距在全部四轮存在。span 与 control/R89 的小差值应结合原始 ticks 和逐轮范围判断。

## 仍未解决的交付耗时

无订阅者 span aggregate wall 中位数 **2.282 µs/输入**，control 为 **2.090**，高 **9.2%**；四轮 span 全部更慢，其最小值也高于 control 最大值。CPU 的约半 tick 中位差不能抵销这个现象，也不能把 wall 直接归因于 daemon；尚需拆解生产者/调度成本。

逐轮 no_subscriber；每行都是相同 200,000 条完整交付，单位毫秒。driver CPU、logd CPU 与 wall 相邻展示，避免把总耗时归因混淆。

| 轮 | 侧 | driver CPU ms | logd CPU ms | wall ms |
|---:|---|---:|---:|---:|
| 1 | c | 472.117 | 510.000 | 522.573 |
| 1 | r89 | 367.770 | 350.000 | 368.229 |
| 1 | control | 418.713 | 410.000 | 419.576 |
| 1 | candidate | 456.035 | 400.000 | 456.652 |
| 2 | c | 482.357 | 520.000 | 531.420 |
| 2 | r89 | 413.070 | 410.000 | 413.598 |
| 2 | control | 416.445 | 400.000 | 417.068 |
| 2 | candidate | 455.475 | 390.000 | 456.098 |
| 3 | c | 391.300 | 440.000 | 444.755 |
| 3 | r89 | 423.319 | 410.000 | 423.821 |
| 3 | control | 378.441 | 370.000 | 378.881 |
| 3 | candidate | 433.504 | 390.000 | 433.856 |
| 4 | c | 471.247 | 510.000 | 515.591 |
| 4 | r89 | 421.449 | 410.000 | 422.041 |
| 4 | control | 418.247 | 400.000 | 418.852 |
| 4 | candidate | 469.613 | 410.000 | 469.983 |

control/span 的 driver CPU 都接近 wall；span 的 driver CPU 每轮也更高。该关系提示生产者 syscall/调度交互需要继续拆解，**不能径直归因于 daemon，也不能因为 driver 占主导就丢弃真实交付退步**。corpus/归一化/保留环 hash 每侧每轮相同；corpus 构造发生在计时前，无订阅者场景没有接收 worker 线程。

已有数据仅含 daemon 总 CPU ticks、driver `process_time`、wall，以及 RSS/HWM/PSS/private dirty/FD 和进程身份。没有 user/system CPU 拆分、上下文切换、schedstat 等待/运行、逐线程 CPU 或 core migration 计数，现有结果不能完成归因。

交付 wall 中位数，单位 µs/输入：

| 场景 | C | R89 | source05 control | span |
|---|---:|---:|---:|---:|
| no_subscriber | 2.595 | 2.089 | 2.090 | 2.282 |
| follow_1 | 9.356 | 10.283 | 9.745 | 9.712 |
| follow_8 | 84.120 | 89.964 | 90.439 | 90.681 |
| trim_heavy | 3.628 | 4.886 | 4.608 | 3.142 |
| backlog_600 | 30.477 | 25.121 | 24.397 | 19.751 |

## 内存和测量边界

测量结束 RSS 中位数（KiB）：

| 场景 | C | R89 | source05 control | span |
|---|---:|---:|---:|---:|
| no_subscriber | 934 | 462 | 526 | 520 |
| follow_1 | 934 | 568 | 652 | 566 |
| follow_8 | 938 | 462 | 528 | 524 |
| trim_heavy | 932 | 546 | 612 | 602 |
| backlog_600 | 1480 | 1018 | 1078 | 1072 |

稳定无订阅者、八读者和 backlog 场景，span 比 control 的 RSS 差仅约 4–6 KiB，仍比 R89 高约 54–62 KiB。单读者测量结束时 RSS 波动大；关闭后 span/control/R89 中位数为 522/528/460 KiB，不能将单次读者缓冲峰值差当作持久容量节省。

- backlog_600 的 daemon CPU 和恢复 CPU 仍低于十 ticks；保留全部样本，不能解释成零成本或微小胜负。
- 单读者样本虽超过十 ticks，只有约 14–18 ticks，不能凭一两个 tick 推断稳定的小幅收益。
- wall 是发送到完整交付的总区间，包含生产者和接收器影响，不是逐条响应延迟。完整检查位于区间外的部分也不计入 wall。
- Oracle 不是 AX3000T 实机；本结果不能解释旧整机日志 lane 高 29.49% 的全部原因，也不能替代后续实机比较。
- 这是正常完整交付和已有正确性门的证据，不是所有故障都不存在的证明。

## 可复核入口

- 派生 JSON：[r93-logd-span-oracle-screen.json](r93-logd-span-oracle-screen.json)，含每格全部四次 ticks、CPU、wall、RSS，以及二进制/工具完整 SHA。
- 私有新证据：`private/r93/logd-four-side-resumed-02/execution-01/`。旧失败、旧 pilot 和历史冻结 source05 未修改。
- 结束后 binary/helper/ns-exec/ubusd 身份复核通过，所有本批 namespace、临时 rootfs 和 owned 进程为空。没有设备访问、部署或生产配置修改。
