# R131 尾延迟补测

原 `router-04` 的 18 个窗口证明了单连接八处理器场景的平均 wall 和 CPU 改善。
但原冻结计划同时要求 p95/p99 护栏，旧 caller 没有采样，因而整项实验应为
**均值与 CPU 子项通过、尾延迟门待完成**。原始窗口、旧计划、旧报告及历史判定不改写；
本补测单独冻结，不能把旧 aggregate 数据当作逐次 latency，也不与它合并。

新 helper 使用同一 exact-image libubus API，daemon CPU1、caller CPU0、argv0 `/sbin/ubusd`。
仅 `EVENT_LATENCY_MODE` 编译增加采样；原 R131 helper ELF 没有替换。
每次 `CLOCK_MONOTONIC` 样本从发送前开始，到该次全部预期 callback 完成（无匹配时 drain 返回）结束。
因此 `user_8_1` 是完整八回调事务延迟，不是首个 handler 的延迟。payload、callback 数和 handler 清理仍检查。
5000 个 64 位样本在计时前分配并预触页，计时结束后输出。计时器与验证开销不扣除，各候选使用同一 helper。

计划为 C/R124/R131 的六种排列，共 18 个全新路由器窗口；每场景 5000 次、200 次 warmup。
每窗测 `user_1_1`、`user_8_1`、`user_1_0`。使用窗口内原始样本计算 mean/p50/p95/p99，
分位数规则为排序后索引 `floor((n-1)*q+0.5)`；每个路由器窗口才是一个配对观察值。

预冻结判定：R131 对 R124 的 `user_8_1` sample mean 必须六块全降且配对中位下降至少 3%；
该 lane 的 p95、p99 或 daemon CPU/op 配对中位上涨超过 5% 则不通过。
两个 guard lane 保留旧规则：wall/daemon/caller 任一指标六块全升且配对中位超过 5% 则不通过。
±1% 记实用平手，不追加窗口追求通过。相对 C 独立报告所有方向。

Oracle 上 exact C/R124/R131 × 三个场景各执行 100 次、20 次 warmup 的功能预检。
九场景均验证 100 个正整数 latency 样本、callback/payload、handler 清理与 CPU affinity；
Oracle 时间只作 JSON 和功能校验，不参与性能结论。SDK 构建首尝试因工具权限失败，原日志保留；
最终构建及九场景结果保留在忽略的 `private/r131-latency/`，派生验证结果见
[`r131-latency-oracle-smoke.json`](r131-latency-oracle-smoke.json)。

路由器生产始终保留 C，每窗口经既有 recovery/namespace/identity/cleanup 门。
补测通过仅关闭该场景的尾延迟缺口；其他 fanout 布局、背压、内存和九组件集成由各自测试负责。
