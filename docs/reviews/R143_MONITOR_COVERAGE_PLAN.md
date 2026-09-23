# R143：当前 R136 的实机 monitor 覆盖

本轮只补精确 C 与当前 generic R136 `ce3d1aa…` 的独立实机覆盖。采集接口中的 `candidate` 始终指 R136；不包含已拒绝的 R142 `367badc…`，也不作新候选采用或部署决定。旧 R131 历史结果不能代替这次测量，原有 R136 无 monitor 注册慢尾仍保留。

## 性能与预冻结统计

固定十个完整配对窗口；零起始偶数窗 C→R136，奇数窗 R136→C。每侧新 daemon，同 socket `/var/run/ubus/ubus.sock`、argv0 `/sbin/ubusd`，daemon CPU 1/caller CPU 0。原 native helper `1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499` 只运行 monitor 模式：每 case **5,000 周期、20 预热**，共 20 case/100,000 个测量周期；driver iterations 也是 5,000。helper 上限 5,000，不能直接改成 10,000。

统计单位是十个配对窗口。每个指标先从单 case 原始整数重算，再取同窗 `ratio = R136/C`。**mean 为主项，p95/p99 为尾项；三个指标各预声明低、高两方向，共六个假设，同属一个 Holm 家族，α=0.05。** 不得看完方向后只报告三个单侧 p 值。

- 降低检验支持数为 `ratio < 0.99` 的窗口数；升高检验支持数为 `ratio > 1.01` 的窗口数。
- 每个检验固定 `n=10`，单侧精确二项符号 p 值为 `Σ(j=k…10) C(10,j) / 2^10`。阈值相等和其他窗口均是不支持的试次，不能删去 ties 或改分母；这是对边界质量保守的处理。
- 六个 p 值全部进入 Holm：按 p 从小到大排序，校正 p 是至当前项的 `max((6−i)×p[i])`，封顶 1。所有比较使用精确分数；校正 p **≤0.05** 才称对应指标“确认降低超过 1%”或“确认升高超过 1%”。
- 其余均记未分辨。包含边界的中位变化 ±1% 是未分辨幅度带；即使中位变化在带外、但校正后证据不足，也不能称已确认方向。没有显著升高不证明非劣或等效。
- 全部十个原比值、原值、幅度中位数/范围、相对 1 和两个阈值的方向数、原始与校正 p 均报告。p50、outer wall、daemon/caller process CPU 全报，但不进入六项延迟家族，不把 wall−CPU 解释为等待或机制。

精确符号推断仍以窗口符号独立为假设；同一路由器连续窗口不是独立机器重复，交替先后只能平衡位置，不能证明没有时间相关。Holm 容许指标间依赖，不消除窗口间依赖。方法对应 [R 精确二项检验](https://www.stat.ethz.ch/R-manual/R-devel/library/stats/html/binom.test.html) 与 [Holm 校正](https://stat.ethz.ch/R-manual/R-devel/library/stats/html/p.adjust.html)。不把每窗 5,000 个循环当成 5,000 次独立重复。

只采固定十窗，全量纳入；失败和负项保留，不挑窗、补窗、改阈值或重跑挽救结论。原 helper 的延迟含 caller poll、收包和验证，数组未预触页；只有一个 monitor 和小 payload，不是纯 daemon 延迟或全部 monitor 负载。

## 独立驻留观察

另采三个配对 memory 窗口，顺序正/反/正，driver iterations 为 1。既有 monitor-memory helper 固定 `sample` 模式、caller CPU 0/daemon CPU 1；每侧新 daemon。八阶段分别为 empty、connected、monitored_small、large_32768、large_262144、large_786432、stopped_connected、disconnected，每阶段在 **1s/5s** 各快照一次，共每 case 16 个快照、六 case 96 个快照。

最大 payload 为 **768 KiB**，不是协议最大帧。核对十个完整镜像及独立序号、停止后不再收镜像、FD 基线恢复、固定 PID/starttime 与 CPU。保留 elapsed_ms，验证 sample 的真实等待，不接受 smoke 的零延迟数据。报告 VmRSS/RssAnon/VmData/VmHWM 的原始 KiB、同延迟 empty 基线增长、同窗 R136−C 绝对差及三个值的范围；尤其完整列出大镜像后、停止但仍连接、断连后的保留。原始 FD 数和所有正增长均保留。

这是描述性驻留观察，不宣称显著性、峰值分配、精确 heap/PSS、泄漏或等效。没有另行冻结的资源预算时不能宣布资源接受；C 自身也会保留 monitor buffer。memory 数据与性能检验完全分开。

## 证据接口与身份

性能、内存各有独立 plan 和结果目录：`monitor-plan-01`→`monitor-01/window-0…9`；`memory-plan-01`→`memory-01/window-0…2`。每窗复用既有 disposable namespace、恢复门与 driver 六项 health 断言，绑定 exact C/R136/helper/launcher/lib/脚本与分析器 SHA，核对同 boot、stock 组件身份、配置、挂载和清理。

每侧 `caller.jsonl` 保留全部原始字段；另存 NUL 分隔 caller argv、before/after status/stat/cmdline/exe SHA、C maps、空日志/对象表、caller exit 0、daemon exit 0/143 和 COMPLETE。归档与展开目录逐项哈希一致；所有 case 使用相同 socket/argv0。正式计划冻结前确认准确路径与字段，不能让分析器静默回退其他 schema。

[机器规则](../../tools/r143/policy.json) 与最终 plan 的规则/hash 必须一致。正式采集前冻结全部输入和支持文件；分析器只读归档，无 router 访问或自动补采。
