# R140：Cortex-A53 编译候选的七负载实机比较计划

本页在结果采集前冻结规则。候选与 R136 使用相同运行时代码，只向固定编译配方
追加 `-Ctarget-cpu=cortex-a53`，不重新构建标准库，不改调度、IRQ、governor 或生产
设置。原配方控制必须逐字节复现 R136；两次 source SHA 清单完全一致、Cargo 有效
flags 只差这个选项，构建 proof 与实际 ELF 一起冻结。Oracle 只作功能门，不能用
其另一型号 CPU 上的速度筛除或推荐 A53 调优。

对照为精确镜像 C `cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88`
与 R136 `ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330`。
候选路径和完整 SHA 显式传给 [计划生成器](../../tools/r140/make_formal_plan.py)。
caller 固定为原 R136 全矩阵 ELF
`0ca42fbafe08b7ace0aaa90f78c08c9c0f69022a64f6d5073ab6ceb77a88e693`；不换成 R135
caller、R137 相位 caller 或 libubus caller。生成计划不访问设备。

只有同一 ELF 的 Oracle 功能检查、实机 wire/FD 与完整未过滤 Rust 单测通过后才能
冻结执行计划。实机前提为 `private/r140/router-correctness-01/{wire,fd}/result.json`；
前后 stock boot/健康必须一致，六项保护/清理标志全部为真，其中至少一门包含成功的
非零项完整单测。候选身份、前提、构建 proof、所有执行/分析输入均记入 SHA 清单。
另外要求同一模板与原 caller 的 C/A53 七负载功能 smoke：100 次、20 预热、共
14 case 全通过，provider/对象清理与身份齐全；它不产生性能筛选，结果不拼入实机。

## 固定采集

八个串行保护窗口。偶数窗口按 C/R136/A53，奇数按 A53/R136/C；两端各占四窗，
R136 固定居中。每个 subject 使用新 daemon，同一 daemon 按下表顺序运行七条
负载，每条 10,000 周期、20 预热。总数 **8 × 3 × 7 = 168 case**。
早期 A53 研究页提到的 native/SEND 只是备选范围；本次正式采集以这里的原 caller
七负载及 lookup/invoke 哨兵为准，不纳入其他负载。

| 负载 | 原始 caller 命令 |
| --- | --- |
| register_1 | `register-cycle SOCKET 1 8 10000 20 PID` |
| register_16 | `register-cycle SOCKET 16 8 10000 20 PID` |
| event_1 | `register-watch SOCKET 1 1 10000 20 PID` |
| event_8 | `register-watch SOCKET 8 1 10000 20 PID` |
| event_nomatch | `register-watch SOCKET 1 0 10000 20 PID` |
| lookup | `lookup SOCKET bench.target 10000 20 PID` |
| invoke | `rpc SOCKET bench.target ping INPUT_JSON EXPECT_JSON 10000 20 PID` |

前五条在空总线上执行。后两条使用同一个原 caller 的 `serve SOCKET 1` 提供唯一
对象 `bench.target`；invoke 输入 `{"n":1}`、逐次校验 `{"ok":1}`。provider 的
CPU 不混入 daemon CPU。对象清理、provider ELF/argv/PID/starttime、亲和性、日志
及退出码全部保留并检查。

daemon 固定 CPU1、argv0 `/sbin/ubusd`、默认 ACL、socket
`/var/run/ubus/ubus.sock`；caller/provider 允许 CPU0–1。每条命令与成功退出留存，
父 shell allowance 前后记录。原 caller 没有独立 live mask、context 或逐周期迁移
快照；不能从放置声明推导它实际在哪个 CPU 执行。daemon 前后 live mask 与身份可查。
沿用既有 120 秒保护器窗口，不为赶时限降低样本数或延长硬限；超时即保留失败并停止。

## 主收益门与延迟否决门

每个窗口、每条负载都配对计算 A53/R136，八窗不复用。

1. 每窗将七条 **mean latency 比值等权取几何均值**。八个窗口几何均值的中位数
   **严格小于 0.98**，且至少 **7/8 窗小于 1**，才通过主收益门。
2. 七负载各自的 mean/p95/p99 共 21 项中，任何一项的八窗比值中位数
   **严格大于 1.03**，且至少 **7/8 窗上升**，就否决候选。
3. 只有主收益门通过且没有上述否决项，才满足本轮性能规则。register_1 p95 是
   独立报告的次指标，不能替代广泛收益或抵消其他延迟回退。

七条等权是工程筛选选择，不代表真实流量分布，也不是把用户“90% 重视性能”机械
换算为 9:1 评分。相对 C 的所有同窗比较完整报告，用来观察竞争位置；不能代替
A53/R136 的改动验收，也不能据七负载宣称全面胜出或语言极限。

逐项比值使用精确分数。窗口几何均值使用 60 位十进制精度计算，先保留 30 位小数，
再算中位数与严格边界；恰好 0.98 不通过主门，恰好 1.03 不触发否决。
这些是预冻结工程规则，不是多指标显著性或等效性检验。

## CPU、体积与驻留观察

完整报告全部 168 case 的 mean/p50/p95/p99、daemon/caller CPU，以及两个控制下
每项的八个配对变化与中位数。CPU 不设新的硬统计门；较小 CPU 收益不能掩盖延迟
负项，大幅意外资源代价仍需如实说明和工程判断。

报告三个精确 ELF 的文件字节数。每个 daemon 在七负载前后记录
VmRSS/RssAnon/VmData/VmHWM，报告全部原值、同进程增量和候选对两侧控制的每个
正向差值；每lane的既有 native memory 字段也保留。它们仅描述本轮时点/生命周期，
不重新认证空闲连接、大消息、扇出驻留、PSS 或长期保留。R136 的完整内存结论仍只
属于 R136 ELF，不能直接转移给新编译产物。

## 完整性与停止条件

原始 archive 与展开文件逐字节核对；重算全部延迟和 daemon process-clock CPU，
不以 tick 回退。caller 只导出 clock delta，没有可独立重建的 before/after，限制保留。
全部 lane 同一个 daemon 的身份必须稳定；日志、对象残留、健康、清理与九组件生产
C 状态均须通过。各窗健康和 boot 一致，不把前后端 CPU 与 wall 相减推导等待。

精确执行八窗，不拼接旧 R136/R139 或 Oracle 性能样本，不据结果重测、删窗、改门
或补窗。任何功能、身份、超时、健康或清理失败都停止并保留原失败。
[分析器](../../tools/r140/analyze_formal.py) 复用 R130/R139 的严格 archive/proc/raw
读取器，完整报告全部正负项。通过本规则仅支持本轮编译候选的判断，不授权部署。
