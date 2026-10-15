# 独立 F / Cortex-A53 编译实验

仅准备，未构建 SDK、未运行远端测量、未选入 G。产品基线是精确 F
`3a3d8e3e` / ELF `b7926bcf…`。实验提交 `c076835d` 只在 dnsmasq 的
packaging Makefile 中加入 `-Ctarget-cpu=cortex-a53`；components Git tree
与 F 完全相同，F 原分支和原 recipe 不变。证据见
[`F_A53_CODEGEN_PREPARATION.json`](F_A53_CODEGEN_PREPARATION.json)。

设备只读结果是两核 Arm `0x41` / part `0xd03` / revision 4，DT 为
AX3000T/MT7981，镜像包架构为 `aarch64_cortex-a53`；Arm 官方资料将
`0xd03` 识别为 Cortex-A53。[Arm MIDR 说明](https://developer.arm.com/community/arm-community-blogs/b/soc-design-and-simulation-blog/posts/comparing-arm-cortex-a72-and-arm-cortex-a57)

精确 SDK `.config` 的 SHA 与 F build receipt 一致，已有
`CONFIG_CPU_TYPE="cortex-a53"` 和 `-Os -pipe -mcpu=cortex-a53`；这是 SDK
C 目标，不能当成 Rust 已使用 A53 调度。F Rust recipe 没有 target-cpu。
本地同版 rustc 1.98.1 / LLVM 22.1.8 查询显示默认 `generic`，显式 A53
会增加 AES、CRC、SHA2、PMUv3 等目标特性，设备公布的 AES/PMULL/SHA1/
SHA2/CRC32/ASIMD 与其相关指令要求相符。这不是仅改变调度的开关。
[rustc target-cpu](https://doc.rust-lang.org/rustc/codegen-options/index.html#target-cpu)

PMUv3 编译能力不代表该内核开放 perf，也不授权用户态直接读取 PMU。
项目没有 PMU 内联汇编；不新增 helper、软件包或内核设置。已有 router
盘点无法支持硬件 IPC 实测，因此设备结果仍报告 CPU/query 和延迟。

F 已使用 `opt-level=3`、`lto=true`、`codegen-units=1`、`panic=abort`。
这里的 `lto=true` 已是 fat LTO。ThinLTO 主要是另一种优化与编译成本
权衡，当前没有这份产物上能提升 IPC 的证据，因此本变体不改 LTO、
codegen units 或 opt level。后续若测 ThinLTO，必须另作单变量对照。
[Cargo profile 文档](https://doc.rust-lang.org/cargo/reference/profiles.html#lto)

## 排期和构建对照

1. 先完成当前 F 的原正确性门和 Oracle/router 两份完整 110 窗口；此
   实验不得占用它们的构建/测量时段。用户要求的空读和 cache/layout
   产品实验分别完成后选 G，本编译变体单独评估，不叠加产品补丁。
2. 取得下一个 SDK 构建时段。使用精确 F 已用的外部修复 builder
   SHA `f4540b1c…` 和 helper `f280b97d…`；F 源分支内继承的旧 builder
   SHA `d33f5c07…` 不是 F 实际构建器，不能直接拿它重建。
3. 用原 F recipe 重建控制，要求 stripped ELF 恢复 `b7926bcf…`；否则
   保留失败并调查构建条件。然后只替换实验 source 的那一个 recipe
   flag，使用独立输出目录。builder 的 recipe 上锁/恢复和 SDK 输入核验
   保持原样。产物不能覆盖 `sdk-f`。
4. 两个实验构建明确固定 F 的 `SOURCE_DATE_EPOCH=1792083838`。Git identity
   分别记录 F/实验 commit 和各自 input blob，但 epoch 都写此固定值；
   receipt 说明它是共同复现参数，不冒充实验 commit 的提交时间。
   保留完整实际 rustc invocation，核只有 target-cpu 改变代码生成参数。
5. 每个变体保留 ELF、APK、prestrip、同次 link map、全部源/SDK/compiler
   SHA、recipe restore 证明、节大小与现有 ELF/APK budget。重编译改变
   布局或启用特性本身不是性能通过依据。

## 正确性和独立整机比较

编译变体必须重新绑定原正确性门到自己的精确 ELF，不能只引用 F 已通过。
在准入前冻结命令、身份、顺序和窗口数量；复用新版本工具 f7c7 loadgen/
702042 cohort/10addedf analyzer，不再改负载。五轮交替 F/A53、A53/F，
完整 11 场景，110 窗口，原 W、配对方向、8 tick 精度、资源/健康门。
不得挑选单个最快场景、合并历史 F 样本或无限重复到有利结果。

Oracle 的完整 daemon screen 只能说明其 CPU 上的运行结果。独立 perf
诊断可比较同侧 instructions、cycles 与 IPC，但 Oracle 并非 Cortex-A53，
不能把 Neoverse 上调度变体的 IPC 外推成设备结论。最终是否改善用户所指
CPU 差距，仍取决于 AX3000T 同机成对 CPU/query 的可辨别下降；若设备
PMU 依旧不可用，就如实保留 IPC 未测量的限制。

保持无可辨别主指标回退和原资源门。只有 latency 下降而 CPU 在
W/8-tick 精度内，不能宣称 CPU 差距缩小。结果与产品结构优化分别呈现；
如果将来两者都值得采用，另冻结组合产物并重新验收，不相加单项收益。
