# netifd 性能研究：2026-09-26

状态：进行中；没有候选完成实机确认，没有宣布收尾。沿用当前工作线；ubusd R136 已关闭。
原始输入、配置、ELF、候选补丁和失败构建只放在 ignored `private/netifd-20260926/`。
Oracle 对应 `/home/ubuntu/netifd-research-20260926/`。本报告只提交派生事实，不提交设备秘密。

## 身份与最小证据地图

| 对象 | 身份 / 证据 | 边界 |
|---|---|---|
| 当前代码起点 | `520d746`，初始工作树干净 | 后续共享库已变，不能沿用 R94 的最终身份验收 |
| 精确 C netifd | `8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90` | 用户提示的 `8edc0c6…` 为转写差异；设备 `/sbin/netifd`、运行 `/proc/PID/exe`、历史/设备 manifest 一致 |
| 正式 R89 | `b127c49888b70a1f1e59318c0b05661623e05030b923975881e4b2279388a478` | 设备 `/root/r89-before-r90`；不是 Oracle、source05 或 R92 |
| 镜像/内核 | OpenWrt 25.12.5；6.12.94；原镜像 SHA `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea` | Wi-Fi 管理；生产九组件始终 C；只允许 namespace 实验 |
| 上游 | netifd `cbb83a1857407a28a63dc09412a1f209195914ef`；tree `76488605b3c105e04cd228b2bd8e37676a15df25`，无补丁 | `private/upstream-ref/netifd-ref` 没有自己的 `.git`，不能用向上搜索得到的根仓 HEAD 代替上游身份 |
| 无线脚本 | `wireless.uc` SHA `e369670e9b92d0cdef5b116570be21d952b4f58fa462fc95e58a4f717b662738`；`wireless-device.uc` SHA `b42b77c783542e2f56e264910d0fb4a15a86a514c0c60aafd63c489231f6ebd7` | 以镜像 wifi-scripts 为准，不用 netifd examples 或较新 stage9 checkout |
| 已有实机结果 | R94：14 lanes × 3 sides × 4 = 168 observations | 空无线、2/32 接口；wireless p95/p99 对 R89 +11.55%/+4.41%；Anon +80 KiB，fd +1；不是全面胜出 |
| 发布方式 | `tools/ci_build_core.sh` 的 standalone core artifact | 不在 owrt-switch APK；Oracle SDK/sstrip 筛选产物不是 canonical CI 身份 |

已重新验证离线 C/R89 bundle 中全部 Rust ELF、manifest 与设备一致，验证两份恢复镜像，以及
当前配置的完整只读归档。见 `recovery/verified.json`、`device-identity.txt`、`health-initial.json`。
没有部署、刷写、切换生产、重启、改生产 Wi-Fi/netdev/nft/ubus 状态。

## 有限并行审查与源码依据

三个只读子代理分别审查精确源码/调用合同（随后审查构建和恢复风险）、Rust 热点、硬件数据与
测量工具；它们没有创建分支或修改候选。主代理实现并逐个保存候选。

精确 [ubus.c](https://github.com/openwrt/netifd/blob/cbb83a1857407a28a63dc09412a1f209195914ef/ubus.c)
共用静态 blob buffer，接口 dump 单遍遍历；状态通知一次构造后发给全局和接口对象。
精确 [system-linux.c](https://github.com/openwrt/netifd/blob/cbb83a1857407a28a63dc09412a1f209195914ef/system-linux.c)
的统计来自 23 个 sysfs 文件；R94 已换成单次 RTM_GETLINK，保留失败回退。事件溢出扩容、完整重扫、
失败重试不在本次可删除范围。已将上述文件及 ucode/proto-shell/interface 源文件与官方固定 revision 逐字节核对。

发现两项文档/既有边界：

- 无线 parse_bool 只接受 0/1/true/false。合同原写 on/off/yes/no 也生效不正确；本次只改正文，
  不改实现。精确 utils.uc、既有单测和 C 差分相互支持。
- 研究初期发现 Rust `network.wireless status/get_validate` 未处理 `device` selector；当前 A/B 筛选
  候选均已单独补齐，并通过 C/A/B 的 22 组 raw 参数矩阵逐字节差分，包含重复 `device` 字段、
  错误类型先后排列与非 UTF-8 字符串。正式 R89 的既有差异另外保留。

## 独立假设和候选索引

以下是从同一起点独立筛选的历史候选；H0/H1/H2/H3c/H5 已组合，H4 处于一次有限实机消融筛选。
表中早期 SHA 为 Oracle SDK release + sstrip 诊断 ELF；当前 A/B ELF 与 selector 正确性修复的身份见后文。

| 候选 | 单一假设 / 改动 | SHA-256 | 当前证据 |
|---|---|---|---|
| base | 当前代码；仅诊断 example 增强 | `0665583158fc32cd019e5df2e32d4675a586757fb1c450c1a4ed71c590f4caa0` | 157 单测；完整 suite 31/31；clippy 项目门通过 |
| H0 | Option 持有回复缓冲，消除 mem::take 的默认占位分配；错误早退归还缓存 | `72f17bdb44ff9abfcc1ad91e7acc3de41d1692850cc92179a85ad47164252106` | 取用微探针每次减少 1 allocation / 4 requested bytes；尚无实机收益结论 |
| H1 | wireless status 直接从借用配置按原字段顺序编码 blob；handler JSON 不改 | `23a77c43c9df70fef12bba4da59cdb87392cdf4536b7cece50c29ae42de685aa` | 158 单测；真实配置投影 byte-for-byte 相同；完整 suite 31/31 通过 |
| H2 | netlink 回复仍保留至少 64 KiB 接收容量；只将 recv 实际写入的 n 字节设为 initialized | `ead0b44ee8113fa630962a391f90fb39c5dbcf091b8645e99d178ec7b0713ba6` | 157 单测；overflow、restart、两种重连故障通过；Oracle RSS/Anon 各少 64 KiB |
| H3 | 回复保留上界单独从 64 KiB 改成 128 KiB | `010c3131c36be06ede7fcb397c9e0ec3a8466bbee1cfcae5002cea2adafb0bb4` | 128 接口微探针扩容消失；实际 daemon 128 接口和常驻取舍待筛查 |

H1 的第一次构建因 match 返回类型不一致失败，原 `h1/build.log` 保留；修正后的构建为
`build-02.log` / `candidate-02.patch` / `source-manifest-02.json`。失败未计为通过。
基线 `clippy -D warnings` 因既有 dead_code 警告失败，保留 `base/clippy.log`；项目实际门是
`--all-targets -- -D clippy::undocumented_unsafe_blocks`，后者结果单独保存为 `clippy-gate.log`。

## 初步 profile，不作为硬件确认

真实配置通过只读归档进入 Oracle 镜像 mount/PID/network namespace，schema 由镜像 handler 的
`dump` 获得；没有运行真实 radio setup。`wireless-profile-output/` 保存输入 hash 和原始 CSV。

- 同一配置输出的 blob 字节完全相同。原 JSON→blob 为 53.00 µs、434 allocations、207 reallocations、
  38,004 requested bytes/op；直接编码为 8.45 µs、0/0/0。它排除了 ubus 传输、事件循环和正常无线硬件执行。
- 回复取用的第二版探针保留对占位对象的观察，防止计时部分被优化掉：30.38→7.33 ns；
  仅分配次数变化可以直接归因，不能将这几个 ns 外推为端到端收益。第一版探针原 CSV 保留。
- 128 接口的 64 KiB 上界每请求产生 1 allocation + 14 reallocations，requested bytes 为 327,664；
  128 KiB 上界为 0，探索耗时 235.55→100.18 µs。2/32/64 接口均未触发此问题。
- Oracle dev status 的 base/H2 `strace -f -c` 均为 10,020 次调用、170,576 次 syscall，
  其中 10,020 次 ioctl 错误为不支持的 ethtool 查询，不是 ubus 请求失败。RSS/Anon 为
  1256/264→1192/200 KiB，fd=11、threads=1。未插桩单窗 own CPU 为57.38→49.29 µs，
  此顺序未校准，不能据此认定 CPU 下降 14%。见 `profile-*-dev-{cpu,strace}/`。

## 工具与校准

`run_candidate.py` 保留原有隔离 harness，新增：同一临时 ELF 路径的 calibration；每 block 内独立随机
三侧的固定 seed 顺序；namespace launcher 直接受设备端 600 s guard 保护；冻结 manifest/driver/tool
身份；保存逐窗 config/生产进程/mount/环境；失败尽力下载原始记录并保留远端位置，停止后续采样。

规模参数支持 32/64/128；128 接口名字统一三位数以保持数字顺序和 C 字典序一致。每窗口只有一种扩展
规模，保留原有精确对象集合、hotplug 回调和子进程回收门。分析器开始汇总已采集的 own/dependency/caller
process clocks，并单列 reaped-child ticks 和逐 lane 前后资源。HWM 是进程启动后的累计高水位，
不是每 lane 的独立峰值；RSS/HWM 仍有内核计数精度限制；这些数字不等于 PSS。

A/A plan 在采样前冻结于 `aa-plan-01.json`：正式 R89 同一临时路径，8 个 fresh namespace，
14 lanes × 每 lane 10,000 请求；8 个窗口全部保留，只用于噪声/顺序/温度/时钟评估。
collector 和 harness 复制到 `frozen-01/` 后不改；完整 hash 见 plan 和每轮输出。
确认实验的样本量、实际门槛、比较集合尚未冻结；不得用本阶段最好的窗口作胜出结果。

## 初始审查快照（后续状态见下文）

仍需：H1/组合完整功能恢复门；H3 实际128接口筛查；真实配置 stub 的三侧 daemon 差分与硬件负载；
正式 core recipe/最终身份构建；A/A 结果和冻结的 C/R89/候选确认；netlink buffer/队列、关闭后回收及
全生命周期内存证据；所有不胜 C/R89 项逐条解释；剩余合理算法方向的 profile/源码排除。
在这些完成前，不接受“netifd 收尾”或“全面优于”的结论。

## 后续复核与证据纠正

当前**没有最终确认候选，也没有完成性能确认**。下列记录纠正 `126f00b` / `b369d08` 中的过早表述；
私有产物仍保留原名与 hash，不能由 `final-*` 或 `confirm-*` 目录名推断已验收。

- `13d21f6fecc0223e006e786bed7b078cfd75e3baf5ad154bb98194d895c268f6` 是 H0/H1/H2/H3c/H5 + 初版 selector 修复的探索 ELF。
  它通过 159 个 daemon 单测、Oracle 31/31 suite、restart、两种 reconnect 和 AX3000T smoke。
  suite 日志 hash 为 `03eb249e647daf60402f6f2bbe705a57f99784cefc93555a375c9092cdb864ee`。
  smoke 的 boot/config/生产身份/mount/清理门全部通过，未安装。它的 **all-target clippy 未通过**：
  profile example 仍引用已撤回的缓存字段。此前把日志尾部警告当成通过是错误，新的两侧已修复该 example。
- `confirm-32` 实际带非空无线配置 stub，与原称“空无线”的设计不符，且实际收益门槛未完整预冻结。
  整批降为探索：13 个窗口已保留，前 12 个才组成 4 个完整随机三侧 block；第 13 个不配对。
  当前窗口自然结束后已停止 collector，下载并核验 raw，验证生产健康及唯一临时目录清理。
  见 `DESIGN_DEVIATION.json` / `STOPPED_DESIGN_DEVIATION` / `health-after-stop.json`。
- H4 的四对 Oracle 单客户端主体 CPU 变化为 −30.30%、−0.12%、−28.88%、−40.65%；四客户端
  也全部下降。unchanged reload CPU 增加 0.22–5.00%，延迟与依赖 CPU 方向混合；缓存仅 908 bytes。
  原先只强调延迟而拒绝 H4 的依据不充分，也不存在已冻结的非劣门。现在用同构建目录/参数、相同其他
  改动的 A（无 H4）和 B（仅增加 H4）做一次有限实机筛选，完成后必须作出取舍。
- 首次 overflow probe 失败中的 `ss` 两行是同一 socket 的瞬时队列变化（r9216/r6912），不是空白。
  空白归一化后的单次通过不证明工具已修复。新 parser 用进程持有 inode 与 port-id 固定身份，保留
  所有读数并用 buffer/drop 区间的保守边界判定。原失败、过渡工具成功均保留。
- selector 新增 raw 边界：重复合法字符串最后一个生效；任何位置的错误类型均 INVALID_ARGUMENT；
  非 UTF-8 的未知字符串名为 NOT_FOUND。前一 ELF 只覆盖普通 JSON 输入，不能称完整 selector 等价。
- 原 `final-candidate/source.tar.gz` hash `b8375d63a62b85f37cd0da626468529fd28b9ca145e82ecfb7f9774991d82555`
  包含大量 target/AppleDouble 文件；其中 tracked 输入与当时提交相符，但缺少工具链/配套脚本。
  新归档包含这些构建输入，约 1.2 MB；历史包不改写。
- 新配对构建曾因共用 Cargo target 与归档零 mtime 误复用旧 ELF，出现 A/B 相同 hash；该次对比作废。
  改为每次清理实验专用 target 后构建，两侧源码路径均为正式 `/tmp/owrt-core-release/netifd`。

`screen-a-06` / `screen-b-06` 是继续筛选的源码快照，清单、补丁、构建/单测/clippy 日志分开保存。
构建 recipe/ABI 门与 canonical GitHub CI 仍区分记录；尚未运行 canonical workflow。

## 当前完成边界

| 要求 | 当前状态 |
|---|---|
| 精确 C / 正式 R89 / 生产 C | 已核实；未部署、刷写、重启或改生产网络状态 |
| 独立算法筛选 | H0/H1/H2/H3a/b/c/H4/H5 已有源码/profile；H4 需有限实机取舍 |
| 全部功能与恢复 | A06/B06均通过31/31及完整恢复；新增参数修复的A09/B09已过unit/clippy/ABI/raw66，完整suite待复核 |
| A/A 校准 | 两轮已结束，不再追加校准，不并入实现对照 |
| 正式性能确认 | 尚未开始有效确认；现有 13 窗为探索，不追认冻结 |
| 真实无线 | 实际配置/schema + 隔离 mac80211 stub；不执行真实 radio 重配置 |
| 内存/fd/线程/netlink/关闭回收 | C/R89/B 同夹具独立诊断已完成；最终选择后核对适用 ELF |
| 其余热点 | PD 投影、事件通知、reload/proto 调用链需完成有限 profile/源码排除表 |
| 最终报告和停止理由 | 未完成；不宣布 netifd 收尾或全面优于 |

后续确认会先冻结全部 workload、每项 N/warmup、seed/order、准确 ELF/tool/fixture hash、指标方向、
测量分辨率与实际影响门槛。若沿用 24 strata × 8 metrics × 2 baselines (`m=384`)，
19 个独立随机 block 的 Bonferroni 中位数秩区间为第 2–18 顺位；资源诊断独立披露，
不把未知、统计不显著、RSS 页计数限制当作等价。具体最终计划尚未冻结。


新 A/B 源码均通过 161 单测、all-target clippy 项目门、release 和 ABI 门。
A（无 H4）ELF 为 `ca0f1d3dda0a02b5941768a32f80c5d080fdb0d0186c5a19873c843eec06bc75`；
B（仅增加 H4）为 `e4cae77344c5d0a00182b7274629ee932faf675adc1e1bf97867523fc6869d03`。
`selector-raw-06` 已验证 22 个 raw blob 请求：C/A/B 的错误码、完整 DATA payload 和字段顺序逐字节
相同，含重复字符串、错误类型先后排列及非法 UTF-8 名称。正式 R89 的既有不等项单独保留。
先前发现的 5 个无线整数字段是 C INT32 / R89 INT64；这 20 字节 wire 差异的修复仅限 netifd 无线，
按 [ucode 的范围规则](https://github.com/jow-/ucode/blob/85922056ef7abeace3cca3ab28bc1ac2d88e31b1/lib/ubus.c#L386)
选择整数宽度，不改共享库，不计入 H0/H1/H2/H3c/H4/H5 算法收益。两侧完整 suite/恢复复核已顺序启动。


## 候选索引补全与排除依据

下列 `h*` 路径相对私有研究根；每个有独立源码归档、源码清单、patch 与 Oracle 构建记录。
H4 的进一步 A/B 对照不是多项未知改动叠加：两侧共享正确性修复与其他已筛选优化，差别仅为缓存。

| 实验 | SDK/sstrip ELF SHA-256 | 处置 / 证据 |
|---|---|---|
| H3b | `e21698cfc91c70719ddd33ad8264eed1a1d9bfa95ec32f7b5e10a02e075c1bf7` | 大回复释放后保留 1KiB；128 接口 ownCPU 235.66us，较 H3c 差；不选 |
| H3c | `7d3d82db622a06daf95dc2dbfb2f2a7dd5cce59ff05dc4c9efd5f88c4889c684` | 上次 dump 长度提示，64KiB 常驻上限不变；128 接口 ownCPU182.04us、RSS/Anon1588/596KiB；选入组合待确认 |
| H4 | `54d1a1d7addac39e300cc832cc69fd2621d80edddf00d2a25c026b104a9da39f` | 配置 blob 缓存；四对 CPU 支持、reload/尾延迟取舍未决；`h4-paired-screen/` |
| H5 | `197d028bab9ad9bc7c474e07a262f3f964031ef413cd7c6f947d8e58c64c0ed0` | ethtool 与设备 ioctl 共用同类 socket；fd11→10；`profile-h5-dev-cpu/` |
| combined-01 | `215e19496b1d4d3242c91ab15d9f6e5b20737aed715d611df7d53374a30bfa64` | 早期组合；尚缺 selector/wire 修复，不是最终候选 |
| combined-01/core-recipe | `136a19dcaa06f966dcba6ff114086d0320363c4577798cbf9cfe7d4ffbd94221` | 早期正式编译片段产物，非 canonical CI；不混入 SDK/sstrip 结果 |

H3a 的 128KiB 常驻缓存虽有更低的探索 CPU（147.35us），其 RSS/Anon 为1676/684KiB，
比 base 的1628/636高48KiB。H3c 保留了更小的常驻上限且已有实测收益，故不选 H3a。
Oracle 四侧数值只用于筛选，不外推 AX3000T 的效应量。

## 实机资源诊断：C / R89 / B

`resources-device-c-01` / `resources-device-r89-01` / `resources-device-b-01` 是单独诊断，不能混入 latency 确认。
工具用 pidfd 短暂复制隔离目标的 fd，只调用 getsockopt/getsockname/fstat，不收发消息。
已在 Oracle 私有 namespace 用已知131070字节接收缓冲核验，并验证目标 fd 数不变。
helper SHA 为 `2fb61e01e6c480f21c77ad607d7ff6cfec394708e034d46065796693d592b640`，
harness SHA 为 `9db0d5469ea3cbedb789e33ef3e585b877fecd186e4571760bb8911b02baf7ea`。

| 阶段 | C RSS/Anon/HWM KiB | R89 RSS/Anon/HWM KiB | B RSS/Anon/HWM KiB |
|---|---|---|---|
| 2 接口 | 2116/668/2116 | 1096/172/1176 | 1112/188/1112 |
| 128 接口 | 2584/1136/2584 | 1472/548/1688 | 1460/536/1560 |
| 缩回 2 接口 | 2328/880/2404 | 1352/428/1688 | 1364/440/1560 |

C fd19/线程1，R89/B fd10/线程1，全阶段不增长；关闭后目标 PID 消失，所有已观测 netlink inode
均从该 namespace 的 netlink 表消失。C route 命令 socket rcvbuf/sndbuf=65536/65536，LINK 与
uevent socket 为131070/65536；R89 route 命令和 LINK socket均为212992/212992。
B route 命令 socket 为212992/212992，LINK为131070/212992；没有把 rcvbuf 的配置上限当实际占用。
C 的 HWM 从2584降至2404，实际观察已经证明这些 proc 计数不能作为精确、单调物理峰值；
因此保留全部原始数值，不用它们声称 PSS 或精确峰值优势。B 的小规模 Anon 较 R89 多16KiB、
大规模少12KiB、缩容后多12KiB；这些是单窗描述值，尚不能作泄漏或等效结论。三窗均通过生产
身份、配置、boot、挂载与清理检查。

`resources-derived-02.json` 的 SHA 为 `f5ded69caead1d1388261136b1b40f3c924178f9d340bafb7a08b399f2c500e5`；
每侧114个归档成员与下载后的 raw 逐字节核验。无线夹具为空，因此这些页差不来自 H4 的 radio/vif
缓存，也不能替代非空无线资源验收。B 缩容后 Anon 较初始仍高252KiB，R89高256KiB；不能称完全回落。
采样边界 netlink Rmem/Wmem/Drops 均为0，不代表已测得两个采样点之间的瞬时队列峰值。

对照正式 R89 manifest 指向的 `d9c10483d95590143f9d6a1f41310e2a13e63fb3`，Interface、Device
结构与 config.rs 没有增加每接口状态。明确增加的常驻来源是 ubus Connection 的4096字节接收区、
小回复复用及命令 netlink 回复实际触页；事件 socket 的用户态 reply 向量没有接收 dump、容量为0。
这些加上分配器布局可以解释数页差异，但没有逐分配测量，不能将16KiB精确拆账。超过64KiB的大回复
会释放，缩容后100次小dump会降低预分配提示，因此不能把缩容残留解释成保留了128接口的大回复。

## 新增畸形无线请求复核

`screen-a-06` / `screen-b-06` 均已通过完整31场景和 overflow/restart/两种 reconnect。
但进一步源码审查发现 read-method 参数校验会跳过无效属性。`selector-malformed-01` 的66组
实测中，A06/B06各有22组不同于C，原始错误码与payload全部保留。发现时 H4 控制器仍在等待，
已停止且没有开启性能窗；计划01–03不再执行，不改称已通过。

修复局限于 netifd 的无线读参数 helper：遵循 libubox 的尾部遍历边界，校验名称和STRING终止，
保留任意字节与内部NUL的ucode查找规则。依据为
[libubox遍历与校验](https://github.com/openwrt/libubox/blob/7dd127841e82eb1cfb61185da37dde7b9bd9ba6d/blobmsg.c#L35)
及 [ucode逐字段参数校验](https://github.com/jow-/ucode/blob/85922056ef7abeace3cca3ab28bc1ac2d88e31b1/lib/ubus.c#L1441)。
07源码快照在构建前被审查拒绝：字段名也错误地按首个NUL截断；ucode会先检查声明的名称长度为6。
07没有生成ELF或采样，保留 `UNBUILT_REJECTED.json`。B08的新增单测失败：测试使用的
`msg_string_bytes` 本来就按首个NUL截断，不能构造需要验证的输入；失败日志与ELF保留，未计为通过。
09改用原始字段构造，A09/B09各通过164单测、all-target clippy、release、ABI，且66组raw请求
的错误码、完整DATA、字段顺序均与C一致。正式R89的已有差异保留，不改写其基线。

| 侧 | ELF SHA-256 | 算法差异 |
|---|---|---|
| A09 | `3a53cbd751b0b0f45abdde8ae9add707f15a851e786bf1fc00d936e5894df0f7` | H0/H1/H2/H3c/H5与全部参数合同修复 |
| B09 | `2e6acc30714906dc9811d0ea521dbbd8ccb33b19666dfe420138f8265e3911a6` | 仅另加H4缓存 |

两侧源码清单仅wireless.rs不同。H4计划04 SHA为
`025d0b966ca34802f86cd9d5aa3508813eb58ab75d7b14cfbff447a489f93240`，保留原8block、负载、顺序、
样本和成本检查线，更新已修复的ELF/源码/manifest身份；控制器等待两侧完整suite和恢复门后才开启硬件。
设备 `/proc/self/smaps` 与 `smaps_rollup` 不可读，现有image无法用这些接口精确核实PSS/物理峰值；
保留status/statm可见值及其观测限制，不把不可测部分写成相同。
