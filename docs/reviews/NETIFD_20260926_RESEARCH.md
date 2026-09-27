# netifd 性能研究：2026-09-26

状态：进行中；没有候选完成实机确认，没有宣布收尾。沿用当前工作线；ubusd R136 已关闭。
最新阶段：H10 精确 canonical ELF 的功能、恢复、raw66 和类型生命周期门已通过；
AX3000T 资源04仍有三项冻结预算失败，正式三方性能确认尚未启动，见文末。
原始输入、配置、ELF、候选补丁和失败构建只放在 ignored `private/netifd-20260926/`
及 `private/netifd-20260927/`。
Oracle 对应 `/home/ubuntu/netifd-research-20260926/`。本报告只提交派生事实，不提交设备秘密。

最新证据修正：H9 前置检查发现并精确清理了旧 suite 遗留的66个进程，其中16个 odhcp6c
在有 monotonic 起止的一秒采样中合计消耗3.99 CPU秒。此前 Oracle 耗时和CPU排名只能作为
存在未控制宿主竞争的探索观察，不能据此声称空闲宿主接受证据；不能回算污染时间或修正系数。
源码、逐进程syscall/分配机制、精确身份和独立路由器数据仍保留。旧31/31也不证明子孙进程回收。
详见下文最新阶段；前文的“尚未构建”等措辞记录各历史阶段，不代表最新候选状态。

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
| 全部功能与恢复 | A09/B09均通过164单测、clippy/release/ABI、raw66、31/31及overflow/restart/两种reconnect；后续算法仍需自身门 |
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

## 剩余查找与短字符串方向的有限筛选

`hotspots-02/raw/micro-micro/raw` 保存当前B06算法的musl诊断三批，每批50万次，不作为A53效应量。

| 接口数 | 对象route ns/op范围 | 当前find_by_name ns/op范围 |
|---|---|---|
| 2 | 3.02–5.96 | 22.52–28.53 |
| 32 | 23.21–29.32 | 95.96–139.89 |
| 64 | 50.86–78.23 | 114.96–129.56 |
| 128 | 104.48–123.05 | 129.09–129.60 |

两类查找均零分配。3/7/8/64字节名字clone分别为37.57–43.30 / 36.83–42.58 /
35.47–46.42 / 49.79–64.41ns，每次1次分配、请求字节等于名字长度。
route/find/clone的最保守上界相加仍只有317.06ns，低于事先确定的0.5us研究优先级线；
不据此增加HashMap或单独开名字借用硬件候选。这是算法筛选取舍，不是A53等效或非劣证明。
事件与PD的专用诊断已结束，前置工具兼容失败均保留，不计为性能样本。

## 事件与临时缓冲的后续筛选

`hotspots-derived-01.json` 索引537项原始文件。精确B06 release的strace显示：1024个事件动作
产生100353次openat、207871次read、97280次fstat、102405次fcntl；源码对应每次全量重扫所有
已知设备设置。PD更新256次产生1664次mmap/munmap与2048次sendto/recvfrom。PD owner status
50000次全部成功，没有文件或netlink I/O。符号诊断ELF的events/PD status/PD update只有
957/798/74个perf样本，均未达事先1000样本门；不能报告精确函数占比或凭未命中排除路径。

| 独立候选 | 精确ELF SHA-256 | 有限筛选 |
|---|---|---|
| H7 | `ee3f6e7a2001f064c863e3ac69367207dd8f6dbd0f3f8b7dfbd25f0197adbc1b` | 小proc文件完整读到EOF，减少std文件大小/标志探测；只改device.rs |
| H8 | `3d721606e3d8f64a60215442e4214e84f8a1af03cc67f89fdbb8a7896edb2575` | 临时netlink接收区仅初始化实收字节；只改netlink.rs |

两侧各自以A09为基线，没有叠加H4或彼此改动，均通过164单测、clippy/release/ABI。
Oracle固定每项2个strace窗及4组AB/BA/BA/AB未插桩配对，按H7后H8顺序执行。
H7 plan SHA为`6d0fee2b4e6d7f4d9f1f8f345772486a8a7b006d2db8bbf57d444fa20437a92c`；
H8为`7d47da425355e4601190bb2bf07cd96451166322017e994b801c397b1e457b7b`。
H8允许settled Anon每对至少少8KiB或每窗minor fault至少少128作为资源复核信号，
HWM单独不触发；主体/依赖/caller与child成本分别披露。三角色两侧child累计tick差最保守
有±12tick量化不确定性，不能把该区间当允许退步或成本相同。

H6事件设置缓存仍是私有、未构建原型。C/A09的有界Oracle差分已确认：MTU1500改1400，
C status保持1500而A09变1400；rp_filter2改0并触发普通NEWLINK后，C保持2而A09变0。
这是Oracle6.17.0-1020-oracle证据，不冒充AX3000T6.12.94结果。
源码审查发现直接缓存需要处理同名同ifindex重建失效；直接迁到C首次claim采样又涉及
配置值投影，因为当前Rust运行路径未写入Device.settings。原型尚未通过合同审查，
不得将减少设置读取视为已经获得的收益。`h6-orig-settings-01/`保留原始状态、内核状态、
namespace身份及宿主网络未变证据。

## H4 实机有限筛选完成，仍未选定最终缓存

计划04的24窗、72条lane观测已完成，错误数0，全部原始文件/身份/配置/生产健康已复核。
窗口08有明确采集偏差：本地controller和SSH waiter消失，原因没有被记录，但设备端冻结
workload已写COMPLETE。恢复时下载48文件并逐项核验hash、计数、输出和身份，独立检查无隔离
进程/临时根/残留挂载，生产九组件与boot/config、Wi-Fi健康通过。保留 `exit:null`，不伪造0；
从09按原顺序继续，没有重跑08。第3block有额外间隔，全部八组仍保留，不能称原流程无偏差通过。
恢复审计见 `H4_WINDOW08_RECOVERY_AUDIT.md`；attestation SHA为
`750f52f0e1cc620bdd6160501df9a3dd4cdcbf38369db5e63eec82ce278d8688`。

恢复版派生器SHA为`376eca32a08a2691e10c4d1cff8d133a84a6b8464c2a8fbc2a889769ae1229af`，
仅对明确的08和attestation哈希接受恢复路径；原派生器保留。
`h4-derived-plan04-recovered.json` SHA为
`6065be21f42d5dd8f371ed70d4d87ed68da7ba6a3f0a4fa7fd8b78558ffcfd84`。

| 负载，B09/A09 配对log中位数 | own CPU | mean | p95 | p99 | 外层吞吐 |
|---|---:|---:|---:|---:|---:|
| 实际配置 wireless_status | −55.54% | −31.32% | −25.21% | −2.45% | +26.21% |
| 实际配置 wireless_status_c4 | −60.82% | −30.79% | −26.19% | −27.19% | +28.80% |
| unchanged reload，32接口 | +4.56% | +5.53% | +7.32% | +11.97% | −5.24% |

两个无线CPU信号通过预冻结筛选门，但reload存在多项成本越界，不能据无线收益抵消。
wireless单客户端p99第8组、四客户端mean第6组及p95/p99第6/8组也越过成本复核线，
全配对值保留。B09比A09的Anon七组多4KiB、一组多8KiB；fd/线程差0。这是proc诊断值，
不能宣称精确物理内存增加量。三条负载的主体CPU/mean中位方向均优于C；正式R89不在本次
消融中，尚不能作最终双基线结论。

处置：H4 eager版本暂不晋级；一次有限筛选到此结束，不追加同版本轮次。源码确认 `load`
每次都预编码缓存，包括无变化reload。私有H4b仅将该不可变配置缓存延迟到该generation首次
status编码，使用固定Rust revision的 `OnceCell`；不缓存动态状态/handler ifname，不更改无线
脚本或生命周期。它尚未构建、筛选，不能把预期reload收益写成结果。

## H7 拒绝、H8 时间边界与 H9 后续

H7-02完成固定4对，own CPU比值为0.965820/0.950722/0.932308/0.972288，中位0.958271，
未达≤0.95。fstat 97375→0，但fcntl 102505→102505，原双机制门也失败；拒绝并从工作树撤回，
不修改冻结门。实际链接的Rust musl `open` 在CLOEXEC成功路径额外执行F_SETFD，`openat`
没有这一步；精确libc archive与ELF反汇编支持，见 `h7-fcntl-source-review.md`。
私有H7b保留完整读取、errno/EINTR/UTF8/trim与CLOEXEC，只单独更换打开原语，尚未构建。

H8-02在第二个strace窗后的完整PD状态比较失败，CPU配对一窗未开。三处差异均为合法的
prefix renewal跨整秒后 `updated:["prefixes"]` 有/无；C和A09/H8都比较绝对deadline，
两侧实际更新回调数不同，不能当相同工作量的性能比较，不能删updated字段使旧门通过。
全部失败保留；另行准备省略prefix寿命的新诊断schema，固定renew/replace次数并明确字段
及通知合同，有限寿命正确性仍须通过原门。它不是原失败窗口的补跑或追认。

H6设置缓存经源码和双侧探针筛选后拒绝：完整C激活采样迁移还需要配置字段投影、原设置
恢复和external/bridge生命周期处理。C本身会保留部分成功的激活采样，普通事件不重试；
不能以“失败采样必须重试”作为错误的拒绝理由。详见 `H6_CONTRACT_REVIEW.md`。

替代H9只复用同次full link dump中的DSA信息，不改变设置读取和生命周期，并保留不完整
DSA数据的单查询回退。ELF `0f059d9d983ce3c13ff8e4fcb28c3f8089df07a159ccb9e75802537dabef3362`
已通过167单测、clippy/release/ABI，完整功能/恢复门进行中。精确6.12.94源码的dump/getlink
共用fill_info，但单查询另有linkwatch_sync_dev；因此仍需事件/lateport/overflow收敛门，
不能凭属性相同宣称整次请求完全等价。只读DSA工具已在Oracle用两个普通接口及ENODEV负例验证，
尚不构成真实DSA或H9性能结果。

## 清洁宿主后的有限筛选与测试修复

旧 r52/r53/r56/r83/r83c 只有 mount/network namespace；helper 在父进程退出后可被宿主PID1
接管。已逐个保存PID/starttime、argv、root、namespace及镜像ELF hash，使用pidfd验证后TERM
清理全部66个对象，没有KILL，没有信号发给该集合以外的进程。宿主网络前后JSON一致。
准确采样为1.003917–1.003977秒、HZ100、399ticks；早期错误的一秒标签已单独标为无效并保留。
旧性能数据和拒绝决定不重写、不追认、不与新清洁样本拼接。纠正报告
`ORACLE_HOST_HYGIENE_CORRECTION.md` SHA为
`783c8f2c0afe3173761555837bebe78a981caffbab71f4ec35a190d0b6ef28aa`。

H9在清洁Oracle按原计划完成2个strace窗及4对未插桩窗。own CPU比值
0.977222/0.999776/0.962921/0.966473，中位0.971848，未达冻结≤0.95，拒绝。
sendto/recvfrom各减少5125次，机制成立；依赖/caller方向混合，不能相互抵消。
报告 `H9_SCREEN_RESULTS.md` SHA为
`d948fad28dd9c8319edcfd18bcf547972b61ea0cc78da26d4d40ed42958fefac`，
584项证据索引SHA为`b2aad56d8a6b4226e99fdffa82e3046f8543e169543711211a41dc5a6615f656`。
DSA只读核验另在AX3000T的lan2/lan3/lan4/wan完成32次请求，dump/single的属性与状态guard一致；
生产C身份、boot/config与Wi-Fi健康不变，collector已清理。这不改变H9拒绝决定。

H8主假设已由精确链接musl的allocator源码/机器码排除：当前128KiB和低usage32KiB请求
走已知零页映射，不存在预想的大块清零；高usage例外所需映射内存超过已观测VmPeak。
这只关闭已观测压力下的假设，不证明任意未来allocator负载相同。省略寿命的替代screen保持UNRUN，
不为旧失败换参数补跑。H6/H7/H8/H9均不在当前候选中。

H4b延迟缓存只存为未构建审查记录。H4c改为在既有same_config分类后移动未变化radio/vif的
配置blob，初次load与changed/added仍立即编码，不增加缓存状态。ELF为
`b292b0cdbf3daeeef27309ab2a9939c93c4d68a5a22ecbeab691780f7e44e69f`；
164单测、clippy/release/ABI通过。性能与新隔离功能门尚待验证，不能宣称解决reload成本。

测试修复复用现有 `benchmark/ns_exec.c`：suite逐case隔离，上述五场景再逐C/Rust侧隔离，
由私有PID1退出统一回收子孙；namespace非零退出不再被忽略。R83删除尾部宽pkill并限定真实脚本argv。
R52在ifdown前验证helper身份并等待该实例消失；updated探针用pidfd STOP保持接口up，前后均确认
无运行子脚本，完整status与同一helper身份必须通过。该修改没有改变netifd或镜像协议脚本。
本地工具语法检查及19+3项断言测试通过，包含缺失身份、错误实例、未退出、未停止、有子进程、
四阶段接口down等负例。C/H4c的R52/R53/R56/R83在validation-01通过；R83c的C侧在新增
errexit下暴露disabled ghost不存在device对象的预期错误，退出1并保留root及日志。
工具修正为保存完整stdout/stderr/CLI退出码，仅veth3允许254、空stdout及Invalid argument；
两侧错误码继续比较。validation-02只重跑R83c，C/H4c通过。全部10个侧的namespace退出0，
逐侧pid/net/mnt census无成员、无读取错误；最终宿主mount/network/namespace完全不变，
项目root存活进程为0。ns-exec正常退出、setsid子孙、launcher死亡回收及退出37传播也通过。
这些是五场景工具验证，不能替代最终组合或正式CI ELF的完整31场景。
结果索引为`suite-isolation-validation-result.json`；最终工具清单SHA为
`60d5408369e284a21232907186c7c3ae17e900febef93742b132bd09faba3c5c`。

H7b在清洁Oracle按原2strace+4对计划完成。主体CPU比为0.92806/0.85356/1.01918/0.93498，
中位0.93152，三对改善、最差≤1.02，通过冻结CPU门；fstat减少100%，fcntl减少约95.0%。
第3对ubusd/caller分别增加8.04%/8.89%，settled三角色child增加36ticks，不能由±12ticks
量化区间解释，也没有同期frequency/steal证据把它认定为噪声。该回退保留未闭合。
稳态Anon差在−8至+4KiB，fd均12→14→10、线程1；只支持进入完整功能/恢复门，尚非全系统接受。
`H7B_SCREEN_RESULTS.md` SHA为`c4101d9215778d50405decb308310a531d2a3c35e97a0b2a160527e19e919b76`，
1208项索引SHA为`21d3e5010b47d6cfd5f81dfe067c1be205629836e3967c56c5bec6505ed407e7`。

## H4c 筛选停止与最终组合验证入口（2026-09-27）

H4c 的精确 ELF 已通过修复后的完整31场景、overflow、restart、两种reconnect及C/raw66
逐字节/顺序/错误码门。四组三侧Oracle筛选执行了12窗，但**原筛选未完成通过**：最后A09窗
namespace退出0后，宿主post gate的aggregate CPU为12.5%，crowdsec同一PID/starttime
在约2.063秒消耗19ticks（单核9.21%），超过冻结5%上限。该观察不证明干扰与timed lane
重叠，但原门必须遵守；失败原文/无COMPLETE保持，不补跑，不以稍后clean覆盖。

第7窗曾因同一内核workqueue线程的动态comm描述变化误报，经独立身份/flags/原始输出/
清理审计后允许继续原剩余顺序；observer仅修正此识别，原失败文件保持。这个恢复与block3
间隔继续披露。最后一窗是真实负载门失败，与第7窗不同，不做恢复接受。

12窗原始数据位于ignored `private/netifd-20260926/h4c-screen-return-02/h4c-screen-01/`。
失败审计SHA为`ce3a918b081b3b169954011ad49be6d77ee64114db526098e8af27e24f2cf2e6`；
不完整派生SHA为`fa1691fc32793a0891ae40dccc28eebccb1abd1335faf0b4f3a5fc981955f4a0`。
只对前三个完整block作事后探索描述，第四组全三侧单列无效附录，原N与阈值不变。

| 前三组描述性主体CPU比值中位数 | H4c/A09 | H4c/B09 |
|---|---:|---:|
| 实际配置warm wireless c1 | −44.80% | +2.65% |
| 实际配置warm wireless c4 | −49.99% | +1.15% |
| unchanged reload32 | −2.86% | −4.39% |
| reload→立即首次status整对 | −4.82% | −4.16% |

warm c1的H4c/B09中位数超过原1.02保留线，不能声称筛选信号通过。该三对绝对变化
为+0.258/+0.732/−0.157us；c4第3组p99较B09高10.24%/13.68us，first-status第2组mean
高9.32%/8.23us；多组reload caller增加2.44–6.88us。完整15个成本/资源review和18个
child量化跨线项保存在派生结果，不用无线CPU收益抵消。最终settled Anon三个block均
H4c336/A09328/B09332KiB，fd10、线程1；这是proc近似诊断，不是物理内存等价结论。

H4c源码保留为进入独立最终验证的候选：初次和变化配置仍立即编码，只转移same_config
已经证明不变的缓存，避免把reload工作推迟到first status。现有证据支持继续验证这一
机制，**没有给它硬件接受或全面非劣结论**。不重跑同一Oracle筛选追分。

H7b随后单独合入该待验证组合：完整读取小型proc文件到EOF，openat原子设置CLOEXEC，
保留短读/EINTR/错误/UTF8/trim/内部NUL处理。它与无线缓存没有共享状态；仍须用
组合后的精确ELF重新证明功能与整体成本。`final-combined-01/`保留新源码快照、补丁及
选择理由。166单测、clippy、release和ABI已通过，完整31+恢复门进行中。H7b第3对
依赖/caller/child增长继续作为未闭合项保留，不因组合而撤销。

## 正式构建资源门与 H10 类型复用（2026-09-27）

H4c/H7b 组合的正式构建源为 `1f9cede1fff402581289e863c44e26d73dc9a9f7`，
host CI `36280225094`、release-image `36280224625` 均成功。canonical netifd
为 `8208c20823cec48c61c0b3df9eb7f0bcb752af2a42e026a266e3cfdcde5b83af`，
不同于 Oracle `c2dadd…`；两者不能混用。canonical 精确 ELF 已通过完整31场景、
overflow、restart、两种reconnect及raw66。候选66项错误码、DATA字节和顺序均与C一致；
正式R89的63项既有差异单列，不计为性能收益。证据在
`private/netifd-20260927/canonical-gates-01/`，独立审计核验2118个文件及448项工具源码。
外层SSH在远端测试和post门结束后仍未返回，确认无测试残留后仅停止任务所属本地SSH；
工具退出255，原自然退出未知，不能补记为0。

实际相关无线配置/stub的AX3000T资源诊断 `final-resources-03/` 已完成C、正式R89及
上述canonical三个窗口，采集、生产身份和清理门通过，**冻结资源预算失败**。
128接口时canonical所依赖的精确C ubusd相对C侧：RSS多36KiB（预算32），
Anon多108KiB（预算32）；全生命周期采样最大Anon多104KiB（预算64）。
R89在128接口时依赖Anon也为244KiB，其采样最大为332KiB，不能据此豁免候选。
这些是事先冻结的工程预算，不是等效性或物理精度保证。

H10只改变netifd的接口注册方式。精确C netifd的`iface_object_type`由固定
`network.interface`对象持有，所有具名接口共享它；原Rust和R89却逐接口发送完整
SIGNATURE，精确C ubusd因此逐份分配type及11个method元数据。Rust依赖Anon在扩容开始
约1秒已达到244KiB，早于约32秒的大dump，支持注册成本归因。精确ubusd收发直接按帧
分配，不使用ustream，排除了“合包撑大ustream”解释。本次不改ubusd守护进程。

共享客户端新增显式类型复用API；原API保持行为。netifd从固定接口对象取得类型，
具名对象只发送OBJTYPE；每次reconnect重新注册并取得新类型。C ubusd仅在请求含
SIGNATURE时回传OBJTYPE，复用回复只有OBJID；单测覆盖这一合同、缺失类型及错误码。
类型过期可能静默创建无签名对象，因此成功返回不是充分证据，仍要求LOOKUP和恢复门。

Oracle候选 `a81b61e677b56b6a2e2dc3a728e6789f4d7ae53c78cc2aafe5dd6f7c421058cc`
通过48项共享客户端和166项netifd单测、ABI、release及clippy。初次源码归档漏收
rpcd的profile_support，导致all-target clippy失败；补齐tracked文件后通过，原归档和
失败日志保留，见`h10-01/source-completeness-failure.json`。不把macOS上误跑的
Linux专用测试作为验收证据。

`h10-resource-screen-01/`冻结计划SHA为
`ea8c6d1642daba43a56a4537c0e685fd2696f32ddbd54b0fd6fd40b1aa1328ba`。
C→旧Oracle组合→H10→H10→旧Oracle组合五窗完成，原5%宿主门、namespace及网络身份门
通过。初始2、扩容128、缩回2的LOOKUP中，C和H10的接口类型数均为1；旧组合分别为
3/129/3，各对象签名hash与C一致。两对128接口依赖Anon分别减少108/112KiB，超过
冻结至少64KiB门；主体三个固定阶段Anon差均为0KiB，主体/依赖fd与线程增量均为0。
这是有界机制/资源筛选，不是延迟、CPU胜负或最终接受；原始采样最大值仍全部保留。
资源快照之后新增LOOKUP握手，可能影响后续allocator历史，不能冒充无插桩最终资源窗。

Linux官方v6.12.94源码解释了reported VmHWM可能下降：`task_mem`汇总当前各CPU残差，
持久hiwater更新却使用较粗global计数，读取status不会回写hiwater。源码支持这一可能
机制，没有重建实机counter值。报告同时保留reported HWM与采样最大、近似及漏峰边界，
不声称精确物理峰值；三个资源FAIL不变。精确源码URL/hash及退出FD回收路径位于
`hwm-source-audit-01/`，报告SHA为
`5e37100b1222bf5cd1d0ecfed1bdff85a1f1d47b988a10494663c6e0611a0299`。

## H10 精确正式产物、合同门和资源04（2026-09-27）

H10提交为 `dc055aee2d576599699c52479bd58c0566584626`，研究tag为
`research-netifd-20260927-h10`。host CI `36308638556`、release-image
`36308634604` 均在该commit成功；正式 netifd SHA256为
`4c0420503a93dd33bd98ad9197bb8da156578fd012dda346507bff54645c41ad`，
不同于Oracle筛选的 `a81b61…`。canonical身份、core manifest和两项CI记录见
`private/netifd-20260927/h10-canonical-ci-01/verified.json`，SHA为
`086a8858baf3a50aa87d16761c83cde96413dd2e28eee18aca74b1f66647e669`。

精确4c…产物已重新执行完整31场景、overflow、restart、两种reconnect及raw66，
不是把Oracle a81…的通过结果转移过来。31项无遗漏或失败；r46/r47/r48使用另行核验
身份的Oracle helper，其余28项使用canonical守护进程，不把helper称为CI产物。
overflow保留原socket身份，收到7446次记录的drop后将rcvbuf从131070扩至262140，
队列归零且后续事件可用；该故障门的 `subject_exit=null` 保持原值。独立审计核验
2127项门证据文件和448项源码输入。新的三侧raw66共198个blob均核验长度、hash和
有序DATA帧；候选对C为0/66差异，正式R89对C仍为63/66既有差异，不计作性能收益。

类型生命周期也已用精确4c…另行重跑：C/候选各七阶段，覆盖动态添加、删除、同名重加、
同broker重连、broker重启及netifd reexec。72条LOOKUP记录仅规范化opaque ID的值，
保留属性槽位、顺序和完整签名后相同；同连接的固定类型anchor保持，新的连接完成注册。
生命周期50项证据及归档逐字节核验，审计为
`h10-canonical-type-lifecycle-01/independent-review-01/verified.json`，SHA为
`ba778cc315c15e15fb8a200099ea5ee3ced395ac59848908970a2bc4bc858bda`。
上述全部门的总审计为
`h10-canonical-gates-01/independent-review-01/verified.json`，SHA为
`d06d3b352cfc9454ba439f1994a29206c20969d82c5e39c34d7728497b04b805`。
这里及下文未带前缀的本阶段证据路径均相对 `private/netifd-20260927/`。

三项观察限制继续保留，不把这批工具执行写成无异常：

- C侧生命周期helper的Proxy在故意重启broker时记录一次后端connect的
  `FileNotFoundError`，连接计数从2变为4，随后一代完整注册且所有恢复后查询与身份门
  通过。异常没有时间戳或connection ID，关联到具体尝试只是推断；canonical对应日志
  为空。没有更换窗口或抹掉traceback。
- 冻结的 `post-raw-check.py` 仍检查旧 `canonical-raw-01/COMPLETE`。该断言不能证明
  本次raw66完成，未追溯修改或重跑。独立证明来自新 `h10-canonical-raw-01/` 的完成
  标记、198个当前blob、当前结果及差分、raw driver自身候选/C断言和正常退出的`&&`链。
  实际post-host/census观察仍保留；该observer没有独立的 `ip -6 route` 快照。
- 远端run-all明确记录 `driver-exit.txt=0`；外层SSH的原自然退出仍为 **UNKNOWN**。
  首次本地停止检查因comm路径不符拒绝且没有发信号；确认远端无匹配任务后，仅TERM
  已核PID/PPID/argv的本地SSH。后写且位于远端原始归档之外的
  `observer/tool-exit.json` 记录工具退出255；不把255或UNKNOWN补写为0，也不猜测传输原因。

### 资源04：固定阶段机制成立，原预算仍失败

`final-resources-04/plan.json` SHA为
`205a3865001dc7f7952df4ede08dff384915cfde5c76607ec7e42068bdb0d18a`。
保持C→正式R89→canonical4c…三窗、实际相关无线配置/stub、N20、缩回后100次小dump、
原120秒guard和原32/64KiB预算。三窗采集、生产C健康/身份及清理门均通过；各36个RPC
lane的错误数为0、完成数正确，完整fixture及工具hash相同。独立审计逐项核验三个raw
归档的2386/2486/2462个文件。**采集完成不等于资源预算通过**：

| 基线 | 角色／阶段 | 指标 | 候选 KiB | 基线 KiB | 增量 KiB | 冻结预算 KiB |
|---|---|---|---:|---:|---:|---:|
| C | 依赖，全生命周期采样最大 | VmRSS |1068|952|116|64|
| C | 依赖，全生命周期采样最大 | RssAnon |224|140|84|64|
| 正式R89 | 主体，active128边界 | reported VmHWM |1560|1484|76|64|

H10的active128依赖Anon已为136KiB，本轮C观察也是136KiB，正式R89为244KiB；
这支持类型复用消除固定阶段重复注册成本的机制，但不是统计等效，也不抵消表中峰值失败。
候选主体初始RSS/Anon相对R89各多24KiB，缩回时各多4KiB；全部110项角色/阶段/基线对比、
14项正增量及46项观测零差保留。不能把观测零差写成等效。

候选依赖的1068/224KiB峰只在 `resource-samples/00512.json` 命中一次，采样括界为
uptime 586817.85–586817.86；前后样本均为980/136KiB。它位于named128_c4的after
快照586817.84之后、active128资源快照586817.91之前；按固定脚本顺序对应
`check_netifd_interfaces 128 after` 的dump、名字及对象列表对账区间。当时依赖fd为12，
记录的两条netlink队列为0。这只能定位区间，不能证明哪次分配造成峰值；也不能将
10ms采样括界当作真实峰持续时间或把netlink为空当作Unix发送队列为空。

主体HWM的76KiB差也保持冻结门失败：候选早在扩容时已导出1560KiB；R89在大dump期间
曾导出1576KiB，随后active128快照降为1484KiB。全生命周期采样最大HWM候选1572、
R891576，不能用这个相反方向的指标替换按阶段冻结的比较。前述6.12.94计数源码解释
只支持近似与非单调限制，未重建实机counter状态，不能据此扣除假定误差或改变门槛。

三侧settled主体fd为19/10/10，依赖为12/11/11，关闭后依赖均为10；记录到的线程均为1。
主体采样最大fd为21/17/17，依赖为16/15/15。没有候选常驻fd/线程增长；各阶段netlink
队列归零，记录的Drops均为0，采样Rmem最大为0/33024/33024字节。该Rmem是观测最大，
不代表未采样瞬间的积压上界。主体wait/关闭退出0、PID消失、观察到的netlink inode消失及
namespace清理通过；并未逐类普查所有socket inode，也没有PSS、caller/后代瞬时峰值或
任意重复周期无增长证明。

资源04全部样本数为565/590/584，采样跨度37.42/38.53/38.42秒。原50ms名义间隔加
probe开销后，实际起点间隔分别为60–140/60–100/60–100ms；不能归一化为相同观测暴露。
C有一次proc读取失败；R89有一次pending child和两次读取失败；候选有一次pending child
和一次读取失败，分别增加1/3/2次原有一秒等待。所有记录保留，不称作噪声或从结果扣除。

资源04独立结果为 `final-resources-04/independent-audit/verified.json`，SHA为
`bc5d80ae67e03ab4a17a5691fbbbe401c6fe5e61af5ba51019d224020ba35bd2`；
报告SHA为 `7124eaaf8663d54cbe2c25842fc7776e03d138892f1b3bd97d912d622cba8d8f`。
`peak-details.json` 保留各角色全量最大值、首次/末次时点、邻近样本、组快照区间和HWM
变化过程，SHA为 `d4814d1c3112b6d56bd72eefe181fb6dca6f989d6eb0314a46e0d77b20945376`。
Oracle筛选中另有H10单对reported HWM多128KiB、采样fd最大多4的report-only观察，
仍单独保留，不当作路由器结果，也不因本轮数值不同而删除。

### 单帧消息生命周期诊断：准备中，尚无运行结论

`resource04-message-lifetime-review-01/REVIEW.md` 的有限源码对账显示，精确C ubusd
按声明长度分配完整传入DATA消息，转发同一指针；部分发送通常只增加队列节点和引用。
已审Rust回复路径没有额外的完整payload发送队列。一个消息大小的瞬时分配是当前较强
假设，但源码不能证明本次只有一帧存活，也不能证明C未采样到的真实峰与H10相同。
该审查没有找到已成立的netifd独有多余拷贝，更未据此放行三项资源失败。

只准备一次有界Oracle诊断：精确C再canonical4c…，保持原生命周期和caller，观察隔离
C ubusd的分配/释放、帧长度、转发指针与部分发送。不修改ubusd，不拆逻辑回复，不插入
逐回复sleep/yield或改socket buffer以让采样漏过峰值。直接offset probe定义和采集接口
位于 `resource04-message-lifetime-review-01/PROBE_PREPARATION.md`；工具只读资格事实
不等于分配/返回probe已获运行验证，**C/H10两窗实现对照尚未执行**。缺失配对、丢事件或
无法完整匹配生命周期应记录未决，不能填成零重叠；插桩结果也不能替换资源04原窗口。
源码审查SHA为 `52c32fc2aa5878bcb135dddf565cd9450fc284d49f4044ab5a44fa93e0ef50a1`。

当前候选索引为原15项加H10共16项，完整历史处置和精确身份保存在
`final-report-inputs-h10/candidate-index.json`；该私有输入草稿记录其生成时点，之后功能与
资源门的最新状态以本节及上述不可混用的审计证据为准。H4c未完成筛选、H7b第三对成本、
原资源03失败和本次资源04三项失败均未撤销。最终C/正式R89/canonical三方性能确认尚未
启动；原绑定8208…的设计草案不是H10的冻结计划，没有H10全负载胜负结论。

### 内存研究停止条件与最终性能比较准入

用户随后明确追问：路由器内存充足时，是否值得继续追约100KiB差距。在说明保留原失败、
完成一次有限诊断后转向CPU/吞吐/尾延迟确认的取舍后，用户要求继续。因此不再以消除这三项
小额观测增量为调优目标；这是新的实际使用取舍，不是改写原32/64KiB预算或将FAIL改成PASS。
最终报告仍须逐项列出这些差异，不能声称内存等效、动态因果已证明或完整组件已接受。

唯一一次单帧诊断冻结计划为
`message-lifetime-profile-01/prepared/plan.json`，SHA为
`d52f5000375616a4be9e7d3eaf8cc0c7493aebbd67c4aadfa90ca85a0af28a70`。
它在首窗宿主预检以57/825ticks、6.909% aggregate CPU超过5%门槛而停止。namespace、
探针和捕获尚未启动；H10窗未运行；外层命令退出1。原计划和14个归档文件逐字节通过
独立审计，结果为FAILED、单帧动态机制UNRESOLVED，不增加或替换窗口。源码中的
完整帧分配/同指针转发/释放路径仍是源码证据，不能冒充实测分配轨迹。
审计为 `message-lifetime-profile-01/independent-failure-audit/REVIEW.md`，SHA为
`28d1e58241e2b49c5ea2af4694268f2026ef3768eba606b6881344704090e660`。

最终性能比较前的只读健康快照记录MemTotal239024KiB、MemAvailable117656KiB；
最大116KiB观测增量约占当时可用内存的0.099%。RSS/Anon重叠，三个差异不能相加；
这也不是未来内存余量保证。九组件C身份、boot、19个配置文件、en0管理链路、DHCP、
四接口、两AP、DNS/IPv4/IPv6和HTTP/HTTPS检查均通过，四份离线恢复artifact重新hash匹配。
现有资源04证明该固定生命周期的队列归零、关闭和namespace回收；不声称任意压力或
任意重复周期无增长。证据为 `final-confirmation-02/preflight/fresh-01/`。

仅上述已知小额内存失败得到继续性能研究的明确处置；新错误、泄漏/积压迹象、持久fd/
线程增加、恢复失败或生产状态变化仍须停止调查，不能自动套用内存余量理由豁免。


### H10 冻结确认实验与已完成主组（阶段记录）

最终 C／正式 R89／canonical H10 确认已按
`private/netifd-20260927/final-confirmation-02/plan.json` 启动，计划 SHA 为
`6236ab71a23185b62ffa7bbbf2e32857b8c4b420106e2017fd5aa3ba4c4ec293`。
此前“尚未启动”描述保留其历史时点，本节记录后续进展，**仍未宣布组件收尾**。
八组共26个strata，每组20个随机三侧block，共480个namespace窗口、1560条lane观察；
11项own/tree CPU、延迟及吞吐指标形成572个metric×baseline对比；每个对比对ratio与
practical-margin各作一项推断，共1144项，每项自身均有区间上下界。
既定rank2–19的家族覆盖下界95.4177856%以共同目标中位数、独立符号及无未解决系统漂移
等冻结假设为条件，随机顺序和质量门不能自行证明这些假设。

主体/依赖/caller CPU、mean、p50的实际门槛为max(2%,2us)，p95/p99为max(5%,10us)，
吞吐为2%；子进程计数保留原保守表示误差，不因观察到零而缩窄。整份计划已按hash冻结；
其中 `practical_budgets.status` 仍保留继承自草案的行政标签，未据此改变预算或原文件。
原collector、analyzer和数值deriver的SHA分别为：

- `f81fe2ad49b3fb808ed0a77e1e995736e6cd09bcb6462c9239f945deecdcc306`
- `8c5728a593bb6d43b36879bf8ba65117a5bf975d4bea71befb7bd747d833217c`
- `528efa71bf504843d9f9d31f6b631ad3f9e5484bf616a25b7168f4911b1cbc08`

main-32已完成60窗、720条lane观察，40920个raw文件逐项核验；退出、身份、boot、配置、
生产九组件C、健康、计数和错误门均通过。下表仅为**全部20个配对log-ratio中位数换算的百分比**，
不是最终家族区间或接受判定；吞吐正值较好，其余负值较好。

| lane | 基线 | 主体own CPU | mean | p95 | p99 | 吞吐 |
|---|---|---:|---:|---:|---:|---:|
| device_status | C |−42.83%|−33.49%|−31.47%|−28.24%|+40.83%|
| device_status | R89 |−38.43%|−30.33%|−28.92%|−26.29%|+35.41%|
| interface_dump_32 | C |−56.31%|−39.82%|−30.56%|−25.88%|+18.66%|
| interface_dump_32 | R89 |−37.46%|−19.94%|−13.19%|−13.71%|+6.36%|
| interface_named_32 | C |−24.54%|−8.23%|+0.37%|+0.95%|+7.01%|
| interface_named_32 | R89 |+0.33%|+0.57%|+4.50%|+0.66%|−0.46%|
| lan_status | C |−21.58%|−9.66%|−6.69%|−4.54%|+5.31%|
| lan_status | R89 |+1.60%|−0.76%|+0.87%|+0.25%|+0.89%|

named32相对R89的mean配对绝对增量中位数为0.58485us，p95为6.1165us；lan_status
主体own CPU为+0.8603us。这些点估计低于相关绝对门槛不等于区间已证明可接受，更不等于
“相同”。所有12个lane、两基线、依赖/caller以及11指标计数在
`final-confirmation-02/stage-main32-audit/` 保留，不用上述代表行抵消其余非胜出或慢窗口。
该目录 `verified.json` SHA为
`15f92b7de7c1116d28c24352a1d57bf6873e7d801b3de5c999e93504f79a0067`，
描述性完整配对表SHA为
`43de2dbd60decfb716364dde5fb8a4b85b5157b03c1bb9f58148edf4b698be96`。

scale64第48窗在namespace退出0、archive已取回之后，checksum SSH退出255而停止；
原stderr未保存，原因UNKNOWN。独立审核随后从保留raw补取manifest并逐项匹配250文件，
计数/健康/清理均通过。`recovery48-01` 的显式hash证书与非空恢复marker允许继续，
原失败result和STOPPED均保留；1–48窗没有重跑。原collector不变，私有分析adapter仅扩展
准入/来源metadata，统计函数保持原样；原deriver仍会拒绝该非正常窗口。
恢复发生在block16结束与block17开始之间，原队列停止记录至第49窗启动间隔
1063.473212秒；不因此宣称
无漂移。证书SHA为 `b5001ddec1319c49fd1f9238885948b8f9caa4b98ca0ba4cd0c82647328bed11`。

第58窗在后续会话中断时丢失本地outer observer，原本地只留下六个pre/log文件；远端
raw COMPLETE存在，250文件已取回核对。namespace及outer退出均UNKNOWN/null，不能
推定0。独立质量审核及显式恢复代码审查均已通过；补采host/config/健康仅为延迟观测。
此次间隔处于block20内部，R89已经测量、candidate/C尚未测量，必须在最终推断中保留
漂移边界；不删除block、不重跑第58窗，也不修改N、顺序或门槛。

第58窗恢复质量审计SHA为
`4f0e931080377d459b2d1b426fc93e1e8e4f0f11168d0f709a3d6084052c329d`；
`recovery58-01/certificate.json` SHA为
`af11c9e3246aa7696a38c0302a4cc8b99727d809a552c8452d6efc61151d2f36`，
冻结amendment SHA为
`b86f19e6968f2aaa8f5a91c3f7a66b0b22dce1f3dc2765217dcfa41478064bb1`；
独立代码审查SHA为
`bf33bdda9a4be84f35752605aa55458a5fa0b33f66f7184d23efc23059b0c421`。
35项合成准入检查和原统计selftest通过，48原规则不变；新增58准入保留null退出及原result
不存在的事实。新analysis-plan只增加恢复绑定/来源元数据，数值deriver与48版逐字节相同。
恢复runner已独立会话启动，原collector日志确认1–58全部preserved，第59窗为candidate，
随后仍为第60窗C及其余六组原命令；没有重采或替换。独立本地进程及只读设备census已排除
并发实验；防休眠只绑定该runner生命周期，未修改持久电源设置。
第58→59窗collector启动记录相隔2612.943851秒（包含第58窗运行时间）；
原实际停止/完成时点未知，不能称为精确空闲间隔。来源为 `recovery58-01/gap.json`。
