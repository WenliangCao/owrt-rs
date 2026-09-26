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
- 研究初期发现 Rust `network.wireless status/get_validate` 未处理 `device` selector；最终候选已在
  正式性能确认前单独补齐，并通过 C/candidate 参数矩阵逐字节差分。重复 `device` 字段仍未由现有
  ubus 客户端构造，报告中单独列为未覆盖输入。

## 独立假设和候选索引

以下是从同一起点独立筛选的历史候选；H0/H1/H2/H3c/H5 已组合，H4 已拒绝。表中早期 SHA 为 Oracle SDK release + sstrip 诊断 ELF；最终 ELF 与 selector 正确性修复的身份见后文。

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
| 全部功能与恢复 | 旧探索 ELF 31/31；新 selector/H4 身份必须重新验证相关及完整门 |
| A/A 校准 | 两轮已结束，不再追加校准，不并入实现对照 |
| 正式性能确认 | 尚未开始有效确认；现有 13 窗为探索，不追认冻结 |
| 真实无线 | 实际配置/schema + 隔离 mac80211 stub；不执行真实 radio 重配置 |
| 内存/fd/线程/netlink/关闭回收 | 旧探索 smoke/诊断存在；最终三侧完整资源证据仍待测 |
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
