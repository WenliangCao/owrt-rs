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

所有候选均从同一起点生成，尚未组合。下表 SHA 为 Oracle SDK release + sstrip 诊断 ELF。

| 候选 | 单一假设 / 改动 | SHA-256 | 当前证据 |
|---|---|---|---|
| base | 当前代码；仅诊断 example 增强 | `0665583158fc32cd019e5df2e32d4675a586757fb1c450c1a4ed71c590f4caa0` | 157 单测；完整 suite 31/31；clippy 项目门通过 |
| H0 | Option 持有回复缓冲，消除 mem::take 的默认占位分配；错误早退归还缓存 | `72f17bdb44ff9abfcc1ad91e7acc3de41d1692850cc92179a85ad47164252106` | 取用微探针每次减少 1 allocation / 4 requested bytes；尚无实机收益结论 |
| H1 | wireless status 直接从借用配置按原字段顺序编码 blob；handler JSON 不改 | `23a77c43c9df70fef12bba4da59cdb87392cdf4536b7cece50c29ae42de685aa` | 158 单测；真实配置投影 byte-for-byte 相同；完整 suite 运行中 |
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

## 未完成与停止条件

仍需：H1/组合完整功能恢复门；H3 实际128接口筛查；真实配置 stub 的三侧 daemon 差分与硬件负载；
正式 core recipe/最终身份构建；A/A 结果和冻结的 C/R89/候选确认；netlink buffer/队列、关闭后回收及
全生命周期内存证据；所有不胜 C/R89 项逐条解释；剩余合理算法方向的 profile/源码排除。
在这些完成前，不接受“netifd 收尾”或“全面优于”的结论。

## 2026-09-26 continuation: H0/H1/H2/H3c/H5 and selector gate

The provisional combination was H0 + H1 + H2 + H3c + H4 + H5. H4 is rejected from the final combination. Eight paired Oracle windows using the non-empty two-radio fixture measured `wireless_status`, `wireless_status_c4`, and 200 unchanged reload calls (40,000 timed calls for each request lane). H4's single-client means were higher in several paired windows and its unchanged-reload mean was higher in most pairs; its four-client values were mixed. The observed direction does not meet a non-inferiority or resource-cost gate. The cache microbenchmark remains exploratory evidence only. The final combination is therefore H0 + H1 + H2 + H3c + H5; it does not retain the immutable wireless status cache.

A correctness gap found during the final contract review was fixed before generating the final ELF. `network.wireless status` and `get_validate` now validate the `device` selector, reject non-string and extra fields with `INVALID_ARGUMENT`, return `NOT_FOUND` for an unknown non-empty radio, return one radio for a known selector, and treat a missing or empty selector as the all-radio form. The exact upstream selector contract is preserved from `private/upstream-ref/wireless.uc:411-430,507-519,541-555`. An isolated C/candidate differential with the fixture covered `{}`, empty, `radio0`, `missing`, null, bool, integer, array, table, and an extra field for both methods: all return codes and valid outputs matched byte-for-byte. Duplicate selector fields were not generated by the existing ubus client and remain outside this probe's input set.

The final Oracle SDK/aarch64 release build (formal recipe flags, ABI check, Rust 1.98.1, musl) is `private/netifd-20260926/final-candidate/netifd-rs`, SHA-256 `13d21f6fecc0223e006e786bed7b078cfd75e3baf5ad154bb98194d895c268f6`. Its source archive is `private/netifd-20260926/final-candidate/source.tar.gz`, SHA-256 `b8375d63a62b85f37cd0da626468529fd28b9ca145e82ecfb7f9774991d82555`. This is a recipe/ABI build and is not a canonical GitHub workflow artifact; no release, install, switch, reboot, or flash was performed. Unit tests pass (159), and the project clippy gate `--all-targets -- -D clippy::undocumented_unsafe_blocks` passes with existing warnings.

The full `tools/netifd_suite.sh` run for this exact final ELF is running on Oracle under `/home/ubuntu/netifd-research-20260926/final-selector-suite`; its log and every case directory are retained. The earlier H1/H2 recovery and suite outputs remain separate and are not relabeled as final-ELF evidence.

## Frozen hardware confirmation design

The two R89 A/A rounds are calibration only. They are not pooled with confirmation and cannot establish equivalence. The confirmation family is frozen as 24 workload strata: 14 primary 32-interface/empty-wireless lanes, four 64-interface lanes, four 128-interface lanes, and two lanes from the non-empty two-radio configuration (`wireless_status` and its four-client form). The eight formal performance metrics are request mean, p50, p95, p99, throughput, subject CPU, dependency CPU, and caller CPU, each against C and formal R89 (`m = 384` planned comparisons). RSS, anonymous RSS, HWM, fd/thread counts, netlink socket buffer/drop observations, and close/reap behavior are reported as engineering/resource evidence, outside the superiority family because current HWM/RSS are diagnostic counters rather than independent peak/PSS measurements.

Each stratum uses 19 independent `random-blocks` blocks (57 fresh namespaces) with the C/formal-R89/final-ELF order uniformly shuffled inside each block and a pre-recorded seed. For `m=384`, the exact two-sided Bonferroni rank interval first permits one adverse block at `n=19` (`k=2`, order statistics 2 through 18); six or eight windows cannot provide that family-level finite interval. Fast lanes use a separate frozen run with `N=40000`; other lanes may use `N=10000`. Outputs from separate lane runs are never paired across runs. Calibration windows, failed windows, and identity/cleanup failures are preserved and excluded from superiority claims.

No production state changed during this work. The C stack remains the running production stack; all candidate executions are isolated namespace runs over Wi-Fi management.

The final candidate smoke on AX3000T used the frozen R96 recovery gate and the existing Wi-Fi management path. Its matrix completed with `passed=true`, `installed=false`, `same_boot=true`, `same_config=true`, `same_production_identity=true`, and `same_host_mounts=true`; evidence is `private/netifd-20260926/final-smoke/result.json` and the downloaded raw namespace record. This is a correctness/cleanup smoke, not a performance claim.

The final ELF's formal recipe ABI check reports `check-abi: all FFI struct layouts match the target ABI`; toolchain identity and ABI logs are in the Oracle final-selector-build directory. Canonical GitHub CI was not invoked, so this report does not label the local recipe build as a release artifact.

The final ELF completed the full 31/31 netifd differential suite (Oracle log SHA-256 `03eb249e647daf60402f6f2bbe705a57f99784cefc93555a375c9092cdb864ee`). The final isolated recovery gates also passed: netlink overflow/resynchronization (`final-recovery-fixed`), restart (`final-restart`), and both ubus reconnect faults (`final-reconnect-device`, `final-reconnect-interface`). The first overflow attempt is retained separately as a failed tool-normalization window; after normalizing `ss` whitespace, the candidate checks were identity, overflow reached, buffer grown, removed-device observation, subsequent events, and serving.

A final-ELF Oracle `perf record` diagnostic on the device-status lane completed with 1,118 samples and zero lost samples (`final-profile-dev/perf.data`). The dominant visible sample was the expected Unix-socket wakeup/send path; the stripped release ELF did not expose useful Rust symbol names. This profile is diagnostic and not mixed into latency confirmation.
