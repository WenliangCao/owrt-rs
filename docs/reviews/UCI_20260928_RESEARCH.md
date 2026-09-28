# UCI 下一轮算法研究与工程收尾

2026-09-28。起点 `2855345597e0ba42bbdcae05e5b9f1bb7cf49275`；正式运行时源码 `feb7a4ee2265a8e7207094764f1c8b41d69fe3bb`。本轮仅优化 UCI CLI/Rust 共享库，不替换系统 libuci.so；已收尾消费者源码保持冻结，只重建并回归。用户原有 prompt 修改和未跟踪文档未纳入提交。

## 研究、取舍和本轮增量

保留 C2 + D1-delta + D2：借用 CLI argv、直接比较 ASCII 命令字节、只读 changes 借用包、delta 遍历不复制整组路径、revert 搬移保留项，以及复用已有的分段转义。净运行时代码只有 CLI、delta、export 三个文件；file/parse/model/context/read_cache/show 与起点相同。没有撤销 RPCD 的工作模型/缓冲复用，完整读取至 EOF、正数短读继续、EINTR、统一取消/超时预算、普通 CLI 锁行为及持久化顺序全部保留。

具体 C/Rust 差别和证伪条件见[候选与拒绝索引](UCI_20260928_CANDIDATES.md)。C 直接借 argv、strcasecmp，Rust 起点额外复制参数和构造命令字符串；C 的 delta 链表遍历无需复制路径数组。分配插桩覆盖真实 CLI 从 libc main 至退出前，各阶段分开计数：最终两种 export 夹具均少 9 次 Rust 分配；读取、解析、Bytes 与输出缓冲的次数不变。它不包含 libc 内部、分配器元数据、kernel 或退出清理，不能等同于 RSS 或 CPU。

拒绝 fresh-read 零初始化变体：两边仍各一次分配，收益不一致，与 CLI 改动组合后小包 export/get CPU 增加约 3.5%/5.1%。拒绝 parser 临时索引：确定性查找计数为 N(N−1)/2，1024 节 Oracle CLI CPU 确实降低 52.91%，但 8 节增加 21.13 µs/8.94%，并增加约 12 KiB ELF 和临时名字表。拒绝 show 分段写：首次写错误后的继续行为不同，撤回后未引入恢复状态机。没有证据支持换分配器、扩大 Bytes 或增加全局索引。

Oracle SDK 同工具链六方案筛选先 pilot（每侧10次、2轮，修正夹具后约4.1秒），再冻结每侧3轮×200次、预热5次、完整随机块，约34.5秒。最终组合对起点三条历史负载命令树 CPU 变化为 −7.58%、−2.76%、−1.05%；show_long +1.50%、batch_read16 +1.00% 同时保留。候选是组合后实测，未相加单项收益。SDK 诊断、native profile、canonical 与实机数据分别列出，不把近期 RPCD 的 Oracle +13–14 µs 小额 CLI 成本直接归咎于数据结构，也不将本轮 Oracle 数字外推到 AX3000T。

## 正式构建与精确身份

[canonical release-image run 36485630189](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36485630189) 成功：干净 Git checkout、Rust 1.98.1、aarch64-unknown-linux-musl、OpenWrt GCC 14.3.0。七个 APK、镜像离线检查和三个 standalone core 构建通过；下载后重新核验全部 APK/镜像/core archive SHA，实际提取九个 ELF，核实 aarch64/static 和 manifest。镜像 SHA256：`1e098f8ac395a22c01899fdfc17b9e72e6493612b8fd9b3632ccf99e8c367288`，未刷写。

| 侧 | UCI ELF SHA256 | 字节与用途 |
|---|---|---|
| 精确 C | `050e9ab320b794f636174536ca4dbca2f615a1c6c37bc19e9ca06bfd6d6e7278` | 16,395；动态链接，精确 /rom 与运行路径相同 |
| 正式 R89 | `1758125b86c80a1a09c2db55df83952f5cbef6542527f1de1f37a088cba115cf` | 506,635；原归档 /root/r89-before-r90/bins/uci-rs |
| R94 | `c3b51560a3b595281a3b919e8881fecf28806fd46a59292c9cc64610be261857` | 486,155；保留的原 SDK 诊断 ELF，含后来修复的缺陷 |
| 最终候选 | `336164c7b49908a356eccf934e40528398811ff2595e2b926170278a15c5c506` | 486,155；本轮 canonical APK 实际提取 |

起点 canonical UCI 为 `76634691d7546c9f996daa94258842f68fe0212fe5ec6dc8cf787038f7530085`，用于独立短增量/共享回归，未当成最终第五侧。C executable 大小不包括动态依赖，不能与静态 Rust ELF 直接当作总系统空间成本比较。精确 libuci SHA 为 `bdfc94c8daca8c900e48bdd41c7c0f134ac92d1d1831a20c9b0179c8232fe5b0`，musl loader 为 `8afe4bccb74f595fd45e3c499c1e7e2520ac03c0881f439a8ccb994bf8d3ee5b`；四侧使用相同镜像及依赖。重新核对 libuci 完整上游 revision `66127cd76c5d0bd46d5a90302cc6110f53a4e2f8`、manifest 及审阅的9个C源文件 SHA，私有只读副本与 pinned checkout 相同。

## 验证与合同边界

[完整派生验证清单](uci-20260928-validation.json) 记录每门日志 SHA、执行 ELF、source/image 前后身份。最终 native 测试 310 个顶层用例：UCI49、RPCD64、NETIFD166、FW4 17、reload-config14；RPCD 一次隔离子测试重执行另计。五个项目规定的 all-targets clippy 通过。UCI 覆盖 libuci_fidelity、config_listing、read_cache_files、io_budget 与读取回归；共享测试确实重新编译本轮 UCI。

| 正式 ELF 功能门 | 结果 |
|---|---|
| UCI r16 | 193/193步骤 stdout/stderr/退出码及配置/delta字节、权限一致 |
| UCI r24 | seed92，1000例差异0 |
| UCI r83 | 498 output + 56 scratch 文件比较通过，保留 R92 声明差异 |
| RPCD r17 | 283/283步骤一致，session/ACL/UCI/apply/confirm/rollback；reload helper 仅在此私有夹具替换 |
| FW4 | upstream31、defaults12通过；defaults错误输入仍有既有C15行/Rust1行stderr差异，未声称全部stderr全等 |
| reload-config r1 | 11参考+9故障通过，原始 pristine C reload_config，覆盖规范化与超时/取消/失败原子性 |
| NETIFD | baseline/dns/metric/route/rule/hotplug/rc七阶段一致；C和候选restart门通过 |

非 UTF-8 rename 仍是明确拒绝，而 C 保存瞬态 raw delta；不使用 U+FFFD 伪造兼容。batch 每命令卸载保持，缓存仍重新核实路径、锁、完整当前内容并重放当前 session/state delta。预算失败移除部分加载包，不要求删除之前已验证的纯 base 缓存。写路径保留 flock、fsync、mode 和原子 rename。

工具验证另含 exec-strict 的失败/正常 stderr 检查、12个分析测试、13个四侧测试及 accounting selftest。修正了短命分析分支原本误用100Hz tick的汇总；原始精细计数一直在数据中。现在单独暴露 command_tree_cpu_us_per_op，排除预热和测量工具 CPU，保留旧字段用于审计；没有完整 getrusage 与 caller clock 的旧数据仍不具备验收资格。

## AX3000T 四侧结果与恢复

当前只读身份为 Xiaomi Mi Router AX3000T、DT `xiaomi,mi-router-ax3000t`/`mediatek,mt7981`（既有设备记录 MT7981B）、OpenWrt25.12.5 r33051-f5dae5ece4、Linux6.12.94；boot `75a17130-62f9-43f8-bd28-7bbbb44ad5c8` 前后不变。五份离线恢复归档重新完整读取并核验SHA，当前配置匹配备份，沿用900秒恢复证据和每窗口600秒namespace guard。Wi-Fi管理/en0健康通过，生产始终精确C栈；未部署、刷写、重启或改生产网络/Wi-Fi/nft/ubus。

所有路径均在只读镜像或namespace私有tmpfs中；`/etc`、默认delta、override、显式绝对路径及符号链接均被chroot隔离。16个正式窗口逐次核验实际ELF/工具/夹具/依赖、生产身份、配置和主机挂载，完成后移除本轮远端临时目录。UCI正确性smoke通过；四侧pilot为各2轮×10次，共约53秒；正式批事先冻结各4轮×200次、预热5次、seed20260928完整随机块，128项测量全部成功，含准备/传输/校验/清理共214.46秒。每次计时含真实exec至退出，stdout/stderr/退出码验证；set/commit/get每次写入不同值，结束后由C另读持久文件、逐字节比较并检查权限和空delta。重置/末尾检查不计时，命令内get验证计时。

CPU为 µs/操作，逐轮中位数；变化为候选减基线。全部mean/p50/p95/p99/吞吐、CPU、峰值、缺页、逐轮范围/配对方向及证据强度见[80行详细表](UCI_20260928_BENCHMARKS.md)和[派生JSON](UCI_20260928_BENCHMARKS.json)。

| 负载 | C CPU | R89 CPU | R94 CPU | 候选 CPU | Δ C µs / % | Δ R89 µs / % | Δ R94 µs / % |
|---|---:|---:|---:|---:|---:|---:|---:|
| export_network | 1763.723 | 913.265 | 803.788 | 798.547 | -965.175 / -54.72% | -114.718 / -12.56% | -5.240 / -0.65% |
| export_64 | 3287.125 | 1837.930 | 1675.390 | 1656.658 | -1630.467 / -49.60% | -181.272 / -9.86% | -18.732 / -1.12% |
| set_commit_get | 8986.075 | 6801.932 | 6269.275 | 6300.405 | -2685.670 / -29.89% | -501.527 / -7.37% | +31.130 / +0.50% |
| get_network | 1729.273 | 878.155 | 772.858 | 775.140 | -954.132 / -55.18% | -103.015 / -11.73% | +2.283 / +0.30% |
| export_multi | 8396.678 | 4906.688 | 4466.140 | 4406.500 | -3990.178 / -47.52% | -500.188 / -10.19% | -59.640 / -1.34% |
| show_long | 9863.315 | 6937.070 | 7065.753 | 6279.620 | -3583.695 / -36.33% | -657.450 / -9.48% | -786.133 / -11.13% |
| delta_64 | 3467.528 | 2349.355 | 2032.330 | 1980.165 | -1487.363 / -42.89% | -369.190 / -15.71% | -52.165 / -2.57% |
| batch_read16 | 11620.115 | 8439.028 | 8603.465 | 8647.185 | -2972.930 / -25.58% | +208.158 / +2.47% | +43.720 / +0.51% |

八条CPU中位数均低于C，七条低于R89；batch_read16比R89增加208.158 µs/2.47%，四轮均增加，mean增加2.67%、p95增加4.79%。相对R94，export_network/export_64 CPU仅−0.65%/−1.12%，逐轮方向混合；set_commit_get/get/batch CPU分别+0.50%/+0.30%/+0.51%，set_commit_get mean+1.16%、p95+5.08%。这些差值不写成“相等”或全面胜出。show_long比R94 CPU−11.13%是当前累计实现的结果，**不是已撤回show改动的本轮收益**。R94所有本批场景都通过完整输出校验，但不因此恢复其作为正确性基准/部署候选的资格。

短命CPU使用getrusage已回收命令树user+system，1µs编码不等于1µs准确度；子shell和三次CLI全计，未全部称作UCI自身。caller CPU独立列出；未使用100Hz零tick推断零成本。资源诊断每窗口另取三次wait4完整生命周期样本，保留minor/major fault和maxrss；没有用退出后的空resident表。所有commit写入仅在私有tmpfs，保留fsync与原子rename，不宣称flash持久化提速。


## 共享消费者与资源取舍

[共享消费者及canonical增量表](UCI_20260928_SHARED.md)单独报告Oracle数据：冻结四个消费者源码，用本轮正式UCI库实际重建；两侧是canonical原ELF，ABBA四窗口，所有回复和场景状态门通过。RPCD大UCI单客户端CPU44.619→43.156µs（−3.28%），四并发46.241→46.213µs（−0.06%），四并发mean+2.90%；没有撤回其模型/回复缓存收益。authorized CPU+0.415µs/+1.92%，state +0.502µs/+1.74%，小额代价明确保留。NETIFD32接口不变重载CPU−1.17%，FW4 print +4.200µs/+0.57%且mean−0.49%，reload-config−3.33%。对应正确性、session delta隔离、规范化和预算门全部通过。另用最终正式reload-config在AX3000T隔离窗口重跑base/delta/override三种持锁的超时和取消，共六个场景通过；释放锁后的恢复、已渲染输出、基线与投递副作用符合既有R95门，窗口清理及全部主机健康/身份检查通过。

正式canonical UCI短增量也有反例：export_network CPU225.700→238.460µs（+12.760/+5.65%），两对窗口方向↑↓、范围重叠；set_commit_get +0.76%，delta_64−6.14%，其他数据逐项列出。不把SDK筛选中的−7.58%等同于正式产物稳定收益，更不据此推断路由器退步；工具链/布局与算法归因分开。选择简单组合的依据是明确少分配/少复制、全部合同门、设备主要负载及消费者整体可接受的实测取舍，而非每格胜出。

资源取舍：候选常见单次读命令wait4峰值中位数396KiB，长值show652KiB，与R89/R94同值；相同场景C为720–884KiB。set_commit_get的shell/后代峰值候选1082KiB，C1080、R891034、R941072；这不是UCI堆大小或并发RSS总和。候选show_long minor faults109.5次，C78/R8990.5/R94108.5；batch为125次，C97.5/R89112.5/R94125.5，多包读取也有相对C/R89额外缺页。所有major faults为0。这些增加没有隐去，未从不同平台/负载求虚假的净收益。资源样本stdout到文件，性能到管道；wait4峰值可含小型launcher的fork→exec区间，每窗三个资源样本的中位数再跨四轮汇总。

新库消费者的完整ELF身份和验证记录在[清单](uci-20260928-validation.json)。常驻窗口末RPCD RSS/Anon/HWM为当前1236/108/1236KiB、新库1174/110/1184KiB；NETIFD1268/340/1268KiB保持。这是所测窗口的观察，不是对长期所有工作负载的内存保证。


## 停止理由与复现

主要机制已有具体实现或反证，简单组合完成独立分配归因、同批筛选、功能门和正式产物验证。其余可见收益集中在巨大合成配置、需要改变错误行为的 show 快路径或无一致收益的分配选择；继续调阈值不值得增加状态与兼容成本。工程结案允许已量化的小额代价，不意味着每个格子获胜或已生产部署。

原始数据、ELF、镜像、恢复归档、配置及源快照保留于 ignored `private/uci-next-20260928/`；只提交代码、工具和脱敏派生报告。保留 BusyBox 无 stat 的首轮 pilot 失败记录；macOS 非UTF8建文件/缺strip工具、既有 all-warnings lint 和 SDK runas 诊断环境限制都在候选索引/原始日志中，正式 Linux/CI 门独立执行，没有改写失败为通过。

复现实机集合使用现有 `tools/benchmark/run_candidate.py` 的 `--component uci --matrix --schedule random-blocks --seed 20260928 --repeats 4 --iterations 4000`，同时传入 canonical 候选、R89 bundle、`--extra-baseline r94=原ELF`、配对 provenance、同一 `--bench`、`--exec-resource-probe` 与 `--guard`。必须先完成当前 boot 的恢复/备份/健康门。命令布局、夹具和计量边界见 [benchmark README](../../tools/benchmark/README.md)；分析用 `analyze_candidate.py`，分配归因用 `profile_uci_allocations.py`。正式构建固定上述 CI commit，后续工具测试/报告提交不改变其运行时源码。
