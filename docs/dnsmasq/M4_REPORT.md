# M4：单线程替换包与资源复核

日期：2026-10-03。状态：**M4 已完成；体积采用用户明确接受的方案 A。** 用户已明确接受方案 A：稳定工具链、`opt-level=3` 的 **1,159,280 字节** ELF。它仍比原 **1,000,000 字节**目标多 **159,280 字节**，这是测量后由用户接受的取舍。相比镜像 C 的 269,305 字节，Rust 是 **4.305 倍**，多 889,975 字节。不会用已作废的 1.5 MB 预算判为通过。

## 退出条件与身份

退出条件是：单线程版本完成受影响的 DHCP、DNS、生命周期和资源回归；确认 TCP 上游停滞、ICMP 检查不会阻塞其他服务；公开体积来源、每步缩减和缓存满载的资源差距；最终 ELF 与源码 commit 对应；同一 ELF 的 APK 在镜像 rootfs 中完成真实安装、升级、卸载、回滚。超出体积目标须由用户决定是否接受。物理路由器未操作，M5、M6、M7 未完成。

| 对象 | 身份 |
| --- | --- |
| 最终产品源码 | `4b3fc62cea8b4d3897c3a9bca082964812e82ffc` |
| 最终 Rust ELF | `faa55065bfd589eb1be9114ea3352aa10c8b9a7e862384deee321c6283b24577` |
| 镜像 musl C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| stock dnsmasq APK | `752fa57e5a986425f03c9f6579097c7f23750fc80b3af317e4ee0e2d1b7a0d89`；155,123 字节 |
| 匹配 SDK archive | `ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25` |
| 工具链与目标 | Rust 1.98.1；OpenWrt 25.12.5 mediatek-filogic GCC 14.3.0 musl；AArch64 静态 ELF |
| 编译设置 | `opt-level=3`、LTO、单 codegen unit、`panic=abort`、strip、`-Cforce-unwind-tables=no` |

构建归档生成于提交之前；之后已逐字核对全部 110 份归档源文件与上述 commit 一致。完整映射和构建命令在 `private/dnsmasq-rewrite/evidence/M4/size-opt3-final/`。包工具的后续 commit 与产品 commit 分开记录，不能把包装工具的 HEAD 冒充 ELF 源码。

## 单线程行为与最终回归

[线程模型 ADR](ADR_THREAD_MODEL.md) 已落实为单一 poll owner。TCP 上游使用非阻塞连接、写入、读取状态机；下游部分写入保留进度，每轮有工作量上限。ICMP 等待期间继续处理 DNS、TCP、TFTP 的就绪 fd，提前唤醒不消耗整个 ICMP 超时；不重入 DHCP。DHCP 监听按 C 的 `interface` 与 `listen-address` 并集处理，原始配置组合直接对照，没有换成容易通过的 LAN 配置。

最终 ELF 的以下结果均对照镜像 musl C；单元测试单列，不将测试二进制当作 release ELF：

| 范围 | 结果 | M4 证据目录 |
| --- | --- | --- |
| DHCP actual20、static-ethers、expiry120、ping-conflict | 四组均零差异，包括静态/ethers、恢复、续租、重绑、释放、DECLINE、到期和冲突 | `size-opt3-final-dhcp-1791029005/` |
| DNS UDP/cache、expiry、TCP、故障恢复、strict-order、all-servers、混合查询 | 1,040 行比较零差异；21 个比较器负向对照生效 | `size-opt3-final-dns/` |
| init、SIGHUP、reload、rpcd UCI apply、真实 odhcpd 发布与 AAAA | 18 步一致；停止后 PID/服务回收 | `size-opt3-final-service/` |
| TCP 上游停滞 10 秒 | DHCP DORA 与 UDP DNS 均在预定的 2 秒上限内完成；协议和清理一致 | `size-opt3-final-service/tcp-stall-attempt1/` |
| ICMP 与 DNS/TFTP 共存 | 实际 Echo 发出后，20 次 UDP DNS 和四块 TFTP 传输在 OFFER 前完成 | `size-opt3-final-service/icmp-tftp-attempt3/` |
| DHCP 原始 interface/listen-address 并集 | C/Rust 一致 | `size-opt3-final-service/interface-union-attempt1/` |
| fast-dns-retry | 释放中间槽并复用后，C/Rust 重试顺序均为 c、d、a；恢复和清理通过 | `size-opt3-final-fast-retry/` |
| Linux musl 单元测试 | 库 439 项、main 10 项通过；17 项 ignored 不计通过 | `size-opt3-final/unit-results.json` |
| 配置解析与启动失败 | DNS 配置 57 例、CLI/include 23 例与 C 一致；五组 release 退出码及负向对照通过 | `size-opt3-final/config-image/`、`startup-exits/` |
| ENOSPC 与 EMFILE | 两项均先 trial 后正式，对镜像 C 零差异；恢复与退出清理通过 | `opt3-final-pressure-1791029049/` |

混合查询中的逐记录 TTL 诊断没有参与断言，TTL 行为由独立 expiry 组覆盖。此次没有重跑 M2 的三项 30 分钟 fuzz；本轮没有改报文解析入口。M2 的旧 all-servers fixture 实际混入了 strict-order，不能证明 all-servers；本轮修正工具后，才得到真正 all-servers 的镜像 C 对照。

收尾发现一个旧缺陷：配置文件缺失或无权读取时，loader 已产生正确的退出码 3，main 却统一返回 1。旧基线和 format 版本均复现；最终版本保留 loader 退出码，镜像 C 对照依次为缺文件 3、缺目录 3、权限 3、语法错误 1、成功 0。诊断文字仍与 C 有差别，原文保留，未宣称 stderr 逐字兼容。

## 体积来源与削减结果

预算变化保留原记录：1.5 MB 预算已作废；700,000 字节曾是临时目标；用户随后明确改为 **1,000,000 字节并保持 opt-level 3**。新计划先记录于 `size-plan-1000000-opt3.json`，再执行产品缩减。APK 的构建前检查上限为 700,000 字节；它不能替代 ELF 目标。

| 步骤 | ELF 字节 | 相对上一步 | 取舍和验证 |
| --- | ---: | ---: | --- |
| 已冻结功能基线，opt-level 3 | 1,220,720 | — | `532a7b42…`，完整功能与压力回归 |
| 加 `force-unwind-tables=no` | 1,196,144 | −24,576 | 采用；DNS 七组、DHCP 四组和 TCP 停滞对照通过 |
| 共享冷错误格式化、直接生成反向域名数字 | 1,196,144 | 0 | ALLOC 内容减少 364 字节，但文件总大小未改善；配置单元和 C 对照通过 |
| 共享启动排序；重试直接按槽倒序遍历 | 1,155,184 | −40,960 | 采用；排序、稳定性负向对照、DNS、真实重试顺序、static-ethers 均通过 |
| 将配置读取器改为 dyn BufRead 的试验 | 1,179,760 | +24,576 | **未采用**，增大体积；不宣称该实验通过功能验证 |
| 修复配置加载退出码，最终产品 | **1,159,280** | +4,096 | 正确性修复保留；全部最终回归见上表 |

最终比起点减少 **61,440 字节（5.03%）**。排序使用一个共享的 usize 索引排序和安全置换，稳定相等项仍按原位置排序；复杂度 O(n log n)，启动/reload 临时内存为 AArch64 上每项 8 字节。DNS 每请求和租约热路径没有因此增加索引向量分配。共享读取器的膨胀结果保留，没有为了展示缩减而删掉失败尝试。关闭可选 unwind tables 的代价是故障回溯可能缺少部分应用帧；panic 仍然 abort，本轮没有将诊断能力的变化当作协议收益。

源码 `932214a` 上的历史 s、z 档位分别为 1,056,880、987,248 字节；用户明确要求保留 opt-level 3 后均排除，z 的未完成资格化标为取消。没有引入 nightly、build-std、panic ABI 替换或裁掉功能。`panic=immediate-abort` 在稳定编译器被拒绝的探测也保留。z 上关闭 unwind table 与 z 原 ELF 相同，不能推断该选项在 opt-level 3 上也无作用。

`elf_size_report.py` 对经过 ALLOC 内容和 LOAD 布局逐项匹配的符号 companion 归因；不是从被 strip 的文件猜 crate 占比。最终 companion 的全部 15 个 ALLOC 节匹配。表中是去重后的函数地址范围，泛型按符号命名空间归属，不能直接当作 crate 的全部存储占用。

| 函数命名空间 | 基线字节 | 最终字节 |
| --- | ---: | ---: |
| dnsmasq_rs | 458,720 | 462,708 |
| core | 163,292 | 120,480 |
| C/汇编/未修饰符号 | 101,724 | 101,724 |
| std | 77,504 | 77,832 |
| alloc | 50,128 | 50,128 |
| gimli + addr2line + rustc_demangle + miniz_oxide | 67,620 | 67,620 |
| hashbrown | 26,140 | 26,140 |
| owrt_ubus | 18,400 | 18,400 |
| libunwind | 17,548 | 17,548 |

最终文件的完整存储分解如下，函数归因与节存储不是可相加的两套成本：

| 存储部分 | 字节 |
| --- | ---: |
| `.text` | 980,740 |
| `.rodata` | 57,868 |
| `.eh_frame` + `.eh_frame_hdr` | 75,828 |
| `.data.rel.ro` | 30,456 |
| 其他带文件内容的 ALLOC 节 | 8,524 |
| 文件头、非 ALLOC 信息及间隙 | 5,864 |
| 合计 | **1,159,280** |

C 的 ELF 动态链接 musl/UBus 等库，Rust 的 ELF 为静态链接；以上是用户要求的文件绝对体积比较，没有把 C 的共享库另算进它的 ELF。运行时成本另用 RSS/PSS 实测。应用只有本仓库 owrt-ubus 一个依赖，没有可直接移除的重型第三方应用依赖。稳定版预编译 std 的 panic/backtrace 支持仍在；仅设置 panic=abort 并不会消掉全部相关代码。

**1,159,280 字节是本轮稳定版工具链、opt-level 3、现有功能与构建约束下，已采用并完成验证的方案的实测下限。** 这是测量范围内的下限，并非所有可能 Rust 实现的数学下界。 当前代码节本身已接近 1 MB，再加数据和运行时支持就超过目标；所要求的局部措施没有弥补剩余 159,280 字节。继续缩小有两条已识别的取舍：opt-level s 可减少内联和展开，但可能增加每请求 CPU、影响吞吐/延迟，代价未测；用户要求把同源码 s 档位与 opt-level 3 的 CPU 对照留到 M6 再决定。另一条路是 nightly 的 build-std，重建标准库以裁剪不需要的运行时支持，但会引入非稳定工具链、自行维护 std 构建及额外回归/供应链成本，本轮不采用。不能把尚未测量的体积或 CPU 收益当作已证明。

## 资源证据及解释边界

已经完成的 60 分钟单线程窗口继续保留，没有因后来的两处修复重跑整小时。它使用较早的 `e5e26fe1…` ELF：C/Rust 各 3,600 样本、实际各 3,600 秒，负载计数完全一致，线程均为 1，FD 为 17/14，采样子进程为 0，租约 20，退出清理通过。最终 ICMP/interface 修复后的 `532a7b42…` 又完成了实际 300 秒确认。这些身份不能写成当前最终 ELF 的一小时结果。

| 窗口 | C RSS Q3→Q4 中位数 | Rust RSS Q3→Q4 中位数 | 结论范围 |
| --- | ---: | ---: | --- |
| 单线程 60 分钟，e5e26fe1 | 1,596→1,596 KiB | 2,120→2,188 KiB | Rust 仍增长；末值 2,320 对 1,596 KiB，差 724 KiB |
| ICMP/interface 修复后 5 分钟，532a7b42 | 1,496→1,496 KiB | 1,872→1,888 KiB | Q4 差 392 KiB（26.2%）；不是满缓存比较 |

撤回“缓存填充足以解释 Rust RSS 增长”的判断。上述窗口只记录累计插入/释放指标，没有实际 live occupancy，不能据此证明缓存条目数；即使双方条目相同，也需要解释各自的分配策略和每条记录成本。

核实精确 C 的 `cache_init` 后，确认 C 在启动时一次分配 cache-size 个 `crec`。匹配 SDK 下 `sizeof(crec)=136`；4096 条为 557,056 字节，512 个桶指针再占 4,096 字节，总计 **548 KiB**，尚未计 allocator 元数据。短名称最多 74 字节，可放在记录内；长名称另分配 bigname。Rust 也预分配槽位，但名称 Vec、规范化名称键、每名索引 Vec、RDATA Vec 以及 HashMap 仍有后续分配。两者都预分配了一部分，不能简化为“C 预分配而 Rust 没有”。源码、布局实测和限制在 `cache-allocation-source/`。

最终 ENOSPC 在租约盘写满时没有伪造已持久化租约，恢复空间后两边按写回重试完成恢复；EMFILE 时两边保持进程存活并暂不应答，释放 FD 后恢复。两项均试跑后各正式一次：ENOSPC trial/正式实际为 120.874/120.838 秒，EMFILE 为 1.306/1.264 秒。参数 300 是每侧 deadline，并非暴露了五分钟。所有进程退出码为 0，PID 文件由产品自行删除，runner 未代删；宿主扫描没有遗留测试进程。

最终 ELF 的满缓存试跑与正式窗口均完成。试跑双方各 300 样本、实际 300.000 秒、19,200 次查询；正式双方各 600 样本、实际 600.000 秒、38,400 次查询。两边的初末证明都得到 4,096 个正确命中和零上游请求；少填一条的负向对照都只命中 4,095 个，并产生一次上游请求，判据正确拒绝。正式资源如下：

| 正式窗口观测 | C | Rust | Rust − C |
| --- | ---: | ---: | ---: |
| 空缓存 RSS | 1,648 KiB | 1,708 KiB | +60 KiB |
| 填满后 RSS | 1,652 KiB | 2,676 KiB | **+1,024 KiB（+62.0%）** |
| Q3 与 Q4 RSS 中位数 | 1,652→1,652 KiB | 2,676→2,676 KiB | 两侧增长均为 0 |
| 满载 PSS | 1,644 KiB | 2,668 KiB | +1,024 KiB |
| 满载 RssAnon | 644 KiB | 1,676 KiB | +1,032 KiB |
| 满载 RssFile | 1,008 KiB | 1,000 KiB | −8 KiB |
| FD | 11 | 8 | −3 |
| 线程 / 采样子进程 | 1 / 0 | 1 / 0 | 相同 |

空→满的 RSS 增量为 C 4 KiB、Rust 968 KiB；除以 4,096 条，观察到的进程增量均摊约为 1 与 242 字节/条。这不是结构体 sizeof 或 allocator 的逐条账目，但它与匿名页差距共同证明：Rust 在当前短名 A 记录场景的附加内存开销明显更高，不能用“双方都在填缓存”抵销该代价。最终满载 Rust RSS 为 C 的 1.620 倍。

**列入 M6 的优化项**：核查重复名称存储、每名称索引 Vec、短 A RDATA 独立分配及 HashMap 容量；考虑合并名称所有权、紧凑索引和短数据内联。每项先说明机制，在相同满载/换入换出负载上测 RSS/PSS、每请求 CPU 和缓存正确性，不能仅靠 sizeof 推断收益。本轮没有借此开启新的性能筛选。

两侧整个正式采样段均保持平台，没有未解释的继续增长；均正常退出、PID 自行删除，host `/proc` 没有残留 runner/daemon。证据为 `cache-full-opt3-preflight-1791029601/` 与 `cache-full-opt3-formal-1791030027/`，都绑定最终 ELF 与 commit；完整的 status、smaps_rollup、逐秒数据、原始报文、命令和失败判据保留。

工具使用 4096 个同长度短名称，每名一个 A、TTL 3600；填充后关闭上游应答，全部名称必须仍返回正确结果且上游请求为零；另以少填一条的独立进程证明判据确实会拒绝不满缓存。C/Rust 在两个隔离 namespace、不同 CPU 上并行，先实际 300 秒试跑，再实际 600 秒正式窗口，期间不跑其他构建或测试。满载夹具为相同的 DNS-only 配置（cache-size=4096、no-hosts、单个受控上游），未启用 DHCP/UBus/TFTP；其绝对 RSS 不能直接与此前混合配置相减来声称重构收益。该测量范围仅为短名动态 A 记录填满后的稳定命中流，不外推长名、CNAME、负缓存、复杂 RR 或持续换入换出。观测到的平台也不能替代这些场景的泄漏检查。

## 可替换包

最终缓存资源窗口结束后，已用最终 ELF 构建 APK，并完成真实包生命周期验证。包装模式复制已验证 ELF，recipe 仅对该模式关闭二次 RSTRIP，并从 APK 解包再次核对 ELF SHA；不会把重新编译后不同的 ELF 当作原冻结产物。源码、包装输入、SDK 工具和后处理策略都进入冻结清单。

包使用 stock 包名 dnsmasq，release 从 2.93-r1 升为 2.93-r2；init、ujail、UBus ACL、配置声明、UID/GID 和其他 ancillary 文件必须保持镜像合同。生命周期工具启用真实 APK scripts，分别验证升级、同版本重装、卸载、缺账户时全新安装、移除后回滚、直接降级及实际 service/DNS。镜像的 `default_postinst` 调用 init `start`，相同配置下 procd 可保留旧进程。因此升级和直接降级要明确执行 `/etc/init.d/dnsmasq restart` 激活新 ELF；报告将安装事务与该激活动作分开记录，不能声称 APK scripts 自动重启。全新安装则先验证 post-install 的自动启动。不会使用 `--no-scripts` 或 `--force-overwrite`。隔离事务使用 `--no-network --allow-untrusted`，因此此次不是镜像默认信任密钥下的签名分发验收；相关密钥和生产发布不在本阶段结论内。两种 stock 变体和完整依赖已按镜像构建时缓存的 APK index 校验，互斥测试必须由具体包冲突证明，不能拿缺依赖当通过。

最终包为 `dnsmasq-2.93-r2.apk`，**633,984 字节**，SHA-256 为 `1cec0056c6834687197096c013a4cd0a364c7b6b86bc5dad55e5692b13623ae2`。stock APK 为 155,123 字节，因此新包是 **4.087 倍**，多 **478,861 字节（308.7%）**。包内 ELF 解包后仍逐字匹配 FAA SHA，SDK recipe 已恢复。构建记录明确保留 `original_elf_target_met=false`，另记录用户对具体 SHA/字节数的接受，没有把原目标改写为通过。

生命周期最终 attempt7 实际完成约 2.38 秒，退出无残留进程；全过程启用真实脚本，逐步核对包数据库、文件唯一归属、权限/UID/GID、配置保留、UID/GID 453、init 链接、ujail 内实际 ELF 和 DNS 响应：

| 事务 | 结果与激活方式 |
| --- | --- |
| stock 同版本重装控制 | 原版脚本语义实测，记录运行中进程与 init start 行为 |
| stock r1 → Rust r2 升级 | 成功；显式 init restart 激活 FAA ELF |
| Rust r2 同版本重装 | 成功；单独记为 reinstall，显式 restart |
| 卸载 | 包记录和所拥有文件移除，修改过的用户配置保留，服务退出 |
| 无 dnsmasq 账户时全新安装 | 账户按 453:453 重建；post-install 自动启动真实 FAA 服务 |
| 移除后安装 stock 回滚 | 成功；post-install 自动启动镜像 C |
| 再升级后直接降为 stock r1 | 成功；显式 restart 后验证运行镜像 C |
| 与 dnsmasq-dhcpv6/full 共存 | 两种准确 APK 及完整依赖参与 solver 模拟；均因具体包冲突拒绝，数据库不变 |

首次包与失败 attempt1–6 都保留。原始包、冻结输入、逐条命令和生命周期结果集中在 `package-faa-accepted-1791030400/`；最终索引与便于领取的产物见下表。旧 `package-build-1790980930` 与 `lifecycle-1790981042` 使用旧 ELF，且脚本/升级覆盖不足，仅保留历史，不作为最终资格化。

## 交付与证据索引

| 内容 | 本地路径 |
| --- | --- |
| 最终 APK | [dnsmasq-2.93-r2.apk](../../private/dnsmasq-rewrite/evidence/M4/delivery-4b3fc62/dnsmasq-2.93-r2.apk) |
| ELF、源码身份、全部最终验证及失败证据入口 | [M4_INDEX.json](../../private/dnsmasq-rewrite/evidence/M4/delivery-4b3fc62/M4_INDEX.json) |
| 领取目录的文件校验 | [SHA256SUMS](../../private/dnsmasq-rewrite/evidence/M4/delivery-4b3fc62/SHA256SUMS) |
| 包冻结索引，明确列出 ELF 对应的源码 commit | [freeze-final-index.json](../../private/dnsmasq-rewrite/evidence/M4/package-faa-accepted-1791030400/freeze-final-index.json) |
| 包装与生命周期完整结果 | [package summary](../../private/dnsmasq-rewrite/evidence/M4/package-faa-accepted-1791030400/summary.json) |
| 最终资源复核及逐秒原始数据入口 | [resource summary](../../private/dnsmasq-rewrite/evidence/M4/opt3-final-resource-validation/summary.json) |

源码 commit 为 `4b3fc62`，包装输入为 `6ce0221`，生命周期工具为 `7de548a`；三种身份没有混用。包证据的 2,129 个文件及资源/压力证据均已回拷并校验，原始 ELF、配置、报文和 rootfs 留在 ignored/private，不进入 Git。当前本地只有 main 分支，未丢弃旧 worktree 中的证据或未提交内容；用户 `docs/prompts/` 的改动保留。

## 失败记录与未完成范围

所有原始证据统一位于 ignored `private/dnsmasq-rewrite/evidence/M4/`。保留的失败包括：旧 TCP/ICMP 阻塞负向对照，all-servers fixture 错误，symbol companion 首次不匹配，未采用的增大体积试验，配置退出码两次复现及旧 ELF 确认，工具身份归档遗漏、旧 CLI 参数和 import 路径错误。最终 ICMP/TFTP 的前两次只因脚本路径错误而未启动产品，第三次才是有效运行；不能把前两次计为执行了产品场景。首个 APK 的 keep 文件因 recipe 和 SDK 双重生成而多了一行；两次辅助合同检查拒绝后，去掉显式复制重新构建。随后升级事务已成功但旧 C 进程仍在运行，测试器把自动重启当成必要条件而失败；原始记录保留，归因为升级激活期望错误，不是 stock 启动失败。尚未运行或中断的 z 场景不计通过。

M6 的吞吐、p50/p95、每请求 CPU 收益均**未证明**；此次有界延迟回归不是性能评估。当前仍需完成整个变体的 M5 合同，配置错误文字的差异也留在未完成范围；没有把当前配置回归外推为 TFTP/PXE/relay/tags 等全部能力已达标。任何 ELF/APK 或 RSS 退步都按绝对值报告。未经 M7，不能称生产验收。
