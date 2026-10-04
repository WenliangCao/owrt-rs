# dnsmasq-rs 交付账本

## 当前状态与下一步

- 当前里程碑：M5；169 项中 **64 项已关闭、68 项部分实现、37 项未实现，剩余 105 项**。
- 刚关闭：local-service 14配置／180行、独立双栈客户端namespace的本地/非本地准入和CLI/config交互全部通过，24负向控制通过。第二批矩阵累计关闭4项，仅fast-dns-retry待完成。
- 当前代码：产品冻结候选 `f1668e28`，ELF SHA256 `9c73a0d979aa1faa79b542fc08bb34f45a716d8bba2a89153ff61d841ed2ebd5`，1,396,848字节（本次relay接线段+20,480，case修复+0，M4+237,568）。此后main仅测试器/账本变更。Oracle产物在 `/home/ubuntu/m5-root-20261004/f1668e28/`，本地在 `evidence/M5/integration-20261004/f1668e28/`；统一库517通过／18忽略、main10通过。上一候选9da20ac0的helper16场景／32侧、boot102事件、leasequery22配置／38查询复跑通过，f166同版复跑正在进行。
- 下一步：relay同f166候选paired-06完成37配置／174场景（含16报文突发）、40语法、4类binding及15负控，Linux隔离守卫6项实际执行通过；正在落盘43条清单与close-summary，核完立即关闭3项。矩阵仅retry定时/成功取消/错误恢复待完成，DHCP identity下一族已备56条C清单。
- 阻塞点：Oracle ENOSPC已通过删除各自已归档的可重建rootfs/构建缓存缓解，可用约1GiB；另23份已完成副本已清理、/m2末态回拷并校验。f1668e28统一回归正在执行（库517通过／18忽略、main10通过），每次最多两族并行并及时回收可重建副本。无须用户决定。物理路由器未操作。
- 活跃分工：`m5/relay` / `worktrees/m5-relay`（relay_checklist）完成剩余清单后合入清理；`m5/option-matrix-2` / `worktrees/m5-option-matrix-2`（option_matrix）推进retry/local-service，已关闭的3项不要重复扣数；`m5/dhcp-identity` / `worktrees/m5-dhcp-identity` 已冻结56条C清单，等本批relay闭合后开工；batch_verify只跑f166同版回归并回拷证据，主代理统一公共接线。上述worktree均在 `private/dnsmasq-rewrite/` 下。

## 工作规则

续接只从本账本的「当前状态与下一步」、工作规则和选项表恢复，不必重读历史消息。每次汇报同步更新开头状态。

- 汇报固定使用「当前里程碑、刚关闭的项、剩余项数、阻塞点」四项；每完成一个功能族汇报一次，最长间隔 30 分钟。剩余项数以本账本逐项状态为准，未执行的检查不算通过。
- 并行子代理按功能族分工，每族使用独立 worktree 和任务分支。`main.rs`、`dns/daemon.rs` 等公共文件由主代理统一整合；子代理交付所需接口和补丁，不在主工作树并发修改公共文件。最多同时四个子代理。
- 提交按明确路径逐个 `git add -- <path>`，不用 `git add -A`；有意义的进展形成小提交。功能族验证完成后由主代理合入 main，再删除对应任务分支并清理 worktree。删除前保留未合入变更、证据和必要的 durable refs，不丢弃活跃任务或未提交工作。
- 每族镜像 C 对照通过后立即合入 main、更新选项状态并扣数，记录候选 ELF 的 SHA256、源码身份及证据；统一复测放在每批结束，不以等待统一版本为由延迟已通过族的记账。
- 每族开工先从精确 C 调用链列出必须覆盖的边界清单，完成后逐条勾选；审计只核对清单及其证据，发现真实缺陷则重新打开对应项。
- 通用选项矩阵只纳入「部分实现且没有已知代码缺口」的选项，以代表值比较镜像 C/Rust 启动结果、`--test` 输出和代表性行为；有代码缺口的继续按功能族处理。不可仅凭语法通过关闭运行时合同。
- Oracle 上不同功能族使用各自独立 namespace 并行对照；正式资源/性能窗口仍排除其他负载。
- 已实现但未对照的功能族不得继续累积。当前先修 helper、TFTP，再完成 RR filter 与 leasequery daemon 级镜像 C 对照；这批通过后再推进下一批。以后每完成两族就统一接线和镜像 C 对照，体积逐族记录，M5 结束时汇总，不为体积中途暂停。
- M5 新功能必须接入单一 poll owner，不加线程、不阻塞等待。每个功能族维护一个族级镜像 C 差分测试器；先读精确匹配的 C 调用链，再实现。原版缺陷保留最小复现，单独记录行为差异。
- 原始证据统一保存在 `private/dnsmasq-rewrite/evidence/M5/`（即 `evidence/M5/`），不散落在临时 worktree；Git 仅提交代码、工具和脱敏报告。用户 `docs/prompts/` 的修改保持原样。
- M5 结束时，在同一版本执行完整 M2、实际 5 分钟资源试跑、两项压力测试和 APK 生命周期验证；复测 ELF 体积和满载 RSS，与 M4 的 1,159,280 字节、2,676 KiB 比较。M4 体积例外仅属于原 ELF，新增体积不能自行豁免。
- 物理路由器不碰；本阶段只做本地与构建机隔离验证。

日更：2026-10-04。本文件是唯一进度入口；每个里程碑只保留一篇报告，原始失败与产物留在 ignored/private。当前进入 **M5**；M4 按用户接受的方案 A 完成。M5 盘点见下表，M6 未完成，未经 M7 不能称生产验收。

## 当前状态与退出条件

| 里程碑 | 退出条件与状态 |
| --- | --- |
| M1 冲刺复核 | 权限、PID、监听来源、netlink、锁和 ethers 独立审查；问题有修复和回归，高风险有负向对照。已关闭，见 [M1_REVIEW_REPORT.md](M1_REVIEW_REPORT.md)。 |
| M2 使用场景 | 镜像 musl C 对照：20 客户端租约全流程、静态/ethers/重启、reload/UCI/odhcpd、DNS 故障恢复与 TCP/cache；三入口各 30 分钟 fuzz。已关闭，历史身份与失败见 [M2_REPORT.md](M2_REPORT.md)。旧 all-servers 夹具实际启用了 strict-order，该项由 M4 的修正工具和真正 all-servers 对照补齐。 |
| M3 长时与资源 | 混合负载实际 60 分钟，比较计数、资源走势和退出回收；ENOSPC/EMFILE 对照。已按用户修订范围收尾，见 [M3_REPORT.md](M3_REPORT.md)。到期等功能引用 M2，不强塞进 12 小时租期的长跑。旧缓存计数不能作为 live occupancy，M4 已完成双方填满后的实测，见 [M4_REPORT.md](M4_REPORT.md)。 |
| M4 可替换包 | 单线程功能和资源验证；最终源码/ELF 对应；稳定工具链 opt-level 3、static、strip、panic=abort；最终 APK 真实安装、升级、卸载、回滚。原 ELF 目标 1,000,000 字节未达成；用户已明确接受方案 A 的 1,159,280 字节，其他超标不能自行豁免。见 [M4_REPORT.md](M4_REPORT.md)。 |
| M5 完整合同 | 先覆盖 UCI/LuCI 的全部 option、tags、script/hotplug、leasequery、relay，再补 TFTP/BOOTP/PXE 等编译能力；每项 C 差分，原版缺陷单列最小复现。尚未完成。 |
| M6 性能 | 在 M4 产物上按冻结协议测缓存命中/未命中/混合/失败/TCP/DHCP/reload；报告吞吐、错误、延迟、CPU、RSS/FD 和体积，无收益写未证明。尚未启动正式性能窗口。 |
| M7 真机 | 离线 runbook、备份、自动回滚、客户端检查和约三分钟窗口；用户另行明确授权才操作物理路由器。未经 M7 不称生产验收。 |

M4 的单 poll owner 已替换六线程接线，决定见 [ADR_THREAD_MODEL.md](ADR_THREAD_MODEL.md)。非阻塞 TCP 上游和 ICMP 等待期间的 DNS/TFTP 服务、原始 DHCP interface/listen-address 并集已修复。最终产品 commit 为 `4b3fc62cea8b4d3897c3a9bca082964812e82ffc`；release ELF 为 `faa55065…24577`，全部 110 份构建归档输入与 commit 逐字匹配。该 ELF 的 DHCP 四组、DNS 七组、生命周期、TCP 停滞、ICMP/TFTP、真实 fast-retry 以及 ENOSPC/EMFILE 对镜像 C 通过；库 439 项和 main 10 项 Linux musl 单元通过，17 项 ignored 不算通过。

体积先做归因，再按用户要求保持 opt-level 3：关闭可选 unwind tables、共享启动排序和减少重复格式化。ELF 从 1,220,720 降至 1,159,280 字节，是 C 的 269,305 字节的 4.305 倍（多 330.5%），比原目标多 159,280 字节，用户随后明确接受该方案 A。format 的文件大小收益为零，共享读取器试验反而增大 24,576 字节，未采用。1.5 MB 旧预算作废；s/z 结果保留但不作为交付选项，没有引入 nightly 或 build-std。详细步骤和代价见 M4 报告。

资源结论不再以“缓存填充”单独解释 Rust RSS 增长。C 确实在启动时预分配 cache-size 个记录；Rust 也预分配槽位，但另有名称、数据和索引分配。新的满缓存测量已完成：双方各 4,096 个可证明命中的动态 A 记录，实际 300 秒试跑后实际 600 秒正式窗口；窗口期间没有其他构建或测试。正式满载 RSS 为 C 1,652、Rust 2,676 KiB，差 1,024 KiB（62.0%），后半段无增长且清理通过。每条记录附加内存成本明显更高，已列入 M6 优化项。最终 APK 为 633,984 字节（stock 的 4.087 倍）；真实升级、重装、卸载、全新安装、移除后回滚、直接降级及两种变体互斥均通过，包内仍是 FAA ELF。升级/重装/降级明确使用 init restart 激活，原版脚本的 start 不冒称自动重启。M4 已关闭；opt-level s 的 CPU 代价留到 M6 测量后决定。

## 验证与编排规则

参考永远是精确 C，期望不能由 Rust 生成。普通修复用单元加受影响 C 差分；解析器、租约、缓存、权限与资源边界保留独立复核、负向对照和回归。红色结果先复跑确认，未执行不算通过，原始失败保留。任何正式资源窗口先试跑，C/Rust 双 namespace 并行绑不同核；性能窗口不跑其他负载。

最多四个子代理，各自有明确文件所有权。证据按里程碑统一放在 `private/dnsmasq-rewrite/evidence/`；实验分支 48 小时内合入或归档后删除。活跃功能族保留各自任务分支/worktree，完成后按开头规则归档和清理；旧 detached worktree 中有 ignored 证据和未提交内容，未为清理而丢弃。用户在 `docs/prompts/` 的改动保持原样。物理路由器没有操作授权，也没有执行操作。

## M5 盘点与工作顺序

盘点基线是 M4 的 `4b3fc62` / `faa55065…24577`。169 项全部逐项检查：**64 项已实现并有 C 差分，68 项部分实现，37 项未实现；剩余 105 项**。部分实现同时包括已知代码缺口和缺少镜像 C 族级行为验证，不能把元数据或语法通过算作运行时完成。历史源码 C、提取原语 C 和镜像 ELF 的证据身份分别记录；完成项也要参加 M5 最终统一二进制回归。 本轮 DNS 本地记录族在精确镜像上使用 build-02 ELF `ea8a39cd…b1a90` 完成 paired-04：140 条服务语义、25 条解析、0 个未执行和 0 个差异；唯一 reference difference 是 C 对非法 `dns-rr ... gg` 的分配失败缺陷，详见 [paired-04/result.json](../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)。

对镜像 init 的静态调用路径核对得到 **A 组 99 项、B 组 70 项**。A 表示原生 UCI/init 生成或调用，行号链接到保留原文的 init；B 表示通常需额外配置。`extraconftext`/conf-dir 可以透传任意指令，不据此把全部选项都算原生生成。`pxe-service`、`pxe-prompt`、`interface-name` 实际有 init 生成路径，归 A。26 个 excluded-capability 选项不混入169项计数；其与C一致的禁用/拒绝边界仍保留。

工作先后为：A 的 DHCP tags/match/option 编码 → helper/hotplug → boot/PXE → relay/leasequery → TFTP → servers/resolv/hosts 动态更新 → 本地记录 → EDNS/rebind/过滤策略与日志/监听缺口，再完成 B。共享底层和不冲突功能族可并行；B 的相关选项可在同一族测试器保留用例，但不挤占 A 缺口的实现优先级。

每族先读精确 C 调用链，再以非阻塞状态机接入单 poll owner，不加线程，不用循环中的阻塞等待。报文编码、helper、relay、TFTP 保留负向对照和定向 fuzz；普通修复只跑受影响验证。C 的缺陷与有意行为差异单列，不能把已知差异改名或删 guard 后算通过。

M5 退出条件：169项全部实现并有C差分，或已证明与C一致的拒绝/未启用；产品没有 not implemented 拒绝点，零已知功能缺陷；同一版本完成完整M2、实际5分钟资源试跑、两项压力、APK生命周期及满载RSS比较，最后写M5_REPORT。体积/内存相对M4的1,159,280字节/2,676KiB逐项报告；M4的体积特许不能复用到新ELF，新增体积待用户决定。

本批已在源码 `db51616d`、ELF `95a23157d1af2ac7ae9c33c474e876a1dacfb0162840f6d42332fc2c4acac21f` 上统一验证，镜像 C 仍为 `097a9e21…cab87`。helper/RR filter/leasequery 各自分支通过后立即关闭；TFTP30场景的9个无剩余缺口选项也已关闭。`dhcp-boot` 的空tag与超长配置安全边界、`tftp-root` 路径防护、`tftp-single-port` 原版旧数据/FD缺陷已单列结案，不把缺陷改名算作零差异。公开状态从此以开头和逐项表为准。

本批构建使用 Rust1.98.1、SDK GCC14.3.0/musl、opt3/static/strip/panic-abort/no-unwind。实测分支增量：helper完整修复相对1,294,448为+20,480字节；leasequery为+16,384；RR filter修复相对ab5f36a为0。主干构建点依次为ab5f36a=1,323,120、7a1d4b7=1,343,600、5d9da23=1,372,272、db51616d=1,376,368。TFTP接线和后续整合存在链接布局交互，独立族归因仍须补测，不能把这些主干差额冒称全部属于单族。最终满载RSS与APK生命周期尚未执行。

文件归属：tags负责人维护config/dhcp_tags、dhcp_host、dhcp_options及编码逻辑；网络负责人维护boot/relay/leasequery和TFTP；helper负责人维护helper/filewatch和loader；DNS负责人维护dns/*、config/dns和本地记录/策略。主代理独占main.rs、config/dhcp.rs、dhcp/daemon.rs及共用接线，其他人用明确patch/API交接。每族仅一个差分测试器，证据统一在 `private/dnsmasq-rewrite/evidence/M5/`。

| 选项 | 组 / init 行 | 负责人 | 状态 | 证据或具体缺口 |
| --- | --- | --- | --- | --- |
| `dhcp-authoritative` | A / 983 | DHCP tags/options | 部分实现 | [按原始索引](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dhcp-1791029005/actual20-comparison.json)；Env 与 REQUEST 分支已接线，M4 authoritative 正常 DORA/renew/rebind 通过；错误 server-id、未知租约 INIT-REBOOT/broadcast/unicast NAK 分支只有旧状态机/源码 C 证据，需镜像族级补证。 |
| `dhcp-broadcast` | A / 1168 | DHCP tags/options | 部分实现 | [按原始索引](../../private/dnsmasq-rewrite/evidence/M1/regression/gates/dhcp_actual_tags_diff-01/result.json)；普通/tag 谓词写入广播标志且遵循 range tag 尚未加入的时点；依赖缺失完整 tags。空/坏 tag 配置需镜像 C 验证，当前 parser 额外拒绝空 tag。 |
| `dhcp-circuitid` | A / 291 | DHCP tags/options | 部分实现 | 解析和option82子TLV精确匹配已接入config/dhcp_tags及daemon；尚缺独立镜像族级边界证据，本地server option82原样echo仍是待补合同。 |
| `dhcp-fqdn` | A / 1009 | DHCP tags/options | 部分实现 | [按原始索引](../../docs/dnsmasq/DHCP_FQDN_IMPLEMENTATION_VALIDATION.json)；已接线 DNS publication/restore/collision 且曾比对镜像 C 8 事件+5配置；报告明确域名恢复/名称碰撞组合未覆盖，未查到该选项完整镜像矩阵在 M4 最终 ELF 上执行。 |
| `dhcp-host` | A / 416,418 | DHCP tags/options | 部分实现 | 2026-10-04 复核：tags/wildcard/name-only 已有正常路径配对；原盘点要求的 nodhcpv6 IPv6 host 拒绝边界尚缺镜像证据。 |
| `dhcp-hostsfile` | A / 1118 | DHCP tags/options | 部分实现 | [按原始索引](../../docs/dnsmasq/DHCP_HOST_FILES_PHASE.md)；普通选择器文件、目录扩展和 SIGHUP 银行替换已实现；通用 host parser 仍拒绝 tags/wildcards/name-only，reload 会暂停 DHCP；empty/stdin 路径被拒绝尚非与 C 等价。 |
| `dhcp-ignore-names` | A / 1198 | DHCP tags/options | 部分实现 | 2026-10-04 复核：现有镜像用例与 generate-names 联用，缺独立无条件、不匹配、配置或 DNS 权威名称保留分支。 |
| `dhcp-lease-max` | A / 1032 | DHCP tags/options | 部分实现 | [按原始索引](../../docs/dnsmasq/DHCP_CONFIG_PHASE.md)；解析和 LeaseStore 上限已接线；M4 默认租约规模未达到上限，缺镜像 C 的 0/1/满上限/释放回收/重启恢复场景。 |
| `dhcp-mac` | A / 497 | DHCP tags/options | 已实现，有C差分 | [M5 dhcp-tags-options final3](../../private/dnsmasq-rewrite/evidence/M5/four/dhcp-tags/run-final4/summary.json)；dhcp-mac set-tag、MAC wildcard 和匹配边界在精确镜像配对中通过。|
| `dhcp-match` | A / 340 | DHCP tags/options | 部分实现 | 2026-10-04 复核：镜像运行用例缺入站 option 124 / vi-encap enterprise/class-list 匹配，输出 vi-encap 编码不能替代该项。 |
| `dhcp-option` | A / 484,693 | DHCP tags/options | 已实现，有C差分 | [M5 dhcp-tags-options final3](../../private/dnsmasq-rewrite/evidence/M5/four/dhcp-tags/run-final4/summary.json)；完整 named/numeric option 表、地址/域名/封装编码在精确镜像配对中通过。|
| `dhcp-option-force` | A / 484,693 | DHCP tags/options | 已实现，有C差分 | [M5 dhcp-tags-options final3](../../private/dnsmasq-rewrite/evidence/M5/four/dhcp-tags/run-final4/summary.json)；force/PRL 优先级、封装和重复选项在精确镜像配对中通过。|
| `dhcp-range` | A / 614,651,655,659,663 | DHCP tags/options | 部分实现 | [按原始索引](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dhcp-1791029005/actual20-comparison.json)；已实现动态 IPv4、单个 set:、mask/broadcast/租期；缺 tag:/net: filters、旧式裸 tag、static 和 proxy 模式；探测 I/O 错误时已知与 C 行为不同，不能以已有 DORA 覆盖全部范围。 |
| `dhcp-rapid-commit` | A / 1017 | DHCP tags/options | 已实现，有C差分 | [M5 dhcp-tags-options final3](../../private/dnsmasq-rewrite/evidence/M5/four/dhcp-tags/run-final4/summary.json)；rapid-commit 配置和普通/rapid 请求族在精确镜像配对中通过。|
| `dhcp-remoteid` | A / 274 | DHCP tags/options | 部分实现 | 解析和option82子TLV精确匹配已接入config/dhcp_tags及daemon；尚缺独立镜像族级边界证据，与relay-agent tags同族补齐。 |
| `dhcp-sequential-ip` | A / 1014 | DHCP tags/options | 部分实现 | [按原始索引](../../docs/dnsmasq/DHCP_SOURCE_MAP.md)；allocation/state 已接线 sequential，源 C 差分覆盖部分 epoch/conflict 分配；未找到镜像 C 开启该选项的多客户端/DECLINE/wrap/restart 族证据。 |
| `dhcp-subscrid` | A / 258 | DHCP tags/options | 部分实现 | 解析和option82子TLV精确匹配已接入config/dhcp_tags及daemon；尚缺独立镜像族级边界证据，与relay-agent tags同族补齐。 |
| `dhcp-userclass` | A / 307 | DHCP tags/options | 已实现，有C差分 | [M5 dhcp-tags-options final3](../../private/dnsmasq-rewrite/evidence/M5/four/dhcp-tags/run-final4/summary.json)；userclass counted-string 匹配和 tag 选择在精确镜像配对中通过。|
| `dhcp-vendorclass` | A / 324 | DHCP tags/options | 已实现，有C差分 | [M5 dhcp-tags-options final3](../../private/dnsmasq-rewrite/evidence/M5/four/dhcp-tags/run-final4/summary.json)；vendorclass 前缀匹配和 tag 选择在精确镜像配对中通过。|
| `no-dhcp-interface` | A / 541 | DHCP tags/options | 部分实现 | [按原始索引](../../private/dnsmasq-rewrite/evidence/M1/regression/gates/dhcp_actual_tags_diff-01/result.json)；列表和 wildcard admission 已实现；旧源码 C 的 excluded-interface 通过，未找到镜像 ELF 对空项、多模式、wildcard 和实际多接口的完整此选项差分。 |
| `no-ping` | A / 1016 | DHCP tags/options | 已实现，有C差分 | [按原始索引](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/tcp-stall-attempt1/result.json)；关闭 ping 分支已实现，历史 extracted C 验证绕过不写缓存；M4 服务含 no-ping 并与镜像 C 通过，启用探测以 ping-conflict 对照。注意启用探测的 I/O 失败差异另挂 dhcp-range，不能视作关闭开关差异。 |
| `read-ethers` | A / 993 | DHCP tags/options | 已实现，有C差分 | [按原始索引](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dhcp-1791029005/static-ethers-comparison.json)；未发现本选项独立剩余产品缺口。完整语法/合并/重载历史差分是源码 C，M4 镜像 ELF 实测地址/主机名映射与重启；M5 收尾仍须重跑最终统一二进制。 |
| `addn-hosts` | A / 216,1059,1062 | helper/文件更新 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；18 lifecycle comparisons; unchanged init generated conf-file/conf-dir/addn-hosts configuration; SIGHUP/init reload/odhcpd hosts DNS side effects |
| `conf-dir` | A / 1175 | helper/文件更新 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image/summary.json)；23 CLI/include acceptance cases and 57 DNS parser cases; syntax only, does not prove daemon runtime |
| `conf-file` | A / 943,1145,1199,1224,1267 | helper/文件更新 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image/summary.json)；Ordinary CLI/include/default/stdin/inode dedup paths implemented. Second empty CLI -C deliberately differs from C undefined NULL-path behavior; retain a minimal exact-image reproduction and explicit behavior-difference record before full closure. Existing acceptance corpus does not cover this edge. |
| `dhcp-leasefile` | A / 1067 | helper/文件更新 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dhcp-1791029005/static-ethers-comparison.json)；Ordinary file restore/write/retry is implemented with image evidence, but LeaseStore rejects duplicate-address restoration unlike C; explicit documented recovery-policy difference remains. Need source-derived duplicate-address C reproduction and compatible handling. Bare optional --dhcp-leasefile has no argument but apply() currently requires one; empty-string fallback exists. |
| `dhcp-script` | A / 1099 | helper/文件更新 | 已实现，有C差分 | [M5 镜像配对](../../private/dnsmasq-rewrite/evidence/M5/helper/close-build-06/private/run-01/result.json)；16 场景，包括实际 hotplug、INIT-REBOOT extradata、只读 init、退出/信号/缺执行文件、helper death 和 SIGTERM 排空；SHA ab9ae470…97359，最终批次 ELF95a23157…c21f 复跑通过。script-arp 单独保留。 |
| `resolv-file` | A / 1111 | helper/文件更新 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image/summary.json)；Only initial nameserver parsing is wired. Rust merges every resolv file and aborts on missing/empty files; C selects latest changed file, tolerates absent file with existing parent directory, retries empty state and updates servers through inotify. SIGHUP/no-poll path missing. |
| `script-arp` | A / 1018,1100 | helper/文件更新 | 未实现 | 当前无通过证据；Generic unimplemented option rejection; no kernel neighbour/ARP transition producer or helper arp-add/arp-del delivery. Must share C helper and event stream without new thread. |
| `servers-file` | A / 1072 | helper/文件更新 | 未实现 | 当前无通过证据；Typed path exists but both main and DNS daemon reject it. Need restricted server/rev-server file parsing, source-specific replacement, startup/SIGHUP load and file-error behavior. Exact C does not inotify-watch servers-file; do not invent auto-update behavior. |
| `dhcp-boot` | A / 516,1077 | Boot/relay/TFTP | 已实现，有C差分 | [M5 boot102行](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/boot-db51616d-02/result.json)；tag/net 优先级、无tag回退、选中context、PRL/BOOTP/NAK、hosts next-server、字段/容量边界通过。空tag和超过255字节只测语法：保留Rust明确拒绝，C空指针/长度窄化缺陷单列；不执行未定义参考路径，不声称这3例字节相等。 |
| `dhcp-relay` | A / 846,849 | Boot/relay/TFTP | 部分实现 | 9da20ac0 已接入单poll，relay-only无租约文件；首轮18配置／72报文通过，扩展31配置／135报文发现hops早退副作用已修，待新候选复跑并勾完43条清单。 |
| `enable-tftp` | A / 1006 | Boot/relay/TFTP | 已实现，有C差分 | [M5 30 场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；双栈/接口选择、单 poll owner 和 PID/线程回收。 候选95a23157…c21f，所有执行/负向对照/回收检查通过。 |
| `pxe-prompt` | A / 1082 | Boot/relay/TFTP | 未实现 | 当前无通过证据；Only metadata; no parser, prompt vendor suboption generation, or PXE service loop. |
| `pxe-service` | A / 224 | Boot/relay/TFTP | 未实现 | 当前无通过证据；Only metadata; no architecture/service parser, UDP4011 socket, proxy menu/discovery/UEFI service dispatch. |
| `tftp-no-fail` | A / 1007 | Boot/relay/TFTP | 已实现，有C差分 | [M5 30 场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；缺目录允许启动、未启用时 exit3、bind 错误不能被 no-fail 吞掉。 候选95a23157…c21f，所有执行/负向对照/回收检查通过。 |
| `tftp-root` | A / 1076 | Boot/relay/TFTP | 已实现，有C差分 | [M5 30场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；目录/接口/启动错误/权限通过。[已知差异](../../private/dnsmasq-rewrite/evidence/M5/tftp/reference-differences/summary.json)：合成根目录内父组件路径C接受、Rust明确拒绝，保留防护；双方原始包和负向控制已记录。 |
| `tftp-unique-root` | A / 1083 | Boot/relay/TFTP | 已实现，有C差分 | [M5 30 场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；IP/MAC/组合、缺目录回退、Ethernet6 租约优先于邻居、非 Ethernet 回退。 候选95a23157…c21f，所有执行/负向对照/回收检查通过。 |
| `add-mac` | A / 1159 | DNS 记录/策略 | 未实现 | 当前无通过证据；No typed option consumer or EDNS configuration mutation; generic option-is-not-implemented rejection. Need actual client identity, signed-packet rules, existing-option strip/replace, cacheability and ECS response matching. |
| `add-subnet` | A / 1162 | DNS 记录/策略 | 未实现 | 当前无通过证据；No typed option consumer or EDNS configuration mutation; generic option-is-not-implemented rejection. Need actual client identity, signed-packet rules, existing-option strip/replace, cacheability and ECS response matching. |
| `address` | A / 174 | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；Local/domain routing is wired and has exact-source primitive and native daemon coverage; full option matrix against image C missing (wildcards, family priority, empty/null literal, classes, rebind interoperation). |
| `all-servers` | A / 1015 | DNS 记录/策略 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；No identified gap in covered selection/retry behavior; M4 all-servers fixture was corrected to actually enable all-servers. |
| `bogus-nxdomain` | A / 220 | DNS 记录/策略 | 部分实现 | [image-elf](../../docs/dnsmasq/DNS_BOGUS_CACHE_PHASE.md)；Address parsing and live bogus policy/cache branch are present. Native daemon interaction gate exists; image bogus/DO reports refer to historical branches, so they require source-content provenance or rerun before crediting 4b3fc62. |
| `bogus-priv` | A / 1223 | DNS 记录/策略 | 已实现，有C差分 | [M5 通用矩阵 run-04](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/run-04/result.json)；启动、--test 输出及代表运行行为通过，C 源码边界清单逐条通过；候选源码62734d5f，ELF dd0bbaae…0ba9a（1,376,368字节，本批体积增量0）。 |
| `cache-rr` | A / 236 | DNS 记录/策略 | 部分实现 | [image-elf](../../docs/dnsmasq/CACHE_RR_IMPLEMENTATION_VALIDATION.md)；Forward generic insertion is merged (4bf072d ancestor verified), including ANY selector/QTYPE0 behavior. Address-form PTR/reverse cache is absent in current cache engine; private 62894d6/0eaaef8 reports are not current implementation evidence. Full generic DNSSEC/metadata/negative/filter composition also needs family closure. |
| `cache-size` | A / 1028 | DNS 记录/策略 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/cache-full-opt3-formal-1791030027)；Configured slot capacity, disabled cache and full 4096-slot behavior are evidenced; reverse-cache/record-type gaps belong to cache-rr/remaining cache contract and do not imply complete caching parity. |
| `cname` | A / 787 | DNS 记录/策略 | 已实现，有C差分 | [M5 paired-04](../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)；140 条本地记录服务语义与 25 条解析场景通过，含 CNAME 链、冲突、循环和类型边界。 |
| `dns-forward-max` | A / 1029 | DNS 记录/策略 | 部分实现 | [source-native](../../docs/dnsmasq/DNS_START_FAILURE_PHASE.md)；Runtime table limit is wired but zero is explicitly rejected by DnsDaemon rather than qualified against C; per-server-group limit semantics and image capacity/recovery need review. |
| `dns-rr` | A / 831 | DNS 记录/策略 | 部分实现 | 2026-10-04 复核：正常配对和非法 hex 错误差异记录保留；OPENWRT_CONTRACT 中 RDATA 长度接受集差异尚未结案。 |
| `domain` | A / 1036 | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image)；Ordinary suffix and IPv4/IPv6 prefix selectors exist. domain=# resolver search, interface selectors and explicit IPv6 ranges are rejected by validate_ready/domain_for_address. Alias shares implementation but needs explicit paired coverage. |
| `domain-needed` | A / 985 | DNS 记录/策略 | 已实现，有C差分 | [M5 通用矩阵 run-04](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/run-04/result.json)；启动、--test 输出及代表运行行为通过，C 源码边界清单逐条通过；候选源码62734d5f，ELF dd0bbaae…0ba9a（1,376,368字节，本批体积增量0）。 |
| `edns-packet-max` | A / 1031 | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；Local/forward/cache EDNS envelope limits are wired and native daemon boundary-tested. Image ordinary 1232-byte regression exists; full boundary matrix against image and new add/strip policy interactions remain. |
| `expand-hosts` | A / 1004 | DNS 记录/策略 | 已实现，有C差分 | [M5 通用矩阵 run-04](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/run-04/result.json)；启动、--test 输出及代表运行行为通过，C 源码边界清单逐条通过；候选源码62734d5f，ELF dd0bbaae…0ba9a（1,376,368字节，本批体积增量0）。 |
| `filter-A` | A / 1022 | DNS 记录/策略 | 已实现，有C差分 | [M5 镜像配对](../../private/dnsmasq-rewrite/evidence/M5/rr-filter/close-01/result.json)；8 配置／256 daemon 行，覆盖本地豁免、UDP/TCP、动态缓存/CNAME、ANY/DO/TC、NX/NODATA、EDE 和上游副作用；负向校准通过。分支 SHA7db3c2fb…62208，批次95a23157…c21f复跑通过。 |
| `filter-AAAA` | A / 1021 | DNS 记录/策略 | 已实现，有C差分 | [M5 镜像配对](../../private/dnsmasq-rewrite/evidence/M5/rr-filter/close-01/result.json)；8 配置／256 daemon 行，覆盖本地豁免、UDP/TCP、动态缓存/CNAME、ANY/DO/TC、NX/NODATA、EDE 和上游副作用；负向校准通过。分支 SHA7db3c2fb…62208，批次95a23157…c21f复跑通过。 |
| `filter-rr` | A / 232 | DNS 记录/策略 | 已实现，有C差分 | [M5 镜像配对](../../private/dnsmasq-rewrite/evidence/M5/rr-filter/close-01/result.json)；8 配置／256 daemon 行，覆盖本地豁免、UDP/TCP、动态缓存/CNAME、ANY/DO/TC、NX/NODATA、EDE 和上游副作用；负向校准通过。分支 SHA7db3c2fb…62208，批次95a23157…c21f复跑通过。 |
| `filterwin2k` | A / 986 | DNS 记录/策略 | 未实现 | 当前无通过证据；No typed policy consumer: load falls through to generic option-is-not-implemented rejection. Must cover local answers, cache extraction/replay, upstream filtering and ANY/DO exceptions. |
| `host-record` | A / 808 | DNS 记录/策略 | 已实现，有C差分 | [M5 paired-04](../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)；多地址、PTR owner/order、TTL 全宽度和本地查询行为通过。 |
| `interface-name` | A / 228 | DNS 记录/策略 | 未实现 | [source-extracted](../../docs/dnsmasq/INTERFACE_NAME_SOURCE_REVIEW.md)；Metadata only; no parser or dynamic interface-derived record state. Need netlink IPv6 flags, no-address existence, PTR precedence and TCP inherited snapshot semantics. |
| `local` | A / 175,1037 | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；Local/domain routing is wired and has exact-source primitive and native daemon coverage; full option matrix against image C missing (wildcards, family priority, empty/null literal, classes, rebind interoperation). |
| `local-ttl` | A / 1078 | DNS 记录/策略 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；Default local TTL reaches configured records/hosts and exact image queries; option override parsing covered. DHCP-specific TTL contract is separately owned. |
| `localise-queries` | A / 992 | DNS 记录/策略 | 已实现，有C差分 | [M5 补正矩阵](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/run-07-localise/result.json)；3配置／12行，hosts及两条同名host-record子网内外地址，启用/禁用基线和UDP/TCP通过，4条C清单全部关闭；候选14d4e5fa，ELF e78d5f28…750989。 |
| `max-cache-ttl` | A / 1081 | DNS 记录/策略 | 部分实现 | [source-extracted](../../docs/dnsmasq/DNS_SOURCE_MAP.md)；Cache policy is connected (max clamp before min clamp) with primitive frozen-clock differential; exact image daemon option gate and reverse extraction semantics remain. |
| `max-port` | A / 1035 | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image)；Scalar parser exists but nondefault values are rejected by main::validate_runtime_ready. Upstream socket allocator does not consume configured source-port range/pool semantics. |
| `max-ttl` | A / 1079 | DNS 记录/策略 | 部分实现 | [source-extracted](../../docs/dnsmasq/DNS_STALE_METADATA_ORACLE.md)；Scalar and cache policy primitives exist; main rejects nondefault max-ttl. It clips certain live upstream TTLs before cache insertion, not just cached replay TTL. |
| `min-cache-ttl` | A / 1080 | DNS 记录/策略 | 部分实现 | [source-extracted](../../docs/dnsmasq/DNS_SOURCE_MAP.md)；Cache policy is connected (max clamp before min clamp) with primitive frozen-clock differential; exact image daemon option gate and reverse extraction semantics remain. |
| `min-port` | A / 1034 | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image)；Scalar parser exists but nondefault values are rejected by main::validate_runtime_ready. Upstream socket allocator does not consume configured source-port range/pool semantics. |
| `mx-host` | A / 774 | DNS 记录/策略 | 已实现，有C差分 | [M5 paired-04](../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)；主机名 finalize、MX 默认值、Additional 地址、排序和溢出边界通过。 |
| `no-hosts` | A / 987 | DNS 记录/策略 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；No identified implementation gap for suppressing /etc/hosts while retaining configured/additional hosts; option matrix should retain this distinction. |
| `no-negcache` | A / 988 | DNS 记录/策略 | 部分实现 | [image-elf](../../docs/dnsmasq/DNS_BOGUS_CACHE_PHASE.md)；Runtime cache extraction boolean is connected. Historical image bogus/no-negcache differential is not a verified same-source gate; reverse PTR negative cache behavior is absent from current cache engine. |
| `no-resolv` | A / 991 | DNS 记录/策略 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；No identified gap for disabling resolver file inputs while retaining explicit upstream servers. |
| `port` | A / 1030 | DNS 记录/策略 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；配置端口有最终镜像 C 对照（包夹具使用1053）；port=0历史语义证据另保留，不冒称包用了53。 |
| `proxy-dnssec` | A / 1010 | DNS 记录/策略 | 部分实现 | [image-elf](../../docs/dnsmasq/DNS_DO_CACHE_PHASE.md)；AD preservation policy is wired in UDP/TCP and cache admission. Historical image DO/AD gate exists but its nonancestor source needs content provenance/replay; generic/reverse metadata scope not fully closed. |
| `query-port` | A / 1033 | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image)；Scalar parser exists but nondefault values are rejected by main::validate_runtime_ready. Upstream socket allocator does not consume configured source-port range/pool semantics. |
| `rebind-domain-ok` | A / 1137 | DNS 记录/策略 | 已实现，有C差分 | [M5 通用矩阵 run-04](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/run-04/result.json)；启动、--test 输出及代表运行行为通过，C 源码边界清单逐条通过；候选源码62734d5f，ELF dd0bbaae…0ba9a（1,376,368字节，本批体积增量0）。 |
| `rebind-localhost-ok` | A / 1132 | DNS 记录/策略 | 已实现，有C差分 | [M5 通用矩阵 run-04](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/run-04/result.json)；启动、--test 输出及代表运行行为通过，C 源码边界清单逐条通过；候选源码62734d5f，ELF dd0bbaae…0ba9a（1,376,368字节，本批体积增量0）。 |
| `rev-server` | A / 169 | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；Numeric unbound upstreams and routing are connected. Hostname endpoints, IPv6 scope, explicit source address/interface/port bindings are rejected by validate_ready/validate_endpoint. rev-server inherits endpoint restrictions. |
| `server` | A / 165 | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；Numeric unbound upstreams and routing are connected. Hostname endpoints, IPv6 scope, explicit source address/interface/port bindings are rejected by validate_ready/validate_endpoint. rev-server inherits endpoint restrictions. |
| `srv-host` | A / 757 | DNS 记录/策略 | 已实现，有C差分 | [M5 paired-04](../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)；SRV root/default、轮转、Additional、无 round-robin 和截断边界通过。 |
| `stop-dns-rebind` | A / 1126 | DNS 记录/策略 | 已实现，有C差分 | [M5 通用矩阵 run-04](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/run-04/result.json)；启动、--test 输出及代表运行行为通过，C 源码边界清单逐条通过；候选源码62734d5f，ELF dd0bbaae…0ba9a（1,376,368字节，本批体积增量0）。 |
| `strict-order` | A / 989 | DNS 记录/策略 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；No identified gap in covered selection/retry behavior; M4 all-servers fixture was corrected to actually enable all-servers. |
| `strip-mac` | A / 1161 | DNS 记录/策略 | 未实现 | 当前无通过证据；No typed option consumer or EDNS configuration mutation; generic option-is-not-implemented rejection. Need actual client identity, signed-packet rules, existing-option strip/replace, cacheability and ECS response matching. |
| `strip-subnet` | A / 1163 | DNS 记录/策略 | 未实现 | 当前无通过证据；No typed option consumer or EDNS configuration mutation; generic option-is-not-implemented rejection. Need actual client identity, signed-packet rules, existing-option strip/replace, cacheability and ECS response matching. |
| `bind-dynamic` | A / 1008 | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；实际配置可启动；动态接口增删、TFTP 与 relay 共享监听仍需闭合。 |
| `enable-ubus` | A / 1002 | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；注册、metrics 与事件已有差分；需补镜像 C 的 subscriber、断连恢复及全部方法族对照。 |
| `except-interface` | A / 193 | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；DNS 过滤已实现；TFTP 监听无入口接口选择，全部服务的排除规则未闭合。 |
| `group` | A / 1179 | 启动/日志/监听 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；已实现组选择、清 supplementary groups；M1 权限差分及 M4 镜像账户/服务验证。 |
| `interface` | A / 184 | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；DNS/DHCP 并集和准入有 M4 镜像证据；TFTP/relay 组合接线未完成。 |
| `keep-in-foreground` | A / 1267 | 启动/日志/监听 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；前台服务与正常信号退出有 M4 镜像全场景差分；未将无此选项的 daemonize 算通过。 |
| `listen-address` | A / 188 | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；原始并集和 UDP/TCP 已验证；需完整 IPv6/scope/动态地址的镜像族级覆盖。 |
| `local-service` | A / 1011 | 启动/日志/监听 | 已实现，有C差分 | [M5 准入矩阵](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/batch2/local-service-02/result.json)；14配置／180行，独立client namespace的IPv4 /31和IPv6 /127本地/相邻非本地源、net/host及显式ACL覆盖、CLI/config和非法参数边界通过，24负控及网络清理通过。候选f1668e28，ELF9c73a0d9…d2ebd5（1,396,848字节），无准入实现改动。 |
| `log-dhcp` | A / 1012 | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；仅参与 DHCP UBus 事件抑制；未实现对应 DHCP 详细日志。 |
| `log-facility` | A / 1026 | 启动/日志/监听 | 未实现 | [source-native](../../docs/dnsmasq/M1_REVIEW_REPORT.md)；元数据列为可用，但无配置消费者；主入口通用 not implemented 拒绝。 |
| `log-queries` | A / 990 | 启动/日志/监听 | 未实现 | [source-native](../../docs/dnsmasq/M1_REVIEW_REPORT.md)；元数据列为可用，但无配置消费者；主入口通用 not implemented 拒绝。 |
| `no-daemon` | A / 984 | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；debug 身份/SIGINT 已实现；缺 C stderr 日志行为，且默认无 -k/-d 的 daemonize 未实现。 |
| `pid-file` | A / 1267 | 启动/日志/监听 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；写入、失败保留和正常删除有差分；M4 镜像生命周期及压力退出均自行删 PID。 |
| `quiet-dhcp` | A / 1013 | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；部分计数/UBus 抑制已实现；尚无完整日志输出实现与差分。 |
| `user` | A / 1178 | 启动/日志/监听 | 已实现，有C差分 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；已消费 UID、组和能力边界；M1 精确源码 C 权限差分，M4 镜像 UID 453 服务验证。 |
| `version` | A / 31,946 | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；仅 Compile time options 与镜像逐字一致；版本首行和后续 banner 不同。 |
| `dhcp-alternate-port` | B / — | DHCP tags/options | 部分实现 | IPv4解析及server/client端口已接入listener与local/relay发送；扩展镜像测试中，全部端口/启动边界通过后关闭。 |
| `dhcp-client-update` | B / — | DHCP tags/options | 已实现，有C差分 | [M5 dhcp-tags-options final3](../../private/dnsmasq-rewrite/evidence/M5/four/dhcp-tags/run-final4/summary.json)；client-update FQDN flags 在精确镜像配对中通过。|
| `dhcp-generate-names` | B / — | DHCP tags/options | 部分实现 | 2026-10-04 复核：无硬件地址时 client-id 回退未按 C 检查长度及剥除硬件类型；现有镜像用例仅覆盖 Ethernet，待补证。 |
| `dhcp-hostsdir` | B / — | DHCP tags/options | 未实现 | 当前无通过证据；配置显式拒绝；无 inotify 动态文件 append/update 接口，不可拿 SIGHUP hostsfile replacement 代替。 |
| `dhcp-ignore` | B / — | DHCP tags/options | 已实现，有C差分 | [M5 dhcp-tags-options final3](../../private/dnsmasq-rewrite/evidence/M5/four/dhcp-tags/run-final4/summary.json)；全局 tag predicate ignore 在精确镜像配对中通过。|
| `dhcp-ignore-clid` | B / — | DHCP tags/options | 部分实现 | [按原始索引](../../docs/dnsmasq/DHCP_STATIC_PHASE.md)；全局 ignore_client_id 已接线到 packet identity；普通 source C 静态/ID 证据存在，但需镜像 C 对同 MAC 变化 CLID、同 CLID 不同 MAC、恢复 leasefile 的专门族差分。 |
| `dhcp-name-match` | B / — | DHCP tags/options | 部分实现 | 2026-10-04 复核：prefix 已有镜像运行证据；精确全名/域名边界及 name-match 到 tag-if 组合未覆盖。 |
| `dhcp-optsdir` | B / — | DHCP tags/options | 未实现 | 当前无通过证据；配置显式拒绝；无 inotify 动态文件 append/update 接口，不可拿 SIGHUP hostsfile replacement 代替。 |
| `dhcp-optsfile` | B / — | DHCP tags/options | 未实现 | 当前无通过证据；配置显式拒绝；没有 option bank reload，需先完整 option grammar 再复用 host file scanner/expand ordering。 |
| `dhcp-reply-delay` | B / — | DHCP tags/options | 未实现 | 当前无通过证据；配置显式拒绝；无 tag-specific delay storage 和 pending DHCP deadline。应接单 owner 状态机，等待期间处理 DNS/TFTP，禁止 sleep。 |
| `dhcp-ttl` | B / — | DHCP tags/options | 部分实现 | [按原始索引](../../docs/dnsmasq/LEASE_NAMES_PHASE.md)；scalar 与 LeasePolicy 已接线；native C 覆盖自定义值、有限/无限租约、expiry narrowing，M4 DNS TTL 只校验范围后归一化，不能视为该选项镜像精确 TTL 差分。 |
| `no-dhcpv4-interface` | B / — | DHCP tags/options | 未实现 | 当前无通过证据；OptionSpec 可用但 DhcpConfig::apply 没有分支，最终被 main 通用拒绝；本变体可复用 IPv4 exclusion，仍需 C 对照。 |
| `tag-if` | B / — | DHCP tags/options | 未实现 | 当前无通过证据；无有序 tag-if 规则或第二轮 context tag 扩展；main 通用拒绝。 |
| `conf-script` | B / — | helper/文件更新 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image/summary.json)；Shell/stdout loader, parse failures, child wait and raw exit mapping implemented. Only acceptance compared; successful emitted configuration effects, nonzero/signalled status, slow output and descendant cleanup need image-C family differential. Parse-error cleanup kills/waits only direct shell; grandchildren/complex pipelines remain unverified. Startup execution predates service poll, but must not add blocking execution to live owner. |
| `dhcp-lease` | B / — | helper/文件更新 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dhcp-1791029005/static-ethers-comparison.json)；Ordinary file restore/write/retry is implemented with image evidence, but LeaseStore rejects duplicate-address restoration unlike C; explicit documented recovery-policy difference remains. Need source-derived duplicate-address C reproduction and compatible handling. Alias shares implementation/canonical occurrence ID, but final image tests use dhcp-leasefile spelling, not alias-specific invocation. |
| `dhcp-scriptuser` | B / — | helper/文件更新 | 已实现，有C差分 | [M5 镜像配对](../../private/dnsmasq-rewrite/evidence/M5/helper/close-build-06/private/run-01/result.json)；普通和 debug 用户凭据、继承 FD、未知用户失败通过；同 helper 候选及批次 ELF。 |
| `hostsdir` | B / — | helper/文件更新 | 未实现 | 当前无通过证据；Config accepts and stores directories, but production read_hosts never consumes hosts_dirs and no inotify runtime exists: silently ignored. Need initial loading, file-source IDs, close-write/moved-to/delete incremental replacement and DHCP name re-evaluation. |
| `leasefile-ro` | B / — | helper/文件更新 | 已实现，有C差分 | [M5 镜像配对](../../private/dnsmasq-rewrite/evidence/M5/helper/close-build-06/private/run-01/result.json)；无脚本不读文件；脚本 init 非阻塞且有界恢复、慢 init 期间 DNS、exit7→17、容量失败5通过；启动失败清理已补实际进程检查并重跑。 |
| `no-poll` | B / — | helper/文件更新 | 未实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image/summary.json)；Typed flag exists, but production startup rejects no_poll. Need initial single resolv load, no automatic reload, and SIGHUP reload; not a C disabled-feature rejection. |
| `script-on-renewal` | B / — | helper/文件更新 | 已实现，有C差分 | [M5 镜像配对](../../private/dnsmasq-rewrite/evidence/M5/helper/close-build-06/private/run-01/result.json)；默认抑制普通续租、启用后 old 事件、改名/INIT-REBOOT/SIGHUP/释放顺序和慢脚本队列通过。 |
| `bootp-dynamic` | B / — | Boot/relay/TFTP | 部分实现 | [source-native](../../private/dnsmasq-rewrite/boot-config-20261001/bootp-regression-01/result.json)；Global no-argument dynamic allocation is integrated. Every argument, including C tag predicates, is rejected. Need tag-aware permission and image C replay. |
| `bridge-interface` | B / — | Boot/relay/TFTP | 未实现 | 当前无通过证据；Only option metadata exists; no parser or bridge-alias ingress remapping. Main rejects via generic not implemented. |
| `dhcp-no-override` | B / — | Boot/relay/TFTP | 部分实现 | [source-native](../../private/dnsmasq-rewrite/boot-config-20261001/boot-options-boot-regression-01/result.json)；Ordinary DHCP/BOOTP boot option/overload behavior implemented with 54 native comparisons. Exact image C and PXE paths are not qualified. |
| `dhcp-option-pxe` | B / — | Boot/relay/TFTP | 部分实现 | DhcpOption::parse_mode已消费PXE位；PXE listener及选择/应答尚未接线，仍有运行时代码缺口，随PXE族实现。 |
| `dhcp-proxy` | B / — | Boot/relay/TFTP | 未实现 | 当前无通过证据；Only metadata; no relay server-id override policy list, config parser or runtime. Must distinguish this option from proxy-mode dhcp-range/PXE. |
| `dhcp-pxe-vendor` | B / — | Boot/relay/TFTP | 未实现 | 当前无通过证据；Packet prefix helper exists but option parser/daemon configuration and PXE runtime do not; generic refusal. |
| `dhcp-split-relay` | B / — | Boot/relay/TFTP | 部分实现 | relay配置、上游option82插入与下游strip已实现，含C多split长度行为；首轮通过，待全族43条清单完成后关闭。 |
| `leasequery` | B / — | Boot/relay/TFTP | 已实现，有C差分 | [M5 镜像配对](../../private/dnsmasq-rewrite/evidence/M5/leasequery/close-20261004/negative-controls-final/summary.json)；22 配置／38 查询，完整报文除计时归一化相同；ACL/source-port/giaddr、已恢复 ACTIVE、防伪状态检查、PRL/overload、stored tags、到期及18负向控制通过。分支 SHA ffedcd27…3e946，批次95a23157…c21f复跑通过。 |
| `shared-network` | B / — | Boot/relay/TFTP | 未实现 | 当前无通过证据；Only option metadata exists; context completion explicitly excludes shared network. Main rejects. |
| `tftp-lowercase` | B / — | Boot/relay/TFTP | 已实现，有C差分 | [M5 30 场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；路径大小写转换和普通服务应答。 候选95a23157…c21f，所有执行/负向对照/回收检查通过。 |
| `tftp-max` | B / — | Boot/relay/TFTP | 已实现，有C差分 | [M5 30 场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；dedicated/single 的 0/1 门限、双栈共享容量、回收重用、nofile40 和 helper completion 队列容量。 候选95a23157…c21f，所有执行/负向对照/回收检查通过。 |
| `tftp-mtu` | B / — | Boot/relay/TFTP | 已实现，有C差分 | [M5 30 场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；接口与配置 MTU 最小值、IPv4/IPv6 头长度差异。 候选95a23157…c21f，所有执行/负向对照/回收检查通过。 |
| `tftp-no-blocksize` | B / — | Boot/relay/TFTP | 已实现，有C差分 | [M5 30 场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；忽略 blocksize 并保持其他协商字段。 候选95a23157…c21f，所有执行/负向对照/回收检查通过。 |
| `tftp-port-range` | B / — | Boot/relay/TFTP | 已实现，有C差分 | [M5 30 场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；双栈端口范围及容量回收，历史耗尽/零起点源码边界证据保留。 候选95a23157…c21f，所有执行/负向对照/回收检查通过。 |
| `tftp-secure` | B / — | Boot/relay/TFTP | 已实现，有C差分 | [M5 30 场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；正确 UID 允许、root-owned 文件拒绝及普通 mode 权限。 候选95a23157…c21f，所有执行/负向对照/回收检查通过。 |
| `tftp-single-port` | B / — | Boot/relay/TFTP | 已实现，有C差分 | [M5 30场景](../../private/dnsmasq-rewrite/evidence/M5/integration-20261004/db51616d/runs/tftp-db51616d-01/result.json)；双栈/容量/回调/超时通过。[原版缺陷](../../private/dnsmasq-rewrite/evidence/M5/tftp/reference-differences/summary.json)：两次普通RRQ的C旧DATA及残留1FD与Rust新DATA/零残留逐字分类；未初始化的bound IPv4源地址路径按源码排除，不复制未定义行为。 |
| `add-cpe-id` | B / — | DNS 记录/策略 | 未实现 | 当前无通过证据；No typed option consumer or EDNS configuration mutation; generic option-is-not-implemented rejection. Need actual client identity, signed-packet rules, existing-option strip/replace, cacheability and ECS response matching. |
| `alias` | B / — | DNS 记录/策略 | 已实现，有C差分 | [M5 通用矩阵 run-04](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/run-04/result.json)；启动、--test 输出及代表运行行为通过，C 源码边界清单逐条通过；候选源码62734d5f，ELF dd0bbaae…0ba9a（1,376,368字节，本批体积增量0）。 |
| `caa-record` | B / — | DNS 记录/策略 | 部分实现 | 2026-10-04 复核：正常配对保留；OPENWRT_CONTRACT 中 CAA tag 接受集差异尚未结案，不算完整关闭。 |
| `clear-on-reload` | B / — | DNS 记录/策略 | 未实现 | 当前无通过证据；No consumer outside option metadata; generic not-implemented rejection. C triggers cache clear when resolv.conf-driven servers change; ordinary SIGHUP always-clear evidence is not this option. |
| `dns-loop-detect` | B / — | DNS 记录/策略 | 未实现 | 当前无通过证据；Advertised compile capability but no startup probe scheduler or loop-detection policy; generic rejection. |
| `do-0x20-encode` | B / — | DNS 记录/策略 | 已实现，有C差分 | [M5 大小写矩阵](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/batch2/casing-03/result.json)；8配置／420行，启停/双flag顺序、首32字母随机化、错误case认证、合并客户端超过32/64字母及TCP通过；关闭编码时保留上游case变化，20负控通过。候选f1668e28，ELF9c73a0d9…d2ebd5（1,396,848字节，case修复增量0）。 |
| `domain-suffix` | B / — | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image)；Ordinary suffix and IPv4/IPv6 prefix selectors exist. domain=# resolver search, interface selectors and explicit IPv6 ranges are rejected by validate_ready/domain_for_address. Alias shares implementation but needs explicit paired coverage. |
| `dynamic-host` | B / — | DNS 记录/策略 | 未实现 | [source-extracted](../../docs/dnsmasq/INTERFACE_NAME_SOURCE_REVIEW.md)；Metadata only; no parser or dynamic interface-derived record state. Need netlink IPv6 flags, no-address existence, PTR precedence and TCP inherited snapshot semantics. |
| `fast-dns-retry` | B / — | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final)；Nonblocking retry state is connected, source-native retry failure/order gate exists, including M4 sorting-change replay. Exact image option-specific retry schedule/failure family gate not indexed. |
| `ignore-address` | B / — | DNS 记录/策略 | 已实现，有C差分 | [M5 通用矩阵 run-05](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/run-05/result.json)；10配置／34运行行，启动、--test、IPv4/IPv6地址边界和处理顺序通过。IPv4 /0与空前缀安全实现精确镜像的/32行为，IPv6 /0仍匹配全部；候选14d4e5fa，ELF e78d5f28…750989，1,376,368字节（增量0）。 |
| `localmx` | B / — | DNS 记录/策略 | 已实现，有C差分 | [M5 paired-04](../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)；默认 MX、hostname finalize 和 localmx 交互通过。 |
| `max-tcp-connections` | B / — | DNS 记录/策略 | 已实现，有C差分 | [M5 容量矩阵](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/batch2/capacity-02/result.json)；1/2/0/非法4配置，跨双地址全局容量、满载排队、释放恢复两轮及UDP持续服务通过，5条C边界清单／20负向控制；候选1e4eeb27，ELF892501c6…e07e75（1,392,752字节），无产品容量实现改动。 |
| `mx-target` | B / — | DNS 记录/策略 | 已实现，有C差分 | [M5 paired-04](../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)；显式 target、默认 target 和 Additional 行为通过。 |
| `naptr-record` | B / — | DNS 记录/策略 | 部分实现 | 2026-10-04 复核：超过 255 字节的字符字段目前丢弃整条记录，C 会截断字段；paired-04 未覆盖，待修复并重跑。 |
| `neg-ttl` | B / — | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-dns/summary.json)；No-SOA fallback is connected and historically C-compared for forward records; reverse negative extraction absent and image option-specific TTL/fallback family gate needed. |
| `no-0x20-encode` | B / — | DNS 记录/策略 | 已实现，有C差分 | [M5 大小写矩阵](../../private/dnsmasq-rewrite/evidence/M5/option-matrix/batch2/casing-03/result.json)；8配置／420行，启停/双flag顺序、首32字母随机化、错误case认证、合并客户端超过32/64字母及TCP通过；关闭编码时保留上游case变化，20负控通过。候选f1668e28，ELF9c73a0d9…d2ebd5（1,396,848字节，case修复增量0）。 |
| `no-round-robin` | B / — | DNS 记录/策略 | 部分实现 | [source-native](../../private/dnsmasq-rewrite/cache-answer-20260930/selection-common-04/summary.json)；Forward/hosts rotation flag is wired; native cache/host ordering differential exists. Reverse-cache paths and exact-image multi-record option matrix remain incomplete. |
| `port-limit` | B / — | DNS 记录/策略 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final/config-image)；Scalar parser exists but nondefault values are rejected by main::validate_runtime_ready. Upstream socket allocator does not consume configured source-port range/pool semantics. |
| `ptr-record` | B / — | DNS 记录/策略 | 已实现，有C差分 | [M5 paired-04](../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)；显式和省略 target、PTR owner/order 与本地查询通过。 |
| `selfmx` | B / — | DNS 记录/策略 | 已实现，有C差分 | [M5 paired-04](../../private/dnsmasq-rewrite/evidence/M5/local-records/paired-04/result.json)；self-MX、显式 MX/localmx 交互和 Additional 顺序通过。 |
| `synth-domain` | B / — | DNS 记录/策略 | 未实现 | 当前无通过证据；No typed configuration or forward/reverse synthesized-name consumer; generic rejection. |
| `txt-record` | B / — | DNS 记录/策略 | 部分实现 | 2026-10-04 复核：正常分段/截断配对保留；OPENWRT_CONTRACT 中 RDATA 长度接受集差异尚未结案。 |
| `umbrella` | B / — | DNS 记录/策略 | 未实现 | 当前无通过证据；No typed option consumer or EDNS configuration mutation; generic option-is-not-implemented rejection. Need actual client identity, signed-packet rules, existing-option strip/replace, cacheability and ECS response matching. |
| `use-stale-cache` | B / — | DNS 记录/策略 | 部分实现 | [source-native](../../private/dnsmasq-rewrite/stale-refresh-20261001/implementation/gate-03/result.json)；UDP stale answer/background refresh implemented for forward records. Native service gate exists; private TCP stale reference is not a merged pass and current TCP/RD/DO/reverse stale semantics need whole-family qualification. |
| `bind-interfaces` | B / — | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；静态绑定及不存在接口处理已实现；完整 IPv4/IPv6/别名和失败组合缺镜像族级证据。 |
| `dumpfile` | B / — | 启动/日志/监听 | 未实现 | [source-native](../../docs/dnsmasq/M1_REVIEW_REPORT.md)；元数据列为可用，但无配置消费者；主入口通用 not implemented 拒绝。 |
| `dumpmask` | B / — | 启动/日志/监听 | 未实现 | [source-native](../../docs/dnsmasq/M1_REVIEW_REPORT.md)；元数据列为可用，但无配置消费者；主入口通用 not implemented 拒绝。 |
| `help` | B / — | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；只有简短提示；缺完整 help 与 help dhcp 选项说明。 |
| `log-async` | B / — | 启动/日志/监听 | 未实现 | [source-native](../../docs/dnsmasq/M1_REVIEW_REPORT.md)；元数据列为可用，但无配置消费者；主入口通用 not implemented 拒绝。 |
| `log-debug` | B / — | 启动/日志/监听 | 未实现 | [source-native](../../docs/dnsmasq/M1_REVIEW_REPORT.md)；元数据列为可用，但无配置消费者；主入口通用 not implemented 拒绝。 |
| `log-malloc` | B / — | 启动/日志/监听 | 未实现 | [source-native](../../docs/dnsmasq/M1_REVIEW_REPORT.md)；元数据列为可用，但无配置消费者；主入口通用 not implemented 拒绝。 |
| `no-ident` | B / — | 启动/日志/监听 | 未实现 | [source-native](../../docs/dnsmasq/M1_REVIEW_REPORT.md)；元数据列为可用，但无配置消费者；主入口通用 not implemented 拒绝。 |
| `quiet-tftp` | B / — | 启动/日志/监听 | 未实现 | [source-native](../../docs/dnsmasq/M1_REVIEW_REPORT.md)；元数据列为可用，但无配置消费者；主入口通用 not implemented 拒绝。 |
| `test` | B / — | 启动/日志/监听 | 部分实现 | [image-elf](../../private/dnsmasq-rewrite/evidence/M4/size-opt3-final-service/summary.json)；语法判定、加载错误退出码已有镜像差分；成功时缺 C syntax-check 提示，全部选项还未接收。 |

### not implemented 拒绝点（基线逐处列出）

下面保留全部字面位置；test-only 原型护栏与产品启动拒绝分开，版本说明不是拒绝点。主入口通用拒绝覆盖未被任何配置消费者处理的选项；解析但未使用的字段另见上表，不能靠只搜字面字符串判断已实现。

| 文件与行 | 范围 | 内容 |
| --- | --- | --- |
| [components/dnsmasq/src/config/dhcp.rs:73](../../components/dnsmasq/src/config/dhcp.rs#L73) | 产品拒绝 | `return Err(Error("DHCP boot tag selectors are not implemented"));` |
| [components/dnsmasq/src/config/dhcp.rs:235](../../components/dnsmasq/src/config/dhcp.rs#L235) | 产品拒绝 | `return Err(Error("BOOTP dynamic tag selectors are not implemented"));` |
| [components/dnsmasq/src/config/dhcp_host.rs:7](../../components/dnsmasq/src/config/dhcp_host.rs#L7) | 拒绝常量（调用在50/138/177行） | `const WILDCARD: Error = Error("DHCP host wildcard selectors are not implemented");` |
| [components/dnsmasq/src/config/dhcp_host.rs:8](../../components/dnsmasq/src/config/dhcp_host.rs#L8) | 拒绝常量（调用在50/138/177行） | `const TAGS: Error = Error("DHCP host tag selectors are not implemented");` |
| [components/dnsmasq/src/config/dhcp_host.rs:9](../../components/dnsmasq/src/config/dhcp_host.rs#L9) | 拒绝常量（调用在50/138/177行） | `const NAME_ONLY: Error = Error("DHCP host name-only selectors are not implemented");` |
| [components/dnsmasq/src/config/dhcp_options.rs:42](../../components/dnsmasq/src/config/dhcp_options.rs#L42) | 产品拒绝 | `.map_err(\|_\| Error("DHCP option code is not implemented"))?` |
| [components/dnsmasq/src/config/dhcp_options.rs:46](../../components/dnsmasq/src/config/dhcp_options.rs#L46) | 产品拒绝 | `"DHCP option name, tag or encapsulation is not implemented",` |
| [components/dnsmasq/src/config/dhcp_options.rs:51](../../components/dnsmasq/src/config/dhcp_options.rs#L51) | 产品拒绝 | `return Err(Error("DHCP option code is not implemented"));` |
| [components/dnsmasq/src/config/dhcp_tags.rs:67](../../components/dnsmasq/src/config/dhcp_tags.rs#L67) | 产品拒绝 | `return Err(Error("DHCP hostname prefix matching is not implemented"));` |
| [components/dnsmasq/src/config/dns.rs:799](../../components/dnsmasq/src/config/dns.rs#L799) | 产品拒绝 | `return Err(Error("interface domain resolution not implemented"))` |
| [components/dnsmasq/src/config/dns.rs:822](../../components/dnsmasq/src/config/dns.rs#L822) | 产品拒绝 | `return Err(Error("upstream hostname resolution not implemented"));` |
| [components/dnsmasq/src/config/dns.rs:825](../../components/dnsmasq/src/config/dns.rs#L825) | 产品拒绝 | `return Err(Error("upstream scope validation not implemented"));` |
| [components/dnsmasq/src/config/dns.rs:830](../../components/dnsmasq/src/config/dns.rs#L830) | 产品拒绝 | `return Err(Error("resolver search-domain loading not implemented"));` |
| [components/dnsmasq/src/dns/daemon.rs:960](../../components/dnsmasq/src/dns/daemon.rs#L960) | 产品拒绝 | `"servers-file loading is not implemented by the DNS daemon",` |
| [components/dnsmasq/src/dns/daemon.rs:967](../../components/dnsmasq/src/dns/daemon.rs#L967) | 产品拒绝 | `"configured DNS policy is not implemented by the daemon",` |
| [components/dnsmasq/src/main.rs:363](../../components/dnsmasq/src/main.rs#L363) | 产品拒绝 | `Err(Error("option is not implemented by dnsmasq-rs"))` |
| [components/dnsmasq/src/main.rs:377](../../components/dnsmasq/src/main.rs#L377) | 版本说明，非拒绝 | `println!("Not implemented: full DNS cache/reload policy and DHCP relay/PXE/leasequery");` |
| [components/dnsmasq/src/main.rs:1573](../../components/dnsmasq/src/main.rs#L1573) | cfg(test) 原型拒绝 | `return Err(Error("hostsdir is not implemented by the local probe"));` |
| [components/dnsmasq/src/main.rs:1577](../../components/dnsmasq/src/main.rs#L1577) | cfg(test) 原型拒绝 | `"resolver file/domain discovery is not implemented by the local probe",` |
| [components/dnsmasq/src/main.rs:1581](../../components/dnsmasq/src/main.rs#L1581) | cfg(test) 原型拒绝 | `return Err(Error("resolv-file is not implemented by the local probe"));` |
| [components/dnsmasq/src/main.rs:1585](../../components/dnsmasq/src/main.rs#L1585) | cfg(test) 原型拒绝 | `"interface selection is not implemented by the local probe",` |
| [components/dnsmasq/src/main.rs:1590](../../components/dnsmasq/src/main.rs#L1590) | cfg(test) 原型拒绝 | `"interface binding is not implemented by the local probe",` |
| [components/dnsmasq/src/main.rs:1608](../../components/dnsmasq/src/main.rs#L1608) | cfg(test) 原型拒绝 | `"resolver policy is not implemented by the local probe",` |
| [components/dnsmasq/src/main.rs:1613](../../components/dnsmasq/src/main.rs#L1613) | cfg(test) 原型拒绝 | `"hostname-dependent MX/SRV records are not implemented by the local probe",` |
| [components/dnsmasq/src/main.rs:1623](../../components/dnsmasq/src/main.rs#L1623) | cfg(test) 原型拒绝 | `"upstream forwarding is not implemented by the local probe",` |
| [components/dnsmasq/src/main.rs:1645](../../components/dnsmasq/src/main.rs#L1645) | cfg(test) 原型拒绝 | `return Err(Error("scalar option is not implemented by the local probe"));` |
| [components/dnsmasq/src/main.rs:1655](../../components/dnsmasq/src/main.rs#L1655) | 产品拒绝 | `return Err(Error("servers-file loading is not implemented"));` |
| [components/dnsmasq/src/main.rs:1671](../../components/dnsmasq/src/main.rs#L1671) | 产品拒绝 | `return Err(Error("configured DNS policy is not implemented"));` |
| [components/dnsmasq/src/main.rs:1675](../../components/dnsmasq/src/main.rs#L1675) | 产品拒绝 | `"hostname-dependent local records are not implemented",` |
| [components/dnsmasq/src/main.rs:1686](../../components/dnsmasq/src/main.rs#L1686) | 产品拒绝 | `return Err(Error("scalar option is not implemented"));` |

盘点输入、精确C调用链、完整证据身份、静态init映射和计时记录保存在 `evidence/M5/inventory/`。此外已经确认但不含字面 not implemented 的缺口包括：默认daemonize、若干日志开关、resolver错误处理、重复地址租约恢复、ICMP I/O失败边界、TFTP目录启动检查/接口选择及历史TFTP差异。它们没有从剩余项中删掉。

## 北极星起点（历史摘要）

北极星曾用实际 UCI 配置完成单客户端 DORA、租约文件、DNS 查询和 UBus 注册；当时使用旧 debug Rust 与构建机 C，仅作为起点，不替代 M2–M7 验收。原始过程、二进制身份、启动/监听/锁/广播等失败与修复见 [ACTUAL_CONFIG_STAGE.md](ACTUAL_CONFIG_STAGE.md)。反向缓存 `0eaaef8` 和 TCP 流式导入 `dff7a39` 已于 2026-10-01 退休，未合入产品；后续已完成任务分支也已清理，成果由 `evidence/20261001/dnsmasq-*-retired` 与 `evidence/20261002/dnsmasq-*` 持久引用保留，旧原始证据未删除。
