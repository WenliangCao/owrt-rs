# owrt-control-plane-rs

一个以**真实 OpenWrt 镜像、对应上游源码和设备运行行为**为依据的 Rust-native
OpenWrt control plane 项目。

## 项目边界

本项目不重写 OpenWrt，也不从抽象架构开始凭空设计。

继续保留经过长期验证的 Linux kernel、硬件驱动、nftables、hostapd、dnsmasq/odhcpd
以及 OpenWrt 的构建和软件包生态。项目首先识别现有系统的管理职责、接口和依赖，再决定
哪些控制平面组件适合用 Rust 重新实现，哪些应该保持不变或仅做适配。

每项设计必须同时说明三类依据：

1. 目标设备实际安装镜像中的内容；
2. 该镜像对应版本的上游源码；
3. 经脱敏的真实运行态行为。

## 当前状态

这是一个全新的干净项目，没有复制旧仓库的代码、抽象或阶段结论。旧项目只能作为比较
材料；任何内容进入这里前，都必须重新通过镜像和源码证据验证。

当前目标已经固定为 Xiaomi Mi Router AX3000T 的 stock 布局，部署规格是 OpenWrt 25.12.5
`r33051-f5dae5ece4` 的官方 `sysupgrade.bin`。`-ubootmod` profile 和 `.itb` 镜像明确排除。

第一个阶段是 **I0：匹配源码基线与部署验证**。先用固件身份锁定准确的 OpenWrt release、
feeds、设备定义、DTS 和镜像配方；再只读检查实际镜像，验证部署内容并找出定制差异；最后
用必要的脱敏运行态观察裁决动态行为。I0 将形成五类边界：

- 保留；
- Rust 接入或包装；
- 优先用 Rust 重写；
- 延后评估；
- 禁止触碰。

在 I0 完成前，不建立大型抽象、不导入旧实现、不连接或修改物理路由器。

## 开始方式

镜像和运行态材料的准备要求见 [docs/IMAGE_INTAKE.md](docs/IMAGE_INTAKE.md)。原始镜像、
解包目录、分区内容、配置备份和任何可能包含设备秘密的文件都不得提交 Git。

执行计划见 [docs/EXECUTION_PLAN.md](docs/EXECUTION_PLAN.md)。计划形成前完成的方法、环境和
官方源码映射与镜像验证记录在 [docs/L0_DISCOVERY.md](docs/L0_DISCOVERY.md)。L0 使用的公开
镜像只验证分析方法，不代表本项目的目标设备或部署版本。

目标部署身份和匹配源码基线分别见
[IMAGE_IDENTITY.md](reports/ax3000t-stock-openwrt-25.12.5/IMAGE_IDENTITY.md) 与
[SOURCE_BASELINE.md](reports/ax3000t-stock-openwrt-25.12.5/SOURCE_BASELINE.md)。I0.2 已完成；其
设备构建/升级基线和控制面源码检查清单见
[DEVICE_BUILD_RECIPE.md](reports/ax3000t-stock-openwrt-25.12.5/DEVICE_BUILD_RECIPE.md) 与
[SOURCE_EXPECTATIONS.md](reports/ax3000t-stock-openwrt-25.12.5/SOURCE_EXPECTATIONS.md)。

I0.3 的全字节、FIT/DTB、SquashFS、文件属性和偏差验证见
[DEPLOYMENT_VERIFICATION.md](reports/ax3000t-stock-openwrt-25.12.5/DEPLOYMENT_VERIFICATION.md)、
[PARTITION_EXPECTATION.md](reports/ax3000t-stock-openwrt-25.12.5/PARTITION_EXPECTATION.md) 与
[SOURCE_IMAGE_DEVIATIONS.md](reports/ax3000t-stock-openwrt-25.12.5/SOURCE_IMAGE_DEVIATIONS.md)。

I0.4 已完成 159-package SBOM、全文件/ELF/service 归属、权限面和 exact source/patch map：
[SBOM.md](reports/ax3000t-stock-openwrt-25.12.5/SBOM.md)、
[FILE_OWNERSHIP.md](reports/ax3000t-stock-openwrt-25.12.5/FILE_OWNERSHIP.md)、
[PRIVILEGE_SURFACE.md](reports/ax3000t-stock-openwrt-25.12.5/PRIVILEGE_SURFACE.md)、
[SOURCE_MAP.md](reports/ax3000t-stock-openwrt-25.12.5/SOURCE_MAP.md) 与
[PATCH_MAP.md](reports/ax3000t-stock-openwrt-25.12.5/PATCH_MAP.md)。可重复生成器是
[i0_4_inventory.py](tools/i0_4_inventory.py)；固件、解包树和 source checkout 仍只保存在 Git
外的 evidence 目录。

I0.5 已完成启动链、服务图、配置链和 IPC 目录：
[BOOT_CHAIN.md](reports/ax3000t-stock-openwrt-25.12.5/BOOT_CHAIN.md)、
[SERVICE_GRAPH.md](reports/ax3000t-stock-openwrt-25.12.5/SERVICE_GRAPH.md)、
[CONFIG_FLOW.md](reports/ax3000t-stock-openwrt-25.12.5/CONFIG_FLOW.md) 与
[IPC_CATALOG.md](reports/ax3000t-stock-openwrt-25.12.5/IPC_CATALOG.md)。可重复生成器是
[i0_5_controlplane.py](tools/i0_5_controlplane.py)。三条最重要的部署事实：`/etc/init.d/rcS`
不存在于镜像（`sysinit` 由 procd 内建 `rcS()` 处理）；`network`/`system`/`wireless`/
`board.json` 都不随镜像发布、在首次启动生成；ubus 有 ubusd 与 rpcd 两层独立 ACL，
socket 本身是 0666。

I0.6 已完成 17 项控制面职责候选表和运行态问题单：
[RESPONSIBILITY_CANDIDATES.md](reports/ax3000t-stock-openwrt-25.12.5/RESPONSIBILITY_CANDIDATES.md) 与
[RUNTIME_QUESTIONS.md](reports/ax3000t-stock-openwrt-25.12.5/RUNTIME_QUESTIONS.md)，生成器是
[i0_6_candidates.py](tools/i0_6_candidates.py)。15 个问题、23 条经源码审查的只读命令；
11 条"看起来像读"的命令被排除，其中 `ubus call rc list` 会对每个 init 脚本 fork+exec。
本阶段不排名替换候选。**设备接入与采集执行都尚未授权**，I0.7 需要用户分别批准。

I0.7 已在用户授权下完成只读运行态采集：
[RUNTIME_OBSERVATIONS.md](reports/ax3000t-stock-openwrt-25.12.5/RUNTIME_OBSERVATIONS.md) 与
[STATIC_RUNTIME_DIFF.md](reports/ax3000t-stock-openwrt-25.12.5/STATIC_RUNTIME_DIFF.md)，
派生工具是 [i0_7_observation.py](tools/i0_7_observation.py)（脱敏自检 0 命中才写出 manifest）。
设备身份与基线逐项一致，包集合只比镜像多 4 个 LuCI 中文语言包。40 个 ubus 对象中静态
字面量零漏注册，三条 build gating 结论全部证实；两处漏报都是方法缺陷：`dnsmasq.dns`
只存在于 OpenWrt 补丁中，`ubus` 伪服务没有 init 脚本。kernel command line 实测不含
`rootfs_mount_options.*`。jail 声明不等于生效——`wpad` 没有获得任何 namespace 隔离。
原始输出只留在 Git 之外的 evidence 目录。

**I0 已全部完成，I0 gate 通过。** 最终报告见
[I0_FINAL_REPORT.md](reports/ax3000t-stock-openwrt-25.12.5/I0_FINAL_REPORT.md)，
分类见 [REPLACEMENT_BOUNDARY.md](reports/ax3000t-stock-openwrt-25.12.5/REPLACEMENT_BOUNDARY.md)，
未解问题与风险见 [OPEN_QUESTIONS.md](reports/ax3000t-stock-openwrt-25.12.5/OPEN_QUESTIONS.md)
与 [RISK_REGISTER.md](reports/ax3000t-stock-openwrt-25.12.5/RISK_REGISTER.md)。
OQ-01/OQ-07 的关闭证据与四阶段审查见
[I0_FOLLOWUP_REVIEW.md](reports/ax3000t-stock-openwrt-25.12.5/I0_FOLLOWUP_REVIEW.md)。

17 项控制面职责中 **10 项停在默认类**（保留或禁止触碰），4 项延后，3 项进入 Rust
工作范围：R13 rpcd 与 R15 logd 为包装，**唯一的完整替换候选是 R05 配置变更检测与分发**
（`/sbin/reload_config`，17 行 shell，上游自称临时方案）。它入选的理由是静态接口面窄、
运行态基线与 trigger 注册已观察、失败静默、无持久副作用、恢复代价为零——不是因为
"可以用 Rust 写"。事件投递 oracle 仍由 RK-01 阻塞。

I0 follow-up 已关闭 OQ-01 与 OQ-07：rcS 顺序/失败传播已确定，设备当前 DHCP/firewall
配置也已脱敏审查，可作为固定当前配置的 C1 oracle。当时剩余前置条件只有 RK-01
（先让"变更已送达"可观测），并且严格保持了 **C1/R1.1 门通过前不创建替代 crate** 的顺序。

**C1 已完成：第一个兼容合同 C1-01 已冻结**，对象是 I0 唯一的替换候选 R05
配置变更检测与分发。合同见
[config-change-dispatch.md](docs/contracts/config-change-dispatch.md)，决策见
[0001](docs/decisions/0001-first-contract-is-config-change-dispatch.md)，
11 个参考用例见 [tests/reference/config-change-dispatch/](tests/reference/config-change-dispatch/)。

C1 期间在设备上取得三条关键行为证据：`/etc/config/` 中 7 个含点文件名对应的 UCI
tuple 均无法解析并产出空基线条目，因此只要 tuple 继续不存在，修改这些文件自身的内容
不会触发事件；删除与修改在
`md5sum -c` 下是同一个 `FAILED` 信号，而新增完全静默；事件顺序按基线字典序确定。
合同要求**复刻**这些行为——把当前 7 个空条目改成读取备份文件内容会改变 procd trigger 的触发面，
那是行为变更而不是兼容实现。

**R1.1 可观测 oracle 已通过。** 精确镜像 rootfs 中的原始 17 行实现通过 11 个合同用例
和 4 个故障场景；每轮比较数、变更条目与逐条 ubus 调用结果已经可观察。报告见
[R1_REFERENCE_ORACLE.md](reports/ax3000t-stock-openwrt-25.12.5/R1_REFERENCE_ORACLE.md)。
这一门先以独立 commit 固化，之后才创建唯一的 R05 crate。

**R1 已完成并通过 gate。** 最小实现位于
[components/reload-config](components/reload-config/)，没有第三方 crate，也没有通用框架。
它继续使用精确系统 `uci` 做规范化、BusyBox `md5sum` 保持共享基线，只把扫描/比较/顺序、
子进程边界和 JSONL 可观测性显式化。目标 AArch64 静态 binary 为 432,248 bytes，低于
512 KiB 的 R1 预算。

在服务器的一次性精确 rootfs 中，候选与原实现 **11/11** 合同案例的事件顺序、事件集合和
完整基线字节一致；部分投递失败、依赖消失、超时、畸形 UCI、并发与 SIGTERM 共 **6/6**
故障案例通过。审查见
[R1_IMPLEMENTATION.md](reports/ax3000t-stock-openwrt-25.12.5/R1_IMPLEMENTATION.md)，机器记录见
[r1-candidate.json](manifests/ax3000t-stock-openwrt-25.12.5/r1-candidate.json)。

**V1 已完成并通过 gate。** 匹配 OpenWrt 25.12.5 filogic 官方 SDK 的 package 位于
[packaging/openwrt/owrt-reload-config](packaging/openwrt/owrt-reload-config/)。安装默认不取得
控制权；只有显式 `enable` 才以重启即失的 bind mount 接管原调用路径，upgrade、downgrade、
uninstall 和新 mount namespace 都会恢复原实现。

APK 实际安装出的 346,531-byte dynamic musl PIE 再次通过 **11/11** 合同差分和 **6/6**
原故障，并通过只读 I/O、磁盘满、依赖恢复和 100 次循环四项 V1 检查。V1 同时发现并修复了
upgrade 未回退和磁盘满截断基线两个真实缺陷。报告见
[V1_VALIDATION.md](reports/ax3000t-stock-openwrt-25.12.5/V1_VALIDATION.md)，机器记录见
[v1-validation.json](manifests/ax3000t-stock-openwrt-25.12.5/v1-validation.json)。

H1 已完成无拆机边界重规划。用户只提供 Wi-Fi、Ethernet 和现有 OpenWrt SSH；UART、拆机、
主板测试点、raw NAND 和刷机永久退出当前执行路径。H1.2/H1.3b 保留为未执行的历史 false
gate，不再错误阻断只涉及 R05 tmpfs 状态的验证。报告见
[H1_NO_DISASSEMBLY_REPLAN.md](reports/ax3000t-stock-openwrt-25.12.5/H1_NO_DISASSEMBLY_REPLAN.md)，
决策见 [0006](docs/decisions/0006-use-a-no-disassembly-device-validation-profile.md)。H1.4 offline
preflight 已冻结并验证 SSH/tmpfs shadow harness，见
[H1_4_PREFLIGHT.md](archive/stage-gates/H1_4_PREFLIGHT.md)（已归档）。它纠正了 synthetic
package 新增应保持静默、修改才发事件的语义，并在首次实机 probe 中发现当前 baseline 与
`network` 规范化结果存在 drift。最终 shadow 序列先隔离观察并吸收该 drift，再检查稳态零事件、
新增静默和修改单事件；真实设备 H1.4 已全部通过，见
[H1_4_SHADOW.md](reports/ax3000t-stock-openwrt-25.12.5/H1_4_SHADOW.md)。执行上限是固定 `/tmp`
路径和 fake ubus，结果为零持久写入、零真实 ubus、零 mount、清理完成。H1.5 默认禁用安装
已经完成：精确 `0.1.0-r1` package 已 offline 安装，switch 保持 disabled，original dispatcher、
配置、baseline、triggers 和 mount 不变；详见
[H1_5_DISABLED_INSTALL.md](reports/ax3000t-stock-openwrt-25.12.5/H1_5_DISABLED_INSTALL.md)。首轮
fail-closed 还发现并修正了目标 BusyBox 无 `stat` 以及 apk 回退会规范化 scripts archive 的
两个方法缺口。

2026-09-02 阶段审计：H1.2/H1.3 物理恢复链假设了用户从未提供的拆机和 UART，每阶段一套 gate
脚本与四处复写的状态文字也与 R05 的实际爆炸半径不成比例，均已移入 [archive/](archive/README.md)。
同日完成了两步实机操作：用原始实现收口 `network` baseline drift（成因是 LuCI/rpcd 路径不经过
`reload_config`，见 [H1_6_DRIFT_PROBE.md](reports/ax3000t-stock-openwrt-25.12.5/H1_6_DRIFT_PROBE.md)），
以及 **H1.6 canary 通过**：候选真实接管约一分钟，稳态零事件、修改与删除各恰好一次真实 ubus 投递，
切回后静默，见 [H1_6_CANARY.md](reports/ax3000t-stock-openwrt-25.12.5/H1_6_CANARY.md)。R05 实机验证
完成。后续五阶段计划见 [docs/EXECUTION_PLAN.md](docs/EXECUTION_PLAN.md)。

**阶段 1 完成：R05 Rust dispatcher 已转正。** 0.2.0 把 trace 改写 syslog、增加开机重新接管的 init 脚本，
离线 R1/V1 harness 全部通过后升级到设备，canary 通过，`boot-enable` 已打开，候选当前接管
`/sbin/reload_config`。报告见 [R05_GO_LIVE.md](reports/ax3000t-stock-openwrt-25.12.5/R05_GO_LIVE.md)，
决策见 [0007](docs/decisions/0007-r05-boot-enable-and-syslog-trace.md)。

**阶段 2 完成：logd 已由 Rust 实现接管。** `components/ubus` 是纯 Rust 的 ubus 线协议库，`components/logd`
在精确 rootfs 中与原 logd 并排比对 10 项输出全部一致，设备上 canary 通过后 `boot-enable` 已打开。报告见
[R15_LOGD.md](reports/ax3000t-stock-openwrt-25.12.5/R15_LOGD.md)，合同见 [logd.md](docs/contracts/logd.md)，
决策见 [0008](docs/decisions/0008-replace-logd-with-rust-and-own-ubus-library.md)。

**阶段 3 完成：uhttpd 已由 Rust 实现接管（含 HTTPS）。** `components/httpd` 在精确 rootfs 中与原 uhttpd 并排
38/38 请求一致，设备上并排、canary 均与原服务一致，`boot-enable` 已打开。报告见
[R14_HTTPD.md](reports/ax3000t-stock-openwrt-25.12.5/R14_HTTPD.md)，合同见 [httpd.md](docs/contracts/httpd.md)，
决策见 [0009](docs/decisions/0009-replace-uhttpd-with-rust-httpd.md)。下一阶段：firewall4 生成器。

阶段 4（2026-09-02）：R09 firewall4 生成器 Rust 化。`components/fw4` 逐函数移植 fw4.uc 与模板，上游 31 个测试文件
逐字节通过（stdout+stderr），设备配置离线渲染与设备 `fw4 print` 相同；`owrt-fw4 0.1.0-r1` 的 `owrt-fw4-switch enable`
以两种实现 `print` 相同为门禁后 bind mount 到 `/sbin/fw4`，经候选 reload 后内核规则集不变，`boot-enable on`。
报告 `reports/ax3000t-stock-openwrt-25.12.5/R09_FW4.md`，清单 `manifests/ax3000t-stock-openwrt-25.12.5/r09-fw4.json`。

阶段 5（2026-09-02）：R13 rpcd 插件层 Rust 化。`components/rpcd` 提供 `file` 与 `luci` 两个 ubus 对象，精确 rootfs
沙箱 63 个请求与原插件相同；`owrt-rpcd 0.1.0-r2` 以裁剪插件目录 bind mount + procd 服务上线，`boot-enable on`。
`session`/`uci`/`rc` 与 iwinfo/luci-rpc/rpc-sys/rrdns 保留在原 rpcd（决策 0011）。`owrt-switch` 一处操作五个组件。
最终报告：`reports/ax3000t-stock-openwrt-25.12.5/FINAL_REPORT.md`；报告 `R13_RPCD.md`，清单 `r13-rpcd.json`。

收官（2026-09-02）：`owrt-switch status` 显示五个组件 enabled / boot-enable on；四次综合探测不变；用户登录 LuCI 浏览期间
`file`/`luci` 的 71 次调用全部由 rpcd-rs 应答。清单 `manifests/ax3000t-stock-openwrt-25.12.5/final-window.json`。

第二轮 §11.0 自检（2026-09-02）：15 项迁移自检 + 四路对抗审查，修复 20 处行为差异（rpcd `file.write` umask、ubus 有符号整数、
logd read 类型策略、httpd 413/MIME、fw4 ipset 空白与 `%.14g` 等），全部按 check→单元→上游→release→差分重验。
报告 `reports/ax3000t-stock-openwrt-25.12.5/AUDIT_ROUND1.md`，清单 `manifests/audit-round1.json`。

阶段 6（2026-09-02）：`components/uci` 以 Rust 复刻 libuci 读写/delta 语义并提供 `uci-rs` CLI；上游 shunit2 112/112，
精确 rootfs 差分 175/175（含 apk 发货二进制）；设备门禁 export/show/changes 逐字节相同后 bind mount 接管 `/sbin/uci`，
`reload_config` 经候选规范化 19 个包与 C 版基线 0 差异，`boot-enable on`（S00）。`owrt-switch` 现管理六个组件。
报告 `R16_UCI.md`，合同 `docs/contracts/uci.md`，决策 0012，清单 `manifests/r16-uci.json`。

阶段 7（2026-09-02）：rpcd 核心对象 `session`/`uci`/`rc` 迁入 rpcd-rs（`uci` 对象基于 `components/uci`），精确 rootfs 双沙箱差分
272/272（含 apk 发货二进制，含 SIGHUP 冻结/解冻）；设备只读门禁 51 项在原 rpcd 与 rpcd-rs 下逐字节相同；`owrt-rpcd-switch enable`
按"停 rpcd → 起 rpcd-rs → 起 rpcd（只剩插件）"接管，`boot-enable on`（S11 先于 S12）。报告 `R17_RPCD_CORE.md`，合同
`docs/contracts/rpcd-core.md`，决策 0013，清单 `manifests/r17-rpcd-core.json`。

阶段 8（2026-09-02）：rpcd 余下对象 `rpc-sys`、`network.rrdns`、`luci-rpc`、`iwinfo` 迁入 rpcd-rs（纯 Rust rtnetlink 与
libiwinfo nl80211 后端复刻），沙箱 r18 74/74、并排 r19 11/11、回归 r13/r17 不变；设备只读门禁 49 项在原 rpcd 与 rpcd-rs
下相同（含两个 radio 的 iwinfo 与 luci-rpc 无线状态）；原 rpcd 进程停止、S12 移除，rpcd-rs 成为唯一 rpcd。
报告 `R18_RPCD_PLUGINS.md`，合同 `docs/contracts/rpcd-plugins-stage8.md`，决策 0014，清单 `manifests/r18-rpcd-plugins.json`。

§11.6 合并（2026-09-02）：fw4-rs 与 rpcd-rs 的内嵌 UCI 解析器均改为 `components/uci`；owrt-fw4 r2 上线（门禁 203 行相同，
规则集不变）。logd-rs 补上 ubus 重连。

第二轮收官（2026-09-02）：阶段 6/7/8 上线，阶段 9（ubusd）经 `tools/r22_ubus_clients_reconnect.sh` 前置检验判定不执行
（决策 0015）。设备上 uci/reload_config/logd/uhttpd/fw4/rpcd 六个控制面组件均为 Rust；procd/ubusd/netifd/无线/DHCP
栈保持原样。汇总见 `reports/ax3000t-stock-openwrt-25.12.5/REPORT_ROUND2.md`。

第三轮（2026-09-03 起）：用户放宽设备边界后，决策 0016 允许一次受控重启验证从未执行过的开机路径（六个组件都是
boot-enable on 但机器 33 天未重启）。已完成备份（配置、overlay、mtd0–7 只读转储）、官方镜像与原厂固件下载校验、
bootloader 选槽逻辑核实、uci-rs 开机路径预检、`tools/r23_reboot_gate.sh pre`；救援手册 `docs/RUNBOOK_AX3000T_RECOVERY.md`。
ubusd 仍排最后，默认建议不做。
2026-09-03 受控重启通过：SSH 39 秒恢复，六个组件按 boot-enable 接管，重启前后 15 组结构化状态相同，bootloader 标志仅计数 +1，
四分钟无 respawn（`reports/.../R23_BOOT_PATH.md`，`manifests/r23-boot-path.json`）。
