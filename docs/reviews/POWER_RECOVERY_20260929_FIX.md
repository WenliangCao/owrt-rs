# WAN 延迟恢复修复与九组件重新部署

2026-09-29。用户明确授权修复后重新部署全部九个 Rust 组件，并自行进行多轮断电复测。**九组件已重新接管，软件重启验收通过；本次修复后的物理断电验收等待用户操作。**

运行源码为 `6a4a405e0c4e1df81a95967a95cbe17897313430`，正式构建为 [release-image 36575083891](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36575083891)。[常规 CI 36575082996](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36575082996) 同提交通过。新 netifd ELF SHA256 为 `adcf2bee51a4d985cea4ed01497da42988b8d0c9ab71eaf2d49eef821afc0a1f`；另外八个 ELF 与上一轮正式产物逐字节相同。保留原 OpenWrt 内核、驱动、执行面和配置，没有刷固件。

**修复内容。** [事故分析](POWER_RECOVERY_20260929_FAILURE.md)已用真机日志与隔离 A/B 实验定位启动清理错误。本次在 [netifd 主程序](../../components/netifd/src/main.rs)移除按协议 `Down` 状态释放设备的启动循环：等待 carrier 的接口继续持有并开启端口，接网后正常启动 DHCP。

扩大回归时还发现，最终删除接口配置后，`pump_removals()` 会保留 autostart 接口的 main-device claim。新增用例中，C 删除接口后端口关闭，而仅修启动的诊断版仍将端口留在 UP。按匹配上游 `interface_cleanup_state()` 的行为，最终移除接口时明确释放 main-device claim，并回收没有使用者的设备对象。等待链路、失去链路、手工关闭及删除配置的行为分别验证。

**验证结果。**

| 验证 | 结果与范围 |
|---|---|
| netifd 单元测试 | 170 通过 |
| 完整 netifd 差分套件 | 构建机同源码 ELF 上 32/32 通过，零失败、零跳过 |
| 正式 ELF 的延迟 WAN 回归 | 8 组 C/Rust 场景全部通过：网络先就绪、共享 WAN/WAN6 延迟就绪、单 WAN 延迟就绪、`auto=0` 后手动开启 |
| 同一回归中的生命周期检查 | 拔线保持设备开启、重新接线获租、共享设备剩余使用者、最后使用者释放、无 carrier 时手动 up、保持配置的 reload、删除/重新添加配置全部通过 |
| 正式 ELF 的既有差分 | R52 DHCP、R56 DHCPv6、R62 PD、R64 晚出现端口、R90 生命周期、R91 日志六项全部通过 |
| 整栈切换与恢复 | APK 安装、九组件下一次启动切换、拒绝错误恢复身份、自动回退、离线 rescue 通过 |
| 同版本 APK 重装 | 配置和启用状态保持、旧进程继续服务、新进程匹配新包身份，全部通过 |
| 持久采集与保护 | 300 秒期限、第三次未确认启动回退、C 启动不循环重启、健康清零后继续保护、错误 C 原件拒绝恢复，全部通过 |

新增 [延迟 WAN 回归入口](../../tools/netifd_delayed_wan_gate.sh)已加入 [完整套件](../../tools/netifd_suite.sh)，使用真实 DHCP 交换、地址和默认路由作验收条件。上游 veth peer 置于独立 namespace，避免待测 netifd 顺带将测试网络提前拉起。IPv6 完整获租/PD 由既有 R56/R62 检查覆盖；新增延迟用例自身验收 IPv4，并检查共享端口上的 DHCPv6 helper 生命周期。

负向证据也保留：旧正式 ELF 被新回归的 `startup-port-enabled` 拦住；仅修启动的诊断版被 `removed-config-releases-device` 拦住。最终版本通过两者。校正测试工具的提交为 `f09b553`：独立调用回归入口时先建立输出目录；APK 测试检查安装文件等于新包预期哈希，支持 RPCD 没有改变的更新。两次工具/假设失败的原始记录均保留，未计为组件通过。

**采集与恢复适配连续试验。** 每次启动继续按 boot 分开采集。新增 [历史记录压缩工具](../../tools/power_archive.sh)仅处理已经结束的启动；先核对 gzip 完整性及解压后的 SHA256，再同步压缩副本，最后移除冗余原文件。当前启动不参与压缩。精确镜像 shell/gzip 下的往返、重复执行、压缩中断后继续、损坏或内容不符的压缩副本测试均通过；错误副本保留原件。

原有 10 MiB 采集预算及 8 MiB 空间保留线继续有效。回退健康窗口从 600 秒改为 **300 秒**，仍保留每 15 秒检查、三次连续健康确认和三次未确认启动保护。实际回退触发和重新联网还需计入初始化、检查间隔及恢复重启的时间。

**实际部署验收。** 部署前重新核验五份离线备份、两份恢复镜像、C 原件、所有正式产物、采集与回退工具、客户端健康。全新部署包 33 个文件在设备上逐项校验；内容相同的不可变文件与旧包共享存储，不同文件单独存放，旧包保留。备份和整栈恢复入口均可用。

软件重启后，14 次健康检查覆盖连续 180.063 秒，随后额外观察 30 秒并再次核验。九组件运行哈希、WAN/WAN6、客户端 DHCP、双频 AP、HTTP/HTTPS、IPv4/IPv6 DNS、路由器外网 HTTPS 和 watchdog 通过。19 份配置文件与部署前完全一致。Rust `fw4 print` 与同一时刻 `/rom/sbin/fw4 print` 在 subnet 集合排序归一化后相同，`fw4 check` 通过。

本次软件 boot 中，WAN 在 18.644202 秒开启、18.654027 秒获得 carrier，没有再出现启动后立即关闭 WAN 的现象。持久 guard 在 uptime 58 秒确认健康并清零未确认启动计数，仍保持 armed；原先仅保护首次部署的 canary 已按流程确认移除。

本次 boot 的 netlink、报文、快照均已写入，历史压缩无错误，部署后 overlay 尚余约 17.5 MiB。额外下载就绪阶段证据，核验 88 个文件；上一轮失败 boot 的 10 个文件全部可从压缩后的保存记录还原，与先前原始证据逐字节一致。电脑侧另启用四小时的只读 UTC/可达性记录。

**用户复测步骤。** 建议至少三轮，分别让 WAN 在恢复供电后延迟 30、60、120 秒接回。每轮先拔电源，再拔 WAN；等待约 20 秒，先恢复供电，到该轮延迟后再接回同一根 WAN 网线。联网后保持至少一分钟，再进行下一轮，让健康确认和证据落盘完成。若某轮自动恢复 C，暂停后续 Rust 试验并保留现场，避免将 C 的联网结果算到 Rust 上。

原始产物、配置、抓包、完整日志、备份及 boot 标识仍仅保存在 ignored `private/power-recovery-fix-20260929/`。`offline-evidence.tar.gz` 保存完整回归及失败尝试，`recovery-gate.json` 固定部署依据；`activation-window.json`、`activation-final-health.json`、`activation-extra-gates.json` 保存本机验收，`power-fix-ready.tar.gz` 保存就绪阶段证据。脱敏机器结果见 [本轮记录](../../reports/ax3000t-stock-openwrt-25.12.5/POWER_RECOVERY_20260929_FIX.json)。
