# 断电复测与生产清理

2026-09-29。用户完成一轮物理断电、断开 WAN、恢复供电后接回 WAN 的复测，联网恢复。随后明确要求保留九个 Rust 组件并清理试验文件。清理已完成：**九组件身份与配置保持不变，overlay 释放 35.9 MiB，可用空间达到 52.5 MiB。**

运行版本仍为源码 `6a4a405e0c4e1df81a95967a95cbe17897313430` 的正式 [release-image 36575083891](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36575083891)。修复与部署依据见[上一份记录](POWER_RECOVERY_20260929_FIX.md)。

## 物理断电复测

用户说明接回 WAN 前只作了大约 11～20 秒的随意等待，没有执行建议的 30/60/120 秒系列。设备记录显示：

| 启动后时间 | 设备事件 |
|---|---|
| 18.844283 秒 | WAN 已开启，尚无 carrier |
| 62.569673 秒 | WAN 获得 carrier，仍保持开启 |
| 63.101673 秒 | WAN 安装 IPv4 地址 |
| 63.101905 秒 | 安装 IPv4 默认路由 |
| 103 秒 | 试验 guard 确认连续健康并清零未确认启动计数 |

WAN 在没有 carrier 的情况下保持开启 **43.725390 秒**，获得 carrier 后 **0.532232 秒**安装默认路由。这个启动过程覆盖了此前触发缺陷的条件：网络晚于设备初始化就绪。设备的 carrier 时间并不等于用户插线的精确时间。后续约每 30 秒的地址更新记录没有伴随 WAN 关闭，不能当作链路失败。

采集时九组件均为预期 Rust 身份，没有切回 C。此次结果支持“等待链路时误释放设备”的修复已生效；它是一轮成功的物理复测，不代表所有断电与上游故障组合均已验收。

## 清理范围与结果

先停止 recorder、快照循环和临时 guard，让记录落盘；停止电脑侧只读观察任务。重新核验五份既有离线备份、两份恢复镜像、九个正式 ELF 与客户端健康，然后制作新的 `/root`、overlay、配置备份。归档通过 gzip 完整性检查，全部普通文件可读取；262 个 root 文件的内容哈希逐项吻合，硬链接按原文件解析，19 份配置逐项吻合。

删除 21 个明确列出的持久路径：旧部署包、候选与回退副本、断电采集器、其开机入口、早期 p6 工具与确认标记，以及三份与 `/rom` 相同的 `.c-orig` 冗余副本。清除相应临时锁和 PID 文件。`/root` 清理后为空。完整删除清单与执行日志保存在离线证据目录。

保留九个实际运行文件、六组件的软件包与必要启动/切换脚本、开机启用标记、原 OpenWrt 内核和执行面、只读 stock ROM、全部配置及用户 LED 定时任务。包内启动脚本是组件正常启动的依赖，属于正式运行内容。

| `df -k /overlay` | 清理前 | 清理后 |
|---|---:|---:|
| Used | 41,832 KiB | 5,084 KiB |
| Available | 17,004 KiB | 53,752 KiB |
| Use% | 71% | 9% |

实际可用空间增加 **36,748 KiB（35.9 MiB）**；使用 `df` 差值，避免对硬链接重复计数。

清理后核验六个守护进程 PID、运行映像哈希与清理前相同，三个命令入口及九组件下一次启动文件均符合离线 manifest。六套 Rust 启动项仍开启，原 log/rpcd/uhttpd 启动项仍关闭。19 份配置、cron、rc.local、sysupgrade.conf 均未变化。WAN/WAN6、客户端 DHCP、双频 AP、HTTP/HTTPS、IPv4/IPv6 DNS、路由器外网 HTTPS 和硬件 watchdog 检查通过。清理期间没有重启或切换组件。

**试验用五分钟自动 C 回退和启动次数保护随试验工具移除。** 标准硬件 watchdog 保留。历史证据和恢复资料已保存在电脑；旧 `/root/owrt-power-test/power_guard.sh`、`/root/r84/stack-switch.sh` 入口已退役。[恢复手册](../RUNBOOK_AX3000T_RECOVERY.md)同步改为校验后从当前 stock `/rom` 复制 C 原件，避免依赖已删除文件。

## 整合为固件的判断

目前是在 stock 镜像上安装六套 Rust 包，并在 overlay 替换三个核心程序。[镜像构建脚本](../../tools/ci_build_image.sh)只内置六套替换包与 `owrt-switch`；[release-image 流程](../../.github/workflows/release-image.yml)在镜像完成后才通过[核心构建脚本](../../tools/ci_build_core.sh)生成 procd/ubusd/netifd 独立归档。因此现有 sysupgrade 产物还不是完整九组件 Rust 固件；已有 ubusd 包配方也没有接入该镜像步骤。

下一步适合把九组件纳入同一构建、版本清单和软件包所有权管理，在同一 sysupgrade 镜像中默认启用。保持相同内核、驱动、程序版本、启动行为和配置时，运行功能与性能可以基本一致；镜像整合主要改善交付、空间布局、升级和恢复出厂的一致性。九个组件仍各自运行，无需合并成单一进程。

“保留配置刷入”会备份选定配置、安装新系统，再恢复这些配置；它不会自动保留整个旧 overlay 或所有另装软件包。已核对精确镜像的 `sysupgrade`/preinit 实现及设备实际保留列表，与 [OpenWrt sysupgrade 说明](https://openwrt.org/docs/guide-user/installation/generic.sysupgrade)一致。新镜像应内置所需软件包和启动默认值，个人 Wi-Fi、密码等配置继续独立备份与恢复。

当前恢复出厂会清空 overlay，回到 stock C；完整 Rust 镜像恢复出厂则应回到其 Rust 默认栈。届时 `/rom` 的身份也会改变，必须另行固定 C 恢复来源并验收升级、配置恢复和故障恢复。本轮只完成清理与设计判断，没有构建或刷入新固件。

脱敏结果见[机器记录](../../reports/ax3000t-stock-openwrt-25.12.5/POWER_RECOVERY_20260929_CLEANUP.json)。原始采集、完整清单、配置及备份只存于 ignored `private/production-cleanup-20260929/`；此前失败轮次证据也保留。
