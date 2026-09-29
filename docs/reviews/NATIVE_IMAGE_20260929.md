# 九组件一体化固件：构建与离线验收

后续进展：同日已完成[保留配置真机部署](NATIVE_DEPLOYMENT_20260929_RESULT.md)。以下保留镜像工程完成时的验收范围。

2026-09-29。**一个完整 AX3000T sysupgrade 镜像已构建，最终产物的离线验收通过，尚未刷入路由器。** 九个 Rust 程序与当前修复后生产版本逐字节相同；本轮改变安装布局、统一软件包管理、配置迁移和恢复方式。现役路由器未被修改。

## 最终产物

| 项目 | 身份 |
|---|---|
| 构建源码 | `a4053dd5d4b4b2dbed3ff8a56d595aeabd33e0d0` |
| 正式流水线 | [release-image 36592957923](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36592957923)，成功 |
| 统一包 | `owrt-control-plane 0.1.0-r2` |
| 固件大小 | 12,759,328 bytes，约 **12.17 MiB** |
| 固件 SHA256 | `144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720` |
| 统一 APK | 4,407,346 bytes；`65a33a71fe6ac16d9d29eb8bb7000403a0043866dbdabf472e727f98de69bc49` |
| 运行实现对照 | [生产构建 36575083891](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36575083891)，源码 `6a4a405e0c4e1df81a95967a95cbe17897313430`；九个 ELF 哈希全部一致 |

固件文件名为 `openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin`。这是上述 Actions artifact 中的定制镜像，文件名与官方原版相同，识别时须同时核对 SHA256。本地镜像、APK、manifest 和构建日志保存在 `private/integrated-image-20260929/canonical-a4053dd/`。本轮未创建 GitHub Release。

## 一体化后的行为

| 方面 | 镜像中的实现 |
|---|---|
| 安装 | 九个程序直接位于 `/sbin/procd`、`ubusd`、`netifd`、`rpcd`、`logd`、`uci`、`reload_config`、`fw4` 及 `/usr/sbin/uhttpd` |
| 文件所有权 | 一个 APK 拥有九个入口；原八个包继续提供其余库、辅助程序、配置和启动脚本，依赖固定为原版版本 |
| 启动 | 原 `log`、`rpcd`、`network`、`uhttpd` 服务启动标准路径；保留 Web 首次启动证书生成 |
| 存储显示 | 不需要原 `/sbin/uci`、`/sbin/fw4`、`/sbin/reload_config` 三个绑定挂载；隔离启动中确认这些挂载不存在 |
| 配置 | 保留配置升级迁移选定配置；首次迁移修正旧部署留下的三项服务禁用，后续原生升级尊重用户的服务禁用选择 |
| 恢复出厂 | 回到镜像内置的 Rust 默认栈 |
| C 恢复 | 九份精确原件位于 `/usr/libexec/owrt-stock/`；`owrt-recover-c` 校验并准备全部文件后替换，随后单独重启 |

正式镜像不带六套旧组件开关服务、boot-enable 标记、采集器或试验 guard。九个组件仍按原职责分别运行。内核和成熟执行面继续来自原版镜像。

首次配置迁移使用 `/etc/uci-defaults/05-owrt-native`：原 sysupgrade 会生成 `10_disable_services`，旧分层部署的 `log`、`rpcd`、`uhttpd` 禁用状态必须在它执行前处理。`/etc/owrt-control-plane-layout` 标记由 keep.d 保留，使后续原生升级不会再次覆盖用户的选择。

详细布局、构建和迁移约定见[发布说明](../RELEASE.md)与[镜像配方](../../packaging/image/README.md)。新镜像的 `/rom` 已含 Rust，C 恢复需使用专用原件目录；[救援手册](../RUNBOOK_AX3000T_RECOVERY.md)已区分两种布局。恢复工具是手动准备 C 栈的工具，没有自动重启或首次启动自动回退功能。

## 原版系统保留核验

最终根文件系统从固定 SHA256 的原始官方镜像重新提取，离线安装统一 Rust APK 与四个匹配版本的中文 APK，再由对应 ImageBuilder 的官方工具装配。中间 SDK 镜像仅提供 Rust ELF，最终根文件系统不解析滚动软件源。

| 核验项 | 结果 |
|---|---|
| 原始官方镜像 | SHA256 `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea` |
| 原软件包版本 | **159 个全部保留**；加统一包和四个中文包后共 164 个 |
| 原文件 | **867 个受保护普通文件内容相同**，原符号链接、权限、所有者也核验；九个替换入口及 APK 数据库、world 元数据另行检查 |
| 中文界面 | 从匹配 LuCI 源码 `128a7812f4be233c5dd7f7466f534fd888785caf` 重建，四份翻译目录文件与现役系统哈希相同 |
| 内核 | 与固定官方镜像的内核载荷逐字节相同，4,336,328 bytes，SHA256 `c20bee280c72744dd203a1832c968156480da6b6f92c210d295fd8c63940d1c6` |
| CONTROL、固件元数据 | 与固定官方镜像相同 |

现役 `/rom` 的 893 个文件哈希另作只读比对。它与所下载的官方基底存在已识别的构建元数据差异：BusyBox 的构建时间字符串差 8 bytes；libnftables 的两个构建时间常量共差 4 bytes；LuCI 相同修订的分支标签不同。此外有四个中文包及 APK 数据库差异。本镜像保留未经补丁修改的官方基底，重建匹配中文包。因此，“原执行面保留”指固定官方镜像的身份，并非声称与现役 ROM 每个字节都相同。此次未读取实际运行内核所在闪存的哈希。

## 最终产物的离线验收

以下结果均来自正式 `a4053dd` 产物重新解包后的文件，在原生 aarch64 Linux 构建机上使用独立文件系统副本和 mount/network/PID namespace；没有接入路由器无线、闪存或 watchdog 设备。

| 验收组 | 最终结果 | 范围 |
|---|---|---|
| 配置、恢复、APK、固件适配 | **8 项通过** | 两种升级迁移、损坏原件拒绝、挂载目标拒绝、九组件幂等恢复且配置不变、两种包重装、原 fwtool 接受 AX3000T 保留配置并拒绝错误机型 |
| Rust 栈启动 | **10 项通过** | PID1 与五个守护进程身份、原服务入口、模拟 LAN/WAN、HTTP/HTTPS、首次证书、日志、UCI/reload_config、fw4 原版对照和语法检查、无三个额外挂载、PID1 重启退出 namespace |
| 实际恢复后的 C 栈启动 | **同样 10 项通过** | 对 `owrt-recover-c` 实际处理过的根文件系统重复上述启动验收 |
| WAN 延迟恢复回归 | **8 个 C/Rust 运行用例通过** | 四种场景各跑 C/Rust：上游早到、晚到且 WAN/WAN6 共用、晚到且单 WAN、明确禁用；另核验生命周期阶段 |
| preinit 的独立 hotplug 服务 | **通过** | 原版与镜像内 Rust `procd -h` 处理 namespace 内真实 loopback uevent，执行效果一致 |

WAN 回归使用最终镜像中的 netifd、原版 C 总线和模拟协议辅助程序，属于隔离组件回归。启动门使用模拟静态 LAN/WAN 和选定原服务。hotplug 门覆盖独立 `-h` 模式，并非物理设备的完整 preinit。两个启动结果各有 10 个成功断言；`physical_hardware_tested: false` 是范围标记，不计作成功项。

配置/恢复/适配六项取自 `final-check-01`，包重装两项取自修正后的 `final-package-check-02`。第一次包门的两项结果因实际跳过重装而作废，其原始日志保留。新门先删除八份包文件清单和一份 C 恢复原件，要求重装逐字节恢复它们，并继续核验九个 Rust 文件及所有权；另外两次反例重放分别让原包和 native 包跳过重装，均正确判失败。

原八个包的旧版签名 APK 已无法从当时软件源获取。重装门据固定原镜像的文件清单、版本和依赖重建无签名测试载荷，配合**最终正式 native APK**，显式指定本地文件运行 `apk add --force-reinstall --no-scripts`；验证的是文件覆盖与所有权，未覆盖原签名包生命周期脚本或在线更新。

配置门使用合成配置执行原版 sysupgrade 备份及 preinit 恢复逻辑，检查 network、wireless、密码文件、cron、rc.local 与额外保留文件，并验证首次迁移和后续用户禁用状态。它提供配置迁移证据，实际刷机后的个人配置仍需逐项核对。

## 已解决并保留记录的问题

| 记录 | 问题与处置 |
|---|---|
| [CI 36586181711](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36586181711)，`7b8bb74` | 镜像已生成，审计无法读取 root 所有的 `/root`；改用具备读取权限的审计进程，保留失败日志 |
| [CI 36587233360](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36587233360)，`83f32c5` | 当次流程成功，但随后对原始基底检查发现 **41 个软件包版本变化**；撤销其最终候选资格，改用固定原始 rootfs，旧产物保留 |
| 原型迁移门 01/02 | 缺失 `/var/lock`，以及测试 shell 的 nounset 影响 stock preinit；补齐测试环境 |
| 原型启动门 01/02/03 | 依次发现运行目录、模拟 system 配置、shutdown inittab 行缺失；第 03 次服务检查完成但重启停滞，保留该失败，不计作完整通过 |
| 首次固定基底预装配 | builder 的 umask 经 APK 改变了 `/usr` 权限；修复载荷目录权限继承，保留严格检查 |
| 首次 APK 测试索引 | 无签名载荷需显式 `--allow-untrusted`；只在离线测试和装配中启用 |
| 最终包门首轮 | `apk fix --reinstall` 返回成功但日志标记 `APK unavailable, skipped`，哈希不变不足以证明重装；改为显式载荷、删除文件恢复断言和跳过拒绝，补跑实际重装与两个反例 |

上述问题解决后，最终正式产物通过表中所有离线门。本轮只调整镜像装配与工具，没有重新修改九个 Rust 实现。

## 交付边界与证据

**镜像工程和离线验收完成。** 物理刷写、首次无线启动、真机断电以及实际 overlay 空间变化留给部署验收。本轮未重测性能；程序哈希相同支持运行实现未变，实际启动顺序与存储布局仍需真机验证。

按项目部署约定，下一轮刷机需要单独明确授权，并先核验离线备份、最终镜像身份、适用于原生布局的自动回退和客户端健康。目前的手动 C 恢复门不等于已完成自动回退；旧分层部署中从 `/rom` 取 C 的 guard 也不能直接复用。

脱敏汇总和验证工具 SHA256 见[机器记录](../../reports/ax3000t-stock-openwrt-25.12.5/NATIVE_IMAGE_20260929.json)。`native_image_check.py` 的固件适配门和重装漏判修正在镜像源码提交之后加入，记录了实际运行脚本的哈希；这些工具改动不改变已验收镜像。

原始记录在 ignored `private/integrated-image-20260929/`。最终离线证据归档 `final-offline-evidence-02.tar.gz` 共 193,427 bytes、346 个普通文件，SHA256 `7ec8d2798c7d19f0e31df5cb51b8b555088cd58d3fb13174fa77eeac0867925b`；已在电脑端核验哈希、gzip 完整性、成员内容和七个工具身份。首份证据归档和完整测试根文件系统副本继续保留。镜像、备份、原始设备资料和测试载荷均未加入 Git。
