# 九组件集成固件的发布与维护

2026-09-29。发布流水线生成一个 AX3000T sysupgrade 镜像，九个 Rust 实现直接安装到 OpenWrt 的标准路径，由一个 `owrt-control-plane` APK 管理。原来的六套开关包与三个独立核心二进制是构建中间产物，正式镜像不包含绑定挂载、boot-enable 标记或试验采集器。四个中文翻译包从匹配 LuCI 修订重建，目录内容与现役系统逐字节核对。固件刷写仍需单独明确授权与恢复核验。

当前适配范围固定为 OpenWrt **25.12.5**、`mediatek/filogic`、`xiaomi_mi-router-ax3000t`。[配方](../packaging/image/native-25.12.5.json)固定九个标准路径、C 原件哈希及原软件包所有者。[镜像配方说明](../packaging/image/README.md)描述安装与迁移约定。

首份正式集成镜像 `owrt-control-plane 0.1.0-r2` 已完成构建、离线验收、保留配置真机部署和用户物理断电复测。固定版本为 [AX3000T Rust9 v0.1.0](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/ax3000t-rust9-v0.1.0)。[镜像验收](reviews/NATIVE_IMAGE_20260929.md)固定产物身份与离线证据；[部署记录](reviews/NATIVE_DEPLOYMENT_20260929_RESULT.md)记录实际运行和清理结果。临时保护已移除，正式镜像本身也不包含试验服务。

## 安装布局

| 组件 | 镜像内的实际程序路径 |
|---|---|
| procd / ubusd / netifd | `/sbin/procd`、`/sbin/ubusd`、`/sbin/netifd` |
| rpcd / logd | `/sbin/rpcd`、`/sbin/logd` |
| uci / reload-config / fw4 | `/sbin/uci`、`/sbin/reload_config`、`/sbin/fw4` |
| httpd | `/usr/sbin/uhttpd` |

沿用原 `log`、`rpcd`、`network`、`uhttpd` 启动服务。httpd 使用原启动脚本生成首次启动证书、读取 `/etc/config/uhttpd`；原 log 启动脚本也保留 logread 的文件与远程日志配置。内核、驱动、无线 handler、dnsmasq、odhcpd、DHCP 客户端、dropbear、BusyBox、LuCI、apk 和 sysupgrade 执行面保留。

APK 的 `replaces` 与 `replaces-priority` 明确指定九个文件归 `owrt-control-plane` 所有；原八个软件包继续提供其余文件。依赖固定为验收过的原包版本，避免原包更新与恢复原件不匹配。旧 `owrt-*` 开关包与此包冲突，不会混入最终镜像。

`/usr/share/owrt-control-plane/release.json` 保存统一版本、源码提交、九组件身份及恢复位置。配方中的 `version` 是统一 APK 版本，后续发布在这里递增。二进制内容以 SHA256 标识。

## 正式构建

正式发布使用 [release-image](../.github/workflows/release-image.yml) GitHub Actions，canonical builder 仍为固定 Rust 工具链的 x86_64 Linux runner，见[决策 0018](decisions/0018-canonical-build-host-ci.md)。

| 阶段 | 工具与结果 |
|---|---|
| SDK 与六个包 | `tools/ci_build_image.sh` 校验官方下载，按现有 SDK 配方构建六个 Rust 程序及中间镜像 |
| 三个核心程序 | `tools/ci_build_core.sh` 构建 procd/ubusd/netifd，固定源码路径及工具链，核验 ABI 与归档身份 |
| 原位整合 | `tools/ci_integrate_image.sh`、`tools/native_image.py` 固定原始官方镜像与 LuCI 源码归档的 SHA256，离线安装统一 APK 与四个中文包，使用匹配 ImageBuilder 的 squashfs/sysupgrade-tar/fwtool 工具重新装配 |
| 内容审计 | 九个标准路径与 ELF 哈希、APK 所有权、C 救援副本、原启动脚本和配置、全部原包版本与文件内容/权限/所有者均检查；内核、CONTROL 与固件元数据逐字节比较 |

沿用原 SDK 配方，保证整合工作不悄悄更换已验收的运行实现。中间镜像只提供六个 Rust ELF。最终根文件系统来自固定 SHA256 的官方镜像，避免普通 ImageBuilder 安装过程从滚动软件源连带更新无线脚本、LuCI 或库。缺失工具、原件身份漂移、文件所有权或执行面变化都会使流程失败。

可在 Actions 页面选择工作分支运行，或执行：

```sh
gh workflow run release-image.yml --ref <reviewed-ref> -f openwrt_version=25.12.5
```

Linux 构建环境下的 `make ci-image VERSION=25.12.5` 运行相同三个阶段。`tools/release.sh apk|image` / `make apk|image` 保留为旧六组件配方的构建机研究入口，**不是九组件正式发布入口**。

最终产物在 `work/native/out/`：

- 一个 `*-sysupgrade.bin`、一个 `owrt-control-plane-*.apk` 和四个匹配版本的中文 APK；用户安装的是整个固件，APK 是镜像装配输入，不支持用它在线替换 PID1/总线。
- `manifest.json`、`binary-sha256.txt`、`SHA256SUMS` 固定镜像、软件包、九个实际程序与发布身份。
- `build-inputs.json` 保留六包及核心构建的来源，构建日志支持复核。

失败流水线另存诊断日志和已生成的候选镜像。未通过的候选不作为发布完成证据。推送 `v*` 标签才创建 GitHub Release；普通 workflow_dispatch 只生成 Actions artifact。

已验收的生产回溯节点采用设备专用标签，例如 `ax3000t-rust9-v0.1.0`：annotated tag 直接指向实际构建提交，从保存的正式产物晋升到 Release，不重新构建。`tools/native_release_prepare.py` 核验固件与真机报告的身份，生成可刷写镜像、组件 SHA256、发布 manifest、验收摘要、恢复说明与装配包归档。先上传草稿并下载复核全部资产，再发布为 Latest。标签的构建提交和后续验收/文档提交分别记录，后续研究使用新版本，不移动已有发布标签。

## 保留配置与首次迁移

sysupgrade 的默认保留配置流程备份选定文件、安装新系统，再由原 preinit 实现恢复。它不保留整个 overlay。个人网络、Wi-Fi、密码、证书与定时任务通过配置备份迁移，不进入公共镜像。额外保留项仍由 `/etc/sysupgrade.conf` 和 `/lib/upgrade/keep.d/*` 决定。

旧的分层部署禁用了原 `log`、`rpcd`、`uhttpd` 服务，sysupgrade 会把这些状态写成 `/etc/uci-defaults/10_disable_services`。集成镜像的一次性 `05-owrt-native` 在它之前运行：首次采用集成布局时移除这三个禁用命令并启用服务，它们现在直接运行 Rust。其他服务的禁用状态继续保留。

迁移完成后写入 `/etc/owrt-control-plane-layout`，由包内 keep.d 规则保留。后续集成固件之间升级时，不再覆盖用户的服务启停选择。该机制仅在首次配置阶段执行，没有后台采集或试验回退进程。

恢复出厂会丢弃 overlay 与个人配置，回到镜像内置的 Rust 默认栈。

## 恢复路径

九份原版程序保存在 `/usr/libexec/owrt-stock/` 下，保留原相对路径，身份来自精确 stock 镜像。**集成镜像的 `/rom/sbin/procd` 等已经是 Rust，不能用作 C 原件。**

SSH 可用时，或进入 failsafe 并完成 `mount_root` 后，运行：

```sh
owrt-recover-c
# 核对成功提示后另行重启；failsafe 使用 reboot -f。
reboot
```

恢复工具先校验全部 C 原件，拒绝仍被绑定挂载的目标，准备并核验全部临时副本，再改名到九个标准路径。它不主动重启，不依赖 ubus/netifd，也不修改用户配置。多次运行结果一致。临时文件全部准备完成前不会更换任何目标；九次改名不构成跨文件的原子事务，中断后可在 failsafe 重跑。

原版内核、早期 init、preinit/failsafe 与救援材料继续保留。恢复出厂或重新刷入集成镜像会重新使用 Rust；永久退回官方版本仍使用验证过的原版固件和独立配置备份。

## 验收边界

`tools/native_image_check.py` 在 aarch64 Linux 的独立 mount/network/PID namespace 与镜像副本中运行精确 sysupgrade 备份、preinit 配置恢复、首次迁移、后续原生升级、错误恢复身份拒绝、完整 C 恢复及 APK 重装检查。`tools/native_apk_fixtures.py` 从固定原始镜像的文件清单重建八个原包载荷，用于 `--no-scripts` 文件归属重装测试；这些测试包不是原始签名 APK。重装检查显式安装本地载荷，要求恢复事先删除的文件，并拒绝 APK 返回成功但跳过载荷的情况。

`tools/native_boot_check.sh` 使用镜像内的 PID1、总线和标准启动脚本，验证模拟 LAN/WAN、RPCD、日志、HTTP/HTTPS、首次证书生成、UCI、reload_config、fw4 与无额外命令挂载。物理无线、闪存写入和断电行为仍由真机验收负责，隔离测试不能替代这些项目。

刷机前需重新核验离线备份、正式镜像身份、适用于新布局的自动回退及客户端健康。现有分层部署的 `/rom` 恢复假设和 `/root/r84` 工具不适用于此镜像。Wi-Fi 管理仍获授权；网线不是普通部署的前提，实际 failsafe/TFTP 操作见[救援手册](RUNBOOK_AX3000T_RECOVERY.md)。

首次原生部署使用的临时保护见[冻结计划](reviews/NATIVE_DEPLOYMENT_20260929_PLAN.md)，已在用户物理复测通过后按要求清理。该计划保留为历史执行依据，当前常规恢复使用镜像内的 `owrt-recover-c`。

## 后续 OpenWrt 版本

先引入精确新镜像及对应源码，在新 rootfs 上运行九组件差分回归，再新增版本的软件包列表与 native 配方。C 身份、原包版本、启动脚本、内核及恢复语义变化必须逐项复核。仅修改版本号下载新版镜像不足以完成适配。

跨宿主 TLS 二进制差异的历史调查见 [R35](reviews/R35_RING_INVESTIGATION.md)。统一构建来源解决发布身份问题。新的固定根文件系统装配不再生成随机本地签名密钥；软件包只用于离线装配。二进制可复现性与整镜像可复现性仍分别核验。
