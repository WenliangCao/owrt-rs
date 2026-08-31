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
[i0_6_candidates.py](tools/i0_6_candidates.py)。13 个问题、19 条经源码审查的只读命令；
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
