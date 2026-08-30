# AX3000T stock / OpenWrt 25.12.5：源码基线

> I0.2 状态：完成
> 日期：2026-08-30
> 设备访问：无

## 结论

目标镜像的 buildroot、五个 feeds、stock 设备定义以及首批控制面组件均已固定到不可变 Git
对象。设备构建/升级配方和源码导出的接口、caller、failure boundary 已形成下一阶段的定向
检查清单。

I0.2 没有把 OpenWrt `main`、release tag commit 和 image revision 混为一谈，也没有混用
AX3000T `ubootmod`。它不宣称源码路径已经在物理路由器上执行，也不选择 Rust 替换对象。

## 1. 不可变 buildroot 身份

| 项目 | 值 |
|---|---|
| repository | `https://git.openwrt.org/openwrt/openwrt.git` |
| annotated release tag | `v25.12.5` |
| tag object | `e20bc3ec9eb9e3dbd0519ddc18f81f3eedc0f45e` |
| peeled release commit | `f0a60eee2fe051741c643ea6118718aae1ef17fb` |
| release tree | `4ac64a90c5cd190209b4a9428fc34f12e6c87d4b` |
| image `VERSION_CODE` | `r33051-f5dae5ece4` |
| full image revision commit | `f5dae5ece4805730c5e2850f8aa84765af2f6b32` |
| source date epoch | `1782737960` (`2026-06-29T12:59:20Z`) |
| kernel recipe | `6.12.94` |

`v25.12.5` 的 peeled commit 与镜像 revision commit 是两个不同标识：前者选择发布源码树，
后者是构建时写入版本字符串的 revision。后续 manifest 和报告必须保留两者，不能用短
`f5dae5ece4` 代替 tag commit。

服务器 evidence 中的 buildroot 已 detached 到 release commit，并通过
`git fsck --connectivity-only`。`include/version.mk`、`version.buildinfo`、
`feeds.buildinfo`、`config.buildinfo` 均已固定；不能以当前 `main` 替代。

## 2. Feed revisions

| feed | official repository | commit |
|---|---|---|
| packages | `https://git.openwrt.org/feed/packages.git` | `5caa62e0bc9f7fb9b0c12a23267bceb7724214dd` |
| luci | `https://git.openwrt.org/project/luci.git` | `128a7812f4be233c5dd7f7466f534fd888785caf` |
| routing | `https://git.openwrt.org/feed/routing.git` | `3d7d0dc7fa43d3eb09498417407e95a6552e5312` |
| telephony | `https://git.openwrt.org/feed/telephony.git` | `2618106d5846a4a542fdf5809f0d3ed228ce439b` |
| video | `https://git.openwrt.org/feed/video.git` | `094bf58da6682f895255a35a84349a79dab4bf95` |

五个 commit 均直接取自目标 `feeds.buildinfo`，已从对应官方 repository 取得、detached 并
通过 connectivity check。LuCI 的 package recipe 和源码因此以 luci feed commit 为准，
不在 buildroot 中臆造同名源码。

## 3. Stock 设备基线

设备唯一选择为：

```text
profile: xiaomi_mi-router-ax3000t
compatible: xiaomi,mi-router-ax3000t
layout: stock
image: sysupgrade-tar | append-metadata
kernel UBI partition: ubi_kernel
root UBI partition: ubi
```

关键文件：

```text
target/linux/mediatek/image/filogic.mk
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t.dts
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t.dtsi
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-common.dtsi
target/linux/mediatek/filogic/base-files/lib/upgrade/platform.sh
target/linux/mediatek/filogic/base-files/etc/init.d/bootcount
target/linux/mediatek/filogic/base-files/etc/board.d/02_network
```

device recipe 声明 128 KiB erase block、2 KiB page、`UBINIZE_OPTS=-E 5`，并加入
`kmod-mt7915e`、`kmod-mt7981-firmware`、`mt7981-wo-firmware`。stock DTS 保留
`ubi_kernel` 与 `ubi`；normal upgrade 走 `nand_do_platform_check()` / `nand_do_upgrade()`。

`xiaomi_initial_setup()` 只属于 initramfs/tmpfs 首次迁移，会格式化 UBI 并写 U-Boot env，
是未授权的破坏性边界。`ubootmod` 的 DTS、单 UBI、kernel/U-Boot-env-in-UBI、`.itb` 和
`fit_check_image()` 均明确排除。

完整设备配方、分区表和升级行为见
[DEVICE_BUILD_RECIPE.md](DEVICE_BUILD_RECIPE.md)。

## 4. 首批控制面组件

| 组件 | package/version | official source | immutable revision |
|---|---|---|---|
| procd | `procd 2026.03.13~58eb263d-r1` | `https://git.openwrt.org/project/procd.git` | `58eb263d5abe03f8c1280bdfa65a3b052614215d` |
| ubus | `ubus/ubusd 2026.06.28~24864e78-r2` | `https://git.openwrt.org/project/ubus.git` | `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` |
| uci | `uci 2025.12.02~66127cd7-r1` | `https://git.openwrt.org/project/uci.git` | `66127cd76c5d0bd46d5a90302cc6110f53a4e2f8` |
| rpcd | `rpcd 2026.06.04~28faf640-r1` | `https://git.openwrt.org/project/rpcd.git` | `28faf6403792d25b9826043aaf37880624c19568` |
| netifd | `netifd 2026.02.26~cbb83a18-r1` | `https://git.openwrt.org/project/netifd.git` | `cbb83a1857407a28a63dc09412a1f209195914ef` |
| firewall4 | `firewall4 2025.03.17~b6e51575-r2` | `https://git.openwrt.org/project/firewall4.git` | `b6e5157527d361f99ad52eaa6da273cb0f2dfd59` |
| odhcpd | `odhcpd-ipv6only 2026.06.29~5d7be43f-r1` | `https://git.openwrt.org/project/odhcpd.git` | `5d7be43f8b9dec0eb47e245cfab81108bb131273` |
| uhttpd | `uhttpd 2026.06.16~7b1bec45-r1` | `https://git.openwrt.org/project/uhttpd.git` | `7b1bec45826bd78c8afc993435bdc0f1df2fe399` |
| ucode | `ucode 2026.01.16~85922056-r1` | `https://github.com/jow-/ucode.git` | `85922056ef7abeace3cca3ab28bc1ac2d88e31b1` |
| LuCI | `luci-base 26.180.75667~128a781` | luci feed | `128a7812f4be233c5dd7f7466f534fd888785caf` |

九个独立组件 repo 已在服务器 evidence 中固定到表中 commit，并逐个通过 detached-HEAD 和
`git fsck --connectivity-only` 检查。LuCI 使用已验证的 feed checkout。

### Build/package 约束摘要

- procd：LTO、PIE，目标安装 jail/seccomp/utrace 支持；
- ubus：LTO、PIE，ABI `20251202`；
- uci：ABI `20250120`；
- rpcd：PIE、`-lcrypt`，目标安装 file/iwinfo/luci/rpcsys/rrdns/ucode plugins；
- netifd：LTO、`libnl-tiny`、`-DDEBUG=1`；
- firewall4：不编译 C，安装上游 ucode/template `root/*`；
- odhcpd：目标是 `ipv6only`，启用 ubus、未编译 `DHCPV4_SUPPORT`；
- uhttpd：只安装 ubus plugin，不安装 Lua/ucode plugin；
- ucode：ABI `20230711`，应用 5 个 OpenWrt patches；
- LuCI：目标是 ucode CGI + rpcd backend；`luci-base` 设置 no-LTO。

除 ucode 外，上述 buildroot package 目录没有 package-level patches。ucode patches 覆盖旧
kernel include、uloop environment/setup callback 和 ubus ownership/refcount；精确名称及影响见
[SOURCE_EXPECTATIONS.md](SOURCE_EXPECTATIONS.md)。target kernel/driver patch 的全量物料映射
属于 I0.4，不被伪装成已经完成。

## 5. 源码恢复出的接口边界

I0.2 已定位并登记：

- procd 的 PID1 状态机，以及 `service`、`container`、`system` ubus objects；
- ubusd socket、ACL、protocol handlers 和 status taxonomy；
- UCI 的 load/save/commit/revert/delta 语义；
- rpcd 的 session、UCI、rc、file、rpc-sys、iwinfo、LuCI/rrdns/ucode plugins 和 ACL；
- netifd 的 `network`、`network.device`、`network.interface` objects/events；
- fw4 的 UCI/ubus/template/nft 调用链、lock/state 和 fail-before-apply 检查；
- `odhcpd-ipv6only` 的 IPv6 lease/RA methods 和 netifd subscription；
- uhttpd `/ubus` proxy，以及 LuCI 通过 executable ucode CGI 而非 uhttpd ucode plugin 进入；
- 配置 consumer/writer、主要生成文件、caller graph 和组件级 failure boundary。

完整方法表、调用图和下一阶段问题单见
[SOURCE_EXPECTATIONS.md](SOURCE_EXPECTATIONS.md)。这些是源码预期；运行对象、payload、时序、
故障恢复和第三方 caller 仍要由 I0.5–I0.7 处理。

## 6. I0.2 退出门评估

| 退出条件 | 结果 | 依据 |
|---|---|---|
| buildroot、feeds、首批组件使用不可变标识 | 通过 | tag object/commit/tree、5 feed commits、9 component commits 均固定并校验 |
| device profile/layout 唯一 | 通过 | 四方部署身份和源码均选择 stock；`ubootmod` 显式排除 |
| revision string 未冒充 tag commit | 通过 | `f0a60eee...` 与 `f5dae5ec...` 分别登记 |
| 形成下一阶段定向检查清单 | 通过 | device、installed surface、IPC/caller/failure/generator 清单已写入两份报告 |
| 未以 `main` 冒充目标版本 | 通过 | 所有源码 checkout detached 到发布/buildinfo 指定对象 |

因此 I0.2 完成。它的完成不代表 I0.3/I0.4/I0.5 完成，也不授权运行态或设备写入。

## 7. 转交下一阶段

I0.3/I0.4 接收以下确定输入：

1. stock tar/FIT/SquashFS 和 DTB expected values；
2. 159-package APK database；
3. 上表 component/package/install/patch expectation；
4. 应存在/不应存在的 modules、scripts、ACL、configs 和 CGI/plugin 路径；
5. device/profile 与 `ubootmod` 冲突检查；
6. package → recipe → source → installed file 的待完成全量映射。

I0.5 接收 [SOURCE_EXPECTATIONS.md](SOURCE_EXPECTATIONS.md) 中的方法/调用图，继续提取逐方法
schema、init lifecycle、事件 payload、reload/rollback 与部分失败语义。I0.6 只为静态证据
无法回答的动态问题设计只读观测。

机器可读版本见
[`source-baseline.json`](../../manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json)。
