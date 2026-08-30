# AX3000T stock / OpenWrt 25.12.5：设备构建配方

> I0.2 状态：完成
> 日期：2026-08-30
> 证据边界：本报告描述匹配源码中的构建/升级实现，以及镜像已经验证的静态结果；不代表
> 物理设备当前的 flash、U-Boot 环境或运行状态。

## 1. 固定目标

| 项目 | 唯一值 |
|---|---|
| 设备 | Xiaomi Mi Router AX3000T |
| image profile | `xiaomi_mi-router-ax3000t` |
| DT compatible | `xiaomi,mi-router-ax3000t` |
| 布局 | stock |
| target/subtarget | `mediatek/filogic` |
| OpenWrt | `25.12.5` / `r33051-f5dae5ece4` |
| buildroot commit | `f0a60eee2fe051741c643ea6118718aae1ef17fb` |
| image revision commit | `f5dae5ece4805730c5e2850f8aa84765af2f6b32` |
| kernel | `6.12.94` |
| 架构 | AArch64 / `aarch64_cortex-a53` |
| 目标 artifact | `openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin` |
| artifact SHA-256 | `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea` |

源码入口：

```text
target/linux/mediatek/image/filogic.mk
target/linux/mediatek/image/Makefile
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t.dts
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t.dtsi
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-common.dtsi
target/linux/mediatek/filogic/base-files/lib/upgrade/platform.sh
target/linux/mediatek/filogic/base-files/etc/init.d/bootcount
target/linux/mediatek/filogic/base-files/etc/board.d/02_network
target/linux/mediatek/filogic/base-files/etc/board.d/01_leds
```

## 2. Profile 唯一性与排除项

匹配源码同时存在 stock 与 `ubootmod` 两套 AX3000T 配方，但它们不是可互换的文件名变体。

| 特征 | stock：本项目目标 | `ubootmod`：明确排除 |
|---|---|---|
| profile | `xiaomi_mi-router-ax3000t` | `xiaomi_mi-router-ax3000t-ubootmod` |
| compatible | `xiaomi,mi-router-ax3000t` | 带 `-ubootmod` 的独立设备定义 |
| flash 布局 | `ubi_kernel` + `ubi` | U-Boot-modified 单 UBI/FIT 布局 |
| kernel-in-UBI | 否 | 是 |
| U-Boot env-in-UBI | 否 | 是 |
| sysupgrade artifact | tar 型 `.bin` | `.itb` |
| upgrade checker | `nand_do_platform_check` | `fit_check_image` |

镜像 metadata、`profiles.json`、tar 的 `CONTROL` 与 FIT 内 DTB 均选择 stock 行。排除的
`ubootmod` artifact SHA-256 是
`ff34acec7a915e0ccf47fb7a1a156e0042194e02c0ae3c4f404911b447ec36d3`。

## 3. 构建参数与 artifact 管线

### 3.1 设备 recipe

`Device/xiaomi_mi-router-ax3000t` 的设备级参数为：

```text
DTS: mt7981b-xiaomi-mi-router-ax3000t
NAND erase block: 128 KiB
NAND page: 2 KiB
UBINIZE_OPTS: -E 5
DEVICE_PACKAGES:
  kmod-mt7915e
  kmod-mt7981-firmware
  mt7981-wo-firmware
IMAGE/sysupgrade.bin: sysupgrade-tar | append-metadata
```

只有选择 initramfs 构建时才生成用于首次迁移的 factory UBI；本项目固定的日常升级输入是
stock `squashfs-sysupgrade.bin`，不是 factory/initramfs，也不是 `.itb`。

### 3.2 Kernel 与 rootfs

Filogic 的通用 kernel pipeline 将 AArch64 `Image` 以 LZMA 压缩，和设备 DTB 一起封装为 FIT；
load address 为 `0x48000000`。目标 rootfs 是 XZ SquashFS。

### 3.3 已部署静态结果

镜像读取结果与源码预期相符：

| sysupgrade tar 成员 | 字节数 | SHA-256 | 解释 |
|---|---:|---|---|
| `CONTROL` | 31 | `eac9cd7ec16d41df0afeb935a037e44f57fb9dc83e8d9662bd74a543cb70b9e1` | `BOARD=xiaomi_mi-router-ax3000t` |
| `kernel` | 4,336,328 | `c20bee280c72744dd203a1832c968156480da6b6f92c210d295fd8c63940d1c6` | Linux 6.12.94 FIT |
| `root` | 5,052,416 | `3f315cf686c9cd951b24881a3a8e0c78448acaad6fd20d2ab6f1003a0e85b1cc` | XZ SquashFS |

最外层还附有 `fwtool` metadata 1.1；compat version 为 1.0，supported device 只包含
`xiaomi,mi-router-ax3000t`。

## 4. DTS 导出的硬件和存储预期

### 4.1 固定分区

| label | offset | size | source 属性/用途 |
|---|---:|---:|---|
| `BL2` | `0x0000000` | `0x0100000` | read-only |
| `Nvram` | `0x0100000` | `0x0040000` | Xiaomi/U-Boot 状态 |
| `Bdata` | `0x0140000` | `0x0040000` | board data、MAC 来源 |
| `Factory` | `0x0180000` | `0x0200000` | read-only；EEPROM/MAC nvmem |
| `FIP` | `0x0380000` | `0x0200000` | read-only boot firmware |
| `crash` | `0x0580000` | `0x0040000` | read-only |
| `crash_log` | `0x05c0000` | `0x0040000` | read-only |
| `ubi_kernel` | `0x0600000` | `0x2200000` | stock kernel UBI 区 |
| `ubi` | `0x2800000` | `0x4e00000` | stock rootfs/data UBI 区 |
| `KF` | `0x7600000` | `0x0040000` | read-only |

SPI NAND 使用 quad I/O、52 MHz，并由 NMBM 管理。表格是 DTS/DTB 预期，不是设备上的
`/proc/mtd` 观测；实际 erase counter、坏块、volume、active slot 和环境变量仍未知。

### 4.2 其他设备约束

- 256 MiB memory；
- console：`serial0`，`115200n8`；
- 蓝/黄 status LED；
- reset 与 mesh 按键；
- MT7981 Wi-Fi 从 `Factory` nvmem 读取 EEPROM；
- DSA port label 为 `wan`、`lan2`、`lan3`、`lan4`。

默认 board network 把 `lan2 lan3 lan4` 组成 LAN，把 `wan` 设为 WAN；WAN MAC 来自
`Bdata`。这些是 board-default 生成规则，不能替代设备上现有 `/etc/config/network`。

## 5. Upgrade、首次迁移与 boot flag

### 5.1 正常 stock sysupgrade

目标 profile 的正常流程是：

```text
platform_check_image
  -> nand_do_platform_check

platform_do_upgrade
  -> CI_KERN_UBIPART=ubi_kernel
  -> CI_ROOT_UBIPART=ubi
  -> nand_do_upgrade
```

兼容性要求：任何未来 package 或控制面都不能把 stock artifact 交给 `fit_check_image`，不能把
kernel/root 合并为 `ubootmod` 单 UBI，也不能把 `.itb` 当作本设备的 sysupgrade 输入。

### 5.2 `xiaomi_initial_setup` 是破坏性边界

源码将 `xiaomi_initial_setup()` 限制在 `rootfs_type=tmpfs` 的 initramfs 环境。该分支会格式化
`ubi_kernel` 与 `ubi`，并写 U-Boot 环境/mtdparts；它是从厂商布局迁移到 OpenWrt stock
布局的初始化路径，不是普通升级步骤。

本项目未执行、也未授权执行该函数。未来如需首次迁移，必须另建物理恢复 gate、确认设备
精确状态并取得单独授权。

### 5.3 `bootcount`

`bootcount` init service 会根据 U-Boot 环境区分 Xiaomi RD03/RD23 路径，并可能更新启动
成功/失败 flag。当前只证明该脚本存在于目标源码/镜像；未读取设备 U-Boot env，不能判断
当前 active slot、boot counter 或实际走过的型号分支。

## 6. Package 与 blob 边界

设备 recipe 显式增加三个无线相关 package：

| package | 分类 | I0.2 处理 |
|---|---|---|
| `kmod-mt7915e` | 开源 kernel driver 模块 | 保留；属于成熟执行面/驱动面 |
| `kmod-mt7981-firmware` | 固件装载配套 | blob 边界，不等于控制面不可研究 |
| `mt7981-wo-firmware` | Wi-Fi offload firmware | blob 边界，默认保留 |

闭源或不可审计 firmware blob 与其外围的 OpenWrt 配置、netifd/hostapd/ubus 接口是不同
边界。I0.2 不以 blob 的存在为理由重写 driver，也不以 driver 保留为理由跳过外围接口调查。

## 7. 下一阶段定向检查表

I0.3/I0.4 必须用部署物验证以下预期：

- [x] sysupgrade 外层是 tar 并附 metadata，而不是 `.itb`；
- [x] tar 的 board、kernel、root 成员和 hash 已记录；
- [x] FIT compatible 为 stock，kernel 为 6.12.94；
- [x] DTB 中 `ubi_kernel` 与 `ubi` offset/size 匹配源码；
- [x] rootfs 为 XZ SquashFS；
- [x] 镜像 package DB 包含三个 device package；
- [ ] 完整比较 DTB chosen、LED、keys、Ethernet、Wi-Fi/nvmem 和所有 status 属性；
- [ ] 验证所有分区、NMBM 参数及 DTB/source 的 expected/observed/delta；
- [ ] 将 kernel modules 与 firmware 文件归属到精确 package；
- [ ] 在获得运行态只读授权后，才比较真实 `/proc/mtd`、UBI volume 和 board name；
- [ ] 不读取或更改 U-Boot env、flash、MTD/UBI，除非另有明确授权和恢复 gate。

## 8. 结论

设备定义不存在未决分叉：后续工作只能以 stock profile、stock DTS、tar sysupgrade 和双 UBI
区域的源码路径为基线。`ubootmod` 配方仅作为冲突检测用的反例，不得进入实现、测试 fixture
或升级逻辑。
