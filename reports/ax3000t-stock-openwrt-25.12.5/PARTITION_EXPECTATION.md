# AX3000T stock / OpenWrt 25.12.5：分区预期

> I0.3 状态：完成
> 日期：2026-08-30
> 证据边界：这是 exact source + image DTB 的静态分区预期，不是设备 `/proc/mtd`、UBI volume
> 或 U-Boot environment 的运行态观测。

## 1. 结论

目标 FIT 内 DTB 与 OpenWrt 25.12.5 stock DTS 对分区的定义完全一致：共 10 个 fixed
partitions，从 offset `0x0000000` 到 `0x7640000` 连续、无重叠、无内部空洞。可升级区域是
`ubi_kernel` 与 `ubi`；这与 stock `nand_do_upgrade()` 配方一致。

该结论排除 `xiaomi_mi-router-ax3000t-ubootmod` 的单 UBI/FIT 布局，但不能证明物理 NAND
容量、坏块映射、NMBM runtime mapping、UBI volume、active slot 或 boot flags。

## 2. 来源

精确源码：

```text
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t.dts
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t.dtsi
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-common.dtsi
target/linux/mediatek/filogic/base-files/lib/upgrade/platform.sh
```

部署证据：

```text
FIT fdt-1 size: 27,827 bytes
DTB SHA-256: adcd474fcad52f62b210e87bcbc97b6f6486810d1807e7728fca6c247989faf0
compatible: xiaomi,mi-router-ax3000t; mediatek,mt7981
```

DTB 对设备层执行了 148 项语义断言，其中包含全部 10 个 partition 的 label、reg 和
read-only 属性；结果全部通过。

## 3. Source / observed / delta

| label | source offset | source size | DTB observed | read-only | delta |
|---|---:|---:|---|---:|---|
| `BL2` | `0x0000000` | `0x0100000` | `0x0000000 + 0x0100000` | 是 | 无 |
| `Nvram` | `0x0100000` | `0x0040000` | `0x0100000 + 0x0040000` | 否 | 无 |
| `Bdata` | `0x0140000` | `0x0040000` | `0x0140000 + 0x0040000` | 否 | 无 |
| `Factory` | `0x0180000` | `0x0200000` | `0x0180000 + 0x0200000` | 是 | 无 |
| `FIP` | `0x0380000` | `0x0200000` | `0x0380000 + 0x0200000` | 是 | 无 |
| `crash` | `0x0580000` | `0x0040000` | `0x0580000 + 0x0040000` | 是 | 无 |
| `crash_log` | `0x05c0000` | `0x0040000` | `0x05c0000 + 0x0040000` | 是 | 无 |
| `ubi_kernel` | `0x0600000` | `0x2200000` | `0x0600000 + 0x2200000` | 否 | 无 |
| `ubi` | `0x2800000` | `0x4e00000` | `0x2800000 + 0x4e00000` | 否 | 无 |
| `KF` | `0x7600000` | `0x0040000` | `0x7600000 + 0x0040000` | 是 | 无 |

静态定义区总长为 `0x7640000`（123,994,112 bytes）。不能用这个末端位置反推物理 NAND
一定是 128 MiB；DTS 没有在本表中描述的尾部，以及 NMBM 保留空间，需要设备运行态和 NAND
几何信息才能解释。

## 4. 存储控制器与 NMBM

DTB 与 source 都声明：

```text
controller: SPI NAND
spi-max-frequency: 52,000,000 Hz
tx/rx bus width: 4
mediatek,nmbm: present
bmt-max-ratio: 1
bmt-max-reserved-blocks: 64
bmt-mtd-overridden-oobsize: 64
device recipe erase block: 128 KiB
device recipe page: 2 KiB
UBINIZE_OPTS: -E 5
```

NMBM 会在 raw NAND 与上层 MTD 之间建立映射。因此即使未来只读观察 `/proc/mtd`，也不能
把逻辑 offset 直接当作物理 page/block 地址，更不能在没有恢复 gate 时读取或写入 raw MTD。

## 5. 校准与 MAC 数据边界

`Factory` 是 read-only，并包含 fixed nvmem layout：

| cell | offset/size | consumer |
|---|---|---|
| `eeprom@0` | `0x0 + 0x1000` | MT7981 Wi-Fi `eeprom` |
| `macaddr@4` | `0x4 + 0x6` | GMAC `mac-address`，使用 offset argument `-2` |

DTB 中 consumer phandle 与 source 完全一致。报告只记录布局和引用，不读取 EEPROM、MAC、
校准数据或任何设备秘密。

## 6. Upgrade 关联

stock upgrade source 明确设置：

```text
CI_KERN_UBIPART=ubi_kernel
CI_ROOT_UBIPART=ubi
nand_do_upgrade <stock sysupgrade tar>
```

`platform_check_image()` 对 stock profile 使用 `nand_do_platform_check()`。以下行为均不兼容：

- 把 `.itb` 当作 stock sysupgrade；
- 走 `ubootmod` 的 `fit_check_image()`；
- 把 kernel/root 合并到 `ubootmod` 单 UBI；
- 把 `xiaomi_initial_setup()` 当作普通升级；
- 在未知 active slot、boot flags 或恢复能力时写 `Nvram`/`Bdata`/UBI。

`xiaomi_initial_setup()` 会格式化 `ubi_kernel` 和 `ubi` 并写 U-Boot environment，只允许在
initramfs/tmpfs 首次迁移语境中考虑。I0.3 没有执行或授权该路径。

## 7. 仍需运行态裁决的项目

- 真实 `/proc/mtd` 和 sysfs MTD 名称/size；
- NMBM 是否成功 attach、实际保留块和坏块状态；
- `ubi_kernel`、`ubi` 中的 volume 名称、大小和 active root；
- U-Boot environment、RD03/RD23 分支、boot counter 和 slot flags；
- overlay 是否已建立、当前挂载和可用空间；
- 物理 NAND 总容量以及 `0x7640000` 之后空间的实际含义。

这些问题进入 I0.6，且任何 collector 都要先证明无写入副作用。当前阶段不连接路由器。

## 8. I0.3 判定

| 条件 | 结果 |
|---|---|
| source 与 image DTB 分区数量一致 | 通过：10/10 |
| label、offset、size 一致 | 通过 |
| read-only 属性一致 | 通过 |
| 分区间 overlap/gap | 无 |
| stock upgrade UBI 名称一致 | 通过 |
| `ubootmod` 混入 | 未发现 |
| 物理布局声明 | 未声明；保留为 runtime unknown |

因此分区静态预期通过 I0.3，但不能作为物理设备写入依据。
