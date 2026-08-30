# AX3000T stock / OpenWrt 25.12.5：部署物静态验证

> I0.3 状态：完成
> 日期：2026-08-30
> 输入模式：只读 `0400`
> 设备访问：无

## 1. 结论

目标 `sysupgrade.bin` 通过 I0.3。它与 I0.2 固定的 stock device recipe 一致：

```text
fwtool metadata
  -> GNU/POSIX sysupgrade tar
       -> CONTROL: xiaomi_mi-router-ax3000t
       -> kernel: AArch64 Linux 6.12.94 FIT
            -> LZMA Image
            -> stock DTB
       -> root: XZ SquashFS 4.0
```

输入前后 SHA-256 一致；9,400,608 bytes 全部归属于 tar、payload、格式 header/trailer 或已
验证的零填充，unknown bytes 为 0。没有 source/image deviation，没有混入 `ubootmod`。

该结论只覆盖官方部署文件的静态结构。它不证明物理路由器当前运行该文件，也不证明 MTD、
UBI、boot slot、overlay 或服务状态。

## 2. 输入与来源门

| 项目 | 结果 |
|---|---|
| filename | `openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin` |
| length | 9,400,608 bytes |
| SHA-256 before | `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea` |
| SHA-256 after | `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea` |
| filesystem mode | `0400` |
| release signature | I0.1 已验证 `sha256sums.asc` |
| profile/metadata/hash | I0.1 已四方核对 |

一次错误的 `fwtool -i` 探测验证了权限防线：工具尝试按输出文件打开输入时被 `0400` 拒绝，
输入 length/hash 未变。之后所有输出写到独立 evidence run 目录。

## 3. Source expectation

I0.2 固定的构建路径是：

```text
Device/xiaomi_mi-router-ax3000t
  -> kernel Image, LZMA, FIT, stock DTB
  -> rootfs SquashFS
  -> scripts/sysupgrade-tar.sh
  -> fwtool append-metadata
```

使用的关键源码：

```text
target/linux/mediatek/image/filogic.mk
target/linux/mediatek/image/Makefile
include/image.mk
include/image-commands.mk
scripts/sysupgrade-tar.sh
target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t*.dts*
target/linux/mediatek/filogic/base-files/lib/upgrade/platform.sh
```

匹配 buildroot commit 为 `f0a60eee2fe051741c643ea6118718aae1ef17fb`，不能用 `main` 或
`ubootmod` recipe 替代。

## 4. 外层容器与全字节归属

### 4.1 顶层布局

| region | offset | length | 验证 |
|---|---:|---:|---|
| GNU/POSIX tar | 0 | 9,400,320 | GNU tar 1.35 parse status 0；SHA-256 `53bed6fa…a2a8a0` |
| fwtool info header | 9,400,320 | 8 | version/flags 均为 0 |
| metadata JSON | 9,400,328 | 264 | SHA-256 `b716a46d…f9b2` |
| fwtool trailer | 9,400,592 | 16 | magic `FWx0`、type INFO、size 288、CRC `72f23d04` |

fwtool source commit 是 `04cd252e4e9394ffacd51f56f1f124abc534f715`。metadata extraction
status 为 0，CRC 验证通过。没有嵌入 firmware signature chunk；源码只在 build key 和 ucert
均存在时条件附加它。

### 4.2 Tar byte map

| region | offset | data length | padding | data SHA-256 |
|---|---:|---:|---:|---|
| directory header | 0 | 512 | — | header |
| CONTROL header/data | 512 / 1,024 | 31 | 481 zero | `eac9cd7e…b9e1` |
| kernel header/data | 1,536 / 2,048 | 4,336,328 | 312 zero | `c20bee28…d1c6` |
| root header/data | 4,338,688 / 4,339,200 | 5,052,416 | 0 | `3f315cf6…b1cc` |
| end/record padding | 9,391,616 | 0 | 8,704 zero | — |

CONTROL 内容是 `BOARD=xiaomi_mi-router-ax3000t`。四个 tar entries 的 owner 为 0/0、mtime
为 source epoch `2026-06-29T12:59:20Z`。tar extract 后的三个文件 hash 与直接按 offset 读取
完全一致。

## 5. Kernel FIT

| 项目 | 观测 |
|---|---|
| FIT description | `ARM64 OpenWrt FIT (Flattened Image Tree)` |
| total/member size | 4,336,328 / 4,336,328 bytes；无 FIT 外 padding |
| created | `2026-06-29T12:59:20Z` |
| default configuration | `config-1` |
| configuration description | `OpenWrt xiaomi_mi-router-ax3000t` |

### kernel-1

| 属性 | 值 |
|---|---|
| description | `ARM64 OpenWrt Linux-6.12.94` |
| architecture / OS | AArch64 / Linux |
| compression | LZMA |
| compressed size | 4,307,090 bytes |
| compressed SHA-256 | `dfbdb4c21690003e466959b136b6188c554e4e9be6750f9fa4183174ac1fc98e` |
| stored/computed SHA-1 | `a422b6a6bfff051626511cdaf910bdae50365105` / 相同 |
| load / entry | `0x48000000` / `0x48000000` |
| decompressed size | 13,271,048 bytes |
| decompressed SHA-256 | `b8e5fda8bb59d20fe047e9068813e325a68cb00bf07813a7e88e82976f51dbe8` |

### fdt-1

| 属性 | 值 |
|---|---|
| description | `ARM64 OpenWrt xiaomi_mi-router-ax3000t device tree blob` |
| size | 27,827 bytes |
| SHA-256 | `adcd474fcad52f62b210e87bcbc97b6f6486810d1807e7728fca6c247989faf0` |
| stored/computed SHA-1 | `13b5a711a2ab5deb4474ead2bbc44870cbc28c50` / 相同 |
| compression | none |

`dumpimage` 需要显式 `-T flat_dt` 才能提取 FIT subimages。首次省略该参数的失败已登记；成功
结果只来自修正后的运行。

## 6. DTB 与 exact source

DTB 可由 dtc 1.7.0 确定性反编译；再次反编译的 SHA-256 仍为
`10260a8001b89f8bdcaa66d3ef2eb4193507c0afcf1737b2f1636e5acf63f64b`。

设备层 148 项语义检查全部通过，覆盖：

- model、compatible、serial/LED aliases、`stdout-path=serial0:115200n8`；
- 256 MiB memory；mesh/reset keys；蓝/黄 status LEDs；
- watchdog、UART0、I2C0、SPI0、Ethernet、Wi-Fi 的 `status=okay`；
- I2C NFC `nt082c@57` 和 pinctrl；
- SPI NAND calibration、52 MHz、quad bus、NMBM/BMT 参数；
- 10 个 partition 的 label/reg/read-only；
- Factory EEPROM/MAC nvmem layout 和 consumer phandle；
- GMAC 2.5G fixed link；MT7531 与 AN8855 两套 source-declared switch nodes；
- WAN、lan2、lan3、lan4/cpu port labels；
- AN8855 16 个 efuse TX calibration cells；
- MT7981 Wi-Fi EEPROM reference。

decompiled tree 有 166 个 node lines 和 935 个 property lines。设备定义没有
`xiaomi,mi-router-ax3000t-ubootmod`、单 UBI 或 ubootmod artifact 属性。

dtc 同时报告 3 条 common SoC tree warning，已完整登记在
[SOURCE_IMAGE_DEVIATIONS.md](SOURCE_IMAGE_DEVIATIONS.md)，没有被隐藏或升级为未经证明的运行
故障。

分区细节见 [PARTITION_EXPECTATION.md](PARTITION_EXPECTATION.md)。

## 7. SquashFS rootfs

### 7.1 Superblock

| 属性 | 值 |
|---|---|
| format | SquashFS 4.0 |
| tar member size | 5,052,416 bytes |
| filesystem size | 5,051,406 bytes |
| member trailing padding | 1,010 zero bytes |
| compression | XZ |
| block size | 262,144 bytes |
| creation | `2026-06-29T12:59:20Z` |
| inodes | 1,223 |
| fragments | 37 |
| IDs | 1 |
| xattrs | not stored |
| duplicate data | removed |
| NFS exportable | yes |

这与 `include/image.mk` 的默认 256 KiB squashfs block、target XZ selection、`-root-owned`、
`-no-xattrs`、`-nopad` 和 device-table `/dev/console` 预期一致。

### 7.2 Numeric inventory

| 类型 | 数量 |
|---|---:|
| directories | 128 |
| regular files | 881 |
| symlinks | 213 |
| char devices | 1 |
| block devices / FIFO / socket | 0 / 0 / 0 |

所有 1,223 entries 都是 uid/gid `0/0`，mtime 都是 source epoch。mode 分布：

| mode | 数量 |
|---|---:|
| `-rw-------` | 14 |
| `-rw-r--r--` | 693 |
| `-rwxr-xr-x` | 174 |
| `crw-------` | 1 |
| `drwxr-x---` | 1 |
| `drwxr-xr-x` | 127 |
| `lrwxrwxrwx` | 213 |

没有 setuid、setgid、sticky bit。superblock 不存储 xattrs，提取树的 `getcap -r` 也返回零
entries，因此没有 file capability。

唯一特殊节点是 `/dev/console`，mode 0600、uid/gid 0/0、major/minor 5:1。它来自 source
`SQUASHFSOPT` device table，并在普通用户提取时被主动排除。

### 7.3 安全提取完整性

最终提取树为 881 files、128 directories、213 symlinks，恰好等于 image inventory 扣除
`/dev/console` 后的集合。两次早期特殊节点排除参数错误均以非零结束，未用于统计；详见偏差
报告。解包目录和可能敏感的 rootfs 内容未进入 Git。

机器可读摘要见
[`filesystem.json`](../../manifests/ax3000t-stock-openwrt-25.12.5/filesystem.json)。完整 numeric
inventory 只保存在 private evidence，其 SHA-256 是
`af940a8b8a4a003858a63f13e623d72200fe80321c4ac67cab078fa054c7fc37`。

## 8. 工具与可复核记录

分析在当前服务器 Ubuntu 24.04.4 LTS aarch64 环境执行：

| tool | version/identity |
|---|---|
| `file` | 5.45 |
| GNU tar | 1.35 |
| dumpimage | 2025.10 |
| dtc | 1.7.0 |
| unsquashfs | 4.6.1 |
| sha256sum | GNU coreutils 9.4 |
| fwtool | source `04cd252e4e9394ffacd51f56f1f124abc534f715` |

关键 private run artifacts 的 hashes 已写入
[`payloads.json`](../../manifests/ax3000t-stock-openwrt-25.12.5/payloads.json)。Git 只保存无秘密的
manifest 和派生报告，不保存 firmware、kernel、DTB、rootfs 或完整 inventory。

## 9. Expected / observed / delta 总表

| 层 | expected | observed | delta |
|---|---|---|---|
| outer | sysupgrade tar + metadata | exact recipe | 无 |
| identity | stock board/profile | CONTROL/metadata/DTB 四方一致 | 无 |
| kernel | ARM64 Linux 6.12.94 LZMA FIT | hash/size/version/address 一致 | 无 |
| DTB | exact stock DTS/DTSI | 148/148 device checks | 无；3 条 common-tree warning |
| partitions | 10 fixed partitions、双 UBI 区 | 10/10 完全一致 | 无 |
| rootfs | XZ SquashFS、256 KiB block | 完全一致 | 无 |
| filesystem attributes | root-owned、no-xattrs、console 5:1 | 完全一致 | 无 |
| trailing bytes | format/member padding | 全为零且全部归属 | 无 |

完整分类见 [SOURCE_IMAGE_DEVIATIONS.md](SOURCE_IMAGE_DEVIATIONS.md)。

## 10. I0.3 退出门

| 退出条件 | 结果 |
|---|---|
| 输入 hash 前后不变 | 通过 |
| 所有字节已解释 | 通过：unknown bytes 0 |
| kernel、DTB、rootfs 独立 hash/type 验证 | 通过 |
| source recipe 与 container/payload 一致 | 通过 |
| DTB device expectation 全量验证 | 通过：148/148 |
| owner/mode/xattr/capability/setid/special nodes 登记 | 通过 |
| parser warning 与失败均进入报告 | 通过 |
| 分区未冒充物理 runtime layout | 通过 |
| firmware/extracted content 未进入 Git | 通过 |

I0.3 完成。I0.4 随后已经在这份结构上完成 159-package、ELF、service、权限和
package/source/file ownership 映射，见 [SBOM.md](SBOM.md) 与
[SOURCE_MAP.md](SOURCE_MAP.md)。这些静态阶段均不授权设备访问或实现替代组件。
