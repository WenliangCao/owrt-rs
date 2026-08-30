# L0：执行计划前置探索报告

> 状态：完成（方法与环境探索）
> 证据截止：2026-08-30
> 物理设备状态：未连接、未读取、未修改
> 目标固件状态：AX3000T stock / OpenWrt 25.12.5 已确认并完成 I0.1

## 1. L0 的目的

L0 不决定要重写哪个 OpenWrt 组件。它只回答以下问题：

1. 新项目目前拥有什么可靠输入；
2. 在哪里执行镜像分析；
3. 需要哪些工具和安全边界；
4. OpenWrt 官方发布物如何建立来源和源码映射；
5. 能否先从官方源码恢复已有实现，再用真实镜像验证部署事实；
6. 后续执行计划能否建立在可复核证据上，而不是停留在架构猜测。

L0 最初使用一份非目标的公开 OpenWrt 镜像验证分析方法。L0 完成后，用户提供了精确目标
身份，目标固件已另行进入 I0；两者的 evidence 目录和结论保持分离。

## 2. 明确排除项

- 不把相邻旧仓库的代码、ADR、组件划分、目标设备、版本选择或阶段结论带入本项目。
- 不因为旧仓库曾选择某种 sidecar、FFI、事务或网络模型，就认为本项目也应如此。
- 不把方法验证用的公开镜像当作目标样本。
- 不连接路由器，不执行运行态命令，不读取或写入 NAND/MTD/UBI。
- 不安装、停止、重启或清理远端服务器上已有的服务和容器。

旧仓库唯一提供的教训是：没有从实际镜像和对应源码出发时，代码量和测试数量不能证明
设计方向正确。

## 3. 仓库现状

探索开始时，新仓库只有一个提交：

```text
37d6f18 Initialize evidence-first OpenWrt control-plane project
```

当时仓库只有：

```text
.gitignore
AGENTS.md
README.md
docs/IMAGE_INTAKE.md
```

已确认：

- 没有远端仓库；
- 没有其他分支或 tag；
- 没有隐藏的实现历史；
- 没有 Rust workspace；
- 没有目标镜像、解包结果或设备 dump；
- Git 工作树在探索开始时干净。

因此，本项目可以从证据模型开始，不需要兼容仓库内既有实现。

## 4. 目标输入发现与后续接收

在以下位置按文件名查找过 OpenWrt 镜像和伴随构建材料：

- 当前仓库；
- 本机相邻项目目录；
- 本机 Downloads；
- 远端分析主机的用户目录，排除本次方法验证目录。

L0 本地搜索发现的文件均属于旧项目的通用 QEMU/SDK 实验，不是可以证明实际装机状态的
目标设备镜像。因此当时没有从磁盘取得：

- 实际安装使用的 sysupgrade 镜像；
- 首次迁移使用的 factory/initramfs 镜像；
- 与实际装机镜像同次构建的完整 metadata；
- 能证明目标设备型号、profile 和当前版本的脱敏记录。

随后用户明确提供并确认：

```text
device: Xiaomi Mi Router AX3000T
compatible: xiaomi,mi-router-ax3000t
layout: stock
release: OpenWrt 25.12.5
revision: r33051-f5dae5ece4
target: mediatek/filogic
kernel: 6.12.94
image: openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin
sha256: a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea
```

该官方文件和同次 build metadata 已下载到仓库外 evidence 目录；签名清单、实算 hash、
`profiles.json` 和 `fwtool` metadata 四方一致。I0.1 结果见
[`IMAGE_IDENTITY.md`](../reports/ax3000t-stock-openwrt-25.12.5/IMAGE_IDENTITY.md)。

## 5. 分析环境

### 5.1 本机

本机是 Apple Silicon macOS 27.0。具备哈希、归档、压缩、Python、`file`、`jq` 和基础
二进制查看工具，但缺少或未直接暴露以下关键能力：

- SquashFS 提取；
- UBI/UBIFS 离线解析；
- U-Boot FIT/image 工具；
- Device Tree 编译/反编译；
- QEMU system/user emulation；
- Linux ELF `readelf` 工具链。

本机适合编辑、审查和保存 Git 历史，不适合作为固件解剖结果的唯一执行环境。

### 5.2 远端分析主机

项目已复制到：

```text
/home/ubuntu/owrt-control-plane-rs
```

复制后校验了 Git HEAD、tree hash 和 `git fsck`。本地副本仍保留，不执行破坏性“搬走”。

主机身份实测为：

| 项目 | 实测值 |
|---|---|
| 主机名 | `instance-20260123-1135` |
| OS | Ubuntu 24.04.4 LTS |
| Kernel | Linux 6.17 Oracle，aarch64 |
| CPU | 4 vCPU |
| 内存 | 23 GiB，无 swap |
| 可用磁盘 | 约 127 GiB |

用户提供的系统版本是 Ubuntu 22.04.5，和实测的 24.04.4 不一致。以后所有工具锁和复现
记录使用实测值。

远端已有运行中的 Web、认证、密码库和其他容器服务。因此分析任务必须：

- 不占用宿主端口；
- 不执行 `docker system prune` 或清理已有 image/volume/network；
- 不停止或重启既有容器；
- QEMU 默认最多使用 2 vCPU 和 4 GiB 内存；
- 长任务使用明确超时，不能依赖无 swap 的主机承受失控内存增长。

### 5.3 已验证工具

| 能力 | 工具 | 实测状态 |
|---|---|---|
| 哈希 | `sha256sum`、OpenSSL | 可用 |
| 文件识别 | `file` | 可用 |
| 归档/压缩 | tar、cpio、gzip、xz、zstd | 可用 |
| SquashFS | `unsquashfs` 4.6.1 | 可用 |
| U-Boot/FIT | `dumpimage` 2025.10 | 可用 |
| Device Tree | `dtc` 1.7.0、`fdtdump`、`fdtget` | 可用 |
| MTD/UBI 基础工具 | mtd-utils 2.2.0 | 可用，但不能代替 raw UBI 离线解析器 |
| ELF | GNU `readelf`、`objdump`、`nm`、`strings` | 可用 |
| 模拟 | QEMU 8.2.2 system/user | 可用 |
| 容器 | Docker 29.7.2 | 可用，宿主已有生产服务 |
| 脚本检查 | ShellCheck 0.9.0 | 可用 |
| UBIReader | `ubireader_*` | 缺失 |
| 通用扫描提示 | binwalk | 缺失；只应作为提示工具，不作结构权威 |

## 6. 官方源码与镜像方法验证

### 6.1 样本边界

使用以下公开镜像验证管线：

```text
OpenWrt 25.12.5
target: mediatek/filogic
profile: abt_asr3000
image: openwrt-25.12.5-mediatek-filogic-abt_asr3000-squashfs-sysupgrade.itb
```

这只是格式 fixture。它不能证明目标设备是 ABT ASR3000、MediaTek、aarch64 或 OpenWrt
25.12.5。

所有下载和提取物位于仓库外：

```text
/home/ubuntu/owrt-evidence/l0-fixture-openwrt-25.12.5-abt-asr3000
```

### 6.2 发布物可信链

执行过以下验证：

1. 固定 OpenWrt keyring commit：
   `f0670054fd3aa9616bcd8d0d0357a1a15c65b758`；
2. 固定主密钥指纹：
   `8A8BC12F46B836C0F9CDB36F1D53D1877742E911`；
3. 使用其签名子密钥验证 `sha256sums.asc`；
4. 将镜像 SHA-256 同时与 `sha256sums` 和 `profiles.json` 比较；
5. 验证前后镜像哈希保持不变。

镜像 SHA-256：

```text
4ef34bb09adbcdc3bbccc915042f2e3701b3d1706f934b0bbbef96002afad2a5
```

该镜像有 `fwtool` metadata，但没有可提取的嵌入式 firmware signature。这证明后续流程
必须分别记录：

- 发布目录签名链；
- 镜像哈希；
- 镜像内 metadata；
- 可选的镜像内签名。

不能把任意一项存在解释成其他项也存在。

### 6.3 容器拆解

`dumpimage` 验证 FIT 内有三个 payload：

| 序号 | 名称 | 类型 | 大小 |
|---:|---|---|---:|
| 0 | `kernel-1` | gzip AArch64 Linux kernel | 5,882,549 bytes |
| 1 | `fdt-1` | DTB | 22,526 bytes |
| 2 | `rootfs-1` | SquashFS | 5,054,464 bytes |

FIT 同时给出了各 payload 的 CRC32 和 SHA-1。提取后重新计算了 SHA-256，并用 `file`、
`dtc`、`unsquashfs` 分别验证 payload 类型。

`fwtool` metadata 为：

```json
{
  "metadata_version": "1.1",
  "compat_version": "1.0",
  "supported_devices": ["abt,asr3000"],
  "version": {
    "dist": "OpenWrt",
    "version": "25.12.5",
    "revision": "r33051-f5dae5ece4",
    "target": "mediatek/filogic",
    "board": "abt_asr3000"
  }
}
```

### 6.4 SquashFS 提取的实际边界

第一次以普通用户提取时，`/dev/console` 字符设备无法创建，`unsquashfs` 返回非零状态。
后续采用两步法：

1. `unsquashfs -lln` 完整记录源文件系统，包括特殊文件；
2. 提取普通文件时排除 `dev/*`，不使用 root 权限伪造设备节点。

结果：

| 类型 | 数量 |
|---|---:|
| regular files | 881 |
| directories | 128 |
| symlinks | 213 |
| source special files | 1 (`/dev/console`) |
| installed packages | 159 |
| init scripts | 25 |
| default UCI config files | 6 |
| ELF files | 161 |
| shell scripts | 96 |
| ucode files | 43 |

这次失败说明分析工具的非零退出不能被统一忽略。特殊文件、xattr、ownership 和 capability
需要独立列清单；“目录看起来解出来了”不等于完整提取成功。

### 6.5 软件物料来源

该样本使用 APK，权威安装数据库位于：

```text
/lib/apk/db/installed
/etc/apk/world
/lib/apk/packages/*.list
```

从数据库可以取得包名、版本、架构、依赖、license、source origin 和文件清单。不能只用
target 级 manifest 替代镜像内安装数据库，因为 target manifest、profile defaults、
device packages 和实际 rootfs 可能处于不同粒度。

旧版 OpenWrt 仍可能使用 `/usr/lib/opkg/status`，后续工具必须根据镜像事实分流，不能把
APK schema 写死为唯一格式。

### 6.6 镜像到源码的映射

官方发布目录提供了：

- `profiles.json`；
- `sha256sums` 及签名；
- `version.buildinfo`；
- `feeds.buildinfo`；
- `config.buildinfo`；
- target manifest；
- CycloneDX BOM；
- SDK、ImageBuilder 和 toolchain。

样本对应 release tag：

```text
tag object: e20bc3ec9eb9e3dbd0519ddc18f81f3eedc0f45e
tag commit: f0a60eee2fe051741c643ea6118718aae1ef17fb
image revision string: r33051-f5dae5ece4
```

tag commit 和 image revision string 不相同，但 tag 源码中的 `include/version.mk` 明确把
`VERSION_CODE` 定义为后者。因此源码身份必须同时保存 tag、tag object、commit 和镜像
revision，不能假设 revision 后缀就是 release tag commit。

样本 profile 可精确映射到：

```text
target/linux/mediatek/image/filogic.mk
target/linux/mediatek/dts/mt7981b-abt-asr3000.dts
```

镜像实际结构和 source recipe 一致：recipe 声明 gzip kernel、外置 rootfs FIT、DTB 和
`append-metadata`。

核心包的镜像版本也能映射到 release source tree 中的 package recipe：

| 包 | 镜像版本 | package recipe source revision |
|---|---|---|
| procd | `2026.03.13~58eb263d-r1` | `58eb263d5abe03f8c1280bdfa65a3b052614215d` |
| ubus/ubusd | `2026.06.28~24864e78-r2` | `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` |
| uci | `2025.12.02~66127cd7-r1` | `66127cd76c5d0bd46d5a90302cc6110f53a4e2f8` |
| rpcd | `2026.06.04~28faf640-r1` | `28faf6403792d25b9826043aaf37880624c19568` |
| netifd | `2026.02.26~cbb83a18-r1` | `cbb83a1857407a28a63dc09412a1f209195914ef` |
| firewall4 | `2025.03.17~b6e51575-r2` | `b6e5157527d361f99ad52eaa6da273cb0f2dfd59` |
| odhcpd | `2026.06.29~5d7be43f-r1` | `5d7be43f8b9dec0eb47e245cfab81108bb131273` |

这验证了后续正确的源码链：

```text
镜像安装数据库
  → OpenWrt package recipe
  → PKG_SOURCE_VERSION / upstream release
  → OpenWrt patches
  → build flags
  → 镜像内文件和运行接口
```

### 6.7 AX3000T 官方源码先行验证

用户提供的对话提出了一个正确的路线修正：AX3000T 不是只能当作黑盒固件研究。L0 随后
直接核对了 OpenWrt 官方仓库，而不是把该对话本身当作证据。

OpenWrt 25.12.5 匹配源码树明确包含两个不同部署 profile：

| profile | 含义 | 镜像路径 |
|---|---|---|
| `xiaomi_mi-router-ax3000t` | 小米原厂 boot/分区布局 | `sysupgrade.bin` |
| `xiaomi_mi-router-ax3000t-ubootmod` | OpenWrt U-Boot 布局 | `sysupgrade.itb` |

官方源码已经提供：

- `target/linux/mediatek/image/filogic.mk` 中的设备 package、NAND block/page 参数、镜像流水线和 boot artifact；
- `target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t.dts` 中的 stock 分区布局；
- `target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t-ubootmod.dts` 中的 OpenWrt U-Boot/UBI/FIT 布局；
- 公共 DTSI 中的 SoC、内存、交换机、端口、LED、按键、Wi-Fi 校准区和只读分区定义；
- `package/boot/uboot-mediatek/Makefile` 中的 AX3000T U-Boot 构建目标；
- `feeds.conf.default` 中 LuCI、packages、routing 等官方独立 feed 的来源。

因此，后续不应从 `binwalk` 输出反推设计。正确顺序是：

```text
目标固件的最小身份信息
  → 锁定匹配 release/tag、feeds 和组件 revision
  → 阅读设备 DTS、镜像 recipe、target overlay 和 package source
  → 从源码导出预期结构、接口、调用者和失败路径
  → 用实际镜像验证哪些内容真的被构建和部署
  → 用脱敏运行态裁决动态行为与歧义
```

“源码公开”仍不能把实际镜像从证据链中删除。`main` 可能已经偏离装机版本；官方 profile
默认包不等于实际 rootfs；自定义 build 还可能改变 feeds、patch、`.config`、包选择和生成
配置。镜像分析因此从“黑盒逆向”降级为“部署一致性验证和差异发现”。

目标现已确认是 `xiaomi,mi-router-ax3000t` stock profile。`-ubootmod` profile、其单一 UBI/FIT
布局和 `.itb` sysupgrade 均已明确排除。

## 7. L0 得出的计划约束

1. 必须先取得最小部署身份并验证发布物；不处理未验证字节。
2. 身份确定后先锁定匹配源码，再从源码产生预期结构和接口清单。
3. 只按 source recipe 对镜像做定向验证；通用扫描器只能发现未解释区域。
4. 输入文件始终只读，提取到新的 evidence work 目录。
5. 每一段 payload 单独记录 offset/index、长度、内部校验和和 SHA-256。
6. 文件系统清单必须先于提取，特殊文件和提取失败单独记录。
7. 软件物料以镜像内 package DB 为主，发布 manifest/BOM 用于交叉验证。
8. release tag、image revision、feeds commits 和组件 source revision 分别锁定。
9. 静态 init script 只能证明声明的行为；实际 ubus object、服务实例和生成配置仍需运行态。
10. 不得从通用 fixture 或 OpenWrt `main` 推断目标版本的部署事实。
11. 在完成接口、调用者、失败边界和兼容合同以前，不创建 Rust 替代组件。

## 8. L0 退出检查

- [x] 当前仓库和 Git 历史已盘点。
- [x] 旧项目被明确排除为方案来源。
- [x] 本机和远端执行环境已盘点。
- [x] 新项目已复制到远端，Git HEAD/tree/fsck 已核对。
- [x] 私有 evidence 目录和 Git 仓库分离。
- [x] 官方签名发布物验证流程已实际跑通。
- [x] FIT、kernel、DTB 和 SquashFS 拆解已实际跑通。
- [x] package DB 和 OpenWrt source revision 映射已实际跑通。
- [x] AX3000T 官方设备定义、两种布局、镜像 recipe、U-Boot target 和 feeds 已核实。
- [x] 提取特殊文件失败的处理策略已验证。
- [x] 远端共享主机资源和服务边界已记录。
- [x] 实际部署镜像身份已接收，官方文件和发布链已独立验证。

目标分析已从身份验证重新执行，没有沿用非目标 fixture 的设备结论。

## 9. 官方参考

- [OpenWrt releases](https://downloads.openwrt.org/releases/)
- [OpenWrt image formats](https://openwrt.org/docs/techref/image.format)
- [Sysupgrade technical reference](https://openwrt.org/docs/techref/sysupgrade)
- [OpenWrt `append-metadata` implementation](https://github.com/openwrt/openwrt/blob/main/include/image-commands.mk)
- [OpenWrt firmware metadata validation](https://github.com/openwrt/openwrt/blob/main/package/base-files/files/lib/upgrade/fwtool.sh)
- [OpenWrt base-files build](https://github.com/openwrt/openwrt/blob/main/package/base-files/Makefile)
- [AX3000T 25.12.5 image recipes](https://github.com/openwrt/openwrt/blob/v25.12.5/target/linux/mediatek/image/filogic.mk)
- [AX3000T 25.12.5 stock-layout DTS](https://github.com/openwrt/openwrt/blob/v25.12.5/target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t.dts)
- [AX3000T 25.12.5 OpenWrt U-Boot-layout DTS](https://github.com/openwrt/openwrt/blob/v25.12.5/target/linux/mediatek/dts/mt7981b-xiaomi-mi-router-ax3000t-ubootmod.dts)
- [OpenWrt 25.12.5 official feeds](https://github.com/openwrt/openwrt/blob/v25.12.5/feeds.conf.default)
