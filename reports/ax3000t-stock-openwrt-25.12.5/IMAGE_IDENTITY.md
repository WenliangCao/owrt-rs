# AX3000T stock / OpenWrt 25.12.5：部署身份报告

> I0.1 状态：通过（用户确认的精确官方部署镜像）
> 日期：2026-08-30
> 设备访问：无
> 原始发布物位置：Git 仓库外的服务器 evidence 目录

## 结论

目标部署规格已经唯一确定为：

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

用户明确确认实际板型和 stock 布局。独立下载的官方文件、签名发布清单、`profiles.json`
和镜像内 metadata 四方一致。数字来源验证通过；尚未采集设备运行态，因此不能由本报告
证明路由器当前的动态状态。

## 发布来源验证

1. 从 OpenWrt 25.12.5 `mediatek/filogic` 官方发布目录下载固件和 build metadata。
2. `sha256sums.asc` 对 `sha256sums` 的签名验证为 Good signature。
3. 签名主密钥指纹为 `8A8BC12F46B836C0F9CDB36F1D53D1877742E911`。
4. 签名子密钥指纹为 `92C561DE55AE6552F3C736B82B0151090606D1D9`。
5. 下载文件实算 SHA-256 与用户提供值、`sha256sums` 和 `profiles.json` 完全一致。
6. 分析前后固件 SHA-256 不变。

伴随材料的 hash 已保存在
[`intake.json`](../../manifests/ax3000t-stock-openwrt-25.12.5/intake.json)。

## Profile 与 metadata

`profiles.json` 的 `xiaomi_mi-router-ax3000t` 项声明：

- `supported_devices`: `xiaomi,mi-router-ax3000t`；
- `type`: `sysupgrade`；
- `filesystem`: `squashfs`；
- size: `9,400,608` bytes；
- device packages: `kmod-mt7915e`、`kmod-mt7981-firmware`、`mt7981-wo-firmware`。

`fwtool` metadata 独立给出相同 compatible、release、revision、target 和 board。metadata 提取
没有修改输入镜像。

## 明确排除 `ubootmod`

以下文件不属于目标部署，不得用于源码映射、解析假设、构建或升级：

```text
openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-ubootmod-squashfs-sysupgrade.itb
sha256: ff34acec7a915e0ccf47fb7a1a156e0042194e02c0ae3c4f404911b447ec36d3
```

目标 stock 固件是 GNU tar 格式的 `sysupgrade.bin`，不是外置 rootfs FIT `.itb`。

## 初始结构验证

与 25.12.5 source recipe `sysupgrade-tar | append-metadata` 一致，tar 包含：

| 成员 | 大小 | SHA-256 | 类型 |
|---|---:|---|---|
| `CONTROL` | 31 | `eac9cd7ec16d41df0afeb935a037e44f57fb9dc83e8d9662bd74a543cb70b9e1` | `BOARD=xiaomi_mi-router-ax3000t` |
| `kernel` | 4,336,328 | `c20bee280c72744dd203a1832c968156480da6b6f92c210d295fd8c63940d1c6` | AArch64 FIT |
| `root` | 5,052,416 | `3f315cf686c9cd951b24881a3a8e0c78448acaad6fd20d2ab6f1003a0e85b1cc` | XZ SquashFS |

FIT 内核描述为 Linux 6.12.94，并带有 stock DTB。实提取 DTB 声明：

```text
model = Xiaomi Mi Router AX3000T
compatible = xiaomi,mi-router-ax3000t, mediatek,mt7981
ubi_kernel = 0x600000 + 0x2200000
ubi = 0x2800000 + 0x4e00000
```

这与匹配 release 的 stock DTS 一致，没有使用 `ubootmod` 的单一 UBI/FIT 布局。

SquashFS 为 XZ 压缩、262,144-byte block、1,223 inodes。先完成 numeric listing，再以普通
用户排除 `/dev/console` 提取 regular 内容：881 files、128 directories、213 symlinks、
25 init scripts、161 ELF files。镜像使用 APK，安装数据库登记 159 个 package。

提取过程有两次已保留的非零运行：`-e` 被误用为 exclude，随后 `-excludes` 又被放在
filesystem 参数之后；两次都只尝试创建 `/dev/console`，没有完成 regular 文件提取。最终
使用 `unsquashfs ... -excludes <rootfs> "dev/*"` 成功。失败没有被当作成功结果，最终统计只
来自第三次完整提取。

## 证据边界

- `DEP` 已证明官方文件身份、布局、静态内容和构建声明。
- `SRC` 已开始固定匹配 release、feeds、设备定义和组件 revision。
- `RUN` 尚未采集；双分区当前激活槽、U-Boot env、服务实例和实际配置仍保持未知。
- 未连接、读取、写入或刷写物理路由器。
