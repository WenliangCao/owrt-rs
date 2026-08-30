# AX3000T stock / OpenWrt 25.12.5：部署软件物料

> I0.4 状态：完成
> 日期：2026-08-30
> 权威输入：精确镜像内 APK 数据库
> 设备访问：无

## 1. 结论

镜像实际安装 159 个 APK package。它们不是由 target manifest 单独决定，而是以下三层的
确定闭包：

```text
target release manifest           135
+ AX3000T profile device packages   3
= /etc/apk/world                  138
+ dependency-only packages         21
= /lib/apk/db/installed           159
```

159 个 package 均有 version、architecture、dependency、provide、origin、license、conffile
和 payload file list 记录。发布 manifest 中 135 个 package 全部存在且版本完全一致；没有
manifest package 缺失，也没有交集内版本偏差。

CycloneDX BOM 有 135 个 source-level component。17 个通用 library 名称通过 APK `provides`
解析为带 ABI 后缀的实际 package；135 项全部可解析。BOM 没有表达 device packages 及其
依赖闭包，因此不能代替镜像 APK DB。

完整逐包记录见 [packages.json](../../manifests/ax3000t-stock-openwrt-25.12.5/packages.json)。

## 2. 证据优先级

| 输入 | 数量 | 本阶段用途 |
|---|---:|---|
| `/lib/apk/db/installed` | 159 records | 实际安装 package、version、dependency、origin、license 的 authority |
| `/lib/apk/packages/*.list` | 159 lists | package payload 文件归属 authority |
| `/etc/apk/world` | 138 selectors | 镜像显式安装集合，不含自动依赖 |
| release target manifest | 135 packages | target 基线交叉验证，不冒充 profile 最终集合 |
| CycloneDX BOM | 135 components | source component/license 交叉验证，不冒充 ABI package 清单 |
| `profiles.json` | 30 defaults + 3 device | target defaults、AX3000T profile 选择器 |
| `config.buildinfo` | 36 `CONFIG_PACKAGE_*=y` | 发布 target 构建配置选择器，不冒充文件归属 |

关键输入 SHA-256：

| 输入 | SHA-256 |
|---|---|
| APK installed DB | `4c7b6466a333633b07c87fa5d89b1379cafd4c3eab8d9e783da6d7c01f3a7341` |
| APK world | `dfc107d77e80ecc75cb5484c70a07b88af5c87cc736164b78fb86f411a150a85` |
| release manifest | `9131221a4d3017e33a1d6f96e1c92e7b9fdc5698f91736dcab967482d4b0b88d` |
| CycloneDX BOM | `e2150abcc0f1b709f4695a18735678a5cbd0f0f26b8c0096e6e864a7b5e4df77` |
| profiles | `a1c448c58e8a1cca016ae0ce0d0d02e5f53b97e3b67a8d9e2ee4aee34e602dd2` |
| config.buildinfo | `d79d1c4b3a18dac919371f8d9f1a9350363d9b94261744bd2cc2f5c3e4c17115` |
| feeds.buildinfo | `e11279b01e7fea7f7d399e25e969d9382be6891071cbc1225804195224b27b52` |

## 3. Target、profile 与 dependency reconciliation

### 3.1 AX3000T profile 的三项增量

`profiles.json` 中 stock profile 明确加入，且镜像全部安装：

- `kmod-mt7915e`；
- `kmod-mt7981-firmware`；
- `mt7981-wo-firmware`。

### 3.2 由这组设备物料拉入的 21 项依赖

以下 package 在 installed DB 中存在，但不在 `/etc/apk/world`：

```text
iw
kmod-cfg80211
kmod-crypto-ccm
kmod-crypto-cmac
kmod-crypto-ctr
kmod-crypto-gcm
kmod-crypto-geniv
kmod-crypto-gf128
kmod-crypto-ghash
kmod-crypto-rng
kmod-crypto-seqiv
kmod-crypto-sha3
kmod-hwmon-core
kmod-i2c-core
kmod-mac80211
kmod-mt76-connac
kmod-mt76-core
kmod-thermal
ucode-mod-digest
wifi-scripts
wireless-regdb
```

这 21 项与三项 profile 增量合计 24，恰好等于“installed 有而 target manifest/BOM 未表达”
的集合。没有第 25 个未解释 package。

### 3.3 选择器验证

- 30 个 target default selector 全部解析到实际 package/provider；
- 三个 profile device package 全部安装；
- 36 个 `CONFIG_PACKAGE_*=y` 全部解析到实际 package/provider；
- 138 个 world selector 全部有 installed record；
- custom feed 有效条目为 0；distfeeds 的八项 URL 均为 OpenWrt 25.12.5 官方路径。

## 4. CycloneDX 的 ABI 名称差异

CycloneDX 使用 source component 名称，APK 使用 ABI package 名称。例如：

| CycloneDX/source name | 实际 APK provider |
|---|---|
| `jansson` | `jansson4` |
| `libblobmsg-json` | `libblobmsg-json20260213` |
| `libgcc` | `libgcc1` |
| `libiwinfo` | `libiwinfo20230701` |
| `libjson-c` | `libjson-c5` |
| `liblucihttp` | `liblucihttp0` |
| `libmbedtls` | `libmbedtls21` |
| `libubox` | `libubox20260213` |
| `libubus` | `libubus20251202` |
| `libuci` | `libuci20250120` |
| `libucode` | `libucode20230711` |
| `libustream-mbedtls` | `libustream-mbedtls20201210` |

完整 17 项 provider resolution 保存在 `packages.json`。这些是命名层差异，不是 BOM 缺失或
版本冲突。

## 5. 包架构、来源与配置文件

| 维度 | 数量 |
|---|---:|
| `aarch64_cortex-a53` | 141 |
| `noarch` | 18 |
| buildroot/base origin | 136 packages |
| LuCI feed origin | 20 packages |
| packages feed origin | 3 packages |
| distinct recipe origins | 75 |
| packages with APK conffile metadata | 16 |
| dynamic conffile entries | 58 |
| static conffile entries | 31 |

所有 origin 都属于固定的 buildroot、packages feed 或 LuCI feed。没有未知 origin，没有
custom repository package，也没有发布 manifest 交集内 version override。

## 6. 关键部署 package

| Package | 镜像版本 | Origin | License |
|---|---|---|---|
| `procd` | `2026.03.13~58eb263d-r1` | `feeds/base/system/procd` | GPL-2.0 |
| `ubus` / `ubusd` | `2026.06.28~24864e78-r2` | `feeds/base/system/ubus` | LGPL-2.1 |
| `uci` | `2025.12.02~66127cd7-r1` | `feeds/base/system/uci` | LGPL-2.1 |
| `rpcd` | `2026.06.04~28faf640-r1` | `feeds/base/system/rpcd` | ISC |
| `netifd` | `2026.02.26~cbb83a18-r1` | `feeds/base/network/config/netifd` | GPL-2.0 |
| `firewall4` | `2025.03.17~b6e51575-r2` | `feeds/base/network/config/firewall4` | ISC |
| `ucode` | `2026.01.16~85922056-r1` | `feeds/base/utils/ucode` | ISC |
| `uhttpd` | `2026.06.16~7b1bec45-r1` | `feeds/base/network/services/uhttpd` | ISC |
| `odhcpd-ipv6only` | `2026.06.29~5d7be43f-r1` | `feeds/base/network/services/odhcpd` | GPL-2.0 |
| `dnsmasq` | `2.93-r1` | `feeds/base/network/services/dnsmasq` | GPL-2.0 |
| `hostapd-common` / `wpad-basic-mbedtls` | `2025.08.26~ca266cc2-r1` | `feeds/base/network/services/hostapd` | BSD-3-Clause |
| `luci-base` | `26.180.75667~128a781` | LuCI feed | Apache-2.0 |

## 7. Firmware 与 license 边界

三个 package 的 payload 是设备 firmware binary：

- `eip197-mini-firmware`；
- `kmod-mt7981-firmware`；
- `mt7981-wo-firmware`。

它们的 package、版本、recipe 和文件 hash 都是 Exact，但 binary 内部实现源码标为
Unknown，不作为替换候选。前后两个 linux-firmware package 的 APK license 字段为空；这项
事实被保留，没有擅自补写许可证。`kmod-mt7981-firmware` 与公开 mt76 driver 共用 recipe，
因此该 recipe 标为 mixed boundary。

## 8. I0.4 SBOM gate

| 检查 | 结果 |
|---|---|
| installed package 无 release/profile/dependency 解释 | 0 |
| release manifest 缺失于 image | 0 |
| release manifest 交集版本冲突 | 0 |
| CycloneDX component 无 provider | 0 |
| target/config selector 无 provider | 0 |
| custom feed entries | 0 |
| unknown package origin | 0 |
| opaque firmware payload | 3，已隔离，不作为控制面源码 |

这份 SBOM 证明部署物料及其静态来源，不证明设备运行时实际加载了每个 module、daemon 或
firmware。动态加载和服务实例属于 I0.5/I0.7。
