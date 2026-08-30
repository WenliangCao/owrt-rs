# AX3000T stock / OpenWrt 25.12.5：Patch 与构建输入映射

> I0.4 状态：完成
> 日期：2026-08-30
> Buildroot：`f0a60eee2fe051741c643ea6118718aae1ef17fb`
> 独立 rebuild/patch replay：未执行，属于 V1

## 1. 结论

部署软件涉及三类不可混淆的修改输入：

1. 75 个 package recipe 下的 313 个 patch assets；
2. Linux 6.12 的 623 个 generic/MediaTek target patches；
3. 257 个 package recipe overlay files 和 246 个 kernel target overlay files。

每个文件都记录相对路径、size 和 SHA-256；每个 patch stack 还记录有序 digest。recipe 中的
`Build/Patch`、`PatchDir`、configure/build flags 和 exact config 均作为应用选择证据保留。

I0.4 的结论是“精确登记官方 build 的输入及应用路径”，不是“在当前宿主独立重建得到 bit-
identical image”。独立 source prepare、patch replay、compile 和产物差分属于 V1，不能在这里
虚构为已经完成。

完整列表见 [sources.json](../../manifests/ax3000t-stock-openwrt-25.12.5/sources.json)。

## 2. Kernel patch stacks

OpenWrt kernel build 对 Linux 6.12 使用以下固定顺序：

| 顺序 | Stack | Patches | Ordered digest SHA-256 |
|---:|---|---:|---|
| 1 | `target/linux/generic/backport-6.12` | 271 | `7c6754541a7b512ea2347c90afc6e04a15b27e68c697de591f36d6d2effbb131` |
| 2 | `target/linux/generic/pending-6.12` | 143 | `0c9bd7ea6b60bfc025f059191d12b8b4bedbba73f1818d3048ce238a94ab3d3b` |
| 3 | `target/linux/generic/hack-6.12` | 56 | `c13efc14099889c620abb9e9532b558fdc7e32067ab49ce4b172ef7cada95013` |
| 4 | `target/linux/mediatek/patches-6.12` | 153 | `e604c58d9ba768a7ec30cc12e4f9392ada66e4301165648b1262d3f9d020c13f` |
| 合计 | — | 623 | 每项逐文件 hash 见 manifest |

目标 package DB 将 kernel 固定为：

```text
kernel 6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1
```

这四个 stack 是 AX3000T 所属 `mediatek/filogic` build 的源码输入。某 patch 涉及的具体 driver
是否在设备上 probe，不能仅由 patch 存在推断。

## 3. Kernel target overlays

| Overlay | Files | Ordered digest SHA-256 |
|---|---:|---|
| `target/linux/generic/files` | 104 | `ddbed83a2dab9a6a593fbb571403e74742492b3689ffda5387bf6ce39b3a8b9e` |
| `target/linux/mediatek/files` | 128 | `ab5e7dadfe1d847176fea8fde4fd2b466257e65703dc2043c5e72721a54eb653` |
| `target/linux/mediatek/files-6.12` | 14 | `e00cb7f691ec1f76ff50e2406ab73a2d423d46bb7bbd2f2eefc718ee97c4c733` |
| 合计 | 246 | — |

这些 overlay 包含 OpenWrt/MediaTek 增补源码和 headers，不是 `.patch`，因此单独登记，避免
只盘点 patch 而漏掉实际编译输入。

## 4. Package patch assets

| Recipe origin | Installed packages | Patches |
|---|---|---:|
| `kernel/mac80211` | kmod-cfg80211、kmod-mac80211 | 154 |
| `network/services/hostapd` | hostapd-common、wpad-basic-mbedtls | 63 |
| `network/services/dropbear` | dropbear | 17 |
| `network/services/ppp` | ppp、ppp-mod-pppoe | 16 |
| `utils/busybox` | busybox | 16 |
| `utils/mtd-utils` | ubi-utils | 7 |
| `boot/uboot-tools` | fit-check-sign、uboot-envtools | 5 |
| `system/apk` | apk-mbedtls | 5 |
| `utils/ucode` | ucode、libucode、九个 modules | 5 |
| `libs/mbedtls` | libmbedtls21 | 4 |
| `libs/zlib` | zlib | 4 |
| `network/utils/iw` | iw | 4 |
| `network/utils/nftables` | nftables-json | 3 |
| `network/services/dnsmasq` | dnsmasq | 2 |
| `libs/libjson-c` | libjson-c5 | 2 |
| 其余有 patch recipe | 其他安装物料 | 6 |
| 合计 | 159 packages / 75 recipes | 313 |

mac80211 使用显式 `Build/Patch`/`PatchDir` 分目录应用 build、subsys 和各 driver family patch。
manifest 保留全部子目录和文件 hash；不能简单把目录递归排序冒充 build application order。

## 5. 核心控制面 patch 状态

| Component recipe | Direct patches | Overlay files | 判定 |
|---|---:|---:|---|
| procd | 0 | 6 | exact upstream commit + OpenWrt install/config overlay |
| ubus/ubusd | 0 | 0 | exact upstream commit |
| uci | 0 | 1 | exact upstream commit + CLI/config integration |
| rpcd | 0 | 3 | exact upstream commit + ACL/config overlay |
| netifd | 0 | 16 | exact upstream commit + protocol/init scripts |
| firewall4 | 0 | 0 | exact upstream commit；package install definition |
| odhcpd | 0 | 3 | exact upstream commit + service/config files |
| uhttpd | 0 | 3 | exact upstream commit + init/config files |
| ucode | 5 | 0 | exact commit + five OpenWrt patches |
| dnsmasq | 2 | 10 | exact source tar hash + OpenWrt ubus/runtime integration |
| hostapd/wpad | 63 | 18 | exact source commit + substantial OpenWrt wireless/ubus/ucode integration |

这说明不能把上游裸 release 当成部署实现，尤其是 hostapd、dnsmasq、ucode。反过来，procd、
ubus、uci、rpcd 等 direct patch 为 0，也不能忽略其 exact build flags、package split 和 overlay
install integration。

## 6. Build flags 与 feature selection

`sources.json` 为每个 recipe 保存与以下项匹配的 raw logical assignments：

- configure、CMake、Meson、Make flags；
- target CFLAGS/LDFLAGS；
- `PKG_CONFIG_DEPENDS`；
- package variant/provider/dependency；
- `Build/Patch`/`PatchDir`；
- package install/conffile definitions。

共享 build inputs 也单独固定：

```text
openwrt/rules.mk
openwrt/include/package.mk
openwrt/include/package-defaults.mk
openwrt/include/kernel.mk
luci/luci.mk
```

59 个 recipe 有显式 install definitions；16 个通过这些 repository macro/kernel template
生成安装动作。1,095 个 recipe auxiliary files 逐一 hash，因而 LuCI `htdocs/root/ucode` 等
非 `files/` 目录没有被遗漏。

## 7. Binary firmware boundary

| Package | Recipe status | Implementation source |
|---|---|---|
| eip197-mini-firmware | exact linux-firmware recipe/hash | Unknown/opaque binary |
| mt7981-wo-firmware | exact linux-firmware recipe/hash | Unknown/opaque binary |
| kmod-mt7981-firmware | exact mixed mt76 recipe | firmware payload Unknown；driver source Exact |

这些 payload 不因被官方 recipe 安装就变成可替换源码，也不要求对 blob 做逆向才能继续研究
外围控制面。默认保留。

## 8. 分析失败记录

I0.4 生成器第一次完成只读扫描后，在写出最终 JSON 前因 Python 布尔量误写为 `false` 抛出
`NameError`。该次没有成功输出，也没有修改 rootfs、release metadata 或 source checkout。
修正为 `False` 后重新从头运行；最终三个 JSON 均通过解析、计数和来源断言。失败没有被
隐藏或算作成功。

## 9. Patch map gate

| 检查 | 结果 |
|---|---|
| recipe patch asset 无 path/hash | 0 / 313 |
| kernel target patch 无 path/hash | 0 / 623 |
| package auxiliary file 无 path/hash | 0 / 1,095 |
| target overlay 无 path/hash | 0 / 246 |
| 核心 source checkout revision mismatch | 0 / 9 |
| build config/feed input 未固定 | 0 |
| binary firmware 冒充 public source | 0 |
| 独立 patch replay 被误报为完成 | 否 |

I0.4 已给出精确、可重放的 source reconstruction specification。V1 若开始构建，必须从这些
固定输入独立 replay，并与当前部署物做差分，而不是更新到较新的源码。
