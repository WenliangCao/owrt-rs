# AX3000T stock / OpenWrt 25.12.5：部署文件到精确源码映射

> I0.4 状态：完成
> 日期：2026-08-30
> 范围：159 APK packages、75 recipes、核心组件 checkout、生成文件
> 替换实现授权：无

## 1. 结论

159 个 installed package 全部映射到 75 个 exact recipe origin；每个 recipe 都固定到 buildroot
或 feed commit、Makefile hash、source selector、build flag evidence、install definition、patch
asset 和 overlay file hash。

所有 ELF、executable、init service 可以沿以下链回查：

```text
deployed path
  -> APK payload owner or explicit image generator
  -> installed package/version/origin
  -> exact recipe Makefile + feed/buildroot revision
  -> PKG_SOURCE_VERSION / release hash / in-tree feed revision
  -> package patches + target patches + build config
```

九个首批核心组件 checkout 的 HEAD 与 recipe `PKG_SOURCE_VERSION` 全部完全一致且 worktree
clean。没有使用 `main` 代替发布版本。

完整机器映射见 [sources.json](../../manifests/ax3000t-stock-openwrt-25.12.5/sources.json)。

## 2. Repository baseline

| Repository | Revision | Tree | Worktree |
|---|---|---|---|
| OpenWrt buildroot | `f0a60eee2fe051741c643ea6118718aae1ef17fb` | `4ac64a90c5cd190209b4a9428fc34f12e6c87d4b` | clean |
| packages feed | `5caa62e0bc9f7fb9b0c12a23267bceb7724214dd` | `13fc8a05d92b2f78d9e51a8bd7d2e3ba62d311e4` | clean |
| LuCI feed | `128a7812f4be233c5dd7f7466f534fd888785caf` | `9e3a94787ee8cc702f4fa0a006be222d5f22c88e` | clean |
| routing feed | `3d7d0dc7fa43d3eb09498417407e95a6552e5312` | `0f53194b13985c5eda9a0b1250deef9bdf321c41` | clean |
| telephony feed | `2618106d5846a4a542fdf5809f0d3ed228ce439b` | `5367b234f0930462522426da121ab46d769270a6` | clean |
| video feed | `094bf58da6682f895255a35a84349a79dab4bf95` | `b6c9524578cd1b1ae16cf3ab02ceb797cabbc36d` | clean |

实际 159 packages 只来自前三类：

| Recipe repository | Recipes | Packages | Recipe patch assets | Overlay files |
|---|---:|---:|---:|---:|
| OpenWrt buildroot/base | 53 | 136 | 312 | 255 |
| LuCI feed | 19 | 20 | 1 | 0 |
| packages feed | 3 | 3 | 0 | 2 |
| 合计 | 75 | 159 | 313 | 257 |

这里的 257 是 package recipe overlay files；kernel target overlay 另有 246 项，不重复计算。
routing、telephony 和 video feed revision 被 release 固定，但本镜像没有来自它们的 installed
package。

## 3. 核心组件 checkout 验证

| Component | Exact source revision | Recipe match | Worktree |
|---|---|---:|---|
| firewall4 | `b6e5157527d361f99ad52eaa6da273cb0f2dfd59` | 是 | clean |
| netifd | `cbb83a1857407a28a63dc09412a1f209195914ef` | 是 | clean |
| odhcpd | `5d7be43f8b9dec0eb47e245cfab81108bb131273` | 是 | clean |
| procd | `58eb263d5abe03f8c1280bdfa65a3b052614215d` | 是 | clean |
| rpcd | `28faf6403792d25b9826043aaf37880624c19568` | 是 | clean |
| ubus | `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` | 是 | clean |
| uci | `66127cd76c5d0bd46d5a90302cc6110f53a4e2f8` | 是 | clean |
| ucode | `85922056ef7abeace3cca3ab28bc1ac2d88e31b1` | 是 | clean |
| uhttpd | `7b1bec45826bd78c8afc993435bdc0f1df2fe399` | 是 | clean |

checkout revision、expected revision、Git tree 和 clean 状态分别记录，不以 package version 的
八位缩写替代完整 commit。

## 4. 关键 package source map

| Installed packages | Upstream selector | Package patches | Recipe overlays | 来源级别 |
|---|---|---:|---:|---|
| procd / procd-ujail / procd-seccomp | `58eb263d…` | 0 | 6 | Exact |
| ubus / ubusd / libubus | `24864e78…` | 0 | 0 | Exact |
| uci / libuci | `66127cd7…` | 0 | 1 | Exact |
| rpcd + native modules | `28faf640…` | 0 | 3 | Exact |
| netifd | `cbb83a18…` | 0 | 16 | Exact |
| firewall4 | `b6e51575…` | 0 | 0 | Exact |
| ucode + modules | `85922056…` | 5 | 0 | Exact |
| uhttpd + ubus module | `7b1bec45…` | 0 | 3 | Exact |
| odhcpd-ipv6only | `5d7be43f…` | 0 | 3 | Exact |
| dnsmasq | source tar SHA-256 `0c00d4e5…bc19` | 2 | 10 | Exact |
| hostapd-common / wpad-basic-mbedtls | `ca266cc2…` | 63 | 18 | Exact |
| LuCI packages | LuCI feed `128a7812…` | 1 total | feed in-tree | Exact |

`sources.json` 保留完整 source URL/hash、package release、license、build option evidence 和
install definition line。表中省略号只用于可读性，不是 machine record。

## 5. Build flag 与 install recipe

每个 recipe 记录：

- `PKG_VERSION`、`PKG_SOURCE_VERSION`、`PKG_SOURCE_URL`、`PKG_HASH`、`PKG_MIRROR_HASH` 等
  exact Make assignment；
- `CONFIGURE_ARGS`、`CMAKE_OPTIONS`、`MESON_ARGS`、`MAKE_FLAGS`、`TARGET_CFLAGS`、
  `PKG_CONFIG_DEPENDS`、variant/dependency/provider 的原始 logical lines；
- `Package/*/install`、`Package/*/conffiles`、`Build/InstallDev` 定义位置；
- recipe `files/` overlay 的逐文件 size/hash；
- recipe 下 1,095 个 auxiliary/source payload file 的逐文件 size/hash；
- package patch assets 的逐文件 size/hash；
- 配套 `config.buildinfo` 的固定 SHA-256。

59 个 recipe 有显式 `Package/*/install`/`Build/InstallDev` 定义；16 个依赖 LuCI、kernel 或
firmware 的 repository-level install macro/template。后一类没有被误报成“无 install recipe”：
其 recipe auxiliary files、`luci.mk`、`package.mk`、`kernel.mk` 等共享构建输入和 repository
tree 均已固定。

因此 build flags 不由目标 ELF 反推，也不由当前 `main` 猜测。复杂 make expression 保留原文
和 exact recipe hash，而不是用不完整的自制 evaluator 冒充 OpenWrt make expansion。

## 6. Generated file source map

| Generated class | Source/generator authority |
|---|---|
| APK installed DB、world、arch | OpenWrt APK image construction + exact installed packages |
| `/lib/apk/packages/*` control state | APK metadata generator + 同名 package |
| `rc.d` links | exact init script + `rc.common` enable logic |
| alternatives links | exact APK alternatives metadata + resolved target |
| `/dev/console` | exact OpenWrt rootfs device table/SquashFS recipe |
| LuCI generated menus/ACL/assets | exact LuCI feed package install recipes；运行期生成继续留给 I0.5 |
| UCI defaults/migrations | 提供它们的 package recipe；执行后的配置不在静态镜像内 |

文件 owner 与 source recipe 的完整连接由 `packages.json` 的 `source_key` 和
`executables.json` 的 `owner_package/source_key` 完成。

## 7. 来源置信度

| 范围 | Recipe mapping | Implementation source | 处理 |
|---|---|---|---|
| 156 public/in-tree packages | Exact | Exact | 可以进入接口/调用者研究；仍不等于替换授权 |
| `eip197-mini-firmware` | Exact | Unknown | 保留 binary blob |
| `mt7981-wo-firmware` | Exact | Unknown | 保留 binary blob |
| `kmod-mt7981-firmware` payload | Exact | Unknown | 与 Exact 的 public mt76 driver source 分开 |
| mt76 recipe 整体 | Exact | Bounded/mixed | driver public，三个 MT7981 firmware files opaque |

Opaque firmware 的 hash 和 install recipe 可复核，但 binary 内部实现不能因 recipe 公开而被
标成 Exact source。它们不属于 Rust 控制面替换候选。

## 8. 无 downstream/vendor override 的证据

- installed origin 全部属于固定的 OpenWrt buildroot、packages 或 LuCI；
- custom feed 有效条目为 0；
- release manifest 交集版本差异为 0；
- package DB 没有未知 origin；
- 24 个 manifest 外 package 全部等于 stock profile device packages 与其依赖闭包；
- 没有发现自定义 package namespace、版本 suffix 或额外可执行文件。

这证明该官方镜像的静态 package/source chain 没有 downstream 增量；不证明设备 overlay 中
没有用户安装 package。

## 9. Source map gate

| 检查 | 结果 |
|---|---|
| installed package 无 recipe | 0 |
| recipe 无固定 repository revision | 0 |
| 核心 checkout 与 recipe revision 不同 | 0 / 9 |
| executable 无 package/source | 0 |
| init service 无 package/source | 0 |
| recipe/source auxiliary file 未 hash | 0 / 1,095 |
| 显式 install definitions | 59 recipes |
| repository macro/template install | 16 recipes，shared macro 已 hash |
| opaque implementation 冒充 Exact | 0 |

I0.4 source map gate 通过。它允许 I0.5 从精确源文件追踪启动、配置和 IPC；仍不允许直接设计
替代进程，因为 caller、runtime instance 和 failure contract 尚未闭合。
