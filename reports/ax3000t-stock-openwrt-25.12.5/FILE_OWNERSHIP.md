# AX3000T stock / OpenWrt 25.12.5：文件归属

> I0.4 状态：完成
> 日期：2026-08-30
> 输入：I0.3 numeric inventory、APK payload lists、APK image state
> 运行目标二进制：否

## 1. 结论

I0.3 的 1,223 个 inode 已全部分类：

```text
128 shared directories
+ 857 package payload regular/symlink paths
+ 237 image-generation regular/symlink paths
+   1 source-generated /dev/console
= 1,223 inodes
```

所有 881 个 regular file、213 个 symlink、唯一 special node 和 128 个目录均有分类。APK
payload 文件没有 duplicate owner；非目录 unknown path 为 0。所有 ELF、可执行文件和 25 个
init service 都能回到 installed package 和 recipe source key。

逐包完整文件列表在 [packages.json](../../manifests/ax3000t-stock-openwrt-25.12.5/packages.json)，
ELF、脚本、可执行链接和 control-plane path 在
[executables.json](../../manifests/ax3000t-stock-openwrt-25.12.5/executables.json)。

## 2. 为什么不能只读取 `.list`

APK 的 159 个 `.list` 文件表达 package payload，共覆盖 857 个 regular/symlink path。最终
rootfs 还包含安装器在成像阶段生成的 APK 数据库、package control state、alternatives 和
`rc.d` links。这些文件不是未归属 vendor 文件，也不应伪造为原 package tar payload。

| 非目录分类 | regular | symlink | 合计 |
|---|---:|---:|---:|
| APK package payload | 687 | 170 | 857 |
| image generated | 194 | 43 | 237 |
| unknown | 0 | 0 | 0 |
| 合计 | 881 | 213 | 1,094 |

## 3. Generated path 的生成器

| Generator | 数量 | 典型路径 | 归属规则 |
|---|---:|---|---|
| APK package metadata generation | 188 | `/lib/apk/packages/*.list`、conffile/alternative metadata | 映射到同名 installed package |
| OpenWrt image APK DB construction | 6 | `/etc/apk/world`、`/etc/apk/arch`、`/lib/apk/db/*` | APK image construction；责任 package 为 `apk-mbedtls` |
| `rc.common` enable links | 33 | `/etc/rc.d/S*`、`K*` | 跟随 target init script owner |
| APK alternatives | 10 | `ssh`、`scp`、`wget`、kmodloader links | 跟随 resolved alternative target owner |

这 237 项均同时记录 `generator`、生成源或 resolved target。报告使用“generated”而不是
“unowned”，避免把 package manager 的持久状态误判为来源缺口。

## 4. Directory 与 special node

128 个 directory 可以被多个 package 共用，APK payload list 不提供排他 directory ownership；
因此目录按共享容器分类，而不强行指定单一 owner。

`/dev/console` 是 I0.3 numeric inventory 中唯一 special node：

```text
character device 0600 uid=0 gid=0 major=5 minor=1
```

它来自 OpenWrt rootfs device-table/SquashFS 生成链，不是 APK payload，并在普通用户提取时
有意排除。该节点的来源已在 `SOURCE_EXPECTATIONS.md` 与 `filesystem.json` 固定。

## 5. 文件数最多的 package

| Package | Payload paths | Installed size | Origin |
|---|---:|---:|---|
| `busybox` | 129 | 428,601 | base/utils/busybox |
| `base-files` | 122 | 239,235 | base/base-files |
| `luci-base` | 76 | 741,604 | LuCI modules/luci-base |
| `luci-mod-status` | 33 | 177,585 | LuCI modules/luci-mod-status |
| `wifi-scripts` | 31 | 275,913 | base/network/config/wifi-scripts |
| `firewall4` | 23 | 130,657 | base/network/config/firewall4 |
| `luci-mod-system` | 22 | 71,673 | LuCI modules/luci-mod-system |
| `netifd` | 20 | 268,908 | base/network/config/netifd |
| `luci-mod-network` | 17 | 279,539 | LuCI modules/luci-mod-network |
| `ubi-utils` | 16 | 283,943 | base/utils/mtd-utils |
| `luci-theme-bootstrap` | 14 | 63,785 | LuCI theme |
| `dnsmasq` | 13 | 312,963 | base/network/services/dnsmasq |
| `kmod-nft-core` | 13 | 367,116 | base/kernel/linux |
| `procd` | 12 | 157,822 | base/system/procd |

Installed size 是 APK DB 字段，不等于 SquashFS compressed contribution。

## 6. 控制面文件归属

| 静态范围 | 文件/链接数 | Package owner 数 | 主要 owner |
|---|---:|---:|---|
| init scripts | 25 | 15 | base-files、procd users、network/service packages |
| rc enable/stop links | 33 | 15 | 跟随 init script owner |
| preinit | 21 | 3 | base-files、dropbear、urandom-seed |
| hotplug | 10 | 5 | base-files、dnsmasq、firewall4、netifd、wifi-scripts |
| UCI defaults | 22 | 14 | base-files、network、LuCI、upgrade packages |
| shipped UCI config | 6 | 6 | dnsmasq、dropbear、firewall4、luci-base、rpcd、uhttpd |
| rpcd/ACL | 21 | 18 | rpcd modules、LuCI、service ACLs |
| LuCI | 159 | 12 | LuCI/application packages、cgi-io |
| netifd/protocol helpers | 19 | 5 | netifd、wifi-scripts、hostapd、odhcp6c、ppp |
| firewall4/nftables snippets | 15 | 1 | firewall4 |
| hostap/wireless integration | 6 | 2 | wifi-scripts、wpad-basic-mbedtls |
| upgrade/persistence | 25 | 14 | base-files、fitblk、ubi-utils、service conffiles |

这里的 owner 是“部署文件由谁提供”，不是“运行时谁会读写它”。reader、writer、generator
输入、写入时机和失败传播由 I0.5 继续建立。

## 7. Executable 与 service 归属门

| 范围 | 数量 | 无 package owner |
|---|---:|---:|
| ELF regular files | 161 | 0 |
| executable regular files | 174 | 0 |
| executable symlinks | 185 | 0 |
| shell/ucode shebang 或 `.sh` 文件 | 135 | 0 |
| ucode/Lua files | 54 | 0 |
| init services | 25 | 0 |

每个记录还携带 package `source_key` 或可经 owner package 回查 `sources.json`。BusyBox applet
以实际 symlink target/hash 识别，没有把 119 个 applet 误当成 119 个独立实现。

## 8. Generated/configuration 边界

I0.4 已固定以下静态生成关系：

- APK image builder 生成 DB、world、arch 和 package control state；
- `rc.common` 依据 init script 的 enable 状态生成 `rc.d` links；
- APK alternatives 生成命令别名；
- rootfs device table 生成 `/dev/console`；
- package recipe `install` 与 overlay 提供 package payload；
- UCI defaults、preinit 和首次启动脚本是“部署输入”，不是已经运行后的输出。

首次启动会删除或改写哪些 UCI defaults、生成哪些 config/keys/overlay 文件，尚未由静态镜像
证明，不能在本报告中预先宣称。

## 9. Ownership gate

| 检查 | 结果 |
|---|---|
| duplicate package payload owner | 0 |
| unknown regular file | 0 |
| unknown symlink | 0 |
| unknown executable | 0 |
| unknown init service | 0 |
| special node 未分类 | 0 |
| generated file 冒充 package payload | 0 |

因此 I0.4 的静态 ownership gate 通过。运行时 overlay、tmpfs、socket、pidfile 和动态生成配置
仍保持 Unknown，留给 I0.5/I0.7。
