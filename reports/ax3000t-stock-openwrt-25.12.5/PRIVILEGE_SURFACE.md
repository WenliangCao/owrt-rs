# AX3000T stock / OpenWrt 25.12.5：静态权限面

> I0.4 状态：完成
> 日期：2026-08-30
> 范围：rootfs 静态 owner/mode、ELF、init scripts、APK runtime users
> 运行进程观察：无

## 1. 结论

镜像没有 setuid、setgid、sticky executable 或 file capability。SquashFS 不存储 xattr；全部
1,223 个 inode 的静态 uid/gid 是 `0/0`。这说明部署物没有通过文件位或 capability 提权，
不说明所有进程始终以 root 运行。

25 个 init script 全部已归属 package/source：18 个使用 procd，2 个显式设置非 root user，
3 个调用 `procd_add_jail`，0 个静态出现 `procd_set_param seccomp`。`procd-seccomp` 已安装，
但不能因为 package 存在就宣称某个 service 实际启用了 seccomp。

完整 ELF、symbol、service 和 ACL path 记录见
[executables.json](../../manifests/ax3000t-stock-openwrt-25.12.5/executables.json)。

## 2. ELF 与 executable inventory

### 2.1 ELF

| ELF type | 数量 | 解释 |
|---|---:|---|
| AArch64 `REL` | 55 | 主要为 kernel modules |
| AArch64 `EXEC` | 41 | 非 PIE executable |
| AArch64 `DYN` shared object | 49 | shared libraries/plugins |
| AArch64 `DYN` PIE | 16 | position-independent executables |
| 合计 | 161 | 全部为 AArch64 |

- 57 个 ELF 声明 interpreter `/lib/ld-musl-aarch64.so.1`；
- 104 个 ELF 没有 program interpreter，覆盖 `.so`、`.ko`、static/loader 类文件；
- RPATH 为 0，RUNPATH 为 0；
- 每个 ELF 均记录 SHA-256、size、ABI、interpreter、NEEDED、SONAME、symbols 和 package owner；
- imported/defined symbol 是 `readelf -sW` 全符号表去重结果，不是对目标二进制的执行输出。

### 2.2 Executable 形态

| 分类 | 数量 |
|---|---:|
| independent ELF regular | 83 |
| executable shell/script regular | 90 |
| executable ucode/Lua regular | 1 |
| BusyBox applet symlink | 119 |
| other executable symlink | 66 |
| unknown executable data | 0 |

此外静态树中共有 105 个 shebang 文件、30 个无 shebang `.sh` fragment，合计 135 个 script
file；ucode/Lua 文件为 54。无 shebang fragment 没有因 executable bit 或扩展名差异而漏掉。

## 3. 文件权限入口

| 检查 | 结果 |
|---|---:|
| setuid entries | 0 |
| setgid entries | 0 |
| sticky entries | 0 |
| file capabilities | 0 |
| xattrs stored by SquashFS | 否 |
| character devices | `/dev/console` 一项，0600，5:1 |
| world-writable regular files | 0 |

`/dev/console` 是 boot 必需 device-table 输出，不是 daemon privilege escalation 入口。运行时
创建的 `/dev`、tmpfs、socket 和 pidfile 权限不在静态 SquashFS 中。

## 4. APK runtime users/groups

六个 package 提供 runtime user/group metadata：

| Package | APK rusers declaration |
|---|---|
| `busybox` | `ntp=123:ntp=123` |
| `dnsmasq` | `dnsmasq=453:dnsmasq=453` |
| `logd` | `logd=514:logd=514` |
| `procd` | `:dialout=20 :audio=29` |
| `ubusd` | `ubus=81:ubus=81` |
| `wpad-basic-mbedtls` | `network=101:network=101` |

这是 account provisioning evidence，不等于每个 daemon 的最终 effective UID。比如 dnsmasq 的
init script 建 jail 但没有用 `procd_set_param user`；它可能根据生成配置自行 drop privilege，
必须在 I0.5 从配置生成器和 daemon 参数继续追踪。

## 5. Init service 静态权限表

`User` 为空表示 init script 没有显式 `procd_set_param user`，不是已证明的永久 root effective
UID。`Jail` 只表示脚本中存在 `procd_add_jail`。

| Service | Package | START | STOP | procd | User | Jail | Explicit seccomp |
|---|---|---:|---:|---:|---|---:|---:|
| `sysfixtime` | base-files | 00 | 90 | 否 | — | 否 | 否 |
| `urngd` | urngd | 00 | — | 是 | — | 否 | 否 |
| `boot` | base-files | 10 | 90 | 否 | — | 否 | 否 |
| `system` | base-files | 10 | — | 是 | — | 否 | 否 |
| `sysctl` | base-files | 11 | — | 否 | — | 否 | 否 |
| `log` | logd | 12 | 89 | 是 | — | 否 | 否 |
| `rpcd` | rpcd | 12 | — | 是 | — | 否 | 否 |
| `dnsmasq` | dnsmasq | 19 | — | 是 | — | 是 | 否 |
| `dropbear` | dropbear | 19 | 50 | 是 | — | 否 | 否 |
| `firewall` | firewall4 | 19 | — | 是 | — | 否 | 否 |
| `wpad` | hostapd-common | 19 | 21 | 是 | `network` | 是 | 否 |
| `network` | netifd | 20 | 90 | 是 | — | 否 | 否 |
| `packet_steering` | netifd | 25 | — | 是 | — | 否 | 否 |
| `odhcpd` | odhcpd-ipv6only | 35 | 85 | 是 | — | 否 | 否 |
| `cron` | busybox | 50 | — | 是 | — | 否 | 否 |
| `uhttpd` | uhttpd | 50 | — | 是 | — | 否 | 否 |
| `ucitrack` | luci-base | 80 | — | 是 | — | 否 | 否 |
| `gpio_switch` | base-files | 94 | 10 | 是 | — | 否 | 否 |
| `done` | base-files | 95 | — | 否 | — | 否 | 否 |
| `led` | base-files | 96 | — | 否 | — | 否 | 否 |
| `sysntpd` | busybox | 98 | — | 是 | `ntp` | 是 | 否 |
| `bootcount` | base-files | 99 | — | 否 | — | 否 | 否 |
| `ubihealthd` | ubi-utils | 99 | — | 是 | — | 否 | 否 |
| `urandom_seed` | urandom-seed | 99 | — | 是 | — | 否 | 否 |
| `umount` | base-files | — | 90 | 否 | — | 否 | 否 |

33 个 `rc.d` S/K links 全部跟随这些 init script 的 package owner；静态 link 表没有未知项。

## 6. 高权限控制面入口

| 入口 | Package/source | 静态理由 | 当前边界 |
|---|---|---|---|
| `/sbin/init`、`/sbin/procd` | procd | PID 1、service supervisor、upgrade handoff | 保留；I0.5 还原 instance/trigger/failure |
| `/sbin/ubusd` | ubusd | 系统 IPC broker，runtime user metadata 为 `ubus` | 保留；socket owner/mode 待运行态确认 |
| `/sbin/netifd` | netifd | netlink、device/protocol orchestration | 保留；配置/ubus/netlink 链待 I0.5 |
| `/sbin/rpcd` | rpcd | RPC/ACL/session/plugin boundary | 高敏感；ACL 与 method catalog 待 I0.5 |
| firewall init + `/usr/sbin/fw4` | firewall4 | 生成并加载 nftables ruleset | 执行面保留；generator 输入/错误待 I0.5 |
| dropbear | dropbear | 远程认证入口 | 保留；真实配置和 host key 属于运行态秘密 |
| uhttpd + ubus module | uhttpd | HTTP/RPC exposure | 高敏感；listen/TLS/session 配置待 I0.5 |
| sysupgrade/fit/UBI tools | base-files、fitblk、ubi-utils | 可写 firmware/storage | 未经单独授权不得执行 |
| hostapd/wpa_supplicant | hostapd/wpad | 无线执行面、以 `network` + jail 启动 | 保留成熟执行面 |
| dnsmasq/odhcpd | dnsmasq、odhcpd | DHCP/DNS/network sockets | 保留成熟执行面 |

I0.4 只确认部署入口和静态 privilege hints，不调用其中任何目标程序。

## 7. ACL 与 exposed surface

镜像包含：

- 14 个 rpcd/service ACL 文件；
- 7 个 rpcd native/ucode plugin 文件；
- 159 个 LuCI/HTTP 静态控制面文件；
- 6 个 shipped UCI config；
- 22 个 UCI defaults/migration 文件。

这些路径全部有 package owner，但 ACL method、ubus object、session enforcement 和调用链尚未
因“文件存在”而被声称为运行合同。它们是 I0.5 的定向输入。

## 8. 权限面 gate

| 检查 | 结果 |
|---|---|
| unknown ELF owner/source | 0 |
| unknown executable owner/source | 0 |
| unknown init service owner/source | 0 |
| setid/capability entry | 0 |
| init script explicit user | 2，已登记 |
| init script jail | 3，已登记 |
| static explicit seccomp | 0，未虚构启用状态 |
| storage/flash command executed | 否 |

静态权限面已闭合；effective UID、jail mount/device allowlist、seccomp 实例、socket mode 和
runtime-created secrets 仍是 I0.5/I0.7 问题，不能由本报告替代。
