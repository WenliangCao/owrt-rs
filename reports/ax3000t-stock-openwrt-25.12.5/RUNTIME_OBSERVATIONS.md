# AX3000T stock / OpenWrt 25.12.5：运行态观察

> I0.7 状态：完成
> 日期：2026-08-31
> 授权：用户明确授权设备接入与采集执行
> 范围：**一台设备、一个时刻、一次观察**。不描述未采集的时序、故障态或其他启动。

## 1. 执行记录

| 项 | 值 |
|---|---|
| 接入方式 | SSH 公钥（ed25519）；口令未在任何命令行中出现 |
| 执行命令 | 仅 [RUNTIME_QUESTIONS.md](RUNTIME_QUESTIONS.md) 已批准的 23 条只读命令 |
| 单命令超时 | 30 s |
| 写操作 | 无。未写 UCI、未 commit、未 reload、未重启服务、未读 MTD |
| 原始输出 | Git 之外的私有 evidence 目录 |
| 非零退出 | 1 条：`ubus -v list udebug` 退出 4（Not found），见 §4 |
| 脱敏 | [i0_7_observation.py](../../tools/i0_7_observation.py) 生成派生 manifest 后自检地址/MAC/口令形状字符串，**0 命中**才写出 |
| 采集验收 | 23/23 个预期文件齐全；header/footer、允许的退出码和设备身份全部由生成器强制检查 |

机器记录见
[runtime-observations.json](../../manifests/ax3000t-stock-openwrt-25.12.5/runtime-observations.json)。
本报告不含地址、MAC、SSID、密钥、会话令牌。

## 2. 身份门（Q00）

设备身份与本项目基线**完全一致**：

| 字段 | 设备实测 | I0.1 基线 |
|---|---|---|
| `DISTRIB_RELEASE` | `25.12.5` | `25.12.5` |
| `DISTRIB_REVISION` | `r33051-f5dae5ece4` | `r33051-f5dae5ece4` |
| `DISTRIB_TARGET` | `mediatek/filogic` | `mediatek/filogic` |
| `board_name` | `xiaomi,mi-router-ax3000t` | `xiaomi,mi-router-ax3000t` |
| `kernel` | `6.12.94` | `6.12.94` |
| `rootfs_type` | `squashfs` | `squashfs` |
| `DISTRIB_TAINTS` | 空 | — |

用户初始提供的版本是 25.12.4，实测为 25.12.5；用户已说明该信息略滞后。冲突已消解，
按 §4.3 记录为"比较了不同时间点的同一设备"，**不**标记 `contradicted`。

## 3. 部署偏移（Q14、Q13、Q03、Q12）

设备不是"纯出厂镜像"，但偏移范围很小且已量化。

### 3.1 软件包：+4 / -0 / 版本变更 0

| 项 | 值 |
|---|---|
| 设备已安装 | 163 |
| 镜像 | 159 |
| 新增 | `luci-i18n-base-zh-cn`、`luci-i18n-firewall-zh-cn`、`luci-i18n-attendedsysupgrade-zh-cn`、`luci-i18n-package-manager-zh-cn` |
| 删除 | 无 |
| 版本变更 | 无 |

四个新增全部是 LuCI 中文语言包，只含翻译数据，不引入守护进程、ubus 对象或 init 脚本。
**因此 I0.4/I0.5 基于 159 包得出的全部结论在本设备上继续成立。** 这条关闭了
[PROVENANCE_GAPS.md](PROVENANCE_GAPS.md) 里"未验证用户是否增删改过 package"的缺口。

### 3.2 随镜像发布的 6 个配置：4 个已改

| 配置 | 与镜像一致 | 说明 |
|---|---|---|
| `dropbear` | 是 | 尽管本次采集正是经 SSH 进行，该文件未被改动 |
| `rpcd` | 是 | `50-migrate-rpcd-ubus-sock.sh` 未产生实际改动（socket 本已正确） |
| `luci` | 否 | 预期：`30_luci-theme-bootstrap`、`50_luci-mod-admin-full` 写入 |
| `uhttpd` | 否 | 预期：`00_uhttpd_ubus` 写入 `ubus_prefix`（见 §5） |
| `dhcp` | 否 | 非 uci-defaults 可解释，属用户/历史修改 |
| `firewall` | 否 | 非 uci-defaults 可解释，属用户/历史修改 |

### 3.3 首启已完成，且设备带有更早的配置历史

- `/etc/uci-defaults/` **为空** → 22 个 uci-defaults 全部执行并被删除；
- `/etc/board.json` 存在；
- `/tmp/.uci` 为空、`/var/run/uci` 不存在 → **没有未提交的 UCI delta**；
- `/etc/rc.local` **存在**（镜像不发布该文件）。内容是 OpenWrt 默认模板加 `exit 0`，
  无自定义命令。I0.5 曾据镜像判断"出厂状态该分支不触发"，在本设备上
  `/etc/init.d/done` 会执行它，但因内容为空模板而无实际效果。

`/var/run/config.md5` 的跟踪列表暴露出镜像中不存在的配置文件，包括
`attendedsysupgrade`、`ubihealthd`、`ubootenv`（均由 uci-defaults 创建，预期内），
以及一组带时间戳的备份与 `dnsproxy` 相关残留。这些文件名表明**本设备在当前固件之前
被其他工具修改过配置**，并经 sysupgrade 配置保留延续至今。

本阶段只登记这一事实，不推断其内容或影响；它属于 I0.8 的风险登记项。

## 4. ubus 实际注册面（Q05、Q09、Q10）

设备上共 **40 个 ubus 对象**。

### 4.1 静态预测的命中情况

| 分类 | 数量 | 结论 |
|---|---:|---|
| 静态字面量对象，已注册 | 22 | 全部命中 |
| 静态字面量对象，**未**注册 | **0** | 没有"源码里有但设备上没有"的漏报 |
| 匹配动态命名规则 | 17 | 六条规则全部得到实例 |
| **未被静态预测** | **1** | `dnsmasq.dns`，见 §4.3 |

动态规则的实际实例：

- `network.interface.{lan,loopback,wan,wan6}` —— 4 个
- `hotplug.{button,dhcp,firmware,ieee80211,iface,leds,neigh,net,ntp,tftp}` —— 10 个
  （I0.5 只能从 ubusd ACL 推出其中 4 个，运行态给出完整集合）
- `hostapd.{phy0-ap0,phy1-ap0}` —— 2 个射频
- `odhcp6c.wan` —— 1 个
- `dnsmasq` —— 使用默认名，未被 `--ubus` 覆盖
- `wpa_supplicant.<ifname>` —— **无实例**，本设备未配置 STA 接口

### 4.2 三条 build gating 结论全部被证实

| 对象 | 方法 | 源码条件 | 预测 | 实测 |
|---|---|---|---|---|
| `dhcp` | `ipv4leases` | `#ifdef DHCPV4_SUPPORT` | 不存在 | **不存在**（只有 `ipv6leases`、`ipv6ra`、`add_lease`） |
| `network.device` | `hotplug_event` | `#ifdef DUMMY_MODE` | 不存在 | **不存在**（只有 `status`、`set_alias`、`set_state`、`stp_init`） |
| `dnsmasq` | `set_connmark_allowlist` | `#ifdef HAVE_CONNTRACK` | 不存在 | **不存在**（`dnsmasq` 只有 `metrics`） |

同时，被我在 I0.5 中间稿废弃的"字节缺失即方法不存在"判据也被证伪：`iwinfo.info`、
`file.stat`、`uci.{add,set,state,reload_config}`、`network.interface.{up,down,status,dump}`
等 12 个曾被误报"缺失"的方法在设备上全部存在。废弃该判据是正确的。

### 4.3 唯一的静态漏报：`dnsmasq.dns`

设备上存在 `dnsmasq.dns` 对象，I0.5 的 IPC 目录没有它。

原因是方法性的，不是笔误：该对象**只在 OpenWrt 的
`200-ubus_dns.patch:176` 中定义**，上游 `dnsmasq-2.93/src/ubus.c` 里出现 0 次。
I0.5 的解析器只读未打补丁的上游 checkout，结构上看不到补丁引入的注册点。

I0.4 已经登记了 313 个 recipe patch 资产，但 IPC 目录从未消费它们。**要得到完整的
ubus 注册面，源码解析必须同时覆盖 patch stack。** 这条已写入 §7 与
[STATIC_RUNTIME_DIFF.md](STATIC_RUNTIME_DIFF.md)。

### 4.4 `udebug` 不存在

`ubus -v list udebug` 返回 `Not found`（退出码 4）。

这关闭了 I0.5 的开放问题：`/usr/share/acl.d/wpad_acl.json` 授权 `network` 用户访问并
订阅 `udebug`，但本设备上**没有任何提供方**。ubusd ACL 会授权不存在的对象，
与 rpcd ACL 授权 `dsl`、`fingerprint` 是同一类现象——**ACL 是意图声明，不是接口清单**。

## 5. HTTP → ubus 暴露面（Q13）

`uhttpd.main` 实测关键项：

| 选项 | 实测值 | 来源 |
|---|---|---|
| `ubus_prefix` | `/ubus` | `00_uhttpd_ubus` 首启写入（镜像中该行是注释） |
| `ubus_socket` | 未设置 | 使用默认 `/var/run/ubus/ubus.sock` |
| `no_ubusauth` | 未设置 | 默认 0，即**要求会话鉴权** |
| `ubus_cors` | 未设置 | 默认 0 |
| `listen_http` | `0.0.0.0:80`、`[::]:80` | — |
| `listen_https` | `0.0.0.0:443`、`[::]:443` | — |
| `redirect_https` | `0` | — |
| `rfc1918_filter` | `1` | — |

`rpcd` 实测与镜像一致：socket 为 `/var/run/ubus/ubus.sock`，`timeout 30`，
`login` 段用户名 `root`、读写范围 `*`。**口令字段未记录、未提交、未展示。**

## 6. 启动与特权实测

### 6.1 kernel command line（Q01）—— 关闭 I0.5 最大的静态未知

```text
console=ttyS0,115200n1 loglevel=8 swiotlb=512 rootfstype=squashfs firmware=0 mtd=ubi uart_en=1
```

**不含任何 `rootfs_mount_options.*` token。** 因此 `/lib/preinit/80_mount_root` 的
`compose_rootfs_mount_options()` 在本设备上返回空串，`mount_root start` 不带额外挂载选项。
I0.5 标记的"cmdline 未知会直接影响 rootfs 挂载选项"这一风险，在本设备上确认为**无影响**。

`/tmp/.failsafe` 不存在 → 本次启动**未进入 failsafe**。

### 6.2 服务与实例（Q06）

设备上 procd 管理 **19 个服务**，镜像只有 18 个 init 脚本声明 `USE_PROCD=1`。

多出来的是 **`ubus`**：它没有 init 脚本，由 procd 在 `STATE_UBUS` 通过
`service_start_early("ubus", "/sbin/ubusd", "ubus", "ubus")` 直接注册，实测
`user=ubus group=ubus respawn={3600,1,0} term_timeout=5`。**任何只扫描 `/etc/init.d`
的静态分析都看不到它。**

声明实例数与运行实例数的差异：

| 服务 | 声明 | 运行 | 说明 |
|---|---:|---:|---|
| `log` | 3 | 1 | 只有 `logd`；未配置 `log_file`/`log_ip`，`logfile`/`logremote` 未产生 |
| `wpad` | 2 | 2 | `hostapd` + `supplicant` |
| `dnsmasq` | 1 | 1 | 实例名 `cfg01411c`，即匿名 UCI section 名 |
| `urandom_seed` | 1 | 1（已停止） | 一次性任务，完成后保留为 stopped |
| `firewall`、`gpio_switch`、`packet_steering`、`system`、`ucitrack` | 0 | 0 | 与 I0.5 的"一次性 procd 服务"分类**完全一致** |

### 6.3 ucitrack 实际注册了 10 条 trigger —— I0.5 的四条预测全部命中

| I0.5 预测 | 实测 |
|---|---|
| procd 服务的 `init` 字段不注册（`firewall`/`dnsmasq`/`network`/`odhcpd`/`dropbear`） | 命中：这些均未出现 |
| 非 procd 的 `init: led` 会注册 | 命中：`["eq","package","system"] → run_script /etc/init.d/led reload` |
| `exec: /sbin/block mount` 会注册但悬空 | 命中：已注册；`/sbin/block` 与 `block-mount` 均不存在 |
| `affects` 指向未安装包仍会注册 | 命中：`luci-splash`、`qos`、`miniupnpd`、`luci_statistics` 四条事件均已注册，无订阅者 |

### 6.4 特权与 jail：声明 ≠ 生效（Q11）

| 进程 | uid/gid | CapEff | NoNewPrivs | 独立 namespace |
|---|---|---|---:|---|
| `logd` | 514 / 514 | 0 | 0 | 无 |
| `hostapd`（工作进程） | 101 / 101 | `…3400` | 1 | **无** |
| `wpa_supplicant`（工作进程） | 101 / 101 | `…3400` | 1 | **无** |
| `ntpd`（工作进程） | 123 / 123 | `…2000400` | 1 | **ipc、mnt、pid** |
| `dnsmasq`（工作进程） | 453 / 453 | `…3400` | 0 | **ipc、mnt、pid** |

三条结论：

1. **wpad 声明了 `procd_add_jail` 但没有获得任何 namespace 隔离。** 原因可从
   `/lib/functions/procd.sh` 的 `_procd_add_jail` 读出：wpad 只写
   `procd_add_jail hostapd`——只有名字，无 flag、无 mount；而 `sysntpd` 写
   `procd_add_jail ntpd ubus` + 5 个 mount，`dnsmasq` 写
   `procd_add_jail dnsmasq ubus log` + mount。**没有 mount 和 flag 的 jail 不产生
   namespace。** wpad 实际获得的只是 user/group + capabilities + no_new_privs。
2. `dnsmasq` 的 `NoNewPrivs=0`，与 wpad/ntpd 的 `1` 不同。这与 I0.5 的判断一致：
   dnsmasq 靠自身 `--user=dnsmasq` 降权，走的不是 procd 的 `user` 参数路径。
3. **所有进程 `Seccomp=0`**，且没有任何进程使用独立 net namespace。

`logd` 以 uid 514 运行，证实 `ubox/log/logd.c:267-275` 的进程内 `getpwnam("logd")` 降权。

## 7. 本次观察当时未能回答的问题及后续状态

- **Q02 没有取得本次启动的日志。** `logread` 的环形缓冲区只覆盖采集前约 93 分钟，
  启动记录已被覆盖，加大 `-l` 行数也无法取回。后续源码审查已经证明 rcS 严格串行及其
  失败传播，关闭 OQ-01；只有真实逐项耗时仍作为非阻塞 OQ-09 开放。默认 procd debug 0
  不输出 `DEBUG(2)` duration，因此普通重启后读 `logread` 仍不够。
- **`reload` 的实际中断行为、服务失败传播、UCI 并发写入**：I0.6 已说明这三项需要主动
  触发或注入故障，不属于只读观察，本次未做也不应做。
- **`/etc/config/{dhcp,firewall}` 的具体改动内容**：已在后续独立、脱敏、只读审查中关闭
  OQ-07。DHCP 现值等价于镜像加 `15_odhcpd` 的预期首启结果；旧 DNS override 已失效；
  firewall 的软件 flow offloading 正在生效。见 [I0_FOLLOWUP_REVIEW.md](I0_FOLLOWUP_REVIEW.md)。
- **设备历史修改的操作者**：现存元数据不足以完全重建，但 C1 oracle 只需要经审查的当前
  输入与行为，不依赖操作者身份，因此不再构成阻塞项。

## 8. 观察边界

本报告是**一台设备在 2026-08-31 一个时刻的一次观察**。它不能外推到：
其他启动、其他配置、故障状态、并发时序，或任何未采集的方法调用结果。
每条结论的适用范围到此为止。
