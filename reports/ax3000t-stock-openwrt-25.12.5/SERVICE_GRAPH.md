# AX3000T stock / OpenWrt 25.12.5：服务图

> I0.5 状态：完成
> 日期：2026-08-31
> 范围：25 个 init script、16 个声明式 procd instance、31 条 trigger、8 组 validation
> 设备连接：无。所有实例、PID、状态和实际重启行为均未观察。

## 1. 结论

25 个 init script 分成三类：

| 类别 | 数量 | 服务 |
|---|---:|---|
| 长驻 procd 服务（有 instance） | 13 | `cron`、`dnsmasq`、`dropbear`、`log`、`network`、`odhcpd`、`rpcd`、`sysntpd`、`ubihealthd`、`uhttpd`、`urandom_seed`、`urngd`、`wpad` |
| 一次性 procd 服务（`USE_PROCD=1` 但无 instance） | 5 | `firewall`、`gpio_switch`、`packet_steering`、`system`、`ucitrack` |
| 非 procd 服务 | 7 | `boot`、`bootcount`、`done`、`led`、`sysctl`、`sysfixtime`、`umount` |

一次性 procd 服务借用 procd 的 trigger/validate 框架，但 `start_service` 同步执行完就
退出，procd 不监管长驻进程。它们没有"运行中"这个状态，全部效果落在它们写出的内核或
文件系统状态上。`firewall` 是这一类里影响面最大的：它的全部状态就是 nftables ruleset。

完整机器记录见
[service-graph.json](../../manifests/ax3000t-stock-openwrt-25.12.5/service-graph.json)。

## 2. 长驻服务的 instance 命令

命令按镜像原文记录。带 shell 参数展开操作符的部分（`${x:+…}`、`${x:1}`、`${x:-…}`）
刻意不展开——改写它们会伪造一条设备上不存在的 argv。多行表示脚本用
`procd_append_param command` 逐项追加，构成**同一个** argv，不是多个进程。

| 服务 | instance | 命令要点 |
|---|---:|---|
| `urngd` | 1 | `"/sbin/urngd"` |
| `log` | 3 | instance `logd`：`"/sbin/logd" -S "${log_buffer_size}"`；`logfile`：`"$PROG" -f -F "$log_file" -p "$pid_file"`；`logremote`：`"$PROG" -f -h … -r "$log_ip" "${log_port}"` |
| `rpcd` | 1 | `"/sbin/rpcd" ${socket:+-s "$socket"} ${timeout:+-t "$timeout"}` |
| `dnsmasq` | 1 | `/usr/sbin/dnsmasq -C /var/etc/dnsmasq.conf.${cfg} -k -x /var/run/dnsmasq/dnsmasq."${cfg}".pid` |
| `dropbear` | 1 | `"/usr/sbin/dropbear" -F -P "$pid_file"` + 15 个条件追加项（`-p`、`-a`、`-s`、`-w`、`-g`、`-j`、`-k`、`-I`、`-T`、`-K`、`-W`、`-b`、`-c`、`-l`） |
| `wpad` | 2 | instance `hostapd`：`/usr/sbin/hostapd -s -g /var/run/hostapd/global`；`supplicant`：`/usr/sbin/wpa_supplicant -n -s -g /var/run/wpa_supplicant/global` |
| `network` | 1 | `/sbin/netifd` |
| `odhcpd` | 1 | `/usr/sbin/odhcpd` |
| `cron` | 1 | `"/usr/sbin/crond" -f -c /etc/crontabs -l "${loglevel:-7}"` |
| `uhttpd` | 1 | `"/usr/sbin/uhttpd" -f` + `-c /var/etc/uhttpd/httpd.${cfg}.conf` + `-p/-s/-h/-i/-I/-y` 追加项 |
| `sysntpd` | 1 | `"/usr/sbin/ntpd" -n -N` + `-S "/usr/sbin/ntpd-hotplug"`、`-p $peer`、`-I "$ifname"`、`-l` |
| `ubihealthd` | 1 | `"/usr/sbin/ubihealthd" -f -d "$device"` + `-i "$interval"` |
| `urandom_seed` | 1 | `"/sbin/urandom_seed"`，`stdout`/`stderr` 打开 |

`log`、`wpad` 用 `procd_open_instance <name>` 显式命名 instance（`logd`/`logfile`/
`logremote`、`hostapd`/`supplicant`）；其余服务的 instance 未命名。

`dnsmasq`、`uhttpd`、`log`、`dropbear` 的实际 instance 数由运行时 UCI section 数量决定
（它们的 `start_service` 走 `config_foreach`）。上表的 16 是**声明点**数量，不是运行
进程数。

## 3. procd 生命周期语义（`/etc/rc.common`，DEP）

`USE_PROCD=1` 时 `rc.common` 重定义命令入口：

| 命令 | 行为 |
|---|---|
| `start` | `rc_procd start_service` → `procd_open_service` … `procd_close_service set`；若定义了 `service_started` 则调用 |
| `stop` | `procd_lock`；`stop_service`；`procd_kill <name> <instance>`；若定义了 `service_stopped` 则调用 |
| `reload` | 若脚本定义 `reload_service` 则 `procd_lock` + `reload_service`，**否则退化为 `start`** |
| `restart` | 基础实现：屏蔽 TERM → `stop` → 恢复 TERM → `start` |
| `running` / `status` | `procd_running` / `_procd_status` |
| `trace` | `TRACE_SYSCALLS=1` 后 `start` |
| `info` | `_procd_ubus_call list` |

**`reload` 没有统一语义。** 只有 8 个服务定义了 `reload_service`：

```text
dnsmasq  firewall  network  odhcpd  packet_steering  rpcd  system  urngd
```

其余服务（含 `uhttpd`、`dropbear`、`wpad`、`log`、`cron`、`sysntpd`、`ubihealthd`、
`urandom_seed`）的 `reload` 等于重新提交服务定义给 procd。任何替换实现必须逐服务对齐，
不能假设 `reload` 一律是"不中断重载"。

`firewall` 额外自定义了 `restart()`（直接 `fw4 restart`），绕过了 rc.common 的
stop→start 序列。

## 4. Trigger 图（31 条）

### 4.1 config.change（UCI 提交触发）

| 服务 | 监听的 config |
|---|---|
| `network` | `network`、`wireless` |
| `firewall` | `firewall`（另有 `procd_add_reload_data_trigger firewall`） |
| `dnsmasq` | `dhcp`、`system` |
| `odhcpd` | `dhcp`、`network`、`system` |
| `system` | `system` |
| `log` | `system` |
| `gpio_switch` | `system` |
| `packet_steering` | `network`、`firewall` |
| `uhttpd` | `uhttpd` |
| `dropbear` | `${NAME}`（脚本内变量） |
| `sysntpd` | `system` |

### 4.2 interface / raw / mount trigger

| 服务 | trigger |
|---|---|
| `dnsmasq` | `interface.*` → `/etc/init.d/dnsmasq reload` |
| `dropbear` | `interface.*` → `/etc/init.d/dropbear reload` |
| `sysntpd` | `interface.*` → reload（config/interface/raw 三种形式并存） |
| `packet_steering` | raw `interface.*` 1000ms → reload |
| `uhttpd` | raw `interface.*.up` 1000ms → `start`；raw `interface.$iface.up` 1000ms → `start` |
| `uhttpd` | raw `acme.renew` 5000ms → reload |
| `log` | `procd_add_action_mount_trigger start "${log_file}"` |

`uhttpd` 的 `acme.renew` trigger 由 acme 包发送。本镜像**没有安装 acme**
（`/usr/sbin/acme`、`/etc/init.d/acme` 均不存在；159 个 package 中无 `acme`）。
这是一条 grep 会命中、但在本部署上没有发送方的悬空边。

### 4.3 ucitrack 注册的跨配置依赖

`ucitrack`（START=80）读取 `/usr/share/ucitrack/*.json`，把 LuCI 的配置依赖翻译成
procd config.change trigger。8 个文件的实际内容：

| 文件 | config | init | exec | affects |
|---|---|---|---|---|
| `luci-app-firewall.json` | `firewall` | `firewall` | — | `luci-splash`、`qos`、`miniupnpd` |
| `luci-mod-network-dnsmasq.json` | `dhcp` | `dnsmasq` | — | `odhcpd` |
| `luci-mod-network-interfaces.json` | `network` | `network` | — | `dhcp` |
| `luci-mod-network-odhcpd.json` | `odhcpd` | `odhcpd` | — | — |
| `luci-mod-network-wireless.json` | `wireless` | — | — | `network` |
| `luci-mod-system-dropbear.json` | `dropbear` | `dropbear` | — | — |
| `luci-mod-system-mounts.json` | `fstab` | — | `/sbin/block mount` | — |
| `luci-mod-system-system.json` | `system` | `led` | `/etc/init.d/log reload` | `luci_statistics`、`dhcp` |

四条部署事实必须一起读：

1. `register_init` 只对**非 procd** 且 `enabled` 的 init 脚本注册 trigger，条件是
   `[ -x "$init" ] && "$init" enabled && ! grep -sqE 'USE_PROCD=.' "$init"`。
   `firewall`、`dnsmasq`、`network`、`odhcpd`、`dropbear` 都声明了 `USE_PROCD=1`，
   因此它们的 `init` 字段在本镜像里**不产生** ucitrack trigger；真正生效的是各自 init
   脚本中的 `procd_add_reload_trigger`。`luci-mod-system-system.json` 的 `init: led`
   指向非 procd 的 `/etc/init.d/led`，这一条会实际注册。
2. `affects` 字段不受上述过滤影响，总是注册
   `ubus call service event '{"type":"config.change","data":{"package":"<affected>"}}'`。
3. `luci-app-firewall.json` 的 `affects` 指向 `luci-splash`、`qos`、`miniupnpd`，
   `luci-mod-system-system.json` 指向 `luci_statistics`——这些包**都没有安装**。
   事件仍会发出，只是没有订阅者。
4. `luci-mod-system-mounts.json` 的 `config: fstab` 和 `exec: /sbin/block mount` 在本
   镜像里**全部悬空**：`/etc/config/fstab` 不存在、`/sbin/block` 不存在、`block-mount`
   未安装。

这四点合起来说明一件事：`/usr/share/ucitrack/*.json` 是 LuCI 侧的意图声明，不是本部署
的实际 trigger 集合。把它当接口合同会得到错误的调用图。

## 5. 配置校验（8 组 `uci_validate_section`）

| 服务 | config | section type |
|---|---|---|
| `network` | `network` | `atm-bridge`、`route`、`route6`、`rule`、`rule6`、`switch`、`switch_vlan` |
| `system` | `system` | `validate_system_section` |
| `log` | `system` | `validate_log_section` |
| `cron` | — | `validate_cron_section` |
| `dropbear` | `dropbear` | `validate_section_dropbear` |
| `sysntpd` | `system` | `validate_ntp_section` |

`network` 的 validation 覆盖的是 `atm-bridge`/`route`/`rule`/`switch` 这些**旁路**段，
不覆盖 `interface`、`device`、`bridge-vlan` 等主干段——那些由 netifd 自己解析。
把 `procd_open_validate` 的覆盖面误当成"netifd 配置 schema"会得到错误结论。

`network` 的 `route6`/`rule6` validation 带 `[ -e /proc/sys/net/ipv6 ]` 条件，
静态无法判定该路径是否成立。

## 6. 特权面

镜像内全部 1223 个 inode 的 uid/gid 均为 0/0，无 setuid、无 setgid、无 file capability
（I0.4 结论，本阶段复用）。默认服务身份是 root，只有两个服务显式降权：

| 服务 | user | group | capabilities | no_new_privs | jail |
|---|---|---|---|---|---|
| `sysntpd` | `ntp` | `ntp` | `/etc/capabilities/ntpd.json` | 1 | 是（5 个 `procd_add_jail_mount`） |
| `wpad`（两个 instance） | `network` | `network` | `/etc/capabilities/wpad.json` | 1 | 是 |
| `dnsmasq` | — | — | — | — | 是（7 个 `procd_add_jail_mount`），仍以 root 运行 |

**init script 的 procd 参数不是特权面的全部。** 两个守护进程由自己降权，procd 参数
里看不到：

| 守护进程 | 降权方式 | 证据 |
|---|---|---|
| `logd` | 进程内 `getpwnam("logd")` + `setgid` + `setuid` | `sources/components/ubox/log/logd.c:267-275` |
| `dnsmasq` | init 脚本写入 `--user=dnsmasq --group=dnsmasq` 到生成的配置 | `/etc/init.d/dnsmasq:1178-1179` |
| `ubusd` | 由 procd 以 `service_start_early("ubus", "/sbin/ubusd", "ubus", "ubus")` 启动 | `sources/components/procd/state.c:155` |

镜像的 `/etc/passwd` 定义了 9 个账户：`root`、`daemon`、`ftp`、`network`(101)、
`nobody`(65534)、`ntp`(123)、`dnsmasq`(453)、`logd`(514)、`ubus`(81)。其中
`network`、`ntp`、`dnsmasq`、`logd`、`ubus` 全部对应上面的降权路径或 ubusd ACL 条目
（见 [IPC_CATALOG.md](IPC_CATALOG.md) §5）。

其余长驻服务（`rpcd`、`netifd`、`uhttpd`、`odhcpd`、`dropbear`、`crond`、`urngd`、
`ubihealthd`）以 root、无 jail、无 capability 限制运行。`rpcd` 和 `uhttpd` 同时是网络
可达面，这一点在划分替换边界时必须显式记录。

其他值得注意的 instance 参数：

- `network`：`respawn`、`watch network.interface`、`limits core="unlimited"`
- `log`：`respawn 5 1 -1`
- `wpad`：`respawn 3600 1 0`、`limits core="unlimited"`
- `dnsmasq`：`netdev $instance_netdev`、`file /var/etc/dnsmasq.conf.${cfg}`、
  `env USER_DHCPSCRIPT="$user_dhcpscript"`
- `cron`：`file "$crontab"`
- `uhttpd`：`stderr 1`

`procd_set_param file` 声明的是"该文件变化即重启该 instance"的依赖，不是普通打开文件。

## 7. 静态证据边界（转入 I0.6）

- **instance 实际数量**：由运行时 UCI section 数量决定，未观察。
- **shell 变量实际取值**：`$PROG`、`$cfg`、`$instance_netdev`、`${listen:1}`、
  `$pid_file` 等未展开，也不应由静态分析臆造。
- **`reload` 的实际效果**：哪些 reload 真正不中断、哪些等价于重启，静态不可判定。
- **服务失败传播**：某个 S 脚本失败后 procd 是否继续、是否重试，未观察。
- **`fw4` 生成的 ruleset**：只有运行态能给出实际 nftables 内容。
- **ucitrack 实际注册结果**：`register_init` 的分支依赖 `"$init" enabled` 的运行时判断，
  必须在设备上确认最终注册了哪些 trigger。
- **jail 是否真正生效**：`procd_add_jail` 依赖 `procd-ujail` 与内核支持，实际是否进入
  namespace 未观察。
