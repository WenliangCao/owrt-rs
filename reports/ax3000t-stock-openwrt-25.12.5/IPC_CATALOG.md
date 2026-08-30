# AX3000T stock / OpenWrt 25.12.5：IPC 目录

> I0.5 状态：完成
> 日期：2026-08-31
> 范围：ubus 对象与方法、两层 ubus ACL、rpcd 会话与插件、hotplug、socket、netlink
> 设备连接：无。没有任何一条记录来自 `ubus list`。全部来自镜像文件与固定源码。

## 1. 结论与方法边界

本目录记录的是**部署镜像中静态可证的 IPC 注册点**，不是设备上实际存在的对象列表。
每条记录都同时给出：

- **DEP**：镜像里哪个文件提供它；
- **SRC**：固定 revision 源码里的注册语句；
- **是否静态可解析**：对象名是编译期常量，还是运行时拼装。

三条自查规则贯穿全文：

1. 源码里存在某个 ubus 对象，**不等于**该对象在本镜像中部署。
2. 该对象在本镜像中部署，**不等于**它在设备上已注册。
3. ACL 授权了某个对象名，**不等于**存在提供方。

完整机器记录见
[ipc-catalog.json](../../manifests/ax3000t-stock-openwrt-25.12.5/ipc-catalog.json)。

## 2. 部署完整性检查

镜像中共有 **22 个 ELF 链接 `libubus.so.20251202`**。工具按各文件动态字符串数据中
是否出现 `ubus_add_object` / `ubus_connect` / `ubus_invoke` 做角色划分。
（镜像已 strip section header，无法用基于节头的工具走符号表；字节匹配只能证明链接的
接口，不能证明该调用路径在设备上被走到。）

| 角色 | 文件 |
|---|---|
| 注册对象（含 `ubus_add_object`） | `/sbin/procd`、`/sbin/netifd`、`/sbin/rpcd`、`/sbin/logd`、`/sbin/ujail`、`/usr/sbin/odhcpd`、`/usr/sbin/odhcp6c`、`/usr/sbin/dnsmasq`、`/usr/sbin/wpad`、`/usr/lib/rpcd/{file,iwinfo,luci,rpcsys,rrdns}.so`、`/usr/lib/ucode/ubus.so` |
| 仅客户端 | `/bin/ubus`、`/usr/lib/uhttpd_ubus.so`、`/usr/libexec/cgi-io`、`/usr/libexec/logread-ubox`、`/usr/lib/libiwinfo.so.20230701`、`/usr/lib/libudebug.so` |
| 链接但无 ubus 入口点字符串 | `/sbin/init` |

`/sbin/init` 是 procd 的 initd，它链接 libubus 但自身不连接 ubus——连接发生在
`/sbin/procd` 的 `STATE_UBUS`。这解释了为什么 preinit 阶段没有 ubus。

`/usr/lib/ucode/ubus.so` 是 ucode 的 ubus 绑定：它自己不决定对象名，对象名由调用它的
脚本给出（见 §3.3）。

## 3. ubus 对象

### 3.1 编译期常量名（源码可解析，18 个）

| 对象 | 提供方（DEP） | 方法 |
|---|---|---|
| `service` | `/sbin/procd` | `set` `add` `list` `delete` `signal` `update_start` `update_complete` `event` `validate` `get_data` `set_data` `state` `watchdog` |
| `system` | `/sbin/procd` | `board` `info` `reboot` `watchdog` `signal` `validate_firmware_image` `sysupgrade` |
| `container` | `/sbin/procd`、`/sbin/ujail` | `set` `add` `list` `delete` `state` `get_features` `console_set` `console_attach` |
| `network` | `/sbin/netifd` | `restart` `reload` `add_host_route` `get_proto_handlers` `add_dynamic` `netns_updown` |
| `network.device` | `/sbin/netifd` | `status` `set_alias` `set_state` `hotplug_event` `stp_init` |
| `network.interface` | `/sbin/netifd` | `up` `down` `renew` `status` `prepare` `dump` `add_device` `remove_device` `notify_proto` `remove` `set_data` |
| `session` | `/sbin/rpcd` | `create` `list` `grant` `revoke` `access` `set` `get` `unset` `destroy` `login` |
| `uci` | `/sbin/rpcd` | `configs` `get` `state` `add` `set` `delete` `rename` `order` `changes` `revert` `commit` `apply` `confirm` `rollback` `reload_config` |
| `rc` | `/sbin/rpcd` | `list` `init` |
| `file` | `/usr/lib/rpcd/file.so` | `read` `write` `list` `lstat` `stat` `md5` `remove` `exec` |
| `iwinfo` | `/usr/lib/rpcd/iwinfo.so` | `devices` `info` `scan` `assoclist` `freqlist` `txpowerlist` `countrylist` `survey` `phyname` |
| `rpc-sys` | `/usr/lib/rpcd/rpcsys.so` | `packagelist` `password_set` `upgrade_test` `upgrade_start` `upgrade_clean` `factory` `reboot` |
| `luci-rpc` | `/usr/lib/rpcd/luci.so` | `getNetworkDevices` `getWirelessDevices` `getHostHints` `getDUIDHints` `getBoardJSON` `getDHCPLeases` |
| `network.rrdns` | `/usr/lib/rpcd/rrdns.so` | `lookup` |
| `dhcp` | `/usr/sbin/odhcpd` | `ipv6leases` `ipv6ra` `add_lease`（**不含 `ipv4leases`**，见下） |
| `log` | `/sbin/logd` | `read` `write` |
| `luci` | `/usr/share/rpcd/ucode/luci`（经 `ucode.so` 插件） | 由脚本 `return { luci: methods }` 导出 |
| `network.wireless` | `/lib/netifd/wireless.uc`（宿主 `/sbin/netifd`） | 由 ucode 对象定义 |

`rc.list` / `rc.init` 值得单独指出：`rc.c` 是 `ADD_EXECUTABLE(rpcd …)` 的一部分，
**编进 rpcd 主程序**，不是可选插件。它提供通过 ubus 启停任意 init script 的能力。

`file.exec` 同样值得单独指出：它提供通过 ubus 执行程序的能力，受 rpcd 会话 ACL 约束。

**`dhcp.ipv4leases` 不在本部署中。** `odhcpd/src/ubus.c:249` 把该方法包在
`#ifdef DHCPV4_SUPPORT` 内，而 recipe 只在完整 `odhcpd` 变体上加
`-DDHCPV4_SUPPORT=1`（`package/network/services/odhcpd/Makefile:71`）。本镜像安装的是
`odhcpd-ipv6only`，其部署二进制的字符串数据中只有 `ipv6leases`、`ipv6ra`、`add_lease`。
这是"源码方法表 ≠ 本 build 方法集"的实例：方法级的 build gating 必须回到 recipe 读，
不能只读方法表。

JSON 的 `methods_confirmed_in_artifact` 记录了在部署文件字节中确认到的方法名字面量，
共 97 条。它是**正向证据**：命中说明该字面量存在；未命中什么也不说明——链接器会合并
字符串常量，`up`、`set`、`info` 这类短名通常作为更长字符串的尾部存放。

### 3.2 由 ucode 脚本发布（DEP，5 处）

| 对象 | 发布文件 | 宿主二进制 |
|---|---|---|
| `network.wireless` | `/lib/netifd/wireless.uc:573` | `/sbin/netifd`（二进制字符串含 `/lib/netifd`） |
| `hostapd` | `/usr/share/hostap/hostapd.uc:1368` | `/usr/sbin/wpad`（二进制字符串含 `/usr/share/hostap`） |
| `hostapd-auth` | `/usr/share/hostap/hostapd.uc:1372` | `/usr/sbin/wpad` |
| `wpa_supplicant` | `/usr/share/hostap/wpa_supplicant.uc:625` | `/usr/sbin/wpad` |
| `wpa_supplicant.${ifname}` | `/usr/share/hostap/wpa_supplicant.uc:752` | `/usr/sbin/wpad`（名字非常量） |

宿主归属不是猜的：`/sbin/netifd` 和 `/usr/sbin/wpad` 的字符串数据里分别含有
`/lib/netifd` 和 `/usr/share/hostap`。

### 3.3 运行时拼装名（静态只能给出规则，6 条）

| 命名规则 | 提供方 | 源码依据 |
|---|---|---|
| `network.interface.<接口名>` | `/sbin/netifd` | `ubus.c:netifd_ubus_add_interface`，`asprintf("%s.interface.%s", …)` |
| `hotplug.<subsystem>` | `/sbin/procd` | `hotplug-dispatch.c:add_subsystem`，前缀常量 `HOTPLUG_OBJECT_PREFIX = "hotplug."` |
| `container` | `/sbin/ujail` | `jail/jail.c:container_object`，仅走容器路径时注册 |
| `dnsmasq`（默认名，可被 `--ubus` 覆盖） | `/usr/sbin/dnsmasq` | `src/ubus.c:113` `ubus_object.name = daemon->ubus_name` |
| `odhcp6c.<接口名>` | `/usr/sbin/odhcp6c` | `src/ubus.c:209` `snprintf(ubus_name, 24, "odhcp6c.%s", interface)` |
| `wpa_supplicant.<ifname>` | `/usr/sbin/wpad` | `wpa_supplicant.uc:752` |

**这六条只能给出名字的形状，给不出实例集合。** 具体有哪些接口、哪些 subsystem，
必须由运行态观察回答（I0.6）。

ubusd ACL 为其中三条提供了独立的部署侧佐证：`/usr/share/acl.d/dnsmasq_acl.json`
授权发布 `dnsmasq`（确认默认名未被改写的意图），`wpad_acl.json` 授权发布
`hostapd.*` 与 `wpa_supplicant.*`，并显示 procd 会创建 `hotplug.dhcp`、`hotplug.neigh`、
`hotplug.tftp`、`hotplug.ntp` 四个 hotplug 子系统对象。

## 4. ubus 传输层

| 项 | 值 | 证据 |
|---|---|---|
| socket 路径 | `/var/run/ubus/ubus.sock` | `sources/components/ubus/CMakeLists.txt:17`；`/sbin/ubusd` 字符串；`/etc/config/rpcd` |
| socket 权限 | `umask(0111)` → 0666 | `sources/components/ubus/ubusd_main.c:354` |
| 启动方式 | procd `STATE_UBUS` 以用户/组 `ubus` 启动 `/sbin/ubusd` | `sources/components/procd/state.c:141-156` |
| 目录属主 | procd 在 `STATE_UBUS` `mkdir(p->pw_dir, 0755)` 并 `chown` 给 `ubus` | 同上 |

socket 是 0666，所以**文件权限不构成访问控制**。真正的控制在 ubusd ACL（§5）
和 rpcd 会话（§6）两层。任何替换实现如果只复制 socket 路径而不复制这两层，
会静默扩大攻击面。

## 5. 第一层：ubusd ACL（`/usr/share/acl.d/`，5 个文件）

ubusd 按连接进程的 unix 用户/组裁决 publish / send / subscribe / access。

| 文件 | user | publish | subscribe / send | access（对象 → 方法） |
|---|---|---|---|---|
| `dnsmasq_acl.json` | `dnsmasq` | `dnsmasq` | — | `hotplug.dhcp`/`hotplug.neigh`/`hotplug.tftp` → `call` |
| `logd.json` | `logd` | `log` | — | — |
| `ntpd.json` | `ntp` | — | — | `hotplug.ntp` → `call` |
| `wpad_acl.json` | `network` | `hostapd`、`hostapd.*`、`wpa_supplicant`、`wpa_supplicant.*`、`hostapd-auth` | subscribe `udebug`；send `bss.*`、`wps_credentials` | `service` → `event`；`wpa_supplicant` → `phy_set_state`/`phy_set_macaddr_list`/`phy_status`；`hostapd` → `apsta_state`；`udebug` → `get_config` |
| `luci-base.json` | `nobody` | — | — | `system` → `board`、`info` |

两点必须记住：

1. 这些 ACL 只对**非 root** 连接生效。以 root 运行的 `rpcd`、`netifd`、`uhttpd`、
   `odhcpd` 不受此层约束。
2. `wpad_acl.json` 引用的 `udebug` 对象由 `/usr/lib/libudebug.so` 相关组件提供；
   本目录未在任何部署二进制中解析出 `udebug` 对象的注册点，应视为待确认项。

## 6. 第二层：rpcd 会话 ACL（`/usr/share/rpcd/acl.d/`，9 个文件）

rpcd 在 `session` 对象之上做会话与授权。ACL 文件按组授予 `ubus`、`uci`、`file`、
`cgi-io` 四类作用域的 read/write 权限。

| 文件 | 组数 | 主要 ubus 授权 |
|---|---:|---|
| `unauthenticated.json` | 1 | read `session.access`、`session.login` |
| `luci-base.json` | 3 | read `file` `luci` `luci-rpc` `network` `network.device` `network.interface` `uci`；write `file` `uci` |
| `luci-mod-network.json` | 4 | read `file` `fingerprint` `iwinfo` `luci` `luci-rpc` `service`；write `file` `hostapd.*` `iwinfo` |
| `luci-mod-status.json` | 7 | read `file` `fingerprint` `iwinfo` `log` `luci` `luci-rpc` `network.rrdns` |
| `luci-mod-status-index.json` | 6 | read `dsl` `file` `fingerprint` `iwinfo` `luci` `luci-rpc` `system`；write `hostapd.*` |
| `luci-mod-system.json` | 9 | read `file` `luci` `rc`；write `file` `luci` `rc` `system` |
| `luci-app-firewall.json` | 1 | read `file` `luci`；write `file` |
| `luci-app-package-manager.json` | 1 | read `luci` |
| `luci-app-attendedsysupgrade.json` | 1 | read `rpc-sys` `system` `uci`；write `uci` |

`/etc/config/rpcd` 定义的登录会话：

```text
config rpcd
	option socket /var/run/ubus/ubus.sock
	option timeout 30
config login
	option username 'root'
	option password '$p$root'
	list read '*'
	list write '*'
```

`$p$root` 表示"用 `/etc/shadow` 里 root 的口令校验"。会话的 read/write 都是 `*`，
即认证成功后不再受 ACL 组限制。**会话超时 30 秒**是这一层唯一的默认时间边界。

### ACL 引用了但本镜像没有提供方的对象

18 个被 ACL 引用的 ubus 对象里，有 2 个在本镜像中找不到任何提供方：

| 对象 | 通常来自 | 本镜像 |
|---|---|---|
| `dsl` | DSL 相关包 | 未安装 |
| `fingerprint` | `rpcd-mod-fingerprint` 等 | 未安装 |

授权存在、提供方不存在。把 rpcd ACL 当作"可用接口清单"会得到 2 个不存在的接口。

## 7. HTTP → ubus 桥

| 项 | 值 | 证据 |
|---|---|---|
| 模块 | `/usr/lib/uhttpd_ubus.so`（仅客户端，不注册对象） | §2 |
| 启用条件 | `[ -f /usr/lib/uhttpd_ubus.so ]` | `/etc/init.d/uhttpd:153` |
| URL 前缀 | `-u <ubus_prefix>`，默认 `/ubus` | `/etc/uci-defaults/00_uhttpd_ubus` |
| socket | `-U <ubus_socket>`，默认 `/var/run/ubus/ubus.sock` | 同上 |
| CORS | `-X`（`ubus_cors`，默认关） | `/etc/init.d/uhttpd:156` |
| 跳过 session 鉴权 | `-a`（`no_ubusauth`，默认关） | `/etc/init.d/uhttpd:169` |

`/etc/config/uhttpd` 里这些 option 全部是**注释状态**；实际值由
`/etc/uci-defaults/00_uhttpd_ubus` 在首次启动时写入 `uhttpd.main`。因此镜像里的
`/etc/config/uhttpd` 不能直接当成设备上的 uhttpd 配置。

## 8. hotplug

### 8.1 procd 内建规则

`/etc/hotplug.json`（sha256 `5bdcecd7…`）3 条顶层规则，由 procd 在 `STATE_EARLY`
通过 `hotplug("/etc/hotplug.json")` 加载。规则语言是 JSON 表达式（`case`/`if`/`and`/
`regex`/`makedev`/`exec`/`return`），用于建设备节点和触发脚本。

### 8.2 脚本处理器（10 个）

| 子系统 | 脚本 | 读取的环境变量 |
|---|---|---|
| `firmware` | `11-mt76-caldata` | `FIRMWARE` |
| `ieee80211` | `05-wifi-migrate` | `ACTION` |
| `ieee80211` | `10-wifi-detect` | `ACTION` |
| `ieee80211` | `11-ath12k-trigger` | `ACTION` `DEVICENAME` `DEVPATH` |
| `ieee80211` | `11_fix_wifi_mac` | `ACTION` `DEVPATH` `PHYNBR` |
| `iface` | `00-netstate` | `ACTION` `DEVICE` `INTERFACE` |
| `iface` | `20-firewall` | `ACTION` `DEVICE` `INTERFACE` |
| `leds` | `00-init` | `ACTION` `DEVICENAME` |
| `net` | `00-sysctl` | `ACTION` `DEVICENAME` |
| `ntp` | `25-dnsmasqsec` | `ACTION` |

`iface` 与 `ntp` 子系统的事件不是内核 uevent，而是由 netifd / ntpd-hotplug 经 procd
的 `hotplug.<subsystem>` 对象注入。这就是 §5 中 `dnsmasq`、`ntp` 用户被授权
`call` `hotplug.dhcp` / `hotplug.ntp` 的原因。

`11-ath12k-trigger` 针对 ath12k 硬件；本设备是 MediaTek filogic + mt76，该脚本是否
被触发取决于实际 PHY，静态不判定。

## 9. 其他 IPC 面

| 面 | 本镜像证据 |
|---|---|
| netlink | 扫描三个组件源码的符号出现：`netifd` 有 `rtnl`×42、`NETLINK_ROUTE`×2、`NETLINK_KOBJECT_UEVENT`×1；`odhcpd` 有 `rtnl`×48、`NETLINK_ROUTE`×2；`procd` 有 `NETLINK_KOBJECT_UEVENT`×1。未扫描 `wpad`（`nl80211` 路径在 hostap 树内）。这些计数**仅作定位用，不构成协议合同** |
| signal / pidfile | `procd_send_signal` 在 `/etc/init.d/` 中出现 4 次；`dnsmasq`、`dropbear`、`log` 各自用 `-x`/`-P`/`-p` 指定 pidfile |
| unix socket（非 ubus） | `hostapd` `-g /var/run/hostapd/global`、`wpa_supplicant` `-g /var/run/wpa_supplicant/global`（control interface） |
| 文件监视 | `procd_set_param file` 在 `dnsmasq`、`cron`、`uhttpd` 上声明，由 procd 监视并重启 instance |
| 日志 | `logd` 提供 `log` 对象（`read`/`write`）；`logread` 作为客户端；procd 在 `STATE_INIT` 后 `ulog_open(ULOG_SYSLOG,…)` |

## 10. 静态证据边界（转入 I0.6）

- **实际注册的对象列表**：只有 `ubus list` 能给出。本目录给的是"镜像允许出现什么"。
- **`network.interface.*`、`hotplug.*`、`odhcp6c.*`、`wpa_supplicant.*` 的实例集合**：未知。
- **`udebug` 对象的提供方**：ACL 引用了它，但未在任何部署二进制中解析出注册点。
- **方法参数 schema**：本阶段只提取了方法名。blobmsg policy 的字段名与类型需要在
  C1 冻结合同时逐方法提取，不能靠方法名推断。
- **`dnsmasq` 是否以默认名注册**：取决于生成的配置里是否有 `--ubus` 覆盖。
- **rpcd 会话的实际存续与超时行为**：30 秒是配置值，实际续期行为未观察。
- **`file.exec` 与 `rc.init` 的实际可达性**：取决于会话 ACL 与登录状态。
  这两个方法的能力等价于远程执行，是替换边界评估中优先级最高的安全面。
- **观察这些对象的采集命令必须逐条审查副作用**：`iwinfo.scan`、`network.interface.up/down`、
  `rc.init`、`rpc-sys.upgrade_*`、`system.reboot`、`file.write/remove/exec`、
  `uci.apply/commit` 都有副作用，**不得**进入只读采集清单。
