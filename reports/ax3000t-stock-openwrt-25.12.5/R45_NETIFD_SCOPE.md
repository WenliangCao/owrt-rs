# R45 · netifd 的本机实际职责

日期：2026-09-07。目的：把 `docs/RUST_CORE_CONTROL_PLAN.md` §3 要求的那张表落到本机，
确定 netifd-rs 必须实现什么、可以不实现什么。

来源：设备只读采集（`uci show network/wireless`、`ubus call network.interface dump`、
`network.device status`、`network.wireless status`、`network get_proto_handlers`），
以及精确源码 `netifd cbb83a18`（23 987 行 C）与 `/lib/netifd` 下的 4 091 行脚本/ucode。
原始采集含 WiFi 口令、公网前缀、DUID 和 MAC，只留在 Git 外；本文只记结构。

## 1. 配置面（全部实际使用）

| 段 | 实例 | 关键属性 |
|---|---|---|
| `interface` | `loopback` | `proto static`，`device lo`，`127.0.0.1/8` |
| `interface` | `lan` | `proto static`，`device br-lan`，`192.168.1.1/24`，`ip6assign 60` |
| `interface` | `wan` | `proto dhcp`，`device wan` |
| `interface` | `wan6` | `proto dhcpv6`，`device wan` |
| `device` | `br-lan` | `type bridge`，`ports lan2 lan3 lan4` |
| `device` | `wan` | `macaddr`（覆盖，值不记录） |
| `globals` | — | `ula_prefix /48`、`dhcp_default_duid`、`packet_steering 1` |

无线：两个 `wifi-device`（radio0 = 2g HE20 ch1，radio1 = 5g HE80 ch44，均 `country DE`、
`cell_density 0`）与两个 `wifi-iface`（都是 `mode ap`、`encryption sae-mixed`、`network lan`、
`ocv 0`），运行时 ifname 为 `phy0-ap0` / `phy1-ap0`。

**本机不使用**：VLAN（无 8021q/8021ad 段）、bonding、macvlan、veth、vrf、tunnel、alias、
iprule（`uci show network` 里没有 `rule`/`rule6`）、静态路由段、extdev（外部设备 handler）。
`ppp`/`pppoe` 的 handler 已注册但没有接口使用它们。

## 2. 协议 handler

`get_proto_handlers` 返回 5 个：`dhcp`、`dhcpv6`、`ppp`、`pppoe`、`static`。

- `static` 是 netifd 内建（`proto-static.c`）。
- 其余 4 个是 proto-shell（`/lib/netifd/proto/{dhcp,dhcpv6,ppp}.sh`），由 netifd 通过
  `netifd-proto.sh`（484 行）调用，回写走 `network.interface.notify_proto`。
- 本机实际跑起来的只有 `static`（lan/loopback）、`dhcp`（wan）、`dhcpv6`（wan6）。
  `dhcp.sh` 拉起 `udhcpc`，`dhcpv6.sh` 拉起 `odhcp6c`——这两个 helper 按计划保留。

## 3. IPv6：这是本机的重点，不是"以后支持"

`wan6` 当前状态：5 个 GUA（`/64`，各自有 preferred/valid 生命周期）、1 个 `/64` 委派前缀
（`class wan6`）、**15 条路由**（9 条 `/64` 直连或下一跳、6 条默认路由）、
`data.passthru` 为 104 字节的 DHCPv6 透传选项。

`lan` 侧：`ipv6-address` 为空，地址来自 `ipv6-prefix-assignment` 的两条——一条从 wan6 的
PD `/64` 切出（带 `local-address ::1/64`），一条从 `ula_prefix` 切出 `/60`。
`delegation: true`，`metric 0`。

即：**前缀委派 → 按 `ip6assign` 切分 → 分配给 lan → 生成 local-address → 通知 odhcpd**
这条链必须实现，`interface-ip.c`（1 863 行）大部分是它。

## 4. ubus 接口（必须提供）

| 对象 | 方法 |
|---|---|
| `network` | `restart` `reload` `add_host_route` `get_proto_handlers` `add_dynamic` `netns_updown` |
| `network.device` | `status` `set_alias` `set_state` `stp_init`（`hotplug_event` 因非 DUMMY_MODE 不存在） |
| `network.interface` | `up` `down` `renew` `status` `prepare` `dump` `add_device` `remove_device` `notify_proto` `remove` `set_data` |
| `network.interface.{lan,loopback,wan,wan6}` | 同上，逐接口实例 |
| `network.wireless` | 由 `/lib/netifd/wireless.uc` 定义（ucode 宿主在 netifd 进程内） |

`network.device status` 每个设备回 40+ 个字段（`bridge-attributes`、`neigh4*`/`neigh6*`、
`drop_*`、`rpfilter`、`ip6segmentrouting`、`statistics`、`link-*advertising`、`flow-control`、
`gro`、`hw-tc-offload`、`conduit`（DSA）等）。9 个设备：`br-lan eth0 lan2 lan3 lan4 lo
phy0-ap0 phy1-ap0 wan`。这一整套字段是 LuCI 状态页和 `ubus call` 调用方直接消费的，
不能只回一个子集。

## 5. 已知的实现难点（按代价排序）

1. **`system-linux.c` 4 787 行**：rtnetlink 读写、bridge/DSA、ethtool、sysctl、
   `/proc/sys/net/ipv{4,6}/*` 的逐设备属性。这是最大的一块，且必须实机才能完全验证。
2. **wireless 由 ucode 承载**：`wireless.uc` 586 行 + `wireless-device.uc` 657 行运行在 netifd
   进程内的 ucode 虚拟机里（`ucode.c` 588 行提供绑定）。Rust 侧要么嵌 ucode 解释器，
   要么用 Rust 重新实现这两段编排逻辑并保持 `network.wireless` 的对象形状不变。
   本轮取后者：脚本 `netifd-wireless.sh`（452 行）与 `hostapd.sh`（1 650 行）保留不动。
3. **IPv6 前缀委派与地址生命周期**（§3）。
4. **proto-shell 的进程与超时语义**：`available`/`setup`/`teardown`/`renew`、
   `notify_proto` 的 action 编号、helper 退出与重试。

## 6. 明确不做

`extdev.c`（外部设备 handler，无配置使用）、`bonding.c`、`vrf.c`、`macvlan.c`、`veth.c`、
`vlan.c`/`vlandev.c`、`tunnel.c`、`alias.c`、`iprule.c`、`system-dummy.c`。
遇到这些段落时**明确报错**，不静默忽略（计划 §2 的要求）。

## 7. 已完成的离线验证（r46–r48）

C 侧的 oracle 是**设备自己的 `/sbin/netifd`**：构建机是 aarch64，把精确 rootfs 拷一份，
在 `unshare --mount --net` 里 chroot 跑 `ubusd` + `netifd`，veth 由外层 iproute2 造。
Rust 侧的探针跑在 chroot 外、同一组 namespace 内，所以它看到的 `/proc/sys/net` 和 netlink
就是 C daemon 刚配好的那一份。

| 轮次 | 比什么 | 结果 |
|---|---|---|
| r46 | 同一串操作分别由 iproute2 和 netifd-rs 的 netlink 编码执行，比内核状态 | identical，57 行 `ip -d link` / `ip addr` / `ip route show table all` / `bridge link` |
| r47 | `network.device status` 逐字段 | identical，6 个设备 234 个字段 |
| r48 | `network.interface dump` 逐字段（8 个接口的 static 配置） | identical |
| — | `tools/check_netlink_consts.sh` | 105 个内核常量全部与头文件一致 |

### 这几轮各自抓到了什么

- **常量检查器第一次运行就抓到 12 个抄错的常量**：7 个 `IFLA_BR_*` 和 5 个
  `IFLA_BRPORT_*` 全都差 1。内核对此只回一个 `ERANGE`（`max_age` 被当成 `hello_time`
  读成 2 秒，低于 6 秒下限），不看头文件根本定位不到。
- **r46 之前我猜的网桥默认值是错的**：真值来自 `bridge_config_init`
  （`forward_delay 8`、`hello_time 1`、`max_age 10`、`igmp_snoop false`），
  不是内核默认值，也不是 iproute2 的默认值。
- **r47 抓到三处必须照抄而不是"顺手修正"的行为**：`devtype` 只看 uevent 第一行、
  `flow-control` 的 `rx`/`tx` 标签上游是反的、`negotiated` 是数组不是两个布尔。
  详见 [docs/contracts/netifd.md](../../docs/contracts/netifd.md)。
- **r47 一开始"只差 devtype"是假的**：sysfs 是按挂载时的 netns 呈现设备的，
  外层 `/sys` 早于这个 netns，探针其实在读**构建机自己的**网卡。补一次
  `mount -t sysfs sysfs /sys` 之后，差异才真实。比较脚本当时还会在第一处差异就
  `continue`，把后面的差异全遮住了——两处都已修。
- **r48 抓到两个真缺陷**：`proto_apply_ip_settings` 的网关路由**只带族标志**
  （所以不打印 `proto`，`metric` 也不打印，因为 `DEVROUTE_METRIC` 没置上）；
  以及 ULA 前缀分配整个没实现。
- **r48 的用例不是空跑**：`ip6hint '30'` 按**十六进制**解析（0x30，地址里是 `:30::`），
  带 hint 的接口先就位，随后 `guest`（offset 0）和 `lan`（offset 0x10）按名字顺序排，
  三者与 C 完全一致；`multi` 实际拿到 3 个 v4 + 2 个 v6 地址和两张路由表，
  `nodev` 报 1 个 `NO_DEVICE`，`manual` 保持 down，`nodeleg` 的 `delegation` 为 false。

### 还没有验证的

状态机本身（`up`/`available`/`autostart`/`uptime`/`l3_device` 在 r47/r48 里是从 C 的
输出里取的，因为它们是 netifd 自己的簿记而不是内核状态）、proto-shell、无线编排、
`network` 与 `network.device` 的写方法、以及 ubus 侧的对象注册与事件。
