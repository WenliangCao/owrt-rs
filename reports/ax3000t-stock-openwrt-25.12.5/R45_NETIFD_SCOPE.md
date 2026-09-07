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
| r49 | **两个 daemon 各自跑起来**：同 rootfs、同配置、同一个 libubus 客户端逐项询问，再用 iproute2 比内核状态 | ubus 面 identical，内核状态 identical |
| r50 | 对两个 daemon 各跑 600 / 1800 轮 `ifdown`+`ifup`，比资源占用与最终状态 | 无失败调用、无 fd 泄漏、最终内核状态与 dump 均 identical |
| r51 | 三条事件通道：`ubus listen` 广播、`ubus subscribe` 通知、hotplug.d 调用 | 三条全部 identical（10 / 8 / 6 条） |
| — | `tools/check_netlink_consts.sh` | 106 个内核常量全部与头文件一致 |

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

### r49 抓到的八个缺陷

全部先在 C 源码里定位成因，再改，不靠猜：

1. **IPv4 地址要自己算广播地址**，内核不会推。`/31`、`/32` 用 `255.255.255.255`，
   更短的用"地址或上主机位"（`interface-ip.c:667`）。少了它 `ip addr` 里没有 `brd`。
2. **前缀路由要接管**：先按内核的样子（`proto kernel`、**metric 0**、main 表）删掉自动
   路由，再加上带接口 metric/表的自己的那条。删除必须发生在
   `interface_set_route_info` 之前——带着接口 metric 去删，什么都匹配不到。
   而且只在 `iface->metric` 或策略表非零时才接管，否则 netifd 根本不动内核那条。
3. **网桥成员要关掉 IPv6**（`bridge_enable_member`），所以成员自己没有链路本地地址。
4. **配置提到但接口没起来的设备要被拉下来**（`set_device_state(dev,false)` →
   `system_if_down`）。
5. **每个委派前缀要加一条 `unreachable` 路由**，metric `INT32_MAX`，避免路由回环。
6. **每个前缀分配要加一条在链路路由**，掩码不短于 `/64`。
7. **`device` 字段按配置报，即使设备不存在**；`available` 跟随设备是否存在，
   与接口有没有起来无关。
8. **设备表只装配置提到的设备**。netifd **不枚举内核链路**：我一开始把
   `/sys/class/net` 全枚举进去，于是一个没人提到的 veth 对端出现在
   `network.device status` 里——C 没有它。

### r50：1800 轮开关之后

| | C netifd | netifd-rs |
|---|---|---|
| 失败调用 | 0 / 1800 轮 | 0 / 1800 轮 |
| fd | 19 → 19 | 8 → 8 |
| 线程 | 1 | 1 |
| RSS（事件通道之前，1800 轮） | 2144 → 2160 KiB | 2064 → 2200 KiB |
| RSS（加上事件与 hotplug 之后，600 轮） | 2144 → 2160 KiB | 2200 → 2324 KiB |
| 最终 `network.interface dump` | — | identical |
| 最终内核状态 | — | identical |

加上事件通道之后基线从 2064 抬到 2200 KiB——每个事件要 fork 一次
`hotplug-call`，C 也一样 fork，但候选的基线因此比 C 高了约 160 KiB。
增长形状没变（600 轮 +124 KiB），仍然是平台化的 arena 增长。

RSS 那 +136 KiB **不是泄漏**：600 轮涨 124 KiB，1800 轮涨 136 KiB——三倍轮次只多涨
12 KiB，是分配器 arena 的一次性增长，已经平台化。起点比 C 低 80 KiB，1800 轮之后
比 C 高 40 KiB，同一量级。

fd 计数一度显示 8 → 9，逐个 `readlink` 之后定位为
`/proc/sys/net/ipv4/neigh/br-lan/locktime`——采样正好撞上一次 `rescan_devices` 里的
sysctl 读。**"数量变了"不等于"泄漏了"**，把描述符逐个列出来才能定性。采样点加了
settle 之后稳定为 8。

r50 还抓到一个真缺陷：**ifdown 要释放 L3 设备**（`interface_flush_state` →
`device_release` → `system_if_down`）。不释放的话设备一直 UP 且没有配置，
表现为 C 没有而候选有的一个链路本地地址。

### r51：事件通道，以及它抓到的四件事

事件在 `network.interface dump` 里**看不见**，只有单独抓才能比。三条通道各自都要：
广播是脚本监听的，通知是订阅者收的，hotplug.d 是真正去重配防火墙、DNS 和 DHCP 的。

1. **ifup 顺序是"配置顺序的倒序"**，不是名字序也不是配置序。
   `config_init_interfaces` 用 `list_add`（头插）把解析出的接口挂到 `config_ifaces`，
   再从头 `list_first_entry` 弹出，于是 `interface_add`——连同 ifup 和它的事件——
   按倒序发生。两次独立运行的 C 顺序完全一致，所以这是合同而不是抖动。
2. **一次 ifdown 会发两条广播**：`__interface_set_down` 进入 `IFS_TEARDOWN` 时发一条，
   proto handler 回 `IFPEV_DOWN` 后 `mark_interface_down` 再发一条。
   两条 ubus 通道都各发两次，**只有 hotplug.d 被去重**（队列折叠掉与正在处理的
   同一个事件）。
3. **`ifdown` 事件一开始整个丢了**：我加发射点的那次编辑锚点已经被前面的插入挪走，
   补丁没落地，编译和测试都不报错。是差分把它抓出来的。
4. **hotplug recorder 一开始两边都没抓到**：C 的 netifd 在 chroot 内 fork，候选在
   chroot 外，一个绝对路径不可能同时对；改成从 `$0` 推导日志路径才两边都写得进。
   更早还有一次**假通过**：`ubus subscribe` 在对象注册之前启动，两边都返回
   `Not found`，于是"0 条通知，两边一致"——比较脚本现在把"参考侧什么都没抓到"
   直接判为失败。

`unsupported`（`proto dhcp`）那条在比较里被单独过滤并注明：C 里它会进 `IFS_SETUP`
等 udhcpc，所以之后的 `down` 是一次真的 `IFEV_DOWN`；本 build 一开始就拒绝这个 proto，
发的是 `ifup-failed`。这是 proto-shell 缺口的**下游后果**，不是另一个缺陷。

### 两个已知缺口（在比较脚本里单独报告，不混进"差异"）

- `network.wireless`：由 netifd 进程内的 ucode 虚拟机里的 `wireless.uc` 注册，
  本 build 不托管 ucode，所以没有这个对象。
- `get_proto_handlers`：本 build 只报它真的能跑的 handler（只有 `static`）。
  报一个跑不了的 `dhcp` 会让调用方以为能用。

### 还没有验证的

proto-shell（`dhcp`/`dhcpv6`/`ppp`/`pppoe`，本机 WAN 真正需要）、无线编排、
`network.device` 的写方法（`set_alias`/`set_state`/`stp_init`）、
`network.interface` 除 `up`/`down` 以外的写方法、`network` 的
`add_host_route`/`add_dynamic`/`netns_updown`、载波驱动的 setup/teardown、
reload 的变更检测（现在是全拆全建）、ubus 事件（`interface.<name>` 的 ifup/ifdown
通知）、以及计划 §2.3 要求的故障用例（WAN 失联、helper 退出、netlink 失败、
重复/乱序事件、接口删除重建、ubus 重连）。

r47/r48 里 `up`/`available`/`autostart`/`uptime`/`l3_device` 是从 C 的输出里取的
（它们是 netifd 自己的簿记而不是内核状态）；**r49 不是**——r49 里这些字段由
netifd-rs 自己产生，两边一致。

### r52：真实 DHCP 交换 + 一次 ifdown/ifup 循环

`tools/r52_dhcp_diff.sh`：veth 对端跑 `busybox udhcpd`（单地址池，两边必然拿到
`10.0.0.100`），两侧各跑一次完整的 `proto dhcp`——netifd 起 `dhcp.sh`，脚本用
`notify_proto` action 1 让 netifd 拉 `udhcpc`，`udhcpc` 跟真服务器要地址，
`dhcp.script` 再用 action 0 把结果报回来。没有任何一环是桩。

比较七项，现在**全部一致**：拿到 lease 的耗时、内核状态（地址/路由/link）、
未被配置的对端设备 `veth0` 的地址被清掉的时机、`ifdown` 之后的现场
（helper 是否还在、设备是否还 up、`wan status`）、再 `ifup` 之后的
`wan status`、`network.interface dump`、hotplug.d 序列。

这一轮抓到的缺陷（每一条都不是单元测试能发现的）：

1. `link-up` 是连字符。写成 `link_up` 的表现不是报错而是接口永远不 up。
2. action 0 的载荷是嵌套表，不是 proto-static 的扁平 UCI 形状。
3. helper 输出只在退出时才读，而 `udhcpc -f -t 0` 不退出——所以前三次跑
   看起来像"什么都没发生"。
4. `link-up:false` 是 `IFPEV_LINK_LOST`，接口不 up 时是空操作；当成 ifdown
   会在启动时就把接口拆掉。
5. 正在 setup 的接口仍在用它的设备，"把没用的设备拉下去"那一趟把 udhcpc 的链路
   抽掉了。
6. `device_init` 会对每个新建的 device 对象清一次内核状态——包括只作为父设备
   被创建的那些。
7. `ifdown` 没有跑 teardown 命令（门槛条件把 `S_IDLE` 排除了，而那正是它该
   出发的状态），helper 因此活过了 ifdown。
8. 设备状态是 claim 计数而不是布尔量；接口持 main_dev 和 l3_dev 两个 claim，
   只在 autostart 被清掉时才释放 main_dev。
9. `ifup`/`ifdown` 要改 `autostart`；`interface_flush_state` 要清 `data`。
10. hotplug.d 用真的排队规则，不能用"这次要不要调"的布尔量——布尔量在 static
    上碰巧对，在 shell 协议上少一次调用。
11. 子进程退出只靠轮询发现，最多晚一个 poll 超时；改成 SIGCHLD self-pipe。

细节记在 `docs/contracts/netifd-proto-shell.md` §4/§4b/§4c/§7。

### 仍然没有验证的（更新）

`network.wireless`（需要 netifd 进程内的 ucode 虚拟机）、`network.device` 的写方法
（`set_alias`/`set_state`/`stp_init`）、`network` 的
`add_host_route`/`add_dynamic`/`netns_updown`/`add_device`/`remove_device`、
载波驱动的 setup/teardown、reload 的变更检测（现在是全拆全建）、checkup 定时器、
主机依赖（action 6 目前返回 `NOT_SUPPORTED`）、`address-external` 与协议自建隧道
（都返回 `NOT_SUPPORTED`）、协议上报的邻居，以及计划 §2.3 的故障用例。

### r53：计划 §2.3 的故障用例

`tools/r53_fault_diff.sh`：一条真的 `proto dhcp` 接口（对端有真的 udhcpd），
四个故障各写一份现场，差异能落到具体某一个用例上：

| 用例 | 做什么 | 关键发现 |
|---|---|---|
| A | `kill -9` 掉 udhcpc | C **会自愈**：helper 死是 `IFPEV_LINK_LOST`，走完 teardown 后 `interface_handle_config_change` 最后一行 `if (autostart) interface_set_up(iface)` 把接口重新拉起来 |
| B | 对端 `ip link set down` | 起接口是**载波驱动**的：`interface_set_up` 只 claim 主设备，之后由 `interface_check_state` 在有载波时才真的 setup、没载波就拆掉。对端没起来的接口停在 `IFS_DOWN` 而不是 `IFS_SETUP` |
| C | 删掉设备再建回来 | `_device_set_present(false)` 会把每个 user 的 claim 都释放掉；接口变 unavailable 并记一条 `NO_DEVICE`；这是**强制** teardown：立刻 flush L3 设备和 `data`，但接口留在 `IFS_TEARDOWN` |
| D | 连续两次 ifup、连续两次 ifdown | `autostart` 由 `interface_set_up`/`_set_down` 自己设，所以每个调用点都会设，不只是 ubus 那个 |

顺手在"已经一致"的路径上抓到两条：

- `device_add_user` 会把设备**当前**状态回放给新 user。少了这一步，一个设备已经
  被别人 claim 过的接口（网桥成员的父设备就是这种）永远收不到 `DEV_EVENT_UP`，
  `enabled` 一直是 false，`interface_check_state` 就不肯把它拉起来。
- C 里一个设备事件只送给**这个设备的** user。claim 一个设备之后去轮询所有接口的
  载波，会让后面的接口在前面那个还在起的过程中就先起来——启动时的 ifup 顺序因此
  变了（C 是 vlist 顺序，也就是配置的倒序）。

`iface->enabled` 的含义也纠正了：它是"主设备被 claim 且 up"（`DEV_EVENT_UP`/`DOWN`），
跟 `disabled` 选项无关。

r53 的 hotplug 比较会把连续重复行合并：一次重复的 `IFEV_DOWN` 变成一次还是两次
hotplug 调用，取决于第二次是否落在第一次还在跑的时候，而**C 自己三次里有一次
落到了另一边**。顺序不同照样失败，只是同一行的次数不同不算。

### r54：reload 到底动了什么

`tools/r54_reload_diff.sh`：四条 static 接口，然后**一次只改一个地方**再
`ubus call network reload`，比的是"哪几条接口被抖了一下"，不是完了之后的状态——
全拆全建和只动改过的那条，最终状态是一样的，只有 hotplug/事件序列能区分。

现在四项全一致：

| 动作 | C 的反应 |
|---|---|
| 什么都不改就 reload | **一条都不动** |
| 改一条接口的地址 | 只有那一条 ifdown + ifup |
| 加一个 section | 只有新的那条 ifup |
| 启动 | 按**字母序**（`interface_start_pending` 走的是按名字排的 avl 树） |

抓到的：

- `network reload` 和 `network restart` 不是一回事。`netifd_reload` 就是
  `config_init_all()`，不拆任何东西；只有 `netifd_restart` 会
  `interface_set_down(NULL)`，而这个 NULL 形式**不清 autostart**，所以之后都会自己
  回来。本 build 之前两个方法共用一条"先全拆再重建"的路径。
- 启动顺序是**字母序**，不是配置倒序。之前记成倒序是因为那些 harness 的接口不同质
  （网桥、lo、veth），实际观察到的是"谁先起完谁先发事件"，跟遍历顺序无关；r54 用四条
  同质接口才把遍历顺序单独测出来。
- `interface_do_reload` 是 teardown 而不是 ifdown：autostart 活过它，这正是接口
  能自己回来的原因。
- 判断"要不要 reload"看的是设备、协议和**协议声明的那些参数**
  （`uci_blob_check_equal`），没人读的选项改了不算——所以 `raw` 不参与比较。

### 一个记录在案的差异：启动时 ifup 的先后

r51 里 C 的启动顺序是 `wired, lan, loopback`，本 build 是 `lan, loopback, wired`
（字母序）。原因不是遍历顺序，而是**起完的时刻**：C 的接口要等设备的载波事件到达才算
起来，所以先起完的先发事件；本 build 在 claim 之后直接读一次载波就把它起完，是同步的。

试过改成纯事件驱动（不在 claim 之后读，等 netlink 事件），**更差**：后来的某个事件把
设备读成瞬时无载波，接口刚起来又被拆掉。所以保留同步完成，代价就是启动顺序。

r51 因此把**启动块**（第一个 ifdown 之前的部分）按集合比，其余严格按顺序比，并且把
两边的顺序都打印出来——这是一个写在报告里的已知差异，不是一个悄悄的过滤器。事件集合、
之后的全部顺序、以及 r54 的遍历顺序都是一致的。

### r55：那些还没实现的写方法，先测再说

`tools/r55_writemethods_diff.sh`：把每个"声明了但没实现"的方法在两侧用同样的参数各
调一次，比返回状态、`network.interface dump` 和 `network.device status`。目的是**先
搞清楚哪些真的会做事**，再决定实现哪些——而不是照着方法名一个个写。

先测出来的事实：

| 方法 | C 的行为 |
|---|---|
| `set_data` | 存进 `data`，置 `updated:["data"]`；**先清 `updated` 再合并**，所以同样的值再发一次，status 里连 `updated` 这个键都没有；值真的变了才算变 |
| `prepare` | 回 `{}`（主设备没有 hotplug ops 时；有的话回 `{"bridge":...}`） |
| `add_device` | 两侧本来就一致 |
| `remove_device`（设备不存在） | `INVALID_ARGUMENT` |
| `remove` | 回 OK，但配置里的接口**不会消失**（只挂一个 100ms 的定时器） |
| `set_alias` | 回 OK，并且**给那个名字建了 device 对象**——之后 `network.device status veth6` 就能查了 |
| `set_state {"defer":true}` | 设备变成 `present:false`；`defer:false` 再变回来 |
| `stp_init` | 回 OK |
| `add_dynamic {"name":"dyn0"}` | **真的建出一条 `dyn0` 接口**，出现在 dump 里 |
| `netns_updown` | 这组参数下 `INVALID_ARGUMENT` |
| `network.device status <未知设备>` | `INVALID_ARGUMENT`，不是 `NOT_FOUND`；而且 `device_find` **不看 present**，没有内核设备的 device 对象照样 dump |

这一轮实现并验证一致的：`set_data`（三个用例）、`prepare`、`network.device status`
的错误码。

剩下的都归到同一件事上——**给任意名字建 device 对象的生命周期**
（`set_alias`/`set_state`/`add_dynamic`/`remove`）。本 build 的 device 注册表只装配置
里出现过的设备，要做这些得先把它改成 C 那样的对象树。没做，也没有用一个假的 OK 糊过去：
这些方法现在仍然返回 `NOT_SUPPORTED`，调用方能看出来它没被支持。

### r56：真的 DHCPv6

`tools/r56_dhcpv6_diff.sh`。`apply_proto_link` 的 IPv6 那一半——`ip6addr` 的表数组
（带生命期和 class）、v6 网关、v6 子网路由——都是照着 C 的源码写的，**从来没跑过**：
r52 只走了 IPv4。

服务端用 rootfs 里的 **odhcpd**（镜像里的 dnsmasq 编译时关掉了 DHCPv6）。odhcpd 正是
设备上真正的 DHCPv6 服务端，而且它靠调 `network.interface dump` 找接口——所以这一轮
顺带测了一个**真实的下游消费者**在用被测守护进程的接口。服务端那一侧
（`srv` 跑在对端 veth 上）自己也是一条 netifd 接口，这样就不用绕开
`system_if_clear_state` 把别人放的地址抹掉的问题（见 r52）——这个地址本来就是 netifd 的。

抓到一条：**协议上报的 v6 地址要带上生命期和 `IFA_F_NOPREFIXROUTE`**。
`parse_addr_item` 已经把 `preferred`/`valid`/`offlink` 解出来了，但
`apply_proto_link` 没往 `sys::Address` 上放。少了这个标志，内核会自己给 /128 加一条
主机路由，在 `ip -6 route` 里看得见——r56 就是这么发现的。

现在内核状态、`wan6 status`、`network.interface dump`、hotplug 四项全一致。
odhcpd 的 IA_NA 地址是按客户端 DUID 哈希出来的，每次跑都不一样，所以比较前把**各自那
一侧**的租约地址换成同一个占位符（同一个 token 全局替换，真差异照样露出来）。

### r57：ubusd 消失又回来

计划 §2.3 要求的最后一条比较好测的故障。C 的答案很清楚：
`ubus_ctx->connection_lost = netifd_ubus_connection_lost`，每 2 秒重试一次
`ubus_reconnect`，成功之后 libubus 会把所有对象在新连接上重新注册。

测出来：C **活着**并且重连，所有对象都回来了；本 build 之前是**直接退出**。退出之所以
看起来"能用"，只是因为 procd 会把它拉起来——代价是所有接口状态全丢。

现在也重连了：总线断了不退出，事件循环继续跑 netlink（断线期间不 poll 那个 fd，否则
会空转），每 2 秒重连一次，成功后重新注册三个固定对象加每条接口一个。
重启前后的对象列表、`network.interface dump`、内核状态三项都一致。

`network.wireless` 在比较里被单独排除并打印一行说明——它由 netifd 进程内 ucode 虚拟机
里的 `wireless.uc` 注册，本 build 不托管 ucode。这是记录在案的缺口，不是静默过滤：
它要是哪天出现了，或者别的地方不一样，比较照样会失败。

### PD 没测成：记录一下为什么

试过让 odhcpd 下发 IA_PD（给 `srv` 配 `ip6assign 60` 和一个 ULA），
`ipv6-prefix` 两边都是空——odhcpd 手里没有可以再分的上游前缀，真要测得再加一个第三方
上游。所以 `ip6prefix` 这条路径目前仍然只有 r49 的 ULA 分配那一半是被验证过的。

### `network.wireless`：现在知道它到底是什么，以及还差什么

之前只写着"需要 ucode 虚拟机"。实测之后清楚多了：

- 对象有 7 个方法：`up down retry reconf status notify get_validate`。
- 没有 `/etc/config/wireless` 时，`status` 和 `get_validate` 都返回 `{}`。
- 有一个配了但没有硬件的 radio 时，`status` 会把它报出来
  （`up:false, retry_setup_failed:true` 加上 config 投影和 interfaces 列表），
  `get_validate` 返回整张 hostapd/mac80211 校验表。
- 这张表**不是写死的**：它来自 `/lib/netifd/wireless/mac80211.sh` 的 `dump`
  ——跟协议 handler 完全一样的模式（`cd` 到脚本目录，跑 `./x.sh "" dump`，
  逐行当 JSON 解析），条目是 `[名字, 类型码]`，类型码就是 utils.uc 里的
  `TYPE_ARRAY=1 / TYPE_STRING=3 / TYPE_INT=5 / TYPE_BOOL=7`，再和
  `default_config_attr` 的四类（device / iface→interface / station / vlan）合并。

所以它是**可以做的**，不需要嵌 ucode：ucode 那 1400 行里，真正决定这个对象长相的
部分就是上面这套。已经落地的是 `components/netifd/src/wireless.rs`：handler 发现、
类型码到名字的映射、四类默认属性的合并（handler 声明的覆盖默认的），带单元测试。

r59 把两个读方法都比对完了：三种配置（没有 wireless 配置 / 一个 radio 一个 iface /
两个 radio 加上各种边角），`status` 和 `get_validate` 两边**逐字节相同**。

第一次跑出来 `get_validate` 就全对了——schema 合并那套是对的——但 `status` 有五处不一样，
每一处都是 wireless.uc 里一行代码：

- **`radios: []` 少了**。`config.radios = radios` 是在 `parse_attribute_list` **之后**
  无条件赋的，所以它永远在最后一个，哪怕是空的。
- **`disabled: null`**。`option disabled 'on'` 走 `parse_bool` 返回 undefined，
  ucode 照样 `ret[name] = undefined`，键还在，值是 null。
  顺带一提这是 netifd 里少见的：UCI 平时认的 `on`/`yes`/`enabled` 这里都不算真。
- **radio1 的 iface 被丢掉了**。`if (!dev || dev.config.disabled) continue`
  ——看的是 radio **投影后**的 disabled。所以 `disabled 'true'` 的 radio 下面的 iface 没了，
  `disabled 'on'` 的还在。
- **`unknown_type` 这个 radio 整个不存在**。没有 `type`、或者没有 handler 认领这个 type，
  就根本不建 radio。
- 另外 `wifi-iface` 自己 `disabled` 为真时直接跳过，但 `wifi-device` 不跳过（第 131 行的
  `&& type != "wifi-device"`）。

这五条现在都有单元测试兜着，不依赖 oracle。

还没接上的是**对象注册**。
`status` 的字段**顺序**要按 handler dump 的顺序（不是字母序）——
`config` 里先是 `default_config_attr` 里出现且 UCI 里设了的，再是 handler 声明的，
都按各自的声明顺序。把 radio 编排（`up`/`down` 真的去拉 hostapd）做出来需要真硬件，
沙箱里验证不了。

**故意不注册这个对象**，而且理由比之前想的更硬：读方法现在是对的，但
`status` 里 `up`/`pending`/`autostart`/`retry_setup_failed` 这四个状态位来自
radio 到底起没起来。沙箱里没有硬件，C 那边 setup 也失败，所以两边都报
`up:false, retry_setup_failed:true`，**一致**——但这个一致只说明"都没起来"，
对一台真有无线电的机器什么都不能证明。真设备上 C 会报 `up:true`，
而现在这套只会报 `up:false`。注册一个把已经工作的无线电报成没起来的对象，
比没有这个对象更糟。

所以 r59 是通过 `netifd-rs --dump-wireless`（一个诊断开关，不是守护进程的一部分）
比对的，而不是通过注册对象。等编排那半边做出来，schema 和投影这半边已经是验证过的了。
r49 和 r57 继续把这个对象单独列为已知缺口并打印说明。

### 阻塞请求期间排队的消息，必须主动去取

r55 偶发地在 `remove` 之后 `ubus call network.interface dump` 超时——同一个二进制，
有时过有时不过。不是竞态难查，是循环少了一步。

`add_object` / `remove_object` / `send_event` 都是**同步**请求：发出去，然后一直读
socket 直到读到自己那条回复。期间读到的别人的消息不会丢，会进 `pending` 队列。
问题在主循环：它只在 `poll()` 报告 socket 可读时才调 `read_incoming()`。
排在 `pending` 里的那条 invoke 不会让 socket 再次可读——**没有新数据了**——
于是它就一直躺在那儿，等到下一次别的事件把循环叫醒。调用方那边就是超时。

`send_event` 每次接口事件都会调一次，所以这个窗口比 `remove_object` 频繁得多。

libubus 是在等待里就地派发的（`ubus_complete_request` 会处理收到的 invoke）。
这里改成推迟到循环里派发，效果一样，前提是循环真的去取——所以 `drain_bus()`
在 poll 之前和每次读之后各跑一遍，把 `pending` 抽干。

### `updated` 到底什么时候置位、什么时候清零

之前这个字段一直是猜的。实测下来规则很窄，而且只有两处清零：

- **`interface_update_start()` 开头无条件清零整个 mask**。全树只有一个调用者：
  `notify_proto` 的 action-0 处理函数。所以静态接口永远走不到这里——它的
  `["addresses"]` 会一直挂着，只要接口不下线。
- **`interface_parse_data()` 开头也无条件清零**，调用者只有 `set_data`。
  所以对一个已经是 `["addresses"]` 的静态接口做 `set_data`，结果是
  `["data"]` 而不是 `["addresses","data"]`。

置位只发生在 vlist 回调里，而且带 `if (!node_new || !node_old)` 的门槛——
**只有真的新增或删除才置位**，原样重放同一条不置位。所以：

- 网关变了、目的地没变 → **不置 ROUTE**。route 的 vlist key 不含 nexthop，
  这是同一条被就地替换（`add_route` 带 `NLM_F_REPLACE`，内核一步换掉）。
  这一条对实现有直接后果：flush 的比较**也不能带 nexthop**，否则会在
  add 之后把刚替换上去的那条删掉。
- 事件也跟着这个 mask：`if (state == IFS_UP && iface->updated)` 才发
  IFEV_UPDATE，mask 为零就什么都不发。
- 字段本身只在接口 up 时打印。

这解释了 r56 为什么会飘：真实的 DHCPv6 交换里 odhcp6c 会连着发好几条
（bound → informed / ra-updated），每条都清一次零、又几乎什么都不重置，
所以 `updated` 大概只活两秒。同一个 harness，C 自己一次报三个 flag、
下一次一个都没有。r56 因此**显式排除** `updated` 和它驱动的 `ifupdate`
并打印说明；语义改在 r55 里断言，那里的 notify 是按已知时刻手动发的。

（r55 那六个用例目前是两边一致，但 C 在整段序列里一直报 `["addresses"]`，
所以它们证明的是"一致"，还没证明"清零那一跳"。这一点没有夸大。）
