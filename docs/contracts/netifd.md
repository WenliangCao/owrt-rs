# netifd 行为合同（本机范围）

对象：`netifd cbb83a18`（OpenWrt 25.12.5）。范围见
[R45_NETIFD_SCOPE.md](../../reports/ax3000t-stock-openwrt-25.12.5/R45_NETIFD_SCOPE.md)。
这里只记**读源码不会一眼看到、但调用方能观察到**的行为，不重复源码结构。

## 1. `network.device status`

- 字段顺序是固定的，不是字母序：`external present type` →（present 才有）
  `up carrier auth_status` → `dump_info` 的 ethtool 块 → bridge 才有的
  `bridge-members bridge-attributes` →（active 才有）设置块 → `statistics`。
- **字段缺席也是接口**。`device_merge_settings` 把标志位算成
  `配置的 | 系统读到的`，所以一个字段只要系统读得到就会出现，哪怕没有任何配置提到它；
  反过来，`lo` 这类不支持 `ETHTOOL_GLINKSETTINGS` 的设备**整个 ethtool 块都不出现**，
  不是出现空值。
- `neigh4reachabletime` 和 `neigh6reachabletime` 共用一个标志位，
  `neigh4gcstaletime`/`neigh6gcstaletime` 也是——一个读到就两个都打印。
- `statistics` 表**总是打开**，即使设备没有任何计数器文件。23 个计数器的顺序是
  源码里三列表格的**列优先**顺序，不是字母序。
- `conduit` 不是网桥 master，而是 DSA 的 conduit：
  `IFLA_LINKINFO/IFLA_INFO_KIND == "dsa"` 且 `IFLA_INFO_DATA/IFLA_DSA_MASTER`。
  `lan2` 同时是 `br-lan` 的桥成员和 DSA user port，它报的是 `eth0`。

### `devtype` 只看 uevent 的第一行

`system_get_dev_sysfs` 读进一个定长缓冲区，然后 **`strchr(buf,'\n')` 截断**。
`system_add_devtype` 传的是 100 字节的缓冲区，于是它只看得见 `uevent` 的**第一行**。
大多数设备第一行是 `INTERFACE=`，所以 `DEVTYPE=` 匹配失败，落到
`type`（ARPHRD 号）查表，veth 因此报 `ethernet` 而不是 `veth`。网桥第一行恰好是
`DEVTYPE=bridge`，才走了 uevent 分支。查表是线性的，**最后一项 `none` 是未知号的默认值**。

### `flow-control` 里 `rx`/`tx` 标签是反的

`system_add_ethtool_pause_an` 里两个局部变量叫 `an_rx`/`an_tx`，
但输出时 `if (an_tx) add "rx"; if (an_rx) add "tx"`——标签与变量名相反。
这是上游的笔误，但它就是调用方今天看到的值，**照抄**，不"顺手修正"。
netifd-rs 的 `autoneg_pause` 保留这个交换并在注释里说明。

自协商开启时输出数组名是 `negotiated`；关闭时是 `selected`，来自
`ETHTOOL_GPAUSEPARAM` 的 rx/tx。两者互斥，不会同时出现。

## 2. 有意的行为差异

| 位置 | C | netifd-rs | 影响 |
|---|---|---|---|
| `ethtool_feature_value` | 申请 `DIV_ROUND_UP(idx,32)` 个 block，却读第 `idx/32` 个 | 申请 `idx/32 + 1` 个 | 当 `idx` 是 32 的正倍数时 C 读越界；本机 `hw-tc-offload` 的下标不在这种位置，输出相同 |

## 3. 网桥默认值不是内核默认值

`bridge_config_init` 的默认值：`forward_delay 8`、`hello_time 1`、`max_age 10`、
`igmp_snoop **false**`、`hash_max 512`、`priority 0x7FFF`、`robustness 2`、
`query_interval 12500`、`query_response_interval 1000`、`last_member_interval 100`、
`stp/stp_kernel/bridge_empty/vlan_filtering 全 false`、`ageing_time` 不设置（=0，
且因为标志位没置上，**创建时不发这个属性**）。

发到内核时时间要乘 100（`sec_to_jiffies`，单位是 1/100 秒，与 `CONFIG_HZ` 无关）。

## 4. netlink 报文的三处非显然之处

- `RTM_NEWADDR` 带 `NLM_F_CREATE | NLM_F_REPLACE`；`RTM_DELADDR` 不带。
- IPv6 地址**总是**带 `IFA_CACHEINFO`（未设置生命周期时两个字段都是 `0xffffffff`）；
  IPv4 从不带。`IFA_FLAGS`/`IFA_F_NOPREFIXROUTE` 只在 IPv6 **添加**时出现。
- 路由的 `rtm_scope` 由有没有网关决定：有网关 `RT_SCOPE_UNIVERSE`，没有
  `RT_SCOPE_LINK`；删除时 `RT_SCOPE_NOWHERE` 且 `rtm_type = 0`。
  `table >= 256` 时 `rtm_table` 置 `RT_TABLE_UNSPEC` 并改用 `RTA_TABLE` 属性。
