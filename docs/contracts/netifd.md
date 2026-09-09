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

## 5. network.wireless（P6）

C 的 wireless 是 `netifd` 载入 `/lib/netifd/wireless/*.uc`（ucode）跑的状态机；
netifd-rs 用 Rust 复刻同一套语义，handler 脚本仍是设备自带的 `mac80211.sh`（shell）。

- **对象注册**：`network.wireless` 恒注册（up/down/retry/reconf/status/get_validate/notify），
  监管与 daemon 两种模式都在。此前"不注册"的取舍（R59 头注）已作废——radio 生命周期已实现。
- **配置投影**：`wifi-device`/`wifi-iface` 按 handler 的 schema（`default_attrs` + handler 声明的
  attr/validate）投影成 blobmsg；`disabled` 走 parse_bool（UCI 接受的拼写里只有 0/1/true/false/on/off/
  yes/no 生效，其余当未禁用）；list-where-scalar、int-typed option 的处理与 C 逐字段对齐（r59 三例）。
- **handler 协议**（wireless-device.uc 的 wdev 状态机）：setup→notify(up/set-retry/set-ifname/
  process-add)→teardown，一次一个串行；notify 命令 `up`/`down`/`set_retry`/`process_add`/
  `set_data`（device_data 记录）逐条复刻；注册的进程消失即拆除 radio；retry 预算耗尽置
  `retry_setup_failed`（r60 六变体：up/fail × cmds，flood/token/proc）。
- **notify 面**：`up`/`down`/`retry`/`reconf` 命令，`status`/`get_validate` 读方法。
- **reload**：`network.reload` 重读 wireless；未变的 radio 完全不动（same_config 判等，
  等价 C 的 `is_equal(this.data,data)` 提前返回），变了的重置预算重跑，消失的销毁——
  不重启没人问的 radio。
- **无 phy 的失败路径**：sandbox 里没有 radio，两侧 setup 都失败并落到
  `up=false pending=false retry_setup_failed=true`，这个一致是失败路径的验证，**不是**
  radio 能起来的证据；后者只有设备窗口能证。

差分依据：r59（投影）、r60 六变体（handler 协议）、r63（设备真 network+wireless 双侧活体 daemon，
1881 ubus 行 + 50 kernel 行逐字节相同；换 /bin/false 作候选即判红——桥不建、静态路由缺失）。

## 6. resolv.conf.auto（`interface_write_resolv_conf`）

netifd 是 `/tmp/resolv.conf.d/resolv.conf.auto`（`-r` 可改）的**唯一写者**，dnsmasq 把它当
resolvfile 读上游。没有它，客户端拿得到租约、到得了路由器，但没有名字解析——P6 窗口 #3 在真机上
正是这样失败的（`dig @192.168.1.1` 无应答，路由器本地查询 REFUSED），而 ubus 里 wan 的
`dns-server` 列表是齐的：daemon 知道上游、只是没写文件。

- **内容**：只收 `state == UP` 且 config_ip/proto_ip 至少一边有 dns 或 dns_search 的接口；
  按 dns_metric、metric、接口名三级升序（C 的 avl 比较器）；每个接口一段
  `# Interface <name>`，先 config_ip 的条目，再 proto_ip 的（`no_dns` 时跳过 proto_ip）；
  nameserver 先于 search；link-local v6 服务器写成 `nameserver fe80::…%<l3 设备名>`。
- **写法**：写 `<path>.tmp`，与旧文件比较（C 比 crc32，rs 比字节，判定相同），不同才 rename；
  失败静默（C 用 D() 调试日志）。目录不由 netifd 创建（非 jail 路径），设备启动时已存在。
- **触发点**：IFPEV_UP 之后（两条 up 路径）、IFPEV_DOWN/LINK_LOST 的 mark_interface_down 之后、
  proto update 替换 proto_ip 之后（`interface_ip_flush`）、`interface_change_config` 末尾。
- **未实现**：jail 变体（`/tmp/resolv.conf-<jail>.d/`），本项目没有 jail 接口。

差分依据：r49（wired 口静态 `list dns` + `dns_search`）、r52（udhcpd 下发 option dns + search）
的探针都 cat 这个文件，C 与 rs 逐字节相同且非空；缺写入的旧候选 60dcff02 在 r49 上判红。
