# netifd 行为合同（本机范围）

对象：`netifd cbb83a18`（OpenWrt 25.12.5）。范围见
[R45_NETIFD_SCOPE.md](../../reports/ax3000t-stock-openwrt-25.12.5/R45_NETIFD_SCOPE.md)。
这里只记**读源码不会一眼看到、但调用方能观察到**的行为，不重复源码结构。

R90 补充：无载波、处于 DOWN 的接口仍可能持有 main-device claim；显式 ifdown
必须释放它，使最后一个用户退出时设备的 `up` 与内核 IFF_UP 都变为 false。
其余生命周期补充见 [proto-shell §9](netifd-proto-shell.md#9-r90-生命周期补充与源码纠正)。

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

## 7. R81 冷审计之后：进程生命周期与配置变更语义（R83）

R81 的 F03–F14 按镜像内 `/sbin/netifd`、协议脚本和 `wireless-device.uc` 的实际行为修复。
清单记载的上游修订为 `cbb83a18`；构建机现有 `stage9/netifd` 是较新的 checkout，不能把该目录
称作这个修订。核对时分别读取固定修订与镜像文件；`proto-shell` / `proto-ext` 的组织差异不代替
运行证据。差分门包括 r83_lifecycle、r83_config、r83_wireless_deadline、r61 和加强后的 r62。

- **退出信号**（F03）：SIGINT/SIGTERM/SIGUSR1/SIGUSR2 → 接口原样留在内核，`netifd_kill_processes`
  用 **SIGKILL** 杀掉自己起的进程（proto 脚本、helper、hotplug 脚本、无线 handler），退出 0。
  无线 handler 虽由 C 的 ucode 部分持有，镜像进程退出时仍会停止它；r83 的 shutdown 用例
  直接核对两侧 handler 进程，纠正了此前“退出时不杀无线 handler”的推断。
- **proto-ext 超时**（F09）：teardown 脚本 5 s、被中止的 setup 1 s（`teardown_timeout`），到点 SIGKILL
  脚本与 helper，状态机按终止完成收尾。`Slot::terminate` 发 SIGKILL 后立即返回；旧 Child 放入
  回收列表，用 `try_wait` 回收，事件循环不做阻塞等待。无线 setup/teardown 的 deadline 为 30 s，
  超时后取消任务并推进重试状态；setup 中的配置变更保留到本次任务结束后重新 setup。
- **config_state**（F04/F11）：删接口 / 需要 reload 的变更先 `set_config_state`；接口已 DOWN 则立即执行，
  否则 `__interface_set_down` 后在 IFPEV_DOWN 路径（`handle_config_change`）执行。删除时
  `proto_ext_free` 对两个任务 SIGKILL；reload 保留运行期 `autostart`（只有 `auto` 本身变了才重置）。
- **变更分级**（F05，`interface_change_config`）：reload 仅当 device / proto / handler 声明的参数
  （shell handler 的 `config` 列表；static 为 ipaddr/ip6addr/netmask/broadcast/gateway/ip6gw/ip6prefix/
  ip6deprecated）/ zone / 接口段里的 device 选项 / `auto` 从开到关 变了；metric、ip4table、ip6table、
  defaultroute 变了只重装地址与路由（`reload_ip`）；dns/dns_search/peerdns 只重写 resolv.conf；
  delegate/ip6assign/ip6hint/ip6class 只重算前缀分配；静态路由段变化只增删对应路由。
- **dns / peerdns / defaultroute**（F06）：接口段的 `list dns`/`dns_search` 进 `config_ip`（所有协议）；
  `peerdns 0` → `proto_ip.no_dns`（协议给的 DNS 进 inactive，不写 resolv.conf）；`defaultroute 0` →
  `proto_ip.no_defaultroute`（协议给的默认路由留在列表、进 inactive、不进内核）。
- **时钟与生命周期**（F07/F08）：`clock.rs` = CLOCK_MONOTONIC（`system_get_rtime`）；地址、前缀、
  分配一律存**截止时刻**，status 打印剩余（preferred 钳 0，valid 与 C 一样按 u32 回绕）。
  `ipv6-prefix` 由当前视图（`dump_interface_status`）从全局前缀表填入本接口的前缀及其 `assigned`；
  `delegate 0` 的接口前缀不参与下游分配，仍保留父前缀及 null route；恢复 delegate 后重新分配。
  普通配置 reload 保留协议持有的 PD，更新其生命周期或成员时在 `updated` 数组中加入 `prefixes`。
  r62 使用真正进入 UP 的协议夹具，比对地址/前缀倒计时、续期、替换、delegate 开关及撤回；
  内核生命周期按数值比较，容差 3 s，不再分桶或只比较零与非零。
- **设备选项**（F12/F13）：`ipv6`/`promisc`/`multicast`/`mtu6` 按 `system_if_apply_settings` 的顺序应用，
  应用点是 `device_claim` 里 IFF_UP **之前**（`system_if_up`）——内核在 NETDEV_UP 会把 IPv6 mtu 重置为
  链路 mtu，所以 C 的 `mtu6` 对刚起来的设备实际不生效，这里同样不生效。`network.device status` 的
  `up` 是 claim 状态（`dev->active`），不是 IFF_UP。
- **add_device / remove_device**（F13）：主设备是网桥 → `bridge_hotplug_add/del`。先查设备，
  `link-ext` 缺省 true，标记 external；即使后面的 hotplug 返回 NOT_SUPPORTED，这个标志也保留。
  新建且非 external 的设备才清状态。非成员 NOT_FOUND；配置里的口 `remove` 回 0 不动；主设备就是它 → 0；
  非网桥主设备 add → NOT_SUPPORTED，remove → INVALID_ARGUMENT；接口无 device 时 C 会把该设备
  hotplug 成主设备——本构建不做，回 NOT_SUPPORTED（**有意偏离**）。
- **disabled**（F13）：`option disabled '1'|'true'`（严格这两个拼写）→ 整段跳过，无接口对象、无 ubus 对象。
- **不再拒绝 reload**（F14）：不认识的段、不支持的 device type、坏 macaddr 记 warning 并跳过
  该项；无效静态地址使所属接口 SETUP 失败，均不阻断其他接口的 reload。
  `config route`/`route6` 现在实现（target/netmask/gateway/metric/mtu/table/type/
  onlink/source/proto/disabled；无 `interface` → loopback + NODEV），进 `config_ip`，接口 UP 时装入内核、
  DOWN 时撤下；`valid` 不承载（**有意偏离**，本机无此用法）；`rule`/`rule6` 仍跳过（warning）。
  没有 `proto` 的接口段仍跳过（C 会用 no_proto 建对象——**有意偏离**，本机无此用法）。

## 8. 日志通道与方法表（R91）

精确参考是 `cbb83a1857407a28a63dc09412a1f209195914ef` 的 `main.c`、
`netifd.h` 与 `ubus.c`，以及该镜像的 `/etc/init.d/network`。后者不设置
`procd_set_param stderr`；只写 stderr 的候选在正常启动后不会把网络日志送到 logd。

- 默认使用 libc `syslog`，ident 为 `netifd`，facility 为 `LOG_DAEMON`，
  默认输出到 `L_NOTICE=2`。接口 setup/up/down、连接变化及协议子进程的 stdout/stderr
  都是 notice；原始 syslog PRI 为 29。
- `-S` 把这些消息改送 stderr，正文不重复添加 ident。与 C 的 `vfprintf` 一样，
  stderr 写入失败不终止 daemon，包括被写满的非阻塞管道。
- `-l <level>` / `-l<level>` 使用 C `atoi` 语义：数字前缀有效、非数字为 0、
  大于 4 钳到 4，负数不钳为 0。只输出级别不高于该值的消息；过滤日志仍须排空子进程管道。
- 协议脚本和 helper 的消息保留实际子进程 PID，形如 `wan (123): ...`。
  消息作为 `%s` 的参数传给 libc，不把子进程输出当格式字符串。
- logd 的 socket 被替换后继续投递，重连由 libc 处理；不新增日志线程或用户态发送队列。

`tools/r91_netifd_logging.py` 在隔离 namespace 中收取真实 `/dev/log` 数据报，并验证
通道、级别、子进程 PID、日志接收端重建及 stderr 写满。既有 Rust 诊断文本、
额外 info/debug 消息和子进程输出分帧不等于完整 C 日志逐字节合同；本轮不实现
`-d` 或 udebug，子进程输出的既有有损 UTF-8/末尾处理差异仍保留。

R88 netifd F6 撤销：镜像匹配的 `iface_object_methods` 与原版运行时都只有
`up/down/renew/status/prepare/dump/add_device/remove_device/notify_proto/remove/set_data`，
没有接口级 `restart`。现有候选的方法表符合该版本；不要从较新上游补入这个方法。
全局 `network restart` 是另一项合同，R88 F9 仍待处理。
