# odhcpd-rs：本机控制接口契约

2026-10-18。只读契约，尚非实现或验收结果。范围是 RA/SLAAC、DHCPv6
IA_NA/IA_PD、租约/触发器、UCI、ubus 与 netifd 生命周期。NDP 代理、中继、
odhcpd DHCPv4 服务必须拒绝启动。保留现有 init、odhcpd-update、dnsmasq 和
netifd 协议脚本；不借此扩展产品范围。

依据是 OpenWrt 25.12.5 的 `odhcpd-ipv6only`，精确源码
`5d7be43f8b9dec0eb47e245cfab81108bb131273`，Oracle 的
`/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components/odhcpd`。
匹配 rootfs 在同证据根的 `extracted/rootfs-files`。运行、`/rom` 和保留的 C ELF
SHA256 均为 `53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
本轮实际配置和接口观察由主线程保存在 ignored
`private/odhcpd-20261018/intake/`；本文不保存地址、DUID、MAC 或主机名。

## 本机配置与拒绝边界

| 配置 | 本机输入 / 必须保留的含义 |
|---|---|
| `odhcpd.maindhcp` | `0`，DHCPv4 由 dnsmasq 提供 |
| `leasefile` / `leasetrigger` | `/tmp/odhcpd.leases` / `/usr/sbin/odhcpd-update` |
| `hostsdir` / `piodir` / `loglevel` | `/tmp/hosts` / `/tmp/odhcpd-piodir` / `4` |
| LAN | `interface=lan`, `ra=server`, `dhcpv6=server`, `ra_slaac=1` |
| LAN RA flags | `managed-config`, `other-config` |
| 共享 LAN DHCPv4 参数 | `dhcpv4=server`, `start=100`, `limit=150`, `leasetime=12h` |
| WAN | `interface=wan`, `ignore=1`；无 RA/DHCPv6/NDP 模式 |
| 静态 host | 0 个；`add_lease` 仍属于公开 ubus 契约 |
| netifd | LAN 有 GUA `/64` 与 ULA `/60` 分配；WAN6 PD `/64`；LAN `data` 为空 |
| 当前租约 / PIO | 3 个 IA_NA、均未接受 Reconfigure；2 个 PIO，不能据此取消 IA_PD 支持 |

`maindhcp=0` 时，C 将每个 `dhcpv4` 模式强制设为 disabled
（`config.c:1277`）。因此现有 `dhcpv4=server`、`start`、`limit` 和 dnsmasq
section **不构成 odhcpd DHCPv4 启用请求**，不能误拒绝本机配置；`leasetime`
同时影响 DHCPv6，不能当作纯 DHCPv4 字段丢掉。应拒绝 `maindhcp=1`，以及
RA/DHCPv6 的 `relay`/`hybrid`、任何非 disabled 的 NDP 模式。hybrid 可能运行时
转为 relay，不能以此刻恰好是 server 放行。`master=1` 的中继配置同属范围外。

C 的 iface policy 没有 `ignore` 字段；WAN 不服务源于模式默认为 disabled，
不是该字段的直接作用（`config.c:145`, `307`）。未知 dnsmasq 配置保持由其所有者
处理。DNR、PXE、PREF64、raw DHCP 选项等未在本机启用，不应未经范围确认就
静默接受为已实现功能。

## 源码默认值与 UCI 读取

| 项目 | 精确 C 默认值 |
|---|---|
| 全局 | `maindhcp=0`, `enable_tz=1`, `loglevel=4`；路径默认 unset，来自本机 UCI |
| 模式 | RA、DHCPv6、DHCPv4、NDP 均 disabled；`master=0` |
| DHCPv6 | dynamic=1, assignall=1, NA=1, PD=1, PD preferred flag=0, PD min length=62, host ID bits=12 |
| 租期 | 43200 s；preferred 上限 2700 s，valid 上限 5400 s |
| RA | SLAAC=1, other-config=1, offlink=0, advrouter=0, preference=medium, default override=0 |
| RA 计时 | max interval=600 s, min=200 s, router lifetime 初值=1800 s |
| RA 其他 | DNS=1, reachable/retrans/hoplimit=0；MTU 未配置时读取接口 MTU |
| DNS | dns_service=1；空 DNS 列表使用接口地址；未配置 domain 时没有搜索域回退 |

依据 `config.c:32,307,1194–1625` 和 `odhcpd.h:51`；README 的 loglevel=6、
RA lifetime=2700 不是这版实现默认值。线上 RA 寿命还受实际路由/前缀期限约束。
本机 managed-config 是显式配置，不是默认值。

C reload 顺序是 network globals（`dhcp_default_duid`）→ dhcp/odhcpd →
dhcp pools → host → boot6 → system timezone（`enable_tz=1` 时）→ netifd `data`
→ 启停服务（`config.c:2026`）。`system.timezone`/`zonename` 空白字符转为 `_`，
若配置存在则属于默认启用的 DHCPv6 输出；不能因本机未显式设置 `enable_tz`
而漏掉。现有 intake 未含 system 文件，首次实现前只需补取这两个字段是否存在。

复用 `owrt_uci::Context::new()`、`file::load()`、`Package/Section/OptionValue`，
保留默认 `/var/run/uci` override、`/tmp/.uci` delta 与字符串/列表差异。C 的
`-c <dir>` 用绝对文件路径加载三个 package，并非仅更换 confdir；绝对路径加载
不应用普通 package 的 override/delta。`config.rs` 的类型转换应直接依据
`uci_to_blob`，可参考现有 `components/netifd/src/config.rs:140` 的小函数；
无需增加通用配置框架或通过 UCI CLI 绕行。

## 进程、init 与信号

`/etc/init.d/odhcpd` 为 procd 前台服务：START=35、STOP=85，执行
`/usr/sbin/odhcpd`、respawn；dhcp/network/system 配置触发 reload，reload 向
服务发默认 SIGHUP。SIGHUP 重读配置；SIGINT/SIGTERM 结束事件循环，C 未在
退出后执行额外清理路径（`config.c:2191`）。不应把“收到 SIGTERM”自动当成
已经发送撤销 RA 的证据。

CLI 为 `-c <dir> -l <int> -f -u -h`（`odhcpd.c:69–191`）：`-f` 表示日志到
stderr，**不是前台开关**；`-u` 禁用 ubus；`-l` 取 `atoi & 7` 并覆盖 UCI；
非 root 返回 2，核心 socket/init 失败返回 4。`-h` 在 root 检查前返回成功。
LuCI/rpcd 解析帮助中的 `Features:` 行；受限版本应如实报告
`ra no-ndp dhcpv6 no-dhcpv4 ubus`，不宣称 NDP 支持。

## `dhcp` ubus 对象

实际 `ubus -v list dhcp` 已与源码相符：三个方法，**没有 `ipv4leases`**。

| 方法 | 参数 / 回复 |
|---|---|
| `ipv6leases` | 无 policy；`{"device":{"<ifname>":{"leases":[...]}}}` |
| `ipv6ra` | 无 policy；`{"interfaces":{"<ifname>":[...]}}` |
| `add_lease` | `ip:String, mac:Array, duid:Array, hostid:String, leasetime:String, name:String`；成功 status 0，非法输入 status 2 |

`ipv6leases` 条目含 `duid`（连续 hex）、`iaid`（u32）、`hostname`（缺省空串）、
`accept-reconf`（INT8）、`assigned`（NA u64 / PD u32）、`flags`（bound/static）、
`valid`（u32 剩余秒），以及 NA 的 `ipv6-addr` 或 PD 的 `ipv6-prefix` 数组。
地址条目含 `address`、`preferred-lifetime`、`valid-lifetime`，非 `/128` 才带
`prefix-length`。无限期 wire 值为 `0xffffffff`（CLI JSON 显示 -1）。包含尚未
bound 但未到期的分配，排除内部 border 项和有限 valid_until < now 的项，
不能直接复用仅输出 bound 租约的文件过滤规则（`ubus.c:93–178`）。

`ipv6ra` 条目含 `prefix`、`length`（u16）、`stale`（INT8），仅非零寿命时带
`lifetime`。length 是内部前缀长度；ULA `/60` 可以在线上 RA 中按 `/64` PIO
发送，不能以 JSON 长度推断报文错误（`ubus.c:181–234`）。

`add_lease` 是内存配置变更，不写 UCI；下一次 reload 重新以 UCI 为准。
`mac`/`duid` 在 ubus 必须为字符串数组（UCI 标量到数组转换另属 UCI 边界）；
DUID 支持 `%IAID`，hostid 为 hex 或 `ignore`，未给 hostid 时可从 IPv4 末字节
生成。共享静态 host 的 `ip`/`mac` 也可用于 IPv6 识别，不能因为它有 IPv4 字段
就拒绝（`config.c:584–740`）。C 此变体没有 DHCPv6 lease/release ubus 事件。

## netifd、内核状态与重连

启动时注册 dhcp 对象、匿名 subscriber 与 `ubus.object.add` 事件；找到
`network.interface` 后订阅并异步 `dump {}`。通知只携带触发信息：C 除明确
ignore 的已知接口外，重新取得完整 dump，再 reload。对象重新出现时再次订阅
并 dump；请求更新前取消旧 dump（`ubus.c:267–439,506`）。

dump 顶层 `interface` 数组使用 `interface`、`l3_device`、`data`，后者提供运行期
DHCP 参数；`up` 和 `ipv6-address` 虽声明了 policy，却不是 C 服务地址来源。
`ipv6-prefix` 主要用于 hybrid 判断。实际 LAN IPv6 地址、期限、链路状态、默认
路由来自 rtnetlink（`netlink.c:81–109,198–234,458`）。因此仅订阅 ubus 后复制
WAN6 PD 不足以复现 C：必须保留 netifd 已分配给 LAN 的边界和内核期限变化。
当前 WAN6 `data.passthru` 不是这个 C iface policy 接受的字段；LAN data 为空。

C 只在启动连接失败时每秒重试，**没有运行时 ubus 断线重连**，此前 r37 已观察到
dhcp 对象不恢复。用户要求的重连是明确增强：断线后丢弃连接内对象/type ID、
订阅和待处理 dump，重建连接、对象、事件注册、netifd 订阅，取得新完整 dump；
期间原有协议服务和有限租约期限仍须运行，不能把旧期限重新从零延长。

直接复用 `owrt_ubus::Connection` 的 connect/timeout、`add_object`、
`add_anonymous_object`、`register_event_handler`、`lookup_id`、`subscribe`、
`invoke_status_until`、`incoming_if_complete`、`reply_data_status` 与 `BlobBuf`。
事件注册是调用 system event object 的 register，**不是 subscribe object 1**。
现有 netifd/dnsmasq owner loop 已示范丢弃旧 ID 后重注册；不照搬整个服务层。
目前公开 invoke API 是有界同步接口；若直接用于 dump，应证明其等待不会拖慢
首条 RA/首个 DHCPv6 回复，不能把 C 的异步行为当成已经具备。

## 租约、hosts、触发器与调用方

租约文件一行格式为：

```text
# <physical-ifname> <hexduid> <hexiaid> <hostname-or-dash> <expiry-epoch> <hex-assigned-id> <prefix-length> [<address>/<length> ...]
```

只输出 bound 且未过期项；无限 expiry=-1。非安全 hostname 字节转为 `\xNN`，
无效 hostname 前加 `broken\x20`，不能允许换行伪造记录。此 C 只有写租约状态，
没有从 leasefile 恢复 DHCPv6 分配的路径；PIO 文件则必须读取以撤销旧前缀。

hosts 写到 `hostsdir/odhcpd.hosts.<logical-interface>`，仅有效 hostname 的
IA_NA；有搜索域时输出 FQDN 和短名，没有时只输出短名。先写
`.odhcpd.tmp`、flush/fsync 后 rename，避免读者看见半文件。PIO 文件名为
`piodir/odhcpd.pio.<physical-ifname>`，格式为 `{"slaac":[{"prefix":...,"length":...,"time":...}]}`，
time 是可省略的绝对时间（`statefiles.c:115–357`）。

每次 statefiles_write 会更新租约文件；**只有有效 NA 地址与 hostname 内容的
摘要改变**才更新 hosts 并 `posix_spawn(leasetrigger, [leasetrigger], environ)`。
没有额外位置参数，也不通过 shell 解析。仅续期或仅 PD 变化不会因此触发；初始
空摘要变化也可能触发一次（`statefiles.c:472–659`）。保留此门槛，避免每次续租
给 dnsmasq 发 SIGHUP。

现有 `odhcpd-update` 调用 procd 给 dnsmasq 发 SIGHUP；dnsmasq init 把
`/tmp/hosts` 加入 hosts 输入。本机 LuCI 的 DHCP 页面和状态页通过
`luci-rpc.getDHCPLeases`、getDUIDHints/getHostHints **读取租约文件**，并用
`odhcpd -h` 发现功能；现有 rpcd ACL 没给页面直接调用 dhcp 对象的权限，
不需要扩张 ACL。相关 Rust 调用方在 `components/rpcd/src/lucirpc.rs:215`
和 `components/rpcd/src/luci.rs:625`。

首次接口验证应一次覆盖：本机配置无误拒启、禁用范围明确失败、三个 ubus 方法
及 blob 类型、一次续期不重复 trigger、名字变化联动、SIGHUP、netifd 对象重建、
ubus 断线恢复及旧 dump 不覆盖新状态。协议时间/内存验收另外依照用户门槛，
本次只读契约没有产生性能结论。
