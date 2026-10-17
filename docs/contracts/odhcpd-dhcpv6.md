# odhcpd-rs：受限 DHCPv6 与状态文件合同

日期：2026-10-18。这里只冻结本机服务端所需行为，不表示候选已实现或通过验收。

实现参考是精确镜像对应的 odhcpd `5d7be43f8b9dec0eb47e245cfab81108bb131273`。
Oracle 只读源码位于
`/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components/odhcpd`，
核对时工作树干净。下列 `src/…:行号` 均指该修订。
运行 C ELF SHA-256：
`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
原始配置、客户端标识和包留在私有证据目录，不写入 Git。

## 1. 本机边界

| 输入 | 已确认值 |
|---|---|
| odhcpd 全局 | `maindhcp=0`，`loglevel=4` |
| 状态出口 | `leasefile=/tmp/odhcpd.leases`，`hostsdir=/tmp/hosts` |
| 事件脚本 | `leasetrigger=/usr/sbin/odhcpd-update` |
| RA 前缀持久文件 | `piodir=/tmp/odhcpd-piodir` |
| LAN | DHCPv6 server、RA server、SLAAC 开启、M+O flags、租期 12h |
| WAN | `ignore=1` |
| LAN 可用池 | GUA `/64` 加 ULA `/60`；WAN6 获得 PD `/64` |
| 客户端快照 | 三个 IA_NA 租约，`accept-reconf=false`，无 IA_PD 租约 |

没有静态 UCI host、定制 DUID 或其余显式 IPv6 服务选项。PXE、NTP/SNTP、DNR、
Captive Portal、raw DHCPv6 options 不因参考源码支持而扩入本轮。
默认 DUID 和 DNS/search 行为仍属于现有默认服务，不能省略。
后续核对纠正了时区边界：C 默认 `enable_tz=1`，本机 system timezone 为
`CET-1CEST,M3.5.0,M10.5.0/3`、zonename 为 `Europe/Berlin`。客户端 ORO 请求时
必须输出相应 POSIX/TZDB 字符串选项 41/42；只传配置字符串，无需时区数据库。
依据：`src/config.c:39`，`src/dhcpv6.c:581`。这是默认有效行为的证据纠正。

用户明示要求 IA_NA 和 IA_PD，因此无现存 PD 客户端不构成删除 PD 支持的理由。
GUA `/64` 无可分配的下游 PD 空间；ULA `/60` 可提供 `/62` 等更长子前缀。
验收必须分别检查两种池，不能以 WAN 的 `/64` 推断本机完全不支持 PD。

NDP 代理、RA/DHCPv6 relay、DHCPv4 服务模式必须在启动前报错退出，不能静默禁用。
不增加 relay 转发或处理链；不改 odhcp6c、udhcpc 和 netifd 的执行协议。
没有现存静态 host 不意味着删除用户明示的 ubus `dhcp.add_lease`：其基本 IPv6 host
配置、匹配和错误返回仍须纳入 `dhcp` 对象合同。本文件只规定其对租约分配的影响。

## 2. 接口与报文

- 每个服务接口绑定 UDP/IPv6 547，绑定设备并接收 pktinfo；加入 `ff02::1:2`
  和 `ff05::1:3`。回复保持原 transaction ID，使用正确接口和客户端地址。
  依据：`src/dhcpv6.c:46`、`:706`、`:848`。
- 默认 server DUID 为 DUID-LL：`0003 0001` 加接口 MAC。不能改为随机启动 ID。
  客户端 DUID 接受范围为 10–130 字节。依据：`src/dhcpv6.c:412`、
  `src/odhcpd.h:199`、`src/dhcpv6-ia.c:1023`。
- 租约身份至少包含接口、IA_NA/IA_PD 类型、完整 DUID 和 IAID；同一客户端多 IAID、
  同包 NA+PD 不得互相覆盖。依据：`src/dhcpv6-ia.c:1109`。
- 默认发送 `SOL_MAX_RT=60`；Information Request 改为 `INF_MAX_RT=60` 并带
  refresh 600。DNS 使用配置地址，否则按接口 DNS 选择；搜索域使用已有配置/接口输入。
  依据：`src/dhcpv6.c:432`、`:458`、`:655`、`:787`。
- 非本机 server ID、自己的 DUID、服务端消息类型均忽略。单播
  Solicit/Confirm/Rebind/Information Request 不回复；单播
  Request/Renew/Release/Decline 返回 `UseMulticast`，不处理租约动作。
  依据：`src/dhcpv6.c:366`、`:701`、`:714`、`:768`、`:774`。
- TLV 和 IA 子选项必须逐层检查边界；IA 固定负载至少 12 字节。未知选项不造成
  崩溃或越界。合法包保持参考输出；畸形包验收关注安全拒绝和状态不被破坏，不能为了
  复刻未定义行为而越界读。依据：`src/dhcpv6.h:165`、`src/dhcpv6-ia.c:1033`。

| 动作 | 对外行为 | 参考 |
|---|---|---|
| Solicit | Advertise；带 Rapid Commit 则 Reply 并绑定；普通 offer 保留 60 秒 | `dhcpv6.c:787`，`dhcpv6-ia.c:1298` |
| Request | 分配/确认；请求地址不在链路上返回 IA 级 `NotOnLink` | `dhcpv6-ia.c:1190`、`:1249` |
| Renew | 已有绑定刷新；不存在则 IA 级 `NoBinding` | `dhcpv6-ia.c:1339` |
| Rebind | 可恢复未知绑定；同时处理旧地址/前缀失效 | `dhcpv6-ia.c:1190`、`:1400` |
| Release | 立即标记到期，撤销 PD 路由，返回状态 | `dhcpv6-ia.c:1172`、`:1357` |
| Decline | 只适用于 NA；动态 IID 隔离一小时，静态 IID 立即释放 | `dhcpv6-ia.c:1362` |
| Confirm | 携带地址不在链路上则 `NotOnLink`；无地址或无已绑定租约时不回复 | `dhcpv6-ia.c:1384` |
| Information Request | 不分配 IA；可无 ClientID | `dhcpv6.c:789`、`:822` |

## 3. 分配与寿命

本机未覆盖的默认值仍生效：`assignall=true`、NA/PD 均开启、hostidlength=12、
PD 最小长度 `/62`、max preferred/valid 为 2700/5400 秒。
依据：`src/config.c:68`、`:317`，`src/odhcpd.h:50`。

NA 动态 IID 池从 `0x100` 到 `0xfff`。C 使用 DUID 最后六字节作为 `jrand48`
种子，再从起点顺序最多探测 100 次，跳过保留 IID、静态 hostid 和已有分配。
默认返回所有有效前缀对应的地址。保持该确定性，避免替换守护进程后无故换地址。
运行期间添加的基本 host 配置按 DUID/IAID 优先、DUID 中可识别 MAC 次之匹配，
hostid/name/leasetime 影响分配。依据：`src/dhcpv6-ia.c:402`、`:421`、`:1047`、
`:1216`，`src/dhcpv6-ia.h:19`。

PD 默认请求 `/62`，先尝试合法 hint，再查找对齐空洞；空间不够可逐步缩至 `/64`。
分配长度须严格大于来源前缀长度；没有空间回复 `NoPrefixAvail`。绑定后添加经客户端
地址、服务接口的路由，metric 1024；释放、过期和前缀撤销时移除相应路由。
NA 不添加此类路由。依据：`src/dhcpv6-ia.c:289`、`:319`、`:342`、`:1043`、`:1226`，
`src/dhcpv6-ia.h:28`。

寿命同时受来源前缀剩余寿命、租期、max preferred/valid 限制，preferred 不得超过 valid。
T1 为最短有效 preferred 的 50%，T2 为 80%，最小 1 秒；无限值保持 RFC 表示。
内部使用单调时钟，不让 NTP 校时改变到期时刻。依据：`src/dhcpv6-ia.c:572`。

前缀删除或 preferred 到期后不再用于新分配。Renew/Rebind 中客户端携带的旧
IAADDR/IAPREFIX 必须以 preferred=0、valid=0 返回；新前缀正确分配，旧 PD route
撤销。RA 的旧 PIO 废止另属 RA 合同，不能用 DHCPv6 回复代替。
依据：`src/dhcpv6-ia.h:33`、`src/dhcpv6-ia.c:747`。

现有客户端均未接受 Reconfigure。C 对接受该扩展的 PD 客户端另有 nonce/HMAC-MD5
握手、Reconfigure Renew 和从 2 秒开始的退避，见 `src/dhcpv6-ia.c:161`、`:500`、
`:523`、`:1259`。本轮明确不实现该扩展：收到客户端 Reconfigure Accept 时继续普通
IA 服务，不返回接受/认证握手，不发送未经协商的主动 Reconfigure。这是与 C 的已知
差异，必须测试没有未经协商的推送。IA_PD 分配、续租、撤路由以及旧前缀正常续租
废止完整保留，不能因省略扩展而删减。

## 4. leasefile、hosts、leasetrigger 与 PIO 文件

`/tmp/odhcpd.leases` 是导出接口。参考 `src` 未发现 DHCPv6 leasefile 读回；
重启后的动态 IID 稳定性来自上述确定性分配，不能把它描述为持久租约恢复。
只导出已绑定、未到期记录，格式为：

```text
# <ifname> <hexduid> <hexiaid> <hostname> <wallclock-valid-until> <hex-host-or-subnet-id> <prefix-length> [<address>/<length> ...]
```

无限 valid 为 `-1`。不安全 hostname 字节转成 `\xNN`，不合法 hostname 另带
`broken\x20` 前缀，禁止客户端用换行/空格伪造记录。
依据：`src/statefiles.c:503`、`:529`、`:589`。

`/tmp/hosts/odhcpd.hosts.<logical-interface>` 只写有合法 hostname 的有效 NA，
不发布 PD。无 search domain 时是 `address hostname`；有域时是
`address fqdn shortname`。FQDN 选项只取第一个 label 作动态主机名，静态 name 优先。
依据：`src/statefiles.c:364`、`:420`，`src/dhcpv6-ia.c:996`、`:1311`。

C 可在每次状态处理重写 leasefile，但仅在有效 NA 地址与合法 hostname 的映射摘要
变化时重写 hosts、调用 leasetrigger。单纯寿命更新或纯 PD 变化不触发；首次空摘要
初始化也可能触发一次。`/usr/sbin/odhcpd-update` 无参数、继承环境、异步执行；
保持其现有 dnsmasq 通知职责，不能每次续租额外调用。
依据：`src/statefiles.c:472`、`:589`、`:643`。

输出使用同目录临时文件，加锁、truncate、flush、fsync、rename，避免消费者读取半份文件。
文件写失败须可诊断，不得崩溃或删除有效内存租约。
依据：`src/statefiles.c:45`、`:81`。

`/tmp/odhcpd-piodir/odhcpd.pio.<ifname>` 是 RA 的持久前缀记录，内容形如：

```json
{"slaac":[{"prefix":"2001:db8::","length":64,"time":2000000000}]}
```

`time` 为可选墙钟到期值，读入后转换为单调时钟；过期记录不恢复。该文件服务于
守护进程重启后的旧 PIO 废止，不是 DHCPv6 分配数据库。
依据：`src/statefiles.c:120`、`:193`、`:276`。

## 5. 必须观测的 C 边界与验收

C `handle_addrlist_change()` 的旧 PD route 删除受 `!ND_RA_FLAG_MANAGED` 限制，
而本机 M flag 开启。首次 PD 验收必须检查路由实际消失，不能照搬条件后宣称正确。
若为满足用户的旧前缀废止要求而修正此行为，要在实现报告明确记录差异。
依据：`src/dhcpv6-ia.c:480`。

C 每秒到期清理释放租约和 PD route，却不立即更新 leasefile/hosts；后续状态事件才
重写文件。若候选改为即时清理，也须记录差异，不能误称参考已有此行为。
依据：`src/dhcpv6-ia.c:553`。

同一隔离网络输入分别运行精确 C 和 Rust，至少覆盖：

1. NA/PD 四步、Rapid Commit、重复请求、多 IAID、同包 NA+PD、无池/耗尽。
2. Renew/Rebind、未知绑定、Release、Decline、Confirm、Information Request、
   server ID/DUID/单播规则和截断 TLV。
3. GUA `/64` 与 ULA `/60` 的不同 PD 可用性；前缀替换、删除、preferred/valid 到期；
   旧地址零寿命、旧 PD route 撤销、RA 旧 PIO 废止。
4. leasefile/hosts 内容、hostname 转义、纯续租不重复 trigger、真实映射变化触发一次、
   进程重启后的 PIO 读回；ubus 增加基本 host 对租约的影响。
5. 首条 DHCPv6 回复不慢于 C，配合总体首条 RA 验收；同条件内存不超过 C 两倍，
   ubus 断线重连不丢必要服务状态。不设微秒门槛、不做 PGO。

当前 C RSS 1132 KiB、anonymous 136 KiB 只是三租约快照，正式内存门须在相同租约数、
相同运行阶段重测。包比较仅归一化事务 ID、实时时间和随机认证材料；不得隐藏分配、
状态码、选项、寿命或路由差异。本合同未实施上述验收。
