# odhcpd RA/SLAAC 合同（本机范围）

依据：OpenWrt 25.12.5 的 odhcpd 源码
`5d7be43f8b9dec0eb47e245cfab81108bb131273`；在用 C ELF SHA-256
`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
下述 `src/` 行号均属于该修订。本合同是源码与脱敏配置的交集，尚不是 Rust
实现或包级差分通过的证明；不包含新性能实验。

## 本机配置和输入权威

- LAN：`interface=lan`、`dhcpv6=server`、`ra=server`、`ra_slaac=1`、
  `ra_flags=[managed-config,other-config]`、`leasetime=12h`；没有其他 RA/DHCPv6
  选项或静态 host。WAN `ignore=1`。RA 不在 WAN 提供服务。
- odhcpd：`maindhcp=0`、`leasefile=/tmp/odhcpd.leases`、
  `leasetrigger=/usr/sbin/odhcpd-update`、`loglevel=4`、
  `piodir=/tmp/odhcpd-piodir`、`hostsdir=/tmp/hosts`。
- 观察到 LAN 获分配 GUA `/64` 和 ULA `/60`，WAN6 PD `/64`，LAN `data` 为空；
  当前有两个 PIO。地址与标识不写入 Git。**netifd 分配长度不代替内核地址长度**：
  实际 RA 以 LAN 内核 `RTM_GETADDR` 的地址、prefix length、`IFA_CACHEINFO` 为准。
  deprecated 将 preferred 置零；有限期限转为单调时钟期限，`UINT32_MAX` 保持无限。
  见 `src/netlink.c:547,663,673`。
- `network.interface` 初始 dump 和后续订阅通知确定 `l3_device`，应用 `data` 后
  重读配置；C 收到未忽略接口通知会重新 dump。`ipv6-prefix` 在 C 的
  `ubus_has_prefix()` 中用于 hybrid 判断，不是 server RA 的 PIO 输入。
  见 `src/ubus.c:296,310,325,351,447,471,506`。
- 默认路由与 delegated-prefix 范围依据 `/proc/net/ipv6_route`；后者取匹配的
  `lo` unreachable/reject route。还需 LAN MAC、ifindex、运行状态、link-local、
  MTU 和 `/proc/sys/net/ipv6/conf/<device>/hop_limit`。不能仅靠 ubus WAN up 位
  判断 RA router lifetime。见 `src/router.c:310,626`、`src/config.c:1148,1983`。

## 本机包输出

所有多字节线字段采用网络字节序；保留如下字段、条件与选项顺序。

| 输出 | 本机规则 | C 位置 |
|---|---|---|
| IPv6/ICMPv6 | link-local 源，IPv6 hoplimit 255，ICMPv6 type 134/code 0；内核生成校验和 | `router.c:110`、`odhcpd.c:244,348` |
| RA header | M=1、O=1，其余 flags=0；cur-hop-limit 取接口 sysctl（读取失败为 0）；reachable/retransmit=0 | `router.c:658` |
| Router lifetime | 默认 1800 秒；存在非 `lo` 默认 IPv6 路由且有合格非 ULA 有效前缀时发送，否则为 0 | `router.c:377,700,807,878` |
| SLLAO、MTU | type 1/len 1，LAN MAC；随后 type 5/len 1，C 的接口 MTU 快照，无可用快照时为 0 | `router.c:686`、`config.c:1543,1563` |
| PIO | type 3/len 4；L=A=1、P/R=0；清零 host bits；线上的 prefix length 为 `max(64,内核长度)` | `router.c:750,815` |
| RIO | 若路由扫描给该地址找到 `0<dprefix_len<64`，发 type 24/len 3，medium preference，完整 24 字节；无匹配则省略 | `router.c:1008` |
| RDNSS | type 25/len 3，一个本机 DNS 地址；首选仍有效且非 deprecated 的 ULA，其次合格 GUA，最后 link-local | `router.c:892`、`odhcpd.c:369` |
| Advertisement Interval | type 7/len 1；值为当前计算的最大广告间隔乘 1000，单位 ms | `router.c:1069` |

正常输入若内核确为 GUA `/64` 与 ULA `/60`，两条线上 PIO 都为 `/64`；
PIO 状态文件和 `dhcp.ipv6ra` 的 ULA `length` 仍为原来的 **60**，不能混用。
二者的 `prefix` 也保留接口地址的 host bits（例如 `2001:db8:1::1`），仅线上
PIO 清零 host bits；同前缀匹配比较原地址的 `max(64,旧长度,新长度)` 位，匹配后
地址 host bits 变化仍更新保存值。精确 C 隔离实证见
[C 基线](../reviews/ODHCPD_C_BASELINE_20261018.md)。
正常排序为有效 GUA 在前、ULA 在后，来自 C 地址排序；不能按文本地址另排序。
没有配置 DNSSL、PREF64、DNR、Captive Portal，故这些选项缺席。
RIO 不能只因 UCI 没有显式配置就省略，其输入是 reject route；不硬编码其数量。

活跃 PIO 的 preferred=`min(内核剩余 preferred,2700,本条 valid)`，
valid=`min(内核剩余 valid,5400)`。RDNSS lifetime 取参与构包的非 ULA 地址中
最大的上述 valid，若为零则回退到计算的 RA lifetime（默认 1800）；**不能因
router lifetime 为零就把 DNS lifetime 也置零**。RIO lifetime 为对应地址剩余
valid，上限 5400。见 `src/router.c:780,810,867,918,1055`。

## 首包、事件和周期

- LAN 运行且 RA 服务 enable 后，首个主动 RA 的 timer 为 **1000 ms**。
  无可用 link-local 时不发包，继续按周期重试。有效 RS 则在收到的回调中直接
  构包发送，不另加延迟；RS 源非 `::` 时单播回该源，否则发 `ff02::1`。
  见 `src/router.c:212,873,1095,1128`。
- 默认周期参数 min=200 秒、max=600 秒；max 再受最短 PIO valid 约束。
  C 随机计算下一间隔，成功发包计数使前两次后续间隔上限为 16 秒。
  正常期限且无 RS/更新时，初始主动发送约为 enable 后 1、17、33 秒。
  `ra_sent` 仅在成功发送后增加；RS 回复也计数。见 `src/router.c:351,1105`。
- 默认 IPv6 路由增删、LAN 地址列表变化将 timer 重设为 **1000 ms**；reload
  对仍启用的接口也重新 setup 并重设 timer。地址列表仅更新期限且都延长时，
  C 通常不发变化事件；地址、长度、preferred 状态变化或期限缩短会发。
  见 `src/router.c:190,237`、`src/netlink.c:197`。
- 首包验收分开记录「服务 enable→首主动 RA」和「有效 RS→首回复」，均与 C
  同条件对照；上述秒数是源码定时行为，不是本轮实测，不设微秒门槛。

## WAN 断开、前缀撤回和重启

默认路由删除后，下一 RA 的 router lifetime 为 0；ULA PIO 继续有效。
旧 GUA 地址消失，或 preferred 已为零且 valid 尚未到期时，C 对记住的旧 PIO
广告 **preferred=valid=0**，A/L 保持 1；新前缀正常广告。RA 停用时也尝试一次
最终撤回 RA。见 `src/router.c:94,698,720,840,878`。

曾广告 PIO 保留在内存与 `/tmp/odhcpd-piodir/odhcpd.pio.<device>`。
首次 stale 设置 `now+5400` 的记忆期限；后续撤回不反复延长；恢复同前缀将
stale 清零。文件为 `{"slaac":[{"prefix":…,"length":…,"time":…}]}`，
active 省略 `time`，stale 的 `time` 是墙钟到期点。启动/reload 读文件，成功
发包且 PIO 状态变化后写临时文件、fsync、rename。
见 `src/router.c:481,573,606,1105`、`src/config.c:1771`、
`src/statefiles.c:81,120,193,276`。

`dhcp.ipv6ra` 返回 `interfaces.<device>[]`，字段 `prefix,length,stale`；
stale 尚有剩余记忆期限时附 `lifetime`。文件位于 tmpfs：可跨 daemon 重启
恢复，不能承诺跨整机重启保存旧前缀。C 对已到 valid 期限但仍留在地址快照
中的地址会跳过 PIO；到期与删除事件交错须单列差分边界，不假定等同即时撤回。
见 `src/ubus.c:181`、`src/router.c:756`。

## 必须保留的边界

- raw socket 绑定 LAN，加入 `ff02::2`，收 pktinfo 与 hoplimit，关闭 multicast
  loop；接收只允许正确接口和 hoplimit 255。错误 code、坏 option 长度、
  `::` 源 RS 携带 SLLAO 不回复。见 `src/router.c:82,273`、`src/odhcpd.c:423`。
- LAN down/up、ifindex 更换和 link-local 更换不能继续使用旧 socket/源地址；
  netlink ENOBUFS 后重新同步地址，不能解释为状态未变。
  见 `src/router.c:237`、`src/netlink.c:251,497`。
- ubus 重连重新注册 `dhcp`、订阅 netifd 并获取新 dump；不能保留旧 object ID，
  不能让重连等待停住 RA/RS。重连是用户要求的验收边界。
- 前缀 A→B、A deprecated、A 删除后恢复、期限耗尽、daemon 重启、损坏/过期
  PIO 文件与墙钟跳变，必须覆盖旧 PIO 的清零与新 PIO 的有效性。
- 本机 `maindhcp=0`，共享 UCI 即使含 `dhcpv4=server`，C 的 odhcpd 有效模式仍为
  disabled（`src/config.c:1279`）。拒绝的是 odhcpd **有效 DHCPv4 模式**及
  NDP/relay/hybrid，不得误拒绝由 dnsmasq 服务的共享配置。
