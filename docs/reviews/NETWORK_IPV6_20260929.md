# DHCPv6 与 IPv6 协同：下一阶段研究

2026-09-29。结论：**值得补齐前缀分配、续租、地址撤销与 DNS 联动的离线验证；暂不值得以提升吞吐为目标重写 odhcpd/odhcp6c。** 当前没有观测到这两个服务的计算能力限制上网速度。

## 1. 本机职责与源码边界

| 部分 | 当前职责 | 精确实现 |
|---|---|---|
| WAN DHCPv6 客户端 | 向上游请求地址、委派前缀和 DNS，处理 Renew/Rebind | odhcp6c `07d324ee7222c0e15b9975281f18236fdccc11bd` |
| 协议适配脚本 | 将 DHCPv6、RA 地址/路由/DNS 合并后通知 netifd | OpenWrt `f0a60eee2fe051741c643ea6118718aae1ef17fb` 的 `dhcpv6.sh`、`dhcpv6.script` |
| 网络编排 | 分配 LAN 子前缀、安装地址与路由、发出 ubus 更新 | 发布固件中的 netifd-rs，构建提交 `a4053dd5d4b4b2dbed3ff8a56d595aeabd33e0d0` |
| LAN IPv6 服务 | RA、DHCPv6 地址/前缀分配、NDP 等 | odhcpd-ipv6only `5d7be43f8b9dec0eb47e245cfab81108bb131273` |
| DNS/DHCPv4 | 转发 DNS、读取本机名、分配 IPv4 地址 | dnsmasq 2.93-r1；实际构建为 `no-DHCPv6` |
| 数据包转发 | 邻居发现、IPv6 路由、过滤与可用的快路径 | 现有 Linux、驱动和 nftables |

本轮已从保存的匹配源码树取得 odhcpd、odhcp6c，两个 Git HEAD 均与配方一致且工作树干净；包没有额外补丁。没有用上游主干替代部署版本。来源基线见 [source-baseline](../../manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json) 与 [sources](../../manifests/ax3000t-stock-openwrt-25.12.5/sources.json)。

DHCPv6、SLAAC 和默认路由要分别观察：DHCPv6 分配地址/前缀及其他参数，RA 承担默认路由发现，并可携带供 SLAAC 使用的前缀和 DNS 信息。设备拿到了 IPv6 地址，并不足以证明它已有有效默认路由和可用解析器。[RFC 9915](https://www.rfc-editor.org/rfc/rfc9915.html)、[RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html)、[RFC 8106](https://www.rfc-editor.org/rfc/rfc8106.html)。

截至本次检索，DHCPv6 基本规范已由 RFC 9915（2026 年 1 月）取代 RFC 8415。设计新测试时应查当前规范；判断这个部署版本是否兼容，仍须同时保留它所对应的 C 实现与既有客户端行为，不能仅凭规范更新就宣称现网有缺陷。

## 2. 本轮只读观察

原始输出在 ignored `private/network-research-20260929/runtime/`。公开结果仅保留类型、前缀长度、数量和统计，不公开地址、DUID、MAC 或主机名。各命令不是一个原子快照；不同命令中的剩余时间不能直接相减当成处理耗时。

| 观察项 | 结果 | 含义 |
|---|---|---|
| WAN / WAN6 | DHCP / DHCPv6，均为 up | 两种接入协议正常运行；本次没有主动续租 |
| 上游 PD | 一个公网 `/64` | 当前可用公网委派规模；没有证据证明上游会接受 `/56` 或 `/60` 提示 |
| LAN `ip6assign` | 配置请求 `/60`；实际 GUA 分配 `/64` | 请求的大小不能扩大上游给出的地址空间 |
| LAN 前缀顺序 | 公网 PD `/64` 在前、ULA `/60` 在后 | 当前满足此前修正的 `network_get_ipaddr6` 地址选择顺序 |
| LAN 服务 | `ra=server`、`dhcpv6=server`、`ra_slaac=1` | SLAAC 与 DHCPv6 并存 |
| RA 标志配置 | managed-config、other-config | 不能由此推断每个终端一定使用 IA_NA |
| DHCPv6 租约 | 4 条 bound IA_NA，0 条 IA_PD | 当前观测到地址分配，未观测到 LAN 下级路由器领取前缀 |
| Reconfigure | 这 4 条租约均未接受 | 不能把主动 Reconfigure 作为这些客户端更新配置的唯一机制 |
| RA 内部前缀记录 | 2 条，均 `stale=false` | odhcpd 当前记住的前缀；不是实际 RA 抓包 |
| odhcpd 内存 | RSS 1088 KiB，RssAnon 148 KiB | 单时点值，RSS 包含共享文件页，不是独占内存 |
| odhcp6c 内存 | RSS 912 KiB，RssAnon 84 KiB | 同上，不能据此承诺重写能回收约 2 MiB |

`bound` 是租约绑定状态，不是终端在线或地址仍处于 preferred 期限的证明；本次四条记录中有两条地址的 preferred 剩余时间已为负、valid 仍为正。该接口由内部期限生成剩余时间，不是抓取到的 DHCPv6 报文，不能直接将其当成线上发送了负数寿命或已发生网络故障。

特别要区分 `/60` 的两个含义：ULA `/60` 可以提供本地子网空间，但不是额外公网 PD；LAN 状态中的分配长度也不等于 RA 的线上 PIO 长度。精确 odhcpd 的 `router.c:819` 将小于 `/64` 的接口前缀以 `/64` PIO 发送，`ubus.c:215` 的 `ipv6ra` 方法则返回内部保存的长度。因此本次 `ipv6ra` 看见 ULA `/60`，不构成“错误广播 SLAAC /60”的证据。[精确 router.c](https://github.com/openwrt/odhcpd/blob/5d7be43f8b9dec0eb47e245cfab81108bb131273/src/router.c#L819)、[精确 ubus.c](https://github.com/openwrt/odhcpd/blob/5d7be43f8b9dec0eb47e245cfab81108bb131273/src/ubus.c#L182)。

## 3. 真正值得验证的边界

### A. 前缀与地址的生命周期

`dhcpv6.script` 把 `PREFIXES`、`ADDRESSES`、RA 路由和 RDNSS 转成 netifd 通知；更新不只是设置一个地址。netifd-rs 的 `set_delegated_prefixes()`、`apply_prefix_assignments()`、`withdraw_assignment()` 还要处理相同前缀的期限刷新、分配撤销、路由删除和地址废弃。这是已替换组件与成熟协议客户端之间最重要的契约。

当前 Rust 代码已有前缀头插顺序、ULA 更新、PD 回调次序和上游状态排序的单测。它们证明对应内部规则；完整的“上游 DHCPv6 → 脚本 → netifd → 内核 → odhcpd → 终端”仍需要独立集成证据，不能由这些单测替代。

### B. RA 与 DHCPv6 期限并不是越短越好

精确版本默认将前缀 preferred/valid 上限设为 2700/5400 秒；周期 RA 的最大间隔默认 600 秒、最小间隔 200 秒、router lifetime 1800 秒。实际发送会结合剩余前缀寿命与路由状态调整，不是把这些默认值原样发给所有客户端。`router.c` 还会让失效前缀的 PIO 生命周期归零；在当前未覆盖 `ra_default` 的配置下，没有适用公网前缀或默认路由时，不继续以正常 router lifetime 宣称默认路由可用。`ra_default=1/2` 可改变相应判断，不能把默认行为推广到所有配置。上述是源码行为，本轮没有用抓包验证每一种分支。

因此不建议为“获取网络快一点”直接缩短全部 RA/租约计时器。先测 Solicitation 响应、续租和事件传递；周期广播过密会增加无线广播和客户端唤醒。前缀换号时的剩余寿命约束与旧前缀撤销已有专门规范。[RFC 9096](https://www.rfc-editor.org/rfc/rfc9096.html)、[精确默认值](https://github.com/openwrt/odhcpd/blob/5d7be43f8b9dec0eb47e245cfab81108bb131273/src/config.c#L305)。

### C. ubus 更新与 DNS 主机名联动

odhcpd 订阅 `network.interface`，接到更新后异步调用 `dump`，再重新载入接口状态；它还监听该对象重新出现。Rust 的对象生命周期、通知与 dump 内容，都是实际调用方依赖的接口。[精确 ubus 实现](https://github.com/openwrt/odhcpd/blob/5d7be43f8b9dec0eb47e245cfab81108bb131273/src/ubus.c#L309)。

租约变化还可能生成 IPv6 主机名文件，并由 `odhcpd-update` 通过 procd 向 dnsmasq 发 SIGHUP。精确 `statefiles.c:588–661` 已有内容摘要比较，并非每次函数调用都会写 hosts 或触发脚本。应在离线场景确认一次真实变更产生的文件、通知与缓存影响；不能直接删掉通知来减少进程创建，否则可能留下过期本地域名。详细 DNS 成本口径见 [DNS 研究](NETWORK_DNS_20260929.md)。

## 4. 建议的离线实验

使用独立 Linux network namespace：受控上游 DHCPv6/RA 服务、路由器测试命名空间、两种终端（SLAAC 与 IA_NA），各端有独立 veth、路由表、ubus socket 和配置。原版 netifd 与 Rust netifd 依次运行同一输入；其余 odhcp6c/odhcpd/脚本版本保持一致。测试前缀使用文档地址，业务探针只访问命名空间内的 TCP 服务。

| 场景 | 核对内容 | 接受标准 |
|---|---|---|
| PD `/56`、`/60`、`/64` 及 NoPrefixAvail | 请求、实际分配、GUA/ULA 分类，LAN 地址与路由 | 与原版的可用前缀分配一致；不虚构公网空间，不把 ULA 当公网成功 |
| 同一 PD 的正常 Renew | preferred/valid 更新，地址和对象是否重复 | 新期限传到内核/RA/租约；无重复客户端、路由或不必要接口重建 |
| 上游不答 Renew、随后允许 Rebind | T1/T2 状态机、旧期限截止、新配置落地 | 行为符合精确协议实现；租约过期后不继续宣称旧公网前缀有效 |
| 前缀更换、撤回，再出现 | netifd 通知、旧地址废弃、PIO、源地址选择 | 新连接采用有效前缀；旧前缀状态与原版相符，保留协议规定的寿命语义 |
| 无默认路由但仍有地址 | 客户端 RA 默认路由、源特定路由、业务可达性 | 不把“有地址”判为联网；路由恢复后状态同步 |
| DNS 随 PD/RA 更新 | resolv 文件、LAN RDNSS、本地域名和解析成功率 | 无永久旧解析器或旧主机名；失效/更新传播有时间戳证据 |
| LAN 下级设备请求 IA_PD | 父前缀容量、保留的 LAN 子网、无法分配的响应 | 不与现有 LAN 重叠；空间不足返回正确状态，不靠修改 hint 制造容量 |
| ubus 对象重注册、重复通知 | odhcpd 重订阅、dump、状态文件和触发次数 | 最终状态等价、无长期漏订阅；重复事件的成本单独记录 |

每项保存协议报文、单调时钟事件序列、内核地址/路由、ubus 状态、RA 与终端业务探针；只归一化时间戳等非语义字段。必须保留前缀选择顺序、寿命、标志和错误响应，不能只比较无序集合。记录 CPU 时间、进程创建次数与峰值匿名页作为次要成本指标。

时间标准分两种：协议 T1/T2/valid 按测试输入的合法期限判断；本地通知处理用同一原版对照量化额外延迟，不把人为设置的短租期当成速度提升。只有发现可重复的状态差异或本地处理热点，才进入代码优化。

## 5. 投入判断

- **优先做**：补齐 netifd-rs 与现有 odhcp6c/odhcpd 的集成测试，尤其 `/64` 容量、续租期限和状态撤销。它保护现有九组件成果，也能发现有明确边界的小修复。
- **条件研究**：若将来增加 VLAN、访客网或 LAN 下级路由器，先确认上游可委派的规模，再设计多子网；当前没有 LAN IA_PD 使用证据，不优先开启新模式。
- **暂不立项**：odhcpd-rs、odhcp6c-rs 的完整替换。它们处理低频租约和生命周期，普通下载数据包经过内核；更换语言没有已证实的转发吞吐收益。
- **保留成熟实现**：NDP、IPv6 内核路由、协议计时与加密认证基础。若发现缺陷，先把失败报文/状态序列固定下来，再选择本项目适配修复或上游修复。

本轮没有主动续租、断开接口、发送 RA/DHCPv6 测试流量或改动生产配置。这里的实验是后续可执行方案，尚未运行，不能作为新增的协议验收结果。
