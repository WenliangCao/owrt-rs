# DNS 与 DHCPv4：精确镜像研究

2026-09-29。**保留 dnsmasq，先做解析路径与故障分解，再决定配置优化。现在没有 DNS CPU 瓶颈或缓存容量不足的证据，完整 Rust 重写不立项。**

本次完成源码、包变体、实际配置和调用方核对；没有向生产 DNS 发起测试负载，没有清缓存、发信号、重启服务或改配置。
此前的 797 / 628 Mbps 局域网结果、硬件卸载对照都不是 DNS 性能测试；DNS 通常影响建连前的等待，不承担已建立连接的持续数据转发。
数据路径研究见[已完成测量](DATAPATH_20260929_RESULTS.md)，整体取舍见[分层规划](NEXT_PHASE_20260929.md)。

## 1. 当前究竟运行了什么

| 项目 | 核验结果 |
|---|---|
| 系统 | AX3000T，OpenWrt 25.12.5，Linux 6.12.94，Rust9 v0.1.0 |
| 安装包 | `dnsmasq 2.93-r1`，普通 `nodhcpv6` 变体；不是 `dnsmasq-full` |
| 包配方来源 | OpenWrt `f0a60eee2fe051741c643ea6118718aae1ef17fb` |
| 上游源码 | `dnsmasq-2.93.tar.xz`，SHA256 `0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19` |
| OpenWrt 补丁 | `100-remove-old-runtime-kernel-support.patch`、`200-ubus_dns.patch` |
| 已编译能力 | IPv6 DNS、UBus、DHCPv4、TFTP、loop-detect、inotify、dumpfile |
| 未编译能力 | DHCPv6、DNSSEC 验证、DBus、Lua、conntrack、ipset、nftset、权威 DNS、IDN、i18n |
| 运行隔离 | dnsmasq 用户，procd/ujail 启动；不能把 ujail 占用直接当可删除开销 |
| 内存快照 | dnsmasq 主进程 RSS 1268 KiB、RssAnon 276 KiB；这不是 USS/PSS，也不是峰值 |

包与源码身份来自[packages.json](../../manifests/ax3000t-stock-openwrt-25.12.5/packages.json)、[sources.json](../../manifests/ax3000t-stock-openwrt-25.12.5/sources.json)。
本轮从现有精确源码副本取回包配方，13 个文件哈希逐项吻合；上游归档哈希吻合，两份补丁在本机干净应用。
功能还用实机 `dnsmasq --version` 交叉确认；“支持 IPv6 DNS”不代表该包提供 DHCPv6/RA，那部分由 odhcpd 负责。
TFTP、loop-detect 编译存在也不等于实际开启。`no-ID` 关闭部分 `*.bind` 查询，不能依赖那些查询收集统计。
此机没有 DNSSEC 验证的计算成本，不能以“换 Rust 后优化 DNSSEC”解释它的现有性能。

实际生效配置及附加配置均已读取：`/etc/dnsmasq.conf` 无有效配置行，实例 conf-dir 为空。

| 配置 | 当前值与含义 |
|---|---|
| 缓存 | `cache-size=1000`；已经高于上游默认 150，不应照通用教程再次“从 150 调大” |
| 缓存语义 | 负缓存开启；未设置强制最小 TTL、过期数据服务或额外 `cache-rr` |
| 报文 | `edns-packet-max=1232`；A/AAAA 都不过滤 |
| 上游 | netifd 自动文件中两个 IPv4、两个 IPv6 nameserver；未开启 strict-order/all-servers |
| 本地名字 | `lan` 域、expand-hosts、`/etc/hosts`、`/tmp/hosts`、DHCP 名字与 `/etc/ethers` |
| 服务边界 | bind-dynamic、local-service、DNS rebinding 保护；允许 localhost 例外 |
| DHCPv4 | LAN 提供服务，150 地址池，12 小时租期；WAN 不提供 DHCP |
| 可观测性 | `dnsmasq.metrics` 已注册，另有无 RPC 方法的 `dnsmasq.dns` 对象 |
| 日志与脚本 | 未开启逐查询日志；生成配置没有 `dhcp-script`/`script-arp` |

`local-service` 的作用受显式 interface/listen 配置影响；完整访问控制还包括 fw4 输入规则，不能只看一个选项。[上游手册](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)

## 2. 调用链及兼容边界

```text
LuCI / UCI dhcp、system ──→ /etc/init.d/dnsmasq ──→ 实例配置与 hosts
netifd-rs / WAN 协议脚本 ──→ resolv.conf.auto ────→ dnsmasq 上游列表
LAN 客户端 / 路由器自身 ──→ DNS :53 UDP/TCP ─────→ 本地回答或转发
LAN DHCPv4 ──→ dnsmasq ──→ dhcp.leases + 本地 DNS 名字 + ubus 事件
odhcpd ──→ /tmp/hosts 中 IPv6 名字 ──→ dnsmasq ──→ LAN DNS
rpcd-rs / LuCI ──→ 两种 leasefile、dnsmasq --version、UCI ──→ 页面
```

1. init 脚本读取 UCI、接口状态及静态定义，生成 `/var/etc/dnsmasq.conf.<实例>`、`/tmp/hosts/dhcp.<实例>`。
   procd 以 `dnsmasq -C <配置> -k -x <pidfile>` 启动，登记配置文件、respawn、jail 挂载与接口触发器。
2. netifd-rs 在接口状态/协议更新后重写 `/tmp/resolv.conf.d/resolv.conf.auto`，内容未变则不替换文件。
   dnsmasq 读取该文件；路由器自身的 `/etc/resolv.conf` 则指向本机解析路径。两份文件职责不同，不能合并成递归回环。
3. dnsmasq 维护 DHCPv4 租约和 DNS 名字，odhcpd 提供 IPv6 hosts。新名字、续租、到期和删除都要保持一致。
4. [rpcd-rs 租约读取](../../components/rpcd/src/lucirpc.rs)仍按 UCI 的 dnsmasq/odhcpd leasefile 解析，提供 `luci-rpc.getDHCPLeases`。
   [LuCI 能力读取](../../components/rpcd/src/luci.rs)还会执行 `dnsmasq --version`；替换二进制只保留端口响应并不兼容这些调用。
5. dhcp/system 配置变动与相关接口事件触发 init reload；reload 重新提交 procd 配置并发送默认重载信号。
   dnsmasq 的 SIGHUP 会清 DNS 缓存、重读 hosts/ethers/租约辅助输入，**不会直接重读主配置**；配置变更还依赖 procd 判定。
6. DHCP ACK/RELEASE 可产生 `dhcp.ack` / `dhcp.release` ubus 通知。
   只有存在 handler 或用户脚本时，init 才启用 `dhcp-script.sh`；该脚本把环境送到 `hotplug.dhcp/neigh/tftp.call`。
   `/usr/share/acl.d/dnsmasq_acl.json`规定 dnsmasq 用户的发布与调用权限，属于系统总线权限，不等于 LuCI session ACL。

odhcpd 还有一条已经核对的联动：`statefiles_write_state()`对选定地址和有效 hostname 计算哈希，变化时才写 hosts 并运行 `odhcpd-update`，后者给 dnsmasq 发 SIGHUP。
因此 IPv6 名字变化会连带清 DNS 缓存；**正常续租而地址/名字不变，不会仅因续租这一事实执行该回调**。
这是可研究的小边界，但本次没有重载频次及延迟时间线，不能由一组计数推断“频繁刷新造成性能问题”。

精确源码落点：包 `dnsmasq.init:987–1112,1250–1380`、`dhcp-script.sh`、`dnsmasq_acl.json`；dnsmasq `lease.c`、`rfc2131.c:1958`；本项目 `netifd/src/main.rs:3489`、`rpcd/src/lucirpc.rs:218`。

另有一个具体的潜在慢路径：OpenWrt 的 `200-ubus_dns.patch` 允许 `dnsmasq.dns` 订阅者收到 A/AAAA 结果并返回改写地址。
源码仅在有订阅者时进入该路径，内部 `ubus_complete_request(..., 100)` 的等待上限为 100 ms；不是每个查询固定增加 100 ms。
本次只列对象和读取 metrics，没有订阅它；对象存在也不证明已有订阅者，更不能宣称生产正在因此变慢。
离线协议测试必须包含“无订阅者、立即响应、迟延响应、断开、地址改写”；观测工具自己订阅会改变被测路径。

## 3. 当前统计能说明什么

2026-09-29 的一次只读 metrics：forwarded **806**、local_answered **203**、cache_inserted **36**、cache_live_freed **0**、stale_answered **0**、dns_unanswered **0**。
DHCP discover/offer 为 9/9，request/ack 为 12/12，decline/nak/noanswer 均为 0；这只是累计计数快照。

- `dns_local_answered` 包含缓存、本地 hosts/租约、配置回答和部分本地错误，`203 / (806 + 203)` **不是纯缓存命中率**。
- 缓存插入/未过期淘汰计数在 `cache_reload()` 重置；不能假定所有 metrics 自同一时刻累计。
  SIGHUP 的这条路径不重置 forwarded/local_answered，所以 36 次插入与 806 次转发尤其不能直接配成同窗比率。
- `dns_unanswered` 在未完成转发记录被回收时更新，并非客户端超时实时总数；为零不能证明解析从未超时。
- `noanswer` 属于 DHCP 统计，不是 DNS 查询失败数。TCP 连接为零也不能免除 DNS-over-TCP 兼容测试。
- 未过期淘汰为零，因此当前快照**没有支持扩大缓存的证据**；仍需多个正常使用窗口的增量而非单点判断。
- 本次未测 DNS p50/p95、各上游耗时、QPS 或 CPU/查询，无法报告“DNS 还能提速多少”。

上述口径直接核对了精确 2.93 的 `src/metrics.c`、`cache.c:774,866,1566`、`forward.c:579,621,1957,3165` 和 `rfc2131.c:1565`。

## 4. 把等待分解后再选优化

| 场景 | 需要区分的成本 | 优先行动 |
|---|---|---|
| 热缓存/本地名 | 客户端调度、Wi-Fi 往返、内核排队、解析/缓存查找、回包 | 有线与隔离 loopback 分开测，排除无线尾延迟 |
| 缓存未命中 | 前述成本 + 上游链路/递归等待 + 回包处理 | 对照受控上游；不把上游几十毫秒归入 dnsmasq CPU |
| 短时重复查询 | 合并进行中的同名查询、客户端重试、回包扇出 | 分开统计客户端请求数、上游实际请求数；不是一一对应 |
| 突发不同查询 | outstanding 表、socket、FD、CPU、上游排队 | 确认是本地饱和还是上游不回答，再考虑并发参数 |
| AAAA 慢或失败 | AAAA NODATA、NXDOMAIN、超时、IPv6 传输不通、随后 IPv6 建连失败 | 分开 A/AAAA 与上游 IPv4/IPv6 四种组合 |
| DNS TCP | 握手、子进程、连接复用、超时、截断回退 | 单独记录成功/失败与资源峰值，不用 UDP 热缓存代表 |
| hosts/租约更新 | init/脚本启动、文件更新、重载、缓存重新预热 | 若确认重复重载导致问题，修触发链；它不是逐请求成本 |

AAAA 查询也可以经 IPv4 上游取得结果；IPv6 上游故障也可能拖慢 A 查询。返回“没有 AAAA”与丢包超时是两种不同现象。
解析成功后 IPv6 连接迟迟不通属于地址可达性/客户端竞速，不应通过全局过滤 AAAA 掩盖；现代客户端的并行解析与连接参见 [RFC 8305](https://datatracker.ietf.org/doc/html/rfc8305)。
NXDOMAIN 与 NODATA 的缓存键、SOA/TTL 语义必须区分，参见 [RFC 2308](https://datatracker.ietf.org/doc/html/rfc2308)。
TCP 是 DNS 正常协议路径而非可删的罕见功能，参见 [RFC 7766](https://datatracker.ietf.org/doc/html/rfc7766)。

精确版本的 `dns-forward-max` 默认是 **每个 server group 150 个并发转发查询**，不是每秒 150 次，也不是整个服务统一的 150 QPS 限额。
当前没有覆盖该默认值。相近重复查询可合并，组内记录占满时会拒绝新转发；盲目增大只可能积压更多上游超时和内存。
DNS UDP 主处理使用事件循环，TCP 有子进程；“C 单线程，Rust 多线程必然快”的说法不足以成立。

## 5. 值得做与暂不做的项目

| 候选 | 当前判断 | 开始修改所需证据 |
|---|---|---|
| 上游可用性与 A/AAAA 路径 | 优先测量 | 某类传输/某个上游持续慢或失败，且对照能隔离原因 |
| 缓存容量 1000→2000/4000 | 条件候选 | 多窗口有未过期淘汰，且重放证明因此发生额外未命中 |
| HTTPS/SVCB 等 RR 缓存 | 条件候选 | 这些类型在实际未命中中占明显比例，再对指定 `cache-rr` 试验；不默认 `ANY` |
| dnsmasq 重载/hosts 更新链 | 条件候选 | 无必要重载、缓存重置与用户解析尾延迟有时间关联 |
| ubus DNS 订阅回调 | 条件候选 | 确认存在订阅者且实际等待占比显著，先修调用方或边界 |
| DNS 本体小修 | 排在配置之后 | profile 显示具体热点且官方实现/配置仍无法解决 |
| 完整 dnsmasq-rs | 暂不立项 | 本地处理持续构成可感知瓶颈，并值得承担 DNS+DHCP 维护面 |

不把 strict-order、all-servers、提高最小 TTL、use-stale-cache 当作免费加速：分别改变选择策略、上游查询量或新鲜度，必须单独评估。
不关闭负缓存、rebind 保护、源端口随机化或 TCP 来换取基准分数；不把 full 变体、加密 DNS 或递归解析器自动视为提速升级。
现阶段也不把 dnsmasq 塞入 PID1/netifd/rpcd：它的输入暴露面与故障边界独立，语言统一不能抵消更大的故障影响。
最新文档用于核对选项含义；实际行为以下载核验过的 [2.93 源码归档](https://thekelleys.org.uk/dnsmasq/dnsmasq-2.93.tar.xz)及本镜像补丁为准。

## 6. 下一份可执行实验

**A. 隔离功能实验。** 在构建机的独立 Linux namespace/临时根目录使用精确 stock 二进制或按相同功能构建的参考；不绑定宿舍 LAN/WAN。
配两个受控 DNS 上游与 DHCP 客户端，仅使用测试域和地址；所有 PID、配置、leases、ubus socket 均位于独立目录。
跨架构模拟可验证协议，不能拿其耗时当路由器性能；同机原生重编译也只能用于候选筛选。

| 测试组 | 必须覆盖的输入与观察 |
|---|---|
| DNS 正确性 | A/AAAA/PTR/CNAME、HTTPS/SVCB、TXT/SRV、大小写、TTL 到期、负缓存、未知类型透传 |
| 报文边界 | UDP 512/EDNS 1232、TC 与 TCP 重试、多问题/畸形压缩指针、ID/源地址匹配、超大响应 |
| 上游异常 | 受控 0/10/50/200 ms 延迟、丢包、SERVFAIL/REFUSED、仅 A/AAAA 不回答、IPv4/IPv6 分别不可达 |
| 本地联动 | DHCP 获租/续租/释放/拒绝/到期、静态租约、hostname 冲突、hosts 增删、IPv6 hosts 更新 |
| 生命周期 | UCI reload、上游文件原子替换、接口改址、ubus 重连、FD/并发耗尽、租约写入失败 |
| OpenWrt 扩展 | metrics 字段、DHCP 通知、DNS 订阅四种响应、hotplug 环境与 ACL 拒绝 |

以协议语义做对照：DNS ID、时间字段、合法 RR 顺序不能逐字节硬比；地址、rcode、TTL 约束、flag、租约状态和事件副作用必须一致。
性能计时独立于可开日志的功能测试；需要抓包时只抓隔离测试网，不能以抓取用户域名作为默认前提。

**B. 隔离性能分解。** 分别测热缓存、唯一域名冷转发、TTL 到期、正常混合、上游失败混合；并发 1/8/32/128，256 仅作超限验证。
同一参考先比较缓存 1000/2000/4000、指定 RR 缓存或必要的上游策略，一次只改一项；保持相同输入与上游脚本。
至少五个交错 A/B/A 窗口，报告实际完成数、失败、p50/p95、CPU 微秒/查询、USS/PSS 峰值、上游请求数、FD/转发记录峰值。
负载发生器记录预定发送时刻，避免服务变慢后发得更少而把尾延迟藏掉；没有足够样本时不报 p99。
数据集为人工合成时明确注明，不能把 100% 热缓存最大 QPS 等同家庭使用收益。

**C. 是否进入真实设备验证。** 先用正常使用期间两次只读 metrics/进程计数的增量筛选，再决定小范围端到端对照。
当前用户授权的是研究；本页没有执行新的生产负载或部署候选。实机配置变动另按项目的部署规则执行。

以下是建议预先冻结的研究门槛，不是已经测出的结果：

- 缓存增大：至少三个窗口出现容量淘汰，且受控重放使未命中数下降 ≥20%；新增 USS ≤1 MiB，TTL/负缓存语义不变。
- 延迟候选：真实代表性混合负载 p95 同时改善 ≥20% 和 ≥2 ms，五轮方向一致，失败率不增加；仅热缓存微秒差不满足。
- CPU 候选：已证实 DNS 本体在实际峰值持续占单核 ≥25%，候选 CPU/查询下降 ≥30%，不能把上游等待计入 CPU 收益。
- 不立项门槛：若受控分解显示未命中等待 ≥80% 来自上游、热回答有线 p95 ≤1 ms 且无本地饱和，停止 DNS 重写，处理上游或无线路径。
- 所有进入下一阶段的候选必须通过功能矩阵；普通输入出现错误答案、跨接口泄漏、租约冲突、进程崩溃或无界资源增长即拒绝。

## 7. 如果仍要完整 Rust 替换，最低交付范围

“替换当前安装变体”至少包含完整活动 DNS/DHCPv4 合同，而不只是缓存一个 `name → IP`：

1. DNS UDP/TCP、IPv4/IPv6 传输、转发分组/选择/重试/合并、TTL/负缓存、通用 RR、CNAME/PTR、EDNS/截断、随机化和资源限制。
2. 本地 hosts/ethers/lease 名字、域扩展、local/reverse 规则、rebind/local-service、动态接口绑定，以及当前用户可用配置的明确支持/拒绝。
3. DHCPv4 DORA、续租/重绑定/释放/DECLINE、广播/单播、client-id、静态租约、租约文件恢复/过期和 DNS 同步，不能给两个客户分配同一地址。
4. 原 CLI/配置入口与版本能力查询、procd reload/respawn、jail/权限、UCI 生成器、ubus/ACL/hotplug、rpcd-rs/LuCI 消费格式。
5. 畸形网络输入测试与 fuzz、内存/FD/并发上限、可诊断错误；保留独立服务故障边界。

当前变体没有的 DHCPv6/RA、DNSSEC 验证、nftset/conntrack/权威 DNS不必凭空扩大到本轮；编译存在而未启用的 TFTP 等需明确兼容或声明裁剪。
若声称是 dnsmasq 包的通用无缝替代，就还要覆盖可启用能力；只实现本机配置应标为受限替代，并在不支持配置出现时明确拒绝，不能默默丢选项。
即使复用成熟 Rust DNS 库，OpenWrt 配置、租约、事件与生命周期合同也不会自动实现。此成本目前没有被测量收益支持。

## 8. 证据与未决项

- 原始 runtime：ignored `private/network-research-20260929/runtime/`；主快照 UTC 19:18:19–19:18:25，随后补充 metrics、总线对象和附加配置。
- 精确源码与完整性记录：ignored `private/network-research-20260929/dns/`，含 `source-integrity.json`、归档、已应用补丁树及精确 LuCI 调用方。
- 上游公开基线：[OpenWrt 精确配方](https://github.com/openwrt/openwrt/blob/f0a60eee2fe051741c643ea6118718aae1ef17fb/package/network/services/dnsmasq/Makefile)、[DNS ubus 补丁](https://github.com/openwrt/openwrt/blob/f0a60eee2fe051741c643ea6118718aae1ef17fb/package/network/services/dnsmasq/patches/200-ubus_dns.patch)。
- 尚未测：DNS 延迟/QPS、上游分项耗时、正常使用的缓存增量、DNS 订阅者实际存在与否、忙时独占内存和 CPU；这些决定是否优化。
- 本报告不保存实际上游地址、设备 hostname、MAC、租约或用户查询域名；没有添加新的常驻采集器。
