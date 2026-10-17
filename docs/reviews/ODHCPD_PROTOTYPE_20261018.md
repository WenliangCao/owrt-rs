# odhcpd-rs 首次完整隔离对照

共同检查 C/Rust 均 20/20，19 个收到的协议报文逐字节相同；同时发现两个尚待
修复的状态接口差异。旧 PD route 清理、拒绝越界 PD route 和 ubus 对象重连三项
明确增强均已实测。此轮不是最终部署或性能验收，没有访问物理路由器。

精确 C SHA `53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
Rust source `0fdd3ffa`，静态 AArch64 ELF SHA
`88bbcc6a93f8227bb67b214a3a757c360e133cef68afc4c12a7134876d2d5652`。
使用 [同一个夹具](../../tools/odhcpd_baseline.py) 和
[C 基线计划](ODHCPD_C_BASELINE_PLAN_20261018.md)，未改变 UCI、协议输入、
事件顺序或判断规则。原件 Oracle `/home/ubuntu/odhcpd-validation-20261018/`
下的 `c-baseline-06`、`prototype-01`、`prototype-02`；本地 ignored
`private/odhcpd-20261018/prototype-01/` 保存归档与双方 results.json。

## 仪器修正

`prototype-01` 在启动时 ENOENT，3秒内无首RA，立即停止。只读定位到提取的
squashfs `/dev` 只有 console，而生产启动会挂 devtmpfs；C 使用 getrandom
未触发缺陷，Rust 显式打开 `/dev/urandom`。在复制的私有 rootfs 内补上 null、
zero、random、urandom 字符节点后，重跑一次 C06 与同 ELF 的 Rust02。无产品
修改，失败轮保留且不作为性能样本。工具的超时清理使用 `unshare --kill-child`。

## 结果与两处差异

- 所有19条收到的 RA/DHCPv6 payload hex 完全相同，未归一化事务ID、寿命、
  地址或选项。共同20项包含前缀零寿命、时区、纯续租/PD不增加trigger等。
- C 在 ULA /62 绑定时额外安装超出 GUA /64 池的route；Rust没有该route。
  C 在前缀变更及Release后残留两条旧PD route；Rust均正确删除。
- ubus重启后 C 的 `dhcp` 对象消失，Rust恢复对象；两者RS仍有回复。本轮未
  证明恢复后每次provider dump/订阅的顺序，也未覆盖ubus断线期间的DHCP续期。
- **待修复：Decline 后 ubus 导出。** `released_state`、`after_hup`、
  `provider_recreated` 中，隔离的NA在两侧都有全零DUID、assigned=`0x9ed`、
  valid=3600。C 的 `ipv6-addr` 仍含两个当前地址，preferred=2700、valid=3600；
  Rust输出空数组。此差异不能被“共同检查全通过”掩盖。
- **待修复：daemon 重启后的导出时机。** 两者内存leases均为空，但C保留旧
  leasefile两行直到后续状态事件；Rust立即清空，并额外调用一次trigger
  （本序列累计C=7、Rust=8）。主线程决定这两处均按C修复。
- 其余文件差异是顺序运行导致的绝对expiry/time值；hosts与普通续租trigger一致。
  原始时间未删除，不能据此推断有限期限行为已经等价。

## 单次时间和同阶段内存

| 观测 | C | Rust |
|---|---:|---:|
| exec前到首主动RA | 1005.182 ms | 1004.608 ms |
| 首RS到RA | 0.210 ms | 0.160 ms |
| 首Solicit到Advertise | 0.664 ms | 0.140 ms |
| 首Request到Reply | 0.358 ms | 0.096 ms |
| 3NA+1PD VmRSS | 1112 KiB | 804 KiB |
| 同阶段RssAnon | 112 KiB | 92 KiB |

Rust RSS为C的72.3%，本序列内存满足两倍边界。时延只留作观测：尚无C/C噪声
标定，不据单点宣称最终“首包不慢”。没有热循环、PGO或性能选优。

复跑命令只改变 ELF 和全新输出目录：

```sh
sudo -n python3 tools/odhcpd_baseline.py \
  --rootfs /home/ubuntu/owrt-v023-20261017/private/native-final-0a925bcc/rootfs \
  --daemon /home/ubuntu/odhcpd-target-20261018/aarch64-unknown-linux-musl/release/odhcpd-rs \
  --out /home/ubuntu/odhcpd-validation-20261018/prototype-new
```

## 下一步固定验收计划（尚未实施）

成本模型仍是首主动RA的1秒timer、事件循环调度与包/文件操作；本轮主要降低了
协议集成的不确定性。下轮先验证两处状态差异的修复，然后把剩余风险压成同夹具
四个独立case，不能用正常NA路径替代边界：

1. 有限preferred/valid、所有PD池消失、Renew/Rebind旧前缀、Release/Decline后
   路由和导出；Confirm在链上/不在链上、未知绑定。每个动作记录包与内核状态。
2. LAN down/up、ifindex替换、link-local替换；PIO跨daemon重启、损坏/过期文件。
   验证旧socket不继续发包，旧PIO零寿命与新PIO有效性。
3. `add_lease`合法/非法输入、provider删除/重建与带计数dump、ubus断开期间
   RA和DHCP继续服务、重连后新对象/订阅/数据生效。乱序或旧dump不得覆盖新状态。
4. 未支持的NDP/relay/hybrid/有效DHCPv4在服务前明确拒启；本机maindhcp=0共享
   dhcpv4=server正常启动。畸形TLV、错误server-ID、单播/错误RS无状态污染。

每case新目录，输入/预期先写入工具，失败保留，只重跑受影响项。当前暂停扩展，
等待主线程分配，避免并行改同一工具。

正式时延/内存方法预案：先在目标环境以精确C做3组C/C成对冷启动，记录相同阶段
首主动RA、首RS、首DHCP回复的自身差值和范围；相同间隔、相同配置/地址、相同
事件顺序，不清全机cache或改governor。随后固定3组C/R成对启动，交替先后顺序，
不额外挑样。判断使用实际C/C波动范围和clock分辨率，不设固定微秒门；超出噪声
的变慢立即报告，落在噪声内写“本轮不可分辨”，不宣称测到改善。协议等待与包
处理等待分列。内存在0租约、3NA+1PD、前缀变更及ubus重连四个固定阶段读取
VmRSS/RssAnon，按相同阶段比较，门仍是Rust RSS不超过C的2倍。最终物理路由器
验证须另按项目恢复门授权；Oracle单点不代替该门。

### 扩展case冻结输入（实施前）

旧 `--case baseline` 为默认，保留其顺序与输入。新增四个case，每个用新的完整
namespace/rootfs目录；C一次按 finite→link→control→reject 收基线，候选等待新
ELF身份确认。正常单包等待3秒，预期忽略包等待0.3秒；每case上限180秒。共同
断言失败立即保留并停止该case；C已知增强缺口单列observations，不伪造共同通过。

- `finite`：GUA/ULA先设 preferred=30、valid=60；一包Rapid Commit绑定NA IAID11
  和PD IAID12，检查各返回可用资源且期限不超内核期限。Confirm在链上为Success，
  加一个不在链上地址为NotOnLink；Rebind保留租约；Release删除当前PD route；
  Decline隔离NA，后续新IAID不复用其IID。重新绑定NA+PD后把地址期限缩为1/3秒，
  Renew传播缩短，等待4.2秒。检查内核地址消失、没有旧前缀的正寿命PIO、无池
  NA/PD没有可用资源；记录到期导出和旧route差异，不要求C复制Rust的及时清理。
- `link`：先收到有效RA，再LAN down/up；重新赋相同地址后须恢复RS。删除veth、
  用同设备名/MAC重建（新ifindex），赋新GUA/ULA与link-local fe80::3，检查新
  RA源/PIO；随后link-local换为fe80::4，不能继续用旧源。停止daemon后分别给
  PIO文件写损坏JSON、已过期旧prefix，重启后须正常服务且不恢复过期PIO。
- `control`：用可计数provider；add_lease指定新DUID、hostid=abc、name=fixed9，
  验证实际NA分配与错误hostid返回。provider变更DNS并notify，DHCP信息回复须
  跟随；provider删除时协议继续，重建后再次notify要触发新dump与新DNS。ubus
  断线期间RS与DHCP继续；恢复后provider给第三个DNS，Rust须重新注册对象、
  订阅并使用该DNS（C的不重连作为已知差异）。不把对象存在代替数据更新证据。
- `reject`：独立启动maindhcp=1、RA relay/hybrid、DHCPv6 relay/hybrid、NDP relay、
  master=1七种配置；Rust须非零退出且没有存活的UDP547服务，C仅记录其支持
  行为。恢复实际maindhcp=0共享dhcpv4=server配置，启动服务。错误server-ID、
  截断外层TLV/短IA、错误RS hoplimit/code/零长option不得污染现有绑定或令进程
  崩溃；畸形包不要求复刻C未定义回复，合法后续请求须仍成功。

此批不加入额外性能样本或新门槛。延时3组C/C与3组C/R将另作固定隔离门，
不会从这些功能case挑选最快值；最终仍需路由器同namespace或离线隔离ELF测量。

finite再固定一个主循环顺序断言：Rapid PD IAID15的包实际发出后，客户端向
控制器确认sent，控制器立即add新GUA再del旧GUA；期间不发RS、不触发provider
reload。3秒内必须主动收到旧PIO零寿命及新PIO有效的RA。确认消息只用于控制
发送顺序，该事件的回复时间不进入性能样本。它针对PD route ACK后的dirty
snapshot吞掉地址变化、导致漏设1秒RA timer的风险。正式latency批次暂不实现，
由单独工具复用Fixture；本轮仅四组功能case。

扩展C首轮：finite的17个共同断言通过，含无需RS的主动withdraw。link在纯内核
ifindex替换时复现C继续向旧ifindex发送、3秒无RS响应；原件
`extended-c-01/link`保留。此项改列自动重绑增强，然后两侧均发送真实netifd
provider通知，检查共同恢复；不是延长等待或隐藏失败。后续只重跑link及尚未
执行的control/reject，finite不重复收数。

link的第二次受影响项运行也确认C缓存旧link-local源，替换地址后3秒无RS响应
（`extended-c-02-link`），因此同样分为纯kernel自动恢复增强与provider通知后
共同恢复两步。没有改变Rust必须自动跟随内核新ifindex/源地址的要求。

control首轮的非法hostid确已被C拒绝，但原夹具错误地把ubus协议状态2当作CLI
进程exit=2；精确镜像CLI实际exit=254并输出Invalid argument。只修正仪器为
检查非零exit与该错误文本，保存原件 `extended-c-01-control`，重跑control；
不把shell退出码声称为已读取的wire状态。

### 新候选回归与扩展结果

source `d0ef9f04`、ELF SHA
`05ce704460e9d10dd35edd56a01183b095380dc584b707110212b359175779e2` 的原baseline
回归20/20；19条协议包仍与C06逐字节一致。此前Decline的三个ubus快照已与C一致；
daemon重启后保持旧leasefile，trigger累计C/R均7，两个待修复项已关闭。

| 扩展case | C共同检查 | Rust共同＋增强 |
|---|---:|---:|
| finite | 17 | 18 |
| link | 10 | 12 |
| control | 11 | 14 |
| reject | 10 | 17 |

共48项共同要求与13项增强，Rust已执行61/61。另对同一批已保存包离线检查两个
活跃PD不重叠，C/R均通过；该断言已加入工具供后续SDK复用，没有新增样本。
旧baseline默认入口仍可重放，扩展入口为 `--case extended`，各子case使用独立
目录，也可用 `--case finite|link|control|reject` 只重跑受影响项。Fixture仍可
被独立latency工具import并控制setup/sequence。

原件归档到 ignored `private/odhcpd-20261018/extended/observations.tar.gz`。
最终C输入分别是 `extended-c-01/finite`、`extended-c-03-link`、
`extended-c-02-control`、`extended-c-01-reject`；Rust为`extended-rust-01/`。
失败的C前置观察也完整保留。扩展不是全报文等价，差异明确如下：

- **已接受的Release分配时机差异。** C Release将槽位标为到期，下一次秒级清理
  前仍占用子网4；立即绑定IAID14得到8，IAID15得到c。Rust已撤销Release绑定和
  route，因此立即复用4，后一个得到8。两侧当前活跃PD均无重叠，Release后
  当前route均已删。主线程决定保留这一差异，不为C不足1秒的占位引入额外层。
- **有限期限的采样相位。** preferred=1、valid=3的单点，C已把对应旧IA返回0；
  Rust仍返回剩余1/3。两者都不超过设置的期限，随后内核地址到期、RA不再广告
  正寿命旧PIO、无池回复NoAddrsAvail/NoPrefixAvail。原始整数秒值完整保留；
  不归一化成相同，不因该单点再加轮。Rust到期后无旧PD route，C仍残留。
- **主动安全拒绝。** 短IA/截断TLV时C忽略坏选项并发送无IA Advertise，Rust拒绝
  整包。两者已有绑定未改变，随后合法Renew成功。错误server-ID和三类坏RS
  均被忽略；七种未支持配置Rust全部非零退出且无存活UDP547服务。
- **内核生命周期增强。** C换ifindex/link-local后需provider通知才恢复；Rust
  在该通知前已使用新接口/源地址。损坏和过期PIO文件均不阻止服务、不恢复坏项。
- **ubus恢复增强。** provider通知的dump计数确实增加，DNS变更通过DHCP包验证；
  provider/ubus不存在期间RA和DHCP仍服务。ubus重启后Rust恢复对象、取得新dump，
  包中DNS从`::54`变为`::55`；C保留`::54`且对象未恢复。

本轮没有正式latency批次，也未接触router。产品冻结该SHA；后续SDK沿用受影响
功能门，时间/内存隔离门由独立工具按既定C/C噪声计划执行。
