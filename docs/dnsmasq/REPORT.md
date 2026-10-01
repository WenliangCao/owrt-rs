# dnsmasq-rs 重写与优化记录

当前状态：进行中。DNS UDP/TCP、hosts/cache SIGHUP、DHCP 动态 context/租期/ICMP/ARP 和 TFTP 独立 TID/单端口/端口范围正在完成服务接线与分项 C 差分；完整功能、性能资源和生产验收均未关闭。阶段成果不等于完成替换。

## 最新状态（恢复会话后核对）

下表是当前进度；后文注明旧冻结源码的构建和检查仅是历史证据。
当前分工、源身份和未完成合同见 [续作检查点](CONTINUATION_20261001.md)。

| 工作 | 已验证结果 | 尚未关闭 |
|---|---|---|
| 主程序 UBus/metrics/doctor/DHCP 通知 | `9910009` 已接线；native C 68/69 配对观察一致 | TCP 父缓存少一次真实插入；不能修饰计数让测试通过 |
| 有序缓存事务 | `69f24bb`、`7b55df8`：471 操作、真实 UDP 42 场景/210 回复一致 | 完整缓存资格、PTR、TCP、EDNS/DNSSEC metadata |
| 普通空 OPT 冷缓存 | `377c8a1`：32 场景/64 回复一致；8 组合/重试场景一致 | option-bearing、versioned、signed、DO/AD/CD 等完整合同 |
| DHCP reverse-host 启动/HUP | `5831e97`：87/87 检查，14 快照等于冻结 C；ACK/INFORM 28/28 | 缺省地址推导、tags/全部 options、PXE/relay/helper |
| 上游初次 socket/send 失败与 TCP 接纳 | `630addb`、`bb1a664`、`cef8001`：资源失败 61/61、监听恢复 17/17、共享连接上限 31/31；负控均检出 | 瞬态重试、缓存回写/pipe 生命周期另验 |
| 后续功能与组合回归 | UDP 瞬态重试 helper53/53、服务61/61；DHCP hosts 地址27/27；组合快照8c34170库381/main6、DHCP→DNS34/34 | 15个ignored未计通过；普通DO/AD/CD的native/image750/750；完整元数据及DO查询的LRU副作用另验 |
| 普通 CD 缓存事务 | `3e3e203`/`0c8f362`：native/image134/134；只抑制最终commit，保留有序移除/淘汰/pending清理 | 原136行image C校准失败保留；完整no_cache触发配置另验 |
| DO 查询缓存副作用 | `aeba67e`：native/image压力门由112/120到120/120，负控119/1；同ELF保留native/imageDO750、nativeCD134，隔离389库+7主程序，native/musl Clippy | generic/NX顺序、RR旋转与hash桶清理另验；见[修复回归](DO_LOOKUP_FIX_VALIDATION.md) |
| 普通 miss 的通用记录查找 | `5c15e16`：独立NX/SOA门从原108/120、DO修复后116/120到native/image各120/120；保留原direct/CNAME门各120/120；最终隔离389+7/16ignored及native/musl Clippy | 全部no-answer路径、旋转与桶清理另验 |
| 通用记录配置与缓存 | `4bf072d`：native/image各22配置+78正向配对，独立QTYPE0各9；最终`ac8a3b6`保留native22+78 | reverse9仍仅C；首次image启动readiness失败保留；泛型DO/AD及完整类型合同未关闭 |
| 畸形通用记录错误回复 | `ac8a3b6`：native/image各35/35，修复前各14差异；保留有序prefix副作用，负控34/1；policy210、bogus256、隔离389+7/16ignored、native/muslClippy通过 | 超大RDATA表示限制与任意畸形输入另验；见[实现回归](GENERIC_MALFORMED_IMPLEMENTATION_VALIDATION.md) |
| 私有反向 PTR 缓存 | `deab8a0` primitive125/125；`62894d6`真实UDP native/image各124/124，before33差异，负控123/1；共享容量/LRU并保留target大小写 | 未合产品；多target顺序和资源门未关闭，后续边界见以下三行 |
| 反向记录 typed transfer | `54346fd`修复配置CNAME错误阻断导入；184/184确定观察，原forward307保留 | 另12条多PTR顺序观察仍有native4/SDK2差异，完整比较器exit1；见[结果](REVERSE_TRANSFER_AFTER_RESULT.md) |
| 真实DHCP与动态PTR共存 | native/image C各62/62；Rust62894完成54，40相同/14差异 | `dhcp-fqdn`启动拒绝，另8未执行；time0归属、本地+动态回答及FQDN接线修复进行中；见[修复前结果](REVERSE_LEASE_SERVICE_RESULT.md) |
| 同名正向操作清理过期PTR | 独立C27/27，Rust54346fd21/27，0实验失败；只读存在性与live共存对照通过 | RD0/RD1查询和插入各留2差异，共6；见[修复前结果](REVERSE_NAME_EXPIRY_BEFORE_RESULT.md) |
| TCP 缓存 | typed transfer原语307/307已合入；私有stream参考TCP32、native UBus69/69、并发12、stale41、CD65、partialEOF27；native/musl transfer各307 | 私有代码未合入；快照表示、OOM/大记录/native管道饱和及全部策略组合仍未验收 |
| 最新目标阶段 | 冻结 `405b7c1`，ELF 1,178,407 B，APK 622,772 B；匹配 SDK/镜像依赖 | 完整目标 UBus 67/69，保留两项失败；不是替换包或生产验收 |

目标 UBus 的两个差异分别是 TCP 父缓存写回缺口，以及目标 musl C doctor
失败解析时原地改坏地址。后者按参考差异保留，不在 Rust 中制造错误地址，
也不从完整门的分母删掉。证据见 [目标阶段报告](PACKAGE_405B7C1_RESULT.md)。
Rust ELF 比精确目标 C 的 269,305 B 增加 **909,102 B（337.6%）**，资源门未过。

最新组合边界：`DNS_BOGUS_CACHE_PHASE.md` 的独立 bogus 事务在 CD 下保持
native/image **256/256**，正常 DO 门仍 **750/750**。普通 CD/no-cache 只阻止
最终 commit、仍保留中间替换/淘汰副作用的 C 合同已通过独立 native/image
**134/134** 门，见 [普通 CD 实现报告](DNS_CD_COMMIT_PHASE.md)。
`TCP_PRIVATE_REFERENCE_RESULT.md` 记录完整私有参考分支及限制，不能把其
通过的服务门当成共享产品已提供 TCP 缓存或资源门已通过。
后续 [stale TCP](TCP_STALE_REFERENCE_RESULT.md) 和
[TCP CD／策略](TCP_CD_POLICY_REFERENCE_RESULT.md) 分别通过41/41和65/65；
两者使用同一私有ELF，覆盖范围没有扩大为产品或完整资源验收。

## 固定身份

目标为 AX3000T、OpenWrt 25.12.5、九组件 Rust 原生镜像，dnsmasq 仍为 C 2.93-r1
普通 nodhcpv6 变体。启动核验使用现有同日源与部署证据，没有访问或修改物理设备。
`private/native-deploy-20260929/native-identity.json` 记录九个 ROM 原生路径已验证、无
可执行文件 bind mount；`live-image-verified.json` 记录 164 个包版本及 910 个 ROM
普通文件与 canonical 一致。镜像 SHA256 为
`144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720`。

精确配方为 OpenWrt `f0a60eee2fe051741c643ea6118718aae1ef17fb`，归档 SHA256
`0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19`。
`tools/dnsmasq/prepare_reference.py` 由版本清单逐一核验配方 13 文件，重新解包并应用
两份 OpenWrt 补丁，保存完整 patched source 哈希。复跑检查漂移，不覆盖输入。

编译选项：IPv6、UBus、DHCPv4、TFTP、loop-detect、inotify、dumpfile；无 DHCPv6、
DNSSEC 验证、DBus、Lua、conntrack、ipset、nftset、权威 DNS、IDN、i18n。
BOOTP/PXE、DHCP relay/leasequery、AD 透传、可启用的 DNS 订阅也必须完成；不能用
当前配置未启用来裁剪。odhcpd/odhcp6c、内核和驱动的职责不变。

## 阶段与验收

| 阶段 | 当前状态 | 通过条件 |
|---|---|---|
| 身份与 C 参考 | 进行中 | 精确源码、选项、依赖、可重建参考和测试器校准 |
| DNS | 进行中 | 本地/路由/UDP上游、CNAME与负缓存子集、SOA authority、SIGHUP hosts/cache、TCP传输与拒绝路径已有分项C门；完整cacheability/EDNS metadata、TCP cache继承写回、动态resolver与完整配置仍待完成；doctor/ubus实际接线已完成但差异门未全过 |
| DHCPv4 | 进行中 | 配置/context/状态/reply/ICMP/ARP、普通static/FQDN、leasefile/到期和同步DNS已有分项真实C门；tags/全部options、relay/PXE/leasequery/helper/hotplug仍待完成 |
| TFTP 等可用能力 | 进行中 | 文件/权限、错误码、TID、窗口、重试/超时/清理、single-port、端口范围已有C服务门；helper/PXE、全部interface/source pktinfo、广义压力与长期增长门待完成，C缺陷差异未抹去 |
| OpenWrt 集成 | 进行中 | 全配置、UCI/procd/ujail、ubus/ACL、reload、调用方和默认权限生命周期仍未关闭 |
| 优化 | 未证明收益 | 正确性通过，冻结工作负载，逐轮成本与资源证据 |
| 目标构建/打包 | 阶段快照已过 | 最新冻结产品 `405b7c1` 已用匹配SDK构建并核验 inert APK，见 `PACKAGE_405B7C1_RESULT.md`；UBus完整门保留两项差异。后续缓存/租约/失败修复未进入该产物 |
| 真机验收 | 未执行 | 单独授权、恢复门、目标环境测量 |

具体源码映射分文件记录。所有原始报文、配置、地址、租约、ELF 和测量记录放
`private/dnsmasq-rewrite/`。用户现有的 prompt 修改保持原样。产品代码不调用 C
参考、不使用 DNS/DHCP C FFI；C 仅用于隔离测试 oracle。

## 证据目录

- `private/network-research-20260929/dns/`：此前已核对的精确输入。
- `private/dnsmasq-rewrite/reference/identity.json`：本次重建的精确源码身份。
- `private/dnsmasq-rewrite/local-c-audit-20260930/answer-rust-final.json`：108 个本地回答 C/Rust 语义 case，0 mismatch；`class-rust-final.json`：9 个非 IN class case，0 mismatch。
- `private/dnsmasq-rewrite/local-c-audit-20260930/routing-review/rust-results/`：10 组路由配置、240 个 case，0 mismatch。
- `private/dnsmasq-rewrite/tftp-service-diff/result.json`：C path/admission oracle 255,528 + 20,000 cases，0 unexpected mismatch；2,408 个显式 `..` hardening differences。
- `private/dnsmasq-rewrite/dhcp-reply-diff/result.json`：hash-pinned `rfc2131.c` reply wire oracle 1,008 cases，0 mismatch，覆盖 primary/file/sname overload、PRL、OFFER/ACK/INFORM/NAK、option 57 capacity 与 broken-string workaround。
- 后续构建、差分、fuzz、基准逐轮追加；未运行项目不计作通过。DNS reply envelope 的 1,537 个结构有效包/19,981 条命令、address policy 的 68 个 ASan/UBSan C/Rust case、negative/cache-reply 的 10 个边界测试和 upstream transport 的 loopback 测试详见各阶段文件。

旧版源码门与早期 smoke 属于历史快照，不能覆盖后续改动。已冻结574f5ed的组合门：host库276通过/5 ignored、main6通过；host与aarch64-musl
all-targets Clippy、fmt、195/169入口索引通过。Linux同快照库278通过/13 ignored、
main6通过；另显式跑4个精确C配置及8个Linux隔离ignored，12个均通过。
专用cache-oracle driver仅按其自带corpus门计数，不能从ignored推算通过。各功能阶段的独立 C 门和原始
失败轮次见下表。旧 local oracle 编译宏不完整的身份已退役：共享 builder 现强制
匹配目标六个 COPTS、原始 config.h 与 Linux ELF 对象；旧报告未保留输入的
部分用新归档语料重建，不假称逐字重跑了原始输入。

## 2026-10-01 续作证据

| 功能/问题 | 本轮证据 | 明确边界 |
|---|---|---|
| 参考身份与测试器 | `REFERENCE_AUDIT.md`；148 source/42 objects/匹配 ubus/libubox；正常12/0与注入失败11/1 | native C 身份，不是目标性能 |
| 本地 DNS 重新资格核验 | `local_answer_recheck.py`；357/357，新完整 query/C/Rust/manifest 在 `private/dnsmasq-rewrite/local-requalified-20261001/` | 新重建语料；历史全 NONE 组的原名字未保存 |
| CNAME/负缓存/回答长度 | `DNS_CACHE_REPLY_PHASE.md`；新 builder 205 commands/149 queries、0差异 | 修复 A NODATA误答AAAA、错误TC、CNAME flags及RR轮转；完整cache仍未关闭 |
| SIGHUP hosts与cache | `DNS_RELOAD_PHASE.md`；23/23；EINTR导致UDP worker退出的失败轮次保留 | resolver、DHCP脚本/metrics和完整reload仍未关闭 |
| TCP 上游 | `DNS_TCP_UPSTREAM_PHASE.md`；20场景25query，18场景完全相同，2项C错误长度重试差异单列 | 不把差异算0；cache父子同步及完整caller另验 |
| TCP 主程序 | `dns_tcp_daemon_diff.py`；15/15场景、116回复，原始证据 `private/dnsmasq-rewrite/tcp-main-20261001/` | 相同cache-size=0；分片、帧顺序、100次限额、拒绝码、upstream复用；不是完整TCP cache等价 |
| DHCP 目的地址/名字 | `DHCP_RUNTIME_PHASE.md`；目的地址3648/3648；配置名字不能被动态客户端夺取 | 原语/状态回归，不代替完整daemon差分 |
| DHCP 配置/context | `DHCP_CONFIG_PHASE.md`、`DHCP_CONTEXT_PHASE.md`；84配置合同匹配+6明确缺口；145场景402步context一致 | static/tag/proxy/relay等未实现项不计等价 |
| DHCP timers/冲突/ARP | `DHCP_REPLY_PHASE.md` 1284/1284；`DHCP_PROBE_PHASE.md` 67647/67647及Linux92/92；ARP定义字段1045/1045及Linux88/88 | ICMP失败停止分配为显式C差异；真实leasefile/DNS/hotplug尚未接完 |
| DHCP daemon组合 | `DHCP_DAEMON_PHASE.md`；广播DORA子集/INFORM/CS6/独占/回收5/5，失败注入校准有效 | 是Rust smoke；不能冒充完整C/Rust服务差分 |
| TFTP 服务 | `TFTP_LISTENER_PHASE.md`、`TFTP_SINGLE_PORT_PHASE.md`、`TFTP_PORT_RANGE_PHASE.md`；192项含12项明确C缺陷差异，0未预期差异；真实超时另18项一致 | 无helper/PXE完整集成或生产验收 |
| 目标包/身份 | `PACKAGE_574F5ED_RESULT.md`；产品574f5ed冻结，匹配SDK，原recipe恢复，77个输入逐项核验 | 阶段inert产物；未做正式替换/镜像装配/生产验收 |

明确记录的参考问题包括：SRV 无 SOA NODATA 栈未初始化读取（3个Valgrind
正常对照无错、最小触发例1错）、TFTP single-port错误旧DATA及文件FD泄漏、
TCP失败重试前缀被上次回复长度覆盖。Rust没有为模拟这些错误而引入错误答案或
泄漏；差异的兼容验收口径仍单独列明，不自动豁免或宣称完全等价。TCP旧OPT状态
跨query继承也已记录为待决会话差异。

资源成本同样保留：ICMP probe Rust比C多1个持久entropy FD；DHCP入口另保留
一个ioctl control socket且每请求重新枚举接口；TFTP端口范围目前每次占用
候选会重建socket而C复用一个。以上没有测量为收益，不能声称优化任务完成。

## 持续接线：共享状态、租约与文件重载

后续源码已经超过上述SDK快照；旧APK不包含这些新单元。

- `DNS_SHARED_STATE_PHASE.md`：单一parent forward cache/table，多UDP监听共用
  配置容量，合并回复保留原listener；真实C门从1匹配/7差异到8/8匹配。
- `DNS_LOCAL_EDNS_PHASE.md`、`DNS_HOSTS_GENERATION_PHASE.md`：按C的UDP限额、
  OPT追加/DO、完整截断语义、配置前缀/hosts/PTR所有权和共享轮转修复。后续
  本地584包、hosts204步及wire76213项通过；初始ASLR相关RR排列只作为固定seed，
  此后使用实际C轮转规则，不逐回复排序。
- `DHCP_PERSISTENCE_PHASE.md`：持有inode、flush/fsync成功才清dirty，失败仍ACK；
  实际生命周期114项、磁盘满后60秒idle重试38项通过。
- `DHCP_STATIC_PHASE.md`：普通CLID/MAC静态规则与名字/options12/15/81，真实
  服务208项、恢复FQDN20项通过；配置86项匹配，8项未支持边界不计等价。
- `DHCP_DNS_INTEGRATION_PHASE.md`：ACK前同步专用DHCP来源发布；初轮30事件及
  扩展34事件全部匹配。包括预缓存替换、保留已有name-wide NXDOMAIN、A/FQDN/
  PTR/CNAME、TCP、父域、renew/restart/release和无流量到期。注错校准29匹配/
  1差异正确失败；没有用等待发布的轮询掩盖ACK时序。
- `DHCP_HOST_FILES_PHASE.md`：普通hostsfile的20次源码合同重读及真实HUP/
  文件/DHCP/DNS组合41项通过；故意错flag为40/1，Unsupported动态选择器暂停/
  恢复另为Rust边界11/0，不冒充与C等价。hostsdir/inotify/tag等仍关闭。
- `LEASE_NAMES_PHASE.md`、`DNS_LEASE_CACHE_PHASE.md`：专用expiry/TTL/PTR、
  hosts优先、selfmx和每个TCP reader的过期删除已接。时钟回拨时C同hash桶的
  无关记录附带删除仍有明确红例；publication失效不等于插入时local阻挡。
  晚到上游回复的local阻挡和安全CNAME本地目标已接；36场景/269观察/95查询中，
  32普通场景无差异，4个C对象复用场景仍有2个参考缺陷差异，完整门保持非零退出。
  不把后者消去后称为完整等价。

UBus真实C合同256/256、独立Rust controller83/83及doctor473/474已有归档；
doctor剩余1项为C接收缓存指针生命周期缺陷，负对照472/474正确失败。
此历史 standalone 阶段之后，`9910009` 已连接真实主程序 counter、doctor 和通知；其服务门仍保留 TCP 父缓存写回差异。
UCI/procd/ujail/ACL/metrics完整事件与权限仍不能由这里的协议门推导为通过。

`DNS_UDP_FAILURE_PHASE.md`：单个completion/recipient失败不再吞掉同批成功回答，
保留有界累计诊断；精确C状态1271步、真实UDP84/84及故意恢复整批丢失的负对照
已通过。`DNS_UDP_ADMISSION_PHASE.md`：接纳/错误helper35项，实际服务40个输入/
43个观察均匹配，包括丢弃、错误码/OPT/DO、满表后恢复；11秒回复/41秒迟到丢弃/
42秒新查询的实际窗口也通过。此前 C 延迟回收与 Rust 主动释放的差异已由 `ad7e2a7` 的 wallclock/按事件
生命周期接线修复；精确 forward 状态与计数 1,285 项通过，不据此声称资源收益。
重复client容量达到上限时，C会以stash ID/question错误拒绝第三client，另有明确
参考缺陷记录，不能把这个ID差异归一化或把Rust当前drop叫作等价。

`METRICS_SOURCE_MAP.md`索引全部30个counter的源写点和reset窗口。
`METRICS_LEASE_PHASE.md`：真实分配/删除（含恢复zero-address到prune6分支）
47场景/3764观察匹配，负对照3763/1；`METRICS_CACHE_PHASE.md`：缓存提交/
压力回收/失败/reload的25场景215快照匹配，C每轮重复3次，负对照214/1。
缓存Daemon接线进一步通过764观察（164查询、382计数快照），负对照763/1。
主程序消息/forward/lease/cache 的实际 owner 已接入 UBus；TCP 父缓存写回仍未关闭。

冻结产品`2415216`的本轮检查：host库328通过/6 ignored、main6通过，Linux库
331通过/14 ignored，真实共享状态8/8、DHCP/DNS34/34；fmt和musl all-targets
Clippy通过。该快照的native ELF SHA256为
`1334f0dfbd9af3a38279a0fb69199be8193f7b5a3e710787a48fb33b37d786be`；
原始日志在`private/dnsmasq-rewrite/integration-20261001/`。没有重复跑仍有效的
port=0旧门，也没有把ignored计为通过或把此host产物叫作目标APK。

`DNS_STALE_REFRESH_PHASE.md` 保留原 stale 后台刷新缺口的 44 比较/13 差异。
`9f32047` 已修复，最终 48/48 服务门包括先发旧回复、再启动刷新次序，
source-bound metadata 1,100/1,100；原先错误的分母和提前发送失败轮次仍保留。
这是已测 stale 边界，不能扩大为全部 EDNS/cache metadata 已实现。

## C 成本基线与优化候选

[C_COST_RESULT.md](C_COST_RESULT.md) 固定保留9个C窗口、660000个正确完成请求、
零错误/超时和3个独立profile。主机CPU/完成请求：hot39.10–40.65µs，mixed
47.69–48.36µs，TCP228.53–230.66µs（计入子进程）。逐轮p50/p95/p99、USS/PSS/
RSS/FD/线程/子进程采样、工具和上游分账、遗漏边界及原始hash索引全部在该报告。
这不是Rust配对收益、饱和吞吐或路由器性能证据。

原C满缓存插入的全表过期扫描在mixed/TCP profile的self cycles分别为11.07%/
21.54%；当前Rust也有该扫描。[CACHE_EXPIRY_SCREEN_V1.md](CACHE_EXPIRY_SCREEN_V1.md)
冻结仅增一个保守最早expiry下界的EPS1候选，跳过确定无过期记录的扫描，必要时
仍按原顺序回收。private候选与B0的37场景26992命令、旧22571原语与1876发布
操作均匹配C；已知CNAME参考差异在两者保留。默认缓存实现未替换。`CACHE_EXPIRY_SCREEN_RESULT.md` 已有冻结的私有原语
24 窗口结果，counted API rebase 仅有正确性；不能推广为当前服务或相对 C 收益。

[DYN1_RESULT.md](DYN1_RESULT.md) 的固定旧产品候选仅改变动态musl/PIE链接，
ELF从989991B降为870915B（少119076B，12.03%），保护/依赖及冻结功能门通过。
默认配方未采用；仍比目标C大601610B，且没有CPU/吞吐/内存收益结论。这一候选
不覆盖后续源码，也不豁免整体体积退步。

[TCP_SNAPSHOT_SCREEN_RESULT.md](TCP_SNAPSHOT_SCREEN_RESULT.md) 完成原冻结的
48 个主机原语计时窗口，24,000 次操作全部成功，无额外轮次。shared 在容量
1,000/10,000 时 CPU/完成分别下降 48.67%/29.84%、快照请求堆下降
49.20%/52.34%；但填充 CPU 的最差配对退步达 13.71%，超过原定 5% 门槛。
三个候选均未获接受，产品缓存布局未改；不挑选较快窗口或放宽门槛。
这些数据不等于相对 C、完整服务或路由器收益。

[TCP_SNAPSHOT_CHUNK_RESULT.md](TCP_SNAPSHOT_CHUNK_RESULT.md) 的独立24窗口
按块共享候选同样未被采用：12,000操作无错，但填充CPU和150满缓存p95
未达到冻结门槛。当前产品仍未选择新的TCP快照表示。

[TCP_SNAPSHOT_INLINE16_RESULT.md](TCP_SNAPSHOT_INLINE16_RESULT.md) 保留新候选的
24个窗口、12,000次无错完成。大容量CPU减少47.39%/27.85%、快照堆减少
49.20%/52.34%，填充CPU和稳态堆均通过冻结门；但150满缓存第一配对的p95
增加8.63%，超过5%上限，候选被拒绝。没有追加轮次、挑选窗口或产品布局变更。

[单记录索引候选](TCP_SNAPSHOT_ONE_INDEX_RESULT.md) 的另24窗口/12,000次完成也
全部正确，但三个满载档的最差填充CPU分别增加50.40%/5.40%/5.10%，均超过5%
门槛，候选同样拒绝。大容量快照CPU减少66.60%/54.60%、快照堆减少51.59%/54.88%
不能抵消该失败。两机制的组合目前只有[源码成本审计](TCP_SNAPSHOT_COMPOSITION_REVIEW.md)，
尚未实现或测量，不得把两个失败候选各自较好的结果拼接成一次通过。

## 历史 574f5ed 目标产物与资源退步

`PACKAGE_574F5ED_RESULT.md` 记录完整身份。最终阶段APK为 **520,797 B**，
SHA256 `2c1ae3a6cb04bf9ed190422c7ec5d57b42eefe7c99377143c8a07702073f75a5`；
Rust ELF为 **989,991 B**，SHA256
`e88fc9131b8321fef7d913fd052ec7ce06af5eebddb38f41621b3d1478f8090e`。
仅安装 `/usr/libexec/dnsmasq-rs`，没有改stock binary/init/UCI。

精确镜像target C ELF为 **269,305 B**（SHA256
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`），
Rust本体增加 **720,686 B / 267.6%**。这是未关闭的资源验收问题，不能因staging
而豁免。C动态依赖的816,407 B由其他平台组件共享，不能当作Rust独占节省空间；
Rust当前是static ELF，静态/动态成本必须分开解释和测量。

在aarch64构建机私有namespace直接执行target-musl C（连同镜像四个匹配库）和
SDK Rust产物：UDP REFUSED **558/558**、TCP **15场景/116回复**、reload
**23**、TCP跨SIGHUP **8查询+2次退出**均匹配；另4项C配置用target-musl
parser/getopt重跑通过。DHCP **5/5**仅是Rust target smoke，没有冒充完整C
service differential。最初native-glibc C对target Rust的跨ABI轮次与后续target
artifact轮次分开保存。

两次构建和181条最终SDK既有/环境warning全部保留。产品源未变但输出目录/工具
变化时ELF/APK hash不同，尚未建立跨目录bit-reproducibility；不靠反复重构掩盖。
这些证据不涉及模拟器内OpenWrt kernel/procd/jail，也不涉及物理路由器或路由器性能。

## 已冻结的局部性能证据

TFTP netascii correctness gate `tftp-oracle-07` 使用当前 C/Rust 源码、97,384 个
case、ASan/UBSan C driver，0 mismatch。随后按 `PERFORMANCE_PROTOCOL.md` 固定的
512/1468/4092 字节、普通/每 80 字节 LF/全 LF 三种输入，C/Rust 交错五轮、每组
1,000,000 次运行；原始窗口在 ignored `private/dnsmasq-rewrite/tftp-bench-03/`。
CPU 比值 Rust/C 的五轮中位数为：普通输入 0.995–1.014、每 80 字节 LF
1.003–1.019、全 LF 0.102–0.387（块越大收益越明显）。这只证明 netascii 热点的
局部主机筛选结果；没有 DNS/DHCP 吞吐、尾延迟、RSS/PSS、目标路由器或端到端收益
结论。

## 下一步

继续关闭完整 cache/TCP/resolver/接口与配置、DHCP tags/全部 options/relay/PXE/helper、其余 TFTP 和 OpenWrt 服务合同。保持实际事件计数，先修复 TCP 写回及资源失败边界；EPS1 和快照候选按冻结门推进，最终再出真正替换包。
保持功能等价和优化目标两条验收线；当前有可运行的受限DNS/DHCP/TFTP开发路径和已验证身份的inert SDK阶段包，仍无可替换生产dnsmasq的完整兼容package。
