# dnsmasq-rs 重写与优化记录

当前状态：进行中。DNS UDP/TCP、hosts/cache SIGHUP、DHCP 动态 context/租期/ICMP/ARP 和 TFTP 独立 TID/单端口/端口范围正在完成服务接线与分项 C 差分；完整功能、性能资源和生产验收均未关闭。阶段成果不等于完成替换。

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
| DNS | 进行中 | 本地/路由/UDP上游、CNAME与负缓存子集、SOA authority、SIGHUP hosts/cache、TCP传输与拒绝路径已有分项C门；完整cacheability/EDNS metadata、TCP cache继承写回、动态resolver、doctor/ubus与完整配置仍待完成 |
| DHCPv4 | 进行中 | 配置/context/状态/reply/ICMP/ARP和真实listener已接；完整leasefile/到期/DNS发布、static/tag/FQDN、relay/PXE/leasequery/hotplug仍待完成 |
| TFTP 等可用能力 | 进行中 | 文件/权限、错误码、TID、窗口、重试/超时/清理、single-port、端口范围已有C服务门；helper/PXE、全部interface/source pktinfo、广义压力与长期增长门待完成，C缺陷差异未抹去 |
| OpenWrt 集成 | 进行中 | 全配置、UCI/procd/ujail、ubus/ACL、reload、调用方和默认权限生命周期仍未关闭 |
| 优化 | 未证明收益 | 正确性通过，冻结工作负载，逐轮成本与资源证据 |
| 目标构建/打包 | 阶段快照已过 | 冻结产品 `574f5ed` + 工具修复已用匹配SDK构建并核验 inert APK；target C/Rust 关键服务门通过，见 `PACKAGE_574F5ED_RESULT.md`。仍非替换包，当前后续EDNS/leasefile改动不在该冻结产物内 |
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
  晚到上游回复在租约发布后能否缓存，以及CNAME→本地记录目标，是当前正在关闭
  的实际功能门，不计入已通过范围。

UBus真实C合同门和独立Rustcontroller进行中，未连接真实主程序counter或DNS doctor。
UCI/procd/ujail/ACL/metrics完整事件与权限仍不能由这里的协议门推导为通过。

## C 成本基线与优化候选

[C_COST_RESULT.md](C_COST_RESULT.md) 固定保留9个C窗口、660000个正确完成请求、
零错误/超时和3个独立profile。主机CPU/完成请求：hot39.10–40.65µs，mixed
47.69–48.36µs，TCP228.53–230.66µs（计入子进程）。逐轮p50/p95/p99、USS/PSS/
RSS/FD/线程/子进程采样、工具和上游分账、遗漏边界及原始hash索引全部在该报告。
这不是Rust配对收益、饱和吞吐或路由器性能证据。

原C满缓存插入的全表过期扫描在mixed/TCP profile的self cycles分别为11.07%/
21.54%；当前Rust也有该扫描。[CACHE_EXPIRY_SCREEN_V1.md](CACHE_EXPIRY_SCREEN_V1.md)
冻结仅增一个保守最早expiry下界的EPS1候选，跳过确定无过期记录的扫描，必要时
仍按原顺序回收。37场景26992命令的压力C/C和C/Rust基线匹配，尚无候选实现或
计时收益，不能把算法计划当成优化完成。

[DYN1_RESULT.md](DYN1_RESULT.md) 的固定旧产品候选仅改变动态musl/PIE链接，
ELF从989991B降为870915B（少119076B，12.03%），保护/依赖及冻结功能门通过。
默认配方未采用；仍比目标C大601610B，且没有CPU/吞吐/内存收益结论。这一候选
不覆盖后续源码，也不豁免整体体积退步。

## 目标产物与资源退步

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

继续关闭本地DNS EDNS/顺序、完整cache与配置，以及DHCP leasefile/周期到期/DNS同步、其余TFTP和OpenWrt服务合同。C成本诊断按独立冻结计划进行；配对优化与资源门随后推进，最终再出真正替换包。
保持功能等价和优化目标两条验收线；当前有可运行的受限DNS/DHCP/TFTP开发路径和已验证身份的inert SDK阶段包，仍无可替换生产dnsmasq的完整兼容package。
