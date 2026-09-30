# DHCPv4：源码合同与阶段证据

本文件记录重写过程，不是功能等价或生产验收声明。参考树是 ignored
`private/network-research-20260929/dns/dnsmasq-2.93-openwrt/src/`，对应
AX3000T / OpenWrt 25.12.5 / dnsmasq 2.93-r1 普通 nodhcpv6 变体。
DHCPv4、BOOTP、PXE、TFTP 均属于目标合同；DHCPv6/RA 保留 odhcpd 职责。

## 已读调用链和状态所有权

`dhcp.c:130-530 dhcp_packet()` 读取数据及接收接口 → 接口/bridge/relay
筛选 → `lease_prune(NULL, now)` → `rfc2131.c:75 dhcp_reply()` →
`lease_update_file()` → `lease_update_dns()` → 选择 relay、ciaddr、广播或
ARP 辅助单播目的地并发送。即使 reply 长度为零，前面的租约副作用仍然提交。
因此网络发送成功与否不能决定是否提交已经生效的租约。

`dhcp_reply()` 的配置/身份/标签/上下文解析在消息分支之前；不能只凭
message-type 决定同一个包属于哪个地址池。DISCOVER/OFFER 通常不分配租约；
REQUEST 成功、rapid commit 与 BOOTP 才提交。失败的 REQUEST 在部分分支会
先删除旧地址租约，然后 NAK 或放弃；这不是可随意改成事务回滚的行为。

活动租约归 C 的 `leases` 链表所有。新分配在链首；CLID 相同或 MAC 回退
命中多个记录时，先找到的最新记录获胜。prune 把移除项依次插入
`old_leases` 链首，等待脚本，不能在移出活动索引后丢失删除事件。
expiry=0 表示无限租约，其他 expiry 在 `now >= expiry` 时到期。

## 已实现与对应验证

| C 位置 | 行为 / 不变量 | Rust | 对照与阶段状态 |
|---|---|---|---|
| `dhcp.c:173-177`; `rfc2131.c:117-156` | 固定头至少 236 字节；BOOTREQUEST；hlen≤16；htype=0 要求 hlen=0；只有含有效 option 53 时要求 cookie；DISCOVER/option 50 清 ciaddr | `dhcp/packet.rs::Packet` + `dhcp/service.rs::dispatch_poll` | 单测；`receive_once`/`poll_once` 已提供 Linux pktinfo admission，完整事件循环仍未接线 |
| `dhcp.c:40-177,248-373`; `rfc2131.c:564-697,877-1055,1066-1235` | AF_INET recvmsg 有界 admission；独立 DHCP/PXE listener；BOOTP、PXE 前缀、LEASEQUERY 分类；普通 giaddr relay 与全 1 giaddr 源地址扩展；stop/nonblocking 状态不进入状态机 | `dhcp/service.rs::receive_once`, `poll_once`, `dispatch_poll` | 6 个 socket-independent dispatch 单测；隔离 Linux recvmsg/pktinfo、IPv4-only 和 stop/nonblocking 测试保持 ignored；relay forwarding、wire reply 未接线，见 `DHCP_SERVICE_PHASE.md` |
| `rfc2131.c:1976-2024` | 第一项满足 minsize 的 TLV；PAD、END、截断；主区域→file→sname；malformed suffix 不否定此前命中；每个区域单独失败 | `packet::find_option`, `Packet::option` | 直接抽取 C 函数差分，主/overload 两类共 4,006 case |
| `rfc2131.c:138-151` | option 57 包含 IP/UDP 头，减 28；下限 548，上限 16384；小于 28 的 C size_t 下溢最终落上限 | `Packet::response_capacity` | 边界单测；保留该可观测行为，无 unsafe |
| `rfc2131.c:2584-2605` | PXE vendor 按配置前缀匹配 | `Packet::pxe_vendor` | 单测；PXE 回复/菜单/端口 4011 未实现 |
| `lease.c:651-702` | CLID 优先；只有至少一侧无 CLID 才 MAC 回退；空 MAC 不匹配；最新记录优先 | `LeaseStore::find_client` | 直接抽取 C 2,002 case，含重复 CLID、相同 MAC 不同 CLID、缺失 CLID |
| `lease.c:948-1008` | 更新 hardware，缺失 CLID 不擦除已有 CLID | `LeaseStore::set_identity` | 单测；脚本 flags 未接入 |
| `lease.c:846-936` | 容量限制；初始 expiry=1；无限/零时长；更新到期时间同时 dirty file/DNS | `LeaseStore::allocate/set_expires`, `expiry_time` | 直接抽取 C 2,003 case；64 位有符号溢出改为 checked_add，无复制 C UB |
| `lease.c:621-648` | 到期等号；显式 target 也删除；本次删除以最旧记录先进入脚本队列 | `LeaseStore::prune` | 直接抽取 C 2,001 case；10,000 次续租索引规模不增长单测 |
| `lease.c:1062-1170` | hostname ASCII 不区分大小写；配置名不可被客户端名抢占；FQDN 模式分域冲突；先通知旧名丢失 | `LeaseStore::set_hostname` | 单测及主代理独立核读；输入 hostname 校验及完整 script flags 尚未连接 |
| `lease.c:23-173`; `util.c:612-681` | scanf 字段宽度/跨行；typed/compact/奇数位 hex；非法 identity 清空；extension 按已存在地址关联 | `lease_file::parse/parse_hex` | 直接抽取 C 各 2,000 case；read_leases oracle 的 setter 是记录器，名称冲突另由 script 差分覆盖 |
| `lease.c:174-254,286-420` | 恢复后清 file dirty，再 prune 到期，DNS 必须刷新；基础五字段和 agent-info/vendorclass 后置；typed MAC 保留 C int 位宽 | `LeaseStore::restore/write_leases` | 恢复/非 UTF8 名字/宽硬件类型/磁盘失败单测；尚未接真实 fsync/重试 timer |
| `lease.c:1010-1030,1211-1317` | 旧名通知早于新位置；删除队列先于活动变化；Add/Old/Delete；leasefile-ro/renew 开关；HUP rerun | `ScriptQueue`, `ScriptFlags`, `LeaseStore::rerun_scripts` | 直接抽取 C 2,000 个 15 步序列；单测核对队列所有权释放 |
| `dhcp-common.c:224-251` | tag conjunction；`!`/旧 `#` 否定；空 filter 受 pass 控制 | `allocation::match_tags` | 单测 |
| `dhcp.c:687-752` | 排除所有上下文 router；dynamic 地址范围；static/subnet fallback；proxy 不参与普通分配 | `allocation::available/narrow` | 单测；接收接口形成的 context 链由上层负责 |
| `dhcp.c:825-923` | SDBM u32 wrap；tag 优先双 pass；consecutive 地址；保留静态地址；class-C .0/.255 跳过；ping 冲突扰动 epoch | `allocation::allocate_address` | 单测；系统 ICMP/cache/load-limit 现由 `IcmpProbe` 提供，错误通过 `ProbeResult::Failed` 立即终止扫描，见 `DHCP_PROBE_PHASE.md` |
| `dhcp.c:244-267,446-466,520-528`; `network.c:21-35`; `util.c:718-749` | 在状态处理前保留原接口名；ARP使用client port/yiaddr/hardware与ATF_COM；ioctl失败后仍发送，EAGAIN有限重试 | `net::ArpEntry/inject_arp`、runtime interface snapshot/preparation/retry | C定义字段/重试1,045项、隔离veth/client namespace 88项通过；C未初始化hardware尾部不宣称等价，见 `DHCP_ARP_PHASE.md` |
| `rfc2131.c:1392-1488` | SELECTING/INIT-REBOOT/续租重绑定 early decision；错误 server 在 authoritative 下 NAK；未知 broadcast 续租忽略、unicast NAK | `request::classify_request` | 单测；返回 `CheckAddress`，**不是已经 ACK** |
| `rfc2131.c:1832-1873` | client-id 扩展硬件身份；client 请求租期至少 120，再与配置上限取 min | `request::extended_hardware_id/lease_duration` | duration 直接抽取 C 2,003 case；extended ID 目前依赖代码核读 |
| `rfc2131.c:1392-1753` | SELECTING/恢复/续租、static 迁移、保留地址、多 MAC 交接、容量、唯一身份；原 lease pruning 早于 NAK；更新名字/期限/interface/server override | `state::request` | 精确 C 真实隔离 UDP 服务与 Rust 离线状态核对；前置 context/tag/host/name 必须由调用方提供 |
| `rfc2131.c:1237-1285` | DECLINE 只删同客户同地址；静态 backoff 600 秒，动态 epoch 增加；RELEASE 校验 network/server/client 三者 | `state::decline/release` | 同一状态差分覆盖，包含错误客户释放不删有效 lease |
| `rfc2131.c:1287-1389` | DISCOVER 按 static→已有→requested→hashed；OFFER 不创建 lease；rapid commit 才提交且失败无 NAK | `state::discover` | 同一状态差分覆盖 OFFER 无 lease、地址冲突、rapid option 与副作用 |
| `rfc2131.c:565-697` | BOOTP 必须 MAC，默认 static only；按配置允许动态；默认无限期限，复用/冲突判定 | `state::bootp` | 同一状态差分覆盖 static/dynamic/disabled；64 字节 vendor serializer 仍待接入 |
| `rfc2131.c:1756-1830,2247-2260` | INFORM 不分配/续期，允许无 context；剩余 lease time 按 PRL；无 PRL 在 C 中表示请求全部 | `state::inform`, `Packet::requests` | 同一状态差分覆盖既有/未知客户、按地址回退、PRL 不请求51、无 context、ciaddr=0 |

## 差分工具与本轮证据

`tools/dnsmasq/dhcp_differential.py` 校验 `rfc2131.c`、`lease.c` 的精确
SHA256 后直接抽取上述 C 函数。C 是预期结果来源，Rust 输出不生成 golden。
编译 C 开启 ASan/UBSan；只有内存输入，无 socket、DHCP 服务或设备访问。

运行（要求 `cc` / `rustc` 在 PATH）：

```sh
python3 tools/dnsmasq/dhcp_differential.py --output private/dnsmasq-rewrite/dhcp-differential/run-N
cargo test --manifest-path components/dnsmasq/Cargo.toml --lib dhcp::
```

seed=20260929、2,000 轮，18,015 项成功，0 mismatch；原始输入、两侧输出、
ELF/本机二进制、C 抽取源码、结果 JSON 留在
`private/dnsmasq-rewrite/dhcp-differential/run-04/`。30 项 DHCP 单测通过。
首轮校准发现固定测试 TLV 的 hex 把预期 PAD 写成了 option 3；两侧同样
返回无匹配。修复 fixture 后重跑，首轮输出保留在父目录，没有删除失败。
`tools/dnsmasq/dhcp_state_differential.py` 通过 `run_isolated.sh` 在 oracle
新建的 network/mount/PID namespace 中启动精确 C 的真实 DHCP 服务，仅 lo。
利用 C `dhcp.c:253-265` 的 giaddr=全1本地测试约定把回复送回测试 socket；
Rust 状态 adapter 在内存中消费完全相同的 request，并按 C 调用方清理 giaddr。
该测试没有启动 Rust DHCP listener，因此不构成 Rust socket/serializer 验收。

最新 `private/dnsmasq-rewrite/dhcp-state/state-run-04/`：51/51 匹配，5 OFFER、
5 BOOTP、20 ACK、6 NAK、15 无回复。核对 message type、地址、lease-time、
server-id、broadcast bit、NAK 原因、rapid-commit option，以及每次处理后的
lease 文件地址顺序、客户身份/名字/CLID 和到期时间（两个实现各读系统秒数，
仅磁盘 expiry 容许 ±1 秒）。报文中的 lease-time 本轮为精确相等。
普通/authoritative、静态单/多 MAC、静态迁移、DECLINE/RELEASE、BOOTP、
rapid commit、INFORM 均有独立 C 结果。旧轮原始数据保留。

这些结果只覆盖表内状态与场景，不证明报文服务、所有配置或完整租约生命周期等价。

## 已确认 C 缺陷与有意差异

损坏 lease DB 含两个不同 MAC/client 的同一 IPv4 地址时，C
`lease.c:23-173` 无条件分配两条活动记录；`lease_find_by_client` 分别找到
它们，`rfc2131.c:1532` 只在 `!lease` 时检查他人占用，因此两客户能够继续
续租同一个地址。在隔离 C 服务中已经用两条初始记录及两次真实 REQUEST
复现 **两个 ACK 指向同一地址**。最小 DB、两个请求/回复和结果在
`state-run-04/duplicate-recovery-proof/`，该缺陷验证不计入兼容通过分母。
Rust `restore` 遇重复地址返回 `AddressInUse` 并禁止开始服务，不悄悄择一或
继续冲突库；已有非 UTF8 名字与超 u8 的硬件 type 已改为 byte/u32 无损保存。

另外，`expiry_time` 使用 checked arithmetic，避免复制 C 超出 time_t 范围的
有符号加法 UB。正常时间域保持 C 的无限期限/零时长语义。

## 优化候选与成本

原 C `lease_find_by_addr` 和 `lease_find_max_addr` 扫描整个活动链表；
地址候选循环重复执行前者，最坏 O(地址候选数 × 租约数)。Rust 用地址
`BTreeMap`，地址检索与范围最大地址 O(log n)。C 每个 DHCP 包前 prune
扫描所有租约，持久化后找最早 alarm 也扫描；Rust 用每租约至多一个
`BTreeSet<(expiry,address)>`，无到期时只查看树首，实际删除 O(k log n)。
更新过期时间同步删除旧键，避免 lazy heap 在高频续租时积累陈旧记录。

这是机制与复杂度候选，不是已测得性能收益。两棵树存在节点与指针成本，
可能比原 C 单链表增加内存；目前不能声称降低 RSS、CPU 或资源。
CLID 查找仍扫描活动租约，输出租约文件按序号排序也有额外成本；后续测量
应覆盖小池（150）与大池、频繁 renewal、无到期流量和批量到期。

## 尚未满足的合同（必须继续，不能裁剪）

- 完整 `dhcp_reply()` 的 tag/config/context/name 前置解析与 context tag 二次
  求值；状态 kernel 必须与这些调用方语义连接，LEASEQUERY 仍待实现；
  完整 wire reply options/tag/overload caller、leasequery agent-id/vendorclass 更新。
  有限 OFFER/ACK 的 T1/T2/fuzz 已接 wire/runtime；详见 `DHCP_REPLY_PHASE.md`。
- 真实 DHCP socket、pktinfo、接口动态变化、relay、ARP 注入、广播/单播
  的完整服务对照；ICMP 依赖已有 67,647 项精确 C 原语与 Linux namespace
  验证，权限/发送失败采用显式错误而非 C 的放行行为，不能计为完全等价。
- `lease.c:174-254` 启动读真实文件/leasefile-ro init 脚本；`286-454` fsync
  失败重试/next alarm；ScriptQueue 仍须接 helper/hotplug 与通知重连。
  内存恢复/序列化及事件通过不等于真实持久化生命周期已通过。
- BOOTP 可用 vend 区仅 64 字节、无 DHCP message type；`packet.rs` 已提供
  bounded COOKIE/TLV/END serializer，但配置/tag 上下文和完整 reply 仍待整合。
- PXE `877-1055,2360-2557`：boot-item、拒绝 BIS 高位、按 architecture/tag
  生成 menu/server/discovery、UEFI workaround、proxy、4011、UUID 回显。
  `option.c:4347-4389,4409-4528` 的 dhcp-boot/pxe-service 配置语义也属于合同。
- TFTP 有独立服务合同，由主代理协调；此模块未替代其实现。
- OpenWrt ubus ACK/RELEASE、metrics、helper/hotplug 环境、odhcpd/DNS 更新、
  reload/ujail/procd/租约恢复、压力/异常路径均待整体验证。

当前验收：**DHCP 原语阶段完成部分对照；完整功能等价未成立；优化目标未成立；
生产未验收。**

## BOOTP vend serializer 对照增量

`tools/dnsmasq/bootp_vendor_diff.py` 从精确 `rfc2131.c` 抽取
`dhcp_skip_opts()`、`find_overload()` 和 `free_space()`，再按
`dhcp_packet_size()` 的结束游标写入固定 64-byte vend 区。seed `0x293001`、
2,000 个随机序列加 8 个边界序列共 **2,008 cases**；C/Rust 在定义输入且
没有 filename/sname overload 的 **429/429** vend 字节序列一致，0 mismatch。
结果保存在 ignored `private/dnsmasq-rewrite/bootp-vendor-diff/result.json`，
C `rfc2131.c` SHA256 为 `14f2e10792ef6108aeb7b69e551f089ba287c8c84d39ea178a5f33acd2038c2c`。

边界证据同时固定了三个兼容边界：vend `options+64` 的 C 条件
`p + len + 3 < end` 留出 `END`；恰好超过该边界时 C 会创建 `OPTION_OVERLOAD`
并把选项移入空的 `file`/`sname`，而当前 primitive 只拥有 vend 区，明确计为
未覆盖的调用方职责（随机批次有 1,576 个 overload cases）；输入 code 0/255
不是 `free_space()` 的正常生成路径，显式用例保留其 C TLV 差异。Rust raw
入口对截断 TLV 返回原子 `MalformedOptions`，不会提交部分输出。

## DHCP reply wire 对照增量

`tools/dnsmasq/dhcp_reply_diff.py` 从精确 `rfc2131.c` 抽取
`clear_packet()`、`dhcp_skip_opts()`、`find_overload()`、`free_space()`，并在
Rust `dhcp_reply_probe` 上比较相同固定头、PRL/overload、mandatory option 与
`dhcp_packet_size()` 结果。seed `0x21312930` 的 5 个边界序列加 1,000 个随机
序列共 **1,008 cases**，0 mismatch。证据在
`private/dnsmasq-rewrite/dhcp-reply-diff/result.json`。

对照期间发现并修复两项 wire 差异：NAK 分支不能调用 `do_options` 或发送已选
普通 options；`borken_opt` 需按 C 优先级检查 option 81，再回退 option 12，未
编码且尾随 NUL 时给 NAK message 保留 NUL。两项均保留 Rust 回归测试。该工具
只覆盖已选 options 的 reply wire 边界，配置/tag/context 解析、PXE、
agent-id 和真实 socket 仍不在通过范围内。

2026-09-30 定时器增量：精确 `do_options` 的 T1/T2 代码块与同一输入 fuzz
已加入上述工具，1,284/1,284 whole-wire cases 通过。使用实际 `Outcome`
租期、配置覆盖约束、无限租期/INFORM 排除、renew/rebind 才抖动及 C u32
运算；运行时 listener 保留独立 entropy FD，并在失败时保留已提交 outcome。
完整阶段边界与证据身份见 `DHCP_REPLY_PHASE.md` 和 `DHCP_RUNTIME_PHASE.md`。
