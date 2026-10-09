# M6b UDP loopback 回退的引入点与相邻边界审查

2026-10-09。本报告是本地源码与 Git 历史审查，不把它算作新 ELF 的运行资格；最终产品仍须从第 1 步完成普通与 targeted 回归。

## 结论与引入提交

main 的首次引入提交是 **`e8b1d6c411fba324888e3e202c0c133156afbed4`**，2026-10-08，`fix(dnsmasq): admit UDP ACLs by live ingress and resume label fallback`。它属于 M6b 事件循环改造的普通 caller 修复批次，不是 M5 原始 listeners 实现，也不是方案 A 的共享 TCP cache 改动。父提交是 `f2420ac49f583882e2260d1a6d3ec007e18d3b23`。

相同改动也出现在侧线 `ea2dcc88e0a7937d1254fb6abd82ceb0a967d0ee` 与 A 线 `69bccf2738f2c07cbc6d8b8a950015d4cea10af3`。三者的 `listeners.rs` Git blob 完全相同：`477229787ac889ba8a0a245858d744cc9e28195e`。不能把这些不同路线的提交混称为三个独立缺陷。

`git show e8b1d6c4 -- components/dnsmasq/src/{main,listeners}.rs` 给出直接因果：

1. `SinglePoll::step_udp` 原来直接调用 `listeners::admit`，新代码改调 `SinglePoll::admit_udp`。
2. Linux wildcard UDP 有接口或地址 ACL 时，新 caller 先取当前 kernel ingress name，再调新增 `udp_acl_name`。
3. 新 helper 只匹配显式接口 pattern，并对 `name_matches` 传入 `false`；它漏掉原 `admit` 已有的 `!config.interfaces.is_empty() && interface.loopback`。
4. 失败后 `udp_acl_exception` 要求目的地址等于一个已枚举、已选择的地址。因此它能处理所选地址的 loopback/IPv4 label 例外，却不能回答未单独配置的 `127.0.0.2`。这与把 loopback 隐式加入接口允许集是两条不同规则。

参考 C [`network.c:501–520`](../../../private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/network.c) 在存在 `if_names` 时，将 `IFF_LOOPBACK` 接口的真实名字补入 `if_names`；随后 [`iface_check:112–156`](../../../private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/network.c) 按这个完整集合执行允许/排除。UDP 的 [`forward.c:1784–1795`](../../../private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/forward.c) 先执行 `iface_check`，只有失败时才枚举并检查 loopback/label 例外。因此，后备例外不能补救新 helper 漏掉的隐式允许集。

## 为什么原 M5 listeners 能通过

账本中 listeners 全族闭合身份是 `f987f9410c064bcf949d16fe26662ab4e58745df` / ELF `2b63edc9…a2fa91`：163 配置、3,534 逐标签观察、18 完整 C 边界和 130 负控通过。M5 最终统一源码是 `dc1b740d7973838e2ae7f098d0726b0484e55074`，ELF `37f85d22…`。`37f85d22` 是 ELF 摘要前缀，不是 Git revision。

在 `e8b1d6c4^` 与 `dc1b740d`，`listeners.rs` 都是 blob `e745199b10f7ca3f4cd19dc50636b49555214598`；实际 UDP caller 均使用已有的 `admit`，其中已存在接口限制下的 loopback 隐式允许。`git diff dc1b740d..e8b1d6c4 -- components/dnsmasq/src/listeners.rs` 只增加新 live-name helpers 与 ioctl wrappers，并未删除原规则。故这是新增生产分支旁路旧正确判定的回退，历史绿结果与最终 ELF 的红结果并不矛盾。

原提交的生产 caller 测试确实调用了 `step_udp`，但只用 `interface=lo` 覆盖 live name 接受；它没有覆盖 `interface=<其他接口>` 时隐式允许 loopback 的分支。另一个 test 用 loopback alias `lo:acl42` 强制期望进入 failed-ACL collector，反而将遗漏固化进见证预期。修复后的测试应使用真实收到的 UDP 包，覆盖未配置的 `127.0.0.2`、其他接口白名单、显式 loopback 排除及 listen-address 优先级；alias collector 测试须明确排除实际 ingress 名字 `lo`，使 direct 名字判定确实失败，而所选 `lo:acl42` 地址标签仍可走 C 的后备例外。

## 同批 loop/readiness 改造的相邻边界

审查范围是 main first-parent 从 M5 `dc1b740d` 到冻结产品 `284376c4` 的 dnsmasq 改动，重点读 `SinglePoll` 的 poll 构造、ready 分派、准入、接口 collector 和各 continuation 的消费处。本表是静态核对，相关既有测试是否在修复后 ELF 上运行由统一验收记录决定。

| 边界 | 当前实现与源码核对 | 关联批次/既有生产 caller 测试 |
|---|---|---|
| UDP live-name 准入 | 新分支独立复制允许集，漏隐式 loopback；本次唯一已确认的新准入缺陷。literal listen-address、static IPv4 bound socket 与 source 判定仍保持各自快路径。 | `e8b1d6c4`；`main_udp_acl_tests.rs` 的缺口如上。 |
| UDP failed-ACL collector | `PendingUdpAdmission` 保存 token/socket/peer/destination/index/query/loopback，暂停新的 DNS 输入；collector 完成只取一次 pending，并继续 `process_admitted_udp`。collector 的 Send 状态有 runnable、Read 状态有 fd 与 deadline，不依赖新的 DNS 包唤醒。 | `e8b1d6c4`；alias continuation 测试需改正确前提。 |
| TCP accept 与缓存视图 | 生产 caller 调 `admit_tcp`，其已有接口限制下的 loopback 允许；无 UDP label 例外是 C caller 的明确差别。接口收集后 `finish_tcp_accept` 保留 accept 时的 peer/MAC/clock 与 local network，再取对应 DNS 视图。 | `main.rs::step_tcp_accept/finish_tcp_accept`；A 的 `f2a59167` 没有改入口 ACL。 |
| DNS startup 与文件发布 | 两个 poll owner 及 UDP/TCP consumers 都用 `files_initializing` 与 `interface_work_pending` 控制新输入；`dns_file_work_runnable` 与 file consumer 都尊重 hosts/DHCP/interface 的发布顺序。已修复的 init-finish continuation 保留 runnable，避免普通 hosts 发布后睡死。 | `6a2cdbd7`、`655aef91`；`main_hostsdir_init_tests.rs` 和 `startup_fifo_keeps_blocked_dns_off_both_wait_sets_without_dropping_it`。 |
| NEWADDR 与接口记录发布 | 当前 `apply_network_events` 只按 clever bind、effective local-service 与未完成初始 listener 请求新代；普通 interface/domain 仍由实际 DNS/accept/check_servers caller lazy 发布。 | `3d4dbc83`；`main_newaddress_tests.rs`。这是本批已定位修复过的另一项 caller 边界问题。 |
| TCP/EDNS budget continuation | buffered TCP input、MAC 完成、forward timer 与 log retry 都可绕过仅 fd-ready 的调度；EDNS 尾部用 `edns_udp_runnable`，只剩 unresolved MAC 时停止自旋。normal 与 DHCP probe owner 都有相应 timer/runnable 入口。 | `d21a58f3`、`4f83d0a7`、`8709f1da`、`0ba85656`；真实 TCP budget、EDNS tail、MAC wait 测试。 |
| DHCP ready 与接口快照 | poll 与 `step_dhcp` 同用 `dhcp_packet_work_allowed`；接口 dump pending 时监听 fd 不参与 poll，但 dump fd/deadline/runnable 参与。消费处在新代 ready 后才读下一包，并在一个事务后释放快照。 | `b9146c37`；held bank FIFO、packet snapshot、global interface generation 测试。 |
| TFTP ready/timeout 与 helper tail | TFTP fd 与 pending transfer 的 250 ms timer 均有 wake；consumer 在 fd/MAC/timer 任一可推进时执行。最后 TFTP completion/冻结 DHCP delivery/ARP change 通过 `helper_next_due` 再进一轮，不需要额外网络包。 | `856fee48`、`4816b19f`；`last_tftp_completion_wakes_helper_without_another_packet`、冻结 DHCP callbacks 测试。 |
| UDP completion、route 与 scratch 生命周期 | 上游 fd readiness 和 `upstream_next_due` 任一可唤醒 completion；route retry 独立 deadline；DNS reload、wildcard TCP pktinfo 与构造 TFTP response 时明确 invalidation。 | `12cbadce`、`70097c66`；upstream timeout、route resend 与共享 packet invalidation 的既有 caller 测试。 |

本段初轮静态审查未确认上述其他 continuation 仍有新产品遗漏；这不是对完整 44 族或新 ELF 的通过声明。随后接口准入专项审查确实发现 TFTP 普通 ACL 将 live name 与 snapshot name 混用，主线程已用精确 C/冻结旧 Rust ELF 确认 IPv6 改名后的持久回退。引入链及运行证据见[接口准入专项审查](M6B_INTERFACE_ADMISSION_REVIEW.md#tftp-改名缺陷的历史因果2026-10-09-独立源码追溯)。其首次 snapshot predicate 在 M5 `86e31143`，持续旧代由 M6b `2c28df78` 删除旧 owner 周期扫描建立；不能将本轮旧否定结论用于覆盖该已确认缺陷。最终资格仍以修复后完整 listeners/DHCP/TFTP 差分及资源压力证据关闭。

## 修复与实际 caller 验证

修复提交 `3492bbded6d0eea6e10239527e2dcd584aec21ae` 从旧 `admit` 提取一个
共用名字判定，`selected`、UDP live-name、TCP 和旧 `admit` 都复用它。
Linux `admit_udp` 用实际 ingress flags 传入 loopback，保留明确地址优先、
静态 IPv4 和无 ACL 的零 ioctl 快路径、failed-ACL 发布列表例外。

`main_udp_acl_tests.rs` 新增真实 `step_udp` 收包与回答：接口列表为 `lan`
或空条目、旧快照为空，仍回答 `127.0.0.2` 的合法查询；另直接调用生产
`admit_udp` 覆盖排除 lo、明确地址、listen-address 单独限制、static、
dynamic、IPv6 与非法 ingress。原 alias continuation 测试改为显式排除
lo，从而继续验证真正的后备收集与原包续步，未删除这一边界。

该源码的 Linux musl main 74 项、库 753 项实际通过，20 ignored 未计入。
第一次 main 的一个旧 FIFO 夹具撞到宿主 `/tmp` 的既存文件；原失败保留，
没有删除共享文件。仅用 fresh task-owned TMPDIR 作一次方法确认，全部通过。
这属于源码/test ELF 验证，尚未构建新的最终 opt3/s，也不代替完整 44 族。
证据在 `E/M6B/loopback-repair-01/`。
