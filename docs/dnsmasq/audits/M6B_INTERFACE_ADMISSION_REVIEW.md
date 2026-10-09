# M6b 接口准入调用链复核

本复核针对最终冻结停点暴露的 UDP loopback 回退，检查 TCP、DHCP、TFTP
是否还有生产调用方与库判定不一致的问题。依据是镜像匹配源码
`private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/` 和 Rust 实际调用链。
调用链表与历史归因来自本地审查；下文另列主线程取得的精确 C／旧 Rust 运行反例，不据此声明最终统一资格。

## C 的共同规则

`network.c:112 iface_check` 将接口名与明确地址作为并集；明确地址匹配
优先于 `except-interface`。`network.c:501` 在接口限制非空时，将发现的
loopback 接口名隐式加入接口列表。空接口条目不匹配名字，但仍形成接口
限制；通配符的 `*` 必须匹配非空后缀。

UDP 和普通 TFTP 在名字判定失败后保留 loopback 及 IPv4 地址标签例外；
TCP 仅保留 loopback 例外。静态绑定 IPv4 UDP/TFTP 信任创建好的 socket；
TCP 两种绑定模式均信任监听 socket。IPv6 的目的地址还须保留作用域。

## 实际调用方

| 服务 | 生产调用链 | 名字与准入来源 | 结论 |
| --- | --- | --- | --- |
| UDP DNS | `SinglePoll::step_udp` → `admit_udp` → `udp_acl_name` / `udp_acl_exception`，或 `admit` | Linux ACL 路径使用当前内核名字；旧通用路径使用发布快照 | 停点缺陷来自新名字路径未带入隐式 loopback；修复必须覆盖 `step_udp` 的真实回答 |
| TCP DNS | `SinglePoll::step_tcp_accept` → `tcp_interface` → `admit_tcp` | 当前连接的内核 ingress 名字、flags；无法取得 ingress 时才按发布目的地址回退 | 已含隐式 loopback、明确地址优先及排除；未发现同类遗漏 |
| DHCP/BOOTP/PXE | `SinglePoll::step_dhcp` → `DhcpSocketListener::process_once_on_listener` → `runtime::process_with_random_and_ports` → `LocalProvider::resolve_on_interface` / `resolve_events` → `InterfacePolicy::select` | sender 提供当前内核名字，provider 提供每包 IPv4 快照 | 普通准入共用 predicate，先执行 `no-dhcp-interface`，再接口/地址并集及次地址回退 |
| DHCP leasequery | 相同 listener/runtime → `LocalProvider::lease_query_reply` → `InterfacePolicy::select` | 与普通 DHCP 一致 | 白名单、排除、loopback 和次地址规则共用，无另写判定 |
| DHCP relay | `process_once_relay_only` / 常规 listener → `RelayRuntime::process` → `InterfacePolicy::select` | 当前名字、primary ioctl 和 IPv4 快照 | 与 DHCP 同一 predicate；先处理合法 relay reply，再执行客户端排除及准入，符合 `dhcp.c` 顺序 |
| DHCP server-ID alias | `LocalProvider::resolve_events` → `InterfacePolicy::selected_address` + `config::tftp::interface_enabled` | 地址枚举及当前 kernel name | 地址本身必须通过接口选择；TFTP 可用性单独判定，避免借 DHCP 次地址回退放行其他地址 |
| TFTP | `SinglePoll::step_tftp` → `poll_once_with_mac` → `receive_server` → `Policy::admitted` | 当前名字用于 dedicated/TFTP veto；普通 DNS ACL 当前转入 `listeners::admit` 的快照名字路径 | 发现输入不一致，见下文 |

## TFTP 的相邻输入不一致

`receive_server` 已获取当前 `interface_name`。Dedicated 接口列表和
`no_tftp` 排除使用这个名字；普通接口白名单/`except-interface` 却由
`Policy::admitted` 转交 `listeners::admit`，后者使用快照行的
`link_name()`。C `tftp.c:216` 对普通 ACL 直接使用当前名字。

最小正常输入是 `port=0`、wildcard、`interface=lan`、普通
`enable-tftp`，接口 index 7、非 loopback、IPv6 地址 `fd42::1`。启动后
保留 `name=lan` 的发布快照，再执行 `ip link set lan name retired0`，
从同链路 IPv6 客户端发 RRQ 到 `fd42::1`。Rust 当前名字是 `retired0`，
但普通 ACL 仍以快照 `lan` 判定为通过。C 的当前名字判定失败，非
loopback 使 `loopback_exception` 失败，IPv6 使 `label_exception` 必然
失败，与发布目的地址是否仍存在无关。

共享 owner 不会自动消除此普通场景：`main.rs` 启用
`use_shared_listener_owner`，禁用 TFTP listener 的每秒自刷新；Linux 的
`InterfaceRefresh` 没有周期扫描；`RouteWatch` 仅将 NEWADDR/DELADDR
及合格 NEWROUTE 解释为事件，纯 NEWLINK 改名没有刷新请求。明确接口
ACL 的 wildcard 模式也不因普通地址事件主动枚举。`port=0` 又排除了
新 DNS/TCP 请求碰巧触发懒枚举。因而这不是只依赖极窄竞态的输入。
此结论先由完整调用链和分支反例提出，随后主线程完成精确 C/冻结旧 ELF
的改名运行见证，见下文证据段。

建议普通 TFTP 准入复用 DNS 的统一“名字、loopback、明确地址”判定，
继续保留静态 IPv4 信任 socket、dedicated 列表及发布列表的地址例外。
不得把这些不同的 C 调用方分支压成一种绑定规则。

## 已有覆盖及本次必要补测

- UDP：`main_udp_acl_tests.rs` 的实际 `step_udp` 见证，需同时覆盖
  `interface=lan` / 空接口条目对未枚举 `127.0.0.2` 的回答、排除 `lo`、
  明确地址覆盖排除，以及 listen-address 单独存在时不扩大 loopback。
- TCP：`listeners.rs::tcp_checks_arrival_names_and_preserves_bound_and_fallback_rules`
  覆盖名字、loopback、绑定和缺 ingress；`tcp_fallback_keeps_link_local_destination_scope`
  覆盖作用域；已有 M5 listeners 真实 ELF 矩阵包含 TCP。
- DHCP：`interface_admission.rs` 覆盖普通/次地址、排除、loopback、通配符；
  `service.rs::socket_listener_processes_local_ack_and_replies_to_peer` 覆盖实际
  socket/runtime；生产主循环已有每包快照的 readiness 测试。M5 listeners
  已有 relay union、except、no-dhcp 见证。
- TFTP：`tftp_policy.rs` 覆盖 scoped owner、dedicated、两种排除语义；
  `tftp_listener.rs::integrated_dual_stack_shares_capacity_and_pending_mac_does_not_block`
  覆盖实际接收分支；M5 listeners 已包含 alias、dedicated、静态缓存名字、
  动态地址及 `no-dhcpv4-interface` 差异。此次应补实际 listener caller
  使用当前名字而非旧快照名字的见证；无需新增验收门。已有
  `tftp-static-renamed` 的 `ip link set lan name retired0` actor 和文件
  夹具可复用，但该 profile 只覆盖静态 IPv4 缓存名字，不能单独验证
  此普通 wildcard IPv6 分支。

## 刻意保留的服务差异

`no-dhcp-interface` 同时禁用 DHCPv4 与普通 TFTP。
`no-dhcpv4-interface` 在 TFTP wildcard 路径不禁用 TFTP，但在 bound
socket 创建路径禁用；对应 `network.c:539` 与 `tftp.c:227`。
Dedicated TFTP 名字列表可覆盖 DHCP 排除，但 bound socket 创建仍先受
DNS 接口/地址选择限制。普通 TFTP 不继承 DNS `local-service` 源限制；
`Policy::new` 只复制接口选择字段。上述差异都有 C 调用链依据，不能
当作待统一的两条判定。

## TFTP 改名缺陷的历史因果（2026-10-09 独立源码追溯）

这里须区分“普通 ACL 读旧名字”的引入、“共享 owner 禁用自刷新”和
“M6b 删除旧 owner 周期扫描”三件事。普通 ACL 并不是本次 M6b 才从
live name 改成 snapshot；M6b 使已有输入不一致不再由周期扫描纠正。

| main 提交 | 变更及因果 |
| --- | --- |
| `86e311434c8f523bbb510fecd50100ea42215deb`，2026-10-03，`finish TFTP policy and Linux listener checks` | 首次加入 `tftp_policy.rs`。`receive_server` 在 wildcard/IPv6 分支取 `SIOCGIFNAME` 的当前名字；`Policy::admitted` 将这个名字用于 dedicated/TFTP veto，却将普通 DNS ACL 交给 `listeners::admit`，后者按快照 index 查名字。因此两条名字来源从 M5 的首次 policy 实现就不一致。该提交还加入按 `now` 秒数改变执行的 `Policy::refresh` 自刷新。 |
| `b6a243534828d9f63895fb315517a224b4984018`，2026-10-05，`expose TFTP sockets to the shared listener owner` | 加入 `shared_listener_owner` 和 `use_shared_listener_owner`，使 listener 自刷新条件变成 `!shared_listener_owner && now != self.refreshed`；共享模式由外部 owner 提供 `refresh_listener_interfaces`。 |
| `b235fc2cad62d157a75d59fe5d4dd9a4732491a6`，2026-10-05，`share partial listener lifetime and bound reply source policy` | main 首次实际调用 `tftp.use_shared_listener_owner()`；main 的 `last_interfaces` 扫描将 `listeners::snapshot()` 结果交给 `tftp.refresh_listener_interfaces`。M5 最终 `dc1b740d` 保留 **100 ms** 的扫描条件和空闲 **2 ms** 的 poll，因此纯改名仍会被 owner 的扫描发现。独立 listener 的按整秒自刷新是另一条已禁用路径，不能把 M5 main 写成 1 Hz。 |
| `5da2771362da4b8af4b7253573ae72e8eac480b5`，2026-10-07，`poll network fds and batch UDP receive` | 首轮 unified poll 将空闲等待改成最近 deadline、无 timer 时 3,600 秒 sentinel，但仍保留 main 的 `last_interfaces` 检查，且 service turn 先于这个检查。源码显示，它可能延长首次新 RRQ 使用旧代的窗口；一次 owner turn 之后仍会执行旧扫描。没有历史 ELF 运行证据，不能将这点写成已完成 bisect。 |
| **`2c28df782c88799d2da297fd2a2aa136ba2738e6`**，2026-10-07，`wake interface maintenance on address events and DAD deadlines` | **建立持续旧代路径的 M6b 提交**。删除 `last_interfaces` 和无条件周期 snapshot，换成 `InterfaceRefresh::due`；普通成熟 listener 没有 timer，只有 address 事件或未完成初始 DAD 能请求维护。`RouteWatch` 订阅 route/address，不订阅 link；解析只将 RTM_NEWADDR/DELADDR（20/21）设为 `address`，RTM_NEWLINK（16）不请求刷新。因此只改名、地址/index 不变的普通 TFTP 继续读原 `lan` 快照。后继 `3d4dbc83` 又按 C caller 收紧 ordinary address publication，但不是这个纯改名持续路径的首次引入点。 |

这条缺陷的普通条件是 IPv6、非 loopback、wildcard、无 dedicated TFTP
名单和 `interface=lan`。改名后 live name 是 `retired0`，snapshot name
仍是 `lan`。C `tftp.c:216` 的直接 `iface_check` 拒绝；IPv6 没有 label
例外，非 loopback 没有 loopback 例外。Rust 的旧 `admit` 将 index 对应
快照 `lan` 判成允许。`port=0` 使其不借助额外 DNS caller 偶然触发
懒枚举；正常 TFTP RRQ 本身也没有刷新 ordinary ACL snapshot 的 caller。

### M5 原改名 case 实际覆盖什么

[`m5_listeners.py`](../../../tools/dnsmasq/m5_listeners.py) 的
`tftp-static-renamed` 只生成一个 `mode=static` profile；冻结清单配置为
`bind-interfaces`、`interface=lan`、**`enable-tftp=lan`**，并设置
`tftp-root=/m2/tftp/lan,lan`。actor 的 before/after RRQ 都发往
`V4['lan']`，从 `lpeer` 发 IPv4 TFTP，rename 后仍预期取得
`synthetic cached owner\n`。这正是 C 静态 IPv4 socket 创建时缓存 owner
name/root 的有意分支。它覆盖了这一兼容要求，但既没有 ordinary
wildcard IPv6，也没有无 dedicated 名单的普通 ACL 改名反例。

不能将 M5 163 cases 的通过泛化为“接口改名所有 caller 均已实测”，
也不能把修复当前名字路径时保留静态 IPv4 cached owner 误称为遗漏。

### 证据与限制

主线程运行、本审查只读核对的
[`tftp-red-summary.json`](../../../private/dnsmasq-rewrite/evidence/M6B/loopback-repair-01/tftp-red-summary.json)
绑定镜像 C `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`
与冻结旧 Rust ELF `e53fbdcb7cb29e0ac0d2d5bcfaa9c5f284849af2114f8d37720bb644485c6c79`。
before 双方均回答 DATA `0003000172656e616d65`；改名且等待 1.2 秒后，
C 的 `after.answer=null`，Rust 仍返回同一 `boot.bin` DATA；双方正常
退出 `returncode=0`、`forced=false`。summary SHA256 是
`41334641decd63852c9a16c6eb2788270805b9cc13703736a7c1b8db7eab58c8`，
完整 actor
[`tftp-rename-observe.py`](../../../private/dnsmasq-rewrite/evidence/M6B/loopback-repair-01/tftp-rename-observe.py)
SHA256 是 `0cb7ed4b2b242f55794705892c27a3bff82e34f31b279e93d88b64eb011a3dd3`。
这个运行结果关闭了“只是理论竞态或夹具进程崩溃”的疑点；完整归档
仍由主线程核验并绑定。本历史追溯没有操作 oracle，没有
构建或运行任何历史 ELF。以上精确提交的归因来自逐提交源码对照，
**不是历史二进制实测 bisect**；M5 极短旧代窗口是否在某个旧 ELF
上实际命中仍未执行，不据此扩展历史运行结论。

## 原始运行证据保全

`E/M6B/loopback-repair-01/archives/` 保存完整 GNU/PAX tar、manifest、
本地 SHA/完整 metadata verification、prune 收据和普通 plain 报告。

| 对象 | archive SHA256 | entry 数 |
| --- | --- | ---: |
| `tftp-rename-c-01` | `790a28b7debfa3fb223ea797a9a692126af6bc1f70edc68cce898c597104f7d7` | 36 |
| `tftp-rename-rust-01` | `4824f668d8d61d8abcd7d79b0ec823206f7ea6d57b79076ebc12b6722438fc60` | 37 |
| UDP 修复 Linux test ELF 与全部尝试 `udp-tests-01` | `ef18a367ebbee5b4d7c6890786a731726ca931cd56acd482c358333d80770119` | 15 |

TFTP 两侧只运行一次，没有同参数复跑。两次 initial DATA 都正确，改名后的
C 无回复、Rust 仍发 DATA；`cleanup.returncode=0`、`forced=false`。
TFTP 缺陷尚未修复；当前 UDP 修复源码 `3492bbde` 只完成 source-bound
Linux 测试，尚未重新冻结最终 opt3/s。原 `284376c4` 的前13步只留历史
身份，未来新 ELF 必须从第1步实际重跑，不能导入这些结果。

## 有界修复的收尾与最终身份

用户随后授权一并修 TFTP，只能复用现有共享 owner 的接口收集续步，
以1小时止损；DNS-TCP/DHCP专项到此结束。实际修复 `8bd80024`
复用 `udp_acl_name/udp_acl_exception`，只增加一份原包 admission 单槽，
与现有MAC等待共用8项上限。`step_tftp` 请求已有 `enumerate_interfaces(true)`；
原collector完成回调发布接口并恢复这一原包，后备放行后走原MAC/dispatch。
没有新增collector、线程、计时器或收集设计。静态IPv4信任cached owner、
dedicated名单、single-port listener ACK与独立transfer ACK边界保持。

`main_tftp_admission_tests.rs` 实际调用main接收链，覆盖旧IPv6名字误放行的
拒绝/collector完成、IPv4 label例外恢复原RRQ且没有第二包、静态IPv4cached
owner与dedicated当前名分支。新增main caller三项及既有TFTP socket三项
在隔离Linux上实际通过；完整main74/lib753亦通过，其他20 ignored不计。
首次 `8bd80024` 新测试夹具字节转义编译错误由 `889fe4f5` 修正，原错误
归档保留，不改成产品红或运行通过。

计时从2026-10-09 17:52:45 UTC开始；18:05:52 UTC精确C/新opt3配对
已通过：改名前都发正确DATA，改名后均无回答，daemon退出0且未强杀。
因此未触发“UDP-only＋TFTP已知差异”的止损方案。最终源码889fe4f5，
opt3 `791a7c33987fbb21887c51041f27722b9cc1bd8bd4cffab0fc03a292517fb10f`；
同源s身份见最终冻结报告。

完整修复验证证据在 `E/M6B/final-889fe4f5/archives/`，均有本地
SHA/全部metadata校验和prune收据，原始upper/special对象只保留完整tar：

| 对象 | archive SHA256 |
| --- | --- |
| `repair-tests-01` | `bfcce6b399b7c42885573188d91e0c696253ada58652b72ce457c2e76077d1a2` |
| `tftp-rename-c-01` | `5dccdb8b3c0afba99d5d14b9001bef908a79fe98ed1e7f0f02c70409438abcdb` |
| `tftp-rename-rust-01` | `36cd8fc4bb7da15a876e7a65adc026f80feb0def32c9c281f0da413333cbc339` |
| 原夹具编译失败 `fixture-build-error-01` | `f1f1f848b0690792af8af2f2e676b6d2fd8e5a409d14834ffb7a820d29f6e386` |

这关闭修复专项；完整最终统一验收仍由新ELF的44族/68步、M2、资源压力、
135、guard及APK链给出。原284376c4的13步未导入新资格。
