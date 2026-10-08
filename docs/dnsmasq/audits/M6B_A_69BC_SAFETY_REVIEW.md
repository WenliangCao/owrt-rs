# A69bc 源码安全审查：候选证据，非最终资格

2026-10-08。审查对象固定为独立 A `69bccf2738f2c07cbc6d8b8a950015d4cea10af3`，
对照已接受 M5 源码 `dc1b740d7973838e2ae7f098d0726b0484e55074`。
本次只读本地精确 Git export、现有 C 源码与历史审查，运行纯文本/哈希 inventory 脚本；
**未访问 Oracle、未 build/test/fuzz、未改产品或物理路由器，`complete=false`，不授最终资格。**
发现两项普通信号错误边界，已立即交 root 统一修复；因此本候选不能填写
`ordinary_unresolved=[]`。第 4 包缓存/租约进一步优化仍延期，没有借本审查追加优化或极端矩阵。

## 精确身份和覆盖

证据根 `E/M6B/resume-20261008/safety-a69bc/`，其中 E 为
`private/dnsmasq-rewrite/evidence/`。源码由 prefixless Git PAX archive 导出，PAX comment
为上述完整 A commit；archive SHA256
`86b3e6bf574948764cd524cf9ad6b33dea3658f9351ba3b53f3580e183dd72bc`。
[完整组件 map](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a69bc/source-map.json)
锁定 dnsmasq/ubus 的 163 个文件，SHA256
`468d8fa666ad4b67e809c34d7c56722f24215b0044609636eb5fe563310b1529`；
子审查重新逐文件 hash，零差异。该 map 没有生产冻结/通过字段。

[完整 inventory](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a69bc/inventory-v2.json)
遍历 156 个 Rust 文件，先屏蔽注释、字符串与字符字面量，再按 Linux/AArch64/musl/
64-bit、feature-off、非 test 配置分类。未知 cfg 保守保留；inline cfg 和独立测试文件
分开，fuzz 输入只作为锁定源码，不计产品路径。脚本及首次 inventory 也保留。
它是定位器，不能替代编译器或人工证明；`unsafe extern` 声明也计位置，不冒充一次内存操作。

| 定位类别 | unsafe | unwrap | expect | Mutex | RefCell | borrow / borrow_mut | try_borrow / try_borrow_mut |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 生产候选位置 | 244 | 213 | 34 | 0 | 29 | 12 / 62 | 7 / 34 |
| inactive cfg（含 inline tests） | 16 | 3440 | 13 | 3 | 12 | 16 / 1 | 0 / 0 |
| 独立测试文件 | 0 | 993 | 0 | 0 | 0 | 15 / 3 | 0 / 0 |
| 非产品 fuzz 输入 | 0 | 1 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |

[inventory→证明完整join](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a69bc/inventory-proof-join.json)
将635个生产定位位置（含Cell类型/声明/borrow）逐个链接到当前人工证明或已核同字节M5来源，
不同SHA文件没有未映射位置；这仍不解除SIG-01/SIG-02或授运行资格。

数量只用于发现遗漏。逐点原行、生产 caller、不变量、错误边界分别在
[缓存审查 JSON](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a69bc/cache-review.json)、
[owner/upstream 审查 JSON](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a69bc/owner-upstream-review.json)、
[FFI/files 审查 JSON](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a69bc/ffi-files-review.json)。
缓存另外纳入 `assert/unreachable/debug_assert`，FFI 审查另外纳入显式错误 fallback；
这些补充没有混入上述四项风险计数。

[M5→A 完整文件/风险 map](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a69bc/m5-to-a-source-and-risk-map.json)
逐文件对 Git blob SHA：124 个 Rust 文件与 M5 完整字节相同；32 个不同，其中19个含生产风险定位点。
同字节模块继承 [M5 主审查](../M5_ROBUSTNESS_REVIEW.md)、
[DNS](20261006/DNS_RUNTIME_SAFETY.md)、[config/interface](20261006/config-interface-safety-review.json)、
[TFTP/helper](../M5_TFTP_HELPER_SAFETY.md)、[logging](../M5_LOGGING_SAFETY_AUDIT.md) 的代码不变量，
并复核本轮新 caller 是否破坏其前置条件；不同 SHA 文件有下面的增量审查，不能称 whole-file unchanged。
这不继承旧 ELF 的实际运行资格。

## 发现的普通错误边界

| ID | 精确 A69bc 位置与触发 | 影响、最小处置与资格 |
| --- | --- | --- |
| SIG-01 | `main.rs:841` 调用 `sys::pipe().ok()`；writer844、reader1397 丢弃 `set_nonblocking` 错误。`ubus/sys.rs:415–423` 的 `pipe2` 只有 CLOEXEC。 | handler90 和 drain4093 假设 NONBLOCK。flags 失败后，满 pipe 的 handler write 或 reader读满64B后的再次read可以阻塞 owner，原子计数不能解锁该阻塞。root 已以 main `398162ff739dff97ce69d46a93a3423b2650fd4f` / A `74e772a6715405fa1c546253f1577e907b1fc8d3` 添加信号专用原子 `pipe2(CLOEXEC\|NONBLOCK)`，普通 IPC pipe 保持 blocking；这是新身份、当时 Linux 未跑，不能回填 A69bc 通过。 |
| SIG-02 | `main.rs:84–95 wake_signal_waiter` 的 write 不保存/恢复 TLS errno；nonblocking 满 pipe 的真实 write 会置 EAGAIN。 | 信号能夹在任何主线程负 syscall 返回与 `last_os_error()` 之间，把原 errno 改为 WouldBlock，进而改变重试/丢弃/故障分类。精确 C `dnsmasq.c:1341–1414` master handler 保存 errno，send_event 后恢复。交 root 加 Linux `__errno_location`，仅 fd>=0 分支 save→write→restore；实际成功和饱和 write 用非 EAGAIN sentinel精准验证。此 reviewer 未执行饱和/故障 test，不宣称 runtime 复现。 |

SIG-01 分配失败路径仍应保留 None、原子 STOP/HUP/reopen 计数及 `wait_for_files:4015–4020`
的100ms无pipe fallback；不能修改 errorpipe/helper 的 blocking IPC 语义。
SIG-02 是普通异步 errno 契约，不是扩大极端配置矩阵。指针长度/FD生命周期的内存证明
与这两项进度/错误分类缺口分开：有效栈缓冲不意味着 handler 不阻塞，也不意味着 errno 不被覆盖。

## 缓存/COW、generation、LRU和引用

精确存储是 **Arc COW**；没有生产 `Weak` root/CNAME 或 cache `RefCell`。
Dynamic CNAME 保存非 owning 的 `(slot,u64 generation)` EntryId；Local CNAME 保存
`Arc<LocalTarget>`，包含 owned Name 与可选 DHCP generation。`Arc::downgrade` 只在测试中。
`cache.rs/cache_name_index.rs/cache_engine.rs/cache_reply.rs` 无生产 unsafe/Mutex/RefCell。

| 路径与位置 | caller 与必须保留的不变量 | 错误/生命周期边界 |
| --- | --- | --- |
| `cache.rs:153–161,266–318` snapshot/metadata；`cache_name_index.rs:50–86` | `daemon.rs:1707`、`main.rs:5176–5183` accept 创建 view。私有 Vec slots、LRU head/tail、reverse chain、pending、failed、generation 与 clock 一起 clone；只共享 immutable Record/LocalTarget、64-slot content block、64 name shard及多RRset list。每个 metadata/map/list写都在自己层 `Arc::make_mut`。没有暴露共享 mutable Entry/map/list。 | parent/child变更先 detach 对应 root；clear先detach content后重建indexes，旧view保持接受时状态。OOM仍是Rust allocator fatal policy，不能冒称 InsertError 或真实压力门已验证。 |
| `cache.rs:119–140,405–410,525–532,1094–1103` CNAME | `get/is_valid`先核 bounds/generation/presence；删除target后旧ID失效，复用slot增generation，clear不重置generation。CNAME terminal/extraction十link预算。 | cycle/broken/expired返回miss/noncommit；没有raw pointer或Arc owning cycle。capture/import不携带child IDs，因此不跨cache对象套用handle。 |
| `cache.rs:600–734,855–1008,1122–1161` insert/commit/free | 成功insert才写Some Entry并push私有pending；failed交易不发布index；成功commit只弹一次；committed slot在name/reverse index唯一存在。remove先删所有index再unlink/free；pending不在LRU，容量不足全pending直接Full。 | ZeroTTL/Full/LongNameLimit/TimeOverflow/LocalConflict明确失败；移除/逐出等有序前缀副作用保持C边界，不因后续失败偷偷rollback。真实普通cache caller仍需新ELF门。 |
| `cache.rs:721,1247` identities | slot及lease publication的u64 checked_add；新publication第一条实际lease触发generation，旧view有自己的generation。 | `2^64`单slot复用/发布耗尽保留fatal而非wrap；明确内部耗尽限制，不扩ordinary矩阵。 |
| `cache.rs:1027–1040`、`cache_name_index.rs:79–84` RRset rotation | 只由Cache::lookup调用；matches为当前name list的distinct有序子集，≥2匹配才能进入Many；COW list detach后依次旋转且保留每个ID一次。 | 两个position unwrap/unreachable/debug_assert依赖这个私有caller契约；外部packet没有任意slot/matches入口。 |
| `cache_reply.rs:35,77,112`；`cache_engine.rs:280,606,1231–1234,1441–1444` | live lookup/checked is_valid到get期间保持同一Cache借用且无callback变更；固定4/16转换均由精确length/get范围分支证明。immutable payload没有interior mutability。 | invalid handle先返回false/None；writer Full和WireError按原Result边界传播；短packet不commit，已发生的合法前缀副作用保留。 |
| `main.rs:2623–2703` private extraction→parent import；`daemon.rs:1832–1848` | 同步sink生成owned CacheTransaction（Record/绝对expiry/authority），不含slotIDs/local target/counters。sink/forward返回后才try_borrow parent；导入以parent当前local/cache/wallclock重新判断方向、conflict、CNAME。 | 成功空transaction与无transaction不同；父导入false不把正确转发reply改成transport失败。debug路径直接短borrow parent current cache，非debug只操作自己的view。 |

40个缓存生产保留点逐个给出caller/invariant/error，见上述JSON和同名MD；
没有通过“26 unwrap/11 expect数量没增加”证明安全。Cache::new的one-based index容量断言
受生产 scalar cache_size≤5,000,000保护；库任意超范围构造另是明确caller误用。
`daemon.rs:1697` fixed envelope PacketWriter65535的expect由writer最小12-byte条件证明。

## 单 owner、RefCell、TCP及upstream

`main.rs`生产 **0 unwrap/expect、0 Mutex**，仍有6个unsafe定位与大量Cell借用，需要caller证明。
信号handler只访问atomics/pipe FFI，不能进入Rc图；`Rc<RefCell<ParentDns/ParentEvents/interfaces/provider>>`
不跨服务线程。只读字段查询、同步状态转移与网络等待不能混成同一种借用边界。

| 主路径与位置 | 不变量/调用顺序 | 显式错误边界 |
| --- | --- | --- |
| `main.rs:902,2111–2121,5160–5193` accept | 一个owner captures local/cache/routing/clock，明确drop(parent)之后才初始化forward/client并增加tcp_active。interface borrow也在actualsocket工作前drop。 | try_borrow_mut失败返回并drop accepted stream/view；snapshot失败在clients.push之前返回。 |
| `main.rs:2578–2593,2632–2703,2711–2777,2904–2911` TCP work | debug queryID/cache sink用短try_borrow；private view不borrow parent。extraction closure不回调ownerloop，完成后parent导回另起borrow；read前的debug invalidation borrow已结束。 | collision转Err/WireError，由step_tcp_clients的result.unwrap_or(false)关闭该work；不是panic/default成功答复。 |
| `main.rs:3750–4066` wait、`4100` fd_ready、`5233–5415` client progress | 只复制fd/deadline/mask，Cell borrow均在poll前结束。每次clear/rebuild fds保留allocation；poll前给已有client挂具体slot，新accept None/0；重复fd mask OR，POLLIN/POLLOUT各消费自己的方向。own subsystem的due-time独立于其他timer。 | poll错误恢复Vec并返回；150s绝对deadline及100query不能因idle/readiness跳过；8step/64step预算尾在memory/now-deadline续，不制造不可运行queue busy loop。 |
| `main.rs:4120–4158` metrics/UBus | 持ParentEvents borrow时只读取独立provider/ParentDns cells，metrics写入plain snapshot，没有反向ownercallback。UBus buffered完整method即使kernel空也runnable；absent transport仅下个owner事件重试。 | entry try_borrow失败io error；不新增重连timer。DHCP probe时provider移出并采用probe_metrics，不能再次borrow该provider。 |
| `main.rs:5925–6066,6228–6320` DHCP/probe/TFTP | step_dhcp先take self.dhcp再try_borrow provider；probe继续DNS/TFTP时owner找不到当前provider，使用已捕获metrics/MAC snapshots。每包dump完成才receive，finish_packet_interfaces之后才下一包。TFTP MAC只借独立provider/neighbors。 | 每个早退drop provider并restore dhcp；wait callback无法触达frame-local RefCell；callback错误终止reply，不能重入当前DHCP/文件reload/UBus。 |
| `main.rs:5377–5415` network/log释放 | 网络结束即dns_work.take释放view/stream/framer/upstream所有权；log-only G仅等原FIFO POLLOUT/retry/完成；stale关闭downstream后只在bounded refresh继续own view。 | 没有拿client.stream None当整个work完成，stale refresh仍有upstream deadline；logger空即逻辑释放，不等新请求。实际S8/150s/压力仍待新身份。 |
| `upstream.rs:434,470–485,503,1074,1136–1194` socket pool | 非空compatible后last；random_source_matches只返回pooled，pool_slot一定Some；settings生产启动一次计算，reload复用，pooled implies pool_slots>0，除数非0。open/reuse后token仍在同owner map；transaction先创建再socket_for。 | bind/open错误Result；failed initial send取消request。索引/slot expect是私有map关系，不保证库调用者任意修改运行中pool配置；生产caller不做该修改。 |
| `upstream.rs:731,989,1320,1583,1695,1722` timers/send/FFI | pollable_at(false)要求已有future retry；wildcard parse是固定literal。匹配reply/成功send不在同mutable borrow中删除pending；timespec/PollFd repr(C)、live buffer和nfds_t ABI明确。 | missing fd/knownterminal错误显式处理；nanosleep/poll errno返回owner重新算deadline。retry_send原C有限重试边界保留。 |
| `upstream.rs:547–588,1212–1236,1312–1317,1448–1467` route resend | SavedUdpQuery仅存monotonic SocketToken/server/destination与最后成功ownedwire，不是raw fd/新socket owner；overwrite/server删除/fail/release都invalidate；retiredtoken不可能alias复用fd。 | absent socket清save返回；resend terminal send错误按C server_send丢弃，无新query/log/dump/retry状态。其他source-only route caller不因此授实际资格。 |
| `tcp_exchange.rs:149,261`（完整字节与M5相同） | active phase只在Some connection后进入；failed take并回Pick。accepted private group不在exchange中替换；empty list先NoReply，Complete才reply_server；position与u16body长度始终受buffer界限。 | UnknownGroup/Deadline/NoReply/Busy/NotStarted显式；两expect证明私有phase拥有connection；64step耗尽返回fd=-1/now deadline，不做内部poll等待。 |

## FFI、files和其余改变的 caller

详细逐点表见ffi-files-review；以下保留新增/被新caller消费的关键边界。

| 路径与位置 | 证明与caller | 错误边界 |
| --- | --- | --- |
| `net.rs:405–427` live ingress名/flags | `[u64;5]`为40-byte aligned initialized Linux64 ifreq，SIOCGIFNAME写16-byte IFNAMSIZ，再完整拷贝该16-byte name给SIOCGIFFLAGS；owned datagram FD覆盖call；只读16..18 flags。main UDP ACL direct-name或IPv4 label fallback不发布旧snapshot。 | 0/超i32index明确拒绝；ioctl Result/None保留实际errno；failed flags只不能用loopback exception。 |
| `listeners.rs:484–522`、`net.rs:245–253,484–552,582–728` | socket成功且fd≥0才唯一from_raw_fd；options/sockaddr/iovec/cmsg在call期间初始化/aligned/live；接收拒绝TRUNC/CTRUNC/超capacity再slice；control长度min40。 | options/bind/send/recv错误Result，setup失败RAII close；没有duplicate close或payload/rawpointer逃逸。 |
| `startup.rs:321–351` | CString/constant NUL终止；NULL门后读libc passwd/group，UID/GID/name在下个lookup前copy；fallback getgrgid仅在getgrnam NULL之后。capability v3两record/fork/uid/gid全scalar或明确repr(C)。 | 原startup错误码保留；M6b这段只增SAFETY说明，不把解释算runtime测试。 |
| `dns/files_runtime.rs:299,448,497–499,652`；`dhcp/files_runtime.rs:320,350–351` | hosts_enabled/watch同步创建；endpoint_update/current先install后consume；groups创建vec[row]非空；error front先Some再pop。DHCP generation/job始终成对，EOF/fullplan前不能take发布。 | parse/open/FIFO/worker failure是原ordered diagnostic，不能输入文本删掉私有generation/job；active FIFO优先于queued trigger。 |
| `dns/filewatch.rs:69–194,279–384`；`dhcp/filewatch.rs:72–231` | owned nonblocking watchfd、liveCString；netlink至少16header、error20、route28才固定转换；inotify get/check_add后解析。peek/TRUNC只取得所需长度，resize后才consume并验证family/kernel pid。 | 短/非法frame安全拒绝；startup EPERM仅一次group0 retry；ENOBUFS向owner返回，不伪造NEWADDR/ROUTE。main3333其它read-error的1s cooldown/附加日志仍须明确actor/source-only及C差异，startup membership不能授runtime recv errno资格。 |
| `helper/process.rs:56–67,347,413,450,478,554,600–664,724` | childIPC只让parent writer/event reader非blocking，childblocking合同保留；flags错误返回StartError/RAII，与SIG01不同。frame4/8转换均先完整length/MAX_FRAME；forkchild独立owned endpoints、_exit，不unwind parentRc；EOF未reap只有限10ms下一ownerturn。 | 语义/credential/spawn/read/wait errors原typednotice，partial/EOF不伪造完整message。 |
| `dump.rs:88–266` | fixed24/16 read_exact、queue front同owner，Rc<RefCell> writer不回调producer；mask immutable borrow在udp mutable borrow前结束；256queue与16KiB写budget、POLLOUT有队列才挂。 | 丢弃失败record/通知，EAGAIN/EINTR retain offset；signal不触writer，无Mutex poisoning。 |
| `ubus/conn.rs` production prefix | SHA `cc7ae6b7dc88e1ad17814f319404f318d4e27671705e7adb9f9e9f5bb746d9ac`与M5相同，变化仅tests。frame/header/subscriber/peer固定长度先验证，take_frame(false)只能Err或完整Some；owner只新增既有has_pending wake caller。 | partial/EOF/timeout reset buffers/FD；unknown payload拒绝；旧debug父UBus关闭缺陷及wrap极端source-only不能被新owner测试改成actual通过。 |

logging/neighbors/TFTP的补充逐点审查也纳入同一ffi-files-review，沿原M5日志/TransferTable/邻居dump证明
核新增queued/active谓词与safe error return；它们不能由一行“无新unsafe”获得资格。

## 最终复绑定与限制

本候选两个普通finding未在69bc修复，不能生成最终complete审查。后继root共同修复将改变
`main.rs/ubus/sys.rs` source map；必须实际核diff、增量复审并重新锁最终source/ELF/build/map，
再把无普通未解的真实review用于final prepare。不能只把此JSON或M5旧JSON的commit改成新40hex。

代码不变量与实际门分开：A服务、原语/隔离、layout/companion、资源/压力、45 CPU、最终M5/M2/
perfguard/135/APK仍由账本的真实收据决定。本次既无Oracle也无模拟tests，不写这些门通过。
当前新增route/debug/wake caller、partial内部pipe/source-only/malformed startup event/child-crash、
netlink其它recv errno、任意组合极端及内存耗尽的实际覆盖限制全部保留；不扩大第1包或第4包。
最后163文件再次逐SHA零差异；[证据manifest](../../../private/dnsmasq-rewrite/evidence/M6B/resume-20261008/safety-a69bc/manifest.json)
SHA256 `ed402cac889aec06049c724557d4f6c7d75bbe3adaf0aaa54c60493811b6c673`。manifest状态为candidate-static-review-with-confirmed-signal-findings，complete=false，
ordinary_unresolved=[SIG-01,SIG-02]，所有运行字段false。
