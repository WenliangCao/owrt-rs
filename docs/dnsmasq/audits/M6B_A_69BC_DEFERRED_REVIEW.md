# A69bc：延期项与兼容边界复审

2026-10-08。这是候选源码的本地只读审查，不是最终 `complete` 收据，没有访问 Oracle、构建或执行测试。审查基点为 main `1ef9e903`，实际产品对象为独立 A `69bccf2738f2c07cbc6d8b8a950015d4cea10af3` / feature-off opt3 SHA `21937fa33b2552801278ea6cb15f0e13cb733824e4cd236382f968a1c1c4324b` / 1,962,024 B。精确镜像 C 为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`，位置均指其匹配 `dnsmasq-2.93/src/`。

结论：A存储没有新增普通配置拒绝或把普通caller改成极端豁免的源码变化；现有镜像缓存完整门也没有新增差异。**发现1个必须复闭的共同资源错误路径**：新增信号wake pipe忽略非阻塞设置失败。该项不归为A存储增量，也不能由M5“Rust无该pipe”的历史豁免覆盖。它修复、实测及复审之前，不能生成 `ordinary_unresolved=[]` 的最终审查收据。其余资格仍按实际新候选门逐项取得，不以本审查证明169项最终统一通过。

## 精确源码与证据范围

`E=private/dnsmasq-rewrite/evidence/`。本次复用 root 已导出的 `E/M6B/resume-20261008/safety-a69bc/source`，没有改这份源码；读取其163文件source map，并将每个SHA与Git69bc对象逐一比较，零不同。

| 对象 | 本地来源与完整SHA | 可授予的范围 |
| --- | --- | --- |
| 候选source map | `E/M6B/resume-20261008/safety-a69bc/source-map.json`，`468d8fa666ad4b67e809c34d7c56722f24215b0044609636eb5fe563310b1529` | 163个输入确属69bc；不是build/run资格 |
| 导出archive | source-map记录 `86b3e6bf574948764cd524cf9ad6b33dea3658f9351ba3b53f3580e183dd72bc` | 导出来源声明；本审查不重新授归档metadata资格 |
| 新六诊断源join | `E/M6B/pair-udp-acl-01/source-join.json`，`a19cf11a4f256b94508e3f3b09a1587296d009ac7d092cafa6adc8c45ec9e95a` | 原编译maps与同21937产品连接；不把prepared写成实际通过 |
| latest ACL三caller | `E/M6B/pair-udp-acl-01/acl-02-result.json`，`2cf40eefc1eed1f5babd716e010cb53d37a8f55150b593027d7b286652bd561f` | 实际late-device/recreated-device/late-label比较及两exit0；不是完整interface族 |
| 中断服务轮 | `E/M6B/full-archives/a-69bc-service-interrupted-01/interrupted-service/plain/result.json`，`50eb9522bd6e78cb618b2a2b8f646e634a18078a1f75041205fe6971cce9c2df` | 14/27，passed=false；保存已执行结果，不与fresh轮拼接整门 |

fresh `a-service-02` 的cache12步已按[恢复记录](M6B_A_SERVICE_69BC_CHECKPOINT.md)完整归档：540 executed/passed、516 required、missing/differences空，保留原9次C运行及四指定PTR的独立参考变体、CNAME PTR及lease caller守卫。其tar SHA `1754c34c1778a6a36bd9fcebcaaa652403bb5a154e3b36294dc744062f94e5f7`。本文不代替本地metadata收据，也不把这12步授为六族27步、44族68步或最终M2资格。

## 普通配置与A存储的审查

与最新NoA `e8b1d6c4` 的component差异只有cache存储/helper、相应cache测试、main的DNS-work所有权与适配测试；`config/`逐文件无差异。与M5最终dc1b的配置目录也无差异，既有合法数字wrap、长度拒绝、domain/SRV/boot/PXE边界没有被A重写。cache-size生产上限仍由 `config/scalar.rs:138` 钉为5,000,000；A的u32 slot link检查不缩减这个范围，slot generation仍u64。

| 普通合同 | 69bc实际源码决策 | 独立证明与未执行边界 |
| --- | --- | --- |
| S1/S2 accept快照和时钟 | `Cache::snapshot`仍clone逻辑视图；`finish_tcp_accept`在读取首帧前建立cache/local/lease/interface与accept-clock。内容和names根共享，slots/LRU/reverse/pending私有 | 原语/view隔离与网络accept supplements必须按latest身份过；connect成功不替代UBus accept见证 |
| S3改写与轮转 | content和names两个窄修改入口先 `Arc::make_mut`；clear逐块detach并换names根；Many list push/remove/rotation再次detach，不排序RR集合。remove保持剩余顺序，未命中remove不改共享owner | code review没有发现漏写入口；source-join不替代正控、故意漏detach/禁rotation/reuse-generation负控 |
| S4/S5完整事务和顺序 | `capture_commit_counted`仅成功commit返回Some，Some(empty)仍有意义；按pending实际pop/commit顺序保存record。parent不得复制child EntryId或合并child全部metrics | 完整cache与fresh transfer gate各自必需；不把空事务当失败，不恢复已退休byte Receiver |
| S6父当前冲突和失败前缀 | `Cache::import_counted:937–982`仍先start_insert，用父当前now/local状态；reverse以地址冲突，不把其PTR目标当forward名字冲突。已发生移除/逐出不回滚 | PTR配置CNAME缺陷是共同已修普通bug，不能分类为故意差异；540库存含固定新增四caller与计数/upstream窄守卫 |
| S7完成/EOF | 当前导回是owned `CacheTransaction`同步消费，在forward完成后、下游Writing前发生；没有全局accept FIFO或新的byte transport | 网络upstream EOF是另一边界；C-only内部pipe切点不等于现Rust产品接口 |
| S8 DNS-work与日志slot | `main.rs:5276–5405`先把所有producer事件交accepted log context，再在实际工作结束时take完整DNS-work；日志未完仍占G与连接上限。stale work不会在下游关闭时提前take | root已核latest66测试中的受控stale owner门；镜像stale和diagnostic S8另有资格。它们不宣称stale专用1Hz对象余额实测 |

以上不放宽TTL、flags、RR内容/顺序、上游次数、失败前缀或计数。空/小缓存、半满/4096/大缓存、30连接上限、10批、150s、交错与S8按既有矩阵执行；第4包缓存/租约进一步优化按用户本次授权延到M6b之后，不能借此增加替代算法或延期普通缺口。

## 共同普通修复不进入豁免表

| 真实缺口及精确C caller | 本次共同修复和资格边界 |
| --- | --- |
| PTR目标是父配置CNAME；`cache.c:969–1056`导入及forward-only local冲突 | NoA/A同时修导入方向，保正常forward冲突。前代8组IPv4/IPv6×UDP/TCP对照与新540四caller都保持1upstream/1insert/后续hit；不是A存储的可接受差异 |
| 首次neighbor dump尾部完成后TCP/UDP/TFTP consumer无唤醒；`arp.c:154–164`与owner MAC caller | 在Some→None时捕获待MAC身份/恢复已有逻辑工作；不伪造network revents、不以新2ms循环掩盖丢唤醒。新的Linux测试和完整EDNS/相关族仍按实际source绑定 |
| hostsdir INIT读完后缺可运行收尾；`dnsmasq.c:1570–1594` clear/reload顺序 | 完成publication的已有job仍runnable；不是FIFO持续等待的故意进展差异。35派生startup失败不能被“极端hostsdir”排除 |
| ordinary NEWADDR提前publication；`network.c:1778–1810`、`rfc1035.c:1875–1918/2018–2034`、`dnsmasq.c:2025–2048` | 只dynamic/有效net/未完DAD主动枚举；普通匹配forward、accept、成功server/resolv各保自己的实际caller。PTR/HUP不偷换代际。targeted10只有其明确范围，full276仍须same ELF |
| withheld stale refresh漏Forwarded日志；`forward.c:2004–2016/555–557` | 提交refresh后立即drain事件；不等reply/expiry。启动fault三case改按真实daemonization error channel选pipe，原exit/errno/子孙深度未放宽。targeted5不替代329全族 |
| ordinary wildcard UDP显式interface ACL依赖旧snapshot；`forward.c:1783–1793/1808–1810` | live ingress name判定及实际failed-ACL异步枚举，保存原packet身份；不恢复所有NEWADDR eager枚举。latest三caller过，完整interface与route/DAD相关门仍待各自实际收据 |

## 已有30条差异及延期标签的精确边界

已先读[M5差异入口](../M5_BEHAVIOR_DIFFERENCES.md)、[账本差异总表](../DELIVERY_LEDGER.md#与-c-的行为差异)、[M5最终失败索引](20261006/FINAL_REPLAY_FAILURES.md)及下面处置报告。账本共有30条具体差异；不是30个可任意扩展的豁免。除信号pipe行须因M6b实际新增接口重审外，A没有改变这些处置源码。下表完整分组覆盖其余29条及该open行。

| 保留行/数量 | 精确C位置与保留理由 | 本候选不能借用的资格 |
| --- | --- | --- |
| 文件FIFO进展、dump FIFO、日志sink进展/永久阻塞退出/FIFO FD（5） | `cache.c:1436–1450`、`option.c:5471/5852–5859`、`network.c:1699–1724`；`dump.c:70–76/291–295`；`log.c:133–134/192/320–326/421–473`及失败FD路径`:221–222/278–281`。单owner必须保持网络/退出、有界队列及已接受记录次序 | 阻塞压力差异须守卫实际C阻塞/退出、Rust健康/overflow/丢弃与释放；普通文件、完整PCAP、正常consumer日志仍严格。不能以FD回收证明cache对象余额 |
| EDNS跨身份合并、部分neighbor发布、未DONE进展、同连接sticky OPT（4） | `forward.c:181–218/3227–3263/1948–1952`、`edns0.c:560–575`；`netlink.c:211–225/327–329`、`arp.c:42–100/154–175`；阻塞dump `netlink.c:114–133/198–225`；sticky `forward.c:2378/2507–2519/2720–2721/2745–2752`。避免身份混用、不发布不完整身份、保证owner进展、每query OPT独立 | [7个EDNS明确输入](20261006/EDNS_INTENTIONAL_DIFFERENCES.md)仍在196库存，有独立阳性和窄负控；sticky仅前序OPT后移除一个未请求OPT且其余wire逐字相同。不能豁免ordinary MAC/wire/EOF/TTL差异 |
| 第二空conf-file、version、log-malloc、CHAOS EDE（4） | `option.c:5654/6057`；`util.c:933–1017`；`rfc1035.c:1838–1854`及`cache.c:2373–2399`。不复制NULL崩溃/未初始化栈诊断，明确实现归属，用户已排除逐字allocator trace | 普通CLI/start/--test及剩余GPL/compile options严格；CHAOS只有固定未初始化EDE suffix，不宽免name/client/rcode。345完整CLI与329日志不能缩矩阵 |
| 巨型SOA、负signed IPv6 prefix、不可编码SYN PTR、非法dns-rr、CAA（5） | SOA `dnsmasq.h:350/rfc1035.c:1016/1038/1052/2326–2327`；prefix `option.c:2679–2697/domain.c:264–279/util.c:524–533`；SYN `domain.c:153–209/rfc1035.c:1992–2000/1600–1608/util.c:294–324`；hex `option.c:5091/5103/5116/util.c:623–625`；CAA `dnsmasq.h:403/option.c:5144–5149`。不复制坏wire、越界、假root PTR或无效hex的超大分配 | [cache极端](20261006/CACHE_EXTREME_DISPOSITION.md)、[endpoint极端](20261006/ENDPOINT_EXTREME_DISPOSITION.md)限定实际payload/语法/阳性。负IPv6 dangerous C与CAA unsafe-excluded不冒充本轮实际C执行。合法上界及安全wrap仍要严格 |
| TFTP scope、零块、peer替换、bound V4源、root parent组件（5） | `tftp.c:289–302/336`；`:385–395/930–933/964/970–971`；`:247–277/305–309/963–971/1020–1039`；未初始化`:63–66/100–119/198–201/320/522`；路径`:487–498/547–553`。修已定位scope/坏块/旧DATA/FD/未初始化源/parent组件问题 | [TFTP处置](20261006/TFTP_DUMP_CLI_EXTREME_DISPOSITION.md)保持global/LL、wildcard/bound、单端口、合法root路径各自范围；危险bound V4历史UB不因完整族通过改称重执行；不读取宿主逃逸路径作阳性 |
| boot空tag/BOOTP predicate、file/sname>255、PXE空menu/vendor、prompt252–255、TFTP/PXE超int数字（6） | `option.c:1338–1344/1360–1368/4664–4701/dhcp-common.c:224–245/rfc2131.c:2571–2579/615`；file `option.c:4347–4392/rfc2131.c:2203–2213/2184–2187`；PXE `option.c:4486/4723/rfc2131.c:2477/2594`及prompt `option.c:4441–4443/rfc2131.c:2323–2354/2187`；numeric `option.c:750–765/3624–3652/4448–4449/4480/4485/4497–4499`与`tftp.c:108–109/236–245/276/385–395`。拒绝不可表示/NULL或signed UB配置 | 原syntax-only明确保持syntax-only；不能把 C --test接受当危险runtime通过。≤255文件、≤251prompt、范围内wrap/clamp、正常BOOTP/PXE实际caller仍必须保留 |
| 信号self-pipe（1，open） | `dnsmasq.c:583–589/1341–1434`、`util.c:352–358`：C pipe/flags失败fatal5。M5“Rust无pipe”的解释不再描述69bc | 见下一节；不能复制旧source-only声明为latest完整错误路径资格 |

处置报告中的“任意malformed/header组合”“allocator多故障组合”“dump gettimeofday组合”等泛标签没有具体新失败输入，仍只是有限覆盖或source-only限制，不是已跑测试，也不是删除required rows的许可。M6b模式明确不另开90分钟fuzz链，不把excluded写成passed；已有ordinary及明确故障、资源、ENOSPC/EMFILE、APK门仍实际执行。

## 普通资源错误路径：信号pipe非阻塞设置失败

准确候选位置：`main.rs:841`以 `owrt_ubus::sys::pipe().ok()`取得可选pipe；`:844`忽略writer `set_nonblocking`结果后发布 `SIGNAL_WAKE_WRITE`；`:1397`忽略reader结果后交owner。`components/ubus/src/sys.rs:415–423`实际 `pipe2`只有O_CLOEXEC，**没有O_NONBLOCK**。

`main.rs:85–93`信号handler写1字节、`:4085–4098`drain循环都按非阻塞FD解释。若任一F_GETFL/F_SETFL失败，blocking fd仍被发布：满pipe下handler可以停住；reader一次恰读64B后会再读，空pipe下可阻塞owner。默认pipe成功、普通服务/完整cache通过、无pipe100ms fallback测试都不能证明这个错误路径安全。此结论来自可执行源路径，没有运行故障注入，也不声称已发生daemon挂死。

该问题是NoA/A共同新增唤醒接线，非A存储导致；必须保持独立归因，但在final freeze前实际修复。可沿既有接口选择原子NONBLOCK创建，或只有两端非阻塞准备完整成功才发布、任一失败drop两端并使用现有100ms原子信号fallback；真实策略由root决定。C原fatal5与Rust可恢复fallback的差异须明确重写当前差异理由，不再写“未分配该pipe”。`StartupChannel`真实daemonization error pipe及三已写failure输入继续精确配对，不能与可选wake pipe混同或按ordinal误选。

root已确认将其按普通错误边界处理，不做极端豁免。准确C初始化链是 `dnsmasq.c:583–589 → safe_pipe(pipefd,1) → util.c:352–358 → network.c:884–894 fix_fd`；writer和reader的F_GETFL/F_SETFL都成功后，才prime EVENT_INIT。C handler `dnsmasq.c:1341–1414`保存errno并选择event，`:1437–1458 send_event`依赖NONBLOCK和event_desc小于PIPE_BUF，一次writev仅重试EINTR。daemonization error pipe在`:593–611`另以safe_pipe(err_pipe,0)建立，reader保持不同的阻塞协议，不能一起改。

给root的最小接口是 `owrt_ubus::sys::nonblocking_pipe() -> io::Result<(OwnedFd, OwnedFd)>`，内部只以 `pipe2(O_CLOEXEC | O_NONBLOCK)`取得FD并按现pipe相同所有权包装；原 `sys::pipe()`继续供blocking reader协议。wake caller只需改 `main.rs:841`这一创建入口，删除`:844/:1397`两次分阶段ignored fcntl。失败时不发布任一FD，保持静态write=-1和owner.signal_wake_read=None，沿`:4011`现100ms兜底；成功时直接按原位置store writer/交owner，不新增queue/thread/poll layer。本报告没有实施这些改动或授其通过。

现有精准fallback测试是 `tests::delivered_signal_counters_wake_even_without_a_pipe_byte`（`:6745–6765`）：明确owner无pipe，三个原子STOP/USR2/HUP分别使wait<50ms，验证已交付逻辑信号不必等100ms。`accepted_mac_wait_does_not_busy_poll_queued_dns_before_snapshot_ready`（`:6930`附近）也明确检查无pipe100ms兜底；HUP同wake与queued reload测试、最终M2真实TERM/HUP另有既定运行门。它们不证明新helper的flags或实际pipe2失败。

修后最小有意义验证应独立确认两端F_GETFL含NONBLOCK/FD_CLOEXEC、空read/fullwrite返回EAGAIN，以及exact64B drain后下一空read不会停住owner；创建失败不留任一端并仍沿既有无pipeatomics合同。root负责同补丁NoA/A的新build/source/test收据及受影响caller门。69bc原服务证据作为历史保全，不能授后继源码资格；CPU未跑，旧准备资产按身份退役并fresh冻结，不增加另一27窗。

## reverse strict、ordered relation与退休接口

精确C `cache.c:297–312 hash_bucket`读取 `typestr`指针数组的实际64B mixer，`:314–340 cache_hash`保持flag分区及equal-name插入序；`cache_find_by_addr`按实际hash遍历改变LRU。跨不同ELF布局的PTR线性输出不是可统一sorting的合同。

历史ae1/e290 reverse的184稳定观察全匹配，但ordering12有4行strict差异，原比较器exit1保留。fresh03只读sidecar在自己的诊断ELF实际bucket/mixer/chain/LRU上验证原21case关系和3负控，`ordered_relation_gate_passed=true`、`full_original_primitive_passed=false`、`product_cpu_pss_qualification=false`均保持。这是有序关系资格，不回写strict4/12、不改comparator、不声称七profile或257-name池已跑。

69bc的六份fresh prepare/source-join还必须分别实际build/run；旧ae1/d8成绩不能换source_commit后算latest passed。latest完整540镜像cache及其9次C变体是实际服务资格，与primitive strict/result、diagnostic relation分别列。若strict仍不同，保留每行差异、真实布局/关系解释和相应能力范围；不能由service绿把`full_original_primitive_passed`改true，也不能由关系模型放宽错误wire或TTL。

当前 `dns/mod.rs`没有 `tcp_transfer`模块；`TcpDnsWork::run_forward → tcp_view_extract → capture_commit_counted → import_tcp_cache_transfer`同步消费完整typed事务。旧 `cache_partial_eof_rust_diff.py`指向不存在的 `dns::tcp_transfer::partial_eof_tests::exact_c_partial_eof_probe`；0 tests/FileNotFound是过时入口红证据，不通过、不要求恢复Receiver。C内部 `cache.c:843–918/952–1056` pipe截断仍是C-only参考；public upstream socket EOF只能证明其真实网络caller。当前capture/import、失败前缀与完成顺序分别由fresh库/完整服务/五accept supplements证明。

## 最终复用门

root最终freeze时不能仅替换本报告里的commit：须核最终编译输入map与本次163输入逐项关系，复审任何新增产品变化；其中信号pipe修复必须有新源码分析与实际受影响测试/镜像收据。fresh六族27steps、原语隔离/companion、五accept、public/内部/压力/45CPU及最终44族68steps/M2/guard/资源/APK/135各自保完整身份和失败。

本报告不生成deferred-review.json、不填写complete或ordinary_unresolved空数组。待明确open项复闭、最终source/ELF身份及全部规定回归真实齐备，root再形成最终source-bound deferred/safety review。完整旧红、中断轮、工具错误、source-only与unsafe-excluded继续留原始证据；未做M7，不称生产验收，物理路由器未触碰。
