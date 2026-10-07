# TCP / forwarding / cache：逻辑续步源审计

2026-10-07。审计产品 `3e1b50b5b5f1bae08292a8bd558bfc8258a02974`；开工 HEAD143126cc 与它的 `components/dnsmasq` 字节相同。独立 no-A 分支 `m6b/tcp-runnable-audit`，不与 A 表示混合，main 由 root 整合；没有访问 Oracle。以下“测试存在”不等于本轮同 ELF 镜像门已重跑。

判据：状态产生后必须①内部已可执行→零等待/明确runnable，②需要 I/O→匹配 fd/events，或③只能等 timer→最近到期；存在 pending 不等于 runnable，不能把未完整的 frame、未完成的 MAC 或 C 的 lazy expiry变成忙等。

| 源 / 产生点（3e 行号） | 状态→poll→消费者 | 审计 / 边界 / 证据 |
| --- | --- | --- |
| TCP accept / listener (`main:4684–4870`) | accept后建立client；next poll 给实际client分配poll_slot，不能继承旧fd revents；listener在G<limit才登记 | `duplicate_fd_masks_merge_without_authorizing_read_from_write`、镜像容量补门计划。capacity full等待slot结束，不添加周期轮询。 |
| TCP input预算尾 (`main:2817–2873`) | `input_offset<input.len` → normal/probe (`3627/5131`) deadline now；`tcp_client_ready:4888`允许无fd处理；完整后续frame可继续，缺header/body仍等POLLIN | host实测 `tcp_buffered_frame_runs_without_socket_readiness_and_sends_new_answer`；新增 Linux `real_tcp_read_budget_tail_resumes_through_normal_and_probe_owner` 用真实写入9帧、首轮4帧、无kernel bytes、normal再4帧、probe最后1帧绑定完整链，仅类型检查、未Linux执行。仅framer.buffered_len>0不能判runnable，半帧等新bytes/EOF。 |
| TCP新reply / 未写完 (`main:2538,2755–2795`) | phaseWriting → POLLOUT，生产者本turn给一次writable；WouldBlock后只等写ready/error/hup，不能将“queue非空”无限0poll | host实测 `tcp_polled_write_does_not_consume_unpolled_read`；慢读真正backpressure镜像补门待跑。budget尾新Writing有真实POLLOUT，不丢读缓存。 |
| TCP lifetime /100query (`main:2734,2773`) | 150s绝对deadline在normal/probe min，predicate到期无fd也进入step；100完整reply后resultfalse | Linux `tcp_idle_deadline_and_completed_client_run_without_fd_readiness`测试存在；100/150镜像资源runner尚未执行。 |
| TCP accept-time MAC (`main:4883,4910`) | neighbor完成/失败或MAC3s恢复；先捕获身份，再让真实stream读事件推进 | **真实busy缺口**：Reading仍poll已排DNS，而lookupPending不读，POLLIN恒亮。`5c377a2b` normal/probe不登记这个stream、predicate不以POLLIN授权MAC；最小Linuxqueued-DNS/no-neighbor测试已类型检查，实际未跑。debug deferred-first-query的WaitingMac仍有独立3s状态，不改变它。 |
| TCP WaitingMac (`main:2738–2755`) | 保存完整query；phase登记fd=-1且MAC3s deadline，neighbors_ready恢复lookup；Ready转reply并本turn一次send | 现有EDNS196镜像族覆盖；需同new ELF重跑身份/缺DONE。无需给partial query或negative cache添加timer。 |
| EDNS UDP waiter (`main:4296,4321–4356`) | queue<=256，每turn最多32个Ready；neighborfd、dump2s、request3s恢复 | **真实尾项缺口**：budget后剩Ready仅有3srequest deadline。`20fd0b8b` 加edns_udp_runnable，normal/probe立即续；下一turn先清标记，全Pending/接口依赖即停止busy。host33与256混合实测通过；Linuxnormal0wait断言仅类型检查。 |
| active neighbor dump (`neighbors:245–247,449–456`) | 发dump后2s绝对epoch截止，FD缺DONE时timeout先于recv；timeout产生Ready(None)供MAC/TFTP恢复 | **真实漏timer**：旧append仅fd，无dump due。`f1d22fe0` 导出active_dump_deadline、normal/probe纳入精确fractional realtime投影；normal/probe到期先advance再TCP/MAC；lib no-recv清理及不加ARP90 timer测试、main1250ms/0投影测试已Linux类型检查，实际未跑。 |
| interface record continuation (`main:4042–4164`) | begin/collector.runnable或fd/deadline→step最多4→publication后take pendingUDP/TCP/files/servercheck同turn恢复 | collector每个已可执行阶段有runnable；完成publication直接执行continuation，不单靠缓存FileStep。main/file全审由root负责；镜像interface族caller证据仍需new ELF。 |
| TCP upstream connect/write/read (`tcp_exchange:51–269`) | 每Exchange保存phase/input offsets；WouldBlock返回borrowedfd+POLLOUT/POLLIN+min(idle,absolute)；mainnormal/probe登记wait | `nonblocking_exchange_yields_for_each_fragment_and_keeps_its_connection`、absolute/idle deadline、EOF reconnect tests存在；mainowner层fd/deadline投影缺最小组合测试，不以transport test代替。 |
| TCP upstream预算尾 (`tcp_exchange:234–242`) | 64步预算耗尽返回fd=-1/events0/deadline=now；mainminwait.deadline、predicate到期进入run_forward | 新 `immediate_source_bind_failures_yield_after_real_transport_budget` 实际host通过：65个合法缺失interface配置走真实socket/bind，首步64次失败且fd=-1/now，下步最后1次终止、0socket。Linux `real_tcp_transport_budget_tail_resumes_through_normal_and_probe_owner` 用193上游经真实请求生产128/64/1尾，normal/probe零ready fd立即续至REFUSED；root实际2c28测试已到正确5回答，但原错误期望2失败，修正断言仍待实际重跑。不能把负fd当“没有工作”跳过。 |
| `TcpDnsService.pending_query/bogus` (`tcp_service:354/374`) | pending_query伴随TcpWait；Complete同步提取→capture→parent import后reply，无异步typed导入队列 | 没有另一个隐含任务需唤醒；cache transaction pending是语义状态，不自动重试。transfer3单位及full image cache family是正确性门。 |
| TCP stale (`main:2703,2776–2812`) | stale reply Writing完成→关闭下游→立即start_forward；pending refresh仍靠TcpWait；Complete返回network_done并移交日志 | 不能以streamNone认DNS完成。独立S8 release提交721610ed另有真实upstream/stale测试，但未合本no-A分支；同ELF镜像stale全族待跑。 |
| UDP upstream terminal events (`upstream:1505/1536/1559`) | event deque非空→append_poll_fds deadline now；normal upstream_next_due now→poll_udp_completions；process_udp还同turnDurationZERO排空 | 逻辑队列已接到主poll；需补owner queued-event/no-fd测试。现fixed-timeout owner Linux测试存在，不能声称覆盖所有event产生入口。 |
| UDP fixed lifetime/fast retry (`upstream:815–883`) | Fixed transaction deadline、fast_retries due→now/nextms；normal/probe返回due，tick/poll执行；C lifetime按新query/pressure lazy reclaim | fixed owner测试存在；fast-retry send/no-fd与lazy40s无需主动timer分别有source+原族证据。不得因“pending40s”添加periodic collect改变C。 |
| UDP socket empty-error retry (`upstream:256/554/1525`) | nonpollable socket短deadline→重新登记；首次空error重试now，重复改EMPTY_ERROR_RETRY | `controlled_poll_error...`/`repeated_empty_poll_error_does_not_continuously_retry_receive`存在；需owner级nearest retry/no-spin组合。 |
| loop probe pending sends (`upstream:472–499`) | probe_refs保留POLLOUT+deadline1s；step最多128，余下仍有真实writablefd，error到期释放refs | IO尾不会仅依赖收包；需要>128 probes或持续WouldBlock的预算测试，当前原90loop族证明行为但未量化预算尾。 |
| log-only TCP / FIFO (`main:4990–5022; logging:298–309`) | network_done=true；context未finished等primary POLLOUT或FIFO retry；finished→normal/probe deadline now→G释放 | Linux `finished_tcp_log_fifo_retries_without_network_events_and_releases_slot`存在；它把network_done手工设true，S8完整work释放测试另用生产deadline/stale路径。主loop不以queue非空忙等。 |
| cache Entry expiry、LRU/pending / DNS source diagnostics | expiry在lookup/pressure用当前clock，child固定acceptclock；commit/import同步；source warning/event末turnlog_dns_diagnostics排完 | 与C一致的lazy状态不设新timer。既有完整cache原语/镜像536场景仍需final ELF重复；这里只审scheduler，不能用“pending”为由自行重试事务。 |

## 修复与测试状态

- `20fd0b8b`：EDNS预算尾逻辑runnable；host两测试通过，Linux--tests检查通过。
- `f1d22fe0`：active neighbor截止及timeout同wake恢复TCP；Linux--tests检查通过；新增lib/main Linux测试未执行。
- `5c377a2b`：accept-MAC依赖未完成时不被已排DNS busy唤醒；Linux--tests检查通过，实际测试未执行。

以上是no-A独立提交；root合入并构建同一new候选后，应执行所有新增Linux测试与EDNS/neighbor/TCP/日志真正镜像门。normal/probe使用同一due投影，C ARP90s仍仅在真实父活动检查；无新增90s周期timer。物理路由器未碰。

## Owner 预算组合补门（2026-10-07）

独立分支 `m6b/tcp-wake-tests`，基点 `7dc3ef814c73e1b5c68cc15ed265808926cc9bb5`。本提交只增加测试，不改产品行为。host 实际运行全部8个 `dns::tcp_upstream::tests`，8通过；`cargo check --target aarch64-unknown-linux-musl --tests` 通过，包含两个新 main owner 测试。主线程尚未执行这两个 Linux 测试，不能记为 owner 门通过。首次命令误用 `--exact` 加短 filter，执行0项；之后用正确 filter重跑1项、再跑8项，两次均实际通过。

8-step 门核对真正下游 stream 已读入全部9帧，`peek` 返回 WouldBlock 后 normal `wait_for_files` 0ready仍从input授权续4帧，再通过 probe poll续第9帧并读回9个正确A答案。64-step 门核对等待负fd/0events/已到期由 transport 真正预算尾生产，normal和probe均不依赖新下游或上游事件。缺失interface让内核/平台绑定路径立即失败，不手工塞入 `TcpWait`，不访问外网。Linux实跑仍须由主线程统一执行。

主线程随后报告实际Oracle `2c28` 库729通过、入口42/43；唯一失败是本测试最终预期rcode2，而实际为5。前面的真实预算、负fd、deadline、normal/probe empty-ready、queries1/Reading断言均已到达并通过。参考 `forward.c::tcp_talk` local_bind失败遍历server后返0，`tcp_request:2633–2634` 设置 EDE_NETERR=23，`:2732–2737` `m==0` 调 `make_local_answer(flags=0)`，`rfc1035.c:1370–1376` 的 nowhere-to-forward 分支固定REFUSED5；Rust `tcp_service:378–383/500–513` 对NoReply同样refusal(23)→error_reply(5)。原测试期望SERVFAIL是错误，现改为精确5，不允许2/5。原实际失败证据由root保留，修正尚待root重跑。
