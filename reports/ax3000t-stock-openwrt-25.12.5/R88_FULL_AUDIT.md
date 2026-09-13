# R88：九个 Rust 组件的完整代码审计与性能评估（对照原版）

日期：2026-09-13。审计对象：提交 `7eccfb0`（与 R87 正式构建 release-image 34716120045 同源，见 `R87_parts/r87_canonical_build.json`）。修复轮：提交 `d9c1048`，正式构建 release-image 34724293710（`R89_parts/r89_canonical_build.json`）。

## 0. 结论摘要

- **审计**：9 个组件各由一个只读子代理对照钉死的原版源码审计，根代理复核了每个组件的最高优先级发现并调整了三处严重度。共 1 个 P1（procd，R87 我自己的 P11 优化引入：总线持续可读时维护节拍饿死，硬件看门狗只在维护里喂）、1 个 P1 潜在（procd 启动期丢弃 hotplug 子进程回收）、12 个 P2、其余 P3；没有发现安全边界（ACL、路径、exec 白名单）上的放宽。
- **修复**：P1/P1 潜在与所有修复代价小、可用既有门验证的 P2/P3 共 14 项在 R89 修复轮修掉（8 个组件），新增探针证明 P1 在 R87 正式二进制上可复现、在修复版上消失；正式构建 → 构建机 65 道门 → 设备矩阵 → 备份 → 离线切换自测 → 部署 → 四个冷启动窗口按 R86/R87 流程重走一遍（§6）。
- **性能**：设备隔离矩阵 74 个负载、148 个延迟/CPU 中位数单元格，R87 构建 3 个高于原版（≤ +3.1%），R89 构建 1 个（httpd jsonrpc_c4 CPU +0.9%）；常驻 RSS 全部低于原版。HTTPD 64 个保持连接内存增量 +260 KiB（原版 +452，R86 +2096）。整机四窗口 13 条 lane 全部快于原版，procd lane −12.5% / CPU −12.2%（R86 +1.0% / +19.0%），mixed 吞吐 +16.2%，固定批次活动 CPU −27.6%，空闲守护进程 RSS 4.9 MB vs 9.4 MB。
- **稳定性/兼容性**：fuzz、限制、busy、资源耗尽、冷启动、断网恢复、离线切换等既有门全部通过；保留 22 项既有 HTTP 畸形请求差异与 §6.2 的 P3 级行为差异。
- **结论**：可以整体替代原版，附 §7 的条件；未解决风险见 §6.4。R89 修复轮已部署并通过四个冷启动窗口（§6.3），路由器现运行 R89 栈。

## 1. 方法与边界

- **代码审计**：9 个只读子代理并行，每个组件对照本仓库内钉死的原版源码（`private/stage2..6/src/*`、`private/upstream-ref/*`）逐路径比较；不改代码、不碰路由器和构建机、不运行 cargo。每条发现要求 Rust 与原版的 file:line 证据，分为 **confirmed**（代码即可确认的行为差异）、**potential**（依赖运行时条件或未能静态确定）、**intentional**（合同或既往报告已记录的有意偏差）。根代理复核了各组件的最高优先级发现（读源码、必要时读上游源码），并对子代理给出的严重度做了调整，调整处已注明。
- **组件基准**：R87 正式构建在 AX3000T 上的隔离矩阵（每侧 4 轮、交错顺序 stock/cand/cand/stock/stock/cand/cand/stock），uci 与 reload-config 的二进制与 R86 逐字节相同，沿用 R86 矩阵。方法与口径见 `R84_DEPLOYMENT_BENCHMARK.md`、`BENCHMARK.md`。
- **系统级对比**：R87 的四个冷启动窗口（Rust-1、stock-1、stock-2、Rust-2），整机真实客户端负载 13 条 lane、空闲前后资源、启动到健康时长；异常与压力场景沿用既有门（fuzz、限制、busy 门、资源耗尽门、断网恢复、重启 15/15、sysupgrade）并在 §5 汇总，不重新跑破坏性场景。
- **不做的事**：不对未读到的路径宣称等价；未执行的验证一律标为“未验证”。

## 2. 逐组件审计结果

每个组件的完整发现表、热路径开销、已核对等价清单和未验证项在 `R88_parts/audit-<组件>.md`。下面只列 confirmed / potential 中值得处理的项与根代理复核结论。

### 2.1 ubusd-rs（对照 `private/stage2/src/ubus`）

无 P0/P1。新的 epoll 就绪集与写兴趣切换经复核：所有写路径都进入 `Server::touched` 或紧跟 `sync_write_interest`（server.rs:153,166,433,490,972；main.rs:189），令牌是客户端 id 而非 fd，断开先 `poller.remove` 再 close（main.rs:217-222），EINTR 重试且信号写自管道，没有丢唤醒。

| id | 类别 | 级别 | 问题 | Rust 证据 | 原版证据 | 复核 |
|---|---|---|---|---|---|---|
| U-1 | potential（代码可确认，未量化） | P2 | 监听 fd 是水平触发；`accept` 遇 EMFILE/ENFILE 返回 Err 后直接 return，监听 fd 仍可读，`epoll_wait` 立即返回，daemon 在 fd 耗尽期间空转 100% CPU。C 的监听 fd 是 `ULOOP_EDGE_TRIGGER`，会睡到下一个连接到来。socket 权限 0666，任何本地用户可触发 | ubusd/src/sys.rs:246-250（只把 EAGAIN 映射为 Ok(None)）；main.rs:224-245（`Err(_) => return`）；main.rs:153 | ubusd_main.c:208-216, :361 | 根代理读源码确认；R87 之前的 poll 循环同样存在，不是 U05 引入。r41 只查 fd 有界，没做耗尽 |
| U-2 | potential | P3 | 对端 `shutdown(SHUT_WR)` 且读得慢时，EOF 后客户端因队列非空被保留，但 EPOLLIN 一直被置起，每轮重读 EOF 直到队列排空。libubus 客户端从不这样做 | main.rs:263-283；readiness.rs:89-96 | ubusd_main.c:221（客户端 fd 边沿触发） | 未量化 |
| U-3 | confirmed | P3 | 属性遍历遇到 raw_len 1..3 的属性即停止；libubox 跳过它并从 pos+4 继续。顶层消息 C 正常处理、Rust 答 INVALID_ARGUMENT；仅手工构造的报文能触发 | ubus/src/blob.rs:62-69；server.rs:1010,233,792,832 | blob.h:244-256；blob.c:243-252 | 根代理对照宏定义确认（`blob_pad_len >= 4` 对 raw_len 1..3 成立，`blob_parse_attr` 丢弃后继续） |
| U-4 | confirmed | P3 | ADD_OBJECT 同时带 OBJTYPE 与 SIGNATURE 时回复缺 OBJTYPE；libubus 只会带其一 | server.rs:227-229,243,286-290 | ubusd_proto.c:153-154 | — |
| U-5 | confirmed | P3 | 事件对象策略：重复字段 C 取第一个、Rust 取最后一个；`object` 接受 INT16/INT8 | server.rs:792-798,832-838；blob.rs:145-156 | blobmsg.c:211-214,226-227；ubusd_event.c:51-54,200-203 | — |
| U-6 | confirmed | P3 | TARGET 按宽度解码（短 payload 取 u16/u8 值）；C `blob_get_u32` 恒读 4 字节 | server.rs:607,657；blob.rs:24-31 | ubusd_proto.c:456,494 | — |
| U-7 | potential | P3 | ACL 文件加载不检查各键的 blobmsg 类型（C 要求 methods/tags 为数组、acl 为表）；只影响 root 拥有的文件 | acl.rs:243-247,253-257 | ubusd_acl.c:314-318,358-370 | — |
| U-8 | potential | P3 | 全量 lookup 被背压挂起、锚对象随后被删除时，续传从第一个对象重来（慢客户端收到重复对象）；C 此处是悬垂指针（use-after-free），Rust 更安全但不等价 | server.rs:407-410；client.rs:51-56 | ubusd_proto.c:214-239；ubusd_obj.c:202-225 | — |
| U-9 | potential | P3 | `try_prefix_batch` 的尺寸估算忽略字段补齐，非表类型方法项会在 debug 构建触发 `debug_assert`；release 只是重新分配。libubus 签名全是表 | server.rs:470-471,487；blob.rs:394-398 | ubusd_obj.c:37-51 | — |
| U-10 | intentional | — | 每客户端 1 MiB 发送队列静默丢弃与 `txq_ofs` 残留缺陷按合同 §3 复刻；`flush` 排空时清零 `txq_len` 是严格改进 | client.rs:125-131,152-155,277 | ubusd.c:143-163,182-183 | r41 drop 模式已比对 |

热路径：invoke 中继、STATUS、精确 lookup 都是借用凭据、一次 `scratch` 构建、一次 syscall，与 C 相当或更低（设备 invoke CPU −0.95%，lookup −13.6%）。可量化的多余开销只在事件分发（每接收方一次 `blob.clone()`）、全量 lookup（一次 id Vec）和监控镜像（仅 `ubus monitor` 挂着时）。每条入站消息的 `vec![0u8; raw_len]` 与 C 的 calloc 等价。与 C 一致保留的弱点：无界 `cmd_queue` 与 `patterns` 增长、`scratch` 不回缩、宣告 1 MiB 后停顿的客户端钉住 1 MiB。

### 2.2 httpd-rs（对照 uhttpd）

无 P0/P1。新的停泊设计经复核：截止时间从 accept/响应后一路带到 park→expire→resume；连接计数在每条关闭路径递减（main.rs:927,815,825,916,932,902）、停泊时不减；缓冲区里有字节时不会产生 Idle；TLS 只在无明文且无待写时停泊；`SO_RCVTIMEO` 在任何分派前恢复为 network_timeout（main.rs:548），正文读取与 CGI 中继不会看到 50 ms。

| id | 类别 | 级别 | 问题 | Rust 证据 | 原版证据 | 复核 |
|---|---|---|---|---|---|---|
| H-01 | confirmed | P2 | Basic 认证通过后 CGI 环境缺少 `REMOTE_USER`，合同 §4.2 列有此变量。设备未配置 realm，属潜伏缺陷 | cgi.rs:187-220（环境表无 REMOTE_USER） | proc.c:120,156；auth.c:172 | 根代理 grep 确认；r83_httpd_compat.py:110 只打印 HTTP_AUTH_*，无门覆盖 |
| H-06 | potential | P3 | 调用超时后的迟到回复被压入池化连接的 `pending` 且永不读取：每次超时多保留一条回复，连接池 ≤8 条，按超时次数无界增长 | ubus/src/conn.rs:217-219,230；bridge.rs:110-116（`Lease::drop` 只看 HUP/ERR，不看 `has_pending`） | libubus 丢弃未知 seq 的回复 | 根代理读 conn.rs:200-232 与 bridge.rs:110-116 确认：请求路径只从 socket 读，`pending` 只被对象服务路径消费，桥接不走该路径。不会误归属（seq/peer 必须匹配） |
| H-11 | potential | P3 | 到达 `-N` 上限时监听线程每 50 ms 轮询一次；连接线程释放槽位时不写唤醒管道。C 关闭时立即重新武装 | main.rs:844-847,927 | client.c:622；listen.c:77-84 | 根代理确认 |
| H-10 | potential（性能） | P3 | 50 ms linger 同样作用于新连接的第一个请求和每一次 rustls 握手往返：RTT ≳ 50 ms 的客户端每连接付出一次停泊 + 线程重生。LAN 不受影响 | main.rs:538；http.rs:233-239,293-301 | — | 未在 oracle 用 netem 量化 |
| H-02 | confirmed | P3 | 检查顺序 100-Continue → TLS 重定向 → RFC1918，C 为 RFC1918 → TLS → 100；`-R -q` 下私网到公网的明文请求得 307 而非 403。设备未开 `-q` | main.rs:576,642-669 | client.c:339-346 | — |
| H-03 | confirmed | P3 | `Authorization: Bearer` 在 `POST /ubus/call/<obj>` 大小写敏感，`/subscribe/` 不敏感；AUDIT_ROUND1 §5 已列，仍开放 | bridge.rs:520-526 vs 558-560 | ubus.c:132 strncasecmp | 根代理 grep 确认 |
| H-04 | confirmed | P3 | `-E` 错误处理器不处理文件处理器的 403；C 以 REDIRECT_STATUS=403 运行它。设备无 `-E` | main.rs:752；files.rs:357-382 | file.c:704-713 | — |
| H-12/13/14/16 | confirmed | P3 | `-q` 端口选择不优先 443；裸端口 `-p 80` 只绑 v4；CGI `Status: abc def` C 输出 `000 def`、Rust 忽略；ubusd 不可达时错误码 −32603 而非 −32000，`GET /ubus/list/x` 恒为 4 | main.rs:643-646,270-271；cgi.rs:544-551；bridge.rs:239-241,464-475 | listen.c:208-224,139-151；proc.c:209-219；ubus.c:793-795,313-317 | 设备均传显式地址，未受影响 |
| H-05/H-08/H-09 | intentional | P3 | 头阶段错误 Rust 补齐 chunked 终止符（协议正确、r27 去 chunk 后不可见）；chunked 扩展与 trailer 更宽松（未写入合同）；/ubus 畸形正文 400 而非 200+−32700（已列入 22 项已知差异） | http.rs:1121-1126,846-892；main.rs:684-687 | utils.c:59-97；client.c:495-529,508-518 | — |
| H-07 | potential | P3 | 批量响应先整体物化再发送（C 每 1 ms 流一项）；64 KiB 未认证 `list` 批量可达数 MiB/连接 | bridge.rs:171-180,499-508 | ubus.c:824-837,203-215 | 未量化 |
| H-15 | potential | P3 | 脚本槽队列 C 为 LIFO，Rust `notify_one` 顺序不定 | main.rs:241-264 | file.c:849,771 | — |

热路径：每次 RPC 回复 blobmsg→Json 树→字节两遍并整树分配（bridge.rs:271,282,592），是 jsonrpc_c4 CPU +3.1% 最可能的来源；每请求两次 `setsockopt(SO_RCVTIMEO)`、每 accept 三次 setsockopt + getsockname；池化 RPC 两次 `poll(0)`；CGI 静默期每 50 ms 一次 `try_wait`+poll。fd/进程卫生：全部 CLOEXEC、`ChildGuard` kill+wait、SSE 连接退出即释放、空闲池 ≤8；除 H-06 未见泄漏。

未验证：`files.rs:306-309` 断言 musl `strptime` 拒绝 `%Z`，故 If-Modified-Since 在设备上永不匹配，而合同 §3.5 写“≥ mtime → 304”，r14 的两条 if-modified-since 用例对设备通过——代码注释与合同不一致，需要看 r14 期望值才能定论。

### 2.3 rpcd-rs（对照 rpcd）

session/ACL、uci apply/rollback、file ACL 与 exec 白名单路径无 P0/P1。R45 字面/`*` 快路径经证明与递归匹配器等价（无 `*?[` 的模式只走空与字面分支，`m(p,n) ⇔ p == n`；空模式只匹配空名；NUL 由 `Field::as_bytes` 截断，与 C 字符串语义一致）。

| id | 类别 | 级别 | 问题 | Rust 证据 | 原版证据 | 复核 |
|---|---|---|---|---|---|---|
| F1 | potential | P2 | 工作线程创建失败会终止 daemon（release `panic = "abort"`）：7 处未检查的 `std::thread::spawn` 加 procwait 的 `scope.spawn`；C 返回错误状态继续服务。终止会丢掉全部会话和已武装的 `apply` 回滚（`apply_sid` 只在内存）。与 R86 F02 修掉的 httpd 同类 | file.rs:418；lucirpc.rs:921,933；rc.rs:213,236；rpcsys.rs:232；rrdns.rs:361；procwait.rs:26；Cargo.toml:22 `panic = "abort"` | file.c:973-976→1079；rc.c `case -1` | 根代理 grep 确认 7 处；可达性需 RLIMIT_NPROC/内存压力，未在设备复现 |
| F2 | potential | P3 | 直接子进程关闭 stdout/stderr 但继续运行：C 立即回 `{code:0}` 并放任其存活；Rust 等到真实退出，超时后 SIGKILL 并回 TIMEOUT（r13 已因 C 的竞态屏蔽 `file_exec_sh` 的 code） | file.rs:495-508,514；procwait.rs:37-41 | file.c:879-886,847-856,790-817 | — |
| F3 | potential | P3 | 输出超过 256 KiB：C 只关管道（子进程再写才因 SIGPIPE 死）；Rust 关管道、等 50 ms 后 SIGKILL | file.rs:486-493；procwait.rs:38-41 | file.c:864-865,810-814 | — |
| F4 | potential | P3 | 通配匹配器边界与 musl fnmatch 不同：未闭合 `[` 返回 false（musl 视为字面）、不支持 `[]x]`/POSIX 类、`?` 匹配一个字节而非一个字符；登录列表 C 用 flags 0（反斜杠转义）。设备 acl.d 全为字面或 `*`，不受影响 | glob.rs:19-45；session.rs:498,506 | session.c:146-147,926-982 | — |
| F5 | potential | P3 | 拒绝侧的 UTF-8 严格性：非 UTF-8 的 grant/revoke function 被跳过、acl.d 中非 UTF-8 function 被跳过、非 UTF-8 sid 回 INVALID_ARGUMENT 而非 NOT_FOUND；不会比 C 多授权 | session.rs:663,532,703 | session.c:571-590,626 | — |
| F6 | intentional | P3 | `uci get/state` 把非 UTF-8 选项值输出为 U+FFFD，C 原样字节；代码标注 DEVIATION，R83 F24 未覆盖 uci 转储 | uciobj.rs:223-233 | uci.c:509-541 | — |

热路径：`session access` 命中路径无堆分配；`uci get` 稳态两次 open、一次 flock、一次 Package 克隆（C 每次重新解析），设备 uci_get_network −13% 延迟、−21% CPU；循环每轮固定成本是 `delayed.reap`、会话到期提示比较、apply 截止检查、`try_recv`；`luci` 对象每次 `ubus_call` 新开一条 ubus 连接（非核心路径）。泄漏：核心路径未见；`timeout<=0` 的会话永不过期与 C 相同；HUP 时在飞的 `file exec` 子进程成为重执行进程的未回收子进程，C 亦然。

### 2.4 procd-rs（对照 procd）

这是本轮唯一的 **P1**，而且出在 R87 我自己的 P11 改动里，根代理已读源码确认并在本轮修复（见 §6）。

| id | 类别 | 级别 | 问题 | Rust 证据 | 原版证据 | 复核 |
|---|---|---|---|---|---|---|
| F1 | confirmed | **P1** | P11 循环只在 `poll()` 返回 0 时才承认“tick 已到”：`other = (*ready == 0 && !pending) || fds[1..]…`。只要总线 fd 持续可读（请求间隔小于 tick：空闲时 1 ms、有任何待办时 200 ms），`fire_timeouts`、`wdt.pump`、`pump_triggers`、inittab respawn、rc 超时全部不跑，硬件看门狗只在 `pump_pid1` 里喂。P11 之前每次唤醒都做维护，不可能发生。R87 设备矩阵单轮最长约 22 s，没有碰到 30 s 的看门狗超时，属于侥幸 | main.rs:516, 2541-2545, 1108-1112, 462-466, 907-911 | uloop_run_timeout() 每轮先处理定时器（上游 uloop.c，仓库未收录） | 根代理确认；修复：维护截止时间锚定在上一次维护，而不是上一次唤醒；oracle 探针 `tools/r89_procd_tick_probe.py`（见 §6） |
| F2 | potential | P1 | 启动期连接 ubusd 的重试循环丢弃非 ubusd 子进程的回收结果（`if dead == pid`）。`coldplug_done` 在最后一条命令入队 500 ms 后即返回，不等串行 hotplug 队列排空；此时若 `hotplug-call` 子进程退出，`Hotplug::reaped` 永不被调用，`child` 永远是死 pid，`start_next` 不再运行：按钮、exec 规则、固件加载整机寿命内失效，队列无界增长，`is_idle()` 恒假（永久 200 ms tick，也把 F1 的窗口拉到 200 ms） | main.rs:2386-2387；hotplug.rs:274-303, 305-330, 256-271, 332-337 | coldplug.c:41；hotplug.c:535,601,391（uloop 在任何状态都回收） | 根代理确认逻辑；在设备上是否真发生未证实（要求 connect 至少失败一次且队列仍在排空）。本轮修复：连接循环收集其它子进程的回收结果并转交 hotplug 队列 |
| F3 | confirmed | P2 | `service state {spawn:false}` 在 term_timeout 后升级为 SIGKILL；C 的 `instance_timeout` 只在 `in->halt` 时 kill，`service_handle_state` 以 halt=false 停止，忽略 SIGTERM 的进程在 C 下继续存活（running:true）。r65 的停止目标都响应 SIGTERM，故未被发现 | main.rs:422, 1987-2028 | instance.c:797-810；service.c:683 | 未改：需要先在沙箱确认 C 行为，再决定是记录为有意偏差还是改为测试 `inst.halt` |
| F4 | potential | P2 | `String::truncate(31)` 截 syslog ident `basename[pid]` 时若第 31 字节落在多字节字符内会 panic；PID 1 的 panic hook 是重启，被 enable 的服务会形成启动循环。触发条件：命令 basename 含非 ASCII 且 ident 超 31 字节并开启 stdout 捕获 | main.rs:555-556；sys.rs:450-470 | instance.c snprintf(ident,32,…) 按字节截断 | 根代理确认；本轮修复为字符边界截断（`syslog_ident`，附单元测试） |
| F5 | potential | P3 | 断连分支不排空实例管道：ubusd 消失期间（每轮退避 ≤1 s）多话的实例会阻塞在写满的 64 KiB 管道上，重连后解除 | main.rs:2486-2510 | ustream 独立于总线读 | 未改 |
| F6 | potential | P3 | 非 PID 1 模式下 `system watchdog {stop:false}` 打开 /dev/watchdog 但 `wdt.pump` 在 `NotPid1` 早退之后，永不喂狗；OpenWrt 上只是测试模式 | main.rs:907-911；watchdog.rs:131-142 | watchdog.c | 未改 |
| F7 | confirmed | P3 | 只带 `bundle` 的 OCI 实例通过启动门却因 `proc::start` 返回 “no command” 被当作 exec 失败 127 反复重生；C 用 ujail 运行。本设备不用 | proc.rs:286；main.rs:166-170 | instance.c:626-640 | 未改 |
| F8 | confirmed | P3 | 缺 `watchdog_print_status()`：看门狗复位后不再打印 “Watchdog has previously reset the system” | watchdog.rs:114-122 | watchdog.c | 未改 |
| F9/F10 | intentional | P3 | EOF 时冲出末尾半行、64 KiB 无换行阈值（C 的 ustream 丢末尾，R87 §P11 与 r85 控制项已记录）；待办期间定时器量化到 200 ms tick（合同 §11） | proc.rs:62-104；main.rs:453-467 | instance_stdio；uloop | — |

P11 时间源覆盖复核：所有时间驱动项（实例停止/重生/看门狗截止、trigger 去抖、rc/rcS 队列与超时、inittab respawn、hotplug 队列/按钮/coldplug、dispatch 50 ms、硬件看门狗）都在 `next_tick_ms` 的 pending 谓词里，但只在 poll 超时返回时才被处理（即 F1）；描述符驱动项（SIGCHLD 自管道、rc 输出、uevent、inotify、实例管道、关机信号）正确唤醒 `other`；只读方法分类（service list/get_data/validate、system info/board）无一派生子进程或武装定时器。

热路径：每次唤醒 `wait_activity` 重建 pollfd 并对 2+hotplug+inotify+2×带管道实例+rc 作业个 fd 做 `poll`（内核 O(N)，uloop 的 epoll 为 O(ready)）；`next_tick_ms` 每次扫描全部实例的两个截止时间；`dump_list` 每次重建回复并 `reset_bounded(16 KiB)`，超过 16 KiB 的列表（128 实例矩阵）每请求一次 realloc 链；请求存储复用。稳态无泄漏；唯一无界增长是 F2 卡住后的 hotplug 队列。

### 2.5 netifd-rs（对照 netifd）

| id | 类别 | 级别 | 问题 | Rust 证据 | 原版证据 | 复核 |
|---|---|---|---|---|---|---|
| F1 | confirmed | P2 | 通过 `network.reload` 删除 shell 协议接口时不运行其 teardown 脚本，helper 被 SIGKILL：`reload_checked` 先替换 `self.cfg`，`begin_teardown` 到新的 `cfg.interfaces` 里查名字落空，走静态路径（`mark_interface_down` → `pump_removals` → `Slot::terminate` = SIGKILL）；`proto_cmd`/`finish_proto_task` 同样早退。后果：udhcpc/odhcp6c/pppd 收不到 SIGTERM（无 DHCPv6 release、无 PPPoE PADT），teardown 脚本副作用被跳过，hotplug `ifdown` 只有一次 | main.rs:394-416, 461-486, 756-765, 2678-2721, 3189-3218, 1651-1653, 2410-2413；process.rs:196-206 | interface.c:349-366；proto-ext.c:795-810, 226-239 | 根代理读源码确认；本轮修复：被删接口的旧配置项保留到 `pump_removals` 才移除（该函数本来就负责移除配置项） |
| F2 | confirmed | P2 | `ifdown` 一个 DOWN 但仍持有主设备 claim（无载波）的接口，设备保持 claimed/IFF_UP；C 的 IFS_DOWN 分支调用 `device_release` | main.rs:2678-2690；claim 在 1455-1460 | interface.c:368-371, 1371-1375 | 未改；需 veth 无载波场景验证 |
| F3 | confirmed | P2 | 接口已 UP（或 DOWN）时 action-0 更新携带的 `data` 被丢弃，IUF_DATA/ifupdate 不触发（仅 data 变化） | main.rs:2181-2188, 2233-2251, 2262-2277 | proto-ext.c:418-421；interface.c:229-256, 869-873 | 未改；r52 用固定租期，两侧都不会置 IUF_DATA |
| F4 | confirmed | P2（仅 ppp 使用，本设备无） | S_IDLE 下 `setup_failed`（action 7）经 `iface_down` 清掉 autostart；C 发 LINK_LOST+TEARDOWN 且 autostart 保留，DOWN 后重跑 setup | main.rs:1887-1898, 2667-2675 | proto-ext.c:602-612；interface.c:900-906, 887-899, 832-843 | 未改 |
| F5 | confirmed | P3 | S_TEARDOWN/S_SETUP_ABORT 期间的 `renew` 被记住或执行，而非丢弃 | proto.rs:290-306 | proto-ext.c:741-757 | 未改 |
| F10 | confirmed | P3 | action 1 从不复位 `task_killed`，一次 teardown 后 S_TEARDOWN 的自动 SIGTERM 被跳过；dhcp/dhcpv6/ppp 都调用 proto_kill_command，设备无影响 | main.rs:1786-1800, 1822, 2447 | proto-ext.c:480 | 未改 |
| F6-F9, F11, F12 | potential | P3 | 缺 `network.interface.* restart` 方法；netlink ENOBUFS 只记日志不重同步；完全不写 syslog（全部 eprintln!，stock init 脚本下 logread 看不到 netifd）；`network restart` 不重新 exec；reload 触发的重启把新配置交给 teardown 脚本；action 5 不经 `interface_set_available` | ubus.rs:81-97；main.rs:4116-4127, 3822-3830, 1651, 1873-1882 | ubus.c:1114-1127；system-linux.c:177-206；main.c | 未改 |

热路径：每次循环唤醒（即每个 ubus 请求）先跑 reaper：对每个运行中子进程的 stdout/stderr 做非阻塞 read、每槽 `try_wait`、五个 `pump_*` 扫描——udhcpc+odhcp6c 存活时每次 `interface dump` 约 6 次 read + 6 次 waitpid；`interface dump` 每接口扫描 prefixes × prefix_assignments 并克隆字符串；`device status` 整体克隆 Device 并做实时 ethtool ioctl（C 相同）；每次链路事件与 ifup/ifdown 触发全量 RTM_GETLINK dump + 全设备 read_settings（约 6 ms CPU/次，代码注释记录）。设备数字仍全部低于原版（interface_dump −8.9%/−23.2%，wireless_status −80%/−95%）。无泄漏；`Config.errors` 从未被填充，`reload` 的“拒绝”分支是死代码（合同 F14 已记）。

### 2.6 fw4-rs（对照 firewall4 ucode）

无 P0-P2；解析器无 panic 路径（所有 `&str` 切片在 ASCII 字节索引处，unwrap 均有前一行守卫）。R09 上游语料逐字节通过、r29 随机配置差分通过。

| id | 类别 | 级别 | 问题 | Rust 证据 | ucode 证据 |
|---|---|---|---|---|---|
| F1/F2 | intentional（AUDIT_ROUND1.md:88 推迟，R83 未收口） | P3 | `list reflection_zone '*'`（反射 dnat）与不带 `port` 的 CT helper：ucode 整次运行以 254 中止，Rust 跳过该项渲染出合法规则集。后者随附 helpers 文件 12/12 带 port，不可达。R83 已把 defaults/include 收成“像 ucode 一样中止”，这两处可同法收口，各约 10 行 | sections.rs:1526-1531；608-612 | fw4.uc:1071-1072,2921-2928；2225,1695-1696 |
| F3 | confirmed | P3 | 加载中止后 `fw4 start/reload` 退出码 254，shell 包装为 1 且 stderr 有“Unable to read firewall state” | main.rs:80-82,325-326 | /sbin/fw4:22-40；main.uc:5-13 |
| F4 | confirmed | P3 | `fw4 -q check` 仍打印 `raw_warn`（shell 把 stdout/stderr 都重定向到 /dev/null） | parse.rs:377-379；main.rs:362-368 | /sbin/fw4:114-121 |
| F5/F6/F7 | confirmed | P3 | 用法文本无空行；ubusd 不可达时缺“Unable to connect to ubus”警告；`fs.error()` 文本只硬编码了 ENOENT/EACCES | main.rs:257-283；input.rs:158-165；emit.rs:243-248 | /sbin/fw4:128-165；fw4.uc:600-610,1865 |
| F8-F11 | potential | P3 | zone `log '0.5'` 真值差异；`list device '*'` 是否保留 null 项（与代码注释相反）；include 被信号杀死时退出码 −1 vs 负信号号；`monthdays 'foo'` ucode 可能因 NaN 下标中止 | sections.rs:1071-1073,643-648；input.rs:318-329；parse.rs:883-897 | fw4.uc:2403,2202,1404-1410；main.uc:128-136 |

开销：每次运行三条 ubus 连接（ucode 前两者共用一条）、`Defaults` 每次策略查询整体克隆、Zone 三遍克隆——常数级；设备 print 99.2 ms→10.7 ms、check 148 ms→60.9 ms。UCI 加载委托共享 `owrt_uci` crate，本轮未在此重审。

### 2.7 logd-rs（对照 ubox logd）

| id | 类别 | 级别 | 问题 | Rust 证据 | 原版证据 | 复核 |
|---|---|---|---|---|---|---|
| F1 | confirmed | P2（子代理评 P1，根代理下调） | `log write` 的 `event` 含非 UTF-8 时整条静默丢弃但仍回 OK：`as_str()` 为 None 跳过 add 块，`reply_status(OK)` 无条件执行。只有发原始 blob 的客户端能构造该输入（JSON CLI 不能），因此下调；但既然报文路径（F3）已记录“有损转换”策略，`log write` 至少应同样有损转换而不是丢弃 | main.rs:250-266；ubus/src/blob.rs:141-143 | logd.c:165-190 | 根代理读源码确认；r28 语料无非法 UTF-8 的 `log write` 用例 |
| F2 | confirmed | P3 | `log write` 在字符边界截断，C 在原始字节 LINE_SIZE−1 截断 | main.rs:256-262 | logd.c:180-183 | — |
| F3 | intentional | P2 | /dev/log 报文的非法 UTF-8 用 U+FFFD 改写，C 原样存字节（AUDIT_ROUND1.md:91 推迟，仍开放） | ring.rs:156 | log_add(char*,len) | — |
| F4 | 与 C 等价（子代理评 potential P2，根代理改判） | P3 | 每流客户端的 `pending` 积压无上限。根代理读上游 libubox ustream.c：`ustream_init_defaults` 置 `w.max_buffers = -1`，`ustream_can_alloc` 对 ≤0 恒真，故 C logd 在 64 KiB 管道之后的用户态写缓冲同样无界；两侧对停滞的 `logread -f` 都不断开 | main.rs:84-111,157-160,210-216 | logd.c:125 + ustream.c（上游 master，钉死版本未逐字比对） | 改判为对等 |

开销：`drain_kmsg` 每次唤醒只 read 一次（C 循环排空），水平触发下正确但突发时多几次 poll/read；每条消息一次 String 分配（C 单一 arena memcpy），受环容量约束。设备 syslog_128 −82%/−73%，log_read_100 −41%/−49%。

### 2.8 uci-rs（对照 libuci/uci）

二进制与 R86 逐字节相同，本轮未改。

| id | 类别 | 级别 | 问题 | Rust 证据 | 原版证据 | 复核 |
|---|---|---|---|---|---|---|
| U1 | confirmed | P3（子代理评 P2，根代理下调） | 把节/选项重命名为非 UTF-8 字节时，内存中的名字被有损转换（`Section.name: String`）；同一进程内（`uci batch`）随后的 show/export/commit 会输出或持久化 U+FFFD，C 保留原字节。增量文件本身按字节原样写入（测试 `rename_to_non_utf8_is_accepted_like_c`），且两侧在回放时都用 `validate_name` 拒绝该行，因此分开的 CLI 调用不受影响。下调理由：只有一个 batch 内先改名为非法 UTF-8 再 show/export/commit 才能观察到 | ops.rs:405-438（419 处 `from_utf8_lossy`）；model.rs:162；export.rs:41 | list.c:486-513 `uci_rename` 原样 strdup | 根代理读源码确认 |

已核对等价：FLAG_EXPORT_NAME 默认关闭仅由 `-n/-N` 打开；commit 原子序列（锁 → 保存并重导入 → 零变更早退 → mkstemp → flock 临时文件（容忍 ENOSYS）→ 写+fsync → realpath+stat+chmod+rename，失败 unlink）；增量命令字符；匿名节 djbhash 命名；`Cmd::Add` 回放修正；`do_add` 原始退出码；`show_changes` 格式；改名在实时调用与增量回放间的校验不对称（libuci 同样）；导出转义与字节保真；错误码/文本 1-7；argv 原始字节；`strtol` 空白跳过；CLI 选项集与 getopt 串。

开销：`ReadCache`（读缓存）只接入 rpcd，CLI 一次性进程用不到；`opendir/readdir` 裸 FFI 快路径（file.rs:259-321）与 `std::fs::read_dir` 回退并存，对几十个文件的目录是维护成本而非正确性问题；`try_literal_line`（parse.rs:593，2026-09-11 在上次 uci 审计之后加入）没有 C 对应物可差分，正确性只靠仓库自身测试，是下次 r24 fuzz 的首要目标。

未验证：`uci_validate_name/str/package` 的 C 定义未定位；`list.c` 的 `uci_delete/uci_add_list/uci_del_list/uci_set` 正文未读；此前记录的 `add_list` 空串 vs NULL、`uci_import` feof 差异未重新推导；临时文件是否在写入前 flock 未逐行确认。

### 2.9 reload_config_rs（对照 17 行 shell 脚本）

该 crate 不依赖 `components/ubus`，与脚本一样 fork `uci`/`md5sum`/`ubus`。事件载荷、扫描集合、首次运行零事件、增/改/删不对称（C-04）、顺序保持与不重试（C-08）、基线原子写入均与合同和 procd 消费端（service.c:760-804，trigger.c:289-306）逐条核对一致。

| id | 类别 | 级别 | 问题 | Rust 证据 | 参考 | 复核 |
|---|---|---|---|---|---|---|
| F1 | confirmed | P2 | 运行锁 `flock(LOCK_EX)` 等待不看取消标志（只重试 EINTR），而程序中其它所有阻塞等待每 10 ms 轮询 `cancelled`；README 声称 SIGINT/SIGTERM 失败关闭。第二个实例在第一个持锁期间收到 SIGTERM 会阻塞到前者结束（受前者超时约束，故 P2） | unix.rs:20-31；engine.rs:85-95,105（取锁在首个 `cancelled.load` 之前，121） | 脚本无锁（新代码，非回退） | 根代理读源码确认 |
| F2 | intentional（合同未写） | P3 | 硬上限 4096 个配置项 / 基线 ≤4096×320 字节，超出即 `InvalidInput` 退出；脚本无上限 | engine.rs:14-15,228-231,401-406 | 合同 C-01 未列 | 建议补合同 |
| F3 | potential | P3 | 两套 JSON 转义（字节级 engine.rs:494 用于 ubus 载荷；字符级 trace.rs:88 用于 JSONL 跟踪）可能漂移 | engine.rs:494-508；trace.rs:88 | — | — |

开销：一次 `md5sum <files>` + 内存比对取代两次 md5sum；每配置一次 `uci show` 与脚本 1:1；子进程等待改为辅助线程阻塞 `wait` + 10 ms 取消轮询（旧的 try_wait 轮询曾在 38 个子进程时多花约 330 ms）。设备 unchanged_config 40.2 ms→25.4 ms（−36.7%），CPU −36.5%。

## 3. 组件基准（设备、正式构建）

来源：`R87_parts/<组件>/results.{md,json}`（httpd、rpcd、procd、ubusd、netifd、logd、fw4），`R86_parts/{uci,reload-config}`（二进制逐字节相同，`validation.json` 的 `exact_binary_identity_reuse`）。每侧 4 轮，数值为逐轮统计的中位数，负数表示 Rust 更低。

| 组件 | 负载数 | 延迟+CPU 单元格 | 高于原版的单元格（含 p99） | 常驻 VmRSS 原版/Rust KiB | fd | 线程 |
|---|---:|---:|---|---|---|---|
| httpd | 16 | 32 | jsonrpc_c4 CPU +3.1% | 1028/996 | 8/11 | 1/1 |
| rpcd | 18 | 36 | 无 | 2004/1180 | 11/7 | 1/1 |
| procd | 8 | 16 | service_list_32_c4 p99 +4.5% | 1142/984 | 8/7 | 1/1 |
| ubusd | 10 | 20 | lookup_all_64 延迟 +0.9%，lookup_all_128 延迟 +1.9%，invoke_c4 延迟 +2.8% / p99 +5.4%，lookup_c4 p99 +0.8% | 976/616 | 11/8 | 1/1 |
| netifd | 14 | 28 | interface_named_32 p99 +1.1% | 2212/1208 | 19/10 | 1/1 |
| logd | 2 | 4 | 无 | 1014/508 | 10/7 | 1/1 |
| fw4 | 2 | 4 | 无（print −89.2%，check −58.9%） | 一次性进程 | | |
| uci（R86） | 3 | 6 | 无 | 一次性进程 | | |
| reload-config（R86） | 1 | 2 | 无 | 一次性进程 | | |

合计 74 个负载、148 个延迟/CPU 单元格，3 个高于原版（均 ≤ +3.1%），CPU/次除 jsonrpc_c4 外全部低于原版。httpd 多出的 3 个 fd 是唤醒管道两端与 epoll fd。

**用户提出的三处回退在正式构建上的现状**

| 项目 | R86 | R87 正式构建（设备） |
|---|---|---|
| HTTPD 64 个保持连接 RSS 增量 | +2096 KiB（原版 +452） | **+256..260 KiB**（原版 +452），持有期间线程数 1、fd 71；关闭后 Rust 不回落（musl 分配器保留，VmHWM 2320 KiB 是 128 个请求在线程上服务时的瞬时峰值），原版回落到 +12 |
| ubusd 精确 lookup p99 | +13.81% | c1 **−9.38%**，c4 +0.80%（单轮离群，见下） |
| rpcd 个别 p95/p99 | 小幅上升 | 18 个负载中只剩 uci_configs c1 p95 +8.5%（p99 −2.3%，均值 −11.8%，CPU −21.1%） |
| 整机 service list 均值 / 控制面 CPU | +1.02% / +18.96% | 见 §4 |

**残余的 c4 尾延迟**：候选在 c4 的 p99 逐轮离散度是原版的 3–10 倍（ubusd lookup_c4 p99 各轮 304/529/374/305 vs 366/329/344/316 µs，sd 91.5 vs 18.8；procd service_list_32_c4 p99 2002/1710/2244/1673 vs 1767/1801/1785/1742，sd 232.6 vs 21.8），而均值与 subject CPU 更低且同样紧。每轮温度 61.9–62.5 °C 两侧持平，排除热节流。根因未归因（需要设备上的逐轮调度追踪）；不构成算法问题的证据。

## 4. 系统级对比（整机）

来源：R87 正式构建的四个冷启动窗口（Rust-1、stock-1、stock-2、Rust-2，2026-09-12 22:12–23:34 UTC；`R87_parts/results.json`、`summary.json`、`deployment.json`），每窗口 5 轮、13 条真实客户端 lane，另有空闲前后各 120 s 的资源采样与 TLS 限速 lane。R89 修复轮的四个窗口见 §6.3。

**典型负载（整机，每侧两次冷启动的中位数，负数为 Rust 更低）**

| lane | 平均延迟 | p99 | 服务端 CPU/次 |
|---|---:|---:|---:|
| procd（service list） | −12.47% | −6.18% | −12.21% |
| rpcd | −18.35% | −8.45% | −20.87% |
| network（netifd） | −27.11% | −15.25% | −34.19% |
| http-static | −10.82% | −9.76% | −16.88% |
| http-jsonrpc | −13.38% | −12.44% | −16.28% |
| log | −41.84% | −26.89% | −46.39% |
| uci | −39.50% | −32.70% | −47.37% |
| fw4 | −92.32% | −92.06% | −92.23% |
| mixed（四类并发） | http −14.91%、network −19.22%、procd −10.30%、rpcd −21.37% | −12.2%…−19.3% | 总计 −18.05%，吞吐 +16.18% |

R86 报告里两处整机回退（service list 均值 +1.02%、控制面 CPU/次 +18.96%）在 R87 全部转为下降；根因是 ubusd 的 O(客户端数) 就绪集重建（设备约 18 个总线客户端），见 `R87_ALGORITHM_REVIEW.md` §2.1。

**持续负载**：每窗口固定批次（500 650 次操作）的服务端活动 CPU：原版 388.3 / 388.3 s，Rust 282.8 / 279.3 s（−27.6%）。

**空闲**（每窗口空闲前 120 s、121 个样本的中位数）

| 指标 | 原版（两窗） | Rust（两窗） |
|---|---|---|
| 守护进程 RSS 合计 | 9424 / 9272 KiB | 4880 / 4864 KiB |
| 守护进程匿名内存合计 | 2268 / 2260 KiB | 1296 / 1280 KiB |
| 守护进程 CPU（单核 %） | 0.075 / 0.075 | 0.025 / 0.025（R86 为 0.042，P11 生效） |
| 系统繁忙容量 % | 1.00 / 1.20 | 1.61 / 0.94 |
| MemAvailable | 139.5 / 138.7 MB | 131.9 / 132.3 MB |

MemAvailable 低 6–7 MB 与 R86 相同口径：九个 Rust 入口文件 7.6 MB（原版 0.5 MB）在身份校验后留在页缓存，守护进程自身的内存更低。

**启动与健康**：首次 SSH 50.2 / 40.3 s（Rust）vs 40.3 / 40.3 s（10 s 轮询粒度）；健康确认 270.7 / 262.4 s vs 266.2 / 266.8 s；四窗口配置、执行面与 nft 规则（计数器归一化后）一致；客户端 DHCP、本地 HTTP/HTTPS、经路由器的 IPv4/IPv6 DNS、看门狗运行、两个无线 AP 桥全部通过。

**TLS**（限速 20/s 的 fresh lane 不比较吞吐；同套件 AES256-GCM 的 keep-alive/fresh 每请求 httpd CPU）：keepalive-c1 −53%、keepalive-c4 −55%、fresh-c1 −86%、fresh-c4 −86%，平均延迟 −19%…−42%。

**交互开销**：Rust 组件之间的交互（procd↔ubusd↔rpcd↔netifd）没有单独的协议开销——线协议逐字节兼容（ubusd r42 逐字节相同、rpcd r26 733 步 0 差异、netifd 29 场景），mixed lane 的总服务端 CPU −18.05% 已经包含所有交互路径。

## 5. 稳定性、压力与异常场景（既有证据汇总）

不重跑破坏性场景；下面是正式构建验证（`R87_parts/validation.json`，58 道门，53 道必需门全部通过，392 个单元测试）与既有设备/沙箱证据的汇总。

| 场景 | 证据 | 结果 |
|---|---|---|
| 畸形输入 fuzz | httpd r27 133 例；rpcd r26 733 步；ubusd r42 固定表+600 变异；logd r28 33 组；fw4 r29；uci r24 | httpd 仅保留 22 项既有差异（多为 Rust 更早拒绝）；rpcd 0 差异；ubusd 逐字节相同；logd 0 差异；fw4/uci 通过 |
| 协议/资源限制 | ubusd r41：消息上限 1048576 二分实测两侧一致；1.3 MiB 全量 lookup 压给只发不读客户端，两侧 daemon 存活、RSS 与 fd 有界 | 一致 |
| 资源耗尽恢复 | HTTPD 资源耗尽门（R86 F02 之后）：限制期原版接受 3/3、Rust 0/3，解除后两侧各 4 个请求成功、连接槽与 fd 恢复、进程存活；`httpd-resource` 门在 R87 验证通过 | 恢复行为一致，限制期 Rust 更保守 |
| 持续负载 | rpcd busy 门、procd 五组双侧 busy 门（原版侧第 4、5 组 exit 1 为已记录的日志丢尾控制项） | 候选全部通过 |
| CGI 压力 | httpd-cgi-stress（单独运行 exit 0；三个 harness 并发时曾 exit 1 一次，见 R87 §4.1） | 通过，附并发噪声记录 |
| PID 1 / TTY / sysupgrade | procd r71 / r72 / r75 门 | 通过 |
| 冷启动与重启 | R23 15/15 重启；R86 四窗、R87 四窗（§4） | 通过 |
| 断网恢复 | R79/R80：netifd-rs 四次窗口两处真机缺口（DSA 口晚注册、resolv.conf.auto）已修；canary 480 s 自动回退验证 | 已修复并在后续窗口通过 |
| 离线切换/回退/救援 | `offline_switch` 五项门（inert 安装、冷阶段保留原件、过早确认与过期定时器拒绝、失败恢复、救援） | 通过 |

本轮审计新识别、尚无门覆盖的异常场景：ubusd fd 耗尽（U-1）、ubusd 半关闭慢读对端（U-2）、httpd 调用超时后的 `pending` 增长（H-06）、rpcd 线程创建失败（F1）、logd `log write` 非 UTF-8（F1）、reload_config 持锁期间 SIGTERM（F1）。

## 6. 问题清单与未解决风险

### 6.1 本轮确认并已修复（R89 修复轮，提交 d9c1048，正式构建 release-image 34724293710）

| 组件 | 项 | 级别 | 修复 | 验证 |
|---|---|---|---|---|
| procd | F1 维护节拍饿死 | **P1** | 维护截止时间锚定在上一次维护而不是上一次唤醒 | 新探针 `tools/r89_procd_tick_probe.py`：R87 正式 procd-rs 在 8 个只读 `service list` 加载器下 `service delete` 5 s 后子进程仍存活（10657 次请求）；原版 C 与 R89 修复版都已 SIGKILL（18326 / 13988 次请求）。r85 busy 五组、r65、r71、r72、r75 全部通过 |
| procd | F2 启动期丢弃非 ubusd 回收 | P1（潜在） | 连接重试循环收集其它子进程的退出并转交 hotplug 队列 | r71 PID 1 探针通过；设备四窗口 hotplug 依赖的无线与按钮路径健康（未做专门的 hotplug 存活断言，见 6.4） |
| procd | F4 ident 截断 panic | P2 | `syslog_ident` 按字符边界截断，附单元测试 | 单元测试 |
| netifd | F1 reload 删除接口不跑 teardown | P2 | 被删接口的旧配置项保留到 `pump_removals` | netifd 29 场景套件通过（含 r83 lifecycle remove） |
| httpd | H-01 缺 REMOTE_USER | P2 | `CgiContext.remote_user` 由认证结果填入 | r83 兼容、r14、r27 fuzz、r85 静态、r86 资源门通过 |
| httpd | H-06 迟到回复滞留连接池 | P3 | `Lease::drop` 丢弃带 `pending` 的连接 | 同上 |
| httpd | H-03 Bearer 大小写 | P3 | call 路径改为大小写不敏感 | 同上 |
| httpd | H-11 上限时不唤醒监听 | P3 | 释放槽位时写唤醒管道 | 同上 |
| ubusd | U-1 EMFILE 下空转 | P2 | accept 失败后把监听 fd 移出就绪集，断开一个客户端后恢复 | r36/r36-ubus/r83/r42（逐字节相同）/r41 通过 |
| rpcd | F1 线程创建失败终止 daemon | P2 | `Deferrer::defer` 用 `Builder::spawn`，失败即回 UNKNOWN_ERROR；procwait 退化为轮询 | r13/r17/r18/r19、busy、r26（见 6.4）、bytes、defer 通过 |
| logd | F1 `log write` 静默丢弃非 UTF-8 | P2 | 与报文路径相同的有损转换 | r15/r28/r21/r25/环形/超大读取通过 |
| reload_config | F1 锁等待不可取消 | P2 | `LOCK_NB` + 10 ms 取消轮询，附单元测试 | r1 差分（正式二进制）通过；oracle 本地构建版因 512 KiB 尺寸预算失败，正式构建 432 KiB 级别通过 |
| fw4 | F1/F2 两处 null 访问不中止、F4 `-q check` 仍输出 | P3 | `aborted` 标志令 `load()` 返回 Err（退出 254）；check 下 `-q` 静默 stdout/stderr | R09 上游语料、r29 fuzz 200 例、defaults、镜像内 print 通过 |

R89 正式二进制的构建机验证：65 道门、60 道必需门全部通过，441 个单元测试；原版侧 procd busy 第 4 组的控制项失败（日志丢尾，R85 起记录）。rpcd r26 首次 733 步中 1 步不同（`luci getFeatures` 的 `netifd_vrf`，环境探测值，一侧 true 一侧 false），两次完整复跑 0 差异，三份日志保留（`R89_parts/validation.json`）。

### 6.2 确认但未修复（记录为已知差异或待下一轮）

- procd F3：`service state {spawn:false}` 在 term_timeout 后 SIGKILL，C 不 kill（需先在沙箱确认 C 行为再决定）；F5 断连期间不排空实例管道；F6 非 PID 1 模式看门狗不喂；F7 bundle-only 实例；F8 缺看门狗复位日志。
- netifd F2（DOWN 且持有 claim 的接口 `ifdown` 不释放设备）、F3（已 UP 时 data-only 更新丢失）、F4（S_IDLE 下 setup_failed 清 autostart，仅 ppp）、F5（teardown 期间 renew 不丢弃）、F10（`task_killed` 不复位）、F6–F9/F11/F12。
- httpd H-02/H-04/H-05/H-07/H-08/H-09/H-10/H-12–H-16（设备配置不触发或属既有 22 项差异）。
- ubusd U-2–U-9（手工报文或慢读对端才能触发）。
- rpcd F2–F6（exec 生命周期差异、fnmatch 边界、拒绝侧 UTF-8 严格性、uci 转储 U+FFFD）。
- logd F2/F3（截断边界、报文路径有损转换——后者为 AUDIT_ROUND1 记录的有意策略）。
- uci U1（同一 batch 内非 UTF-8 改名的 U+FFFD）。
- fw4 F3/F5–F11（退出码、用法文本、警告文本、ucode 真值边界）。
- reload_config F2（4096 项硬上限，建议写入合同）、F3（两套 JSON 转义）。

### 6.3 R89 部署与窗口

R89 正式构建于 2026-09-13 07:25 UTC 经 Wi-Fi 部署（备份三份归档、两份恢复镜像校验，overlay 可用 29 152 KiB，需 22 629 KiB），四个冷启动窗口 Rust-1、stock-1、stock-2、Rust-2 全部健康，最终九个组件身份核对通过，设备停留在 R89 Rust 栈（`R89_parts/deployment.json`、`results.json`、`summary.json`）。

| 项 | R89 结果（Rust vs 原版） | R87 同项 |
|---|---|---|
| 整机 lane 平均延迟 / 服务端 CPU | procd −11.92% / −12.50%，rpcd −18.57% / −20.07%，network −26.26% / −33.84%，http-static −12.74% / −17.73%，http-jsonrpc −13.64% / −16.08%，log −42.02% / −46.78%，uci −40.62% / −47.37%，fw4 −92.5% | procd −12.47% / −12.21%，其余同量级 |
| mixed 总吞吐 / 服务端 CPU | +16.56% / −17.89% | +16.18% / −18.05% |
| 固定批次活动 CPU | 389.0 / 389.7 s → 283.6 / 280.8 s（−27.5%） | −27.6% |
| 空闲守护进程 RSS 合计 | 9408 / 9440 → 4796 / 4800 KiB | 9424 / 9272 → 4880 / 4864 |
| 空闲守护进程 CPU（单核 %） | 0.083 / 0.067 → 0.025 / 0.042 | 0.075 → 0.025 |
| 空闲 MemAvailable | 139.0 / 138.4 → 131.7 / 131.1 MB | 同口径差额 |
| HTTPD 64 保持连接 RSS 增量 | 原版 [452, 452, 452, 452] KiB → Rust [264, 256, 248, 268] KiB | +452 → +256..260 |
| 首次 SSH / 健康确认 | 50.3 / 100.4 s（Rust）vs 50.3 / 70.3 s；279.0 / 323.7 s vs 274.9 / 296.7 s | 50.2 / 40.3 vs 40.3 / 40.3；270.7 / 262.4 vs 266.2 / 266.8 |

后两个窗口（stock-2、Rust-2）两侧都比前两个窗口晚被 10 s 粒度的轮询看到 SSH，健康确认相应推后；四窗口的配置、执行面与 nft 规则一致，客户端 DHCP、本地 HTTP/HTTPS、经路由器的 IPv4/IPv6 DNS、看门狗与两个 AP 桥全部通过。修复轮没有改变任何热路径的性能：与 R87 相比 procd 每请求 CPU 之差在 ±0.8% 内，整机各 lane 在 ±1.5 个百分点内。

### 6.4 未解决风险与未验证项

- procd F2 在设备上是否曾经发生未证实：没有窗口断言过启动后 hotplug 存活；建议在 r71 探针加 coldplug `exec /bin/sleep 3` + 事后 uevent 断言。
- c4 尾延迟离散度（§3）根因未归因。
- httpd `If-Modified-Since` 的代码注释与合同 §3.5 不一致（§2.2 未验证项）。
- rpcd r26 的 `netifd_vrf` 一步差异说明该探测值在沙箱内不稳定，非 Rust 缺陷，但门本身存在偶发红。
- 覆盖有限：审计聚焦高爆炸半径路径，各组件“已核对等价”清单之外的路径未逐行比较；iwinfo/rrdns/luci-rpc、无线脚本广度、`owrt_uci` 内部未重审。
- 设备 overlay 上现有三份栈包（/root/r84 = R89、/root/r84-prior-r89 = R87、/root/r84-prior-r87 = R86），R89 前可用空间 29 MB；验收后应删除最旧的一份。

## 7. 能否完全替代原版

**可以整体替代，附条件。** 九个组件在功能门（65 道，含逐字节的 ubusd 线协议 fuzz、733 步 rpcd 差分、29 场景 netifd 套件、133 例 HTTP fuzz）、隔离矩阵（74 个负载，延迟/CPU 全部或近乎全部低于原版，常驻内存全部更低）和整机四窗口（13 条 lane 全部更快、活动 CPU −27.6%、空闲守护进程内存减半）上都优于或等于原版；本轮发现的唯一 P1 出在 R87 自己引入的优化里，已在 R89 修复、用能区分好坏二进制的探针证明、重新过完整流水线并部署（§6.3）。

条件与保留：(1) 22 项既有 HTTP 畸形请求差异与本轮列出的 P3 级行为差异（§6.2）继续作为已知差异存在，其中多数是 Rust 更严格或设备配置触不到的路径；(2) §6.4 的未验证项，尤其 procd 启动期 hotplug 存活断言，应在下一轮补门；(3) MemAvailable 低 6–7 MB 是静态二进制的页缓存代价，守护进程自身更省。

## 8. 证据索引

- 审计：`R88_parts/audit-{ubusd,httpd,rpcd,procd,netifd,fw4,logd,uci,reload-config}.md`（子代理发现表 + 根代理复核）。
- 组件矩阵：`R87_parts/<组件>/results.{md,json}`、`R89_parts/<组件>/results.{md,json}`；uci 沿用 `R86_parts/uci`。
- HTTPD 路由器内存：`R87_parts/httpd_memory_router.json`、`R89_parts/httpd_memory_router.json`。
- 整机：`R87_parts/{results,summary,deployment}.json`、`R89_parts/{results,summary,deployment}.json`。
- 构建机验证：`R87_parts/validation.json`、`R89_parts/validation.json`（65 道门、日志 sha256）。
- 正式构建身份：`R87_parts/r87_canonical_build.json`、`R89_parts/r89_canonical_build.json`。
- 探针与门脚本：`tools/r89_procd_tick_probe.py`（新）、`tools/r85_procd_busy_gate.py`、`tools/r26_rpcd_fuzz.py`、`tools/r42_ubusd_fuzz.sh`、`tools/netifd_suite.sh`、`tools/r27_httpd_fuzz.py` 等。
- 既往报告：`R87_ALGORITHM_REVIEW.md`、`R86_PERFORMANCE_REVIEW.md`、`R86_REGRESSIONS_COMPLETE.md`、`AUDIT_ROUND1.md`、`R30_STABILITY_REVIEW.md`、`R83_R81_FIXES.md`。
