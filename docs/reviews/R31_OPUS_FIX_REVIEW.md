# 给 Opus 的执行指导：复审 d1520f9 与补齐上传路径

日期：2026-09-05。审查基线：`d1520f9c1636f6e95932356de026771b3c858815`。
本轮只审查、运行本机测试、编写指导；未修改生产代码、测试代码、Cargo 清单或发布脚本，未操作路由器。

## 结论与执行顺序

修复方向正确，原 R30 四个探针都通过，70 个 host 单元测试通过。但不能将 R30-01..04 标成完整关闭：发现一个 rpcd 输出溢出回归、两个 CGI 生命周期缺口。先补这些，再做 R30-05 请求流式上传，最后独立升级工具链。每步独立提交、记录差分结果。

不要恢复完整响应 Vec，也不要只提高 4 MiB 上限。资源修复的目标是固定内存、明确截止时间、正确收尾，而不是用更大的限制推迟失败。

## A. P1：rpcd 输出溢出后仍等待被自己阻塞的子进程

位置：`components/rpcd/src/file.rs:325–357,391–400`。

`Pipe::read_ready()` 在 256 KiB 时把 `open=false`，但仍持有 `File`。子进程继续输出，管道写满后阻塞；主循环先等待子进程退出/超时，直到最后才检查 overflow，最终错误返回 TIMEOUT。默认 exec timeout 为 120 秒，这期间同步 `file exec` 占住 rpcd 主循环。

本机原样提取当前 `run_command` 和 Pipe/poll helpers，链接实际 owrt_ubus 并引用实际 procwait，500 ms timeout：

| 命令 | 结果 |
| --- | --- |
| `/bin/sh -c 'head -c 1048576 /dev/zero'` | 553 ms，Err(7) TIMEOUT |
| 同命令输出重定向到 stderr | 559 ms，Err(7) TIMEOUT |
| `printf ok` | 8 ms，成功 |

匹配参考树 `private/stage5/src/rpcd/exec.c` 的 stdout/stderr read callback 在 `ustream_read_buf_full()` 时立即安排 NOT_SUPPORTED 回复。

执行要求：

- 将 overflow 当成独立的结束原因，检测后立即收尾，不能先继续等待 timeout，也不能被后续 TIMEOUT 覆盖。
- 真正释放/关闭 capture fd；按参考语义收口直接子进程和回收责任。关闭布尔值不等于关闭 fd。
- 所有退出路径正确回收直接子进程。不要为了关闭后代的管道而任意杀服务进程组，`file exec` 可以运行合法的 daemonizing command。
- 回归测试覆盖 stdout、stderr、两路同时超限、持续写入、临界大小、输出后 sleep、子进程忽略 SIGPIPE；预期状态对照原版，不只断言“很快结束”。正常小输出内容与退出码仍须一致。
- 做实际 ubus 并发探测：异常命令结束后，其他 RPC 和 session/apply timer 正常推进。仍须说明正常长命令同步占用主循环是已有架构限制，不能宣称已经全面实现原版异步行为。

## B. P1：CGI socket 写入仍绕过 script_timeout

位置：`components/httpd/src/cgi.rs:177–180,201–210`；`main.rs` 的 BufWriter 与 `accept_loop` socket timeout。

新的截止时间只在 pipe poll 循环顶部检查。`resp.body()` / `resp.flush()` 同步写 socket，网络写超时独立使用 `-T`；客户端不读或缓慢读取时，脚本期限已经过了，relay 线程仍在写 socket，ChildGuard 也未执行。持续小幅进展甚至可以一再延长整个响应的生命周期。

本机复现：`-t 1 -T 5`，CGI 输出 16 MiB；客户端设置 `SO_RCVBUF=1024`，发请求后不读取。2 秒后 CGI 仍存活。证明“一条 deadline 覆盖整个请求”的报告表述不成立。

执行要求：

- 截止时间必须传递到实际 socket/TLS 输出层。等待可写、部分写、重试和 flush 都检查剩余预算；网络空闲超时与脚本总期限取实际适用的较早截止点。
- 不能只在 flush 前后检查时间，阻塞发生在 flush 内部。也不能用一个固定 SO_SNDTIMEO 就声称整个 write_all 有总时限。
- HTTP 与 TLS 都需可中止；如果采用非阻塞 transport，处理 WouldBlock、TLS 需要读/写的状态、已缓冲数据和部分写，不要在应用层盲目 poll 一个 fd 后执行无界阻塞操作。
- 保持背压与固定大小缓冲。响应开始前的错误和已开始响应的中断要分开：后者不能追加第二个 HTTP 状态行或伪造完整成功正文。
- 验收包括零读取、低速读取、断连、TLS、大 CGI 输出；检查期限、子进程、fd/线程及峰值 RSS。应优先用脚本 PID 是否及时回收等稳定断言，避免仅凭客户端总耗时下结论。

## C. P2：直接子进程已退出，CGI 仍等后代 stdout 到超时

位置：`components/httpd/src/cgi.rs:129–175`，循环没有观察直接子进程退出。

本机 CGI `sleep 3 & exit 0`，`-t 1`：约 1.001 秒后返回 504。直接脚本已经成功退出，只是后代持有 stdout。参考 `relay.c` 中 `relay_proc_cb` 设置 process_done 并安排 `relay_close_if_done`，不会仅按 stdout EOF 判定结束。

执行要求：同时观察直接进程退出、stdout EOF、deadline；退出时有界地处理已可读输出后结束 relay，不等后代 EOF。退出状态要缓存，确保不会重复回收或对已回收 PID 发信号。新增“直接退出 + 后代持管道”测试，不能只测试“父进程 wait 后代”这个已有用例。

如采用短周期 try_wait 作为最小实现，明确其延迟上限并测量，不要把周期轮询隐藏在“即时完成”的说明里；无需为此引入通用运行时。

## D. 一并收口 CGI header 计数与错误边界

`cgi.rs:184–188` 在解析空行之前把整个 read chunk 算进 header_bytes；最后一个 read 同时包含头尾与正文时，也会把正文算作头部。靠近 64 KiB 时，结果可能依赖 pipe 分包方式。

只累计到 header 终止空行为止的真实头部字节。测试让脚本先写约 62 KiB 合法 header（无终止空行），短暂停顿后一起写终止空行和 16 KiB body；头部小于上限就不能因正文同块到达而拒绝。此项是代码路径确认，未计入本轮已执行的动态复现结果。

## E. 核实 R30-05：4 MiB 上传限制成立，按端点分流修复

`main.rs` 仍调用 `read_body(..., 4 * 1024 * 1024)`，超限 `Ok(None)` 落入静默 return。本机 `wc -c` CGI：1024 bytes → 200 且计数正确；5242880 bytes → connection reset。

匹配 uhttpd `client.c` 经 `data_send` 逐段转发 CGI body，没有这个 4 MiB 限制。但“uhttpd 完全没有任何限制”不准确：Content-Length 和单个 chunk 长度有 INT_MAX 检查，`/ubus` 还有独立 65536-byte 限制。

目标镜像的 `packages.json` / `executables.json` 已确认 `/www/cgi-bin/cgi-upload`、`cgi-backup` 和 LuCI flash.js 存在，合同 CGI 前缀为 `/cgi-bin`。因此经该入口的大上传必然会撞上当前全局限制。不过本轮没有登录实机或执行真实固件上传；应写“当前代码会阻断 >4 MiB 上传”，不能写“设备固件升级链已端到端实测失败”。20–30 MB 也不应代替实际镜像文件大小证据。

执行要求：

1. 先用匹配 LuCI 源码/镜像确认 flash.js → 上传 API → CGI handler → 文件落点与返回格式，补充已有合同遗漏。不要另造一个上传 API，也不要替换成熟的 CGI 上传执行组件。
2. 解析请求头后先确定 handler：CGI 用有界流式 body；`/ubus` 保留自己的小消息上限与错误语义；静态/错误路由明确 drain 或关闭策略。不要把所有端点改成无限收包。
3. CGI 原样收到 multipart 字节与 Content-Type/boundary；Content-Length 和 chunked 的 env、解码、EOF 行为对照原版。业务字段、session 校验仍由原执行组件处理。
4. body decoder 增量处理长度/chunk framing，不预分配整个 chunk，不让 trailer/size-line 的长度与数量无限增长。保留本次的 checked_add 和畸形终止符保护。
5. 同时推进客户端读取、CGI stdin 写入、CGI stdout 读取与响应发送，防止“脚本先输出再读 stdin”和“客户端先完整上传再读响应”造成互等。Rust BufReader 已预读的 body 必须保留；TLS 已解密缓冲同样不能丢。
6. 无 body 时及时关闭 stdin；断流、截断、超时、超限、脚本提前拒绝均有明确状态和清理行为。响应尚未开始时可返回对应 4xx/5xx；有未消费的 body 时不得直接复用连接解析下一请求。
7. 不把统一上限改成 32/64 MiB 当最终修复。若需要临时 413 止血，将其标明为临时反馈改进，不能据此关闭上传兼容性问题。

验收矩阵：

- 长度 0、1 KiB、4 MiB±1、5 MiB、实际目标镜像大小、至少 32 MiB 的无害随机/确定性文件，CGI 收到的字节数与哈希相同。
- Content-Length、chunked、Expect: 100-continue、multipart；HTTP 和 TLS；慢上传/慢下载/中途断连/提前 CGI 错误。
- keep-alive 上连续请求不串包；`/ubus` 65536-byte 边界与既有错误响应不回归。
- 大文件与并发下 RSS 随缓冲/并发数增长，不随文件总长度增长；无僵尸或管道/线程泄漏。
- 在一次性精确 rootfs 中比较原 uhttpd 与候选上传行为。先用收件计数 CGI，再在隔离环境测试真实上传 handler。

**不执行物理路由器刷写，也不要把真实 sysupgrade 动作作为上传测试。** 本次授权是指导文档；设备写入、替换、实际上传等操作仍需单独明确授权与适用恢复门。离线回放只允许上传落盘/校验，不触发 sysupgrade、reboot、restore。

## 本轮已执行验证及限制

- 实际 host rustc：1.98.1，LLVM 22.1.8，aarch64-apple-darwin。
- `make test`：70/70；HTTP 当前锁文件 build 成功；既有 resource probe 四项通过，畸形 header 无残留子进程。
- 本轮新增临时 probe（只在 /tmp，未修改仓库测试）：rpcd 输出溢出、5 MiB 上传、CGI 直接退出/后代持管道、慢客户端下载。
- AArch64 Linux/musl SDK 产物、精确 rootfs 差分和设备端验证均未重跑。所有时间仅用于本机 bug 复现，不作为路由器性能结论。
- 应修改 R30 报告中“全部修复”“deadline 覆盖整个请求”“脚本不读 stdin 会 EPIPE”等表述；不读但仍持有读端只会反压，关闭读端才导致 EPIPE。

工具链升级执行指导另见 [RUST_1_98_1_UPGRADE.md](RUST_1_98_1_UPGRADE.md)。

---

# 执行记录 A–D — 2026-09-05

三项缺口全部独立复现后修复，D 一并收口。仅 host 验证：`make test` **76/76**，clippy 无新增告警，未操作路由器。
本节只覆盖 A–D；E（上传）和工具链升级是后续独立提交。

## 复现→修复对照

| | 修复前 | 修复后 |
| --- | --- | --- |
| A `head -c 1M /dev/zero`（timeout 500 ms） | `Err(7)` TIMEOUT @ 558 ms | `Err(8)` NOT_SUPPORTED @ < 100 ms |
| A 同上重定向 stderr | `Err(7)` @ 560 ms | `Err(8)` NOT_SUPPORTED |
| A `trap '' PIPE` 持续写入 | 跑满 timeout | NOT_SUPPORTED，< 1.5 s（2 s timeout） |
| B `-t 1 -T 30`，客户端不读 16 MiB | 脚本存活至 **-T**（30 s） | 脚本 **2.15 s** 消失 |
| C `sleep 3 & exit 0`，`-t 1` | 1.002 s → **504** | **0.053 s** → **200** |

## A — rpcd 溢出：关掉 fd，overflow 是独立终止原因

`Pipe.file` 改为 `Option<File>`：命中 256 KiB 时 `file = None`，fd 真正关闭，子进程拿到 EPIPE 而不是堵在没人读的管道上。
`open` 布尔换成 `file.is_some()`，不再存在"标记已关但 fd 还开着"的状态 —— 这正是回归的成因。

overflow 在循环内即刻 `break`：另一条管道可能永远不到 EOF（脚本只往还开着的那条写），原来要等满 timeout。
随后在 `procwait::wait` 之前返回 NOT_SUPPORTED，不再被后面的 TIMEOUT 覆盖，对应 `exec.c:246,276` 的
`ustream_read_buf_full()` → `rpc_exec_schedule_reply(NOT_SUPPORTED)`。收尾用 50 ms 有界 wait（忽略 SIGPIPE 的子进程走 SIGKILL），
只作用于直接子进程，不碰进程组。

新增 4 项测试：stdout 超限、stderr 超限、两路同时超限、忽略 SIGPIPE 的持续写入，外加"刚好差 1 字节"必须完整返回。
断言的是**状态码**（NOT_SUPPORTED vs TIMEOUT）而不只是"很快结束"。

## B — 把脚本预算传到 socket 写

`CgiContext` 增加 `client_fd` 与 `network_timeout`。relay 每次写之前，把客户端 socket 的 `SO_SNDTIMEO`
压到**脚本剩余预算**，写完恢复成 `-T`（`ManuallyDrop<TcpStream>` 借用 fd，不接管所有权）。
停读的客户端因此让写失败并触发 ChildGuard，而不是把 relay 和子进程停在那里等满 `-T`。

**准确的界限**：脚本存活 ≤ script_timeout + 一次阻塞写（其超时即当时的剩余预算），实测 `-t 1` 下 2.15 s。
不是"一条 deadline 精确覆盖整个请求"——那个说法我上一轮写错了，此处按实测重写。要做到精确覆盖需要非阻塞 transport
加 TLS WouldBlock 状态机，代价远大于收益，没有做。

新增 socket 级测试：真实 TcpStream，对端从不读取，脚本输出 32 MiB，`-t 1 -T 30` 下必须在 4 s 内返回。

## C — 观察直接子进程退出，而不只是 stdout EOF

循环每轮 `try_wait()`；一旦直接脚本退出就置 `script_done`，之后 poll 用 0 ms 只做一次"已可读"排空（对应
`relay_proc_cb` 里的 `ustream_poll`），随后结束 relay，绝不等后代 EOF。`504` 也收紧为 `timed_out && !script_done`。

轮询周期显式写成 `CHILD_TICK_MS = 50`：uloop 靠 SIGCHLD 立刻知道，我们靠 tick，**退出最晚在 50 ms 内被发现**，
只在管道安静时才走到这个上限。没有为此引入通用运行时或进程级 SIGCHLD handler。
测试用的是"直接退出 + 后代持管道"，与原有"父进程 wait 后代"用例并存。

## D — header 计数只算真实头部

改为按解析出的完整头部行累加（含 CRLF）再加上未解析的 `header_buf` 尾巴，body 不再被计入。
测试：约 62 KiB 合法 header，终止空行与 16 KiB body 同块到达，必须 200 且 body 完整。

## 顺带

`serve`/`dispatch` 的 `local/remote/is_tls/client_fd` 收进 `Conn` 结构体，参数从 8 个降回 1 个（clippy `too_many_arguments`）。

## 待办（未做）

- **E：4 MiB 请求体上限**，仍是 P1，按 R31 §E 的分端点方案单独提交。
- **工具链统一到 1.98.1**，按 RUST_1_98_1_UPGRADE.md 单独提交。
- 需要更正的旧表述已在本节改写：R30 报告里"deadline 覆盖整个请求"和"脚本不读 stdin 会 EPIPE"（不读但持有读端只反压，
  关闭读端才 EPIPE）两处不准确。

---

# 执行记录 E — 请求体流式上传 — 2026-09-05

4 MiB 上限已移除，改为按端点分流 + 增量解码。仅 host 验证：`make test` **77/77**，httpd clippy **0 告警**，
新增 `tests/review/httpd_upload_probe.py` 全部通过。未做设备验证、精确 rootfs 对照，也没有执行任何真实 sysupgrade。

## 验收矩阵结果（`tests/review/httpd_upload_probe.py`）

| 用例 | 结果 |
| --- | --- |
| Content-Length 0 / 1 KiB / 4 MiB−1 / **4 MiB+1** / **5 MiB** / **32 MiB** | 全部 200，CGI 收到的字节数与 sha256 完全一致 |
| chunked 6 MiB | ok |
| `Expect: 100-continue` + 6 MiB | ok |
| `/ubus` 65536 字节（正好到上限） | 正常处理，不是 413 |
| `/ubus` 65537 字节（超一字节） | **413**，不再静默断连 |
| keep-alive 上连续两个 POST | 各自 sha256 正确，不串包 |
| 畸形请求（冲突 framing / 垃圾请求行） | 各自拿到 **400** |
| httpd RSS（跑完整个矩阵，含 32 MiB） | idle 2592 → peak 3392 KiB，**delta 800 KiB** |

修复前：5 MiB → connection reset，25 MiB → broken pipe，客户端拿不到任何状态码。

TLS 单独验证（自签 DER 证书，`-s`）：静态 5000 B 字节一致；**8 MiB 上传** sha256 一致，200 OK；server RSS 4304 KiB。
即 TLS 路径同样不再随上传大小占用内存。

## 怎么改的

**`http::BodyReader`**（新）：增量解码 Content-Length 与 chunked，一次只交出调用方缓冲区那么多字节。
chunk size / trailer 行有 4096 字节上限；chunk 长度用 `u64` 计数，**从不按 size 预分配**，所以上一轮的 `checked_add`
保护变成结构性的——没有可以溢出的分配点。畸形终止符、截断 body、超长 size 行都是 `InvalidData`，
并把 `bad` 置位使连接不可复用。旧的 `read_body()` 整体删除（已被完全取代），其覆盖迁移到新测试。

**分端点策略**（R31 §E.2）：路由先于读 body。
- CGI：`&mut BodyReader` 直接传进 `cgi::run`，边写 stdin 边拉取；
- `/ubus`：保留自己的 `MAX_POST = 65536`（= `UH_UBUS_MAX_POST_SIZE`），超限回 **413** 并关连接，不再继承 CGI 的策略；
- 其他路由：handler 不消费时，keep-alive 前最多 drain 64 KiB，超出就关连接，绝不带着未消费 body 去解析下一个请求。

**CGI stdin 供给**：4 KiB staging window。只在 stdin POLLOUT 时才向 `BodyReader` 拉取，
所以脚本停止读取会自然反压到客户端，而不是在我们内存里堆积。body 读完即关闭 stdin（脚本看到 EOF）。

**读写共用一条流**：response 与 body 是同一个 socket/TLS 流，改用 `RefCell<BufReader<Box<dyn Stream>>>`，
写侧是 `SharedWriter`。每次借用只覆盖一次读或一次写，从不跨越；借用失败转成 io error 而不是 panic 掉连接线程。

## 过程中自己引入又修掉的一个回归

改完 `serve()` 后，畸形请求返回**空响应**：`match http::read_request(&mut *client.borrow_mut(), ..)` 里，
scrutinee 的 `RefMut` 存活到整个 `match` 结束，于是 reject 分支借不到流。先把结果 bind 成变量再 match 即可。
已加进 upload probe 作为回归项（冲突 framing / 垃圾请求行都必须拿到 400）。

## 明确的限制（未做，不宣称）

- **socket 是阻塞的**：一个在读完 stdin 之前就输出超过 socket 缓冲区的 CGI，遇上"先上传完再读响应"的客户端，
  会互相等待到 `-T` 超时，而不是死锁不返回。uhttpd 是全非阻塞事件循环，不存在这个窗口。
  真实上传 handler（`cgi-upload` 先读完 stdin 再回小 JSON）不触发。**这是已知差异，不是已解决**。
- `bad chunk size` 这类 body 层错误现在发生在路由之后：不存在的路径会先返回 404 再暴露 framing 问题（连接仍会关闭）。
- 未做：LuCI `flash.js` → 上传 API → handler 的合同逐条核对；精确 rootfs 中与原 uhttpd 的行为对照；设备端真实镜像上传。
  这三项都需要设备/镜像环境，本轮授权范围之外。
