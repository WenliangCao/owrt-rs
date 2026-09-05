# 给 Opus 的执行指导：复审 993fb15，尚不能判定完成

日期：2026-09-05。
审查提交：`03cd180`（R31 A–D）、`44a03aa`（工具链）、`993fb15`（请求体流式上传）。
本轮仅读代码、运行 host 验证和 /tmp 临时复现、编写本文件；没有修改实现/测试/构建配置，没有操作设备。

## 判断

有实质进展：普通大文件上传已不受 4 MiB 限制；rpcd 溢出、CGI 直接退出与僵尸回收的现有回归通过；七个 MSRV 和开发/CI/发布默认版本均统一到 1.98.1。

**但“都做完了”不成立。** 请求流式处理仍有阻塞与错误响应问题，R31 的头部计数修复没有真正生效，编译器身份校验/记录还有缺口。Linux、SDK clean 构建、精确 rootfs 与离线发布产物的验证也尚未提交证据。

## 1. P1：stdin 可写不代表客户端有 body 可读

位置：`components/httpd/src/cgi.rs:197–202`，`http.rs::BodyReader::read/read_chunked`。

当前先 poll CGI stdin，然后直接 `body.read(&mut stage)`。这会阻塞于客户端 socket：

- 阻塞期间不能检查 script deadline、直接子进程状态，也不能处理 stdout 中已经准备好的响应。
- socket 的 `-T` 限制只约束单次底层等待，不等于整个 body read 的总期限；chunk line/trailer 还可能在一个调用里多次等待。
- 对已经关闭的 CGI stdin，POLLERR/POLLHUP 同样会进入 `revents != 0` 分支，仍先读客户端数据，处理顺序错误。
- `unwrap_or(0)` 把解码/网络错误伪装为正常 EOF；随后代码可能按成功脚本路径合成 200，丢失真正的错误响应。

### 本轮已执行复现

本机当前 debug httpd，`-t 1 -T 3`，客户端只发送：

```http
POST /cgi-bin/count HTTP/1.0
Content-Length: 100

```

之后保持连接，但不发送 body。count CGI 等待 stdin EOF：**3.005 秒**后才拿到 504，而不是受 1 秒脚本期限约束。

另一个 CGI 不读 stdin，立即写出：

```text
Status: 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nrejected
```

同样的停顿上传请求：**3.002 秒**后拿到 **200 OK**。原 403 响应没有送达。原因是卡在 body.read，恢复后循环看到 deadline 已过、script_done=true，却没有先消费 stdout，于是走无 header 的缺省 200。

这不是报告中提到的“CGI 输出大于 socket 缓冲才会互等”：**一个很小的提前拒绝响应也会出错。** 不能以真实上传 handler 通常先读完 body 为由关闭此问题。

### 必须改动

1. body 解析器要能增量推进并暂停：无完整数据时返回待输入状态，不能在一次调用里等待整个 size line、终止符或 trailer section。
2. relay 同时关注客户端读 readiness、已预读/已解密的 body、CGI stdin 可写、stdout 可读、直接进程退出与总期限。stdin HUP/ERR 应先关闭该写端，不能因此读取客户端。
3. 同时就绪时公平处理两侧，提前 CGI 响应不可因等待上传而丢失；直接进程结束时仍要按参考语义有界消费已就绪 stdout。
4. 传输层保留固定缓冲和背压，不恢复全量 Vec。HTTP/TLS 使用同一个明确的 readiness/期限合同；不能只把客户端 fd 加进 poll 后仍调用可能继续阻塞的 read_line。
5. 正常 EOF、截断、畸形 framing、网络 timeout、脚本主动关闭 stdin 分别处理。响应已开始时按关闭/中断处理，不追加新状态行；未开始时按合同返回错误。不要 `unwrap_or(0)` 混淆全部情况。
6. chunk trailer 只有单行 4096 上限仍不够：增加总字节/行数边界，检查整个解析过程的 deadline。否则客户端不断发送短 trailer 会长期困在一个 read 调用内。

### 增加回归

- 发请求头后暂停 body；慢速 Content-Length 上传、分段 chunk size/CRLF、持续 trailers。
- CGI 提前 403/500、立即关闭 stdin、直接退出、先输出再读 body。
- 客户端先上传完再读响应和同步双向传输；HTTP 与 TLS。
- 断连/截断/畸形 body 不得静默变成成功；未消费 body 不复用连接。
- 断言真正状态/正文、脚本回收时间与后续请求可用性，不只是断言连接最终能结束。

## 2. P2：R31 header 上限修复实际仍把正文算进去

位置：`components/httpd/src/cgi.rs:240–245`。

当前在解析终止空行前检查 `header_bytes + header_buf.len()`；header_buf 此时仍包含同一个 read 中的正文。改用累计计数并没有改变这个错误判断顺序。

本轮复现的 CGI（Python，仅本机临时 fixture）：

```python
sys.stdout.buffer.write(b'X-Pad: ' + b'a' * 61990 + b'\r\n')
sys.stdout.buffer.flush()
time.sleep(.2)
sys.stdout.buffer.write(b'\r\n' + b'b' * 16384)
sys.stdout.buffer.flush()
```

实际 header 总计 **62001 bytes**，小于 65536；当前响应 **500 Internal Server Error**。
已有测试在 shell 中反复 printf，无法保证触发需要的边界分包，测试通过不能证明缺陷消失。

修复：在有界输入窗口中先识别实际 header 终止位置，再计费到该位置为止；没有终止位置时再检查未完成头部的总量。每处理完一个完整 header line 也应检查累计值。正文永远不参与 header cap。

测试使用可控制的 reader 分段单元测试（配合少量端到端验证），覆盖真实 header 大小 65535/65536/65537、空行跨块、正文与最后空行同块、前述 62001-byte 示例。先确定上限是否包含最后空行，并在实现与断言中一致。

## 3. P2：工具链检查和 manifest 仍不是“实际编译器身份”

位置：`Makefile::check-toolchain`、`tools/ci_build_image.sh:108–109`。

check-toolchain 只运行 PATH 中的 rustc，没检查 Cargo 实际使用的 RUSTC。发布构建用 `$CARGO`，但 manifest 单独运行 PATH 中的 cargo/rustc，忽略 `$CARGO` 覆盖和 `$RUSTC`。源码注释声称处理了这些绕过方式，实际没有。

本机复现：PATH 指向 1.98.1，同时设置：

```sh
RUSTC=/Users/USER/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustc make check-toolchain
```

仍输出 `toolchain: pinned and consistent` 并退出 0。这里只执行了检查，未用旧编译器发布产物；正常 Cargo 构建会受 MSRV 等进一步限制，但该检查的成功结论仍错误。

实施要求：

- 正式构建前明确处理 CARGO、RUSTC、RUSTC_WRAPPER、RUSTC_WORKSPACE_WRAPPER 及 Cargo config 的 compiler 覆盖。可以拒绝不符合发布策略的覆盖；不要求建立复杂工具链发现框架。
- 使用与真实构建一致的 Cargo/编译器入口获取身份、验证固定版本，并用同一份事实生成 manifest，不能构建后另查无关的 PATH 命令。
- 工具链安装/身份校验提前失败，不要下载 SDK、构建镜像之后才发现版本问题。
- 两个发布入口都适用。保留研究用 override 时，应明确非正式状态；不能冒用固定发布标签。
- 添加不下载 SDK、不访问设备的负向检查：RUSTC 不一致、CARGO 覆盖、缺失/非法 pin 必须得到预期失败或明确非正式结果。

## 4. R31 的完整写期限要求尚未满足

位置：`cgi.rs:233–236,260–269`。

这轮确实改善了“完全不读”的普通正文场景，但仍只是临时设置 SO_SNDTIMEO：

- 初始 header + 第一块正文的写入/flush 没有使用缩小后的预算。
- `remaining` 没有与配置的 network_timeout 取较小值，可能把本来更短的网络超时延长。
- 一个 write_all/flush 内的多次部分写，可能分别使用相同 timeout；不能保证总期限。
- 返回错误前恢复较长的 network_timeout，外层 BufWriter drop/后续 flush 的行为也需要纳入失败收尾审查，不能只测直接写 TcpStream 的单元测试。

本轮未再次穷举部分写/TLS 的 deadline 复现，因此不把这些代码证据冒充新的端到端实测。请与第 1 项统一解决整个 transport 的 deadline，不再逐个补 SO_*TIMEO。新增通过实际 `Server::serve`/BufWriter/TLS 路径的慢速与中断测试。

## 5. 已通过的项目与发布剩余工作

本轮实际重跑：

- `make test`：**77/77**（--locked），HTTP build 成功。
- `httpd_upload_probe.py`：0/1 KiB/4 MiB±1/5 MiB/32 MiB 的普通上传、6 MiB chunked、Expect、/ubus 边界、keep-alive、畸形请求头均通过。
- `httpd_resource_probe.py`：原四项通过，僵尸子进程列表为空。
- `make check-tools` 通过。正常 PATH 的 pin/MSRV 一致；第 3 项暴露其负向验证不足。

因此 rpcd 原溢出问题、普通大上传、基础工具链固定可以认可。但不是整个发布验收通过。

执行记录已明确以下工作未做，保持这些未完成状态，不要用 host tests 替代：Linux tests、SDK clean 重建、APK 实际 binary 的精确 rootfs 差分、离线镜像、版本升级性能/体积对照、CI/构建机可重复性、发布前 PKG_RELEASE 更新。

`tests/review/httpd_upload_probe.py` 在每次请求完成后才采样 RSS，所谓 peak 是**请求后采样点的最大值**，不是上传过程峰值；本轮观察 idle 2592、采样最大 3344 KiB。若要证明峰值内存有界，应在传输期间持续采样，或使用适用的 peak accounting。不要把这组点测标为真实峰值。

最后，前一份执行记录说“核对 LuCI 合同、精确 rootfs 对照都在授权范围外”不准确：只读核对已获材料/在一次性隔离环境验证，本身不等于操作物理设备。若缺少材料/工具，记录具体缺少什么，不要泛化为需要设备写权限。物理上传、替换、刷写仍不得擅自执行。

## 交付要求

先修第 1 项传输/生命周期，再完成第 2、3 项；第 4 项并入第 1 项设计。每项给出可稳定重现的失败用例、修复后结果和匹配原版的证据。
无需改 unrelated 模块、重新引入大框架或进行风格重构。保留本轮已经正确的增量 body 解码、真实 fd 关闭、ChildGuard 和版本单一来源。

---

# 执行记录 — 2026-09-05

三项全部复现后修复。仅 host 验证：`make test` **80/80**，httpd clippy **0 告警**，
`make check-toolchain` / `check-toolchain-negative` / `check-tools` 通过。未操作路由器。

## 复现 → 修复

| 用例 | 修复前 | 修复后 |
| --- | --- | --- |
| 停顿上传 → 等 stdin EOF 的 CGI（`-t 1 -T 3`） | 3.004 s → 504（受 `-T` 约束） | **1.001 s → 504**（受 `-t` 约束） |
| 停顿上传 → 立即 `Status: 403` 的 CGI | 3.003 s → **200**，403 丢失 | **0.031 s → 403** |
| 62001 字节 header + 同块正文 | **500** | **200**，正文完整 |
| `RUSTC=<1.97.1> make check-toolchain` | `pinned and consistent`，exit 0 | **exit 1**，报出实际版本 |
| `CARGO=env RUSTUP_TOOLCHAIN=1.97.1 cargo` | 同上 | **exit 1** |
| `RUSTC_WRAPPER=…` | 同上 | **exit 1**（`OWRT_ALLOW_TOOLCHAIN_OVERRIDE=1` 则标 `official=no` 放行） |

## 1 + 4 — relay 改成就绪驱动，deadline 落到 transport

问题的根不是"缺一个 SO_SNDTIMEO"，而是 relay 会在客户端 socket 上阻塞。所以按第 4 项的要求一次性解决整条链路：

- **`http::Sink`**：response transport 抽象。`Out` 是它的实现——一个 16 KiB 窗口，
  `write` 只入队；`drain_ready` 非阻塞推送；`drain_blocking` 的预算是**配置的 network_timeout**，
  且覆盖整次 drain 而不是单次写，所以多次部分写不能把期限累加延长。
- **CGI 期间客户端 socket 置为非阻塞**（`NonBlockingFor` 守卫，任何退出路径都恢复），
  relay 期间 `set_deferred(true)` 让 `write` 绝不触发阻塞 drain。
- **一个 poll 集合**同时看：客户端可读（需要 body 时）、客户端可写（有待发数据时）、
  CGI stdin 可写、CGI stdout 可读，外加 `try_wait` tick 与总期限。
  处理顺序是先推已排队的响应（腾出窗口，也正是提前拒绝要走的路），再喂 stdin，再收 stdout。
  **stdin 的 POLLERR/POLLHUP 先关闭写端**，不会代替脚本去读客户端。
- **`BodyReader` 改成可暂停的状态机**：`Stage::{Size,Data,AfterChunk,Trailer}` + 跨调用保留的半行缓冲。
  客户端没有更多数据时返回 `WouldBlock`（不再是伪装成 EOF 的 `unwrap_or(0)`），
  size line / 终止 CRLF / trailer 都可以被切在任意位置。正常 EOF、截断、畸形 framing、
  WouldBlock 分别处理：只有真正的解码失败才置 `bad` 并使连接不可复用。
- **trailer 总量上限**：单行 4096 之外，新增整段 8192 字节 / 64 行上限。
- **单一出口**：504、正常收尾、relay 主动中止都汇到同一处 flush + `set_deferred(false)`。
  修这一处时发现自己引入的 bug——早退的 `return resp.error(504,…)` 会把 504 留在 buffer 里，
  客户端拿到**空响应**；已被 `stalled upload -> /cgi-bin/sink` 覆盖。

**边界（实测，不是意图）**：脚本存活受 `-t` 约束，实测 `-t 1` 下 1.001 s；
响应发送受 `-t` 剩余预算约束，收尾 flush 有 50 ms 下限以免正好卡在期限上的响应发不出去；
连接级 drain 受配置的 `-T` 约束。

### 新增回归

- host 单元：`chunked_decoding_resumes_across_every_split`（size line/CRLF/trailer 被切开，逐字节喂）、
  `endless_trailers_are_bounded`（行数与字节数两个上限）、
  `a_client_that_never_reads_cannot_outlive_the_script_timeout`（走真实 `Out` + TcpStream，不是直写 socket）。
- 端到端（`httpd_upload_probe.py`）：停顿上传 → 504 / 403 各自在 2.5 s 内、
  慢速滴灌 300 KiB 字节哈希一致、畸形请求仍得 400。
- TLS 单独验证：静态 5000 B 与 8 MiB 上传均字节一致。

## 2 — header 上限

计费点移到"每解析出一条完整 header 行"之后、空行分支之前，正文永远不参与。
**上限的定义写死为：包含终止空行在内的全部 header 字节**，实现与断言一致。
新增 `header_cap_counts_only_header_bytes`：总量 65535 / 65536 通过且正文完整，65537 得 500。
原来的 shell fixture 无法保证分包，已换成可控大小的构造。

## 3 — 编译器身份

新增 `tools/toolchain_identity.sh`，是"这到底是哪个编译器"的唯一答案，**Makefile 检查和发布 manifest 共用它**——
被验证的身份就是被记录的身份，不再构建完再去查 PATH 上无关的命令。

- 解析 `$CARGO` / `$RUSTC`；`$RUSTC` 未设时从 `$CARGO` 推导（`env RUSTUP_TOOLCHAIN=x cargo` → 同样的 rustc），
  不再直接看 PATH。
- `$CARGO` / `$RUSTC` 是**合法的固定手段**（发布流程自己就在用），所以按版本校验而非一律拒绝；
  wrapper 无法按版本校验，标记 `official=no` 并默认拒绝。
- `.cargo/config*.toml` 里的 `rustc` / `rustc-wrapper` 覆盖同样标记。
- `ci_build_image.sh` 在**下载 SDK 之前**执行这项检查，版本问题不会等到构建一小时后才暴露；
  manifest 的 `toolchain` 段新增 `official` 与 `override` 字段。
- `make check-toolchain-negative`（`tools/toolchain_negative_test.sh`，不下载、不联网、不碰设备）
  覆盖 9 个用例：pin 正常、CARGO 同版本放行、wrapper 拒绝、显式非正式放行、RUSTC 指向不存在的二进制、
  CARGO/RUSTC 指向旧版本、伪造 pin、缺失 pin。已接入 CI。

## 5 — 度量方法

`httpd_upload_probe.py` 的 RSS 改为**传输期间连续采样**（10 ms 间隔的后台线程），
不再是每次请求完成后的点测。整个矩阵（含 32 MiB 上传、6 MiB chunked、慢速滴灌）：
idle 2560 → 传输期间峰值 3792 KiB，**delta 1232 KiB**，与文件大小无关。

## 仍未做

Linux 测试、SDK clean 重建、APK 实际 binary 的精确 rootfs 差分、离线镜像、
1.94 vs 1.98.1 的性能/体积对照、CI/构建机可重复性、发布前 PKG_RELEASE 更新 —— 全部保持未完成。
host 测试不替代这些。这些需要 Linux 构建主机或 CI 运行，已单独向用户确认授权。
