# 稳定阶段审查 — 2026-09-05

审查基线：HEAD `8138a02`，加工作区原有 `components/httpd/src/http.rs` 分块解析修改（未改动它）。
本轮重点是 HTTP/CGI、rpcd 子进程生命周期和性能测量方法，辅以七个 crate 的 host 单元测试；不宣称逐行覆盖全部实现。
只在本机执行测试，没有连接、修改或重启物理路由器，也没有执行设备 benchmark 脚本。

## 结论

已有数据支持显著的**控制面局部性能提升**，尤其 fw4 规则生成与 TLS 静态请求；不能扩大为所有路径均更快、整个路由器更快，或资源异常路径已经稳定。
发现四项需要修复的问题。生产实现本轮未修改：HTTP 流式发送、背压和子进程清理需要一起设计并跑目标 Linux 差分，不能用单独取消 `join` 等方式掩盖泄漏。

## 发现（按优先级）

### R30-01 / P1：HTTP 完整响应缓冲，内存没有响应大小上限

位置：`components/httpd/src/main.rs:260–271`；关联 `cgi.rs:102–110`、`files.rs` 的静态文件读取循环。

所有 handler 都写入 `Vec`，直到 `dispatch` 返回才写 socket。静态文件尽管每次读取 16 KiB，仍会把整个文件保存在内存；CGI 还有无界 channel。响应大小和并发连接数相乘，内存可以远超日常 RSS 点测；长时间输出也无法实时抵达客户端。

本地 HTTP 实例中，CGI 立即输出完整 header 和 `hello`，随后 sleep 2 秒：客户端约 **2.155 秒**后才收到首字节。这是在 `-t 1` 下运行，亦暴露 R30-02。
内存增长结论来自实际写入 `Vec` 的代码路径，本轮未做 OOM 压测。

修复建议：使用有限大小的输出缓冲向 socket/TLS 流发送，并在 CGI 管道加入背压、头部总量上限和取消机制；清理路径须能处理 socket 写失败。不要仅将 channel 改为有界后继续无条件 join，否则可能形成新的死锁。
验收：大文件/大 CGI 输出、慢客户端与中途断连、早期首字节、峰值 RSS、TLS 与正常响应字节兼容。

### R30-02 / P1：CGI 超时不能限制完整请求生命周期

位置：`components/httpd/src/cgi.rs:137`、`:200–205`。

超时只约束 `recv_timeout`。stdout 先关闭时，channel 断开会跳出循环而不设置 `timed_out`，随后 `child.wait()` 无期限等待；超时杀掉直接子进程后，后代仍可能持有 stdout/stdin，令 reader/feeder 的 `join()` 无期限等待。每个这样的请求都持续占用 HTTP connection slot。

`-t 1` 本地复现：

- CGI 内容 `exec 1>&-; sleep 3`：约 **3.153 秒**才返回 **200**，而非按超时结束。
- CGI 内容 `sleep 3 & wait`：约 **3.152 秒**才返回 **504**；杀掉 shell 并没有使管道线程退出。

匹配源码树 `private/stage3/src/uhttpd/proc.c`、`relay.c` 中，脚本 timeout 与 relay 状态机独立，kill 路径会将 relay 标成 EOF；Rust 实现不应依赖后代关闭 pipe 才能结束请求。
修复建议：一个截止时间覆盖进程、stdin/stdout 和取消清理；子进程必须回收，管道读取必须可取消。验收同时覆盖 EOF-before-exit、继承管道的后代、脚本无输出、客户端断连。

### R30-03 / P1：rpcd file exec 的超时后仍会等待后代管道

位置：`components/rpcd/src/file.rs:336–343`。

`procwait::wait` 已经返回退出或超时，调用方仍无条件 join 两个阻塞 pipe reader；TIMEOUT 通过 `code?` 返回之前也必须等到 EOF。`file exec` 在主请求路径同步执行（`main.rs` 的 dispatch → `file::call`），因此不只是耗尽 worker，还可能阻塞 rpcd 主循环处理其他请求和计时器。

本机 harness 原样提取 `run_command` 函数并直接引用 `procwait.rs`，设置 100 ms timeout：

- `/bin/sh -c 'sleep 2 & exit 0'`：**2013 ms** 后才返回成功。
- `/bin/sh -c 'sleep 2 & wait'`：**2017 ms** 后才返回 TIMEOUT。

harness 用最小 Json/status 类型支撑编译，只验证真实的 spawn/wait/read/join 控制流，不是 ubus 端到端复现。
匹配源码树 `private/stage5/src/rpcd/exec.c` 的 timeout reply 会释放并关闭 pipe；process callback 也主动关闭读端，不等待后代 EOF。
修复建议：让 pipe drain 可取消并受同一截止时间约束，直接子进程退出后按照原版边界收尾。验收必须包含 daemonizing command，而不只是 `/bin/true` 和直接 sleep。

### R30-04 / P2：CGI 畸形 header 路径产生僵尸进程

位置：`components/httpd/src/cgi.rs:170–177`。

发现无冒号的 header 后只 `child.kill()`，直接返回 500，没有 `wait()`。Rust 的 Child drop 不会回收进程。没有全局 waitpid 回收路径时，每次触发都会保留僵尸，累积消耗进程表。

CGI `printf 'invalid\r\n'; sleep 1` 返回 500 后，本地 `ps` 观察到 httpd 子进程 `Z <defunct>`。
修复建议：统一收口所有返回路径的 kill/reap 与 pipe 线程取消，不要让错误处理绕过清理。验收为重复畸形响应后无残留子进程，服务继续可用。

## 性能结论与下一步

以 BENCHMARK §11 为准：fw4 print 203→17 ms（11.9×）、check 261→72 ms（3.6×）；TLS CSS 531→1005 req/s（+89%）；reload_config 55.7→36.2 ms（延迟下降 35%）。这些是有价值的提升。

但大 CSS 1436→1384 req/s，rpcd `rc list` 1137→1253 ms，短 RPC 多数接近原版。报告首页原有“httpd 全面更快”“慢项全部消失”过度概括，已更新并保留各轮历史记录。

测量仍有三个边界：

1. `bench_device_side_by_side.sh` 的循环没有校验命令退出码，失败也会进入均值；HTTP 客户端也把错误请求计入 req/s，不能只看吞吐数，必须同时核对 status 和响应内容。
2. `/rom/sbin/reload_config` 仍通过当前 PATH 调用已接管的 UCI；fw4 原脚本也使用当前系统依赖。它们验证当前环境下替换入口的收益，不是恢复完整原版栈后的系统对比。
3. 固定顺序、少量轮次、选择第二次运行，不足以解释几个百分点的差异；后续应多轮交替 C/Rust，记录成功数、p50/p95/p99 和峰值资源。现有 HTTP `-n 400 -c 4` 总共 400 请求，不是每个线程 400。

优化顺序：先解决上述超时/回收/响应缓冲，再测大响应与慢客户端，最后追查 rc list。当前不建议为短 RPC 的 0.2 ms 差异引入缓存或大规模异步重构。

## 本轮验证与限制

- 找到本机 Rust toolchain 后，`make test`：**65/65 通过**（含工作区已有 HTTP chunk 测试）；`make check-tools` 通过。
- HTTP loopback diagnostic：`tests/review/httpd_resource_probe.py`，先 `cargo build --manifest-path components/httpd/Cargo.toml`，再从仓库根目录运行该脚本。只使用临时目录与本机回环地址，输出观测而非伪装成通过的回归测试。
- 所有新增动态证据来自 macOS host。尚未重跑精确 OpenWrt rootfs 差分、AArch64 产物或物理设备验证；Linux 目标的严重性判断依据共享 Rust 控制流和现有匹配源码，不将 host 耗时当设备性能数值。

---

# 修复记录 — 2026-09-05（同日）

四项发现全部复核成立，均已修复。对照源码树确认了每一项的原版语义，改动按原版行为收敛，而不是简单加超时。
验证只在 macOS host：`make test` **70/70 通过**（新增 5 项生命周期回归测试），clippy 无新增告警，未连接路由器。

## 复现与结果（`tests/review/httpd_resource_probe.py`，`-t 1`）

| 用例 | 修复前 | 修复后 |
| --- | --- | --- |
| CGI 提前关 stdout 后 sleep 3（`closed`） | 3.204 s → 200 | **0.031 s** → 200 |
| 后代继承管道 + `-t 1`（`descendant`） | 3.154 s → 504 | **1.002 s** → 504 |
| CGI 先输出后 sleep 2（`stream`，首字节） | 2.154 s | **0.034 s** |
| 畸形 header 后残留子进程（`bad`） | `Z <defunct>` | **无残留** |

24 MB 静态文件下载（新增 smoke，同一二进制）：httpd RSS **28832 → 3120 KiB**，字节一致，首字节 0.013 → 0.001 s。

## R30-01 — HTTP 响应流式发送

`main.rs` 的 `Vec` 换成 16 KiB `BufWriter` 直接写 socket/TLS 流，对应 uhttpd 的 client ustream。
`Response::flush()` 新增，CGI 每个 relay chunk 之后调用一次，所以首字节在脚本仍在运行时就到客户端。
小响应仍是一次 write（缓冲区未满），静态文件本来就按 16 KiB 读，`BufWriter` 对 ≥ 容量的写直接透传，吞吐路径不变。
CGI 的无界 `mpsc` channel 随线程一起删除：现在读管道和写 socket 在同一线程，socket 阻塞会自然反压到管道，无需有界 channel。

## R30-02 — CGI 单一截止时间

`cgi.rs` 的 relay 线程 + channel 换成本线程一个 `poll(2)` 循环，同时驱动 stdin（POLLOUT）与 stdout（POLLIN），
`script_timeout` 是整个请求的截止时间。两条原版语义被显式实现：

- `relay_close_if_done()`：stdout EOF 即结束请求，不等脚本退出（`closed` 用例 3.2 s → 0.03 s）。
- `proc_timeout_cb()` → `uh_relay_kill()`：超时 SIGKILL 后自己把 relay 标成 EOF，不等后代关管道（`descendant` 用例 3.15 s → 1.00 s）。

不再有 `join()`，因此没有"后代持有管道 ⇒ 请求线程永久占用"的路径。POLLOUT 保证管道至少 PIPE_BUF 可写，
每轮写 ≤ 4096 字节，写不会阻塞；脚本不读 stdin 时拿到 EPIPE，直接关闭 stdin。

## R30-03 — rpcd exec 不再等待后代

`file.rs::run_command` 的两个阻塞 reader 线程换成 `poll(2)` + `try_wait()`，与 `exec.c` 对齐：
直接子进程退出（`rpc_exec_process_cb`：最后一次 `ustream_poll` 后 close）或超时（`rpc_exec_timeout_cb`：SIGKILL + 用已缓冲数据回复）即返回，
从不等待继承管道的后代。管道 EOF 但子进程仍活着的情况由既有 `procwait::wait` 兜底（有界 + SIGKILL）。
这条路径在 rpcd 主循环上同步执行，所以修的是主循环卡死，不只是延迟。

新增测试 `file::tests::descendant_holding_the_pipes_does_not_extend_the_call`：
`sleep 5 & exit 0`（timeout 200 ms）必须 < 1 s 正常返回；`sleep 5 & wait` 必须 < 1 s 返回 TIMEOUT。修复前两者都是 ~2 s / ~5 s。

## R30-04 — 子进程回收收口

`ChildGuard`（`Drop` 里 kill + wait）对应 `uh_relay_free()`：`if (r->proc.pending) kill(SIGKILL)` 加 uloop 的 waitpid。
畸形 header、header 超限、超时、EOF、socket 写失败、`?` 提前返回——所有路径共用同一个回收点，不存在绕过清理的错误分支。

## 附带改动

- **CGI header 总量上限 64 KiB → 500**（`MAX_HEADER_BYTES`）。原版让 ustream 无限增长；这是标注的 DEVIATION，
  防止脚本不发空行时 `headers` 无界增长。真实 CGI 不会有 64 KiB 头部。
- **修掉一处 MSRV 破坏**：工作区原有的 `http.rs` 分块解析改动用了 `Option::is_none_or`（Rust 1.82 起稳定），
  而 crate 声明 `rust-version = "1.78"`。SDK 工具链若为 1.78 会编译失败，已换成 `checked_add` + `match`。

## 新发现 R30-05 / P1：请求体上限 4 MiB，超出直接断连（未修）

`main.rs:247` 用 `read_body(..., 4 * 1024 * 1024)` 把整个请求体读进内存；超限返回 `Ok(None)`，
`serve` 对该分支只 `return`，连接被静默丢弃，客户端拿不到任何状态码。

本机实测（CGI 回显 `wc -c`）：1 KiB → `200 OK`；5 MiB → connection reset；25 MiB → broken pipe。

uhttpd 没有请求体上限（`client.c` 把 POST body 流式喂给 relay，`uhttpd.h` 只有 `max_script_requests` / `max_connections`）。
影响面：LuCI 的固件上传（sysupgrade 镜像 20–30 MB）和大备份恢复在当前设备镜像上应当是失败的。

没有一并修，是因为这需要把请求体也改成流式喂给 CGI stdin（不再先 `read_body` 到 `Vec`），
属于 R30 四项之外的独立改动。建议作为下一项，并在设备上用真实 sysupgrade 镜像验证。
