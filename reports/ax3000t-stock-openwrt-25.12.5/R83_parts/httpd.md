# R83 · httpd：F18–F20 与 H05

日期 2026-09-10。参照为 uhttpd `7b1bec45` 和精确 OpenWrt 25.12.5 rootfs 内的 uhttpd、
CGI/ucode、rpcd。所有服务运行在一次性 rootfs 副本，只绑定构建机 loopback。
TLS 证书/私钥在测试中临时生成，未纳入 Git。最终构建摘要见 [validation.md](validation.md)。

## 1. 修复

| 路径 | 修复后的行为 |
|---|---|
| CGI 无头、半头、坏头或输出头前超时 | 502；脚本 spawn/exec 失败为 500；保留合法 Status 头 |
| UA 判定 | 按 Opera、MSIE、Chrome、Safari 顺序，macOS Chrome 的 Safari token 不触发关闭 |
| Basic auth | 读取 httpd.conf；支持路径保护、realm、明文/crypt/系统账户引用，锁定或不存在账户拒绝；认证后的 CGI 凭据覆盖同名请求头 |
| CLI 选项 | 索引、解释器、alias、目录 charset、符号链接策略、TCP keepalive、TLS 重定向/套件均生效 |
| 连接与脚本限制 | 所有 listener 共享 `-N`；满时暂停 accept 并保留 backlog，`-N 0` 不限；`-n` 控制脚本槽并排队，静态请求仍可服务 |
| 慢请求头 | 每个完整请求头有总 deadline，客户端每次送一个字节不能无限延长 |
| `-t 0` | 按 proc.c 关闭脚本超时；早期草稿误称“一秒超时”已纠正 |
| `/ubus` 大正文 | 超过 64 KiB 返回 HTTP 200 + JSON-RPC -32700 并关闭；不会回 HTML 413 |
| 404/403 | 保留原始请求目标和 query，使用原版转义规则 |
| SSE | 实现 subscribe、Bearer/:subscribe ACL、CORS、retry 和事件帧；权限拒绝码为 -13 |
| ubus 生命周期 | 普通调用复用连接（空闲池上限 8）；SSE 单独持有连接，断开后释放 |
| TLS | 无效证书/密钥使启动失败；显式 16 KiB rustls buffer，保持 CGI 向慢客户端的背压 |
| 调试清单 | 包的 init 脚本不再默认传 `--call-log`，仅显式启用时记录 |

## 2. 运行证据

`r14_httpd_check.py` 从只比较 CGI 长度区间改为归一化后完整正文 hash；加入确定性的环境
输出、正常/失败 CGI、query 和 UA 用例。61 个请求的状态、关键头与正文全部一致。

`r83_httpd_compat.py` 的 31 个兼容结果全部一致，并分别验证期望状态。覆盖 Basic auth、
系统账户、选项、两个脚本串行时静态请求仍可用、连接槽释放、慢头超时、断开的队列客户、
SSE、HTTPS 重定向与 TLS 传输。20 次普通 ubus HTTP 请求使用同一 Unix socket inode。

TLS 慢读用例让 CGI 输出 128 MiB，客户端只慢速读取一小部分，在积压期间采样 RSS。
本次 C 增长 44 KiB，候选增长 116 KiB，均低于 8 MiB 门限。该门验证内存背压，
不声称慢客户端下载完全部 128 MiB。R81 的“rustls 默认无界缓冲”是假设；锁定的
rustls 0.23.43 默认已有界，本轮仍显式设置上限并验证运行行为。

## 3. SSE 清理的独立资源门

12 个 SSE 客户端订阅后断开，provider 保持运行，随后删除 provider 对象。
候选在这两个时点都必须释放 HTTP/ubus fd；参考 uhttpd 在该场景保留了 12 个 fd。

```text
SSE disconnect resource gate: C retained 12 fds; Rust retained 0 fds
r83 httpd extended compatibility: 31/31 PASS
r83 httpd disconnected SSE cleanup: PASS
```

资源要求单独报告；没有将参考泄漏写成双方通过，也没有把该值放入通用掩码。

## 4. 畸形请求模糊测试的既有边界

最终 r27：**133 用例，22 处差异，0 个存活失败**，原始差分命令按设计退出 1。
不能把它写成“133/133 一致”。这些差异均属于 [R25 §3.3](../R25_ROUND5.md) 和
[R33 §1](../R33_RELEASE_GATES.md) 已记录的边界，本轮没有新增正常请求差异。

| 既有边界 | 本次差异用例 |
|---|---|
| 坏请求行使用 close/HTTP 1.0，而 C 的错误头可能写 Keep-Alive/0.9 | http09、http12、http2、httpx、lowercase-method、unknown-method、trace、connect、method-only、tab-separated、raw-space-in-path、pipelined-bad-second |
| LF 或畸形头的接受/拒绝时序 | lf-only、header-no-colon、header-obs-fold、header-ctrl |
| NUL 路径拒绝，而 C 截断后使用路径 | percent-nul、cgi-pathinfo-nul |
| 超长请求行的错误响应和 reset 差异 | long-path-8k |
| 畸形 chunk 长度的错误响应/等待差异 | chunked-bad-size、chunked-huge-size |
| 超深 JSON 数组的 parse-error 包装 | json-deep-array |

r27 新增独立双侧存活断言，不能因两侧都死而通过；大 JSON 回复也比较完整归一化正文的
SHA-256，不再只比较前 2000 个字符。两个负向自测分别注入双死与正文末尾差异，均能判错。
这些改动加强比较，没有通过放宽掩码把既有差异消掉。
