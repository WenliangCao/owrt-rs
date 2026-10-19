# 合同 C3：HTTP 前端（R14 uhttpd）

> 冻结日期：2026-09-02
> 依据：镜像内 uhttpd 2026.06.16~7b1bec45 源码（client.c、file.c、proc.c、cgi.c、ubus.c、relay.c）、
> 设备实际启动参数、2026-09-02 对设备的只读 HTTP 采样（`private/stage3/http/uhttpd-baseline.txt`）。

## 1. 设备上的实际配置

```
uhttpd -f -h /www -r OpenWrt -x /cgi-bin -u /ubus -t 60 -T 30 -k 20 -A 1 -n 3 -N 100 -R
       -p 0.0.0.0:80 -p [::]:80 -C /etc/uhttpd.crt -K /etc/uhttpd.key -s 0.0.0.0:443 -s [::]:443
```

含义：docroot `/www`；CGI 前缀 `/cgi-bin`（LuCI 是 `/www/cgi-bin/luci`，ucode 脚本，按普通 CGI 执行）；
`/ubus` JSON-RPC 桥（会话鉴权开、无 CORS）；脚本超时 60 s；网络超时 30 s；keep-alive 20 s；
TCP keepalive 1；最多 3 个并发脚本、100 个连接；RFC1918 过滤；目录列表开；无 httpauth、无 Lua/ucode
插件前缀、无 alias、无 error_page；证书/私钥为 DER（563/121 字节，EC）。

## 2. HTTP 层

| 项 | 行为 |
|---|---|
| 请求行 | 方法 ∈ GET/POST/HEAD/OPTIONS/PUT/PATCH/DELETE，版本 HTTP/0.9/1.0/1.1，否则 400 并关闭 |
| 头 | 名称转小写；重复 Content-Length 或同时有 Content-Length 与 Transfer-Encoding → 400；`Transfer-Encoding` 非 chunked → 501；`Expect: 100-continue` 回 `HTTP/1.1 100 Continue`，其他 Expect → 412 |
| keep-alive | HTTP/1.1 且未 `Connection: close` 时保持；HTTP/1.0 关闭。UA 按 Opera、MSIE、Chrome、Safari 的顺序判定；macOS Chrome 中的 Safari token 不触发关闭 |
| 状态行 | `HTTP/1.x NNN Summary\r\n` + `Connection` + （可选）`Transfer-Encoding: chunked` + `Keep-Alive` |
| 分块 | 仅 HTTP/1.1、非 HEAD/OPTIONS、非 204/304、且未由处理方禁用时使用；块头为大写十六进制 |
| RFC1918 过滤 | 来源为私网地址而服务端地址为公网地址时 403 |
| 错误页 | `Content-Type: text/html`，正文 `<h1>Summary</h1>` + 说明；带请求体的错误请求后关闭连接 |
| 限制 | 单行头缓冲 4096 字节，整个请求头有网络 deadline；独立审查加固后，请求头累计至多 65536 字节（含请求行、前导空行、终止空行）和 512 个字段，超限 413 并关闭连接；`-N` 为所有 listener 共享的连接上限，满时停止 accept，空出后继续；`-N 0` 不限 |

## 3. 静态文件（file.c）

1. URL 按 `?` 切分查询串，路径 URL 解码，从最长前缀起逐级 `canonpath`+`stat`，剩余部分为 `PATH_INFO`；
   解析结果必须仍在 docroot 内。
2. 目录：无尾斜杠 → `302 Found` + `Location: /path/[?query]`；有尾斜杠 → 依次找
   `index.html`、`index.htm`、`default.html`、`default.htm`；都没有 → 目录列表（HTML，按名排序）。
3. 文件：要求 `S_IROTH`；方法只允许 GET/POST/HEAD/OPTIONS，否则 405。
4. 响应头：`ETag: "<ino>-<size>-<mtime>"`（十六进制）、`Last-Modified`、`Date`、`Content-Type`（按扩展名表，
   缺省 `application/octet-stream`）、`Content-Length`；文件响应不分块。
5. 条件请求：`If-Match` 不匹配 → 412；`If-None-Match` 匹配时 GET/HEAD → 304，其他 → 412。
   **精确镜像的 musl `strptime` 不接受原版使用的 `%Z`**，`If-Modified-Since` 和
   `If-Unmodified-Since` 因日期解析失败被忽略；R92 双侧 HTTP 用例确认，包括从同一响应取回的
   Last-Modified。不能把较新 libc 的日期行为写成本镜像合同。304/412 仍带 ETag/Last-Modified/Date。
6. 不存在 → 404 `The requested URL <path> was not found on this server.`；无权限 → 403。
   错误正文保留原始请求目标及 query，并按 uhttpd 的规则转义。

## 4. CGI（proc.c / cgi.c / relay.c）

1. 匹配：物理路径以 `/www/cgi-bin` 为前缀，或扩展名命中 `-i` 解释器（设备无）。非解释器脚本必须
   `S_IFREG|S_IXOTH`，否则 403。
2. 环境：清空后设 `PATH=/sbin:/usr/sbin:/bin:/usr/bin`，`GATEWAY_INTERFACE=CGI/1.1`、`SERVER_SOFTWARE=uhttpd`、
   `SCRIPT_NAME`、`SCRIPT_FILENAME`、`DOCUMENT_ROOT`、`QUERY_STRING`、`REQUEST_URI`、`SERVER_PROTOCOL`、
   `REQUEST_METHOD`、`PATH_INFO`、`REMOTE_USER`、`HTTPS=on`（TLS 时）、`REDIRECT_STATUS`、`SERVER_NAME`、
   `SERVER_ADDR`、`SERVER_PORT`、`REMOTE_HOST`、`REMOTE_ADDR`、`REMOTE_PORT`，以及请求头映射
   `HTTP_ACCEPT`、`HTTP_ACCEPT_CHARSET`、`HTTP_ACCEPT_ENCODING`、`HTTP_ACCEPT_LANGUAGE`、`HTTP_AUTHORIZATION`、
   `HTTP_CONNECTION`、`HTTP_COOKIE`、`HTTP_HOST`、`HTTP_ORIGIN`、`HTTP_REFERER`、`HTTP_USER_AGENT`、
   `HTTP_X_HTTP_METHOD_OVERRIDE`、`HTTP_AUTH_USER`、`HTTP_AUTH_PASS`、`CONTENT_TYPE`、`CONTENT_LENGTH`。
   `chdir(docroot)` 后 `execl` 脚本本身。
3. 请求体原样写入子进程 stdin；子进程 stdout 按行解析头直到空行：`Status: NNN text` 设状态；
   `Content-Length`/`Transfer-Encoding` 出现则不分块；其余头透传；然后正文按分块转发。缺省状态 200 OK。
4. 超时 60 s 杀进程；`-t 0` 关闭脚本超时。`-n` 控制并发脚本槽，超出时排队，静态请求继续服务。
5. 退出时无完整头、半头、坏头、输出头前超时 → 502；spawn/exec 失败 → 500。

## 5. `/ubus` JSON-RPC 桥（ubus.c）

| 请求 | 行为 |
|---|---|
| `GET /ubus/list[/path]` | `ubus lookup`，返回带签名的对象表（类型名 boolean/number/string/array/object） |
| `GET /ubus/subscribe/<path>` | Bearer session 需 ACL `:subscribe`，`-a` 可关闭鉴权；拒绝为 HTTP 200 + `{"code":-13,"message":"Permission denied"}`；`text/event-stream`，`-e` 设置 retry，每条通知 `event: <method>\ndata: <json>\n\n` |
| `POST /ubus` 或 `/ubus/` | 正文为 JSON 对象或数组（数组为批量，逐个处理，结果用 `[ ... ]` 包裹）；最大 65536 字节 |
| `method: "call"` | `params = [sid, object, method, args]`；`sid` 缺省 32 个 0；先 `ubus lookup`，再调 `session.access {ubus_rpc_session, object, function}`；通过后调用目标并注入 `ubus_rpc_session`；参数中自带 `ubus_rpc_session` → -32602 |
| `method: "list"` | 无参数 → `result: [对象名...]`；参数数组 → `result: {对象: 签名}` |
| 响应 | `{"jsonrpc":"2.0","id":<原 id 或 null>,"result":[status, data?]}`；ubus 错误 → `error:{code:<ubus status>,message}`；无返回数据时 `result:[0]` |
| 错误码 | -32700 Parse error、-32600 Invalid request、-32601 Method not found、-32602 Invalid parameters、-32603 Internal error、-32000 Object not found、-32001 Session not found、-32002 Access denied、-32003 ubus request timed out |
| `POST /ubus/call/<object>` | Bearer 头为 sid；JSON 的 `method` 为方法名、`params` 为参数 |
| `OPTIONS /ubus` | 200，`Content-Length: 0` |
| 头 | `Content-Type: application/json`；CORS 头仅在 `-X` 时 |

正文超出 65536 字节时返回 HTTP 200 + JSON-RPC -32700 并关闭连接。普通请求复用 ubus 连接，
空闲池最多 8 条；SSE 单独拥有连接并在客户端断开时释放。参考 uhttpd 在提前断开订阅的测试中
会保留客户端 fd，因此清理资源是候选的独立门，不把这个原版泄漏作为兼容目标。

## 6. TLS

设备在 443 提供 HTTPS，证书/私钥为 DER，`redirect_https=0`。候选必须同时监听 80 与 443；TLS
实现见决策 0009。证书/私钥无效时启动失败；`-q` 控制 HTTP→HTTPS 重定向；`-P` 支持
IANA、OpenSSL 与镜像 mbedTLS 的套件拼写。rustls 0.23.43 默认缓冲有界，候选显式设为 16 KiB；
慢读客户端的 128 MiB CGI 下载按 RSS 增量门验证背压。

## 7. 配置与鉴权（R83）

`/etc/httpd.conf`（`-c` 可改）支持路径 Basic 认证、明文/crypt 密码及 `$p$` 系统账户引用，
锁定或不存在的账户拒绝，空密码账户行为按原版。`-r` 设置 realm；认证后的 CGI 凭据覆盖同名请求头。
未受保护路径的 HTTP_AUTH 头映射保持原版行为。

`-I` 索引文件、`-i` 解释器、`-y` alias、`-b` 目录字符集、`-S` 符号链接限制、`-A` TCP keepalive
均生效。包的 init 脚本不再默认开启 `--call-log`；显式开启时才维护调试清单。

## 8. 参考用例

见 [r14_httpd_check.py](../../tools/r14_httpd_check.py)：一组 HTTP 请求（静态、条件、目录、404、CGI
登录页、`/ubus` list/call/batch/legacy/OPTIONS/错误）对原 uhttpd 与候选并排执行，比较状态码、
关键头与正文哈希；`Date`、`Keep-Alive` 值等时变项屏蔽。
R83 增补 r14 的 CGI 错误、环境、query 和 UA 用例，r27 比较正文长度及哈希；
`tools/r83_httpd_compat.py` 覆盖 Basic auth、选项、连接/脚本队列、慢头、SSE、连接复用和 TLS。

## 9. R92 边界合同

- 检查顺序为 RFC1918 过滤 → HTTPS 重定向 → 100 Continue；loopback 不增加 C 中没有的例外。
  `-E` 也处理静态文件/禁目录列表的 403，传 REDIRECT_STATUS，错误处理器递归有界。
- 裸端口同时尝试 IPv4/IPv6；主机名按解析结果绑定；任一成功监听可保留。重定向只选实际绑定的
  同地址族 TLS 监听，并优先 443。CGI 三字符 Status 按原版 atoi 前缀解释，包括 `abc` → `000`。
- header 阶段错误发送完整 chunk 结束符；原版可缺少结束符。chunk 扩展和有限 trailer 继续接受
  （单行 4096 字节、trailer 总计 8192 字节且至多 64 行）。chunk 长度不得超过 INT_MAX。
  framing 错误返回 HTTP 400 并关闭，原版在 `/ubus` 下可回 HTTP 200 + -32700。
- 控制字节请求头（允许 HTAB）立即返回 400，避免 NUL 截断或无法传入 CGI 环境；LF-only 请求
  继续接受。完整的 22 项处置逐项记录在
  [r92-deviations.json](../../tests/reference/httpd/r92-deviations.json)，不是笼统豁免。
  [r92_httpd_fuzz_gate.py](../../tools/r92_httpd_fuzz_gate.py) 比较 133 项完整规范化响应；
  仅控制字节头、超大 chunk 两项允许相对正式 R89 改变，其余保持既有结果。
- batch 回复逐项序列化、写出并 flush；下游写失败立即终止后续 RPC。仍保留 ≤65536 字节的输入
  JSON 树和一个 RPC 的回复，不承诺把任意单次 RPC 回复限制到固定字节数。原版也会在慢读下积压。
- ubus 连接失败：JSON-RPC call → -32000；GET list → HTTP 500/code 2；lookup 状态按实际返回。
  候选重连并执行配置的 deadline；原版断连后可能一直失效，lookup 无超时。这两项恢复改进保留。
- `-n` 等候槽由线程调度唤醒，不保证原版 LIFO 顺序；队列用例验证槽位上限、每请求只执行一次及
  全部请求完成。无客户端接口依赖 LIFO，避免为内部排队次序引入额外全局队列。

运行对照：[r92_compat_probe.py](../../tools/r92_compat_probe.py) 的 HTTP 场景；慢读 batch
与失败停止：[r92_recovery_probe.py](../../tools/r92_recovery_probe.py)。

## 10. R93 共享连接槽恢复

`-N` 的计数覆盖全部 HTTP/HTTPS、IPv4/IPv6 listener。满额后任一连接关闭、停放连接到期、
TLS 初始化失败或工作线程创建失败，都通过同一释放入口归还连接槽；从满额变为可接入时
唤醒全部 listener。新请求不需要等另一 listener 的 50 ms 防御重查。唤醒写使用非阻塞管道，
重试 EINTR；管道已满表示已有唤醒待处理。注册失败保留有界重试，不进入无限等待。

[双监听器回归](../../tools/r93_httpd_cap_probe.py) 检查主动连接关闭、停放连接关闭、停放到期后的
接入和完整响应。接入测试同时确认满额时请求留在 backlog，不通过提前接入降低恢复延迟。
50 ms 连接停放和恢复时新建工作线程的策略不由本修复改变。

## 11. 独立审查请求头资源界限

v0.3.0 只有单行 4096 字节上限，短头行可在网络 deadline 内持续累积到内存。
新增累计 64 KiB 和 512 字段上限是相对于匹配 C 原版的明确加固分歧；既有单行错误语义不变。
计数只覆盖当前请求头，保留正文和下一条管线请求；超限后不再派发当前请求或后续管线请求。
512 字段上限保留现有 300 字段兼容用例。测试覆盖累计字节和字段数边界、前导空行、连续管线请求。
