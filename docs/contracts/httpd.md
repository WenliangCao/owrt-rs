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
| 限制 | 头缓冲 4096 字节，整个请求头有网络 deadline；`-N` 为所有 listener 共享的连接上限，满时停止 accept，空出后继续；`-N 0` 不限 |

## 3. 静态文件（file.c）

1. URL 按 `?` 切分查询串，路径 URL 解码，从最长前缀起逐级 `canonpath`+`stat`，剩余部分为 `PATH_INFO`；
   解析结果必须仍在 docroot 内。
2. 目录：无尾斜杠 → `302 Found` + `Location: /path/[?query]`；有尾斜杠 → 依次找
   `index.html`、`index.htm`、`default.html`、`default.htm`；都没有 → 目录列表（HTML，按名排序）。
3. 文件：要求 `S_IROTH`；方法只允许 GET/POST/HEAD/OPTIONS，否则 405。
4. 响应头：`ETag: "<ino>-<size>-<mtime>"`（十六进制）、`Last-Modified`、`Date`、`Content-Type`（按扩展名表，
   缺省 `application/octet-stream`）、`Content-Length`；文件响应不分块。
5. 条件请求：`If-Modified-Since`（≥ mtime → 304）、`If-Match`（不匹配 → 412）、`If-None-Match`
   （匹配：GET/HEAD → 304，其他 → 412）、`If-Unmodified-Since`、`If-Range`。304/412 响应带 ETag/Last-Modified/Date。
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
