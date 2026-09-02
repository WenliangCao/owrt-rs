# AX3000T stock / OpenWrt 25.12.5：阶段 3 —— R14 uhttpd 替换（httpd-rs）

> 日期：2026-09-02
> 状态：`complete_live_boot_enabled`
> 合同：[C3](../../docs/contracts/httpd.md)；决策：[0009](../../docs/decisions/0009-replace-uhttpd-with-rust-httpd.md)

## 实现

`components/httpd`（约 2000 行）：HTTP/1.0/1.1 解析与 keep-alive、静态文件与条件请求、目录列表、CGI
（fork/exec + 头解析 + 分块中继）、`/ubus` JSON-RPC 桥（复用 `components/ubus`）、RFC1918 过滤、
自写最小 JSON、TLS（rustls + ring，唯一第三方依赖）。每连接一线程、阻塞 I/O。接受 uhttpd 的
命令行，因此 `/etc/init.d/owrt-httpd` 用与原 init 脚本相同的逻辑从 `/etc/config/uhttpd` 生成参数。
静态 musl 二进制 1,249,416 字节；SDK 动态 musl PIE 打包为 `owrt-httpd`。

## 离线并排比对（oracle，精确 rootfs，真实 ubusd + rpcd + LuCI CGI）

同一 38 个请求从宿主机发往 chroot 内的原 uhttpd 与候选：

| 类别 | 请求 | 结果 |
|---|---|---|
| 静态 | `/`、`HEAD /index.html`、HTTP/1.0、`/luci-static/resources/cbi.js`、CSS、查询串、`%2e` 编码、路径穿越 | 一致 |
| 目录 | 无尾斜杠 302（分块、无 Content-Length）、目录列表（符号链接按文件处理） | 一致 |
| 条件 | `If-None-Match` 304；`If-Modified-Since` 在 musl 上因 `strptime %Z` 失败而恒不生效（两者都返回 200） | 一致 |
| 错误 | 404、`PUT` 405、`/ubus/other` 404、`/cgi-bin/nope` 404 | 一致 |
| CGI | `/cgi-bin/luci`、`/admin/status/overview`、HEAD（403 登录页 + `x-luci-login-required` 等头） | 一致 |
| `/ubus` | OPTIONS、GET list、GET list/session、POST list、access、拒绝、坏 sid、无对象、坏方法、坏版本、参数含会话、批量、坏 JSON（保持 keep-alive）、legacy call、legacy 无对象、登录、Expect: 100-continue | 一致 |

屏蔽项：`Date`、`Keep-Alive`、`Set-Cookie`、`ETag`（含 inode）、会话 id、CGI 正文（只比长度区间）。
机器记录：`private/stage3/r14-httpd.json`（摘要进入 manifest）。

## 设备步骤

| 步骤 | 观察 |
|---|---|
| 安装 0.1.0-r1 | 三文件哈希与离线一致；原 uhttpd（pid 2016）不受影响；无 rc 链接；switch disabled |
| 并排 8080/8443（0.1.0） | 候选启动失败：`[::]:8080` 与 `0.0.0.0:8080` 冲突。原 uhttpd 用 `IPV6_V6ONLY`；候选未设。原服务全程正常 |
| 修正 0.1.1 | v6 监听套接字设置 `IPV6_V6ONLY`，宿主机双栈复测通过 |
| 升级 0.1.1-r1 | 三文件哈希与离线一致；原 uhttpd 仍在运行 |
| 并排 8080/8443 | 候选与原服务同时监听；宿主机 13 项探针 × HTTP/HTTPS 与原服务 80/443 完全一致（含 LuCI 登录页 403、`x-luci-login-required`、`/ubus` access/denied、304、OPTIONS）；TLS 用设备现有 DER 证书握手成功 |
| canary | `switch enable`：原 uhttpd 停止，候选接管 80/443；探针与原服务基线一致；`disable` 后原 uhttpd 恢复、HTTP 200 |
| go-live | `boot-enable on` 把 `S50uhttpd` 换成 `S50owrt-httpd/K50owrt-httpd`；`enable` 后探针再次与基线一致 |

候选记录到的 `/ubus` 调用清单（阶段 5 输入）：`session access`；用户登录 LuCI 后清单会继续累积在
`/tmp/owrt-httpd-calls.txt`。

## 监测窗口（约 3 分钟）

2026-09-02T13:10:49Z 至 13:12:40Z，三次只读探测，间隔约一分钟。每次结果相同：

| 项 | 值 |
|---|---|
| uhttpd pid | 无 |
| httpd-rs pid | 22540（未重启） |
| 监听 | 0.0.0.0:80、0.0.0.0:443、[::]:80、[::]:443 |
| switch / boot-enable | enabled / on |
| RSS / 线程 | 1840 kB / 5 |
| 主机 `GET /cgi-bin/luci` | HTTP 403（登录页，与 uhttpd 基线一致） |
| 主机 `GET https://…/cgi-bin/luci -k` | 200（自签证书，与基线一致） |

## 最终状态与退路

- 设备现状：httpd-rs 0.1.1 服务 80/443，`owrt-httpd-switch status` = enabled，`boot-enable on`，
  rc 链接 `S50owrt-httpd` / `K50owrt-httpd`；uhttpd 二进制与其 init 脚本原样保留。
- 退路：`owrt-httpd-switch disable`（一步回到 uhttpd，不重启）；`owrt-httpd-switch boot-enable off`
  撤销开机重挂；`apk del owrt-httpd` 全部清除。任何一步都不要求重启。
- 原始输出：`private/stage3/device/`（不入库）。
