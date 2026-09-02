# 决策 0009：用 Rust 重写 uhttpd（含 /ubus 桥、CGI、TLS）

> 日期：2026-09-02
> 状态：已定
> 阶段：阶段 3

## 背景

R14 uhttpd 以 root 运行、终结 TLS、执行 CGI（LuCI 本身），并把 `/ubus` JSON-RPC 暴露给浏览器。它的
失效面是 Web UI 不可用，SSH 不受影响。设备上没有 Lua/ucode 插件前缀、没有 httpauth、没有 alias。

## 决策

1. **范围**：`components/httpd` 实现合同 C3 全部内容：HTTP/1.0/1.1 解析与 keep-alive、静态文件与条件
   请求、目录列表、CGI（fork/exec + 头解析 + 分块转发）、`/ubus` JSON-RPC 桥（复用 `components/ubus`）、
   RFC1918 过滤。不实现 Lua/ucode 进程内插件（设备未用）。
2. **依赖策略放宽一次**：TLS 用 `rustls`（`ring` provider），这是唯一的第三方依赖。若交叉编译失败或
   体积不可接受（> 3 MiB），退路是候选只接 80 端口，443 保留给原 uhttpd（把原配置的 `listen_http`
   去掉），并在报告里标为缺口。
3. **JSON**：自写最小 JSON 解析/序列化（RFC 8259 子集，含转义与数字），不引入 serde；输出格式与
   `blobmsg_format_json` 一致（紧凑、无空格）。
4. **进程模型**：单进程、每连接一个 std 线程、阻塞 I/O（含 rustls `StreamOwned`）；CGI 子进程通过管道
   中继。选线程而不是单线程 `poll`，是因为 rpcd 调用与 CGI 都可能阻塞数秒，线程模型让一次慢调用
   不拖住其他页面请求，代码也更短。连接数上限沿用 `-N 100`。
5. **切换**：package `owrt-httpd` 默认 disabled；`enable` 停原 `uhttpd` 服务并以相同配置启动候选（读
   `/etc/config/uhttpd`），`disable` 反向；`boot-enable` 交换 rc 链接，形式同 0007/0008。
6. **验证**：在精确 rootfs 中用 ubusd + rpcd + 原 uhttpd 与候选并排跑同一组请求（含 LuCI CGI 登录页）；
   设备窗口先在 8080/8443 并排，再交换端口。候选记录每次 `/ubus` 调用的对象与方法，作为阶段 5 的输入。

## 后果

- LuCI 全部通过 Rust 前端提供；`/ubus` 调用清单成为 rpcd 替换范围的证据。
- 引入 rustls 使二进制增大约 1–1.5 MiB；overlay 剩余 57 MiB，可接受。
- 若 TLS 退路生效，"完整替换"降为"HTTP 由 Rust、HTTPS 由原 uhttpd"，报告必须写明。
