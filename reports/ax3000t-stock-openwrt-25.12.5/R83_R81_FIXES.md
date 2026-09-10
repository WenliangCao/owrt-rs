# R83：R81 冷审计修复核实与收尾

日期：2026-09-10。审计依据：[R81_COLD_AUDIT.md](../../docs/reviews/R81_COLD_AUDIT.md)
（`a903721`，28 项组件发现、5 项工具链发现）。接手时提交停在 `068eada`，另外已有一批未提交修复。
本轮保留已证实的修复，补齐漏项，修正修复中引入的差异，并加强会产生假通过的测试。

验证在 `oracle` 的一次性 rootfs 副本、mount/network/PID namespace 中执行。没有操作实体路由器，
没有生成或刷写发布固件。固件、提取目录、私有配置、TLS 私钥和原始观测保留在 Git 外。
最终验证、命令、构建产物摘要见 [validation.md](R83_parts/validation.md)。

## 1. 证据边界

部署规格为 `ax3000t-stock-openwrt-25.12.5` 的精确 rootfs。
上游基线见 [source-baseline.json](../../manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json)
与 [sources.json](../../manifests/ax3000t-stock-openwrt-25.12.5/sources.json)：netifd `cbb83a18`、
procd `58eb263d`、ubus `24864e78`、rpcd `28faf640`、uci `66127cd7`、
firewall4 `b6e51575`、uhttpd `7b1bec45`。

此前草稿把 `stage9/netifd` 目录直接称为 `cbb83a18`，这个说法不正确：现有 checkout 比该修订新。
本轮独立读取固定修订；涉及 `proto-shell` / `proto-ext` / ucode 所有权的差异，以镜像二进制和
镜像脚本的实际观测裁定。最明显的例子是退出时无线 handler 的清理：仅看 C 的进程表会误判它
应该存活，实际镜像退出会停止它，候选现已跟随这一行为。

分报告中保留的旧二进制 hash 和故障注入输出是历史复现证据，不代表最终构建。

## 2. 组件发现逐项处理

| 项 | 最终处理 | 验证依据 |
|---|---|---|
| F01 | procd 日志经不 panic 的写入路径；PID 1 panic/crash 走恢复路径 | 满非阻塞 stderr 单测；r83_procd_r81 的 PID 1 场景 |
| F02 | ubusd 的无 path 系统对象通过第一层 ACL 检查，保留对象自己的权限检查 | r36 root/非 root；r83_ubusd_acl 线级探针 |
| F03 | netifd 处理退出信号，停止协议脚本、helper、hotplug 和无线 handler | r83_lifecycle；r83_wireless_deadline shutdown |
| F04 | 删除接口保留 teardown 所需状态，完成后清理 helper | r83_lifecycle remove；r54/r58 |
| F05 | 区分协议重启、IP 参数变更、DNS 更新和前缀重分配 | r83_config：DNS/metric/route/rule reload；DHCP pid 保持 |
| F06 | 配置 DNS 对所有协议生效；peerdns/defaultroute 控制 active/inactive 与内核状态 | r52；r83_config 的真实 DHCP 租约及路由/resolv 快照 |
| F07 | 所有 netifd 时限和 uptime 使用 CLOCK_MONOTONIC | clock 单测、调用点核对；没有修改宿主墙钟 |
| F08 | 地址/PD 生命周期输出剩余秒；填写 ipv6-prefix；delegate 切换更新分配；普通 reload 保留协议 PD | 加强后的 r62：UP、倒计时、续期、替换、不同父前缀长度、delegate 0→1、撤回 |
| F09 | 1 s/5 s 协议超时、30 s 无线超时；terminate 发 SIGKILL 后立即返回，以 try_wait 回收 | process 单测；r83_lifecycle；无线超时门同时验证事件循环可用 |
| F10 | setup 期间的 wireless reload 记为待应用，结束后按新配置重跑 | 无线门直接核对 setup channel 1→6 |
| F11 | 接口 reload 在 DOWN 回调继续，避免立即 up 被状态机拒绝 | r54；r83_lifecycle/config 的事件和状态比较 |
| F12 | 应用 ipv6/promisc/multicast/mtu6，设置顺序与原版一致 | r63；r83_config 的 flags/sysctl |
| F13 | 实现桥端口热插拔；设备 up 取 claim 状态；disabled 段不发布；add_device 的 external 标志副作用生效 | r55 完整设备表；r79 无线入桥；r83_config |
| F14 | 不支持的段不再阻断整次 reload；补充 config route/route6 | r61 双侧错误配置比较；r83_config |
| F15 | logd 重连先结束旧连接；本地大回复和 socketpair 错误只影响当前请求 | oversize_read、ubusd 重连门 |
| F16 | 环回绕同时驱逐覆盖区与哨兵之后的旧记录 | 混合长度 C 算法金标；ring_wrap 的 read/logread；r28 |
| F17 | 非法 defaults/include 终止渲染、退 254，不输出 policy null | defaults 门；r09；r29 包括 ucode 崩溃例 |
| F18 | CGI 半头/坏头/输出头前超时返回 502，启动失败 500 | r14 CGI 错误、环境与正文哈希 |
| F19 | UA 按 Opera/MSIE/Chrome/Safari 顺序判定 | r14 macOS Chrome、Safari、旧 IE 变体 |
| F20 | Basic auth、CLI 参数、SSE、整体头 deadline、共享连接上限、CGI 队列、TLS 配置与背压、ubus 连接复用；关闭默认调试清单 | r14/r27；扩展 HTTP 门及独立资源门；见 httpd 分报告 |
| F21 | 原样 service set 保留运行实例的日志管道；spawn 保持 SIGPIPE 忽略状态 | 单测；r83_procd_r81；r65 |
| F22 | 修复 delete 状态、libsetlbf、每实例 data 事件、cgroup、makedev 模式、inittab 重试、facility 与 hotplug 环境；补齐 poll fd | 单测；r83_procd_r81；r65/r71/r72/r75 |
| F23 | file exec 用 worker/Deferrer；luci ucode 同步 helper 的指控经核对不成立，保留原版同步语义 | exec 并发与 session 响应时延门；原版 ucode 调用链 |
| F24 | 字节串贯穿 blob/JSON/file/ACL；去除并发 umask 窗口；修正 ACL 长度、DNS 包校验及主机名解析；所有两秒延迟动作含 uci.reload_config 用 fork | raw_bytes；r18 实际 PTR；延迟门覆盖 HUP、精确 PID 回收及 worker 状态不被抢走 |
| F25 | 匿名段改类型、空删除索引、长行 NUL、batch/tuple/非 UTF-8/扩展索引语义对齐；导出和 delta 缓冲写入 | libuci_fidelity；r16/r24；r83_uci_findings |
| F26 | 超时继续后续包并更新基线；并发调用等待锁；大文件及非 UTF-8 文件名不阻断整轮 | 11 个参考场景 + 9 个故障场景；使用原包链接参数通过大小门 |
| F27 | 订阅释放、monitor 属性顺序、事件序号、ACL HUP/点文件、blob padding、整数/浮点格式及热路径分配修正 | ubus/ubusd 单测；r36/r42/r83 线级门 |
| F28 | 共享 MD5、poll/信号封装、I/O ABI 结构、JSON→blob 转换与连接 shutdown；移除等价副本 | 各调用组件单测/差分；目标 SDK ABI/常量编译校验 |

## 3. 工具链发现逐项处理

| 项 | 最终处理 |
|---|---|
| H01 | 正确的 bash shebang；check-tools 按解释器检查；CI 先运行测试，再检查工具 |
| H02 | 网络计数器按字段路径屏蔽，保留 multicast 设置；r26 只屏蔽 session ID 位置，保留 MD5；r55 比较实际返回码和完整设备表。r13 的候选 exec code 原本已有硬断言，保留其对 C 进程回收竞态的说明 |
| H03 | r50 实际运行 200 周期并断言失败数、RSS/fd/thread 和内核状态；r52 断言租约与父端口状态；r57 断言重连期间存活；r49/r63 拒绝空内核证据 |
| H04 | 对两侧分别要求有效回复、UP/租约和存活，拒绝双空/双死；真实 namespace 双 false 注入验证 netifd 门能判红；r65 同时验证双死与中途截断 |
| H05 | PD 按数值比较，保留 wireless retry；helper 缺失、SDK 缺失、零测试和部分 suite 都不能称作通过；套件含 r46/r63 与无线时限门；日志混长并保留原始字节；HTTP 增补 CGI/UA/TLS，完整比较大 JSON 回复并断言双侧存活；fw4 比较 ucode 崩溃路径；RLIMIT 检查限定到实际表并改为交叉编译静态断言 |

另外修正了几处此前会掩盖问题或产生误报的夹具：r18 的 JSON 数字是 INT32，不能设置插件的 INT16
端口，原 DNS 响应器监听 5353 导致两侧都返回空对象；现监听实际的 53，并独立要求收到 PTR。
r65/logd 混长环夹具使用私有 proc 且阻断宿主 kmsg 输入，避免权限识别失败或宿主消息挤掉夹具日志。
r75 最后一步以 PID 1 exec 的 argv/env 为成功证据；该 exec 会结束 namespace，客户端是否来得及
记录错误码不具确定性，前四个失败回复仍逐字节比较。

## 4. 兼容范围与裁定

- F20 的 rustls“默认无界缓冲”是假设，当前锁定的 0.23.43 默认有界；实现显式设置 16 KiB，
  并用 128 MiB CGI 的慢 TLS 客户端验证 RSS。`-t 0` 按 proc.c 关闭超时。
- HTTP 提前断开 SSE 的 fd 清理单独要求候选完成；参考 uhttpd 在这个场景会保留 fd，报告保留双方
  实测值，未把这个差异隐藏在通用掩码中。
- r27 的 133 个畸形 HTTP 用例有 22 处既有差异、0 个存活失败，原始差分仍退出 1；
  逐项属于 R25/R33 已记录的错误路径边界，详见 httpd 分报告，不称作全等通过。
- fork 延迟动作必须在 rpcd HUP 后继续执行。候选还明确 shutdown 旧 ubus transport，防止子进程
  继承的 fd 占着旧对象名；只回收自己登记的 PID，并跨 re-exec 携带这些 PID，不抢 worker 的 wait 状态。
- F24 的修复覆盖 STRING **值**、文件路径、argv/env/output 与 ACL 对象/键。通用 JSON 对象字段名仍是
  UTF-8 String；任意非 UTF-8 字段名、事件名不是此次字节串转换修复所承诺的范围。
- netifd 保留既有本机范围：无 device 接口的热插拔主设备分配、静态路由 valid、无 proto 的接口对象、
  rule/rule6、隧道等完整通用配置语义不在本机替换合同内。F14 修正的是它们阻断其他配置 reload 的失败边界。
- F28 保留与各组件不同接口/所有权相对应的 FFI；不把所有低层接口强行纳入新框架。
  netifd 为 ABI 校验保留的 UAPI 常量及示例导入模块会产生 dead_code 警告；严格 clippy lint 门单独验证。
- logd 不复制原版小环/长记录下的越界内存读取；超大 oneshot 回复及时返回请求错误，而原版可能超时。
  两侧继续服务是该故障门的硬条件。详见分报告。

## 5. 分报告

[netifd 合同](../../docs/contracts/netifd.md) · [httpd](R83_parts/httpd.md) ·
[procd](R83_parts/procd.md) · [rpcd](R83_parts/rpcd.md) · [ubusd/ubus](R83_parts/ubusd.md) ·
[uci/reload-config](R83_parts/uci-reload.md) · [fw4](R83_parts/fw4.md) · [logd](R83_parts/logd.md) ·
[最终验证](R83_parts/validation.md)。
