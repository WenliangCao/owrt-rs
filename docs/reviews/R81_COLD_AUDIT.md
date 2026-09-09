# R81 全面审计：九个 Rust 组件 + ubus 库 + 差分工具链

日期 2026-09-09。对象：HEAD 19e85fa。方法：十个独立审计线程按组件分工，逐函数对照
C/ucode 参考源（netifd cbb83a18、procd 58eb263d、ubus 24864e78、rpcd 28faf640、uci 66127cd7、
firewall4 b6e51575、uhttpd 7b1bec45、ubox logd）读 Rust；协调方对每个 S1/S2 级结论重新
读源码复核（标"已复核"）。构建机 `oracle` 上 `cargo test --release` 全部 312 个单元测试
通过，clippy 只有 8 条风格提示。未触碰路由器。

预算说明：审计中途按用户要求收窄到高爆炸半径路径；"未覆盖"项列在 §2。

置信度：**读码确认** = C 与 Rust 片段并列即可证明；**假设** = 需运行才能证实。
严重度：S1 断网/安全；S2 调用方可见偏差；S3 潜在偏差（本机配置下不触发）；S4 开销/卫生。

---

## P0

**procd-rs 作为 PID 1 用 `eprintln!` 往自己设成 O_NONBLOCK 的 stderr 写日志。** 串口
发送缓冲满（XOFF、线噪 0x13、或 respawn 循环一次刷出 >4 KiB 日志）时 `write` 返回
EAGAIN，Rust 标准库对 stderr 写失败除 EBADF 外一律 `panic!`，release profile 是
`panic = "abort"`，PID 1 退出即内核 panic；此时 procd 已停止喂狗，只能等硬件看门狗复位。
C procd 同样把 stderr 设成非阻塞（state.c:54），但日志走 `ulog`（kmsg → syslog），从不
写 stderr，stdio 写失败也不检查。详见 F01。

---

## 1. 范围

**覆盖**：netifd（main/interface/device/config/ip/netlink/sys/ethtool/ubus/proto/wireless/process）、
procd（除 trigger.rs/jsonscript.rs/watch.c/dispatch 解析外全部）、ubusd 全部 + owrt-ubus 库
（blob/msg/conn/json/convert/sys）、rpcd（session/file/uci/rc/sys/rrdns/luci-rpc/main；iwinfo
仅 netlink 生命周期）、httpd 全部、fw4 全部、uci 全部、logd 全部、reload-config 全部、
tools/ 下全部差分脚本与 fuzzer、312 个 `#[test]` 的断言体扫描。

**未覆盖**：netifd iprule/vlan/tunnel（本机不用，仅确认"缺失"）；procd trigger/jsonscript；
rpcd iwinfo nl80211 字段级、luci.rs 21 个 ucode 移植方法；uhttpd auth.c 主体（未移植，见 F-H12）；
rustls 源码（F-H5 标假设）；libubox `uci_blob.c`（不在本机，F-N14 标假设）；
所有需要 rootfs/root/路由器的 harness 都未执行。

---

## 2. 发现（按严重度）

### F01 — PID 1 日志写非阻塞 stderr 可致 abort → 内核 panic
S1 · procd · 读码确认（机制）/假设（触发频率） · **已复核**
- rust `components/procd/src/sys.rs:561-566`（fd 2 加 O_NONBLOCK）、`sys.rs:273`（`klog` → `eprintln!`）、全 crate 50 处 `eprintln!`；`Cargo.toml` `panic="abort"`
- c `state.c:54`（同样 O_NONBLOCK）、`procd.c:128` `ulog_open`（日志走 kmsg/syslog）
- 触发：ttyS0 115200，4 KiB 发送缓冲；任何让 tty 停止排空的条件（XOFF、线噪）叠加一次 >4 KiB 的日志突发。
- 修法：日志改走 `/dev/kmsg`（INIT 前）/ `syslog(3)`（INIT 后）；保留的 stderr 写法一律 `let _ = writeln!(io::stderr(), ..)`；加 panic hook 做 C 的 `do_reboot()`（sync、sleep 2、reboot）而不是 abort。
- 测试：`tools/audit/r81_procd_findings.rs`（填满 O_NONBLOCK 管道后 `catch_unwind(eprintln!)`）。

### F02 — ubusd 对无 path 的系统对象（event/acl/monitor）一律拒绝非 root 调用
S2 · ubusd · 读码确认 · **已复核**
- rust `components/ubusd/src/server.rs:473-478`（`o.path.clone().unwrap_or_default()` → `b""` 进 `Acl::check`）、`acl.rs:55-59`（只放行 uid 0）
- c `ubusd_acl.c:108`（`!obj → return 0` 放行）；合同 `docs/contracts/ubusd.md:188` 自己也写了 `obj == NULL → 直接放行`
- 影响：本机 wpad 以 uid `network` 运行（PRIVILEGE_SURFACE.md:102），`acl.d/wpad_acl.json` 的 `send: [bss.*, wps_credentials]` 规则形同虚设——hostapd 每次 `ubus_send_event` 得到 STATUS 6，`ubus listen bss.*` 收不到；任何非 root `ubus send/listen`、`acl query` 都被拒。r36 §7 只以 root 跑 listen/send，故未发现。
- 修法：`invoke()` 传 `Option<&[u8]>`，`None` 直接放行；不要对 path 用 `unwrap_or_default`。event/acl 对象自己的 SEND/LISTEN 检查保持。
- 测试：`tools/audit/r81_ubusd_acl_pathless.rs`。

### F03 — netifd-rs 没有 SIGTERM 处理：restart/stop 后 udhcpc/odhcp6c/handler 子进程全部孤儿化
S2 · netifd · 读码确认 · **已复核**（main.rs 只装了 SIGCHLD）
- c `main.c:316-340,410`（SIGINT/TERM → uloop_end → `netifd_kill_processes` SIGKILL 全部子进程）
- 触发：`/etc/init.d/network restart`（procd 发 SIGTERM）。旧 udhcpc 继续 renew 并向新 daemon 灌 `notify_proto`；`pgrep udhcpc` 每个接口两份。
- 修法：自管道方式装 SIGTERM/SIGINT；退出前对所有 Slot（protos/hotplug/wslot）SIGKILL。

### F04 — 删除/重命名接口后 ProtoState 直接 drop，helper 不杀、teardown 的 kill 请求被拒
S2 · netifd · 读码确认（两位审计者独立得出）
- rust `main.rs:365-381`（`set_down` 起 teardown 脚本，同一调用里 `protos.retain` 丢 Slot；`process.rs:31` 注明 drop 不杀）、`main.rs:1316-1333`（`notify_proto` 已找不到接口 → NOT_FOUND/NOT_SUPPORTED）
- c `proto-shell.c:384-397`（`proto_shell_free` SIGKILL 两个 task）、`interface.c:674-687,1415-1430`（remove 推迟到 teardown 完成）
- 触发：删掉 `config interface wan`（dhcp）后 `network reload`；或 `network.interface.X remove`。
- 修法：删除时保留 ProtoState 直到 `Finish::Down`，或先对两个 Slot SIGKILL（不等待）再 retain；`notify_proto` 按 ProtoState 而不是 `cfg.interfaces` 路由。

### F05 — 任何接口选项变化都 ifdown+ifup；C 只在 device/proto/handler 参数变化时 reload
S2 · netifd · 读码确认 · **已复核**
- rust `main.rs:90-97`（`config_changed` 比较整个 `InterfaceConfig` 去掉 `raw`；注释说的是 `uci_blob_check_equal` 语义，实现不是）
- c `interface.c:1287-1405`（metric/ip4table/ip6table → 只重挂 IP；dns → 只换 resolv.conf；ip6assign/hint → 重算前缀；peerdns/delegate 原地更新）
- 触发：`uci add_list network.lan.dns=1.1.1.1; commit; network reload` → lan 断一次，hotplug ifdown/ifup 触发 dnsmasq/firewall/odhcpd 重启；C 只改 resolv.conf.auto。
- 修法：实现 `interface_change_config` 的分类。

### F06 — `peerdns`/`defaultroute` 解析了但从不生效；非 static 协议的 `list dns` 被丢
S2 · netifd · 读码确认 · **已复核**（`no_dns` 只在 main.rs:2990 被读，无处赋值）
- c `interface.c:862-871`、`interface-ip.c:1543-1574`
- 触发：wan `option peerdns '0'` + `list dns '9.9.9.9'`（LuCI "使用对端通告的 DNS"关掉）：C 只写配置的 DNS，DHCP 的进 `inactive`；Rust 反过来。`defaultroute '0'` 仍装默认路由。

### F07 — `now()` 用墙钟：NTP 校时后 uptime 变成十几亿秒，前缀期限判定错乱
S2 · netifd · 读码确认 · **已复核**
- rust `main.rs:130-132`（`SystemTime` 自 UNIX_EPOCH）；`3243-3249` uptime；`1633-1650,2137-2145,3892-3913` 前缀期限
- c `system-linux.c:3795-3801`（CLOCK_MONOTONIC）
- 触发：路由器从 1970/编译日期时钟启动，sysntpd 校时后 `network.interface.lan status` 的 uptime ≈ 1.7e9；校时前存的 PD 期限之后全算过期。
- 修法：`clock_gettime(CLOCK_MONOTONIC)`。

### F08 — IPv6 地址/前缀分配的 preferred/valid 输出存储值而非剩余秒；`ipv6-prefix` 永远为空；`delegate 0` 不生效
S2 · netifd · 读码确认
- rust `main.rs:1611-1612,2192-2197`、`interface.rs:252-257,484-490`（原值输出）；`main.rs:1615-1651`（无处写 `ipset.prefixes`）；`main.rs:3918-3949`（不看上游 `no_delegation`）
- c `ubus.c:553-561,751-759`（`until - now` 钳 0）、`interface-ip.c:1345-1381,1325-1340`
- 影响：LuCI 显示与 odhcpd 读取的 `network.interface dump` 字段与 C 不同；wan6 `status` 缺 `ipv6-prefix`；`delegate 0` 时 lan 仍拿到 PD。r63 只跑了 static/udhcpd，PD 路径没比过。

### F09 — proto-shell teardown/abort 无 1 s/5 s 超时；wireless handler 无 30 s 超时；`Slot::terminate` 在事件循环里阻塞 `wait()`
S2 · netifd · 读码确认 · **已复核**（grep `teardown_timeout|5000|30_000|from_secs(30)` 为空）
- c `proto-shell.c:200-221,350-360`（超时 SIGKILL 并完成状态机）、`wireless-device.uc:13,194-198,235-237`（30 s cancel）、`main.c:261-268`（SIGKILL 不等待）
- rust `main.rs:1242-1277`（Abort 只发 SIGTERM）、`proto.rs:385-404`、`main.rs:4148-4259`（wslot 无 deadline）、`process.rs:186-192`（SIGTERM + 阻塞 `wait()`）
- 影响：忽略 SIGTERM 或 D 态的 helper 让接口永远停在 TEARDOWN，之后 `ifup` 被拒；一个卡住的 mac80211.sh 阻塞全部 radio；start_in 复用槽位时整个 daemon 阻塞到旧子进程退出。
- 测试：`tools/audit/r81_process_termination.rs`（要求 `terminate()` < 500 ms，当前应失败）。

### F10 — radio 正在 setup 时 `network reload` 的新 wireless 配置被静默丢弃
S2 · netifd · 读码确认
- rust `main.rs:3875-3877`（state 非 Up/Down 直接 return，无记录）
- c `wireless-device.uc:143-159,378-393`（`config_change=true`，setup 完成后重跑）
- 触发：启动期或连按两次 Save & Apply（2–6 s 窗口）。

### F11 — reload 时对非 DOWN 接口同步 set_down + iface_up，被状态机拒绝，之后多发一次 ifup-failed
S2 · netifd · 读码确认
- rust `main.rs:424-445`、`proto.rs:274-286`（Teardown 态收 Setup → Refuse）
- c `interface.c:1228-1235,735-790`（reload 从 IFPEV_DOWN 回调里做）
- 触发：改 dhcp wan 的 `hostname` 后 reload；hotplug 序列 C 为 ifdown,ifdown,ifup，Rust 为 ifdown,ifdown,ifup-failed,ifup。

### F12 — `config device` 只应用 macaddr/mtu/txqueuelen；`ipv6 '0'` 等一律静默忽略
S2 · netifd · 读码确认
- rust `main.rs:886-906,800-808`；`config.rs:267-316`（`ipv6/promisc/multicast/mtu6` 解析后不用，未知选项也不报错——与 main.rs 自称"报错、从不忽略"矛盾）
- c `system-linux.c:2365-2471`
- 触发：LuCI 关掉 wan 设备的"启用 IPv6" → `/proc/sys/net/ipv6/conf/wan/disable_ipv6` C 为 1，Rust 为 0。

### F13 — `network.interface.X add_device/remove_device` 一律拒绝；`network.device status` 的 `up` 取 IFF_UP 而非 claim 计数；`disabled` 接口仍被创建发布
S2/S3 · netifd · 读码确认
- rust `main.rs:3490-3504`（注释"C 也这样"只对非 bridge 成立）、`main.rs:698`、`config.rs:330`+`main.rs:918-936`
- c `interface.c:1084-1115`+`bridge.c:980-1014`、`device.c:1355`、`config.c:147-149`

### F14 — 存在任何"不支持的段"（`config route/route6/rule`、旧式 `type bridge`）时**所有** reload 永远返回 INVALID_ARGUMENT
S3（本机配置无此段）· netifd · 读码确认 · **已复核**
- rust `config.rs:240-249`、`main.rs:306-316`
- c `config.c:633-656,786-826`（从不拒绝；route 段进 config_ip）
- 说明：R45 把静态路由段列为"本机不使用"，但失败模式过重：一条 route 段让之后改 LAN IP 也不生效直到重启。至少应降为 warning。

### F15 — logd-rs 重连逻辑在旧连接仍打开时永远注册不上 `log` 对象
S2（日志面完全失效直至 `service log restart`）· logd · 读码确认（机制）· **已复核**
- rust `main.rs:296-341`（`run_connected` 任何 Err 都进 `reconnect()`，而 `self.conn` 只在 `register_log` 成功后才替换；旧连接仍持有 `log` 路径，ubusd 拒绝重复注册 → 1 Hz 死循环）、`conn.rs:114-116`（>1 MiB 回复本地拒绝为 INVALID_ARGUMENT）
- c `logd.c:231-265`（`ubus_auto_connect`，只在 socket 真断后重连）
- 触发：`ubus call log read '{"stream":false}'` 且 ring 编码超 1 MiB（`log_size` ≥ ~660 KiB，`option log_size '1024'` 常见）；socketpair EMFILE 等亦然。
- 修法：`reconnect()` 先 drop 旧连接；本地 INVALID_ARGUMENT 按单请求错误回 STATUS 而不是当断线。

### F16 — logd ring 回绕分支只按队首 offset 驱逐，被覆盖的旧条目留在列表里
S2 · logd · 读码确认 · **已复核**
- rust `ring.rs:71-82`（`while front.offset <= next0 pop else break`；队首若是上一圈的高 offset 尾巴则立刻 break）
- c `syslog.c:195-206,304-325`（链从 `log` 重走）
- 影响：混合长度日志下（典型 60–200 B 夹杂 ~1 KiB 行）第一次"比上一圈更早回绕"就触发；`logread` 输出被覆盖的旧行，保留量超过 `-S`。r15/r28 用定长消息，永远同点回绕，测不出。
- 测试：`tools/audit/r81_logd_ring_wrap.rs`。

### F17 — fw4 `config defaults` 有非法选项时渲染 `policy null;`，而 R25 声称"按 ucode 默认值继续"
S2 · fw4 · 读码确认 · **已复核**
- rust `sections.rs:366`（`parsed.unwrap_or_default()` → 全 None）、`emit.rs:194`（`None => "null"`）、`render.rs:809-813`（`reject with icmpx type `）；`sections.rs:2166` 的 `parse_defaults({})` 兜底只在 `None` 时走，此处是 `Some(空)`
- ucode `fw4.uc:1942-1984`（strict 模式崩溃退 254）、`753-754`
- 影响：nft 拒绝规则集（与 ucode 崩溃结果同为无防火墙），但 `print` 退 0，`check` 报 nft 语法错误而非具体选项，`start` 在 nft 失败前已写 `fw4.state` → 之后 `fw4 start` 说"already loaded"。R25 §3.1 的 DEVIATION 描述不实。r29 fuzzer 遇 ucode 崩溃即跳过，不检查 Rust 输出。
- 测试：`tools/audit/r81_fw4_defaults_fallback.rs`。
- 未发现 Rust 规则集比 ucode 更宽松、或 ucode 能加载而 Rust 不能的用例。

### F18 — httpd CGI 错误面：脚本无完整头 → 200（C 502）；超时 → 504、坏头 → 500（C 均 502）；spawn 失败 → 直接断连（C 500）
S2 · httpd · 读码确认 · **已复核**（cgi.rs:339-356 vs proc.c:192-201）
- rust `cgi.rs:138,339-356,440-443`、`main.rs:308-310`
- 触发：`/cgi-bin/luci` 打印头之前崩溃、cgi-io 内部错误、`#!/usr/bin/missing`。

### F19 — httpd 把所有含 `Safari/`+`Mac OS X` 的 UA 都强制 close；macOS 上 Chrome/Edge 每个请求新建 TCP+TLS
S2 · httpd · 读码确认 · **已复核**（http.rs:249-251 vs client.c:419-447 先判 Opera/MSIE/Chrome）

### F20 — httpd 其他偏差
S3 · httpd · 读码确认
- 请求头阶段只有每次 read 30 s，没有整体 deadline（`main.rs:475-477`）→ slow-loris 可占满 100 个槽；`max_connections` 满时 accept 后立即关（C 停 accept 排队），`-N 0` 拒绝一切（C 不限）。
- `/ubus` body >64 KiB 回 413 HTML（C 200 + JSON-RPC -32700，`main.rs:371-376`）；LuCI 编辑 >64 KiB 文件得到非 JSON。
- 404/403 正文丢 query、用规范化路径、HTML 转义风格不同。
- 合同列了 `GET /ubus/subscribe` SSE，未实现且未记为偏差。
- `-n -S -q -I -i -y -A -c -r -e -b -P` 接受即忽略；本机 init 传的 `-n 3 -A 1` 都是空操作；`-t 0` 变 1 s；`/etc/httpd.conf` basic auth 完全未移植（配置了即静默绕过）。
- **假设**：TLS 下 rustls `Stream::write` 缓冲明文使 `pending()==0`，CGI 大文件下载到慢客户端时无背压、内存增长。
- 每个 JSON-RPC 元素一次 `connect()`+HELLO（C 进程生命周期一条连接）；init 脚本（`owrt-httpd.init:35`）仍带 `--call-log` 调试清单，每请求加锁、排序、重写 `/tmp/owrt-httpd-calls.txt`。

### F21 — procd `service set`（含内容不变的 reload）把运行中实例的 stdout/stderr 日志管道关掉
S2 · procd · 读码确认 · **已复核**（instance.rs:284-301 `*self = new`，保存元组不含 `log_out/log_err`，new 里为 None）
- c `instance.c:1513-1570`（`instance_config_move` 不碰 `_stdout/_stderr`）
- 叠加：Rust std 在 exec 前把 SIGPIPE 复位为 SIG_DFL（C 子进程继承 SIG_IGN，`procd.c:90`），带 `stdout 1` 的服务 reload 后再写日志即 141 退出。
- 触发：任何 `procd_set_param stdout 1` 的服务执行 `/etc/init.d/x reload`。

### F22 — procd 其他偏差
S2/S3 · procd · 读码确认
- `service delete '{}'` 回 INVALID_ARGUMENT（C NOT_FOUND，`main.rs:1537`）。
- stdout 管道实例缺 `LD_PRELOAD=/lib/libsetlbf.so`（日志按 4 KiB 块到达，kill 时丢尾）。
- `service.data.update` 不再对每个解析实例触发（`instance.c:1664`）。
- 无 cgroup 归置 `/sys/fs/cgroup/services/<svc>/<inst>`（本机 cgroup2 已挂载）。
- hotplug `makedev` 在 `umask(0)` 下 `create_dir_all` → 0777 目录（C 0755）。
- inittab exec 失败不再按 500 ms 重试；未知 `facility` 以 -1 进 openlog；合成的 `DEVNAME/DEVICENAME` 泄入 hotplug 脚本环境与通知。
- 主循环固定 200 ms 只 poll ubus fd，uevent/子进程退出/日志管道都按 tick 处理（+200 ms 延迟，空闲 5 次/s 唤醒）。

### F23 — rpcd `file exec` 与 luci 的 shell 帮助函数在单线程请求循环上同步执行
S2 · rpcd · 读码确认 · **已复核**（main.rs:175-187）
- c `file.c:1047-1065`+`exec.c`（uloop 注册 + `ubus_defer_request`）
- 触发：LuCI 诊断页 ping/traceroute（`-t` 30 s）期间，uhttpd 每个 JSON-RPC 都要的 `session access` 全部阻塞；`uci apply` 回滚定时器延迟。rc/rpc-sys/rrdns 已有 `Deferrer` 线程模式，file/luci 没用。

### F24 — rpcd 其他偏差
S3 · rpcd · 读码确认
- `file` 参数/回复经 `Json`：非 UTF-8 `data`/`path` 变 `""`（`file write` 把目标截成空文件、rc 0），read/exec 输出替换为 U+FFFD（C 原字节）。同一根因也在 owrt-ubus `convert.rs:404`：任何非 UTF-8 STRING 字段被换成空串（hostapd 的 GBK SSID 等）。
- `file write` 的 `umask(0)` 窗口与 rc/uci/rpc-sys 在工作线程里 `Command::spawn` 竞争：util.rs 断言"单线程"已不成立，子进程可能继承 umask 0。
- exec ACL 命令行长度判定差一（`file.rs:276`：C 含 NUL）。
- `reload_config`/`upgrade_start`/`factory`/`reboot` 的 2 s 延迟动作在线程里而非 fork 子进程，SIGHUP/SIGUSR1 内 2 s 即丢失。
- rrdns 截断/畸形响应输出部分 PTR（C 整包拒绝）；`server` 为主机名时 UNKNOWN_ERROR。

### F25 — uci 偏差
S2/S3 · uci · 读码确认
- **S2** 匿名段改成不同长度的类型时 Rust 仍匿名，libuci 变具名（`list.c:724-738` 走 `uci_alloc_section(old->e.name)`）：`uci set network.@device[0]=bridge` 后 `show`/`commit` 输出不同（`ops.rs:636-646`）。
- **S2** `uci delete pkg.sec.opt=`（空/空白索引）Rust 拒绝退 1，C 的 `!sscanf` 对 "" 返回 EOF 为真，删除整个选项（`uci-rs.rs:484-490`）。shell 里 `$idx` 为空的常见写法行为反转。
- S3 长行内 NUL：C `fgets` 分块保留行边界，Rust `read_until` 截断后粘下一行（`parse.rs:104-127`）；fw4/netifd/rpcd 共用此读取。
- S3 batch 模式解析错误缺 `(unknown) at line N, byte 0` 后缀；`add_list pkg.sec=v` C 成功写垃圾 delta、Rust INVAL；非 UTF-8 tuple 错误码/顺序不同、`rename` 到非 UTF-8 名被拒；扩展索引 `@t[ ]`/`@t[4294967296]` 与 strtol/int 截断不同。
- **S4** delta 保存与 commit 导出对裸 `File` 逐字节/逐 token `write(2)`（`delta.rs:28-35`、`file.rs:162`）：一次 `uci set` ≈16 次系统调用，`uci -m import` 2000 项 ≈40k 次；rpcd `uci set` 同路径。加 `BufWriter` 即可。
- 测试：`tools/audit/r81_uci_findings.rs`（7 个应失败 + 1 个对照）。

### F26 — reload-config 偏差
S3 · reload-config · 读码确认
- 子进程 10 s 超时使整轮 `run()` 提前返回：后续包不发事件、基线不重写（合同 C-08 要求继续），下次重发已送达事件（`engine.rs:157-179`）。
- 新加的 `flock` 对并发调用直接退 75 不做任何事（README 写了 fail-closed，合同未列为偏差）：两次快速 Save & Apply，第二次提交的包要到第三次才派发。改为阻塞等锁即可。
- 输入限制 fail-closed：`/etc/config` 里一个 >1 MiB 文件或非 UTF-8 文件名让整轮退 64、零派发（原脚本对怪文件哈希空串、其余照发）。

### F27 — ubusd/ubus 库其他偏差
S3/S4 · 读码确认
- 释放仍有订阅者的对象时 owner 收不到最后一条 NOTIFY(ACTIVE=0)（`server.rs:317-320` 丢弃 `reg.unsubscribe` 返回值；`ubusd_obj.c:190-211`）。
- MONITOR 镜像属性顺序 CLIENT,PEER,SEND,SEQ,TYPE（C 为 CLIENT,PEER,SEQ,TYPE,SEND）；事件 seq 每次派发一个（C 每条投递 `++event_seq`）；r36 §16 经 CLI 重渲染并 mask seq，看不见。
- HUP 时 acl.d 为空/不可读会清空 ACL 表并 seq++（C 提前返回不动）：sysupgrade/apk 瞬态期间 HUP 让 wpad/dnsmasq/ntp 失去权限直到下次 HUP。`.x.json` 点文件被当 ACL 加载（glob 不匹配）。
- `blob::iter` 接受末尾未填充的属性（libubox `blob_pad_len` 检查停止），仅 `attrs_of` 在顶层打了补丁；手工报文可让 Rust 注册 C 丢弃的方法。
- `server.rs:1037-1071` `append_json` 重复了 `convert::json_to_fields` 且整数全走 INT64（C INT32）。
- `json.rs:49-56` 浮点用最短往返格式，libubox 用 `%.17g`：`0.1` vs `0.10000000000000001`，LuCI 收到的 DOUBLE 字段字节不同。
- 每个 INVOKE 克隆 `Vec<u32>`+2 个 `String` 凭据（root 亦然）、每个 STATUS 新建 BlobBuf：≈10 次 malloc vs C 2 次；R82 显示墙钟不可见。

### F28 — 结构性冗余：八份手写 libc FFI
S4 · 全部 · 读码确认 · **已复核**
- `ubus/sys.rs`、`ubusd/sys.rs`、`procd/sys.rs`、`rpcd/util.rs`、`rpcd/iwinfo/sys.rs`、`netifd/sys.rs`+`netlink.rs`+`process.rs`、`uci/sys.rs`、`reload-config/unix.rs` 共 3.3k 行，各自重声明 `fcntl`（7 份）、`socket/bind`（8）、`signal/set_signal_handler`（3）、`umask`（4）、`getpwnam/lookup_user`（3）、`md5`（procd 与 rpcd 各一份）、`poll_fds`（ubus 与 ubusd 各一份）。ubusd 依赖 owrt-ubus 却零处使用 `owrt_ubus::sys`。目前各份 EINTR 处理一致，但任何一处修复不会传播到其他七处（F01 的 stderr 处理正是这种分散的产物）。
- `#[allow(dead_code)]` 9 处；`unwrap_or_default()` 109 处（其中 F02、F17 两处直接导致 S2）。

---

## 3. 工具链与 CI 发现

### H01 — GitHub CI 自 2026-09-07 起连续 12 次红，procd/ubusd/netifd 接管的所有提交都没跑过 CI 单测
运行确认。`host-tests` 在 `make check-tools` 步失败：dash 的 `sh -n tools/netifd_suite.sh` 报 line 60 "redirection unexpected"（`<<<`）；r49/r50/r51/r52/r53/r57 六个 `#!/bin/sh` 脚本还用了 `<( )`，本机 `sh -n` 同样报错（已跑）。它们只通过 `netifd_suite.sh` 的 `bash` 调用能跑。后续的 cargo test/clippy 步从未执行。修法：shebang 改 bash 或去掉 bash 语法；把 check-tools 放到测试之后。

### H02 — 掩码按最后一个键名匹配，把设置项一起遮掉
- r55/r58 `SKIP` 含 `multicast`，`devices.<n>.multicast`（设置布尔，`device.rs:380`）与 `statistics.multicast` 一起被跳过（已复核）；r19 `MASK_KEYS` 同理遮掉 `flags.multicast`；r26 把所有 32 位十六进制串都 mask，`file md5` 结果从未比较；r13 把 `file_exec_sh` 的 `code` 也 mask 掉（注释说要比的正是它）。

### H03 — 只记录不断言
- r50 只以最终 `interface dump` 决定退出码；`failed calls`、RSS/fd/线程数、kernel diff 只打印（已复核）。r55 `--- status $?` 进了段名，返回码从未比较（已复核）。r52 veth0 前后状态只打印。r57 `survived.txt` 不断言。r49/r63 两侧 kernel dump 同为空也判 identical。

### H04 — 参照方存活无哨兵：两侧同死判 identical
- r55/r58 `parse()` 退化为原文比较，`Failed to connect to ubus` 两侧相同即通过；r36 `daemon_alive: no`、r42 `survived: no` 对称记录；r59 FAILED→None 与崩溃候选的 `{}`→None 相等；r62 原文 diff。r52/r53 没有 r56 那种"参照方拿到租约"门（无 udhcpd 时全部 identical 退 0）。R36 §"三个假通过"与 R45 r51 记录过同类事故。

### H05 — 其他
- r62 注释说生命周期"未归一化"，实际 valid 分桶、preferred 0/非 0；r63 未记录地 mask 了 wireless `retry`；r36 `list_rc` 记的是 `printf` 的返回码、helper 缺失时两侧同样打印 SKIP；`check_netlink_consts` 只查 RTM_/IFLA_ 两个前缀两个文件（NDA_/NUD_/SIOC/ETHTOOL_ 不查，人工核对当前值正确）；`check_abi.sh` 无 SDK 时退 0；netifd_suite 的"full pass"不含 r46/r63/r65，SUBSET 部分运行退 0；r15/r28 定长消息测不到 F16，r28 两侧 `errors="replace"` 解码遮掉非 UTF-8 差异；r14/r27 CGI 正文只比 `len//512`，无 env dump、无 UA、无崩溃/超时/坏头、无 404?query、无 TLS；r09 发现 0 个 testcase 也退 0；r29 跳过 ucode 崩溃用例不检查 Rust 输出。

---

## 4. 核对后认为忠实的部分（压缩）

- **ubusd/ubus**：线协议读写状态机与 fd 传递、txq、`attrs_of` 策略、`check_method`、ADD/REMOVE/LOOKUP/INVOKE 转发、SUBSCRIBE 规则、HELLO/PING、客户端拆除顺序、id 分配、ACL 匹配/root 旁路/文件属主检查、`sys.rs` 结构布局（msghdr/cmsghdr/ucred/sockaddr_un/stat/pollfd）、conn.rs seq/peer 匹配。
- **procd**：状态机与 `kill(-1)` 广播、信号处理器异步安全、看门狗 ioctl、inittab 正则/askconsole 规则、rcS 顺序与超时、实例 start/exit/stop/restart 与 respawn 预算、uevent 解析/firmware 协议/环境过滤、sysinfo/statvfs/tm/utsname 布局、`system board/info` 字段序、sysupgrade 三布尔门与失败清理。
- **netifd**：netlink 编码（地址 flags/CACHEINFO、路由 scope/table/metric/prefsrc/MTU、neigh、bridge attrs、jiffies）、事件名/hotplug 环境/队列折叠、状态 dump 字段序、proto-shell `plan()`/`task_finish`/notify 属性与错误码、地址/路由项解析、handler 发现、wireless handler JSON/重试预算/notify 门、resolv.conf 写法、RTNLGRP_LINK 订阅与 C 一致、netlink/sys/ethtool/process 全部 unsafe 的结构布局。
- **rpcd**：session 全部（id 熵、超时、ACL 匹配、login 顺序、freeze/thaw）、file canonicalize/ACL 顺序/读写标志/exec 查找与超时、uci 15 个方法的参数策略与错误优先级、apply/confirm/rollback、rc list/init、rpc-sys、rrdns 查询构造、luci-rpc 租约/DUID/ethers 优先级、rtnl 结构偏移。
- **httpd**：请求行/头解析与限制、chunked、canonpath/docroot、目录列表、MIME、条件请求、CGI 环境变量集与 `PATH_INFO` 拆分、CLOEXEC、`/ubus` 分派与错误码、CORS、RFC1918 过滤、监听选项、rustls 配置。
- **fw4**：全部 `parse_*`、zone/forwarding/rule/redirect/nat/include/ipset 语义、`read_ubus` 字段、渲染的每个 chain/hook/priority、statefile 键、`/sbin/fw4` 子命令。
- **uci**：引号/反斜杠/注释、`cfg%02x%04x` djbhash、delta 前缀表与顺序、commit 的锁-导出-fsync-rename 序列、CLI 退出码与输出格式。
- **logd**：`<pri>` 解析、时间戳剥离、LOCAL7 丢弃、1023 截断、`lines` 语义、oneshot、notify 字段、socket 权限与降权顺序。
- **reload-config**：扫描集、排序、基线格式、变更判定、事件 JSON。
- **工具链**：r65（含 selftest）、r71/72/75、r79、r64、r61、r60、r56、r51、fuzzer 以 C 为 oracle 且可复现、r82 用 VmRSS。

---

## 5. 建议新增的门（每条附可判红的注入）

1. **PID 1 stderr 门**（F01）：ns 启动，stderr 接 pty，向 master 写 XOFF 后连杀 respawn 子进程 10 次，断言 PID 1 存活。注入：当前二进制。
2. **ubusd 非 root 系统对象**（F02）：r36 加 `asuser network ubus -S send bss.add '{}'`、`asuser nobody ubus call acl query`，断言两侧 rc 0；注入：删掉 send 规则 → 两侧 rc 6。
3. **孤儿门**（F03/F04）：remove/删段/SIGTERM 后 `pgrep -c udhcpc` 与 C 相等；注入：跳过 terminate。
4. **reload 粒度门**（F05/F11）：`list dns` 与 `hostname` 变更后 `ubus monitor`+hotplug ACTION 序列逐字节比较。
5. **peerdns/defaultroute 门**（F06）：udhcpd 下发 option 6，`peerdns 0`+`list dns`，比 resolv.conf.auto 与 `inactive.dns-server`。
6. **时钟门**（F07/F08）：sandbox `date -s +30d` 后比 `uptime` 与 `ipv6-prefix-assignment[].valid`；PD 服务器路径进 r63。
7. **超时门**（F09/F10）：`trap '' TERM; sleep 600` 的 helper，`ifdown` ≤6 s 到 IFEV_DOWN；handler 睡 3 s 期间 reload，须第二次 setup；handler 永不退出 → 35 s 内 `retry_setup_failed`；`tools/audit/r81_process_termination.rs` 进 CI。
8. **logd 门**（F15/F16）：`-S 2048` 填满后 `read {stream:false}` 须回错误状态且 `logread` 仍可用；r15 混入 900 B 行后比 `logread | wc -l`；r28 按字节比较。
9. **fw4 门**（F17）：r29 对每个 Rust 输出 `nft -c -f -`；ucode 崩溃用例与"坏段置空"的 ucode 输出比；`r81_fw4_defaults_fallback.rs`。
10. **httpd CGI 门**（F18/F19）：`cgi-env` 逐字节、崩溃/半头/挂起/坏头/坏解释器五例 502/502/502/502/500、Chrome-on-Mac UA 保持 keep-alive、404?query 正文哈希、100 连接 slow-loris 后第 4 个客户端须在 network_timeout 内被服务。
11. **procd 门**（F21/F22）：`stdout 1` 实例原样 `set` 后日志继续、pid 不变；`service delete '{}'` 状态比；`DEVNAME=net/tun` 后 `stat /dev/net`。
12. **rpcd 门**（F23/F24）：`file exec sleep 5` 后 200 ms 内 `session list` <1 s；`file read` 含 `\xff` 的字节比对；1023 字节命令行两侧 PERMISSION_DENIED；`uci reload_config` 后 2 s 内 HUP 仍执行。
13. **uci 门**（F25）：r16 加 `set @rule[0]=redirect; show; commit; cat`、`delete x.y.z=`、batch 坏 tuple、`@t[ ]`；r24 WEIRD 加 `\x00` 并放进 >31 字节值。
14. **工具链**：netifd `suite_selftest`（两侧 `/bin/false` 必须因存活原因判红）；掩码改为路径感知（`statistics.*`）；r50 断言 failed calls/fd/RSS/kernel diff；r52/r53 加租约门；CI 把 check-tools 改成 bash 语法检查并放到 cargo test 之后。

---

## 6. 复核记录

协调方逐条重读源码确认：F01、F02、F03、F05、F06、F07、F09、F14、F15、F16、F17、F18、F19、F21、F23、F28、H01、H02（r55/r58、device.rs:380）、H03（r50、r55）。其余按审计线程的并列引文采信，标"读码确认"。构建机测试：`cargo test --release` 10 个 crate 全绿（312 tests），clippy 8 条 `map_or`/`collapsible_match`/`is_multiple_of` 风格提示。

审计线程新增的演示测试位于 `tools/audit/`（8 个文件，均未运行；本机无 cargo，且它们不属于任何 Cargo target）。
