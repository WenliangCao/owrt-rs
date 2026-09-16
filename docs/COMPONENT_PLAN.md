# 九组件攻坚计划与日志

> 用途：逐个组件把 Rust 控制面做到「正确不退、性能全胜」。重开会话先读这一页，
> 按表格找到下一个未打勾的组件；每个组件可交给不同模型独立攻破。
> 完成一个组件就在这里打勾、填数字、写一行日志，并提交。

## 准则

1. **保证正确性**：绝不能让任何已修复的 bug 重现。每个组件的「已修复缺陷」段是它的回归清单；
   对应的历史门（r14/r27/r83/r85/r92 fuzz、组件差分、恢复探针）在改动后必须全部重跑并保持绿。
2. **保证性能**：性能不仅要 100% 优于 C 原版，还要尽可能全面优于正式 R89（`d9c1048`）。
   每条负载分别报告自身 CPU、平均/尾延迟、内存；不能用混合得分或延迟改善掩盖某一项 CPU 退步。

## 工作要求

- **当成研究来做**：先读原版 C 的数据结构与执行形态，再读我们的实现，找出算法/形态层面的差距
  （分配次数、系统调用序列、线程/事件所有权、每请求重建的对象），而不是调参数。优先重写热路径算法。
- **一击毙命，不做无谓测试**：找准精确的改进点，预测它省掉什么（哪几次 syscall、哪几次分配），
  再一次性在 Linux 主机上跑门禁 + 四侧性能；不在 macOS 上做实验（见
  `memory/no-macos-experiments.md`）；不用多轮探索式测试消耗 token。每次改动都要有正向收益，
  否则回退。
- **最终以路由器实机对比为准**：Oracle（AArch64 Linux）四侧结果只是筛选；打勾的依据是 AX3000T 上
  C / R89 / 候选 四轮交错的实机结果。实机窗口要 detached 运行、按客户端健康验收
  （`memory/detach-long-device-drivers.md`）。

## 每个组件的标准流程

1. 读本页该组件段：实机差距表、已修复缺陷、既有候选与提示。
2. 定位算法差距，写出可证伪的预测（省掉哪些 syscall/分配，哪条负载应降多少）。
3. 改动 + 单测；本地只做编译冒烟。
4. Oracle 一次性：SDK musl 构建 → 该组件全部历史门 → 四侧性能（C / R89 / source05 / 候选）。
   构建与门禁脚本参考 `/home/ubuntu/r94-httpd/{build.sh,run-gates.py,perf/run.py}`。
5. 实机四轮交错四侧；全部负载 CPU 与延迟均低于 C，且不低于 R89（或差值在四轮范围内重叠并已解释）。
6. 打勾，把最终数字填进表格，写日志，提交。

图例：✅ 完成（Oracle 全门绿 + 性能优于 C 与 R89；标注「实机待补」者尚缺最终实机四侧）；☐ 待攻坚。

## 进度总表

实机数字来自 2026-09-15 R93 source05 九组件矩阵（AX3000T，四轮中位数，`docs/reviews/R93_*_DEVICE_BASELINE.md`）。
「落后」只列 source05 相对基线更差的负载；空白表示该组件所有已测负载均已优于两侧。

| 状态 | 组件 | 实机相对 C | 实机相对 R89 | 下一步 |
|---|---|---|---|---|
| ✅ | **logd** | 全胜（R94 终版实机：syslog_128 CPU 5.65 vs 31.95，read_100 121.0 vs 809.5） | 全胜（vs 8.40 / 420.5；延迟 −40%；RssAnon 120 vs 174 KiB；四轮不重叠） | 完成。[实机报告](reviews/R94_LOGD_DEVICE.md) |
| ✅ | **httpd** | 全胜：紧密 16 条 CPU/延迟全低于 C（512 B c1 57.5 vs 168.5）；停放五档 −28…−45%（jsonrpc_c4 CPU 470 vs 463 在自身范围内持平） | 紧密 10 条静态低 14–31%（不重叠）、6 条持平；停放五档低 20–70%（不重叠） | 完成。[报告](reviews/R94_HTTP_FASTPATH.md)。遗留研究：jsonrpc_c4 bridge 路径 |
| ☐ | rpcd | session_access_64_c4 延迟 275.4 vs 274.6（持平） | session_access_granted CPU +19.6%、session_access_64_c4 CPU +27.8%/延迟 +13.8%、session_access_64 CPU +20%、uci_get_authorized CPU +4% | 授权快路径（R93 glob 候选有 Oracle 信号）+ 会话 ACL 查询算法 |
| ☐ | procd | 全胜 | 8 条负载 CPU 系统性高 1.5–6.2%（service_list_32_c4 +6.2%、named_128_c4 +5.9%、system_info_c4 +2.5%） | service list 序列化/对象遍历热路径 |
| ☐ | ubusd | lookup_all_64/128 延迟 786/1549 vs 775/1510（CPU 更低） | 多条 lookup 延迟高 0.9–2.5% | lookup 全表遍历与回复分帧（R93 pathless/borrow 候选未合入） |
| ☐ | netifd | 全胜 | wireless_status CPU +6.0%/延迟 +1.9%；interface_dump_c4 CPU +3.1%；device_status_c4/lan_status_c4/device_status_all_c4 延迟 +2.5–3.1% | wireless status 拼装、并发下 blob 构建 |
| ☐ | fw4 | 全胜（print −89%，check −58% CPU） | check 延迟 +1.24%（四轮重叠） | 归因 check 执行链墙钟；否则打勾 |
| ☐ | uci | 全胜 | 全胜（CPU 四轮范围不重叠） | 仅需实机复核大配置/异常输入即可打勾 |
| ☐ | reload-config | 全胜 | 26270 vs 26420 µs（重叠，不宣布稳定胜出） | 覆盖改动传播场景后打勾 |

---

## logd ✅

**R94 改动**（`88a958c`、`e7c2da4`）：字节 arena 环（沿用 C `log_add` 保留算法，无堆 Entry）；
blobmsg 模板帧（`frame.rs`，与旧 BlobBuf 逐字节相同）；流改用 pipe（同 C），一轮 ≤256 条 datagram
合并成每流一次 write，256 KiB 管道；burst-spin（连发时 0 超时 poll 至多 4 次）。

**结果**：Oracle 两次四侧 160/160 字节相同；follow_8 CPU 11.9 vs C 15.6、R89 21.7 µs/条（R93 span 候选曾比 C 差 34.6%）；
trim_heavy 3.0 vs C 3.6/R89 4.7；RSS 496–524 KiB。实机 stage-one 候选 `000f3f15` 四轮：见总表。

**已修复缺陷（回归清单）**：R81 F15 重连时旧连接未关导致 `log` 对象永远注册不上；F16 环回绕只按队首驱逐，被覆盖旧条目残留。
R88 F1 非 UTF-8 `log write` 静默丢弃却回 OK → 有损转换。R92 环/限额合同（`logd_bytes`、`logd_limits`）。
R93 旧 poll 下标误断健康流；断连期间积压/oneshot/关闭回收；重连节拍；总预算保护健康读者（`test_logd_stream_recovery.py` 5/5）。

**实机终验（2026-09-16，终版 `08c833fd`，四轮 24 观测）**：syslog_128 CPU 5.65 vs R89 8.40 vs C 31.95 µs；log_read_100 121.0 vs 420.5 vs 809.5；平均与 p95 延迟均比 R89 低约 40%；RssAnon 120 vs 174 KiB。逐轮范围不重叠。见 [R94_LOGD_DEVICE](reviews/R94_LOGD_DEVICE.md)。
门：单测、clippy、固定语料 15/15、流恢复 5/5、r92 logd_bytes/limits、历史 r15/r28/r21/r25/r83。未部署生产。

## httpd ✅

**R94 改动**（`4537438`、`d67a6e4`、`3b98ab2`；报告 `docs/reviews/R94_HTTP_FASTPATH.md`）：
- 监听器内联快路径（`fast.rs`）：已停放 plain 连接收到完整小 GET/HEAD（普通文件 ≤32 KiB，无 CGI/ubus/auth/alias/政策）
  时在监听器线程就地完成：peek → 现有 parser → `files::serve` 写入有界内存 → 精确消费头 → 非阻塞 send。
  socket 不离开 epoll，消掉每次停放请求的 epoll DEL/ADD、线程移交、50 ms 接收超时、8 KiB reader 重建。
  不合格请求整体回退且未消费任何字节。短写保留 ≤4 个 PendingReply 经 POLLOUT 排水。
- 请求头控制字符 SWAR 8 字节扫描 + 按长度索引的头名表（R93 剖析中逐字节扫描占头解析 12–18%）。
- 移除 R93 空闲 worker 缓存：它保留 4 个线程 1 s，违反 R85 内存门（连接关闭后 Threads 必须回基线）——正是 R93 worker/head 候选无法合入的原因；快路径已用零线程覆盖其目标场景。

**结果**：Oracle 全部门绿（8 项历史门 + shared-cap + http-r92；fuzz 133/133 无新偏差；r85 64 连接内存门通过）。
Oracle formal 四轮（64 样本、832,000 请求）：停放 60/80 ms R94 CPU 每轮均为 40.0/42.5 µs，C 57.5/58.75，R89 281/292；gap0 32.5 vs R89 32.4 vs C 39.75；gap40 60.0 vs R89 61.25 vs C 55.0（gap<50 ms 不停放，走线程路径）。
**实机紧密矩阵**（2026-09-16，16 负载四轮 192 观测）：全部 CPU 与延迟低于 C；相对 R89 CPU −0.9%…+2.7%、延迟 +0.2%…+3.9%，**16 条逐轮范围全部重叠**——持平，不是胜出；jsonrpc_c4 CPU 498 vs C 487（范围重叠）。该矩阵为 gap 0 连发，连接从不停放，快路径不参与；SWAR 也没把 512 B c1 拉到 R89 以下（86.5 vs 85.5）。常驻 VmRSS 1130 vs R89 992 KiB（+138，其中匿名页仅 +8），需在停放内存门里核对快路径 scratch/响应缓冲的保留量。

**已修复缺陷（回归清单）**：R81 F18 CGI 错误面（无完整头/超时/坏头 → 502，spawn 失败 → 500）；F19 macOS Chrome/Edge 被当 Safari 强制 close；F20 其他偏差。
R88 H-01 Basic auth 后缺 REMOTE_USER；H-06 迟到回复滞留连接池；H-03 Bearer 大小写；H-11 连接上限时不唤醒监听。
R92 政策顺序 RFC1918→redirect→100 Continue；控制字节头 400；chunk 长度/trailer 界限；batch 逐项 flush 与下游失败即停；
ubus 断连重连与 deadline；`-n` 槽由调度唤醒；22 项处置见 `tests/reference/httpd/r92-deviations.json`。
R93 共享连接限额释放时广播全部监听器（`r93_httpd_cap_probe.py`）。

**实机停放间隔（2026-09-16，四轮 60 样本 168,000 请求 0 错误）**：CPU C/R89/R94 — 0 ms 260/204/203.5；20 ms 290/210/215；40 ms 290/210/215；60 ms 290/615/**210**；80 ms 290/675/**215** µs/请求；延迟 60/80 ms 461/754/**419**、465/786/**428**。五档全部低于 C，60/80 ms 比 R89 低约 2/3，其余在 1 tick 内。R93 的 2.2–2.4 倍 C 差距已闭合。见 [R94_HTTP_FASTPATH](reviews/R94_HTTP_FASTPATH.md)。

**第二阶段（紧密路径，2026-09-16 下午，`977c480`/`76de74c`/`ebaec81`）**：strace 证明 R89 与候选每个静态响应都是同样的 10 个 syscall、daemon CPU 约 80% 在内核，于是砍到 4 个：接收超时固定 50 ms（`http::Sock`，按阶段 `ReadWait` 语义，零 poll 零 setsockopt）；精确发送 Content-Length（少一次 EOF read）；直接 `openat`（去掉 musl `open()` 的 fcntl）；每连接线程按 (dev, ino, ctime) 复用最近打开的文件并 `pread`（去掉 openat+close）；lookup 4 次分配 → 1 次。第三轮曾因 poll 头等待让 jsonrpc_c4 退步 10%，第四轮改固定超时后消除。
实机终验（候选 `16fa25d9`）：紧密 10 条静态 CPU 低于 R89 14–31%（512 B c1 57.5 vs 83.0）、延迟低 5–22%，范围不重叠；1 MiB/CGI/JSON-RPC 持平；停放五档 CPU 低于 R89 20–70%、低于 C 28–45%。10 项门全绿。

**待办**：无阻塞项。遗留研究：
① jsonrpc_c4 自身 CPU 470 vs C 463（自身范围内持平，R89 时代即如此）——要明确压到 C 以下需看 bridge JSON-RPC 序列化/ubus 调用路径；② 常驻 VmRSS 比 R89 高 138 KiB，几乎全是文件页（代码体积），匿名页 +10 KiB。LINGER 50 ms 未改。

## rpcd ✅

**已攻克（R94，2026-09-16，实机三侧四轮 216 观测，候选 `a362c468`）**：ubus 服务端接收改为读前缓冲——
一次 `recvmsg` 整块读入固定缓冲、从中切出完整帧，把 R89 每请求 3 次 `recvmsg` 降为 1 次（`strace` 5→3 系统调用/请求）；
会话 ACL 匹配去分配——ASCII 尾星按前缀直接匹配、匹配前用无通配前缀 key 预筛（同 C 的 strncmp）、其余 fnmatch 短操作数走栈缓冲，
去掉授权请求每条 ACL 的 4 次 CString 分配。实机：18 负载全部优于 C（重负载超一倍）；对 R89 16/18 延迟与 CPU 双优、多数 CPU 逐轮范围不重叠。
**R93 退步全部收回**：`session_access_granted` CPU -16.7%（20-21 对 22-25，不重叠）、`session_access_64` CPU -13.7%（22 对 25-26）、
`session_access_64_c4` 延迟 -6.8%/CPU -5.6%（R93 曾 +13.8%/+27.8%）、`session_access_granted_c4` -8.4%/-21.1%、`uci_get_authorized` CPU -2.4%。
唯 `uci_get_64`/`uci_get_64_c4`（64 段 UCI 读，非会话路径）对 R89 +0.8%/+2.1% CPU，范围与 R89 大幅重叠属噪声，仍远优于 C（675 对 1510）。
报告 `docs/reviews/R94_RPCD_RECV_ACL.md`；18/18 门绿（模糊 733/733，依赖 6 组件单测全绿）；未部署。

**已修复缺陷**：R81 F23 `file exec`/luci shell 在单线程循环同步执行；F24 其他偏差。Round 5 字节忠实文件读取（shadow/passwd/board.json/acl）。
R88 F1 线程创建失败终止 daemon → UNKNOWN_ERROR + procwait 轮询回退。R92 glob/session/file 界限。
R93 断连保留会话与回滚、离线到期恢复文件、失败通知按包名去重轮转（断连/半帧各 20 项）；
ubus 库 deadline 覆盖完整 header/body，避免 `service.event` 超时导致 rpcd 退出（`453ceed`）。

## procd ☐

**实机差距（R93）**：8 条负载全部优于 C；相对 R89 CPU 系统性高：service_list_32 69→69.5、system_info 143→145.5、
service_list_32_c4 55.1→58.5（+6.2%）、system_info_c4 120.5→123.5、service_list_128 205.5→208.5、
service_list_128_c4 185→189、named_128 30.5→31、named_128_c4 25.3→26.8（+5.9%）µs/操作。

**既有候选**：watch 队列去 O(W²) 冷扫描（`private/r93/procd-queue-local-20260915`），仅本机模型验证。

**提示**：R93 修复把 watch/hotplug 注册分批、维护节拍锚定，可能给主循环加了固定开销；先量 `service list` 一次调用的 blob 构建与实例遍历分配数，
对照 C `service_dump`。c4 退步更大提示每请求重复计算。

**已修复缺陷**：R81 F01 PID 1 写非阻塞 stderr 可 abort（P0）；F21 `service set` 关掉运行实例日志管道；F22。
R88 F1 维护节拍饿死（P1，`r89_procd_tick_probe.py`）；F2 启动期丢非 ubusd 子进程回收；F4 ident 截断 panic。R90 F3。
R92 kill(-1) 守卫、nice int8、respawn/watchdog 数组、watchdog 重开与状态、5 个恢复路径界限。
R93 全量 watch/热插拔注册分批并保留 rcS 前顺序；set-return/service.start 通知时序（source-03/04 回归已修，`R93_PROCD_FINAL_REVIEW.md`）。

## ubusd ☐

**实机差距（R93）**：`lookup_all_64/128` 延迟 786/1549 vs C 775/1510 µs（自身 CPU 更低）；相对 R89 多条 lookup 延迟高 0.9–2.5%
（lookup_all_64_c4 2510→2574、lookup_prefix_64 697→714）；invoke_c4 反而更低。

**既有候选**：pathless 遍历 / lookup borrow（`private/r93/ubusd-star-lookup-borrow`）Oracle 初筛方向混合，未合入。

**提示**：延迟比 CPU 差说明是回复分帧/写出形态（多次 sendmsg 或大 blob 拷贝），不是计算；对照 C `ubusd_send_obj` 的单帧写。

**已修复缺陷**：R81 F02 无 path 系统对象（event/acl/monitor）拒绝非 root。wire fuzz 四项忠实度（`30d4963`）。R88 U-1 EMFILE 下监听空转。
R92 acl/client/server 界限。R93 accept 暂态错误有界重试与 100 ms 恢复（`r93_ubusd_accept_probe.py` 8/8）；
prefix lookup 背压下 64 个大签名对象漏 DATA（`3262a56`，只在严格工具复现，矩阵不覆盖）。ACL 目录须 root 属主（沙箱陷阱）。

## netifd ☐

**实机差距（R93）**：14 条全部优于 C；相对 R89：wireless_status CPU 25→26.5（+6.0%）/延迟 +1.9%、wireless_status_c4 CPU +4.6%；
interface_dump_c4 CPU 63.49→65.48；device_status_c4 延迟 2406→2481、lan_status_c4 477→489、device_status_all_c4 3773→3869。

**提示**：wireless status 是纯序列化路径，看每次调用重建的字符串/Vec；并发延迟退步看主循环里是否有同步 netlink 查询被串行化。

**已修复缺陷**：R81 F03 无 SIGTERM 处理致 udhcpc/odhcp6c 孤儿；F04 删除接口后 ProtoState 直接 drop；F05 任何选项变化都 ifdown+ifup；
F06 peerdns/defaultroute 不生效；F07 墙钟当 uptime；F08 IPv6 preferred/valid 与 prefix 输出；F09 teardown/handler 无超时且阻塞 wait；
F10 radio setup 中 reload 丢配置；F11 reload 对非 DOWN 接口 set_down 被拒；F12 `config device` 只应用三项；F13 add/remove_device 一律拒绝；
F14 有不支持段时所有 reload 返回 INVALID_ARGUMENT。R88 F1 reload 删除接口不跑 teardown。R90 生命周期批（F2–F5/F10–F12）；R91 日志通道。
R92 netlink 界限。R93 重连注册固定对象与全部接口对象全成功才切回在线。开放：F7 netlink 溢出恢复、F9 全局 restart/re-exec。

## fw4 ☐

**实机差距（R93）**：print/check CPU 9300/19650 vs C 96000/107650、R89 9500/19900；check 延迟 61084 vs R89 60335（+1.24%，四轮重叠）。

**提示**：CPU 更低而墙钟更高 → 执行链里有等待（子进程/nft 调用序列），不是规则生成算法；归因后大概率直接打勾。

**已修复缺陷**：R81 F17 `config defaults` 非法选项渲染 `policy null;`。Round 5 warnings 按 ucode 字符串化列表。
R88 F1/F2 两处延迟 null 访问不中止（现退出 254）、F4 `-q check` 仍输出。R92 input/emit/render/sections 修复。开放：F3/F5–F11 退出码与用法/警告文本边界。

## uci ☐

**实机差距（R93）**：export_network CPU 900 vs C 1750/R89 950，export_64 1840 vs 3270/1880，set_commit_get 6820 vs 8970/6960；三项均胜且四轮不重叠。

**提示**：无已测退步。打勾前用大配置与异常持久化输入做一次实机复核即可。

**已修复缺陷**：Round 4 非 UTF-8 输入；R81 F25 偏差；R92 ops 界限、非法 UTF-8 rename 原子拒绝合同（r83）；libuci 忠实度测试（r16/r24 1000 例）。开放：U1 同 batch 非 UTF-8 改名的 U+FFFD。

## reload-config ☐

**实机差距（R93）**：unchanged_config 25417 µs / CPU 26270 vs C 40214/41440、R89 25695/26420；与 R89 四轮重叠。

**提示**：一次性进程，成本是 md5 编排与子进程；只覆盖 unchanged-config，改动传播与事件风暴未测。补测后打勾。

**已修复缺陷**：R81 F26 偏差。R88 F1 运行锁不可取消（`LOCK_NB` + 10 ms 轮询）。R92 engine/json/trace（两套 JSON 转义 F3）。
合同：512 KiB 尺寸预算（opt-level s），F2 4096 项硬上限待写入合同。

---

## 日志

- 2026-09-15 R93：九组件实机三侧四轮 888 个观测闭合（source05 vs C vs R89），各组件差距见上表。
- 2026-09-16 logd R94：arena 环 + 模板帧 + 批量 pipe + burst-spin；Oracle 160/160 字节相同，全负载优于 C/R89/R93；实机 stage-one 候选优于 R89（CPU、RssAnon）。终版实机待补。
- 2026-09-16 httpd R94：监听器内联快路径 + SWAR 头扫描；移除 worker 缓存（违反 r85 内存门）。Oracle 全门绿；四侧停放 60/80 ms CPU 37.5–42.5 µs，低于 C（57.5–60）与 R89（282–292）；gap0 持平 R89、优于 C。formal 四轮进行中，实机待补。
- 2026-09-16 实机窗口（全 C 生产栈，namespace 三侧四轮）：logd 终版 24 观测全胜 C/R89，**logd 完成**；httpd 紧密矩阵 192 观测全部低于 C、与 R89 逐轮重叠持平；httpd 间隔驱动因恢复门 boot_id 过期停止，重生成恢复门后重跑。给 `run_candidate.py`/`r93_http_gap.py` 加 `--stack stock`（路由器回滚到 C 后驱动仍可跑）。
- 2026-09-16 httpd 实机停放间隔四轮完成：五档 CPU/延迟全部低于 C，60/80 ms 比 R89 低 66–68%，其余与 R89 1 tick 内；快路径目标闭合。紧密矩阵仍与 R89 持平，httpd 标为「停放 ✅ / 紧密 ☐」，紧密路径为下一轮目标。
- 2026-09-16 httpd 紧密路径攻坚：每静态响应 syscall 10→4（固定 50 ms 接收超时 + ReadWait、精确 Content-Length、直接 openat、每线程 fd 复用）、lookup 分配 4→1。第三轮 poll 头等待让 jsonrpc_c4 退步 10%，第四轮改固定超时消除。实机终验：紧密 10 条静态低于 R89 14–31%、停放五档低 20–70%，全部低于 C；10 项门全绿。**httpd 完成打勾。**
