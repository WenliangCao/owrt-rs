# R36：ubusd-rs 离线差分结果

日期：2026-09-06。基线 `bb8f6f3`。合同：[docs/contracts/ubusd.md](../../docs/contracts/ubusd.md)。
状态：**离线通过**。未打包，未接触设备。

工具：`tools/r36_ubusd_diff.sh`（同一套客户端序列打两个 daemon，逐字节比对 transcript）、
`tools/r37_ubusd_reconnect.sh`（决策 0015 的 r22 场景，参数化 daemon）。
两者都在构建主机上、精确 rootfs 的独立副本 + 私有 net/mount namespace 里跑。

客户端全部是设备上的真实二进制：`/bin/ubus`（libubus CLI）、`/sbin/rpcd`、`/sbin/netifd`、
`/usr/sbin/dnsmasq`、`/usr/sbin/odhcpd`、`/sbin/logd`、`/usr/libexec/logread-ubox`，
外加本项目的 `logd-rs`。**候选服务端没有只由候选客户端验证。**

## 1. r36：行为差分 —— 两份 transcript 逐字节相同

| 覆盖 | 结果（两端一致） |
|---|---|
| 空总线、lookup 缺失对象、通配 lookup | rc 一致 |
| rpcd 注册 9 个对象 | `file iwinfo luci luci-rpc network.rrdns rc rpc-sys session uci` |
| 对象签名 | `session`、`uci` 方法表逐项一致 |
| invoke / 回复 | `session create` 返回同样的 JSON 结构；`session.list`、`uci.get`、未知方法 rc 一致 |
| 事件 | `ubus send` → `ubus listen` 收到 `{"test.event":{"k":"v"}}`；`ubus.` 保留前缀被拒（rc 6） |
| 对象增删事件 | 杀掉 rpcd → 9 条 `ubus.object.remove`、总线清空；重启 → 9 条 `ubus.object.add` |
| 非 root | `nobody` 调 `uci` 被拒（rc 4）、`ubus list` 看不到任何对象 |
| 畸形输入 | 超长/超短长度字段、截断头、永不到达的正文——连接被断开，daemon 存活并继续服务 |
| 慢客户端 | 一个只发不读的客户端挂着时，其他客户端 `list`/`call` 正常 |
| 调用方消失 | 不读回复就断开，daemon 存活 |
| subscribe | 订阅缺失对象 rc 255；订阅 `uci` 期间总线正常，取消后正常 |
| `wait_for` | 已存在的对象立即返回；不存在的对象持续等待 |
| **传 fd（SCM_RIGHTS）** | 两个并发 `logread-ubox -f` 各自拿到自己的管道描述符，都收到之后写入的日志行 |
| 描述符泄漏 | 整段探测后 delta 0；再做 20 次连接/断开后 delta 仍为 0 |

### 本轮修掉的一个真实缺陷

`PING`、`ADD_OBJECT`、`REMOVE_OBJECT`、acl `query` 在 C 里**先发 `DATA`、再 `return 0`**，
所以客户端会收到 `DATA` 之后还有一条 `STATUS(0)`。第一版 ubusd-rs 少发了这条 STATUS，
libubus 的请求就永远不完成：rpcd 每注册一个对象都要等满一个超时（`session` 立刻上来、
`uci` 约 10 秒后、其余在整轮里没上来），所有 invoke 一律 `UBUS_STATUS_TIMEOUT`。
只读 handler 看不出这点，它在 `ubusd_proto_receive_message` 的返回值分派里。已修，合同已补。

### 本轮修掉的三个"假通过"

第一次拿到"逐字节相同"时，有三组用例其实什么都没测，identical 把它们盖住了：

1. 对象增删事件：原本启第二个 rpcd 当 provider，路径重复注册不上，两边都是 0 个事件。
2. 畸形输入：管道送给 `nc -U`，而这个 rootfs 的 busybox **没有 nc**，一个字节都没发出去。
3. subscribe / `wait_for` / `logread`：用了 `timeout`，而它同样**不是这个 busybox 的 applet**（rc 127）。

传 fd 那一项是**测错**而不是没测：`logd.c` 建管道后用 `ubus_request_set_fd` 把读端挂在
**STATUS** 回复上（正是 ubusd 唯一不关闭描述符的两种类型之一），而 follower 只能看到它连接
**之后**写入的行。原来的用例先写后跟，两边自然都是 0。改正后才真正走通这条路径。

教训记在这里：**"两边一致"不等于"测到了"**，每条用例都要能指出它证明了什么。

## 2. r37：ubusd 重启后的客户端恢复 —— 候选没有新增缺陷

场景与 0015 的 r22 相同：netifd、dnsmasq(`--enable-ubus`)、odhcpd、logd-rs 起来后杀掉 ubusd，
2 秒后重启，观察 60 秒。

```
启动时（两端相同）：dhcp dnsmasq dnsmasq.dns log network network.device
                    network.interface network.wireless
重启 60 秒后（两端相同）：log network network.device network.interface
未恢复（两端相同）：network.wireless、dnsmasq、dnsmasq.dns、dhcp
四个进程全部存活，netifd 与 logd 的调用 rc 均为 0
```

**C 与 Rust 的 transcript 逐字节相同。** 这复现了决策 0015 记录的事实，并且确认那三处
恢复失败**属于客户端，不属于总线**：ubusd-rs 没有让情况变好，也没有变坏。

由此得到在线切换时**必须重启的客户端名单**（这是名单，不是执行授权）：

| 客户端 | 原因 | 建议顺序 |
|---|---|---|
| netifd | 重连后不恢复 `network.wireless` | 1（它拥有接口与无线编排） |
| dnsmasq | 空闲时不迭代主循环，不重试 `ubus_init` | 2 |
| odhcpd | 没有 `connection_lost` 处理，永久脱离总线 | 3 |

logd-rs、rpcd（断连即退、由 procd respawn）、每次调用新建连接的那些客户端不需要额外处理。
procd 与 hostapd/wpad 在这个沙箱里跑不起来，仍只有源码依据，与 0015 的边界一致。

## 3. 以 uid 81（`ubus`）运行的差分 —— 通过

设备上 procd 用 `service_start_early("ubus", "/sbin/ubusd", "ubus", "ubus")` 启动总线，
即 uid/gid 81，**不是 root**（`PRIVILEGE_SURFACE.md:78,125`）。而 §1 的所有运行都是 root，
这是一个我自己漏掉的前提。补测（`DAEMON_USER=ubus`，两端都经 `asuser` 降权）：

- 两份 transcript **79 行逐字节相同**，覆盖与 §1 完全一致；
- socket 属主 `ubus:ubus`、模式 0666（`umask(0111)` 后 bind 的结果）；
- 传 fd、非 root ACL 判定、描述符零泄漏在降权下同样成立。

过程中有一段自找的麻烦：我在任务还在跑的时候就去读 transcript，看到它"截断"，
一度以为 ubusd-rs 在 uid 81 下有缺陷。shell trace 显示脚本实际已经跑到更后面——
丢的是沙箱被拆掉时未刷出的 stdout，不是脚本停了。改成前台跑到底就一致了。
**教训：读一个还在运行的产物等于读噪声。**

## 4. r39：性能对照 —— 内存约一半，`lookup_all` 慢 14%

同一沙箱、同一份负载、同一个客户端（`components/ubusd/examples/bench.rs`）分别打两个 daemon。
构建主机 aarch64，10 个对象在总线上（9 个 rpcd + 1 个 bench provider）。

| 项目 | C ubusd | ubusd-rs | 差异 |
|---|---|---|---|
| lookup（按名，n=3000） | 18.6 µs | **17.4 µs** | 快 6% |
| lookup_all（全量，n=300） | **57.4 µs** | 65.4 µs | **慢 14%** |
| invoke（n=3000） | 36.0 µs | 36.3 µs | 持平 |
| notify（n=3000） | 1.2 µs | 1.4 µs | 持平 |
| 8 并发 invoke（每个 750） | ~107 µs | ~111 µs | 慢 4% |
| daemon CPU（顺序阶段） | 10 ticks | 10 ticks | 持平 |
| daemon CPU（并发阶段） | 8 ticks | 9 ticks | 持平 |
| daemon RSS | 856 → 868 KiB | **452 → 468 KiB** | **少 47%** |
| 描述符 delta | 0 | 0 | 持平 |

**当时不能说"全面更快"**：唯一明确的优势是常驻内存约为一半，唯一明确的劣势是全量 lookup
慢 14%（57 → 65 µs）。这一条已经定位并修掉，见 §5。

### 这一轮的两个 harness bug（不是 daemon bug）

1. 并发阶段用了裸 `wait`，它会连 daemon、provider 和 rpcd 一起等，而这三个都不退出。
   两端**同样**卡死，C 的 transcript 也停在同一行。这一度看起来像"Rust 在高负载下死锁"，
   是 C 基线同样卡住才排除的。现在只等 8 个负载客户端，并且每个阶段都有硬超时，
   卡住会表现为少一行而不是永不结束。
2. 顺序阶段从来不是问题：3000 次的 lookup / invoke / notify 在两端都正常，延迟接近。

顺带记一个操作教训：清理远端进程时用 `pkill -f <模式>` 两次杀掉了我自己的 ssh 会话
（模式出现在我自己的命令行里）。之后只按明确 pid 清理。

## 5. 全量 lookup 慢 14% 的根因与修复

r39 的 10 个对象里有 9 个是 rpcd 的真实对象（`uci` 15 个方法、签名约 1.6 KB），
所以第一反应"每个对象的分配开销"其实没有区分开两件事：对象**数量**和签名**大小**。
用 r40 分开测（每组 5 次取中位数）：

| 配置 | C | ubusd-rs（修复前） | 差 |
|---|---|---|---|
| 10 个小对象 | 48.0 µs | 48.2 µs | +0.4% |
| 160 个小对象 | 437.6 µs | 434.9 µs | −0.6% |
| 1 个对象 / 16 方法（1.6 KB 签名） | 27.4 µs | 31.1 µs | **+13.5%** |
| 1 个对象 / 64 方法（6.6 KB 签名） | 42.9 µs | 51.1 µs | **+19.1%** |

**对象数量完全不是因素；差距只跟签名大小走。**

第一个假设（每条消息 `as_bytes().to_vec()` 的拷贝，而 C 用共享缓冲区不拷贝）**被证伪**：
改成借用发送后，64 方法那一档仍然是 +19%。改动本身保留了（它确实是 C 的语义），
但它不是原因。

真正的原因是**装配缓冲区**：C 用一个静态 `blob_buf b` 反复复用，缓冲区只增长一次；
ubusd-rs 每个对象新建一个 `BlobBuf`，从 4 字节起反复 realloc。改成在 `Server` 上留一个
`scratch` 缓冲区（`std::mem::take` 取出用完放回，四个提前 return 全在取出之前）后：

| 配置 | C | ubusd-rs（修复后） | 差 |
|---|---|---|---|
| 10 个小对象 | 48.2 µs | 46.3 µs | −3.9% |
| 160 个小对象 | 442.5 µs | 447.3 µs | +1.1% |
| 1 个对象 / 16 方法 | 27.2 µs | 25.9 µs | **−4.8%** |
| 1 个对象 / 64 方法 | 42.9 µs | 40.7 µs | **−5.1%** |

已测范围内不再有慢于 C 的项。修复后重跑 r36（root 与 uid 81）与 r37 确认行为未变。

顺带记一条测量方法上的教训：单次运行的噪声足以让 C 自己在两轮之间从 40.3 µs 变到 43.9 µs。
第一次"修完更慢了"的结论就是这么来的。改成每组 5 次取中位数之后信号才稳定。

## 6. 尚未覆盖

- **procd**：沙箱里必须是 PID 1 才能跑，本轮无证据。它的 50 ms→1 s 退避重连只有源码依据。
- **hostapd / wpa_supplicant**：沙箱无无线硬件。它们的订阅路径（`hostapd.*`、`wpa_supplicant`）
  只在 r37 的启动阶段间接证明过 `network.wireless` 注册成功，没有单独验证。
- **monitor 对象**：已加一步逐条比对（方向 + 类型序列、消息条数、非 root 被拒），
  待下一轮运行确认。
- **发送队列溢出**：慢客户端用例证明了不会拖垮 daemon，但没有构造出足以超过 1 MiB 上限、
  真正触发"静默丢消息"的负载。
- **`UBUS_MAX_MSGLEN`**：仍取上游 CMake 默认 1048576，未从设备构建独立确认。
- 打包已完成（`packaging/openwrt/owrt-ubusd`，`owrt-ubusd-0.1.0-r1.apk`，sha256 `0b36bde5`，
  r38 证明它对运行中的总线完全无影响）；切换路径分析见
  [UBUSD_SWITCH_ANALYSIS.md](../../docs/reviews/UBUSD_SWITCH_ANALYSIS.md)，**未执行**。
- procd 自己作为 ubus 客户端的行为（它必须是 PID 1，沙箱跑不了）。
