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
| **monitor 流量镜像** | 一次 `session list` 调用产生 12 条镜像，方向+类型序列逐项相同：`->status ->hello <-lookup ->data ->status <-invoke ->invoke <-data ->data <-status ->status <-invoke`；非 root 开 monitor 被拒（rc 6） |

### monitor 比对当场抓到的第二个缺陷

加上逐条镜像比对后，第一次运行就差了一条：C 是 12 行、以 `->status ->hello` 开头，
ubusd-rs 只有 11 行、**没有 `->hello`**。原因是 `add_client` 直接调用 `Client::send`
发 HELLO，绕过了镜像；C 的 `ubusd_send_hello` 走 `ubus_msg_send`，是会镜像的。
改成先插入客户端再经 `Server::send` 发出，两端就完全一致了。

这条只有做逐条镜像比对才看得见——之前只验证了 monitor `add`/`remove` 的权限判定。

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

## 6. r41 / r42：两处限制与线协议模糊测试

### r41：消息大小上限与发送队列上限

`UBUS_MAX_MSGLEN` 一直是"上游默认 1048576，未确认"。用设备自带的 `/sbin/ubusd` 二分：

```
1048572 接受   1048576 接受   1048577 断开   1048580 断开   2097152 断开
```

两端逐项相同。**这个常量现在是实测确认的，不是抄来的。**

发送队列上限（超限静默丢消息）此前也没被真正触发过。用 200 个各带 64 个方法的对象
（单个签名 6617 字节，一次全量 lookup 约 1.3 MiB 回复）压给一个只发不读的客户端：
两端都是 daemon 存活、RSS 增长有界、fd 有界、期间其他客户端 `list`/`call` 正常，
之后再来 10 个立刻断开的客户端也没有残留。

### r42：线协议模糊测试，抓到四个保真度缺陷

`components/ubusd/examples/fuzz.rs` 用固定表 + 定种子变异发同样的字节给两个 daemon，
比对每个用例的判定。**第一次运行就差了四处，全部是候选错了**：

1. **协议版本字节**。`ubusd_main.c` 根本不看 `hdr.version`——只有 libubus 客户端侧看。
   发 `version != 0` 的客户端在 C 下被正常服务，ubusd-rs 用了共享 crate 的严格
   `Header::decode`，直接断开。改成自己解析头（不动共享 crate）。
2. **属性策略**。`ubus_parse_msg` 是 `blob_parse_untrusted` 加 `ubus_policy`，
   **不合类型的属性被静默丢弃**，handler 看到的是"该属性不存在"。ubusd-rs 之前来者不拒。
   最直观的一例：把 `OBJPATH` 的 NUL 结尾改掉，C 因 STRING 检查丢掉整个属性，
   LOOKUP 于是走无路径分支**把所有对象发出去**；不做过滤的实现拿着没结尾的字符串去查，
   回 `NOT_FOUND`。600 个变异里有 32 个正好打中这里。
3. **`blobmsg_check_attr`**。方法签名检查既比 libubox 严（要求 payload ≥ 3、忽略补齐规则）
   又比它松（不检查 blobmsg 类型范围、不做按类型的长度检查）。照 `blobmsg.c` 逐条重写。
4. **签名不合格不是错误**。`ubus_create_obj_type` 返回 NULL，C 继续创建一个
   **没有类型的对象**——有 id、可以 remove，但永远不出现在 lookup 里。
   ubusd-rs 之前回 `INVALID_ARGUMENT`。

修完之后 **664 行逐字节相同**（固定表 + 600 个变异 + 健康检查），
daemon 存活、对象集合未变、fd 有界。

## 7. r43：虚拟机里以真实 procd 作为 PID 1 启动

构建主机上本来就装了 `qemu-system-aarch64`（没有新装任何系统组件）。用官方
OpenWrt 25.12.5 **armsr/armv8** 内核 + ext4 rootfs 起一台虚拟机，procd 就是真正的 PID 1，
总线由它在 `STATE_UBUS` 自己拉起——这是 chroot 沙箱做不到的，之前关于 procd 的一切只有源码依据。

把候选装到 `/sbin/ubusd`（procd 按绝对路径启动的位置），与原版各启动一次：

| | C ubusd | ubusd-rs |
|---|---|---|
| PID 1 | `/sbin/procd` | `/sbin/procd` |
| 实际运行的总线二进制 | 32962 字节 | **528440 字节，字符串确认是候选** |
| 对象数 | 31 | 31，**逐项相同** |
| procd `service list` / `system board` | rc 0 | rc 0 |
| `network.interface dump` | rc 0 | rc 0 |
| 运行中的服务 | 9 | 9 |
| socket | `srw-rw-rw- ubus ubus` | 同 |
| 总线进程 uid | 81 | 81 |

对象集合两端完全一致，包含 procd 自己的 `service`、`system`、`container`，
netifd 的 `network*`、dnsmasq、odhcpd 的 `dhcp`、rpcd 的九个、以及七个 `hotplug.*`。
**19 行启动 transcript 逐字节相同**（除去用于区分二进制的三行）。

顺带补上了 0015 里一直缺的一项：**procd 自己作为 ubus 客户端，杀掉总线后能重连并重新注册**
`service`/`system`/`container`——两端行为相同，其余客户端的部分恢复情况也相同。
这一条此前只有源码依据（50 ms→1 s 退避），现在有实测。

### 这台虚拟机不能证明什么

- **不是设备的 target**：armsr/armv8，内核与虚拟硬件都不同；无无线、无交换芯片、无 flash 布局。
- **rootfs 是可写 ext4，不是 squashfs + overlay**。这里是直接替换 `/sbin/ubusd`；
  设备上要靠 overlay 遮住 squashfs 里的同名文件，**那一层没有在这里验证**，
  failsafe 不挂 overlay 这条救援出口也没有在这里演练。
- 因此这轮结果支持"候选能在真实 procd 下当系统总线跑起来"，**不等于**设备上的开机选择方案已验证。

## 8. 尚未覆盖

- ~~procd~~：已由 r43 虚拟机覆盖（见 §6），但仅限 armsr 目标。
- **hostapd / wpa_supplicant**：沙箱无无线硬件。它们的订阅路径（`hostapd.*`、`wpa_supplicant`）
  只在 r37 的启动阶段间接证明过 `network.wireless` 注册成功，没有单独验证。

- ~~发送队列溢出~~：r41 用 200 个 6.6 KB 签名的对象（约 1.3 MiB 的 lookup 回复）压给一个
  只发不读的客户端，两端都 RSS 有界、fd 有界、继续为其他客户端服务。
- ~~`UBUS_MAX_MSGLEN`~~：r41 用设备自带的 C ubusd 二分确认为 **1048576**（1048576 接受、
  1048577 断开），两端一致。
- **设备上的 overlay 遮蔽与 failsafe 分支**：r43 的虚拟机是可写 ext4，没有 squashfs+overlay
  这一层，这条仍未验证。
- 打包已完成（`packaging/openwrt/owrt-ubusd`，`owrt-ubusd-0.1.0-r1.apk`，sha256 `0b36bde5`，
  r38 证明它对运行中的总线完全无影响）；切换路径分析见
  [UBUSD_SWITCH_ANALYSIS.md](../../docs/reviews/UBUSD_SWITCH_ANALYSIS.md)，**未执行**。
- procd 自己作为 ubus 客户端的行为（它必须是 PID 1，沙箱跑不了）。
