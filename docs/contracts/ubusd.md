# 合同：ubusd-rs

参考实现：`private/stage2/src/ubus`，OpenWrt 25.12.5 的 `ubus/ubusd 2026.06.28~24864e78-r2`
（`24864e7840b3a02a9ef76284a373f6b2f00b8a9b`）。本文只记录**本机需要复刻的行为**，
每条都能在该 revision 的源码里定位。实现见 `components/ubusd`。

## 0. 本机范围（P0）

镜像里 22 个 ELF 链接 `libubus.so.20251202`。按 ubusd 需要提供的能力分类：

| 能力 | 谁用 | 不做会怎样 |
|---|---|---|
| 对象注册 / 查找 / 调用转发 | procd、netifd、rpcd(-rs)、logd(-rs)、ujail、odhcpd、odhcp6c、dnsmasq、wpad、rpcd 插件、ucode ubus 绑定 | 一切都不工作 |
| 订阅 / 通知 | netifd ↔ wpad（`hostapd.*`）、rpcd `service` 事件 | 无线编排、服务事件丢失 |
| 事件对象（id 1）register/send | procd（`ubus.object.*` 监听）、netifd、hotplug | 服务/接口事件链断 |
| ACL 对象（id 2）query | rpcd 会话层 | LuCI 权限判定失效 |
| monitor 对象（id 3） | `ubus monitor` 调试 | 只影响调试 |
| SCM_RIGHTS 传 fd | rpcd `file exec`、cgi-io、logd | 相关调用失败 |
| 非 root ACL 裁决 | dnsmasq、logd、ntp、wpad、uhttpd 的 `nobody` 会话 | **静默扩大攻击面** |

设备上的 `/usr/share/acl.d/` 有 5 个文件：`dnsmasq_acl.json`、`logd.json`、`ntpd.json`、
`wpad_acl.json`、`luci-base.json`。socket 是 0666，文件权限不构成访问控制——两层
授权全在 ubusd ACL 和 rpcd 会话里。

## 1. 属性解析：`ubus_parse_msg` 会**丢弃**不合策略的属性

`ubus_parse_msg` = `blob_parse_untrusted(msg, len, attrbuf, ubus_policy, UBUS_ATTR_MAX)`。
策略是：`SIGNATURE` NESTED、`OBJTYPE`/`OBJID`/`STATUS` INT32、
`OBJPATH`/`METHOD`/`USER`/`GROUP` STRING，其余不约束。

不合规的属性**被静默丢弃**（`blob_parse_attr` 返回 0，不写进 attrbuf），于是 handler
看到的是"该属性不存在"，通常回 `INVALID_ARGUMENT`——或者走"没有该属性"的那条分支。

这条很容易漏。例如把 `OBJPATH` 的 NUL 结尾改掉：C 因为 `blob_check_type` 的
STRING 检查把整个属性丢掉，LOOKUP 于是走**无路径分支、把所有对象都发出去**；
不做这个过滤的实现会拿着一个没有结尾的字符串去查找，回 `NOT_FOUND`。r42 的随机变异
一次就打出 32 个这样的用例。

其他细节：id ≥ 14 的属性忽略；同 id 的**后一个覆盖前一个**；
遍历时要求**补齐后的长度**仍然放得下，否则停止。

## 2. 线格式

头 8 字节：`version:u8 = 0`、`type:u8`、`seq:be16`、`peer:be32`。紧跟一个 blob_attr：
`id_len:be32`（高位 `0x8000_0000` = extended，`0x7f00_0000` = id，低 24 位 = 含 4 字节头的长度），
后接 payload。

读侧（`ubusd_main.c: client_cb`）：

0. **`version` 字节完全不检查**：`ubusd_main.c` 读完前缀、校验 blob 长度就按 type 分派。
   一个发 `version != 0` 的客户端会被正常服务，不是被断开。（只有 libubus 客户端侧检查它。）
1. 先读满 12 字节（8 头 + 4 blob 头）到 `hdrbuf`，期间 `recvmsg` 带 `SCM_RIGHTS` 控制块；
   收到 fd 就存进 `pending_msg_fd`（**已持有一个未消费的 fd 时不再接收**，控制块置空）。
2. `raw_len < 4` → 断开；`pad_len(raw_len) > UBUS_MAX_MSGLEN` → 断开。
3. 再 `read()` 剩下的 `raw_len - 4` 字节。
4. 收齐后 `ub.fd = pending_msg_fd`，`pending_msg_fd = -1`，派发，然后**立刻重试下一条**。

`UBUS_MAX_MSGLEN` 是编译期常量，上游 CMake 默认 `1048576`。**已用设备自带的 `/sbin/ubusd`
二分确认**（r41）：声明 1048576 字节的消息被接受，1048577 被断开。两端一致。

写侧（`ubusd.c: ubus_msg_writev`）：`sendmsg` 两段 iovec（头 + data），头里 seq/peer 转大端。
**只有 `offset == 0` 且 `fd >= 0` 时才附 `SCM_RIGHTS`**；续传不带 fd。

## 3. 发送队列

- 直接写：`tx_queue` 为空时先试一次 `writev`。全部写完就结束。
- 部分写：`txq_ofs = written`、`txq_len = -written`，注册 `ULOOP_WRITE|EDGE_TRIGGER`，再入队。
- 入队上限：`txq_len + 8 + len > UBUS_CLIENT_MAX_TXQ_LEN`（= `UBUS_MAX_MSGLEN`）时
  **静默丢弃该消息**，不报错、不断开。慢读客户端因此会丢消息——这是原版行为，必须复刻。
- **已知共有缺陷**：如果一次直接写只写了一部分、随后 `ubus_msg_enqueue` 又因为超限把这条
  消息丢掉，`txq_ofs` 会留下一个非零残值而队列是空的。下一条消息若一次写完，这个残值不会被
  清掉，再下一条进队列的消息就会从错误的偏移续传。只有单条消息接近 1 MiB 时才可能触发。
  ubusd-rs 与 C 行为一致（未擅自偏离），记录在此。
- 队列排空且收到 `ULOOP_WRITE` 时处理 `cmd_queue`（见 §4 lookup），空了就退回只监听 READ。

## 4. ID 分配

`ubusd_id.c`：`getrandom(GRND_INSECURE)` 取 u32，**必须 ≥ 1024**（`UBUS_SYSTEM_OBJECT_MAX`），
冲突就重取。client id 与 object id 用同一套规则、各自独立的表。

系统对象固定 id：`EVENT=1`、`ACL=2`、`MONITOR=3`。它们 `client == NULL`，走内建 `recv_msg`。

## 5. 消息处理

派发前：`type != STATUS && type != INVOKE` 时关闭随消息到达的 fd。
`retmsg` 的 seq/peer 从入站消息复制。返回值语义：

- `-2`：命令已入队，**不回状态、不释放消息**；
- `-1`：不回状态（只有转发类走这条：INVOKE、NOTIFY、STATUS/DATA 回复）；
- 其他：回 `UBUS_MSG_STATUS`，payload 是 `STATUS=htonl(ret)`。

**易错点**：`PING`、`ADD_OBJECT`、`REMOVE_OBJECT`、acl `query` 都先发一条 `DATA`
**然后 return 0**，所以客户端会收到 `DATA` 再收到 `STATUS(0)`。少发这条 STATUS，
libubus 的请求不会完成，调用方一路超时（`UBUS_STATUS_TIMEOUT`）。

未知 type → `INVALID_COMMAND`。

| type | 行为 |
|---|---|
| `PING` | 原消息改成 `DATA` 回给自己，再回 `STATUS(0)` |
| `ADD_OBJECT` | 见 §5 |
| `REMOVE_OBJECT` | 见 §5 |
| `LOOKUP` | 见下 |
| `INVOKE` | 见 §6 |
| `STATUS` / `DATA` | 对象回复，见 §6 |
| `SUBSCRIBE` / `UNSUBSCRIBE` | 见 §7 |
| `NOTIFY` | 见 §7 |

**LOOKUP**：无 `OBJPATH` 时遍历整棵 path 树（strcmp 序）；每发一个就检查 `tx_queue`，
一旦非空就把命令连同「下一个对象」入 `cmd_queue` 并返回 `-2`，等可写时继续。
有 `OBJPATH`：空串 → `INVALID_ARGUMENT`；不以 `*` 结尾 → 精确查找，无则 `NOT_FOUND`；
以 `*` 结尾 → 去掉 `*`，`find_ge` 后按前缀连续遍历，一个都没有 → `NOT_FOUND`。

每个对象由 `ubusd_send_obj` 发出：**无 type 的对象直接跳过**；方法按 ACL `ACCESS` 逐个过滤；
`cnt || !all_cnt` 才发送（一个方法都看不见且该类型有方法时，整个对象对该客户端不可见）。
payload：`OBJPATH`、`OBJID`、`OBJTYPE`、嵌套 `SIGNATURE`。

## 6. 对象生命周期

**ADD_OBJECT**：有 `OBJTYPE` → 复用已有类型（refcount++）；否则有 `SIGNATURE` → 新建类型，
每个方法过 `blobmsg_check_attr(pos, true)`。
**任一方法不合格时不是报错**：`ubus_create_obj_type` 返回 NULL，C 继续往下走，
创建一个**没有类型的对象**——它有 id、可以被 remove，但永远不出现在 lookup 里
（`ubusd_send_obj` 对无类型对象直接返回）。回复仍是 `DATA`，只是不带 `OBJTYPE`。

`blobmsg_check_attr(attr, true)` 的完整规则（libubox `blobmsg.c`）：必须 extended；
payload ≥ 2；名字长度字段非 0；payload ≥ `pad4(2 + namelen + 1)`；名字后一字节为 NUL；
blobmsg 类型 ≤ 8；再按类型做长度检查（STRING 末字节为 NUL、INT32 恰好 4 字节等，
ARRAY/TABLE 不额外检查）。
有 `OBJPATH` → 先过 ACL `PUBLISH`；`strdup` 后插入 path 树，**重名插入失败即整个对象创建失败**
（回 `INVALID_ARGUMENT`）；成功则发 `ubus.object.add` 事件。
回复：总是 `OBJID`；只有当请求带 `SIGNATURE` 且类型创建成功时才带 `OBJTYPE`。

**REMOVE_OBJECT**：必须是属主，否则 `PERMISSION_DENIED`；对象不存在 `NOT_FOUND`。
回复带 `OBJID`，并且**当 `type->refcount == 1`（即将销毁）时带 `OBJTYPE`**。
先发回复，再释放对象。

**释放对象**（客户端断开时对其所有对象执行）：先退订自己订阅的全部目标；再对每个订阅者
发一条 `UNSUBSCRIBE`（seq = `++subscriber->invoke_seq`，peer = 0）后解除；清理事件注册；
有 path 则发 `ubus.object.remove` 并从 path 树摘除。

## 7. 调用与回复

**INVOKE**：需要 `METHOD` + `OBJID`。ACL `ACCESS` 不过 → `PERMISSION_DENIED`。
对象无 client（系统对象）→ 走内建 handler。否则：`hdr.peer = 调用方 client id`，
转发 payload = `OBJID`（目标对象）、`METHOD`、`USER`、`GROUP`（调用方的，存在才带）、`DATA`，
**带上原消息的 fd**，type 改 `INVOKE` 发给对象属主；返回 `-1`。

**STATUS / DATA（对象的回复）**：需要 `OBJID`；`STATUS` 型还需 `STATUS` 属性、`DATA` 型还需
`DATA` 属性；对象必须存在且属于发送方；按 `hdr.peer` 找回原调用方，找不到就静默丢弃。
然后 `hdr.peer = OBJID`，原样转发。任何一步失败都只是 `goto out` → 返回 `-1`，**不产生错误回复**。

## 8. 订阅与通知

**SUBSCRIBE**：`OBJID`（自己的对象）+ `TARGET`。目标必须存在且有 client；不能订阅自己客户端的对象。
目标**没有 path** 时：只有同 user 或同 group 才允许，否则 `NOT_FOUND`（不是 PERMISSION_DENIED）。
目标有 path 时走 ACL `SUBSCRIBE`，不过也是 `NOT_FOUND`。
成为第一个订阅者时向目标属主发 `NOTIFY`（`OBJID` + `ACTIVE=1`，seq = `++invoke_seq`，peer = 0）。

**UNSUBSCRIBE**：在自己的 `target_list` 里按 target id 找，找不到 `NOT_FOUND`。
最后一个订阅者离开时同样发 `NOTIFY`（`ACTIVE=0`）。

**NOTIFY**：必须是属主。`NO_REPLY` 未置位时先回一条 `STATUS`：`OBJID` + 嵌套 `SUBSCRIBERS`
（每个订阅者 id，attr id = 0）+ `STATUS=0`。然后对每个订阅者转发一条 `INVOKE`
（`no_reply` 时 payload 带 `NO_REPLY=1`）。返回 `-1`。

## 9. 事件对象（id 1）

`register`：`{pattern: string, object: u32}`。`object < 1024` → `PERMISSION_DENIED`；
对象不存在 → `NOT_FOUND`；非属主 → `PERMISSION_DENIED`；空 pattern → `PERMISSION_DENIED`。
末尾 `*` → partial 并去掉该字符。再过 ACL `LISTEN`。

`send`：`{id: string, data: table}`；`id` 以 `ubus.` 开头 → `PERMISSION_DENIED`（保留给内部事件）。
过 ACL `SEND`。

投递（`ubusd_send_event`）：`obj_event_seq++`，按字典序遍历 pattern 树，用
`ubus_strmatch_len` 的**单调匹配长度提前退出**（`cur_match_len < match_len` 即 break）；
非全匹配时只有 partial 且 `match_len == strlen(key)` 才算命中。
每个命中对象：**发送方自己的对象不回环**；同一轮 `event_seen == obj_event_seq` 去重。
消息 type = `INVOKE`、peer = 0、seq = `++event_seq`，payload = `OBJID=0`（发送时按接收者改写）、
`METHOD=<event id>`、`DATA`。

内部事件：`ubus.object.add` / `ubus.object.remove`（data = `{id, path}`）、
`ubus.acl.sequence`（data = `{sequence}`），以 `cl = NULL` 发送，因此不受 ACL 限制也不回环。

## 10. ACL 对象（id 2）与 ACL 裁决

**裁决**（`ubusd_acl_check`）：`cl == NULL || cl->uid == 0 || obj == NULL` → **直接放行**。
root 完全不受 ACL 约束。其余按字典序遍历 acl 树，同样的单调匹配长度提前退出；
凭据匹配：`uid` 相等，或 `gid` 相等，或在 `extra_gid` 里。
`ACCESS` 类型另外要求方法名出现在 `methods` 数组里（或数组里有 `"*"`）。

**加载**（`ubusd_acl_load`，启动时和 SIGHUP 时）：glob `<acl_dir>/*.json`；
**必须是普通文件、`st_uid == 0 && st_gid == 0`、且不含 `S_IWOTH|S_IWGRP|S_IXOTH`**，
否则记日志跳过。文件里 `user` 优先于 `group`；两者都没有则整个文件忽略。
`getpwnam`/`getgrnam` 查不到时 uid/gid 记为 **0**（不是 -1）——即匹配 root，这是原版行为。
加载完 `ubusd_acl_seq++` 并广播 `ubus.acl.sequence`。

`query` 方法：返回 `{seq, acl: [...]}`，只包含调用方自己注册的、且有 `acl` 私有字段的对象。

**客户端凭据**：`SO_PEERCRED` 拿 uid/gid/pid；`getpwuid`/`getgrgid` 任一失败则**拒绝该连接**。
附加组从 `/proc/<pid>/status` 的 `Groups:` 行读，最多 64 个。

## 11. monitor 对象（id 3）

`add` / `remove`，**仅 uid == 0 且 gid == 0**，否则 `PERMISSION_DENIED`。
有监听者时，每条收到的消息（派发前）和每条发出的消息（`type != MONITOR` 时）都镜像一份：
`MONITOR_CLIENT`、`MONITOR_PEER`、`MONITOR_SEQ`、`MONITOR_TYPE`、`MONITOR_SEND`、`MONITOR_DATA`，
type = `UBUS_MSG_MONITOR`，seq = 每个监听者自己的 `++m->seq`。

## 12. 进程与 socket

`-s <socket>`（默认 `/var/run/ubus/ubus.sock`）、`-A <acl 目录>`（默认 `/usr/share/acl.d`）。
启动：忽略 `SIGPIPE`；`SIGHUP` 经 self-pipe 触发 ACL 重载；创建 socket 目录 0755；
`unlink` 旧 socket；`umask(0111)` 后 bind（结果 0666）；非阻塞 listen；加载 ACL。
退出时 `unlink` socket。

新连接：`accept` 循环直到 `EAGAIN`；建立 client 后**立即发 `HELLO`**（seq=0、peer=client id、空 payload）。
这条 HELLO 走的是普通发送路径，因此**同样会被镜像给 monitor**（`ubusd_send_hello` → `ubus_msg_send`）。

## 13. 实现注记

`ubusd_send_obj` 是这个 daemon 例行发送的最大消息（一个对象的完整签名，rpcd 的 `uci`
约 1.6 KB、更大的可到 6 KB+）。C 版用一个**静态 `blob_buf b`** 反复复用，缓冲区只增长一次；
一个每次新建的缓冲区要从 4 字节起反复 realloc。实测（5 次取中位数）：每次新建时
1.6 KB 签名慢 13.5%、6.6 KB 签名慢 19.1%；改成复用一个 `scratch` 缓冲区后变成 -4.8% / -5.1%。
对象数量本身不是因素（10/160 个小对象两端持平）。

回复也按 C 的做法**借用而不是拷贝**：队列为空时直接从装配缓冲区写进 socket，
只有 socket 没收完的部分才分配。

## 14. 已知缺口与有意差异

| 项 | 状态 |
|---|---|
| `UBUS_MAX_MSGLEN` = 1048576 | **已用设备的 C ubusd 二分确认**（r41） |
| 慢客户端超限静默丢消息 | 复刻原版；如改为断开需单独记录并验证调用方 |
| 客户端断连后在途请求 | 原版靠对象释放时的 UNSUBSCRIBE + 调用方超时；不新增机制 |
| 0015 记录的重连缺陷（odhcpd/dnsmasq/netifd.wireless） | **是客户端侧问题，不由 ubusd-rs 修复**；切换方案必须给出需重启的客户端名单与顺序 |

## 15. R92 异常恢复与线协议补齐

- 对端半关闭输入后移除读就绪监听，已有回复排空后关闭；慢读半关闭不能持续占满 CPU。
- 暂停的 LOOKUP 保存下一路径的 owned 下界；该对象在恢复前被删除时从下界继续，不回到树首，
  不重发已完成的对象。精确 C 原版在对应删除场景会崩溃，保留修复而不复刻悬空指针。
- 顶层 raw attribute 声明长 1–3 时按 C 遍历继续跳过；SIGNATURE 中不合法的短成员使类型创建失败，
  仍可创建无类型对象。复用类型且请求同时带 SIGNATURE 时回复包含 OBJTYPE；签名前缀按补齐长度计。
- event 的同名字段选第一个类型正确的字段；object 仅 INT32；事件名保留原始字节。
  ACL methods/tags 只接受 ARRAY，私有 acl 只接受 TABLE；类型错误字段不授予权限。
- TARGET 长于 4 字节时使用前 4 字节；声明长度不足 4 时有意返回 INVALID_ARGUMENT，
  不复刻原版跨 attribute 读取。合同例子中原版读到其它字节后回 NOT_FOUND，并不构成合法短字段。

原版/R89 反例与候选门：`r92_recovery_probe.py`；原始报文、debug build 补齐断言与非 root ACL
可见性：`r92_compat_probe.py` 的 `ubusd_wire`、`ubusd_acl_types`。

## 16. R93 accept 错误恢复

精确原版 `ubusd_main.c:get_next_connection()` 遇到 `EINTR`、`ECONNABORTED` 立即重试；
其它错误结束当轮 accept。R89/R92 为避免 level-triggered listener 在资源耗尽时空转，
把所有 accept 错误都改为移除监听，且只在客户端断开时恢复。这会使一次暂态错误永久阻止
新连接；`ENFILE`、socket 内存或传递的 FD 恢复也不一定伴随客户端断开。

R93 对 `EINTR`、`ECONNABORTED` 在当轮最多尝试 16 次；其它错误或预算耗尽时移除
listener，并在 100 ms 后重试。已有客户端断开可提前触发重试；重新注册失败也保留
100 ms 重试期限。正常状态没有周期唤醒。移除监听本身失败时返回事件循环错误，避免
带着永久可读的失效 listener 空转。

探针 `tools/r93_ubusd_accept_probe.py GNU_BINARY OUTPUT` 在 Linux 的独立 Unix socket
上保留一个持续 PING 的客户端，再排队第二个连接。单次 `EINTR`/`ECONNABORTED`、
短时错误流、`ENFILE`/`ENOMEM`/`ENOBUFS`/未知错误通过 `LD_PRELOAD` 注入；`EMFILE`
则实际耗尽测试子进程的 96-FD 限额，再只释放占位 FD。恢复条件是两个客户端均未断开时
第二个收到 HELLO，错误调用次数有上限。它不耗尽宿主机的全局资源，也不连接路由器。
