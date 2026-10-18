# odhcpd 独立审计：RA、PIO 与内核状态

2026-10-18。结论：**确认两项 P2；未确认 P0/P1。** 动态 `hop_limit`
被永久缓存；一次运行期内核快照错误会结束整个守护进程。另实证了被忽略的
`NLM_F_DUMP_INTR` 会伴随缺项，但精确 C 依赖也有这一边界，不把它列为
Rust 独有回归或当前两个前缀场景的发布阻断。本报告不授权发布、刷机或路由器操作。

**后续状态：两项 P2 已在 e33fa56c 的最终 SDK 上定向复验关闭，见文末。
以下原始发现及原 ELF 证据保留，不以修复结果覆盖历史。**

审计者未参与此前实现。独立读取了 `AGENTS.md`、研究指导、实现和精确 C 源码，
合同仅用于确认范围，没有沿用已有报告的 passed 结论。冻结 Rust 源码为
`d0ef9f04d8533c174c5177301b3f479e11d6e4d0`；本次审查文件与该提交无差异。
实际运行的是既有 SDK ELF，没有本地或远端重编产品：

- Rust SHA256：`79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55`。
- C 源码：`5d7be43f8b9dec0eb47e245cfab81108bb131273`。
- C ELF SHA256：`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。

## P2 / RA-1：默认 RA hop limit 不再跟随内核，reload 也不能恢复

位置：`components/odhcpd/src/main.rs:274`、`:308`、`:589`、`:672`；
`components/odhcpd/src/router.rs:315`。

默认 `ra_hop_limit=0` 本应读取接口 sysctl。当前只在创建 `RaService` 时读取，
以后 RS、周期 RA 和同 ifindex 的 SIGHUP reload 都继续使用旧 `ra.hop_limit`。
接口不存在变化时，这个值能一直过期，直到 socket 被重建或进程重启。

最小复现使用私有 veth LAN 和原有合成双前缀夹具，依次：

1. 设置 `net.ipv6.conf.br-lan.hop_limit=64`，启动守护进程，发有效 RS。
2. 修改同一 sysctl 为 `123`，再次发 RS。
3. SIGHUP 后再次发 RS，内核值仍为 `123`。

| 实际 ELF | 初次 RA | 修改 sysctl 后 | SIGHUP 后 |
|---|---:|---:|---:|
| 精确 C | 64 | 123 | 123 |
| 冻结 SDK Rust | 64 | 64 | 64 |

这里比较的是 RA header 第 4 字节的 Cur Hop Limit，IPv6 包自身的 hop limit
仍为 255。精确 C `src/router.c:651,661` 每次 `send_router_advert()`
在配置为零时调用 `odhcpd_get_interface_config(..., "hop_limit")`。
影响是默认配置下客户端持续收到过期的建议 hop limit；此次输入无需改变 UCI
或重建接口。建议在实际构包时重读默认 sysctl，显式非零 UCI 值仍优先。

## P2 / KERNEL-1：运行期快照的一次瞬时错误导致整个协议服务退出

位置：`components/odhcpd/src/kernel.rs:91`；
`components/odhcpd/src/main.rs:354,709,765,809`；
共享调用点 `components/netifd/src/netlink.rs:276`。

事件 socket 的 ENOBUFS 有扩容和重同步逻辑，但重同步所用 command socket
的 dump 错误会经 `snapshot()?`、`refresh_kernel()?` 一直传播到 `main()`，
以状态码 4 退出。所有接口的 RA/RS、DHCPv6 和内存租约一起丢失，需要 procd
重新启动；这是受控退出，不是内存安全崩溃。

最小实证先确认冻结 SDK 能回复 RS，再 attach strace，仅对第 3 个
`recvfrom` 注入一次 ENOBUFS，随后在私有网络命名空间改变 LAN MTU。
轨迹确认错误落在运行期 GETLINK dump，未落在 event socket：

```text
recvfrom(4, RTM_NEWLINK(... mtu=1499 ...), ..., MSG_TRUNC) = 1488
recvfrom(4, ..., MSG_TRUNC) = -1 EAGAIN
sendto(3, RTM_GETLINK, NLM_F_REQUEST|NLM_F_DUMP, seq=7) = 32
recvfrom(3, ..., 131072, 0, ...) = -1 ENOBUFS (INJECTED)
+++ exited with 4 +++
```

日志为 `odhcpd-rs: No buffer space available (os error 105)`。
**这是 syscall 故障注入结果，没有声称 Oracle 或本机自然发生了 command
socket 溢出。** 它确认单次可恢复观察失败当前被提升为整个服务失败。

C 的控制流有所不同：`src/netlink.c:197–206` 对地址 dump 返回负值保留
旧地址集并返回，`src/netlink.c:497` 的事件错误也不直接退出主进程；没有
Rust 这种统一全状态快照的错误传播路径。未运行相同的 C syscall 注入，
不声称 C 在所有 ENOBUFS 情形都能恢复或不会阻塞。建议由 odhcpd 调用层
限定重同步重试与错误状态，明确是否接受 fail-fast/procd 重启策略；本次不改实现。

## 共同既存边界：中断 dump 被当作完整快照

`components/netifd/src/netlink.rs:271–305` 未检查任何消息的
`NLM_F_DUMP_INTR`，且 `NLMSG_DONE` 的状态 payload 未检查。
`Kernel::snapshot()` 返回后，`main.rs:355` 直接替换权威状态；RA 可将缺项
视为前缀消失，DHCPv6 reconcile 也会消费它。

在 Oracle Linux `6.17.0-1020-oracle` 的新网络命名空间内创建 1000 个合成
GUA，发送 RTM_GETADDR，读第一块后删除其中一个已返回地址。真实内核后续
数据块带 flags `0x12`（MULTI | DUMP_INTR），合并结果缺少仍存在的
`2001:db8:1f2::1`，同时包含已删除地址。块长依次为
3744、32400、32400、3484 字节。本例没有修改内核返回值，证明此标志对应
实际不一致，而不只是理论上的检查缺失；没有再运行整套守护进程矩阵。

精确 OpenWrt package 配置将 libnl-tiny 固定于
`40493a655d8caa2ccf5206dde1e733abe2920432`。该版本
[nl.c](https://raw.githubusercontent.com/openwrt/libnl-tiny/40493a655d8caa2ccf5206dde1e733abe2920432/nl.c)
同样不检查 DUMP_INTR，DONE 直接调用 finish；odhcpd 的
`src/netlink.c:626` finish 也不检查状态。因此不能描述为 C 正确、Rust 错误。
本轮限定为记录既存风险，不要求扩大共享 netifd transport 或重建其他组件。
未来若增强，需在 odhcpd 使用的严格 dump 路径中完整消费失败序列并重新取样，
避免仅检测到一个 flag 后留下旧序列消息。128 KiB command recv 未检查截断
亦已静态看见，但未构造本机场景的超长 datagram，不另报已确认故障。

## 审查范围与没有新增发现的边界

当前模型是：内核快照决定当前前缀和默认路由，成功 sendmsg 后的 PIO ledger
决定必须撤回的历史，PIO 文件只恢复进程重启状态。最危险的边界是将不完整
观察当成删除、或在成功发送前持久化；前者存在上述共同 dump 局限，后者
在本次静态审查中未发现。

- 检查了 `router.rs`、`kernel.rs`、`model.rs` 全文及 `main.rs` 的服务重建、
  RS/计时、PD route ACK 后刷新和错误传播；向下追踪了共享 netlink 和 netio。
- RS 的 code、hop limit、完整 option 长度、零长 option、`::` + SLLAO
  拒绝与精确 C 对照；接口验证位于 netio。未发现新的绕过输入。
- 核对了有限 preferred/valid 剩余寿命、旧 PIO 撤回、stale 截止不反复延长、
  WAN 默认路由删除、源前缀 RIO、同前缀 host bits 更新、PIO 解析/原子替换。
  到期地址仍在快照中被跳过、墙钟跳变以及 tmpfs 仅跨进程重启是已有 C 边界。
- link down/up 和 ifindex 更换会关闭旧服务并重建；发送使用当前 link-local。
  route 写入等待 ACK，失败不会标记成功；ACK 后 refresh 会比较新旧地址，
  不会只用已更新快照自比较而吞掉并发地址变化。这些为静态结论，未重跑矩阵。
- 本次没有性能/PGO、Mac Rust 构建、物理路由器访问、固件写入或发布。
  已接受的首 RA 与亚毫秒取整差异未重测、未重列阻断。

下一轮只需裁决两项 P2 的处理及针对性回归；本审计不要求重复宽矩阵。

## 最小实验及复现证据

每项实验事前均有可证伪预测：hop-limit 预测 C 更新/Rust 不更新；dump 预测
并发删除可能产生 DUMP_INTR 和缺项；错误注入预测 command recv 错误导致
退出 4。指标是精确字节、消息集合和退出状态，无时间收益门槛或性能代理。
仪器分别为真实 RS/RA、原始 rtnetlink 和标明 INJECTED 的 strace。

工具和原始输出只在审计独立目录：
`oracle:/home/ubuntu/odhcpd-audit-ra-kernel-20261018/`，本地工具副本位于
ignored `private/odhcpd-audit-ra-kernel-20261018/`。脚本复用仓库的
`tools/odhcpd_baseline.py` 夹具 setup/client，只运行指定 case；所有写入、
chroot 和 namespace 都在该新目录，已有 evidence/rootfs 只作为读取源。

```sh
# 在 Oracle，从独立审计目录运行；ROOT 是精确 C extracted/rootfs-files。
# SDK 是上文冻结 ELF。每个 OUT 必须尚不存在。
sudo unshare --mount --net python3 hop_limit.py --rootfs "$ROOT" --out "$OUT"
sudo unshare --mount --net python3 hop_limit.py --rootfs "$ROOT" --out "$OUT" --daemon "$SDK"
sudo unshare --net python3 dump_interruption.py
sudo unshare --mount --net python3 snapshot_error.py --rootfs "$ROOT" --out "$OUT" --daemon "$SDK"
```

关键原始结果 SHA256：

| 相对证据路径 | SHA256 |
|---|---|
| `hop-c/results.json` | `20b6d02ac84252a35bc3e9ed2f7c53a590282e5c2f5cae80917eeaf5ce275429` |
| `hop-rust/results.json` | `3c11b0ba2c4039eed73718f692febd7e343e18f760b1632fc80274b23c4abbb5` |
| `dump-interruption.json` | `c3f8e985e07bd2efad8a3dc9ec745c2cbe39f339cb6bd5dbf807e0dcb833f833` |
| `snapshot-error-rust/results.json` | `99dcc5a9ce6c299261093010ccc53e60d24143b748d70fb9e5aaf7fefd025994` |

工具 SHA256：`hop_limit.py` 为
`1f4e010af3506e0bef64fdc6aa79f2d44c67ffbc580d474ac1ec774e0f986463`；
`dump_interruption.py` 为
`f468694cfabab4b2b36e1c449484e54b1313dbc95e65c5f86e9fe0de7a83a9c1`；
`snapshot_error.py` 为
`386bd419abf0372d8176994de9d39483f6c5941e714016f4ab08bc5477b10c44`。

## 修复复核：RA-1、KERNEL-1 均关闭

2026-10-18 08:57 UTC，独立静态复核及最终 SDK 的两个目标用例完成。
源码：`e33fa56c426f51931251df022228cd7ab905b63d`；canonical CI：
`39112918594`；实际复验 ELF 为
`oracle:/home/ubuntu/odhcpd-validation-20261018/sdk-e33fa56c/odhcpd-rs`，
执行前及夹具副本重新核对 SHA256：
`c4a7c2731e02cb14fca5f94e4cbe940e0f9c91f64ca45be2e98ab19281250048`。
没有构建或运行中间候选，没有改动共享 netlink transport。

静态核对结果：`main.rs:117` 的 helper 在显式配置非零时直接使用配置，
默认值在实际构包时重新读 sysctl；RS、周期 RA 和两种停用路径均使用它。
`main.rs:475` 对指定瞬时快照错误保留状态，设置 1000 ms 后重试；
`:523` 在 retry 期间不根据旧 `kernel.routes` reconcile；`:432` 成功后才
替换状态、提交 pending config，并触发所有 router 重同步。pending reload
期间的 `add_lease` 同时更新 active/pending 配置，未发现本范围的新状态丢失路径。

| 原发现 | 冻结 SDK 的目标复验 | 结论 |
|---|---|---|
| RA-1 | 原 `hop_limit.py` 同输入得到 64 → 123 → 123，与保留的精确 C 结果一致 | closed |
| KERNEL-1 | 一次 command socket ENOBUFS 后 PID 不变；原 bound NA/PD 身份、地址与 PD 路由在错误窗口和恢复后相同；窗口内 RS、DHCPv6 Information-request 仍有回复；恢复后两份原绑定 Renew 成功 | closed |

KERNEL-1 复验使用新增 `snapshot_recovery.py`，保留原退出反例脚本不变。
在注入前绑定一个 NA 和一个 PD；MTU 1500 → 1499 的事件触发失败 dump，
检测到一次 INJECTED ENOBUFS 后立即删除 WAN 默认路由，使该通知发生在
retry 窗口。窗口内 RA 仍使用保留快照的 MTU 1500、router lifetime 1800；
成功重同步后 RA 变为 MTU 1499、router lifetime 0，无需再生成一个变化事件。
原 PD 路由没有被守护进程删除或重新安装；trace 中的 NEWROUTE dump 响应
和 DELROUTE 通知不算 route 写操作。

实际 command 序列是 GETLINK seq 14 遇一次注入 ENOBUFS；约一秒后 seq 15
因前次 dump 尚未消费完而收到真实内核 EBUSY；再下一秒 seq 16/17/18 完成
LINK/ADDR/ROUTE 快照。没有第二次故障注入，进程在这两个重试间隔均继续服务。
这同时验证了 EBUSY 的重试分支，而不是仅验证“没有退出”。时间仅用于判断
重试顺序，没有性能结论。重试代码没有有限总次数，本次仅验证上述有限瞬时故障。

本次只运行这两个目标用例。没有重新运行 DUMP_INTR 实验；共同既存 dump
一致性边界仍未增强，原报告的限制继续有效。未访问路由器、刷机或发布。

新证据仍在独立目录 `/home/ubuntu/odhcpd-audit-ra-kernel-20261018/`：

| 相对路径 | SHA256 |
|---|---|
| `hop-sdk-e33fa56c/results.json` | `ee09c2d4d55266233e5a15766b85154ff90afbd3f56cd148634736cac9d487ee` |
| `recovery-sdk-e33fa56c/results.json` | `f8d6507331a304e5d0ef33582158c28186ee8259878903ad31d4187a87d560a8` |
| `recovery-sdk-e33fa56c/strace.log` | `5dc35650cb45a75e5e9ef63f3d5009bd19ad2f5b58842719e0d513dce8aa59c4` |
| `snapshot_recovery.py` | `54319b555b067de89ab9e5d83b68e1a9ea2fac03a3b9fb0af7a2c1c72e063021` |

恢复用例与上文相同私有命名空间命令执行，将脚本换成
`snapshot_recovery.py`，额外传入 `--candidate-sha` 和上文完整 SDK SHA。
当前没有本审计范围的未关闭新增发现；后续决定只需纳入其他独立审计结果，
不需要继续扩展本报告的场景。
