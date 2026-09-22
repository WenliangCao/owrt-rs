# 对 R118 方向意见的核查

2026-09-22，回应 `a3ec944`。停止客户端容器继续筛选，保留原 FD 差分期望和 R115 开发基线；
没有授权把兼容性下降自动换成速度。性能/资源 90/10 的权重不取消“不得复现已修复 Bug”的约束。

## 接受的批评

R120 相对 R115 的局部改善没有消除 C 差距，见[结果](R120_UBUSD_CLIENT_INDEX_RESULT.md)。
后续先做符号级 profile，不再重复接收控制流或容器变体。约 1% 的探索变化不足以判胜。
更高内存可以作为明确资源取舍；此前内存门不应无限阻碍用户更重视的实际性能。

## 不能据此直接返回 R109

- **“libubus FD 只随第一次发送”不符合 exact 源码。** revision
  `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` 的 `libubus-io.c`，SHA-256
  `9ba94835b2f78b9993d8e6e4f5636e4e4f81ab373ac752afd4ad5bca6bb5fe67`，
  在 `len += cur_len` 之前检查旧 `len > 0`，第一次成功短写后仍可能再附同一 FD。
  每次 `writev_retry` 仍只包含一帧；重复 FD 本身**不证明**普通 libubus 会发生 R109 错配。
  六个既有案例是覆盖证据，不是所有短写、缓冲和调度组合的证明。
  [精确上游源码](https://raw.githubusercontent.com/openwrt/ubus/24864e7840b3a02a9ef76284a373f6b2f00b8a9b/libubus-io.c)。
- **“不跨客户端”只能指入站 socket 状态，不包括最终接收者。** R109 将 FD 关联到另一帧后，
  INVOKE 的 OBJID 或 STATUS 的 peer 决定转发目标；同一发送连接的两帧可以指向两个不同客户端。
  这是源码推导，尚未新增双接收者实测；没有据此宣称已证明 ACL 绕过。
  既有 wireprobe 两帧共用同一 provider，不能证明“不会误投给另一接收者”。
- **last-byte 规则依赖接收缓冲切块。** 一个 `sendmsg(F1 || F2, fd)` 若被一次大 recvmsg 消费，
  R109 marker 可落到 F2；若剩余接收空间只覆盖 F1，marker 可落到 F1。
  Linux 在首次消费携 FD 的 skb 时取走 ancillary，并不把其起点编码进 recvmsg 结果。
  这可以记录为实现相关偏差，但不是发送方可由帧内容稳定推知的归属契约。
  [Linux v6.12 实现](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/unix/af_unix.c)、
  [unix(7) ancillary barrier](https://man7.org/linux/man-pages/man7/unix.7.html)。
- `no_leak=true` 只验证引用最终释放，不证明 FD 随正确请求送达；EOF/RST 的拒绝结果等价也不能类推为资源归属等价。

## 后续边界

R109 保留为历史性能参照，R115 保留为兼容性开发参照。先按符号定位差距，再决定是否值得新实验。
指令数用于诊断，不能把“至少少 3% 指令”当通用性能必要条件：syscall、cache miss 和等待可改变时间而不同比例改变用户态指令。
“±1% 平手”应写成当前分辨能力内未证实差异，不是假定统计等价。
若以后明确选择缩小兼容范围，须列出实际调用者、双接收者和短写结果及具体偏差，再由用户决定；不先改测试抹去反例。
