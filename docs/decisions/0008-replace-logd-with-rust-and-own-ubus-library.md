# 决策 0008：用 Rust 重写 logd，并自建最小 ubus 库

> 日期：2026-09-02
> 状态：已定
> 阶段：阶段 2

## 背景

R15 logd 是 I0 判定的最低风险 daemon：两个 ubus 方法，失效只影响日志。它同时要求"注册 ubus
对象、按 ACL 发布、作为 procd instance 运行、向调用方传递 fd"这四件事，正是后续 httpd、fw4、rpcd
都需要的基础。

## 决策

1. **不绑定 libubus/libubox**。`components/ubus` 用纯 Rust 实现 ubus 线协议：8 字节报文头 +
   blob/blobmsg 编码、HELLO、LOOKUP、INVOKE、ADD_OBJECT、DATA/STATUS 回复、NOTIFY，以及
   `SCM_RIGHTS` fd 传递。只用 std 与少量手写 FFI（sendmsg/recvmsg/poll/setuid）。
2. **logd 完整替换而非包装**。I0 时把 R15 定为"包装"是因为怕改变保留语义；合同 C2 冻结了这些语义
   并有原实现可并排比对，直接替换成本更低、收益更清楚。`logread`、`logger`、`/etc/init.d/log` 的
   结构不变。
3. **同名对象不能并存**：ubusd 拒绝重复路径，因此设备 canary 只能"停原 `log` 服务 → 起候选 →
   验证 → 切回"，窗口约 3 分钟；切换瞬间丢环形缓冲区内容，与原实现重启相同。
4. **package `owrt-logd`**：默认 disabled；`enable` 用自己的 init 脚本替代 `log` 的 logd instance，
   保留原 logread 文件/远程实例逻辑；`disable` 反向。开机接管有独立开关，形式与 0007 相同。
5. **不做 udebug**：设备上没有 `udebug` 对象。

## 后果

- 阶段 3、4、5 复用同一 ubus 库，不再各写一套。
- 日志路径出错时可见后果是 `logread` 无输出或缺行，SSH 与网络不受影响；`disable` 即恢复。
