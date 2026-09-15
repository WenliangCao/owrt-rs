# 共享 ubus 客户端：连接与期限

适用 `components/ubus` 的 Linux 客户端和对象服务端；不改变 ubusd 的权限、凭据或协议。

## 新连接

`Connection::connect(path)` 在 **1 秒总预算**内完成 Unix socket 接入和完整 HELLO 接收。
`connect_timeout(path, Duration)` 可显式选择预算；零预算立即超时。预算只属于新建连接，
失败销毁该连接，不关闭调用者已有的服务连接，不清除 rpcd 会话或 apply 回滚状态。

Linux 使用非阻塞 connect。AF_UNIX backlog 满返回 EAGAIN 时，按同一绝对截止时间短暂退避
并重试 connect；不把尚未连接的 socket 可写误当作连接成功。EINPROGRESS 以可写和 SO_ERROR
检查完成。成功后恢复阻塞模式，保持既有对象服务接口；HELLO 逐段读取仍使用同一截止时间。
路径长度、内嵌 NUL、文件访问权限及普通连接错误继续由原校验或内核拒绝。

这是相对精确 C/libubus 的有意恢复边界：C 的初始 connect/HELLO 可以长期阻塞。
本边界防止未发送 HELLO 或 accept backlog 停滞使 procd 喂狗、日志接收或 HTTP 工作线程无限停顿。
一秒内未完成会返回超时；调用者保留自己的重试/失败策略，不承诺永远等待慢总线。

非 Linux 仅为本地编译/部分单测辅助，保留 `UnixStream::connect` 的既有行为；完整接入预算
承诺针对部署目标 Linux。不要把 macOS 辅助测试解释成 Linux socket ABI 验证。

## 已建立连接

限时请求的总预算覆盖发送和完整回复帧。未进入半帧的普通超时保留服务连接，迟到回复依序号
区分；已丢失帧边界的超时关闭传输，防止下一条请求把半帧当成报文。请求的非正数 timeout
仍表示无限等待，与新连接的零 `Duration` 不同。

对象服务端可用 `set_server_io_timeout(Duration)` 为完整帧接收及回复/通知发送设置总预算。
procd、netifd、logd、rpcd 在初始连接和重连时均启用一秒预算；无数据的
`incoming_if_started` 仍立即返回 `None`，不会等待一秒。预算耗尽关闭该传输，交还主循环
执行维护和重连；rpcd 保留内存中的会话和配置回滚状态，离线继续处理回滚期限，见
[rpcd 合同](rpcd-core.md#6-总线断连时保留回滚r93)。显式限时请求仍使用自己的请求预算。

这不是增量事件循环：一次报文或发送仍可能占用主线程至一秒。单次 I/O 上限也不是整个
处理函数的上限；多次同步请求的累计时间必须在具体 daemon 的维护路径中分别验证。
