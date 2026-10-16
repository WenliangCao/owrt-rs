# recvmmsg 共用接收池：当前不排入候选

结论：不实现。它可以减少系统调用边界，但不是现有 `receive` 的直接替换。
为保留短路、重发和 owner 调度，需要新增跨轮次未消费包状态；短返回还不能
表达现有接收错误边界。当前没有足够的低负载收益证据支持这组改动。
这是否决本轮排队，不是证明所有批量接收方案都不会更快。

只读产品来源为 `185db90c9cabd26c0af09765636ef15bf6d35f79`。没有修改产品、
编译、测试、Oracle/router 访问或复跑 read-one/adaptive。以下源码行号绑定该提交。
独立 99b519 只延后 Arc 克隆，不提供批量接收接口，也不解决下列调度问题。

## 现有接口与边界

- `net.rs:580`：非阻塞 `recvmsg`，单一可变切片；返回
  `Result<Option<Datagram>>`。截断、控制截断、源端口零和缺失 pktinfo 为
  `Ok(None)`；真正的 syscall/address 错误为 `Err`。
- `listeners.rs:444`：单包包装映射为 `Incoming`，保留 peer、local source
  和 interface。Linux 64 位使用该 net 实现，其他目标仍有独立后备路径。
- `main.rs:3161,4925`：owner 仅一个已初始化的 65,535 B Vec。每次处理借用
  当前包；已有 interface/MAC 延迟路径在需要时转为拥有的副本。
- `main.rs:4637`：正常轮次共有 16 个 `step_udp == true` 的预算。
  short/QR/ACL reject 返回 true、继续该 listener；oversize/discard/receive
  error 返回 false、停止该 listener，但仍处理其 TCP 和后续 listeners。
- `main.rs:5935–6092`：DHCP probe 的 DNS 服务是另一条调度路径，每次等待后
  每个 listener 只调用一次 `step_udp`，并维护 ICMP 的完整超时边界。

## 在同一池内分槽并不能只改一个 syscall

默认 `edns_max=1232` 时，16 个 payload 槽只需 19,712 B，可以使用原池的
不同切片，无须 16 个 64 KiB buffer。配置在 `scalar.rs:149,228` 最终支持
512…65535；槽长必须覆盖当前允许的完整包，槽数最多为
`min(16, remaining_budget, floor(65535 / edns_max))`。例如 4096 B 上限只能
容纳 15 槽，65535 B 只有一槽，后者不能靠批量降低接收次数。固定 1232 或
4096 B 分槽会错误截断其他合法配置，不能作为通用实现。

此外需要每槽独立 sockaddr、pktinfo、iovec、mmsghdr 和完成状态；metadata
不包含在原 payload Vec 中。现有已核 ABI 为 MsgHdr 56 B、IoVec 16 B、地址
storage 32 B、控制 buffer 40 B。新 mmsghdr 的布局、对齐和每次调用前复位
必须单独核验，所有指向切片的原始指针不得跨 pool 移动/重分配保留。
这里没有把 65,535 B iovec 容量误算成每包复制或清零量。

| 边界 | 直接批取的问题 | 保持现有行为所需改动 |
| --- | --- | --- |
| 16 包预算 | 一次取回多包不等于多次返回 true；invalid false 不消耗旧预算 | 分开记录 kernel 已取包、逻辑已消费包和剩余 owner 预算 |
| invalid 短路 | 第一个 oversized/discard 包之后的有效 tail 已离开内核 | 停在原短路点并保存 tail，不能丢弃或继续处理 |
| 多 listener 共池 | 上一 listener 的 tail 仍占池，旧 owner 此时会继续下一个 listener | 分配空槽/保留 per-listener 顺序；跳过其他 listener 或直接清池都会改变调度 |
| 接口暂挂 | 第一个包的 admission/processing 可启动 interface collector | 尾包继续保留，门控未开时不能消费或反复零超时唤醒 |
| buffered work | 尾包可能已经清空 socket 的内核队列，没有新的 POLLIN | `wait_for_files`、`step_udp` 和 probe wait 都要按可运行尾包唤醒，且不能绕过初始化/interface 门控 |
| listener 删除 | 原来未读内核包随 socket 关闭消失 | 按 SocketToken 取消未消费 tail；为 tail 无条件持有 Arc 会延长旧 socket 生命周期 |

因此侵入范围至少是 `net.rs` 的新 Linux 批收 ABI/逐槽解码、`listeners.rs`
包装、`SinglePoll` 的池/尾包/预算状态、正常与 probe 两套等待和消费路径，
以及 `remove_listener` 清理。用同一全局队列全部串行消费会使代码较短，
却不能自动保持原来的跨 listener 公平性和门控边界。没有建议为此建立新框架。

## resend 和 dump 必须仍按逻辑消费顺序发生

`main.rs:4955–4990` 在每次成功消费、discard 和非 WouldBlock/TimedOut 错误
时清除 resend；空读则保留最后一次实际转发。`upstream.rs:595–619` 的保存
状态与 route event 可观察，不能只按“收到一批”清一次。例如先转发 Q1、再
丢弃 Q2 时，最终必须清掉 Q1 的 resend；提前清整批、随后处理 Q1 会做错。
逐槽虚拟消费可以保留这部分顺序，但需要显式的槽状态和错误边界。

非阻塞 `recvmmsg` 返回当前可收的消息数。若已收到至少一条后遇到错误，
它返回成功数量；后续错误通知还可能被别的网络事件覆盖。因此正的短返回
不能证明结束原因是 EAGAIN，不能据此决定保留还是清除当前 resend。为恢复
旧错误探测而再次调用单包接收，会重新引入本来要省掉的低负载空读；还必须
证明错误的可见时序没有变化。[Linux recvmmsg 手册](https://man7.org/linux/man-pages/man2/recvmmsg.2.html)
是这条 API 限制的依据，不是本镜像上的运行验证。现有 socket 已是非阻塞，
不能引入阻塞等待或以 timeout/MSG_WAITFORONE 延迟首包换取凑批。

`process_admitted_udp:5023` 在 admission 后才分配 query context、记录 QUERY
dump 和日志。不能在批取时预先给全部包分配 ID、记录 dump，或改变与 reply/
upstream dump 的交错。`dump.rs:174–223` 已把记录复制到拥有的队列，消费后
回收槽本身可行；跨轮次未消费槽仍须保持原字节，且不能复用为下个 listener
或 DHCP/TFTP 的接收区域。已有 MAC/interface 延迟单包的拥有关系必须继续保留。

## 收益判断与停止点

单包低负载下，批收仍需要发现下一包不可读；可以省的是一次用户/内核往返，
不是证明整个空队列检查消失。该收益要抵消多槽 metadata 准备和持久状态分支。
高负载有多个已排队包时能合并更多 syscall，但旧 owner 已按 16 包摊销 poll，
且不能因此改变 budgets 或 probe 服务量。没有现185/A53批收测量，也没有将
过去 F/read-one 的 PMU 差异换算成 recvmmsg 预计收益。

历史 read-one 已因高负载退步淘汰，adaptive 未建立真机可辨收益；两者不重跑。
本轮优先完成既定 C/185 stat+cycles 定位及已保留的小候选。除非新证据明确
把剩余成本归到可批量摊销的接收边界，并先解决短返回错误与池尾包兼容问题，
否则不排 recvmmsg 产品原型或远程实验。
