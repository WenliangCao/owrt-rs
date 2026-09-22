# R126：无接收者回复提前退出

R125 八对象 fanout 的精确 ELF profile 中，R124 的 attrs_of、对象查询及客户端查询仍可见。
源码核对确认：原版 libubus 的八个 event handler 位于同一连接，每个 INVOKE 都产生一个 peer=0 STATUS；
ubusd 没有这个客户端，最终静默丢弃。精确 C 与 R124 目前都先解析/校验对象，再查目标客户端。
这不是 C 已做而 Rust 遗漏的优化，也不是 profile 已经证明的耗时归因。

只从 R124 `a5b0ff1ec71a38d8c840b6995f859b503a08387d` 新建独立候选。
把 response 中现有 dest/clients.contains_key 检查移到 attrs_of 前；删除旧位置，不加第二次检查。
对有效目标仍做全部属性、类型和所有者校验；对无目标提前返回同一个 NoStatus。
入站 monitor 仍在 receive 入口执行；STATUS 的 OwnedFd 返回时关闭，DATA 的 FD 仍由 handle 入口关闭。
解析和 registry get 都是无副作用只读操作，单线程中两处之间没有回调或客户端表修改。
不修改 prefix/body FD 边界、读取/发送系统调用、事件序号、队列或 ACL；不合并 fanout。

最小功能回归覆盖：目标缺失的有效/畸形 STATUS 和 DATA 均不输出；
有目标时正确转发与错误所有者拒绝保持；入站 monitor 字节和 FD 关闭可观察行为保持。
保留 R124 既有大消息、排队、epoch、ACL、协议和 FD 门。
本假说预期每次八对象事件最多省八次 attrs_of 和对象查询，不省客户端查询或收包 syscall。
不承诺消除内核成本、caller CPU 差距或实机约 2% 耗时差距。

候选先按规范路径构建并校验 R124 控制 ELF，执行单测和既有六组功能/恢复门。
先用原版 libubus v3 ACK helper 做 Oracle 同步计数；固定一/八对象及无匹配、低/64-held，
A/A 校准与候选/基线反序块的精确参数、工具和产物身份在运行前另冻 JSON。
指令下降至少 3% 是用户态预筛启发式；若未过，停止并记录，不直接启动 router 性能系列。
通过后先路由器原协议/FD/单测门，再预冻同一实机规则的 C 对照，完整报告 wall 与 CPU 正负结果。
±1% 仅工程平手，不称为统计等价；Oracle 不作最终性能结论，不增加窗口追逐显著性。
