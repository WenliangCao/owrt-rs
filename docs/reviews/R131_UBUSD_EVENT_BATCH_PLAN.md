# R131：同一 owner 的连续事件帧批量发送

R130 已证明减少发送系统调用本身没有在路由器上形成稳定注册收益；本轮转向 R124 的明确事件尾项。
R125 的精确夹具在一个 listener 连接上注册 8 个 handler，R124 对每个匹配对象都发送一帧 INVOKE，
八对象 fanout 仍约慢 C 2%。C `ubusd_event.c` 会为每个对象调用 `ubus_msg_send`；事件帧不携带 FD。

从精确 R124 `a5b0ff1ec71a38d8c840b6995f859b503a08387d` 独立建候选，只做以下范围：

- 仅当连续匹配帧发往同一个 owner、目标不是 monitor、该 client 当前发送队列为空，且批次总线字节不超过 16 KiB 时，把完整 wire frame 追加到持久 `event_batch`，一次提交；
- 跨 owner 不重排，owner 改变或达到上限就 flush；首帧仍沿用当前直接发送，单接收者路径不增加复制；
- 每帧仍先执行 mirror、分配 event sequence、patch OBJID，并保持原 pattern 顺序；monitor 非空时全部回退逐帧，以保留 `M1,E1,M2,E2` 顺序；
- 已有队列、大帧、短写和队列上限均按逐帧语义恢复，未发送帧各自计入 cap；不携带 FD，不改变输入接收边界。

`Client::send_lookup_batch` 的现有短写循环先视为需要修复的潜在缺陷：跨越多个帧时只能设置一次首个未完成帧的偏移，
后续帧直接按原帧入队，不能反复覆盖 `txq_ofs`。候选必须新增跨 frame2/frame3、EAGAIN、已有队列、cap drop 的逐字节测试，
并复用该健壮 helper；若无法证明，退回逐帧路径，不实现批量。

功能门覆盖：三 owner 连续与 A,B,A 交错、重复 pattern dedup、monitor 顺序和镜像、慢读者/已有队列、16 KiB 边界、
大 payload、大帧短写、sequence wrap、sender exclusion、事件删除、FD wireprobe、ACL/UTF8/release 回归。
所有输出帧的 header、OBJID、seq、payload、队列长度和最终 socket 字节必须与 R124/C 逐字相符；生产仍运行 C。

先在 Oracle 做精确 R124/候选的 syscall/指令预筛，确认 same-connection 8-object lane 的 `sendmsg` 确实下降且 A/A
校准通过；没有按符号和真实 sendmsg 计数的收益，不上路由器。路由器只跑一次预冻结的 C/R124/R131 交错系列，
daemon CPU1、caller CPU0、统一 argv0、每窗健康/清理/原始 latency 保留。以 R124 为主对照：八对象 mean/p95/p99、daemon/caller CPU
均报告；六块全降且 mean 中位至少 −3% 才记稳定收益，p95/p99 或 daemon CPU 中位回退超过 5% 即拒绝。
`±1%` 记工程平手，不称统计等价；不把 R125 未钉核 caller 数值与新结果拼接。

这是一个单独、可撤销的 fanout 实验，不与 R130 合并，也不改变 R124 基线，所有失败与短写缺陷公开保存。
