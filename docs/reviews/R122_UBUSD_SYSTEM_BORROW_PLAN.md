# R122 系统调用入参借用实验

R121 的精确符号 profile 指出分配/释放为可见用户态热点；R115 的 system invoke 仍在同步派发前复制 METHOD 和 DATA。
候选 `6f38c06` 基于 R115 `b28dbc8`，只让 `system_object` 借用当前消息及两字段，删去两次 `to_vec()`。
credentials、事件编码、HashMap、接收算法、FD 归属、monitor 和发送队列策略都不改。

假设：本次 event.send 的 METHOD 和 DATA 均非空，少两对分配/释放及对应复制；无 DATA 的系统调用只少 METHOD 的一对。调用结束后借用不逃逸。
新增完整 receive 入口回归：慢读者强制排队，覆盖并结束输入缓冲生命周期后，event 与 monitor 内容必须仍逐字节正确。
保留原协议/FD/ACL/背压/恢复门；先 Oracle 46 条单测与六组功能恢复门，再路由器单测、原协议和 FD 差分。

通过后只执行一次固定 C 对照系列：低连接、64-held 各十窗口，每窗口三种 user-event lane、每段 5000 次，预热 2000。
沿用已验证的原版 libubus 调用者与 ABBA/BAAB 脚本，窗口间交换 C/候选槽位，规模交错。
记录 daemon/client/total CPU 与 wall；完整 payload/计数、原始 ELF、库和清理身份校验，每窗口后继续生产 C。
不从旧 R115/C 比率拼接出 R122/C；不追加直到显著为止的窗口，也不把 Oracle 排名当成实机效果。

本系列首先回答这三个事件 lane 的顺序事务平均用时是否优于 C，以 wall_us 为主指标，daemon/client/total CPU 为次指标，完整报告两规模×三 lane×四指标共 24 项。
每窗口先聚合每方四段，再形成一个配对比值；user_8_1 以每次发送事务计，64-held 是额外空闲连接数。
±1% 按工程取舍记为平手；十窗口全同号只是方向证据，仍报告幅度、散布和假设独立同分布下的 rank interval。
wall 不能称为饱和吞吐、p99 或全 ubusd 性能；不得事后挑选某个改善的 CPU 指标宣布性能胜出。
正确性任一失败立即停止。候选未胜 C 就保留负结果；不得宣称性能目标完成，其他工作负载也不会因此自动通过。
采样 JSON 计划待精确 ELF 与前置门身份齐备后冻结；不提前部署或合入主运行源码。
