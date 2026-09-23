# R142：独立 monitor 驻留夹具

[独立 Rust helper](../../tools/benchmark/examples/monitor_memory.rs) 不替换冻结的性能 caller，
也不输出延迟排名。它在新的隔离总线上建立 sender/monitor 两个连接，向确定不存在的
对象发完整合法的 INVOKE，要求 NOT_FOUND；因此每次只有一个大入站镜像及一个小 STATUS
镜像，避免大 PING 的两份大镜像先挤满队列而造成伪失败。

按固定顺序观察八个阶段：无连接、两连接未监听、16-byte payload 已监听、32/256/768 KiB
payload 完整镜像后、停止监听但两连接仍在、全部断连。每阶段 `sample` 模式在进入后约
1s/5s 读 daemon VmRSS/RssAnon/VmData/VmHWM 与 FD 数；同时检查 daemon PID/starttime、
CPU1 和 helper CPU0。每阶段第二次睡眠为额外 4s，实际 elapsed_ms 保留。`smoke` 模式
跳过这些等待，仅验证功能；两份 0ms 输出不得混入正式驻留数据。

十个镜像逐字节比较完整属性顺序、header、原 payload 和独立 monitor 序号；明确检查
add/remove 时机、停止后无镜像、最终 FD 回到起点。输入原 blob 加 44 字节后仍须小于
1 MiB。它不声称覆盖最大合法输入、SCM_RIGHTS、饱和扇出或内核 socket 内存，768 KiB
只是本次最大 payload 点。镜像已经读完不代表分配器归还内存，正是后续快照要观察的内容。

[构建脚本](../../tools/benchmark/build-monitor-memory.sh) 只生成一个新的 musl/SDK helper，
不改 daemon 或原性能 caller。先在 Oracle 对精确 C/R136/候选做 `smoke`；正式路由器
样本、顺序和清理门另行冻结，功能通过或 Oracle 驻留均不构成实机优势结论。
