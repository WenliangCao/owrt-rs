# R142：Oracle monitor 协议补充

[monitor_boundary_oracle.py](../../tools/r142/monitor_boundary_oracle.py) 复用既有 R134
映射、ELF 与进程身份校验，在 Oracle 各自启动 exact C、generic R136、R142 候选。
每个实现各跑下列两个固定功能案例；共六只独立 daemon，固定 CPU1，不采集计时成绩。
同一套断言作用于三个实现，任何失败保留原目录并停止，不以重跑改变结论。

1. **多 monitor 生命周期及 FD 隔离**：两个 monitor 与 caller 预先连接；执行 add、
   重复 add、remove、readd 和注册状态下断连。逐帧验证完整 mirror envelope、payload、
   序号、独立序列重置与接收顺序；remove 后确认该连接不再收到镜像。向 PING 传入
   SCM_RIGHTS witness，所有输出均用限帧 recvmsg 读取并拒绝任何 ancillary data，
   保持客户端连接时要求 witness 写端 EPIPE，证明 daemon 未保留 FD。
2. **快慢双 monitor**：暂停慢读者，完成 128 次携 16,384-byte payload 的 PING，
   快读者每次完整接收三条镜像。随后排空慢读者，必须观察非零且少于 384 条幸存镜像，
   每条字节和序号与原生成序列匹配且严格有序；恢复一个小 PING，两个 monitor 均须
   完整收到三条恢复镜像。不同实现的丢弃位置和数量不要求相同。

每案前后验证 daemon PID/starttime、映射身份、CPU、FD baseline；所有客户端正常关闭，
daemon 只通过 SIGTERM 收尾，日志为空。三秒 I/O 与进程收尾限时仅用于发现功能卡死。
namespace 外运行的 Python caller 是新功能探针，不能与原 caller 绝对延迟比较。

既有 8 wire、6 FD、2 recovery 门及原 R131 event-stress helper 的 grouped、interleaved、
monitor、slow 功能检查另行复用，不替换旧输入。序号 wrap 与强制 short-write 字节所有权
由独立 SDK 第 56 项回归覆盖；本探针不作 heap/RSS 或内存上限结论，内存证据另取。
