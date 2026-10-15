# A53 上 E 完整 UDP owner 分配计数

三个事前固定窗口全部通过，仅报告计数。E+meter source `6d6e6038`、
SDK ELF `3ade51ea…`，使用原隔离case/group/guard、新f7 loadgen与既有
校验器。每窗1000条预暖、1000条warmup、4000条measurement均正确，
共18,000条；case exit0及原`set -e`脚本最终`wait daemon`后COMPLETE，
证明daemon正常退出0，退出时一次写计数报告。

| 完整缓存命中步骤，每次实际命中 | 窗1 | 窗2 | 窗3 |
| --- | --- | --- | --- |
| 实际cached分母 | 5200 | 5200 | 5200 |
| alloc | 5 | 5 | 5 |
| dealloc | 5 | 5 | 5 |
| realloc | 0 | 0 | 0 |
| requested bytes | 270 | 270 | 270 |
| released bytes | 270 | 270 | 270 |

分母合计15,600，包含预暖期间真正缓存命中的请求，**不是硬写5000**。
每窗cached分配直方图仅bin5=5200。step范围覆盖receive、admission、
完整process_udp、send和所持对象drop；三窗nested_steps及
unscoped_classifications均为0，31/32/32个进程观测样本均为单线程。

条件为cached-only的完整owner turn，每cached query也同为5/5/0、
270/270B；其turn数分别5112、5200、5198，说明turn不能替代query分母。
全程所有owner turn另保留三类原始矩阵，不能将条件结果当成全程平均：
三窗共20,313 turns、181,945 alloc、172,105 dealloc、2,407 realloc，
申请10,377,696B、释放9,933,103B。`no_packet` turn仍可处理上游完成或
控制工作，不等于纯idle；无包step也不能直接当成EAGAIN系统调用数。
这些是owner循环范围，不包括循环前初始化、报告输出和后续清理，
不能据全程申请/释放差断言泄漏。

计数版ELF为2,358,043B，超过原2,200,000B发行门；该门没有放宽，
产物不晋升。**全部CPU/latency数据均EXCLUDED**，这些计数不证明耗时、
IPC、C侧分配次数或任何性能收益。请求字节也不是RSS/USS或malloc实际
占用。与先前本地API子链的5/270相同，只是计数一致，不能由此反推每个
分配点已动态归属。

三份tar、132个原始文件已逐项核验；125个guard样本、50次DNS、23次HTTP
及10次双栈HTTPS均通过。设备有效副本归档后回收，临时rust槽已恢复
原F `b7926bcf…`，c槽仍E `8b8082b9…`，生产8472…/3086/2115未变。
收尾无STOP、活动测试组或本任务活进程，可用内存97,752KiB。

[原始计数派生结果、身份与归档回执](E_UDP_ALLOCATION_DEVICE_RESULT.json)
保留全部分类矩阵、计数口径和完整scope限制。
