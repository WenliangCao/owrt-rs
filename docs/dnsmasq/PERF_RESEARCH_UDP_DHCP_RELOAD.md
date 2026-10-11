# UDP / DHCP / reload 性能研究

2026-10-11。完成研究与收尾；三项均未低于C，按追加的复杂度/收益停止条件结束。

候选源码`ceaf0299b075570bda282098dd06001225affbbd`与清理版本`c1cb6c35`源码树相同；feature-off opt3 ELF为`98ac292af035e771d15151552f8caadb938f8112ca7264573e51a749ec74e36a`。镜像C SHA为`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。保持每包DHCP新接口视图和既有行为合同。

## Oracle最终收尾

| 场景 | 889fe4f5 Rust五轮中位 | 最终C三轮中位 | 最终Rust三轮中位 | Rust相对起点 | Rust相对本轮C |
| --- | ---: | ---: | ---: | ---: | ---: |
| UDP缓存命中，µs/请求 | 16.744 | 11.865 | 12.403 | −25.92% | +4.54% |
| DHCP，µs/周期 | 739.639 | 473.749 | 525.038 | −29.01% | +10.83% |
| 并发reload，µs/请求 | 37.529 | 19.771 | 27.246 | −27.40% | +37.81% |

44族完整功能回归：44/44族、67/67命令通过，同一98ac ELF；结果为Oracle `private/final23-families-repaired-combined/result.json`。54窗（9场景×C/候选×3轮）：54/54有效且行为检查通过，Oracle `private/final23-windows/state.json`。全部九场景的CPU、p95、吞吐、RSS/PSS及新增错误检查，未检出超过本次协议阈值的历史退步；普通新增错误、辅助行为错误均为0。最终三项均未低于C；余差分别0.539µs/请求、51.288µs/周期和7.475µs/请求。按用户修订的复杂度/收益停止条件结束，不声称合同内不可能继续降低。

其余六场景的稳态CPU（µs/请求；故障场景取故障前阶段）：

| 场景 | 889 Rust | 本轮C | 最终Rust |
| --- | ---: | ---: | ---: |
| UDP未命中 | 79.546 | 93.386 | 72.248 |
| 混合DNS | 32.122 | 31.057 | 26.091 |
| 上游故障前 | 121.629 | 141.564 | 109.145 |
| TCP本地 | 24.097 | 27.864 | 21.402 |
| TCP缓存 | 19.878 | 33.586 | 19.115 |
| TCP未命中 | 97.502 | 226.172 | 95.395 |

三项分别在三轮中均高于同期C；其余六项上述阶段均在三轮中低于C。UDP-hit、TCP-local、TCP-cache的饱和吞吐受生成器限制；故障期无正确回答，CPU/正确请求和p95不可比较。其余详细阶段及分类保留在派生分析中，“无显著差异”不表示等价。

正式窗口保持30秒预热、120秒测量及原饱和/故障/空闲/排空合同。阈值仍为吞吐退步≥5%、CPU/p95≥10%、RSS/PSS≥10%且≥64KiB；变化须超过两组最大W=(max−min)/median。按本次三轮要求用3/3方向；历史五轮计算median/W、历史1–3轮作方向参照。这是历史比较，不冒称完成原五轮4/5条件。新增普通错误直接退步；generator受限的吞吐不作容量结论。

## 主因和保留的改动

DHCP的大差距来自逐包接口查询内的重复工作。精确889fe4f5重测为275.738次syscall/周期，C约81；旧资料的317次属于更早版本，不能全部计入本次收益。保留每包全新的观察，只在同一次dump内复用接口flags和接口名；限定非阻塞netlink续步并按readiness推进，修正单租约删除时按整表预留的临时Vec，并复用包缓冲。清理候选约78次syscall/周期，ioctl与C均约16次；重复接口查询已不再构成剩余差距，租约持久化等合同工作仍保留。

UDP命中的已知用户态浪费包括重复名称/元数据处理、无用EDNS复制和临时集合/容量。最终只保留直接借用、避免无用构造、普通缓冲复用等简单改动。reload没有增加专门快捷路径；其剩余问题与低速DNS/owner路径共同研究。

相同256名、20客户端的清理候选长窗口（各3对，30秒预热/120秒测量）显示：1kQPS C/Rust为18.243/22.915µs，10kQPS为10.908/12.153µs。低速差距更大，但不支持“Rust每轮执行更多指令”：Oracle PMU-only对照的用户指令反而少12.7%，IPC C/R=1.030/0.562，L1I refill约2.56倍。计数窗口本身明显抬高总CPU，只支持机制方向，不能换算成未插桩CPU份额或外推真机IPC。

另一组带计数诊断在1kQPS下，每次正ppoll返回的用户指令C/Rust约12,511/10,804，syscall/请求约3.0/4.0；Rust每请求多约一次EAGAIN。正ppoll返回不是物理调度唤醒，插桩计数不能代替未插桩CPU；数据不支持继续堆叠主循环跳过条件来解决主要余差。

清理撤回或未采用Name内联存储、EntryIds三态容器、备用query/log缓冲、额外caller gates、DHCP poll顺序、重复发送API、特殊名称验证路径和5µs自适应UDP预算。它们缺少足够独立长窗口收益来支撑复杂度；不声称每项分别被证明有害。

固定UDP预算1可省末尾接收尝试，但Oracle同批长窗口相对固定16：10k稳态CPU−10.24%，saturation CPU+34.43%、p95+34.34%。饱和generator受限，QPS变化不是服务容量上限；已有CPU/延迟代价不支持采用。当前仍用固定16。

## Cortex-A53真机补充（与Oracle分开）

只在/tmp放临时文件和测试进程，loopback非标准端口15353/15354，最高1kQPS；仅计测试daemon自身utime+stime。每窗30秒预热后150秒测量，C/R交错。reload只含hosts/HUP，没有Oracle场景中的TFTP。未建立并验证完整的DHCP网络命名空间/虚拟接口隔离，按授权跳过，不将其解释为内核必然不支持。

| 场景 | 起点889 Rust（1对） | 起点同批C | clean23 Rust（三对中位） | clean23同批C中位 | Rust绝对变化 | C归一变化 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| UDP hit，µs/请求 | 152.800 | 63.600 | 95.133 | 60.067 | −37.74% | −34.08% |
| reload，µs/请求 | 169.379 | 67.534 | 101.503 | 64.331 | −40.07% | −37.09% |

C归一变化=(当前Rust/C)/(起点Rust/C)−1。起点只有一对，W不可估计；这是累计改善的方向证据，不是正式显著性结论。当前仍比同批C高58.38%/57.78%。当前Rust hit三轮W=12.40%，reload W=5.26%；第3个hit Rust窗口有10次外部/proc观测，保留在统计中，不据此解释其偏高值。user/system分项随轮次明显漂移，总CPU不由分项中位数相加。首轮“约70%的余差在内核态”未被后续分项稳定复现，不作为最终归因。

真机hit的Rust三轮user/system分别为29.20/64.47、39.27/55.87、51.07/54.40µs；对应C为18.47/40.47、16.40/45.40、25.80/34.27µs。逐轮总量及其他变体分项见`router-variant-summary.json`。

| 独立候选（各2对） | hit的C归一变化 | reload的C归一变化 | 取舍 |
| --- | ---: | ---: | --- |
| owned static IPv4省IP_PKTINFO | −5.19% | 未测 | 信号小于现有跨轮波动，未恢复到最终代码 |
| 固定UDP预算1 | −4.05% | 未测 | 未弥补余差，且Oracle高负载代价已知，仍退休 |
| opt-s | +5.91% | +11.14% | 未采用 |
| target-cpu=cortex-a53 | −0.77% | +8.77% | 未采用 |

以上只作研究筛选，不能套正式收益判定；原默认构建已是fat LTO、codegen-units=1，未重复构建相同组合。

真机/proc识别到的ppoll样本中，C/Rust均为6个fd，未见Rust多轮询fd的证据；这是抽样，不是逐次完整跟踪。Oracle全量诊断同样为hit 6/6、DHCP 47/47、reload通常8/8。

设备perf_event_open返回ENOSYS，IPC/L1I未测，不能确认真机的指令缓存因果关系。一次私有SIGPROF诊断记录13,829个当前PC，范围包含启动、预热和负载；最大标签sccp（23.8%）确认是musl系统调用shim，99.82%的该项样本在svc后的ret。ITIMER_PROF的system时间可投射到该返回位置，不能把它当可删wrapper成本或精确内核比例。未命名段为memcpy及少量原子辅助；时间辅助+vDSO约1%，wait_for_files约0.93%。其余分散在DNS回答、owner收发控制、事件交接和分配辅助，没有找到足以解释约35µs余差的单一自然改动，不继续微分配优化。

其他主要PC归属：process_udp 5.61%、answer_records 4.56%、DnsDaemon::poll_inner 4.39%、LocalAnswerer 3.79%、take_query_events 3.50%；malloc/free合计6.42%。这些是粗略样本分布，不能直接换算成每请求CPU分摊。

最后一次独立strace计数：C450,874调用/149,808正确请求=3.009679，Rust593,979/150,000=3.959860；差异主要在recvmsg尝试。原样aggregate errors为C recvmsg115、Rust recvmsg146513，其余0；没有errno/fd明细，不能全部命名为EAGAIN。两端clock_gettime/ioctl均0（vDSO不进入该表）。插桩CPU/延迟全部排除性能比较，ptrace批处理比例不等于真实唤醒频率。

真机所有已完成窗口及失败清理的生产dnsmasq身份、WAN、DNS健康检查通过；任务进程与/tmp目录清理已验证。最后strace对照的最小可用内存108256KiB，任务目录峰值15496KiB。没有改生产服务、系统配置或闪存。

## 失败尝试、证据和停止理由

较早SDK libc/startup替换、跨层Question复用及多种细碎容器/跳过条件没有可靠收益，未保留。一次受影响用例子集因遗漏valid-complete/raw-unknown控制而无法归类既有netlink-partial-error参考差异；不是已证实的新增产品回归。完整族保留原控制。

收尾修复了两处验证工具问题，产品ELF未变：`ff68488a`使每答即断开的TCP用例按连接周期比较临时端口，避免把C偶然再次选到48001误判为连接复用，并保留地址/目的/UDP固定端口保护；完整188个endpoint服务用例及190行语义审计补测通过。`bdde4fae`在UBus partial-frame用例的唯一DNS seed前等待本进程监听端口绑定；受控启动延迟证明UBus已注册时DNS仍可能未bind、首包可丢（20次自然启动未复现原故障）。响应时限和metrics检查不变，完整UBus 2148检查、350配对、10负控通过。原失败保留，其他42族复用同一ELF的通过结果。

真机baseline一次reload在测量前被watchdog中止，原记录和无配对C保留，fresh C/R替换配对；heartbeat改为原子替换，但不声称已证明唯一原因。首个SIGPROF诊断构建因后置C对象的libc符号未抽取而失败，在对象后补同一self-contained libc完成fresh构建。首个strace因-I1的后台SIGINT处理未产生detach/summary而作废；改-I2后fresh pair均退出130且summary完整、TracerPid=0、daemon身份存活，属于正常请求SIGINT的工具退出。

停止是工程取舍，不是证明合同内绝无继续优化空间：大的重复工作已消除，剩余成本分散；简单编译/系统调用策略没有跨场景足够收益，更专门化的事件循环会增加M6b最敏感路径的维护风险。最终保留简单候选；44族和54窗通过，未检出超过协议阈值的历史退步，余差不作未经证实的精确CPU分摊。

原始perf/strace、ELF、路由器原始输出均留private；本地证据根为`private/dnsmasq-perf-research/`，Oracle为`/home/ubuntu/dnsmasq-perf-research/private/`。主要派生证据：`long23-review/summary.json`、`pmu23-only-review/summary.json`、`router-variant-summary.json`（保留baseline配对索引）、`sigprof-current-interpretation.json`、`router-syscall-summary.json`；最终Oracle分析`final23-analysis.json`（原始重算与独立审查关键数值一致）。未合入main，未推送GitHub。
