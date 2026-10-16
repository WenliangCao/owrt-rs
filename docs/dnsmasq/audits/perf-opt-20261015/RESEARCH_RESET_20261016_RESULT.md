# 研究方向调整：本批统一结果

**Oracle200qps下G比C多约3960用户周期/query，同时L1I refill多113%、L1D多85%、
分支预测失败多58%；决定继续验证冷时缓存/分支成本，尚不认定A53主因已证实。**
9e未晋级，G仍是完整验收通过的交付。对应唯一计划/新测量规则是
[FROZEN_RESEARCH_SUPPLEMENT_20261016.md](FROZEN_RESEARCH_SUPPLEMENT_20261016.md)，提交d81f3f1d。
这里3960是两侧中位数之差；三次配对周期差的中位数为3550.5712，决策用配对结果。

## 我对外部诊断的判断

同意首要假设应转向低速率时的代码/数据与分支成本，同意旧>8tick门限限制5µs级探索，
同意允许小改动组合实测、取消热native/饱和sendlag作为A53前置门，并大幅缩减重复文档。
不同意把低/高载80%的周期差全部认作缓存停顿：批处理、轮询、调度、生成器上限都改变。
也不同意用未显著的2–4tick宣称真实收益、把refill当独立足迹行数、或把Rust骨架当内核地板。
报告“未组合”不适用于最新9e：它已经包含6ab、inline-address、owner outlines、warm writer等，
实测G118→9e114µs仍未分辨。sendlag一直完整记录，但G在该诊断恶化时仍已验收晋级；
本批更明确规定它是生成器诊断，不能独自否决产品。c95已完成实际SDK聚拢，无需新linker脚本。

当前模型：G比C的低速成本更可能含额外cache refill和branch代价，但真实A53归因待速率扫描
与布局干预。若高速下差距不收窄，或PGO/c95均低于新测量噪声，则降低“布局足以解决”的判断；
下一步先量匹配C收发/事件循环参照，不能再把不同诊断中位数相加当预算。

## Oracle固定PMU诊断：完成

12/12窗口，7个同组事件，共84个counter全部time_enabled==time_running，无缩放/补测。
每格3次C/G配对，200qps与rate0，独立1000prewarm排除；计数括号包含5s warmup、20s测量、
固定1s drain，分母是前两段实际correct。低速各5000，高速C为4544031/4530318/4506924，
G为5800928/5782663/5801750。原流量、ACK及清理有效。

| 每query用户事件 | C低速中位 | G低速中位 | 配对G−C中位 [三次全范围] |
| --- | ---: | ---: | --- |
| cycles | 13403.18 | 17363.16 | 3550.5712 [3207.9264,3959.9780] |
| L1I refill | 574.27 | 1225.25 | 632.2808 [630.6162,656.5818] |
| L1D refill | 128.15 | 237.42 | 109.2626 [104.6840,109.3296] |
| ITLB refill | 50.99 | 38.47 | −12.6948 [−12.8260,−9.3130] |
| DTLB refill | 43.49 | 52.80 | 11.0846 [9.3094,11.8276] |
| branch misprediction | 238.69 | 378.02 | 139.3336 [138.2782,140.3050] |

低速IPC0.6721→0.4427；高速C/G周期5475.25/3502.81，G的IPC1.5705。
高速G仍有约53%更多L1I refill，周期却少36%；L1D配对差−3.975/−7.434/+2.666方向不一致。
这些反例反对“每个miss固定代价相加就是全部周期”的简单模型。高速生成器CPU99.66–99.71%，
只能称闭环高载，不能叫独立服务端饱和极限。所有计数限Neoverse-N1用户态，不外推A53因果。
[Arm N1 PMU事件定义](https://documentation-service.arm.com/static/66ace6ee0469d5197d40c93e)
也不把这些refill解释为唯一cache line数或退休分支错误率。

完整summary与537个raw哈希：
`/Users/USER/Developer/owrt-perf-cg-pmu-20261016/private/cg-pmu-20261016/summary.json`，
SHA256 `ca7a412fb9e9bab1ea8612ee2f40ef11f6f3169f70d0782ce2c017cc6a90ddd5`。
raw保留Oracle的`loop/private/cg-pmu-20261016`；固定argv矩阵SHA320a68775d1c9a63a9a69d8690360c995cabb64a21c3417f57642aafb4adcc8f。
捕获和summary结束后，本机挂起SSH单独终止退出255；未终止远端任务或改变任何窗口。

## 已有PGO与c95：运行资格已齐，真机结果待测

现有PGO0910b49和同源E8b8082b9一次最小启动/A+AAAA/live身份/RELRO/NX/noWX/正常TERM均PASS，
无强制清理或残留。未重训/重建。原ELF超预算88419B、APK超93382B保留，仍不可发布。
最小smoke raw本机`owrt-perf-pgo-sdk-smoke-20261016/private/perf-opt-20261015/pgo-existing-runtime-20261016/raw/runtime/result.json`，
SHA4a35a3a0dfcf71f8127cc82f7b59b37034cf279e34365668be2ec5de5db43067。

c95c5571仅22个Linux方法section属性，965相关检查、SDK原硬化/预算、原signals12+3+3一次通过。
实际ELFdc2dddfe0a627946506e7fd6d5dcf86c0803da1f40987a96d5130f6b2ba51b70仍2145051B，
19个保留inputsections连续40708B，无gap/夹入。APK1168633B。不同泛型实例可能共方法section，
不称每section就是单函数。资格合并结果b7306546，不再启动原native240/owner32前置流程。

## 仓库与清理

主仓库main提交a3dfe43e只含两份原Fable文档和AGENTS.md简短必读/每轮自检要求。
按三个指定路径暂存，docs/prompts所有用户未提交文件保持，未push，未合并产品代码。
已移除12个完成clean工作树和6个废弃branch，12个HEAD保留archive tags；private与其他ignored
数据同卷原子移动至`/Users/USER/Developer/owrt-perf-evidence-20261016/<旧目录名>/`，原字节不改。
[唯一清理映射](dns/completed-worktrees-cleanup-20261016.json)提交59f2b886/3ab2695c。
活跃测量树、G交付和当前输入路径保留。

## CPUclock与A/A：完成，固定物理批次仍在运行

跨进程getcpuclockid/gettime成功，接口reported resolution1ns，但tight读最小观测正增量
25385ns、paced最小33232ns；100ms工作累计91.336ms而tick只8。阻塞100ms增60693ns。
fork child约91.57ms未计入父CPUclock；回收后旧PID/clock分别ESRCH/EINVAL。该接口可用来
分辨sub-tick累计CPU，不宣称ns精度。新CPUclock和helper tick使用相同身份/端点范围，
原resource tick另列；仅稳定单进程/单线程/无子CPU增长的UDP窗口判ns有效。

默认5+20窗的G/G四窗全有效，两对CPUclock差+3.2802782、+4.9424388µs/query，经验噪声
最大4.9424388µs（不是全环境上界）。同端点tick差2/3，原resource tick每query差4/6µs。
这说明新仪器消除了粗量化，却没有消除环境波动。后续候选按事前规则同时超过5µs和本批
A/A经验幅度，不据此宣称小于5µs的真实收益不存在。42窗固定批次已14:36:53UTC启动：
A/A4、三速率18、E/PGO10、G/c9510；原计划不随观察结果改变。

## 本机D1原型：尚未选入计时

独立9e child4de2d573复用旧的按需metrics，aeba3093增加保守的plain fresh UDP入口；
无EDNS/异常flags/日志/订阅等情形回落。复用现有local所有权检查、单次LRU、TTL/回答writer、
upstream poll与send/recycle尾部，没有新缓存状态或原地写包。第一次实现漏掉deferred准入后的
resend清除；6dcdd5d3复现了多发47字节包，修后同test无包且pending/counters不变。
修复在未选原型中完成，计时中c95/G/PGO全部未改。

736lib+23bin本机测试通过（8ignored），musl alltargets通过。原hosts测试另暴露缺失哈希桶
前提：lease名还须避开x.test，05bfb529单独修cfg(test)夹具，保留原finite/immortal行为断言。
3拓扑×2lease定向证明及原失败日志留存。7组新增差分/回归覆盖bytes/TTL/LRU和无副作用回落。

局部ELF5024648→5028680B；process_udp4660→5344B，own frame1056→1136B，另有624B
快速wrapper和704B选择closure。它跳过重复通用入口，但增大owner并增加miss回落前检查；
没有CPU收益结论。完整本机raw与local-result在`owrt-perf-plain-cached-entry-20261016/private/`。
是否送测等本批物理结果，不从静态大小决定、不混进当前候选。

C匹配骨架诊断补丁/原SDK构建命令亦已在correctness/private/c-receive-diagnostic准备，
未构建/运行；保留原C recvmsg/send_from/loop，仅回G receive相同固定应答。只有本批仍有
未解循环差额才选择。它测循环/内核/用户态残余，不命名为不可压缩内核地板。

C/G速率扫描、E/PGO和G/c95物理结果仍待完成；不把准备或本机测试通过当性能完成。
