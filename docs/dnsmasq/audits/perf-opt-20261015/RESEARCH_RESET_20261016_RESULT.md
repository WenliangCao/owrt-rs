# 研究方向调整：本批统一结果

**PGO对同源E的独立九对真机UDP命中CPU全部更快，配对中位节省47.90µs（31.78%）；
决定继续与已接受G做118窗完整矩阵，并完成实际PGO产物的44族正确性门。**
九对通过不代替完整资格；G仍是完整验收通过的交付。对应唯一计划/新测量规则是
[FROZEN_RESEARCH_SUPPLEMENT_20261016.md](FROZEN_RESEARCH_SUPPLEMENT_20261016.md)，提交d81f3f1d。
Oracle低速C/G用户周期两侧中位数之差约3960，三次配对差的中位数为3550.5712；
本报告对照决策采用配对结果。

## 我对外部诊断的判断

同意首要假设应转向低速率时的代码/数据与分支成本，同意旧>8tick门限限制5µs级探索，
同意允许小改动组合实测、取消热native/饱和sendlag作为A53前置门，并大幅缩减重复文档。
不同意把低/高载80%的周期差全部认作缓存停顿：批处理、轮询、调度、生成器上限都改变。
也不同意用未显著的2–4tick宣称真实收益、把refill当独立足迹行数、或把Rust骨架当内核地板。
报告“未组合”不适用于最新9e：它已经包含6ab、inline-address、owner outlines、warm writer等，
实测G118→9e114µs仍未分辨。sendlag一直完整记录，但G在该诊断恶化时仍已验收晋级；
本批更明确规定它是生成器诊断，不能独自否决产品。c95已完成实际SDK聚拢，无需新linker脚本。

当前模型：PGO已在A53产生大幅收益，Oracle同源实验同时减少指令、refill和分支事件，
支持编译后热路径效率是重要变量。但速率扫描中G/C相对差几乎不变，不能把绝对差收窄
当作缓存独占归因；PGO也不只改布局。下一步先用完整G/PGO矩阵判交付，再直接量C/PGO
剩余差距，按剩余成本选方向；不先叠加G的强制outline或把历史中位数相减当预算。

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

## 已有PGO与c95：产物身份与运行资格

现有PGO0910b49和同源E8b8082b9一次最小启动/A+AAAA/live身份/RELRO/NX/noWX/正常TERM均PASS，
无强制清理或残留。未重训/重建。原ELF超预算88419B、APK超93382B的历史结果保留。用户后来授权的新PGO预算见下节；
完整候选资格仍未全部完成。
最小smoke raw本机`owrt-perf-pgo-sdk-smoke-20261016/private/perf-opt-20261015/pgo-existing-runtime-20261016/raw/runtime/result.json`，
SHA4a35a3a0dfcf71f8127cc82f7b59b37034cf279e34365668be2ec5de5db43067。

c95c5571仅22个Linux方法section属性，965相关检查、SDK原硬化/预算、原signals12+3+3一次通过。
实际ELFdc2dddfe0a627946506e7fd6d5dcf86c0803da1f40987a96d5130f6b2ba51b70仍2145051B，
19个保留inputsections连续40708B，无gap/夹入。APK1168633B。不同泛型实例可能共方法section，
不称每section就是单函数。资格合并结果b7306546，不再启动原native240/owner32前置流程。

## 仓库与清理

主仓库main提交a3dfe43e只含两份原Fable文档和AGENTS.md简短必读/每轮自检要求。
按三个指定路径暂存，docs/prompts所有用户未提交文件保持，未push，未合并产品代码。
已移除88个完成clean工作树和37个废弃branch，88个HEAD保留archive tags；private与其他ignored
数据同卷原子移动至`/Users/USER/Developer/owrt-perf-evidence-20261016/<旧目录名>/`，原字节不改。
[唯一清理映射](dns/completed-worktrees-cleanup-20261016.json)提交59f2b886/3ab2695c/a54bca6f；
当前保留26树（18个指定active/control/交付目录，8个仍被引用或完成状态未充分确认）。
活跃测量树、G交付和当前输入路径保留。

## CPUclock与A/A：完成

跨进程getcpuclockid/gettime成功，接口reported resolution1ns，但tight读最小观测正增量
25385ns、paced最小33232ns；100ms工作累计91.336ms而tick只8。阻塞100ms增60693ns。
fork child约91.57ms未计入父CPUclock；回收后旧PID/clock分别ESRCH/EINVAL。该接口可用来
分辨sub-tick累计CPU，不宣称ns精度。新CPUclock和helper tick使用相同身份/端点范围，
原resource tick另列；仅稳定单进程/单线程/无子CPU增长的UDP窗口判ns有效。

默认5+20窗的G/G四窗全有效，两对CPUclock差+3.2802782、+4.9424388µs/query，经验噪声
最大4.9424388µs（不是全环境上界）。同端点tick差2/3，原resource tick每query差4/6µs。
这说明新仪器消除了粗量化，却没有消除环境波动。后续候选按事前规则同时超过5µs和本批
A/A经验幅度，不据此宣称小于5µs的真实收益不存在。42窗固定批次于14:36:53UTC启动：
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

## 真机速率扫描：18/18有效

| qps | C每query CPU，三次µs | G每query CPU，三次µs | 配对G−C中位 [范围] µs |
| --- | --- | --- | --- |
| 200 | 82.614,81.055,86.265 | 116.678,115.331,113.851 | 34.064 [27.586,34.275] |
| 1000 | 59.876,53.459,51.833 | 76.184,76.411,86.156 | 22.952 [16.308,34.323] |
| 2000 | 46.706,47.666,49.533 | 76.860,67.955,65.278 | 20.289 [15.745,30.154] |

2000相对200的配对差中位收窄40.44%，达到事前≥三分之一预测。两侧成本均显著随速率
下降，支持“稀疏请求成本重要”的模型；同时中/高率范围较宽，不能把三次当确认区间。
关键反证是配对G/C相对开销中位+41.233%/+42.935%/+42.564%几乎不变。绝对差虽符合
预写预测，却没有显示Rust特有劣势的比例下降；两侧可能受公共调度/批处理/频率等同比影响。
频率本身未测，不能把它当已知原因。此结果降低“绝对差收窄足以确认冷缓存主因”的证据力；
缓存局部性、分支与调度仍须靠布局干预和匹配骨架来区分，不把关联独占归因cache。
高率仍剩约20µs，保守D1入口与匹配循环参照仍是可区分的后续方向。无无效窗/补测/ns缺失，
固定批次继续完成原E/PGO和G/c95五对，结果如下。


## 现有E/PGO真机五对：强CPU信号

| 配对 | E CPUclock µs/query | PGO CPUclock µs/query | PGO−E µs |
| --- | ---: | ---: | ---: |
| 1 | 138.6491882 | 93.3955972 | −45.2535910 |
| 2 | 145.6782964 | 95.0929890 | −50.5853074 |
| 3 | 139.3235804 | 111.4332728 | −27.8903076 |
| 4 | 138.2615110 | 94.2689968 | −43.9925142 |
| 5 | 144.3706860 | 95.0436884 | −49.3269976 |

配对中位−45.253591µs，5/5，超过事前5µs和A/A4.9424µs条件。原tick中位140→94µs，
−32.857%，W21.277%，差23ticks，也过旧门；不是仅依赖新仪器的微弱信号。
p50每对少0.0327–0.0518ms；p95配对差−0.070787/−0.365936/+0.149345/+0.031238/−0.126801ms。
第3窗CPU111.43及p95 0.54275保留，不称尾延迟全面改善，也不把五对当95%确认。

在源和输入匹配的前提下，这证明现有profile驱动的编译变换有大幅实际潜力；PGO同时改变
内联、分支选择、代码生成与布局，尚不能分解为纯地址排列或缓存缺失因果。42窗已安全闭合，
原E/PGO依d81f完成九对5+45确认；原预算失败不改写，新PGO限额另行记录。

事前追加ff5e959f只选择一个体积变量：同E、同profile、opt-level2。原因是已有O2 actualSDK
缩ELF98304B/ APK40449B，量级比HCS更有依据，但APK很可能仍超，不能承诺成功。LLVM22
[SizeOpts.cpp](https://github.com/llvm/llvm-project/blob/release/22.x/llvm/lib/Transforms/Utils/SizeOpts.cpp)
的pgso默认true；actualprofile99%集合2336未达large>12500，关闭lwss限制确非空操作，但会
扩大到中温/非热点代码，且目前没有实际尺寸证据，因此本轮不与O2并试或叠加。若O2尺寸或
收益不符合目标，先读实际结果再改模型，不做参数遍历。O2结果见下节，当前计时产物不改。正式资格/完整矩阵/可发布状态尚未达成。


## 固定42窗闭合、c95小收益与后续执行

42/42有效，所有ns列有效，无补测/新增DNS错误；1890raw files、1762guard、118external
检查完整保留。最低MemAvailable74464KiB，结束80020KiB；E/F精确恢复，production未改变。
原结果`private/perf-opt-20261015/research-reset-20261016/windows/result.json` SHA
`b511bf8703c2184794f7342d0f18e57521d8fa2b59cbf9b97e65efd1a56ea868`。

G/c95五对CPUclock差−15.3494352/−7.8849252/−12.7045032/−8.2526460/−7.7322480µs，
中位−8.252646、5/5，达到新筛选门。原tick中位116→106只5ticks仍未分辨，说明旧门确会
挡住值得后续确认的小收益。p50五对改善，p95差−.035470/+.001386/−.143728/−.026930/+.015080ms。
c95保留作后续组合方向，没有已接受或叠加PGO收益的声明。

原E/原PGO九对确认已完成，200qps/5+45+1、各窗实际CPU N10000/latency N9000，artifact不变。
18/18有效，无补测，CPU配对差（µs）：
−49.378193/−51.947714/−46.606181/−44.658128/−47.659429/−56.843360/−46.403493/−49.254658/−47.904381。
中位−47.904381，配对百分比中位−31.777%；[d(2),d(8)]=[−51.947714,−46.403493]，
三个连续block中位−49.378193/−47.659429/−47.904381，均超过5µs和A/A4.942439µs。
E/PGO两侧中位150.374222/101.872656µs，全范围140.621960–150.838585/91.243768–105.857242。
九对p50、p95均改善；p95配对差−0.183892至−0.039010ms。原五对中两次p95反向仍保留，
不把本次全同向解释为所有负载尾延迟保证。旧tick诊断150→102µs、9/9、W14.706%亦通过。
不声称配对独立性已经证明，故次序区间只报告数值，不自动赋予96.09%覆盖率。
原raw `private/perf-opt-20261015/research-reset-20261016/confirmation-e-pgo/result.json` SHA
`739ecea262d3061f7e3832d7dae02a092fe2e464f8d18fd4c934fc529c617974`；810原始文件、1165健康样本保留，
E/F测试槽和生产身份恢复，结束MemAvailable81356KiB。

条件完整矩阵3d4a91e2因此进入执行：直接G/PGO的11场景118窗（hit9对，其余10scene各5对），
不另叠重复18+110漏斗。
只有3UDP加入有效CPUclock，fork TCP和DHCP/lifecycle保留原口径；33primary与全resources保持。
Oracle原44/67并行，本次actualPGO F10 13/704、protocol368pairs/366exact、TCP13/50
已经通过，仅原C差异/预期timeout保留；完整44结果待完成，不继承旧machine-code PASS。

## 同源E/PGO的Oracle归因诊断：完成

6/6窗、42counter均无复用，三对200qps、每窗实际N5000。配对百分比中位及三次全范围：

| 用户态事件 | PGO相对E中位 | 三次范围 |
| --- | ---: | ---: |
| 指令 | −24.641% | −24.643%至−24.638% |
| 周期 | −48.350% | −48.936%至−44.987% |
| L1I refill | −59.881% | −60.579%至−59.431% |
| L1D refill | −17.901% | −22.631%至−15.869% |
| ITLB refill | −51.046% | −51.643%至−50.591% |
| DTLB refill | −2.732% | −4.492%至+4.077% |
| 分支预测事件 | −66.004% | −66.158%至−65.783% |

IPC两侧中位0.44465→0.62461，周期配对中位少10494.0218/query。周期降幅大于指令降幅，
并伴随I/D refill和分支事件下降，符合事前预测；DTLB不是一致下降。不能把这些N1关联
直接量化为A53的停顿因果。原summary本机`owrt-perf-cg-pmu-20261016/private/e-pgo-pmu-20261016/summary.json`，
SHA `9e4728b5de7350fc2ee5d394c7e9e08d9a31951b55e9885e3e60ace1f16fc2cb`，267个raw哈希保留。

同一actual SDK产物的静态检查还有反例：PGO的run_inner30368→193124B、process_udp4484→16300B，
local回答器14032→28204B，owner frame也更大，实际却更快且refill更少。因此整个函数字节数
不是每次执行触碰的热足迹；不能仅因G的outline缩小函数就预期与PGO相加有利。

## 新PGO预算与O2失败

用户授权后，依据本批live mtd/UBI/df，d29c289a固定PGO ELF2500000B、APK1400000B。
当前overlay available56504320B=53.887MiB；rootfs74LEB、data525LEB，共599个126976B LEB；
其余25个PEB保留。UBI未分配0不意味着UBIFS满，也不能直接在线扩rootfs。未来整镜像
rootfs上限82LEB=10412032B，仅增8LEB；data至少517LEB且保留配置后必须有≥16MiB实际用户
可用空间。APK压缩大小不能推算squashfs；kernel34MiB空余不借用。预算理由和raw SHA详见协议。
现有PGO符合新组件数字；未安装、扩容或刷机，未声称新完整固件已通过集成。

单次同E/profile的O2产物为ELF2063131B、APK1142122B，虽然都符合旧尺寸，profile校验失败：
2817条missing-profile warnings，crate标识随opt-level改变，原profile名字无法匹配。
实际-Copt-level2与71adfc95profile身份和静态保护均核对；零hash-mismatch警告不能抵消
missing profile。停止该方向，没有把它当有效PGO，也未通过改profile名字/重训/重建掩盖失败。
原日志/产物在pgo-sdk-smoke树`private/perf-opt-20261015/pgo-opt2-20261016/`，sourceefcc85b2。

用户更正G+PGO仅可选。当前优先完整确认/验收现有E+PGO；G新训练只保留可行性，不启动。
如将来选择，必须锁同source/opt3/Cargo/CGU/LTO/buildslot并生成新profile，不能套E的profile。
旧E训练和评估后缀不同，但seed原为同0x293001，不能宣称完全seed隔离；将来新训练可事前
另定种子。不存在把G与PGO历史收益相加的决定。
