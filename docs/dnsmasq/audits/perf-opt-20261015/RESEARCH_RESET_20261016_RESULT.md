# 研究方向调整：本批统一结果

**I（G+新PGO）已接受：H/I UDP命中CPU中位97.52→85.16µs，配对节省14.54µs，9/9；完整118窗全部有效，33主指标3改善/0可辨退化/30未分辨。**
实际44族/67任务与shipping边界通过，一次独立复核完成，见[candidate-i-acceptance.json](candidate-i-acceptance.json)。
当前唯一计划为[FROZEN_RESEARCH_SUPPLEMENT_20261016.md](FROZEN_RESEARCH_SUPPLEMENT_20261016.md)。
直接C/I16已完成：低率配对I−C为−0.97µs，未见可辨正残余，不宣称等价。D1/D2研究继续；无固件集成或部署。
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

当前模型：PGO在A53已有明确收益，I在原简化命中场景与精确C的直接低率配对差为−0.97µs，
没有可辨正残余。不能因此推断真实配置也零开销：七条公开local/RFC6761规则让旧路径在本机
每query产生23次分配，修正后零；实际J PGO的Oracle指令下降约61%、周期约40%，同时IPC
下降、I-TLB refill上升，说明单独追求IPC或任何一个缓存指标都不足以判断总成本。
下一轮裁决J组合在公开配置的A53 CPU/时延是否真的改善，并以原完整矩阵约束其他场景；
不相加E/G/H/I的历史收益，不从本机分配次数或N1计数直接换算A53微秒。

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
已经通过，仅原C差异/预期timeout保留；实际44族/67任务已全部通过，无重跑或新增未分类失败，不继承旧machine-code PASS。
原runner family result SHA `cb7dcb2cacf70a80eeea62c13efe5e025e1a649a1674e40de455136203c36faf`。

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


## G/原E+PGO完整物理矩阵：118窗通过

118/118有效，没有失败窗或补测。33项原primary有13项可分辨改善、0项可分辨退化、20项未分辨。
原同源E对照量化PGO编译的作用；这里G→E+PGO是整体交付方案比较，不是PGO/G源码收益相加。
七个流量场景的CPU全部达到原判据。UDP-hit同时满足新九对规则：ns两侧中位
115.3187851→94.6739073µs/query，配对差中位−21.1329182，[d2,d8]=[−29.3940802,−16.3166440]，
三个block中位−21.2760389/−20.7657938/−25.0887021，9/9改善且全部超过A/A幅度。
38个UDP窗口ns全部有效；hit每窗N10000，miss/mixed各N5000。后两者配对ns中位分别
−85.6903832/−30.005817µs，只描述原五对，不加确认区间。

以下保留全部33项原指标（CPU为原计量，UDP ns另列；U表示未分辨，不等于没有差别）：

| 场景 | 指标 | G中位 | PGO中位 | 变化 | W | 同方向对数 | 判定 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| udp-hit | p50 ms | 0.170350 | 0.154807 | -9.124% | 12.330% | 9/9 | U |
| udp-hit | p95 ms | 0.267605 | 0.266681 | -0.345% | 57.648% | 7/9 | U |
| udp-hit | CPU µs/op | 116.000000 | 94.000000 | -18.966% | 14.655% | 9/9 | 改善 |
| udp-miss | p50 ms | 1.626789 | 1.566466 | -3.708% | 1.334% | 5/5 | 改善 |
| udp-miss | p95 ms | 2.048047 | 1.836994 | -10.305% | 48.557% | 4/5 | U |
| udp-miss | CPU µs/op | 450.000000 | 362.000000 | -19.556% | 2.762% | 5/5 | 改善 |
| udp-mixed | p50 ms | 0.179506 | 0.167657 | -6.601% | 13.330% | 5/5 | U |
| udp-mixed | p95 ms | 1.708732 | 1.651333 | -3.359% | 32.648% | 3/5 | U |
| udp-mixed | CPU µs/op | 182.000000 | 152.000000 | -16.484% | 9.211% | 5/5 | 改善 |
| tcp-hit | p50 ms | 0.204204 | 0.182738 | -10.512% | 7.498% | 5/5 | 改善 |
| tcp-hit | p95 ms | 0.319233 | 0.377094 | +18.125% | 65.389% | 3/5 | U |
| tcp-hit | CPU µs/op | 148.000000 | 118.000000 | -20.270% | 8.475% | 5/5 | 改善 |
| tcp-miss | p50 ms | 1.595088 | 1.543614 | -3.227% | 1.452% | 5/5 | 改善 |
| tcp-miss | p95 ms | 2.240171 | 1.824530 | -18.554% | 47.598% | 3/5 | U |
| tcp-miss | CPU µs/op | 396.000000 | 334.000000 | -15.657% | 6.061% | 5/5 | 改善 |
| dhcp-home6 | p50 ms | 0.397407 | 0.349010 | -12.178% | 2.904% | 5/5 | 改善 |
| dhcp-home6 | p95 ms | 0.602611 | 0.578067 | -4.073% | 307.360% | 3/5 | U |
| dhcp-home6 | CPU µs/op | 412.000000 | 352.000000 | -14.563% | 4.545% | 5/5 | 改善 |
| dhcp | p50 ms | 2.583564 | 2.188390 | -15.296% | 6.665% | 5/5 | 改善 |
| dhcp | p95 ms | 3.142780 | 2.932266 | -6.698% | 16.565% | 5/5 | U |
| dhcp | CPU µs/op | 2568.000000 | 2172.000000 | -15.421% | 2.804% | 5/5 | 改善 |
| startup-small | p50 ms | 4.518891 | 4.213892 | -6.749% | 3.530% | 5/5 | U |
| startup-small | p95 ms | 4.923607 | 4.594601 | -6.682% | 30.071% | 5/5 | U |
| startup-small | CPU µs/op | 5253.550000 | 4976.350000 | -5.276% | 4.845% | 5/5 | U |
| config-small | p50 ms | 5.890693 | 5.444120 | -7.581% | 2.497% | 5/5 | U |
| config-small | p95 ms | 6.945262 | 6.411745 | -7.682% | 633.050% | 5/5 | U |
| config-small | CPU µs/op | 5778.500000 | 5242.250000 | -9.280% | 5.860% | 5/5 | U |
| hup-small | p50 ms | 1.006711 | 0.938850 | -6.741% | 1.338% | 5/5 | U |
| hup-small | p95 ms | 1.120047 | 1.056185 | -5.702% | 4385.029% | 3/5 | U |
| hup-small | CPU µs/op | 1230.750000 | 1148.050000 | -6.719% | 8.190% | 5/5 | U |
| hup-large | p50 ms | 14.694357 | 13.466742 | -8.354% | 4.903% | 5/5 | 改善 |
| hup-large | p95 ms | 15.809557 | 14.245014 | -9.896% | 62.712% | 5/5 | U |
| hup-large | CPU µs/op | 16051.150000 | 14605.800000 | -9.005% | 4.136% | 5/5 | U |

TCP-hit p95中位上升18.125%，3/5对上升、W65.389%，未分辨；UDP-hit p95两对上升、7对下降。
因此不能称尾延迟全面改善。生命周期保留20次原RUSAGE_CHILDREN范围和1ms时延门，不能因
CPU以微秒显示就取消原>8tick条件；只有hup-large p50额外达到可分辨改善。

| 场景 | RSS中位 KiB G→PGO | Anon峰值中位 KiB | Anon完整范围 G / PGO | FD峰值完整范围 G / PGO |
| --- | ---: | ---: | --- | --- |
| udp-hit | 2396→2300 | 516→504 | 516–520 / 500–532 | 12–12 / 12–12 |
| udp-miss | 2518→2422 | 684→660 | 664–692 / 652–668 | 12–13 / 13–15 |
| udp-mixed | 2484→2310 | 612→596 | 608–612 / 592–600 | 12–12 / 12–12 |
| tcp-hit | 2572→2560 | 716→700 | 712–728 / 700–700 | 20–20 / 20–20 |
| tcp-miss | 3566→3550 | 2140→2104 | 2076–2164 / 2076–2136 | 28–28 / 28–28 |
| dhcp-home6 | 2300→2000 | 360→344 | 356–360 / 340–344 | 18–18 / 18–18 |
| dhcp | 2776→2480 | 856→824 | 820–876 / 804–852 | 18–18 / 18–18 |
| startup-small | 2284→1958 | 340→332 | 340–340 / 328–332 | 18–18 / 18–18 |
| config-small | 2288→1960 | 340→332 | 340–340 / 328–332 | 18–18 / 18–18 |
| hup-small | 2284→2008 | 356→344 | 352–356 / 340–348 | 18–18 / 18–18 |
| hup-large | 3076→2916 | 1168→1160 | 1168–1172 / 1160–1164 | 18–18 / 18–18 |

11场景RSS中位均下降12–328KiB，Anon峰值中位下降8–36KiB；RSS峰值中位变化−316至+28KiB，
TCP-miss为3952→3980KiB。FD中位全部相同，但UDP-miss峰值范围不同：PGO第三窗一次15，
下一样本回12，五窗before/after均12；保留该瞬时增加，不称全范围一致或据此断言泄漏。
七个流量场景所观测的线程/进程峰值均1；采样不能排除未捕获短生命周期进程。
生命周期资源仍仅ready快照，不是瞬时峰值。RSS/Anon/Shmem不等于USS或唯一缓存足迹。
所有RSS/File/Anon/Shmem/tree/FD/thread/process范围及每窗DORA记录均留在下述结果JSON。

DORA在原warmup，测量阶段为renew-only；不混合各窗生成合并分位数。home6初始cohort极值
G1.750820–2.304495ms、PGO1.597166–3.074532ms，后者最大值上升保留；150规模对应
G1.290705–13.812504ms、PGO1.171290–8.409087ms。原home6每窗只有6条初始DORA样本。

最终派生结果`private/perf-opt-20261015/research-reset-20261016/g-pgo-full118-result.json`，SHA
`f6ee48ea3cc33ea56bef35e0b05faf79606c30c2e4c3e9c642e5fc6e61e8de99`；118份archive/3850文件，
11个guard段4611合格/4615总样本、306次外网检查均保留。最低MemAvailable67564KiB，
仍满足原64MiB门。结束E/F测试槽恢复，production ELF8472…及PID/start3086/2115未变，
结束可用内存77100KiB。完整Oracle性能矩阵没有重新跑；依据3d4补充，当前资格以实际产物
44/67、原边界、完整A53矩阵与一次候选独立复核为准，Oracle性能仅作分离的归因诊断。

行为修复单列：b1136023过期CNAME修复共同存在于E/G/PGO，本轮无新行为修复，不是PGO
对E或对G增益的变化因素；它相对v0.2.0的独立CPU成本未在本轮量化。UBus350→346及
负载/计数工具修补不改变本轮产品ELF。旧C差异、原预算失败和所有不利数据保持。


H独立复核闭合：3850raw/118窗、33指标、全部恢复/健康及本机PGO关键输入匹配。
复核进度文件SHA `1235abbf49cbfda53eeb4bf6fe2d04969f87a44901c25ab17637e58e668c09b9`，
所审产物manifest为7241d412…；H接受为新的软件性能候选，G保留回退及对照身份。
已本地保留原merged profile929880B、APK1293382B和50个raw profile的原清单；50份raw内容
仍留原Oracle目录，未宣称全部本地复制。完整44归档189423472B已下载核SHA39ecec02…。
具体产物、构建入口、预算、范围限制和复现路径集中在H接受清单，不生成重复收据。

## 精确C/H残余：低载仍差10.40µs，选择一次G+PGO组合

固定16/16窗全部有效，无补测，CPUclock均有效。200qps五对CPU N10000，C/H两侧中位
77.7398606/88.1426227µs，配对H−C为13.881748/6.6887149/11.1118182/10.0199273/10.4027621，
中位+10.4027621µs，配对百分比中位+13.3815%，五对都慢；旧tick78→88亦可分辨。
2000qps三对N50000，C/H中位49.84768054/53.02039514µs；配对差
5.10658626/3.74100608/3.1727146，中位+3.74100608µs（+7.9554%），绝对残余缩64.04%。
不为三对或五对赋予确认区间，也不把其结果与前几轮C/G中位数相减推“缩小百分比”。
低率p50中位0.130802→0.142113ms（+8.647%、W7.797%、5/5），旧规则可分辨更慢；
p95中位0.269529→0.288149ms（+6.908%、W38.531%）未分辨。低率p95配对差
−.004848/−.043627/+.013003/+.058399/+.018620ms，保留混合方向。
高率p95差−.080944/+.005154/−.056937ms；不能把更低CPU等同于每项时延都优于C。

原结果`private/perf-opt-20261015/research-reset-20261016/residual-c-pgo16/result.json` SHA
`82159dd34e633ff0249e5b37272581ea7ee3d27b64f9dd5b02adab3336b62eda`；16archive/720文件、
893guard样本/60外网检查均保留，最低MemAvailable69776KiB。E/F恢复、生产身份不变。

Oracle原C/H同窗u/k六窗也全部有效，实际N5000、24counter无复用。配对H−C周期/query：

| 配对 | 用户态 | 内核态 | 同窗合计 |
| --- | ---: | ---: | ---: |
| 1 | −2910.4854 | −2436.0280 | −5346.5134 |
| 2 | −2901.2320 | −3676.1914 | −6577.4234 |
| 3 | −3401.2910 | +11149.0304 | +7747.7394 |

用户态三对均更省，但内核/总周期没有稳定方向；内核指令差三对+2197.0080/+2100.0886/
+10497.4780。第三对的不利变动保留，不能认定A53剩余差就是内核成本。summary SHA
`63edefe80ae703d22d2446ad3a89a2970129e3ded41d4fed9a4545dfb9cd7854`，270raw文件；
本机已于恢复gap下载核验，路径`owrt-perf-cg-pmu-20261016/private/c-pgo-mode-pmu-20261016/summary.json`。

低载残余符合事前5–25µs预测且超过5µs目标，因此ff878699选择一次G+PGO组合实验。
理由是G原有分配消除、fresh回答和静态socket改动可能补H，强制outline又可能抵消PGO，
预期净效果0–10µs，不能预设有益。固定新G专属profile、训练seed0x20261016，其余原11场景、
source/opt3/LTO/CGU1/toolchain不改；直接H/H四窗校准加H/G+PGO十窗screen，达到5µs/新AA/
4of5才进行44和完整118。H仍为已接受交付，不混入新产物、不自动把训练完成当晋级。


## 单次G+PGO构建与14窗screen：达到完整验收条件

G185源码不变，原11场景单次训练全有效，50个正常退出profiles，训练seed0x20261016与评估
0x293001不同；训练/评估后缀仍分别pgo.test/m6a.test。新profile
`f36b6e61a105225ffbc2aa1592b168a494d1e72533df944a2acabab62c2f9c60`，931832B，未复用E71ad。
原opt3/fatLTO/CGU1/工具链不变；实际H/I effective flags仅profile路径不同。
use ELF `6ccff2e9fa87ba69f50a6e583a26f48b58bcfec2f22fd199774ad2c2cfb49182`，2288419B；
APK `a6fd7a67f020cd744c6d7b18a96f129914eb2d76e3de5033c3f73c1b119208d5`，1295290B。
新caps、静态硬化、零missing/mismatch、实际G/G+PGO最小A/AAAA/保护/正常退出均通过。
初次stdin launcher类型错误发生在训练启动前，原stdout/stderr保留；没有重复build或训练。
546文件及全部50rawprofiles一次下载核验；唯一private构建结果SHA
`4e1f0107eb9256657b49d58d62b8821dc0c00c64298b1c500b5918c120457102`，在
`owrt-perf-pgo-sdk-smoke-20261016/private/perf-opt-20261015/g-pgo-20261016/result-summary.json`。

14/14窗有效，无补测/错误/超时，630raw文件保留并已恢复。新H/H两对差−7.5815366/+6.9059034µs，
经验噪声7.5815366，较上一批大，不能拿旧4.9424降低本批门。I−H五对
−8.0990642/−12.8332084/+0.6557062/−10.2845372/−11.1690840µs，中位−10.2845372，4/5改善，
超过5µs和新AA。旧tick92→82只5ticks，仍未分辨，说明新计量允许有依据的小收益继续确认。
不利数据：p95中位0.260449→0.308384ms（+18.405%、4/5升、W119.287%，未分辨），第三对
p95多0.416334ms；p50 0.149575→0.139034（−7.047%、W8.965%）亦未分辨。RSS中位2324→2220KiB、
Anon504→504，FD12/线程1/进程1不变。不能在screen阶段宣称尾延迟或完整资格已通过。
原结果`private/perf-opt-20261015/research-reset-20261016/g-pgo-screen14/result.json` SHA
`c59e1190453dccac1c4a048abf7b86edd1f0e12a2dcc704a64e1641727da4d21`。

决定按ff878699预写分支，直接执行actualI44/67+shipping边界和H/I完整118窗，不加独立18窗。
三个九对block必须各自超过本批AA7.5815366；H仍为接受候选，I暂未晋级。
H/I源码与新profile均变化，所以这是整体组合效果；不会将历史E/G和E/H收益相加。


## D1重新落在G源码上的原地入口：本机完成，尚未实测

主代理独立树`owrt-perf-d1-inplace-20261016`从精确G185开始，产品提交7081d3dd/f769dcd0，
当前4c0dbc59另含单独cfg(test)夹具修正；没有继承9e/6ab的其他优化。入口在原ACL/admission
通过后、仅同步持有receive buffer的路径使用。普通无EDNS单IN A/AAAA新鲜命中原地保留问题
并写入header/c00c/RR/TTL；None不改包、LRU或local语义状态，容量不足/本地所有权/到期租约
原路回退。保留成功后的resend失效、query ID、local_answered、零等待upstream poll，以及
先当前回答、再上游完成回答的顺序；deferred路径继续原实现。未改变EAGAIN行为。

730lib+25bin本机全部通过（8ignored），aarch64-musl all-targets检查通过；未声称Linux专项
实际运行。新增差分覆盖bytes/TTL/LRU/过期/本地优先级/长名/容量边界/回退不改包，真实UDP
owner测试覆盖原地buffer、计数、queued upstream完成顺序和功能开关回退。
新长名夹具最初因cache4的C long-name quota失败，c0b3257d单独将该夹具容量提高到10，
不改产品上限。旧hosts夹具修正4c0dbc59是已有05bfb529的移植，不混作性能优化。

独立计数树`owrt-perf-d1-count-20261016`复用原whole-owner allocator（4d32c412/ce4ff745），
同进程一次测原路径和新路径，各20warm后2000次cache hit；两个scope都是alloc/dealloc/
realloc/requested/released全部0。计数含原step_udp收取/准入/处理/发送，不含client/harness；
是本机计数，不是未插桩A53计时。初次--exact漏模块名跑0test保留，正式全名仅运行一次。
日志分别在两树private/d1-local与private/d1-count；插桩树不作为产品候选或计时输入。


D1最终首测源更新为ba40be3a（在f769dcd0之后单独收窄plain名字解析）：先验证无压缩名称，
再向现有scratch复制一次；不再进入通用指针walker。最终731lib+25bin PASS/8ignored，
Linux全目标检查PASS。独立计数子树4f3b5ab7在同一正式全名测试中再测原/新各2000，五项
分配计数仍全0。仅本机非PGO/rust-lld检查得到owner848B、plain解析240B、回答主体1816B，
不含传递callee，不等于动态热足迹或SDK/PGO性能，不能用它提前晋级。

D2最终准备源2f7fe9aa：c9755eaa按需metrics、0fc4ed11单就绪UDP分派、cf651814允许未来
定时器和空闲DHCP，最后仅移植既有cfg(test)hosts修正。wait保存本次最早deadline，step前
及UDP批后检查到期；原UBus→DHCP每轮重绑前缀保留，资格不增加poll/recv。helper/TFTP/
neighbors和其他待办仍原路；16包预算/信号/上游处理不改。完整本机722lib+29bin PASS，
8ignored；Linux新增路径仅编译，尚未实际运行。D1+D2独立组合57087ce1另有732lib+31bin/
Linux检查PASS，只作准备。D1快路已经跳过metrics，所以两者该项重叠，收益不能相加。

下一步a0b59eb4固定D1先行：I接受后新PGO训练，Linux新增plain_*先实际隔离执行；14窗
全部5+95+1，CPU N20000、同长度A/A。新watchdog22385595修正已声明长窗不能在100秒内
完成的工具问题，附复现；62d51439准备固定新14。当前I矩阵私有工具未改。

I实际44/67及shipping边界已完成：合并结果SHA
`e06b41753d9bb54339857267fd0e494a05e8cb9a3b2b5de37597621793d74337`。唯一失败来自原
m5_rr_filter夹具仅选UDP空闲端口，精确C启动时TCP地址被占用。de58466d只改双协议端口
选择，c5e21447保存确定性复现（旧函数失败、新函数通过）；未改C期望/比较器/I源码，
只重跑该门，其他成功前缀复用、未执行族按原序列完成。原失败attempt和rr重跑全保留。
原raw归档201752610B、SHAcd4147d85d51b8fa32d015e633ebe0dcfaf0cf0c6081c86252cd06bf7847c8d3，
已在设备恢复gap下载，全83634个regular文件/681341272B逐hash核验。I最终接受见下。


## I完整验收与下一轮决定

H/I全部118/118有效、无补测，结果SHA76a3edf7fd493a81bcbe2158d8829b1e6ed9f81d45665fe6ecd1b85904436f97。
UDP命中CPUclock配对中位−14.5439082µs，d2/d8为[−17.4785219,−9.6761227]；三个block
−16.8571425/−9.6761227/−15.3597544µs，各超过本批AA7.5815366。旧tick97→86也过门。
另两改善为hit p50（.157962→.142650ms）与mixed p50（.162963→.147652ms）。
不利项保留：miss CPUclock配对+4.8978536µs，DHCP150 CPU2176→2204µs，HUP-large CPU+2.4827%；
均未分辨。home6 DORA最大2.284874→4.747485ms来自原warmup cohort，不与其他分位数合并。
RSS中位变动−92..+106KiB，Anon peak−16..+4KiB；FD中位相同但miss范围H13..13/I13..14。
11健康段4593/4596合格样本、306外网检查通过，最低MemAvailable66508KiB；恢复E/F，生产未变。
全部3850个设备raw文件及正确性归档已下载核验；原端口工具失败保留，仅相关门重跑。

决定接受I，H保留回退。当前模型：PGO和G组合继续改善，但不能把14.54µs从历史C/H10.40µs
残差直接相减；正在运行的C/I低高载直接配对才能回答。D1已在新I源基上准备，重复通用名字
处理降为一次plain扫描是待测机制，不是已证明收益；按a0b59eb4完成Linux专项、独立新训练
与95秒长窗14窗。D2保留为后继或组合，metrics收益与D1重叠；不重试D3。
行为修复b1136023在E/G/H/I共同存在，不贡献本轮变量差；独立对v0.2.0代价未测。工具修复不改计时ELF。


## D1覆盖边界：无关local规则不能让全局缓存快路失效

实际离线脱敏配置有local规则，而ba40的全局规则gate会长期回退；系统接口地址数量本身
不会触发local.interfaces gate，它只由interface-name规则构造。已见edns-packet-max和
DHCP authoritative也不是EDNS改写/DNS auth开关。真实请求OPT/flags与订阅者比例未知。
因此当前ba40的固定14只量裸fixture机制，尚不能宣称实际配置性能收益，不自动晋级完整门。

主代理已在独立树owrt-perf-d1-local-rules-20261016提交4cd1d7c6，按查询名匹配本地域规则，
无关规则保持原地cache回答；733lib+25bin PASS/8ignored，Linux全目标check PASS。
新回归测试在原ba40上复现不必要的fallback，修正后A/AAAA回答字节及LRU与general一致；
匹配规则、标签边界、大小写、两种wildcard、dotless、binary escape维持回退。实际Linux/SDK/PGO
及设备收益尚未验证。它与当前ba40构建分开，后继依据实际数据选D2组合，不加入计时中候选。


## 精确C/I残余与当前模型

16/16有效、无补测。200qps两侧CPUclock中位C82.3696533/I80.2226416µs，配对I−C
[−5.6197146,+1.2118855,+0.3018676,−3.9064041,−0.9725363]，中位−0.9725363；旧tick81→81。
2000qps两侧50.10755054/45.8517965µs，三对[+5.17380538,−11.1851873,−4.25575404]，
中位−4.25575404，方向不稳。低/高p50/p95均原门未分辨；不是显著更快或等价证明。
低率RSS中位C1244/I2300KiB、Anon228/504、FD11/12；高率RSS1216/2236，范围全保留。
原结果residual-c-i16/result.json SHA1390cce884d69720a5faca2ce4ece3fcd8d45ea0f67aad709fb567827051d1ff；
720文件核验、897guard/60外网检查通过，最低MemAvailable71708KiB，E/F恢复且生产未改。

决定暂不追加C收发骨架：当前简化命中fixture已无可辨正差距；用户追加D1/D2继续，但主问题
转为真实配置能否用到优化。root复用既有whole-owner计数，在同一公开local=/lan/配置各跑
20warm+2000稳定命中，原ba40 general与D1两侧都是10000次alloc/dealloc、236000B；即每查询
5次/118B，D1全fallback且多了一次plain扫描。独立4cd修正后general和D1两侧都0分配，
所以收益机制不只属于D1：它也恢复G已有fresh shortcut。旧“零分配”只适用于原简化配置。
这是本机非PGO插桩计数，不能折算成A53微秒或证明真实请求覆盖率。输入/输出在
owrt-perf-d1-count-20261016/private/d1-count/local-rule-{before,after}.log，源afd86e27→0bff6d89。
4cd经独立针对性审查无行为风险发现，f675e9e0另保存4128组旧/新后缀匹配对照。下一轮按真实
配置因素选择源码与配对，仍保持原正确性语料/基线/失败数据，不新增审计框架。


同一计数fixture进一步加入公开RFC6761六规则（加lan共七条），把query后缀移到.example避免
匹配.test：原路径每query23次alloc/dealloc、401B（2000次合计46000/802000B），D1旧入口
同样回退；覆盖修正后general/D1均零。本机debug及release两种编译的计数一致，均未用其
elapsed判断性能；日志rfc6761-{before,after}{,-release}.log保留在同一private/d1-count。
诊断源b796e88c；before仅将local.rs替回afd86e27对应blob，after恢复该提交的修正，测试后
工作树干净。此证据仍不是实际PGO机器码的分配计数或A53时间。

后继已分别准备：D1+规则+D2源b059fc43（735lib+31bin/8ignored/Linuxcheck通过），或无D1的
D2+规则源f56fdd49（724lib+29bin/8ignored/Linuxcheck通过）；5a077516预先固定按原D1五对
方向只选一个新profile，测公开规则条件。当前ba40新profile/use构建和actualLinux13项完成，
实际ELF b9e1eddbbabed9654fe708e5c9d1e9e27b78ccc0e0509bbac212a055c92bf5c2，2296611B；
APK1299617B，profile e638a583045e18a0ae2a9d501f7026cd81504d52615dcd472f08c229d4ac7e57，
934368B，原11场景单次50raw、零missing/mismatch、smoke/硬化/新caps通过。579文件已下载；
唯一构建结果SHAed50677ae50398be38d9fe63577c106c3c6c29ed03d7109dc6f3a1e23a08454f在
active PGO树private/perf-opt-20261015/d1-pgo-preparation-20261016/result-summary.json。


## D1固定长窗：5/5同向，保留组合而非改门

14/14有效，CPU N20000、latency N19000、steady upstream=0；I/D1 CPUclock中位
86.7900481→79.18431515µs，五对D1−I为[−6.77374285,−9.85964660,−7.60573295,
−7.75875960,−11.45069265]，配对中位改善7.75875960µs。新I/I两对−3.404347/+7.78929155，
所以严格screen未触发：不因只差0.030532µs就改门，也不把同向结果解释为无效。原tick
87→78.5µs有分辨率但W17.241%未分辨；p50−7.242%/W17.644%/5of5未分辨；p95−0.606%/
W35.883%/3of5且两对上升，均保留。95秒窗降低了tick量化，但本批A/A波动没有消失。
RSS中位2332→2300KiB，Anon峰值中位504→504（I范围504..504、D1 500..512）；FD12、
线程1、进程1一致。630raw/14归档、1645guard/110外网检查及恢复通过，最低MemAvailable
65680KiB仅高于原门144KiB。随后gap经本地/远端hash比对回收已完成ba40/H私有副本4585030B，
MemAvailable76408KiB；保留I/E/F和生产，不改64MiB门，不删原结果或本地可恢复产物。
原result SHA b5c8196a78a0bd075a5c3696259d1eb06f754966fc8f2d7db3c4b9c9a323d357，
summary SHA4c56fad3a7ef46a4ce50ff55541a7b25eb72813bdada07d6b19005bb6771460d，位于
private/perf-opt-20261015/research-reset-20261016/d1-pgo-screen14/。

按5a077516事前分支选择J（D1+规则+D2）b059fc43；不追加ba40窗口或其完整门。
原stage的Linux udp_dispatch_实际8项5通过/3失败，未进入SDK/训练/设备；27原文件均保存。
三个失败断言在初建owner上要求idle，但Linux构造器的arp_awake初始为true，原step_neighbors
才会清除。root独立23aece16仅修cfg(test)夹具：先走原full turn，另加Linux回归验证待办存在
时不可跳过、正常排空后才允许就绪UDP。产品guard没有放宽；Mac相关6/6、Linux测试编译通过。
原b059归档tag perf/dnsmasq-j-linux-fixture-failure-20261016；原失败summary SHA
 a46dbd20a00bbe31c481a0f8643990e1007e51e76fd989a40600e4141498ae71保留。
J1改用独立新目录与23aece16身份，实际Linux9项及未执行filter通过后才继续原单次新PGO；
不是重跑未修改的失败源码，不覆盖b059记录。公开规则工具4b3d3ec1显式选择独立case/group，
原ba40和所有旧case保持，规避组名变化后误用旧AA。工具/夹具修正不列作产品性能优化。


## J1正式产物和实际PGO计数

源23aece16的实际Linux16lib+11bin（含udp_dispatch_9）全过，原11场景单次训练50raw，
新profile732093b36c0fbcce9bde11f3fc1d20581ffa4e4faa27118b5bcabf6b5ec68f49（936480B）。
ELF9e3326bad7c6ac8c9261994af8d70095ae86186e6ea149511080d2662f8f94b8（2288419B），
APK7f14b54864541e5662d9b276e30f9f5996be80d3dcc540014794ad562af4832e（1293163B）。
原编译31warning行保留，profile missing/mismatch为零；新caps、静态硬化、实际smoke通过。
597文件和全部50raw profiles已回收核验，唯一summary SHA2616f68f2aa44aa9dec2ab208bb2bb6681fe19172b44d2e701be2eacbafc528b，
在active PGO树private/perf-opt-20261015/rules-next-pgo-preparation-20261016/j1-rules-d2/result-summary.json。
私有smoke绑定曾在读取旧b059路径时失败，发生在plan/daemon启动前；修正J1路径后实际smoke
仅执行一次。首次非sudo证据读取被root daemon.log权限拒绝（0B），改为sudo只读后回收；
这些日志保留，没有重建、重训或重新计时。

Oracle I/J公开规则6窗均有效，每窗N5000，42个counter全部无复用/缩放。用户态每query：

| 事件 | I中位 | J中位 | 三次配对变化范围 |
| --- | ---: | ---: | ---: |
| instructions | 15021.1532 | 5866.8578 | −60.943%至−60.666% |
| cycles | 14151.9764 | 8502.3796 | −44.690%至−38.543% |
| L1I refill | 684.3144 | 471.4912 | −32.007%至−29.734% |
| L1D refill | 241.3456 | 182.4180 | −29.690%至−17.733% |
| I-TLB refill | 16.9166 | 20.0690 | +5.634%至+23.274% |
| D-TLB refill | 60.8936 | 46.5080 | −25.683%至−21.636% |
| branch misprediction | 197.3338 | 90.4544 | −54.196%至−53.463% |

周期配对中位变化−40.282%，两侧中位比−39.921%，不混用。IPC中位1.0555→0.6900，下降
仍伴随总用户周期减少；I-TLB的不利变化也保留，不能把收益全部解释成“足迹更小/IPC更高”。
实际PGO工作量缩减支持方向，但三对N1不替代A53、不证明独立因果或分配调用数。原summary
在哈希root daemon.log时权限失败，sudo只读运行同一汇总器成功；SSH结束后的本地无输出残留
在远端无实验进程确认后终止，exit255保留；六次capture无失败/重试。结果SHA
c29e6592f26dcb7c05be7d03ca00709e40077932f048d96554a1ef2629c15846，267raw等设备恢复gap回收。
小摘要在同树private/perf-opt-20261015/rules-next-pmu-20261016/small-summary.json。

另一次只读检查说明A53低率/proc user/system分项不能用于本轮归因：C/I16中有同窗C 0/84µs、
I 81/0µs这样的分项，而总CPUclock仍约80µs；不把分项中位数当作真实用户/内核差额。
实际I ELF还含按getauxval(16) bit8选择LDADD或LDXR/STXR的原子helper，Oracle存档cpuinfo含
atomics；路由器对应字段仅在当前测量恢复gap补读，不据此另造候选或宣称它是主因。

## J公开配置筛选通过；下一覆盖问题来自同名双栈

J实际14/14有效。200qps、5+95+1、CPU N20000/latency N19000，I/J CPUclock两侧中位
104.82254125→77.4346551µs；五对差为−26.0778943/−24.08311365/−22.4088802/
−24.4215409/−31.3325813µs，中位−24.4215409，5/5，超过新AA5.8929906。
AA原两对−5.8929906/−1.32177275保留。原tick104.5→77µs（−26.316%，W9.091%）可辨；
p50 .160502→.134110ms（−16.443%，W15.148%，5/5）可辨；p95 .348010→.278761ms
（−19.899%，W38.227%，5/5）仍未分辨。RSS中位2328→2380KiB，Anon504、FD12、线程/进程1均同。
630raw核验、1646guard/110外网检查，最低MemAvailable70016KiB、恢复后83476，生产/E/F身份不变。
result SHA3531f8d0fc5b2614ec29cdda78fa878e0fddf631f50c11267368a4f541bfbe27，summary
8cf15b476c455dd58040441769b6d2154fc840a087162872c0751f2b8d606290。独立公开九对及原118、
实际44/67继续，不提前接受J。已补读A53两核CPU part0xd03，Features无atomics；只作Oracle外推限制。

root在等待期间发现另一覆盖边界：J只给单槽名字缓存hint，同名正A+AAAA属于Many，D1和
general已有fresh捷径均回退。原aaaa30生成器按名字index固定族，因此不覆盖这种状态。
已有whole-owner仪器只新增同名AAAA预热：七条公开规则、20warm+2000查询，旧路径每query
11次alloc/dealloc、416B，general和D1相同；D1另加一次无效plain扫描。原型4ce24c62仅
把恰好各一条fresh A/AAAA纳入hint，两成员任一stale/expired/negative/异常长度均回退，
其余RRset仍原路。两条路径计数均降到0，D1名字扫描从3general+4skip+1plain变为1plain。
这是本机插桩计数，不是实际PGO计数或A53时间；instrumented树e8796627→ffe84c73，日志
在private/d1-count/dual-family-{count,after}-release.log，误用未限定exact过滤器的零测试日志也保留。
产品树基于J23aece16，738lib+31bin、8ignored及Linux全目标check通过；新测试直接以未走hint的
answer_records_general为字节/TTL/淘汰参照，另核验对族过期和旧hint失效。一次针对性审阅无阻断项。

当前模型修订：总命中成本取决于规则和缓存形状是否让快捷路径生效，不能只谈二进制体积。
双栈原型消除11次分配提供下一实验理由，但hint变大、额外检查及新PGO布局可能抵消收益。
先完成J资格及直接C/v0.2.0参照，双栈原型不混入J；下一轮只用固定合成双族状态测J/新产物，
预期5–20µs，若未达5µs/同轮AA不追逐这个区域的更多小变体。真实客户端请求分布未知。
AD/CD及空OPT仍回退；DO关系到unsigned缓存的LRU/转发语义，保持原路。因覆盖比例和单次
增益未测，暂不把空OPT扩展排在已测出额外工作的双栈方向前，也不把本轮24.42µs全归于D1。

## J公开九对确认与实际正确性完成

18/18有效，无补测。I/J CPUclock中位105.62458985→78.6807272µs，九对全部改善，配对中位
−27.0737731µs，d2/d8[−30.23524205,−22.56886425]；三块−26.11422535/−27.18916395/
−26.74208055均超过既定AA5.8929906。原tick105.5→78.5µs（−25.592%，W7.583%）改善，
p50 .163887→.133802ms（−18.357%，W5.305%，9/9）改善，p95 .351933→.304691ms
（−13.424%，W45.715%，7/9）未分辨，两个上升配对保留。结果SHA
d2b045987cb6f0440c461be07953a5155cbe0b2bdb309d39e7850aa8fdabad88，18归档/810raw核验，
2109guard/140外网，最低MemAvailable69312KiB、恢复后81632；生产/E/F恢复。
同一次独立审阅确认上述原3指标2改善/0可辨退化/1未分辨。J仍需完成原118，尚未接受。

J实际44族/67任务全部PASS，family SHA0cbc64184a9f0425c6e1557e6383a0bca1048c34117e1ad6abe8f705a137cf02。
实际PGO F10 13/704（仅原43条合格PTR顺序差）、protocol368/366 exact（仅原C-pointer2）、
TCP13条件/50对零差异及原预期超时保留，fresh source corpus已通过。归档189951312B，SHA
911d3258a47e2b0ad88fa97c5029c3e80ab577f586112de6267157c45d0926f9；83020regular/657774717B，
manifest SHA78390d225193a2697062b81b5f8935ef61741102dbcdf8acac5889ef0906e423。首次归档
读取root-owned F10日志被拒，发生在创建tar前；原stderr保留、同脚本sudo只读完成，无产品重跑。
归档在公开18恢复gap回收，本机核验与原118并行；Oracle释放给K，不重复原门。

另备好未选择的空OPT/AD/CD原型4fca22ef（独立J源基）：窄准入、规范OPT原地追加、DO仍回退，
保持原+15判界及两层限额；738lib/31bin/14专项、Linuxcheck通过。没有SDK/PGO/真机收益数据，
不混入J/K，也不因准备好了就排在双栈方向前。它只降低未来扩面实现的不确定性。

## 断流接管与报文覆盖模型（2026-10-17）

原5个直接子代理会话均已结束：loop/next_coverage正常完成，correctness/dns/dhcp于
22:07–22:09UTC记录stream-disconnected。J118本机81010/81023仍活跃，继续原进程/目录；
设备由新device代理独占，生产PID3086未变。Oracle无活跃旧工作负载，K实际新三项、50份
profile及use产物已完成，只接续尚未执行的smoke与正确性，不重复构建/训练。
K ELF f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08，2296611B；
APK1296161B，caps与实际smoke/硬化通过。原shipping/source边界通过，44/67仍在执行；
J118与K尚未最终接受，I仍为已接受回退。原成功门和检查缓存均复用。

主代理新增一次非计时诊断c541540a，沿已有owner分配计数器，范围为完整`step_udp`的接收/
处理/发送及其析构，不含wait/control工作；K诊断源码的singleton
路径与J相同，公开七规则、单fresh A、各20warm+200计数。plain/AD/CD/AD+CD/空OPT/
AD+CD+空OPT六形状各D1开关，共12窗，全部0alloc/dealloc/realloc/bytes。普通路径每查询
3次general name walk、4次encoded skip；空OPT为3/8；只有plain+D1为0/0/1次plain scan。
正确ID/单回答/CD保留与AD清除/OPT数量均验证，日志`owrt-perf-d1-count-20261016/private/
d1-count/flag-shape-release.log` SHA c1e63e8b2cb0e6a3ab1ded4143813c52ab0a1a9587ebc724300c0b72a961a23c。
这是native插桩计数，不是实际PGO或A53时间；未把计数窗口的elapsed列为收益。

当前模型：AD/CD/非DO空OPT排除D1，但没有重新引入这里的分配。J规则修正和K双族hint也
服务于普通fresh路径；不能按D1覆盖率折减整个J的27.07µs收益。备用原型的价值主要待验证于
少走解析/入口及减小触碰范围。下一步固定600秒被动真实UDP样本决定扩面优先级，再决定
是否对其单独测量；DO仍保留原有转发/LRU语义。采样工具24f8c9bc仅输出聚合，已过131072
flags/OPT组合、24个cBPF分支及ASan/UBSan。原SDK构建后在隔离Linux veth首次实际采样：
16个合成发送精确得到8条查询、固定health名排除1、AD2/CD2/OPT4/空OPT3/DO1；IPv6 HBH
可通过过滤，非53/非本机目的/出站不进入查询，TCP仅2段/1载荷段，0drop/0收包错误。
验证依据`query-shape-validation-20261017.json`（48ee9645），helper ELF392264B、SHA
0eab970fd8f27846167c4f8df98ffccfec9582001e7768048175c7bc63698101；设备真实样本仍待完成。

## J正式接受：公开配置净省27.07µs，原118窗无可辨退化

接受精确J源23aece16/ELF9e3326ba/profile732093b3，I保留回退。公开九对105.62459→
78.68073µs、配对中位−27.07377µs及三个block超过AA5.89299的确认保持；44/67及shipping/
source成功证据复用。断流后原118继续一次跑完，118/118有效、0补测、3850raw全部核验；
最终独审复用29窗并新增89窗，没有重测。原33项0改善/0可辨退化/33未分辨，符合事前
“公开配置确认获益+简化全矩阵无可辨退化”的接受条件，不临时要求简化hit也满足5µs。

简化hit CPUclock中位81.3483→74.1296µs，9/9同向，配对−6.7338µs；这里只描述，不套用
95秒公开AA判45秒窗口。旧tick82→74µs仍未过W18.29%及量化门。保留UDP-miss CPUclock
配对+8.33475µs（4/5变慢）、TCP-hit p95+24.17%（W210.87%）、HUP-large p95+26.70%
（W60.06%）；原门未分辨不等于证明不存在退化。home6暖机DORA max2.555→5.298ms单列。
RSS中位差−76..+64KiB、Anon峰中位−40..+16KiB；FD中位均相同，miss范围12..13→12..14。
11段4583合格/4586总guard样本、304外网检查通过，最低MemAvailable68016KiB；生产及E/F
身份恢复，恢复后73412KiB。最终结果SHA74fd80525d09a9458c143cd3128e178da81b145916cd394ad5fa190535c07667；
恢复SHA d24aa858fab7fff3dce5e1a849294e947cfb6b17d0b20cfe7cde486367051dea。唯一正式身份文件
为`candidate-j-acceptance.json`，独立结论为`correctness/j-final-review-20261017.json`。

当前模型：真实配置因素能决定快捷路径是否生效，J约26%的净收益是源码组合与新PGO的整体
作用。K实际44/67已全过，仍须自己的双栈14窗达到5µs/同轮AA。下一轮先用固定真实查询
采样澄清D1报文准入，再做原C/J与v0.2.0/J直接对照；不相加跨轮收益，不部署或合入main。

## 真实查询形状：19条夜间查询，暂不启用备用原型

23:10:50UTC开始，固定600秒实际600.087秒，无中断、丢包、截断、分片或收包错误。
过滤后187帧中150出站跳过；目的本机53的UDP为18个IPv4、1个IPv6，TCP0。固定健康名
排除0。19条可读DNS查询头的AD/CD/二者并集均0/19；其中18条完整解析（17A+1AAAA），
OPT、DO及非空OPT均0/18，J与备用原型报文形状准入同为18，备用新增0/18。
另1条body未解析，不能声称其OPT/DO为零，更不能据此诊断产品报文错误；原聚合完整保留。
分钟查询数为0/2/3/1/5/0/1/2/1/4，末尾不足一秒空桶单列，没有延长或补采。

本窗口只有0.032query/s，低于事前100条的代表性提示线。决定保留4fca22ef，不进入新PGO/
性能验收：当前样本没有显示扩面的实际需求。**这不能确认全天标志分布，也不能证明EDNS
客户端不存在。** 即使18/18满足J的报文形状，缓存新鲜度、CNAME/RRset及配置仍会使快路回退，
不能将它称为实际D1命中率。DOH/DOT、TCP请求和pre-DNAT外部目的DNS不在此比例范围。
任何后续扩大采样须选更有代表性的活动时段；本次原样本不替换，已有被动工具可直接复用。

原聚合`private/perf-opt-20261015/research-reset-20261016/query-shape-600s-20261017/aggregate.json`
SHA c191b79610c0e8b52edd0fb178e4b7e9c5f8c9fd6b80e17f4e5b2169861f3dc0；只含计数，无名字、
IP或逐包记录。前后接口地址集合哈希一致，603guard/40外网检查，最低MemAvailable72372KiB，
生产与E/F身份恢复。临时helper已按hash核验回收，C/J16→v0.2.0/J10→K14继续原排程。

当前模型：本次实流量未暴露AD/CD/OPT覆盖缺口；剩余已知成本先由同名双栈K筛选裁决。
该形状下11次分配是否能稳定省5µs仍未知；原C与v0.2.0直接对照用于回答整体残余与总收益。

## 公开配置精确C/J：没有需追加分段实验的正残余

16/16有效、无补测，原七规则与m6a.example。200qps五对C/J CPUclock中位75.02404→
72.64947µs，J−C配对差[−3.45341,+2.87280,−2.05371,−3.03244,−1.90170]，中位−2.05371µs。
2000qps三对47.11436→42.17395µs，配对[−1.19413,−11.40412,−4.94040]，中位−4.94040µs。
原CPU tick/W、p50和p95均未分辨。低载没有≥5µs且五对一致的正残差，按事前分支不追加
C骨架或分段实验；这不证明等价或稳定优于C，也不引用其它窗口长度的AA判显著。

低载RSS中位C1216/J2360KiB、Anon峰228/500KiB、FD11/12；高载RSS1232/2380KiB，完整
范围保留。最低MemAvailable69072KiB，894guard/60外网检查，生产及E/F恢复。原结果
`public-c-j-direct16/result.json` SHA250f5b1361b64e0d3dbdbc025ee87f2ab15b08ae1c809c2198d2bb4fcc12f6a2，
summary SHA a0f71272c047ac380c44464a524884ba0e2df2c82cdbbfb13c94a6e5d1a6d905。

当前模型：普通鲜活命中与C的可辨CPU差距已不是下一主问题；公开规则与缓存形状决定
覆盖范围。接着完成单独v0.2.0/J五对，取得直接总收益；再按原双栈条件测K，不相加历史中位数。

## 原v0.2.0/J直接对比：公开配置CPU降低51.22%

10/10有效、0补测。200qps、原5+45+1/CPU N10000，公开七规则与相同m6a.example；
原v0.2.0 8472be5a对精确J9e3326ba。CPUclock中位149.69423→73.02592µs，两侧中位比
−51.21661%；五对J−v0.2.0为[−76.74313,−75.06499,−75.31441,−73.30055,−78.54452]µs，
中位−75.31441、5/5改善。该直接收益略超过事前30–70µs预测，不能拆分为各历史优化的收益。
旧tick149→73µs（−51.01%，W6.85%）也可辨；p50 .204666→.125262ms（−38.79687%，
W4.23832%，5/5）可辨。p95 .355704→.265989ms（−25.22181%，W40.20843%，5/5）仍未分辨。

RSS中位2292→2376KiB、Anon峰516→496KiB，FD12/线程1；完整范围在原summary。
最低MemAvailable67776KiB，649guard/44外网检查，生产及E/F恢复。原结果
`public-v020-j-direct10/result.json` SHA135cfd35e6463dd6bf2e1f41cc677e5c7a86e5a016d2460958917a59ed9c6f12，
summary SHA ddd1592b442c1489bfddfd5cde3aba1cb8b32d10bc9cbf5a7d57fd35a06eb004。
这是包含早先授权行为修复与PGO的整体交付对照；测试的正常鲜活命中不触发已知过期CNAME
缺陷，仍不能独立归因该修复。前节C/J与本节是两批配对，不拼接成同轮三方统计。

当前决定仍是接受J；普通命中已获得直接总收益，且没有C正残余触发新的分段实验。K现按
既定14窗筛选开始准备，只有达到5µs及本轮AA才执行双栈九对确认，确认通过才原118；
先前完整正确性只复用，不重复。真实标志样本不足以支持开启备用原型，维持保留决定。

## K首轮被64MiB保护中止：无性能结论，先回收历史测试副本

原14窗只完成4个J/J和首个J，共5个有效窗；首个K窗约30秒时，00:04:44UTC guard报
low_memory并停止隔离组。最后成功guard样本65988KiB，资源probe为65432KiB，低于门
104KiB；不是DNS错误、产品崩溃或可自动替换的生成器漏发。原controller exit1、cleanup
无错，生产PID3086与E/F恢复、STOP及partial保留，不计算半窗收益，K尚未完成筛选。

附近J RSS2500/Anon488KiB，K RSS2376/Anon488KiB；K期间系统MemAvailable67932→65432，
MemFree72468→69944、Cached79872→80056、Shmem47868→48052、Slab31640→31704KiB。
停后无测试残留，MemAvailable先80076后77696KiB。任务/tmp总47648KiB，历史runs约
13944KiB及256个旧guard日志15071561B可在完整本地核验后回收；新partial388KiB保留。
原只读记录在`k-dual-family-screen14/post-stop-readonly.txt`和`retained-runs-sizes.txt`。

模型与决定：本次观察不能支持K泄漏或性能变差，已知环境中积存的约28MiB测试副本足以
改变可用余量。先完整流式归档/hash核验后回收旧副本，按新冻结条件要求125秒基线最低
88MiB，再开独立完整14窗并重新校准AA；实时64MiB门不改，原失败不抹除、不拼接数据。
原J接受、两个直接对照、一次真实样本和全部正确性不重复；再次健康失败则停，不循环重试。

清理已完成：实际选择254个旧guard文件及32个旧run目录（本次失败证据明确排除），
1585文件/25712523B在本机逐hash备份且二次核验远端未变后回收；释放tmpfs占用28772KiB，
任务根47648→18876KiB。生产/工具/ELF及当前failed guard与partial保留。旧STOP字节
SHA ea469aeba53f7a6f2cc4d1703c9b78d078d4e27618ff88e31b20850e28ee26af已本机保留并在设备
归档为`STOP-k-dual-first-low-memory-20261017`；原low_memory日志不改。清理后MemAvailable
110360KiB，不能把前后全部差值归因文件回收；DNS成功、HTTP403、IPv4/IPv6外网200，
生产与E/F核对通过。一次只读清单SSH255发生在复制/修改之前，其失败日志保留。
依据`memory-hygiene-retained-backup/pruned.json` SHA
bff5d18ce049b4a4a0df2a1b9d41dbb4f676086e6b766aa0a428dea39af949a7。

新125秒基线最低105084KiB，超过90112入口；DNS p95 .85ms/max9.088、HTTP max76.662ms。
独立`k-dual-family-screen14-after-prune`已启动，旧批次不复用任何窗口；新确认/完整阶段
入口均绑定新AA/exit。scope和protocol hash元数据在开窗前修正并留旧副本，产物/工具不变。
实时64MiB门不变，收益仍待完整14窗决定；没有因这次修复重训、重建或重复正确性。

清理后批次也在5个完成窗后退出，原因已定位为执行器沿用原远端label：r1-K在case第22行
mkdir即碰到保留的旧partial，daemon/预热未启动。收到的45文件与原low_memory partial
逐hash相同，只作来源证据，禁止当新K结果。新guard最低96260KiB且无stop事件，生产/E/F
恢复；不是健康再失败。原4AA及r1-J完整有效，错误STOP及碰撞记录保留。
按新冻结接续保留4AA，唯一远端前缀先跑r2–r5八窗，最后AB整对补r1一次；原r1-J不选用。
最终仍14个固定有效窗，不重做有效AA，不拼旧内存失败数据；开跑前检查所有新label不存在，
新125秒基线仍须88MiB。当前仍无完整K性能窗，修正规则没有根据候选效应选择数据。

接续工具已通过一次有界静态核对：实际schedule与唯一label清单逐字段一致，r2–r5顺序
BA/AB/BA/AB，末尾r1 AB；最终14严格取新4AA+10比较窗，confirm18和条件118绑定同一
选择与AA。接续125秒基线最低104336KiB，10个唯一远端label在基线前后均确认不存在，
固定10窗已开始。入口`run-k-fixed-continuation.py`，选择计划`k-dual-family-resume-selection.json`；
真实新增输出`k-dual-family-screen-resume10`，最终派生目录`k-dual-family-screen14-selected`。
上述路径均相对`private/perf-opt-20261015/research-reset-20261016/`；旧目录不可当当前入口重开。

## K双栈筛选通过：配对中位净省36.50µs，进入九对确认

固定接续10窗全部有效，最终严格取清理后原4AA及新10比较窗。原r1-J完整保留但不选，
碰撞45文件只是旧partial引用，旧low_memory批次零窗口进入。没有重训、重建、额外选样或
重复正确性。J/K CPUclock中位122.13615→87.57290µs，五对差（按原round编号）
[−36.49739,−37.34741,−31.71967,−36.24502,−40.17209]，中位−36.49739µs、5/5，
超过5µs与清理后原4AA给出的3.0579007µs。r1补对在最后实际执行，不能把编号顺序称为
原始时间顺序；筛选中位/方向不依赖此排序。两段最低MemAvailable95268KiB，恢复通过。

p50 .189432→.145959ms（−22.94913%，W7.02680%，5/5）可辨；p95 .400407→.322772ms
（−19.38902%，W23.92391%，4/5）未分辨，原一对上升保留。RSS中位2336→2392KiB，
Anon峰492→488KiB，FD12/线程1。固定双族800填充、零steady上游及TTL时限均通过。
派生结果`k-dual-family-screen14-selected/result.json` SHA
61966dc8d674738a16412c35e200e2e99ecf006562965e59435158e2c6c68e52；summary SHA
66918bc92286711b8d789e5f75862025452359f332943b83e5d3a968ac3dea3d。完整选择与排除在原result中。

当前模型修订：36.50µs超过原5–20µs预估，说明这种缓存形状回退到整条通用路径的成本
比先前估计大。不能把收益全除以11次分配来推单次allocator成本，也不能拆开新源码与PGO
的作用。K尚未接受；现在只按既定同双栈九对确认（同AA3.0579007、5+95+1）验证稳定性，
确认通过才原118。普通单族C/J与v0.2.0/J数字不与本双栈结果相加，不声称C/K双栈已对比。

## K九对观测器缺失与最小工具修复

独立九对确认已完成r1–r6共12个有效窗；r7-J的100秒/20000请求全正确，800预热填充、
steady上游0、零错误/超时/漏发，before/after各2条正常，COMPLETE存在；但资源观测文件
及stderr均0B，原分析器assert samples拒绝，不能使用该窗CPU/资源。r7-K未启动，
最低MemAvailable96784KiB、无健康stop、外网均200，生产/E/F恢复，STOP及全部raw保留。
只读dmesg无OOM/segfault/hung-task匹配。原case吞掉observer wait状态且未存实际argv，
所以实际死因未知；最终PID文件为正整数，不能证明启动瞬间已写完。

主代理找到可解释签名的PID发布竞态：echo先创建再写文件，父shell只等-f即可读到空值；
starttime随后读取/proc//stat仍成功，原probe空helper参数会静默exit2。Oracle原精确
ac7ae7ee probe一次复现exit2/0B/0B，正常helpers得exit0/2条样本；事件控制暂停证实旧
publisher暴露空PID，tmp+rename只发布完整PID。**这是机制复现，不是r7实际根因证明。**
证据集中在`resource-probe-pid-race-20261017.json`（f8919f70/d2c66b17）。

ade5309e只修case工具的原子PID发布、starttime参数、observer参数/PID/start/exit记录与
非空输出/错误退出检查；不改sampler或产品二进制。Mac与Oracle4项事件控制回归和sh -n
均过；Oracle测试日志SHA35ee5071d6c6d49fa3d0dcdd3ef641617ec00bbde6c252725b3e4339c4f13206。
下一6窗双栈case及未开始的full case按局部差分移植，路由与自哈希指向实际新脚本；逆
替换精确恢复旧hash，配置、流量、两次预热、CPUclock及完整场景均不变。
按冻结方案保留12有效，先r8/r9四窗、末尾AB补r7一次，坏r7-J不选；最后仍9对，同AA与
判据，不用6对替9对。确认通过才118；再次观测失败停，不自动增加样本。


## K双栈九对确认通过：净省39.47µs，进入原118窗最终回归

修复后固定6窗全部有效，最终选择原r1–r6的12窗及新r8/r9/r7的6窗，坏r7-J保留且排除。
每对两侧工具一致；工具版本变化、中断和实际执行顺序保留，未重复原12窗、PGO或正确性。
J/K CPUclock中位123.08019→83.11558µs，配对中位−39.46670µs，9/9改善；d2/d8
[−41.17618,−36.31240]µs，三个逻辑三对block中位−39.64957/−36.80340/−39.46670µs，
均超过同一筛选AA3.0579007µs及5µs效果门。该次序统计区间不证明独立性或名义覆盖率。
p50 .183122→.141651ms（−22.64665%）可辨；p95 .375017→.316232ms（−15.67529%）
未分辨，9/9同向。RSS中位2412→2356KiB、Anon峰中位492→488KiB、FD12/单线程。
两段健康1600+738样本、106+50外网检查，最低MemAvailable94856KiB；生产及E/F恢复通过。

唯一派生目录`k-dual-family-confirm18-selected`中的result SHA
8664e6264b1d9f8d2303153d20fd152f0479f7071520004af78955d5c3c9d928。
增量独立复核942个raw文件hash及原分析器重算通过；新增6个observer均PID/start吻合、
各102样本、正常TERM exit1。此前筛选和正确性复核直接复用，不重复全量审计。

当前模型：独立确认与筛选均支持同名A+AAAA使J落入通用路径的额外成本约35–40µs，
K去掉这条路径后显著改善；源码、布局与新PGO的贡献未分别识别，不能把全部时间归于
11次分配。原118统一使用修复的observer启动工具，裁决其他DNS/DHCP/生命周期场景是否
出现可辨退化。K在原118、资源健康及最后一次增量复核全部通过之前仍不接受。


## K原118在第31窗停止：混合上游phase计数不符，未接受

原30有效（18 hit+10 miss+mixed r1两窗），mixed r2-K的上游setup999/steady801，旧门
要求steady800；r2-J未开始。客户端5000/5000正确、零错误/超时/漏发，上游1800/1800完整，
observer正常exit1，生产健康正常且E/F恢复。完整raw/failure保留于`j-k-full118`，有效30
索引SHA5ff2078d3dee5e8122912747437808fb445fa682678cc4174b62e5b7fff6ddad。

主研究及独立只读复核确认：4000测量raw序号完整，3200hit/800miss，预热1000覆盖800名。
客户端按计划时刻归组，上游按实际answer时刻分桶，机制允许错位；但暖机尾部未保存逐条
时间，上游无请求身份日志，不能把此失败直接叫已证明的边界假阳性。测量开始前后27–75ms
延迟也保留，不归因产品或调度器。仅total1800不能排除额外命中转发与遗漏未命中的抵消。
按新冻结的精确名字集合计数改进下一批工具，旧窗保持无效；K仍不接受。
