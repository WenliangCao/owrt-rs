# netifd 工程结案：保留H10（2026-09-27）

**按用户明确选择的工程边界结案，保留H10；原严格性能门并未全部通过。**
用户要求列清9项UNRESOLVED，取消缓冲区追加筛选，报告提交后停止研究；生产继续使用C。
实际相关无线配置、设备状态和接口dump的主要收益已得到实机支持；仍有事件cycle尾部、
空无线四并发、大规模dump尾部以及依赖CPU的未闭合差异。功能与恢复门通过，不代表这些
性能差异通过。生产九组件全程保持精确C，没有部署、刷写、重启或改变生产无线/设备/nft。

用户指出20轮大矩阵过慢后，停止继续放大样本，改为固定的33窗工程复核；该队列实际耗时
约35分钟并完整结束。原480窗矩阵保留为未完成。此次改变降低统计结论的强度，不降低
功能/恢复/身份/健康硬门，不修改原性能门槛，也不把旧失败或未决重新标为通过。

## 身份与范围

| 身份 | SHA256 |
|---|---|
| 设备/manifest核实的C netifd | `8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90` |
| 正式R89，设备bundle `/root/r89-before-r90` | `b127c49888b70a1f1e59318c0b05661623e05030b923975881e4b2279388a478` |
| canonical H10 | `4c0420503a93dd33bd98ad9197bb8da156578fd012dda346507bff54645c41ad` |

候选源码为 `dc055aee2d576599699c52479bd58c0566584626`；后续Git提交仅增加派生报告。
Oracle H10 `a81b…`、旧canonical `8208…`、A09/B09及source05均没有冒充正式R89或最终4c。
设备为AX3000T/MT7981B，OpenWrt25.12.5、kernel6.12.94、en0 Wi-Fi管理；boot始终为
`75a17130-62f9-43f8-bd28-7bbbb44ad5c8`。测试仅使用既有mount/PID/network namespace。

同源码host/release CI成功：36308638556/36308634604。exact canonical已有48个ubus、
166个netifd unit、clippy/release/ABI，以及full31 suite、overflow/reexec、两类reconnect故障、
raw66和type生命周期证据。full31中的r46/r47/r48使用独立标识的Oracle helper，
其余28项使用exact canonical daemon，未把helper的身份冒充canonical。candidate对C raw66零差异；R89的63项历史差异仍保留，未用它
改变候选合同。type生命周期72个元数据检查通过，opaque-ID值规范化边界见研究日志。

## 样本与分析

共164个已完成namespace窗口、1036条lane观察，覆盖26个strata及572个metric×baseline
对比。main32与scale64各20个完整三侧block；实际无线3个；128dump保留旧11窗，其中
3个完整block及2个未配对窗口；其余新组各2个block。128dump未配对的4条lane观察全部
保留，未跨block补配、丢弃或重跑。有效计量RPC/cycle的workload错误数为0；33个新窗口
全部正常完成。采集恢复及/proc扫描错误仍分别保留，不属于“所有错误为零”。

scale64第48、58窗属于显式证据恢复，原退出/失败/延迟补采来源均保留。第58窗退出始终
UNKNOWN/null，间隔位于block20内部；质量审核并不能证明没有系统漂移。原128dump
第11窗完成后按用户的耗时纠正停止，第12个空目录未启动namespace，原group COMPLETE不存在。

百分比为所有完整配对log-ratio中位数换算的变化，不挑最快窗口，不池化请求重算尾部。
新n2/3结果只作描述；没有原1144项家族置信保证、总体等效或全面非劣结论。保留所有原
own/tree CPU计量区间、c4预热/分母口径及10ms uptime吞吐界。零child计数不缩窄误差。
完整mean/p50/p95/p99/吞吐及主体、依赖、caller own/tree CPU见
[全部指标表](NETIFD_20260927_ALL_METRICS.md)。逐窗RSS/Anon/HWM/fd/thread在派生JSON，
连续采样及关闭回收另见resource04；缺失的峰值/角色观察没有填成0。

## 代表性收益（相对正式R89）

| 场景 | n | 主体own CPU | mean | p99 | 吞吐 |
|---|---:|---:|---:|---:|---:|
| device_status |20|−38.43%|−30.33%|−26.29%|+35.41%|
| 32接口dump |20|−37.46%|−19.94%|−13.71%|+6.36%|
| 64接口dump |20|−36.91%|−18.68%|−10.20%|+6.15%|
| 128命名接口 |2|−19.18%|−11.24%|−2.20%|+11.27%|
| 实际配置wireless status |3|−91.29%|−80.68%|−58.98%|+193.65%|
| 实际配置wireless status c4 |3|−92.60%|−74.33%|−62.14%|+186.22%|

实际无线使用只读采集的配置、匹配image的handler schema及隔离stub。此处验证状态投影
和查询路径，未触发生产radio重配置，也没有测物理radio setup/channel switching或全真实
handler执行成本。实际配置两lane的全部原配对指标方向均有利；n3仍不是统计保证。

## 必须保留的回退与未决

572个比较中有73个描述中位点方向不利；其中9个逐pair归一化成本增量中位数超过原门槛。
其余44个虽中位点在门内，仍有单配对越门；20个所有观测配对点在门内，也不能据此称非劣。
全部578个配对越门记录保留，其中339个出现在中位方向有利的比较中。own/tree和这些索引
互相重叠，不能相加成独立失败数。每项处置及来源见私有 `final-disposition-01/`，全量表见
`final-summary-01/{point-adverse,over-budget-pairs,priority}.csv`。

| 问题 | 原观察 | 当前解释与限制 |
|---|---|---|
| 64dump依赖own/tree CPU vsR89 | +3.75%，配对绝对中位+13.9173us，20/20为正 | 内容/顺序未变；发送、分配布局或调度原因未决，不能归为噪声或用主体收益抵消 |
| 128dump单客户端p99 vsR89 | +10.50%；三对+828.437/+683.862/+280.609us，均超原5%点门 | 未归因；128KiB保留buffer可能减少分配，但缺本轮干净尾部对照 |
| 空无线c4 vsR89 | mean+0.84%、p95+5.08%、p99+9.79%、吞吐−3.61%、caller own/tree+2.70% | 两对混合，原p95/p99/吞吐归一化成本中位越门；实际无线收益不抵消它 |
| reload p99 vsR89 | 中位点+2.54%；两对−753.879/+1295.091us | 第二对超过原426.675us允许量；不能只看较小中位数 |
| 128named c4 p99 vsR89 | 中位点+0.40% | 第二对+41.779us超过34.351us允许量，n2不支持非劣 |
| events主体own CPU vsC | +50.31%，约+7.971ms/四动作cycle | 主体tree为+1.59%，两项分别保留；own差异不能被tree/延迟收益抵消 |
| events p95/p99 vsR89 | +10.39%/+17.76%；p99两对+86.304/+176.312ms | 均超原点门，不能称微小；耗时尚未隔离到daemon内部 |

事件计时从启动整个cycle脚本到子进程返回，包含四动作、状态轮询、地址/路由对账、
/proc子进程扫描、observer证据检查、最终settling及落盘。不是纯netifd响应时间；原四动作
单位仍保留，不能事后扣扫描开销或除4。候选两个p99 cycle均为[1,6,1,5]次action poll、
15次扫描；R89相应为同样次数及[1,7,1,6]/17次扫描，不能解释为候选多轮poll。
现存journal有cycle起止时间，缺逐action/扫描阶段时间。旧C A/A有约9.13%的p99变化，
它不能解释或豁免本次候选回退。具体边界源码为 `exec_journal.rs:79–84` 及
`isolated.sh:515–570`。

main32的细小中位差异、每个较慢窗口、priority条件“candidate比C差而R89比C好”及全部
role成本也均列入完整处置，未用上表代表行取代。原CPU/mean/p50 max(2%,2us)、尾部
max(5%,10us)、吞吐2%规则仍有效；此次没有事后把它们放宽成PASS。

## 9项UNRESOLVED逐项

以下9项均保留UNRESOLVED。百分比仍为配对log-ratio中位数换算；绝对差是配对差值
中位数，两者不是“两个总体中位数相减”。n是独立三侧block数，不是请求总数。
依赖own/tree两行是不同计量口径，本负载点值相同，不能算成两项独立机制。

| # | 场景 | 基线 | 指标 | n | H10变化 | 配对绝对差中位 | 处置与边界 |
|---|---|---|---|---:|---:|---:|---|
|1|events-static2/events_static2|C|主体own CPU|2|+50.306%|+7.971 ms/cycle|完整四动作cycle；阶段诊断见下节，未归因到daemon内部。|
|2|events-static2/events_static2|R89|p95|2|+10.385%|+72.205 ms/cycle|完整四动作cycle；阶段诊断见下节，未归因到daemon内部。|
|3|events-static2/events_static2|R89|p99|2|+17.764%|+131.308 ms/cycle|完整四动作cycle；阶段诊断见下节，未归因到daemon内部。|
|4|scale-128-dump/interface_dump_128|R89|p99|3|+10.503%|+683.862 µs/RPC|三对p99均超门；缓冲方向已按用户指示取消，未证明无收益。|
|5|scale-64/interface_dump_64|R89|依赖own CPU|20|+3.753%|+13.917 µs/RPC|20/20方向不利，18/20点越门；发送/调度等具体原因未决。|
|6|scale-64/interface_dump_64|R89|依赖tree CPU|20|+3.753%|+13.917 µs/RPC|20/20方向不利，18/20点越门；发送/调度等具体原因未决。|
|7|wireless-empty/wireless_status_c4|R89|p95|2|+5.080%|+19.428 µs/RPC|两对方向混合；第二对明显越门，实际无线收益不抵消此项。|
|8|wireless-empty/wireless_status_c4|R89|p99|2|+9.792%|+52.012 µs/RPC|两对方向混合；第二对明显越门，实际无线收益不抵消此项。|
|9|wireless-empty/wireless_status_c4|R89|吞吐|2|-3.614%|-465.598 RPC/s|两对方向混合；第二对明显越门，实际无线收益不抵消此项。|

### 重点：事件p95/p99对R89的退步（n=2）

两项在两个原配对中都超过冻结的max(5%,10µs)允许量，不能归为微小差异，也不能用
主体CPU下降或相对C更快来抵消。每侧每窗N128、预热8个完整四动作cycle；经验p99为
该窗第二大cycle。**n=2只有两组三侧block**，没有置信保证或长期p99精确估计。

| 指标 | block | R89 | H10 | H10−R89 | 原允许量 |
|---|---:|---:|---:|---:|---:|
|p95|1|702.563ms|739.453ms|+36.890ms|35.128ms|
|p95|2|681.808ms|789.328ms|+107.520ms|34.090ms|
|p99|1|782.794ms|869.098ms|+86.304ms|39.140ms|
|p99|2|707.747ms|884.058ms|+176.312ms|35.387ms|

配对描述变化为p95 **+10.39%**、p99 **+17.76%**。后续仅一窗/侧、N32的阶段诊断
观察到较慢周期主要增加在**内核地址/路由对账、子进程扫描、状态轮询及等待阶段**，
没有集中在四次操作RPC返回阶段。详细阶段数值见下节；异步daemon/helper工作与这些
阶段重叠，不能推定全部是工具开销，或从原确认延迟扣掉。两个实验的样本不合并。

## 资源与正常关闭

原resource04三项FAIL仍保留：依赖采样最大RSS对C+116KiB、Anon+84KiB，以及主体
active128 reportedHWM对R89+76KiB（各对应64KiB门）。用户询问约100KiB差距是否值得
继续追调。基于实际影响与研究成本，本轮不再优先做内存专项；这不是用户豁免原门槛，
也不是内存等效或原门PASS。HWM近似/非单调、采样间隔
60–140ms及不同观测暴露均保留，不能据此扣除假定误差。

该固定生命周期中，settled主体fd C/R89/H10为19/10/10，依赖为12/11/11；关闭后依赖均10，
记录线程均1。没有候选持久fd/线程增加；settled netlink队列归零、Drops观察均0，采样
Rmem最大为0/33024/33024字节。主体退出0、PID及观察到的netlink inode消失、namespace
清理通过。这不证明任意重复周期无泄漏、所有socket inode清空或未采样瞬间无峰值。

## 最终建议与停止理由

保留精确canonical H10（`4c0420…`，完整hash见身份表），作为本轮推荐候选；生产九组件
继续运行精确C。这次是用户明确授权的**工程结案**，没有把原门槛放宽成PASS，也不宣称
每个负载都胜过R89/C。9项UNRESOLVED、44项单对越门边界和三项资源FAIL全部保留。

停止理由：主要查询路径已有清楚的实机收益，功能/恢复/正式构建成果已具备；用户认为H10
已足够优秀，并明确要求停止追加实验。剩余差异的完全归因不再是本轮结案前置条件。
这是研究范围的明确调整，不是对事件尾部实际影响、统计非劣或所有算法方向已排除的证明。
不会继续大矩阵、追约100KiB内存、补跑中断窗口或开启新的性能候选。

H12仅改变回复保留和dump预分配两个阈值64→128KiB。用户取消前，同recipe Oracle
H10/H12构建、各166单测、clippy及ABI已完成；H10复现`a81b61…`，H12为
`969907d84f0e4abb57c1aaebcf0c8da8b553d2900a2599b219f84e03673909e7`。
取消到达时短队列已经启动：前两窗完整结束，第三窗namespace退出0，停止信号打断其
post-host观察；原`FAILED_STOP_QUEUE`和不完整post证据保留，第四窗未启动。
这些原始记录只归档，**不分析性能、不晋级H12、不声称筛选完成或H12被性能证伪**。
取消后的只读核验确认三个所属namespace/root无残留进程，宿主地址/路由文件不变。
H12没有进入路由器，没有主线代码修改、正式CI或全功能门验收；H10源码与ELF保持不变。

H12私有目录：`private/netifd-20260927/h12-buffer-screen-01/`，含两行patch、构建、取消记录。
取消归档SHA256：`e02443cd2a6027845fb9b8a8b3246ee92f7b3f8441bca600126d7aa859848228`。
最终候选索引在 `engineering-confirmation-01/candidate-index-closeout-01.json`；历史17项及
新增H12取消项共18项，旧候选索引和所有拒绝/失败理由保持原样。

## 有界事件阶段诊断（后续补充）

仅追加R89→H10各一窗，N32/W4，约82秒包含准备、采集与核验；不是新的确认实验。
私有collector副本仅增加两侧schedule，harness副本只用shell内建read/printf记录阶段时间。
精确ELF、四动作、合同、扫描、5ms等待、guard及生产健康门保持原样；两窗退出0，所有
64个计量cycle通过。原1036观察及所有确认失败不变，诊断数据另存、不合并。

| 每四动作cycle的描述值 | R89 | H10 |
|---|---:|---:|
| mean |660.778ms|694.727ms|
| empirical p99（N32最大样本）|695.742ms|943.596ms|
| 操作RPC阶段平均合计 |46.875ms|48.750ms|
| 状态RPC阶段平均合计 |70.000ms|73.438ms|
| 内核地址/路由对账阶段平均合计 |233.750ms|254.375ms|
| 子进程扫描阶段平均合计 |133.750ms|140.000ms|
| 等待阶段平均合计 |61.250ms|67.188ms|
| 主体own CPU/cycle |26.506ms|23.673ms|

H10最长cycle的command/status/kernel/scan分别50/130/340/200ms；R89最长cycle分别
50/80/230/150ms。慢周期没有集中在操作RPC返回；状态检查和工具对账阶段占大量时间。
这些阶段同时与异步daemon/helper工作重叠，不能将差值全部归给工具或事后从总延迟扣掉。
固定顺序、单窗、10ms uptime量化及新增记录开销限制因果和尾分位推断；原尾部退步仍未闭合。

源码补充：H10相对R89补齐setup/up Notice，down原有日志改走libc syslog；该隔离夹具
/dev为新tmpfs、没有logd或/dev/log。缺日志依赖可能增加失败socket调用，是测试环境边界，
不是本次已证实的尾差原因。普通link全量rescan和SIGCHLD回收策略在R89已存在，未发现
H10新增1秒回收等待的证据。没有为分数关闭日志、减少扫描或改变脚本合同。

证据目录：`private/netifd-20260927/event-phase-diagnostic-01/`。
plan SHA256 `966fdae5b48f8ae2ea50c31098c8afee9c3844a5969fe00a6c2361acf37ebbfc`；
完整阶段summary SHA256 `0da4c7eb023ccd7a696e3ad369f167117a7bf548f6e0fbff74156a94b7cc5308`。
collector/harness/probe/ELF/benchmark/guard hash在plan；每窗archive和文件hash完整保存。
最终原collector健康验证通过，boot/config/生产身份不变。额外清理了已停止旧128dump队列
遗留的私有staging bundle；原11窗归档保留，未删除任何未回收窗口或生产文件。

## 数据、hash与工具

原始资料均在ignored/private，不把无线配置、image、设备dump、ELF或密钥放入Git。
路径以仓库根为基准：

- `private/netifd-20260927/final-confirmation-02/collection/`：131个旧完整窗口及未启动prefix。
- `private/netifd-20260927/engineering-confirmation-01/collection/`：33个新完整窗口。
- `private/netifd-20260927/engineering-confirmation-01/final-summary-01/`：1036观察、572比较、全部role/资源summary及越门索引。
- `private/netifd-20260927/engineering-confirmation-01/final-disposition-01/`：73项逐项处置。
- `private/netifd-20260927/final-resources-04/`：资源生命周期原样本；`h10-canonical-gates-01/`：功能/恢复原证据。
- `private/netifd-20260927/final-report-inputs-h10/`：17候选索引、热点图、既有失败和机制边界。

| 产物 | SHA256 |
|---|---|
| 原冻结设计 | `6236ab71a23185b62ffa7bbbf2e32857b8c4b420106e2017fd5aa3ba4c4ec293` |
| 新工程设计 | `6d6e37613658c281208e65cf087087c0e4b563e96ae1e05fffe7ee235130de03` |
| 原collector | `f81fe2ad49b3fb808ed0a77e1e995736e6cd09bcb6462c9239f945deecdcc306` |
| 原harness | `dcd5b4325927dc2dd2dd964a59c717087933ebbaca624f32404b5c7c38c2c67e` |
| 原analyzer | `8c5728a593bb6d43b36879bf8ba65117a5bf975d4bea71befb7bd747d833217c` |
| 工程分析adapter | `6ffb095529f59c676c4161ffad3846a7af13379f182c1dbcadb89aa07572e649` |
| 完整合并script | `ac54d051049dbfd463c0c6b6d03879ff244cf110b616e260ac08e0e4f40c167f` |
| 全部结果JSON | `b85366969851af385639e87793f7eaa150c20c733aa72f9d1a1c63de0c458de5` |
| 逐项nonwin处置 | `1d941c9af2b3d34f6e4cc80ef1285301a718e4fc3c8931eb7ee3d457f5b37746` |
| 新组完成索引 | `1b6102cd3fc57400d67b37d5555217717b944110efebc5f42a7130f126c9c035` |
| 33窗结束生产健康核验 | `7af0b4f1ee73cf08dc9b17c1e4ed9964313fa112c40eb5c72431fcf2683692ca` |
| 工程结案候选索引 | `3c156a4fbda3ca3e98103ec87f970751f25b50ebed6c9a08c86e6b1b2e8fb939` |
| 结案只读健康核验 | `6af8c111fca65af7d891485548d171ecc218fb77411ef3a6af1059813666f156` |

统计与逐项审查仅访问本地归档。结案只读核验保存在
`private/netifd-20260927/engineering-closeout-01/`：生产九组件仍为精确C，boot/config及
客户端健康与阶段诊断结束时一致，路由器无本实验staging目录；namespace进程清理证据
分别保存在原collector和Oracle取消归档。未申请或进行生产切换。

历史研究、源码和失败恢复细节见 [研究日志](NETIFD_20260926_RESEARCH.md)。
