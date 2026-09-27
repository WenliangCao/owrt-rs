# netifd 工程复核结果（2026-09-27）

**H10 是当前保留的候选；工程复核完成，尚不能宣布原严格收尾条件全部满足。**
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
保留，未跨block补配、丢弃或重跑。错误数为0；33个新窗口全部正常完成。

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

## 建议与停止边界

保留精确H10及其已通过的功能/恢复成果，继续维持生产C。实际配置status与主要device/dump
路径的收益清楚，但事件尾部等尚未达到原严格收尾要求。**当前不能声称条件6、7全部满足**，
也不能把“工程复核完成”改写成“netifd全指标验收通过”。

停止旧的大矩阵有明确成本理由：128dump仅前10窗就接近一小时；完整20轮对当前工程决策
过重。新33窗已补齐缺项，后续不应再自动扩大重复数或为微小数值争优。若继续，优先考虑
仅两个短窗的事件阶段时间诊断，分清工具cycle与daemon成本；128KiB buffer只保留为一个
明确的内存/尾部取舍，不用污染Oracle排名宣称它无助。上述追加实验尚未运行。

原17项候选/拒绝索引及有界热点图保留；H3a曾筛查但不等于已证伪128尾部收益，H4c旧
筛选未完成、H7b单对依赖/caller增量、H8/H9/H11处置及所有原失败保持原貌。当前报告给出
完整证据和建议；接受这些工程边界与坚持原严格完成条件是不同的决策。

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
| 最终生产健康核验 | `7af0b4f1ee73cf08dc9b17c1e4ed9964313fa112c40eb5c72431fcf2683692ca` |

统计与逐项审查仅访问本地归档。最终只读census和client health证明生产九组件仍为精确C、
boot与客户端健康不变，无本实验owned root或进程。未申请或进行生产切换。

历史研究、源码和失败恢复细节见 [研究日志](NETIFD_20260926_RESEARCH.md)。
