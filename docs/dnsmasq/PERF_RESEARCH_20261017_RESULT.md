# dnsmasq-rs 持续研究结果：2026-10-17

**K仍为接受候选；按用户第三次专家复核指示，停止未命中/DHCP候选推进，只完成一次小HUP诊断后收尾，不发布。**
本轮计划见[研究计划](PERF_RESEARCH_20261017_PLAN.md)。J/K原接受证据与所有失败保持不变。

## 当前模型与第一轮决策

单族命中已接近精确C，但不等于不可压缩地板。混合负载成本大体符合命中/未命中的加权
组合，K仍有配对+4.21µs、5/5的不利方向。更大的未知数在UDP转发增量和DHCP同步更新。
DHCP6/150的差异同时改变到期时间更新频率，不能把两点拟合当线性复杂度证明。
首轮用精确K的系统调用和PMU定位工作，不重新跑通过的资格或已有同产物诊断。
R17-1已完成；下一轮先修采样强度，再依据有效归因选择产品实验。


## 发布名字复用：机制通过，尚未选入真机

源56320021（基K）：沿真实`DnsDaemon::publish_lease_names`，20预热后固定200次替换，
旧代释放包含在计数区间。6租约/12名字每次alloc含realloc为39→27，150租约/300名字
635→335；realloc次数不变，requested/released每次分别少384B/9600B。全部名字交替
改变的6租约负控39→39，不复用大小写不同或位置不同的输入。16项聚焦测试通过，原需
外部C环境测试1项忽略，Linux aarch64-musl全目标编译通过；两次纯编译适配失败保留。

这是本机确定性工作计数，不是A53时间或PGO结果。源码只共享不可变名字Arc，新expiry、
地址、索引与active状态仍新建，完整hosts/cache冲突与首次发布回调仍执行；旧TCP快照
保持原到期和地址。计数源码与补丁在`owrt-perf-lease-name-reuse-20261017`，原raw在该树
`private/lease-name-reuse/`。R17-1归因尚待完成，不能因原型现成就自动安排完整资格。

## 现有证据范围与仪器

只读盘点确认精确C097a9e21完整11场景对照仍是base2 C/v0.2.0；后续诸多`comparison.c`
实际上是Rust基线槽，不能拼成C/K矩阵。旧C TCP树FD143/151是9进程逐进程相加，不是
独立内核对象；父FD19/19才可与Rust20/28同口径看。新研究不把这些历史比例当K残余。
K既有20个DHCP窗的620资源样本满足稳定单进程/单线程与child CPU0；未保存ns端点，
不能补造，但下一实际筛选可在原before/after边界复用CPUclock helper。预计同长度
2对A/A+5对比较加125秒健康为11–12分钟，候选和主场景未定，不提前占用设备。


## R17-1：内核工作不可忽略，原采样受节流而无效

11窗流量完整、5个stat共20counter均enabled==running，udp-miss strace完整；5个user
cycles采样均lost0却有2111–10008次THROTTLE，原分析器未检查。全部raw保留并收窄结论：
旧采样排名只能提供探索线索，不能据比例量化热点。没有选择性重跑。唯一摘要
`private/r17-1-k-attribution/summary.json` SHA
a8be24dc6dbf88400841389eaf24566c03e6fa4542a2b5e76f4d230f1690a1f4，584raw逐hash回收。

| 精确K、N1独立stat | 用户周期/op | 内核周期/op | 内核占该对总周期 |
| --- | ---: | ---: | ---: |
| UDP miss | 57554.7 | 117956.2 | 67.21% |
| UDP mixed | 23890.8 | 57258.0 | 70.56% |
| TCP hit | 14140.2 | 70116.4 | 83.22% |
| DHCP6 | 54482.0 | 127793.3 | 70.11% |
| DHCP150 | 657999.4 | 686792.9 | 51.07% |

这是N1单窗计数，不是A53时间分解；也不把kernel视作不可压缩。5000次UDP miss记录
5000 socket/close、5000次4B read、19986 ppoll（9993零timeout）、5000成功recvmsg及
5000 EAGAIN、5000 recvfrom/sendto/sendmsg。另323 mmap/281 munmap也保留。没有沿用
旧candidate-C这类Rust标签当精确C语言参照，未将syscall数量换算成节省时间。

模型修订：UDP转发额外成本的大部分在内核，所以重复唤醒与I/O边界比单个解析小改动
更值得验证；DHCP150用户与内核两半，单独省300名字分配未必足以跨50µs门。下一R17-1b
固定period200000的五样本（预测354–8225，零节流且>=300才使用）和DHCP6/150两次strace。
不修改系统perf cap，不重复stat/udp-strace；若仍不合格停止此采样方式，不连续调参。


## R17-1b完成与用户调整后的停止决定

新7窗全部流量完整。三个DNS的低频样本1383/548/350均零节流/丢失，逐样本enabled==running；
UDP miss的poll_inner/insert_reply/malloc/free分别约9.62/9.47/8.17/6.36%用户样本权重，
TCP local lookup约20.30%，这些是N1 emitted范围的粗分布，不是A53可节省CPU。
DHCP6/150仍有162/2392个THROTTLE，按计划停止该采样方向。原解析器对:S的actual READ
增量误要求恒等200000，初次离线失败保留；7a1fbb45仅改解码重放同一raw，不重跑target。
唯一摘要`private/r17-1b-k-attribution/summary.json` SHA
d558e53e5f5113be5c97bab7f80057cca32870dfb743d93ab5f3fa095bba076e；402raw逐hash回收。

两次DHCP strace有效：6/150的fsync/ftruncate/lseek为156/2500，lease write为156次
64470B /26707次25610580B。150的16907 mmap/16888 munmap分别约257.25/256.93MB，
其中14424/14415位于fsync后至DHCP reply前，6客户端该区间均0；trace无generation marker，
只说明顺序，不冒称调用栈归因。大量地址重用与4096/8192/24576/45056B映射反复出现，
是可信的未来高规模线索，但用户家用6租约场景下不值得为它继续完整构建/验收。

用户随后指定第三份专家复核，允许最后可选小HUP计时、若无简单问题收手。主代理同意
“预期收益×发生频率”应进入停止条件：物理上仍可优化、已有原型或比C还快都不是继续
研究的充分理由。不同意把跨轮C/K量级叫精确同轮收益，或把mixed +4.21µs的来源定为已证
hint/布局因果；这些科学限制不影响当前产品价值上的停止决定。无新UDP/DHCP/编译选项
计时，无DHCP14开跑。不会把本次停止描述为所有潜在收益都已测到低于噪声。

名字复用原型56320021未送SDK/PGO/真机，已retired-unselected；完整历史保存在
`archive/perf/owrt-perf-lease-name-reuse-20261017-20261017`，private/target逐hash归档到
`/Users/USER/Developer/owrt-perf-evidence-20261016/owrt-perf-lease-name-reuse-20261017/`。
唯一映射仍是`audits/perf-opt-20261015/dns/preparation-worktrees-cleanup-20261017.json`。
K产品/接受身份不改，所有探索失败保留。当前仅最后小HUP一次诊断待收尾，不涉及路由器。
