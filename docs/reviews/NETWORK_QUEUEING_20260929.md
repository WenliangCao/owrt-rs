# 排队、限速与满载延迟研究

2026-09-29。**值得研究的是“下载、上传忙起来以后，其他请求还能否及时得到回应”。优先补足定位证据，再评估现成 SQM/CAKE；目前没有理由重写排队算法，也没有证据证明本机必须长期限速。**

本轮只读核查设备、匹配源码与既有测量，没有安装包、变更配置或再次压测。既有生产固件保持不变。

## 1. 已知现状与能成立的判断

依据是[前轮整机实测](DATAPATH_20260929_RESULTS.md)、[精确源码身份](../../manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json)及本轮只读快照。
当前 AX3000T 使用 OpenWrt 25.12.5 / Linux 6.12.94，软件 flow offload 开、硬件 flow offload 关、WED 关；packet steering 已开。

| 证据 | 观察 | 判读 |
|---|---|---|
| Wi-Fi→有线 LAN | 中位吞吐 797 Mbps，CPU 68.61% | 这条路径没有 WAN，仍已消耗相当处理资源 |
| LAN 上传期间，本机 TCP 建连 | p95 从空闲 13.65 升至 50.90 ms | 无线、本机收发及客户端调度值得查；不是宿舍 WAN 拥塞的证据 |
| WAN 双向负载期间，本机 TCP 建连 | 软件窗口 p95 100.90 / 97.29 ms，各有 1 次超时 | 本机访问也受满载影响，但尚未得到公网 RTT 的排队增量 |
| 默认 qdisc | `net.core.default_qdisc=fq_codel` | 系统并非完全没有主动队列管理；此值不证明每个接口当前都挂该 qdisc |
| 无线 AQL | 两个 PHY 的 `aql_enable=1` | 已有按预计空口时间限制积压的机制，不应先把 AQL“重新打开”当优化 |
| 无线队列快照 | 两个 PHY 的 `fq_backlog=0`；5 GHz 历史 `fq_overmemory=497` | 只是单时点与累计计数，没有对应窗口增量，不能用来诊断本轮卡顿 |
| TX 队列 | `wan` 1，载体 `eth0` 16，两个 AP netdev 各 1 | 设备层次很重要；不能由 eth0 的队列数推断 WAN 整形天然能用 16 队列 |
| 已安装工具/包 | 无 SQM、CAKE、IFB、tc；`tc` 调用返回 127 | 新实验需要先准备匹配包及依赖；本轮没有实际 qdisc/filter dump |

前轮延迟是 Mac→路由器 HTTP 端口的 TCP 建连时间，含无线争用、重传、操作系统调度等；不等同于 ping RTT、公网业务时延或内核队列驻留时间。
`networkQuality` 的 367～404 Mbps 下载、461～491 Mbps 上传中位值来自 Wi-Fi、宿舍上游及动态服务端的组合，不能直接抄成固定 SQM 限速值。
该轮样本也不足以承诺 p99 或把两个超时归因到特定队列。

## 2. 要区分的三类等待

| 等待位置 | 典型辨别证据 | 合适的处理方向 |
|---|---|---|
| Wi-Fi 空口与无线发送队列 | LAN 内流量就能重现；无线探针变差、有线探针稳定；retry/airtime/AQL 增量随负载变化 | 信道与干扰、客户端信号、既有 airtime/AQL、发送路径与 WED 对照 |
| 客户端或路由器 CPU 调度 | 有线和无线本机探针一起变差，单核 softirq/时间挤压上升；吞吐随流数出现平台 | 先查每核负载、IRQ/RPS 分配；再评估卸载或减少处理工作 |
| WAN/宿舍上游排队 | 有线客户端至路由器稳定，但固定公网端点在满载时显著变慢 | 在可控边界做 SQM/整形；确认是否是本路由器流量造成拥塞 |

三者可以同时存在。AP 的下行 AQL 也管不到 Mac 自身的上行发送队列；路由器上挂 WAN CAKE，更不会改善完全留在 LAN 桥内的文件传输。
按字节公平与按空口时间公平也不同：慢无线终端传同样多字节可能占用更多空口，WAN 按主机公平不能代替无线调度。
Linux 的多核收包分配解决处理工作落在哪个核，qdisc 解决数据按什么顺序、速度发出；两者要分别测。[Linux 网络扩展机制](https://docs.kernel.org/networking/scaling.html)

## 3. 各方案实际做什么

**FQ-CoDel** 把连接分开排队，并在持续积压时发出拥塞信号，让小请求较少被大下载拖住；它本身不是指定“最高 400 Mbps”的整形器。
如果网卡能以 1 Gbps 发给上游，而宿舍瓶颈只有更低速率，本机 qdisc 可能一直很空，队列却堆在上游；此时仅设置默认 FQ-CoDel 不够。
要让它控制该瓶颈，通常还要搭配 HTB/TBF 等速率控制。其默认公平对象是流，多开连接的设备仍可能分得更多带宽。[RFC 8290](https://www.rfc-editor.org/rfc/rfc8290.html)

**CAKE** 把速率控制、主动队列管理、按流/主机隔离及封装开销补偿结合起来；更适合少量明确参数的家用网关试验。[CAKE 原始论文](https://arxiv.org/abs/1804.07617)
上行是在包离开 WAN 前控制发送；下行常把 WAN 收到的包重定向到 IFB，再在这个虚拟出口排队。
下行控制通过拥塞反馈影响发送方，不能撤销包抵达本机前已经经历的等待，也不能指挥宿舍其他住户的流量。

**SQM** 是配置这些内核机制的脚本，不是在 shell 里逐包转发。把 SQM 脚本翻成 Rust 不会让 CAKE 处理每个包的成本自动下降。
匹配版本的 `piece_of_cake.qos` 使用一个 best-effort 类，分别配置 WAN 出口与 IFB，并以 ingress filter 重定向下行，适合作为首次简单候选。[匹配脚本](https://github.com/tohojo/sqm-scripts/blob/20ba92639546075d8e39346dcb88a3cdfe8ee903/src/piece_of_cake.qos)

和九组件的集成边界是 UCI、procd reload trigger、netifd 的 `ifup/ifdown` hotplug；正式纳入镜像前，要验证配置重载与接口重新建立时队列正确重建，WAN/WAN6 共用设备不会遗留或重复挂接。[SQM 服务入口](https://github.com/tohojo/sqm-scripts/blob/20ba92639546075d8e39346dcb88a3cdfe8ee903/platform/openwrt/sqm-init)、[hotplug 入口](https://github.com/tohojo/sqm-scripts/blob/20ba92639546075d8e39346dcb88a3cdfe8ee903/platform/openwrt/sqm-hotplug)

若要验证“一个人开很多下载，也不能挤走其他人”，可另设上行 `dual-srchost`、下行 `dual-dsthost` 的候选；IPv4 NAT 场景要保留内部主机识别。
公平对象主要是 IP 身份，不等于设备账户，IPv6 多地址、隧道及多个主机共用 NAT 要单独检查。[iproute2 6.18 CAKE 手册](https://github.com/iproute2/iproute2/blob/v6.18.0/man/man8/tc-cake.8)

首轮不同时增加应用分类、DSCP 优先级、ACK 过滤和自适应带宽。每增加一种政策，都增加分类正确性、客户端兼容与结果解释成本。
特别是共享宿舍网络，空闲测速高、晚间容量低时，单一固定限速是效率与时延的折中；目前还不知道其变化范围，不能先承诺某个数值最佳。

## 4. 匹配版本核查：已经有多队列 CAKE，但本机条件有限

源码基线为 OpenWrt `f0a60eee2fe051741c643ea6118718aae1ef17fb`，packages feed `5caa62e0bc9f7fb9b0c12a23267bceb7724214dd`。
原生 Rust 固件沿用该内核与软件包体系；不要拿 OpenWrt 主干的新功能说明直接当当前已安装能力。

| 项目 | 匹配源码结论 | 对实验的影响 |
|---|---|---|
| `sqm-scripts` | `1.7.2-r1`，提交 `20ba92639546075d8e39346dcb88a3cdfe8ee903` | 用这一版冻结脚本行为 |
| 依赖 | `tc`、`ip`、`kmod-sched-cake`、`kmod-ifb`、`iptables`、`iptables-mod-ipopt` | 不是只增加一个小脚本；需核算完整依赖和镜像增量 |
| `tc` | iproute2 `6.18.0-r2`；`tc-tiny` 是默认 provider，依赖 sched-core | 不必为了初试直接引入 tc-full/BPF 的更多依赖 |
| CAKE 模块 | `kmod-sched-cake` 包含 `sch_cake.ko`，依赖 sched-core | `cake_mq` 同在此模块，不是另一个独立内核包 |
| 内核 | generic 6.12 补丁回移了 Linux 7.0 的 cake_mq 系列及后续修正 | “6.12 的 CAKE 一定只有旧单队列实现”不适用于此镜像源码 |
| 默认行为 | SQM `USE_MQ=0`；只有显式开启、目标有多 TX 队列且验证 qdisc 成功才选 cake_mq | 安装 SQM 不等于自动得到多核整形 |
| IFB 创建 | `use_mq=1` 时，脚本可按 CPU 数创建多 TX 队列 IFB | 本机下行有单队列/双队列对照的研究入口，尚未安装验证 |

对应证据：[SQM 包配方](https://github.com/openwrt/packages/blob/5caa62e0bc9f7fb9b0c12a23267bceb7724214dd/net/sqm-scripts/Makefile)、[内核模块配方](https://github.com/openwrt/openwrt/blob/f0a60eee2fe051741c643ea6118718aae1ef17fb/package/kernel/linux/modules/netsupport.mk)、[tc 配方](https://github.com/openwrt/openwrt/blob/f0a60eee2fe051741c643ea6118718aae1ef17fb/package/network/utils/iproute2/Makefile)、[SQM 多队列选择与 IFB 创建](https://github.com/tohojo/sqm-scripts/blob/20ba92639546075d8e39346dcb88a3cdfe8ee903/src/functions.sh)。

当前内核包身份为 `6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1`。准备实验包时同时核验架构、内核 ABI、包哈希与依赖闭包，而不是只看“同样是 6.12”就混用当前在线仓库的 kmod。

`cake_mq` 在多 TX 队列上建多个 CAKE 实例，共享配置并根据活跃队列调整发送速率；它增加并行机会，不保证连接均衡分布，也不等于把整台机器的两核算力全部交给单条连接。
在该实现中公平调度状态分布于子队列，因而还须实测不同流数/主机分布下的公平性，不能只看汇总速率。[匹配多队列补丁](https://github.com/openwrt/openwrt/blob/f0a60eee2fe051741c643ea6118718aae1ef17fb/target/linux/generic/backport-6.12/700-05-v7.0-net-sched-sch_cake-share-shaper-state-across-sub-ins.patch)、[作者的设计与局限分析](https://netdevconf.info/0x19/docs/netdev-0x19-paper16-talk-paper.pdf)

**本机上行的实际限制：`wan` 只有一个 TX 队列，SQM 挂这里会选择普通 CAKE。**
不能为了得到 eth0 的 16 个队列就把规则挪到 eth0：它是 DSA 载体，设备范围、标签和 LAN/WAN 路径都会改变，需要另行证明计费对象正确。
下行 IFB 多队列可以作为后续候选；是否把工作分到两核、是否比 FQ-CoDel 方案划算，都要测。

## 5. 卸载与排队：需要按路径判断

| 机制 | 与排队的关系 | 本研究怎么处理 |
|---|---|---|
| 软件 flow offload | 跳过部分 IP/Netfilter 慢路径，仍可能经过设备 tc；不是“所有 QoS 都失效” | 首轮为隔离变量关掉，CAKE有效后再单独恢复软件卸载验证 |
| PPE 硬件 flow offload | 已命中硬件的数据可以绕过 CPU 上的 tc/IFB 队列 | 首轮保持关闭；流量未穿过整形器就谈不上该整形器保证总限速 |
| WED | 改变无线 DMA/硬件协作路径；与 HFO 的连接命中不是同一条件 | 保持关闭；以后另测 WED 与无线队列/时延的组合，不笼统判为AQL全关 |
| GRO/GSO/校验和卸载 | 合并/分段及校验工作，不是 Netfilter flow offload | 首轮不一起关；CAKE 的分段政策另有成本与延迟取舍 |
| RPS/packet steering | 把软件处理分配到 CPU | 保留现状；单核瓶颈有证据后再单独试，不视为硬件转发 |

Linux 6.12.94 的 `sch_handle_ingress()` 在 `nf_ingress()` 前；软件 flowtable 的直接出口调用 `dev_queue_xmit()`。
这支持“选对实际入/出口时，软件卸载可以保留 tc 控制”的判断；却不保证挂在任意 VLAN/bridge/隧道上的规则都一定命中。[收包顺序](https://github.com/gregkh/linux/blob/v6.12.94/net/core/dev.c)、[软件 flowtable 出口](https://github.com/gregkh/linux/blob/v6.12.94/net/netfilter/nf_flow_table_ip.c)
被跳过的 Netfilter 钩子也意味着依赖这些钩子的每包 DSCP/mark 分类需要另外验证；“整形还有效”不等于“所有分类规则都等价”。[Linux 6.12 flowtable 文档](https://docs.kernel.org/6.12/networking/nf_flowtable.html)

匹配 mt76 的 `mt7915_net_fill_forward_path()` 只有 WED active 才提供 `DEV_PATH_MTK_WDMA`，PPE 随后可选择 WDMA 出口。
据此推断，实际走 PPE→WDMA 的包可以绕开原软件无线排队；但普通软件 TX 路径仍保留 AQL 处理，`wed_enable=Y` 这个开关本身不足以证明所有包都绕开 AQL。[mt76 匹配实现](https://github.com/openwrt/mt76/blob/39c960c3ada558b4c2e7915772483d3731573d09/mt7915/main.c)、[PPE 出口选择](https://github.com/gregkh/linux/blob/v6.12.94/drivers/net/ethernet/mediatek/mtk_ppe_offload.c)

## 6. 建议实验矩阵：先定位，再选择

以下是待单独授权执行的方案，本轮没有实施。先把依赖装配、配置差分和撤销过程准备好，再进入短时对照窗口；无需现在重开 Windows。
同一单元至少五轮，固定端点、方向、连接数和包长政策；每轮 30 秒负载，并取得足够的空闲与满载探测样本。
探测可固定每秒 5 次，五轮每个目标约 750 次；p95 使用成功样本的 nearest-rank，超时另计，协议始终一致，不把 TCP 建连与 ICMP RTT 混算。
先使用一个固定公网端点，再用第二端点验证结论；不把更换服务器造成的差异算作路由器优化收益。

| 顺序 | 对照 | 回答的问题 | 进入下一步的条件 |
|---|---|---|---|
| Q0 | 无线 LAN 单向上传/下载 + 有线、无线到路由器的同步探测 | 前轮本机延迟主要来自无线还是全机处理？ | 取得两种接入视角及队列/每核增量 |
| Q1 | 有线客户端公网单向上传、单向下载、双向 + 空闲 | 上游排队是否可重复出现？ | 公网满载延迟增加、有线本机探针稳定，才按 WAN 排队方向推进 |
| Q2 | 原配置 → 关闭软件卸载、无 SQM → 原配置 | 单纯关闭软件卸载花了多少 CPU/吞吐？ | 把这个成本从 CAKE 成本里拆开 |
| Q3 | 无卸载基线 → 单队列 CAKE → 无卸载基线 | 保持其他条件时，控制速率能否降低满载等待？ | 先上行，再下行，最后双向；各自按匹配稳定容量设候选 |
| Q4 | CAKE → 同速率 HTB/TBF + FQ-CoDel → CAKE | 若 CPU 成为代价，较简单方案是否更合适？ | 只在 Q3 有延迟收益但成本明显时做 |
| Q5 | 已合格 CAKE → CAKE + 软件卸载 → CAKE | 能否保留整形、公平性并收回处理成本？ | tc字节、实际限速、IPv4/IPv6、主机公平性都通过 |
| Q6 | 单队列 IFB → 显式 cake_mq IFB → 单队列 IFB | 下行能否有效利用两核？ | 仅在下行单核瓶颈出现且包/驱动能力确认时做 |
| Q7 | 已合格候选，两台主机各1流，再1流对8流 | 多连接设备会不会挤压另一台？ | 固定相近 RTT/端点；分别覆盖 IPv4 NAT 与 IPv6 |

Q0/Q1 同时记录：每核 busy/softirq、NAPI 与 mt76-tx 线程 CPU、`softnet_stat` 丢弃与 time-squeeze、接口字节/丢包、无线 retry/airtime/AQL 增量、TCP 重传及探测失败。本机使用 threaded NAPI，部分包处理记入线程上下文，不能只由 softirq 百分比判断成本。
进入 SQM 后再记录 `tc -s` 的带宽、backlog、drop/ECN、每类统计与 IFB 字节；用同步差值证明测速流量经过预期队列。
不能把 AQM 主动 drop、网卡接收丢包、TCP 重传和探测超时合并成一个“丢包率”。

限速从**有线、同端点、多轮且上游相对稳定**的实测容量推导，先对照约 95% / 90% / 85% 三档；这只是搜索范围，不是默认生产值。
上下行分别求值，并说明速率是 IP 有效载荷还是包含封装开销；DHCP 只说明接入方式，不能说明宿舍后续链路的全部计费开销。
若换时段后容量大幅变化，先评价固定整形是否值得；自适应控制另立候选，不能假定它自动解决共享上游拥塞。

## 7. 预先冻结的判定标准与撤销

建议收益门：基线公网满载 p95 增量至少 20 ms 且可重复；候选让该增量降低至少 50% 且绝对下降至少 10 ms。
建议代价门：有效吞吐保留匹配基线至少 85%，并达到按同一计量口径换算的限速目标至少 90%；任一核连续 5 秒达到 95% 且伴随吞吐或延迟恶化，则判处理能力不足，降低目标或改方案。
这是下一轮待冻结的工程取舍，不是前轮已经证明的成绩，也不是游戏、语音的普遍质量保证。

公平性候选另外要求两主机在1流对8流时，五轮中位吞吐之比落在 0.8～1.25，并交换主机角色复核；MQ 方案同样要过这项。
IPv4 和 IPv6 都必须受控；管理访问、DNS、DHCPv6/RA 正常，候选不得出现可重复的新超时、持续内存增长或流量绕过。
没有可重复的 WAN 排队增量，或收益必须以明显不可接受的吞吐损失换取，就不部署 SQM。

撤销按本轮创建对象的清单执行：停止候选 SQM、移除其 IFB/ingress filter/qdisc、还原原有队列配置及服务状态、恢复软件卸载 1 / 硬件卸载 0。
实验前必须取得可重放的队列/过滤器基线与配置身份；不是执行一遍 `tc qdisc del` 就算恢复，也不删除其他服务创建的对象。
持久配置、包集合与运行规则分别核对；实验引入的软件包只能按记录还原依赖集合，原始数据取回 private 后再清理临时文件。
本轮没有新增服务或包，因此现在无须执行这些撤销步骤。

## 8. 投入判断与尚缺证据

| 方向 | 是否值得 | 成本与边界 |
|---|---|---|
| 区分无线、本机 CPU、WAN 排队 | **优先做** | 主要是测量工具和短对照，直接决定后续有没有必要限速 |
| 现成 CAKE/FQ-CoDel + SQM | **有条件值得** | 需要依赖、CPU余量和带宽折中；不是打开就免费提速 |
| cake_mq 下行 IFB | **后续候选** | 源码已具备入口；只有证据显示下行单队列瓶颈才值得增加变量 |
| 应用优先级、自动限速、复杂策略 | 暂缓 | 当前问题与需求尚未定位，先避免维护更多分类和控制逻辑 |
| Rust 重写 CAKE、FQ-CoDel 或 tc | 不立项 | 热点在成熟内核路径，控制脚本语言与逐包吞吐不是同一件事 |
| Rust 状态展示/配置接入 | 小范围可做 | 等策略选定后复用 tc/netlink 与现有 ubus，不新增常驻高频采样服务 |

仍缺：有线公网基线、同端点空闲/满载延迟、每核与队列同步增量、当前各接口实际 qdisc/filter、宿舍容量的时段波动、CPU受限时CAKE实际能力、安装后包/内存增量。
既有 797 Mbps LAN 成绩和约 65% 的 Wi-Fi 上网 CPU 占用，不能线性外推“还能跑多少 Mbps CAKE”；双向整形增加的工作也不是单向结果的简单复制。
最值得交付的结果是可解释的吞吐—延迟—CPU取舍，选择有证据的现成机制；本机是否应长期运行 SQM，留给上述对照回答。

本轮证据缓存位于 ignored `private/network-research-20260929/queueing/`，设备快照位于 `private/network-research-20260929/runtime/`；公开文档未包含客户端地址、MAC、完整配置或固件文件。
