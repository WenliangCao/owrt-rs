# AX3000T：网络转发与硬件加速研究

2026-09-29。**值得继续研究现有驱动的配置和命中路径，不值得再写一套 Rust 转发器。上一轮“HFO 没有降低 CPU”的结论仍然成立，但只适用于 WED 关闭的 Wi-Fi 上网组合，不能据此否定有线 PPE 或 WED 的收益。**

本轮仅阅读源码、复算已有数据、读取运行状态；没有改变路由器配置、安装包、重启或运行新负载。下一步实验是方案，尚未执行。

## 1. 精确版本与证据范围

| 层次 | 本次依据 |
|---|---|
| Rust 固件 | `ax3000t-rust9-v0.1.0`，项目源码 `a4053dd5d4b4b2dbed3ff8a56d595aeabd33e0d0` |
| OpenWrt 基底 | 25.12.5，buildroot tag commit `f0a60eee2fe051741c643ea6118718aae1ef17fb`，image revision `f5dae5ece4805730c5e2850f8aa84765af2f6b32` |
| 内核/板级 | Linux 6.12.94，`mediatek/filogic`，`xiaomi_mi-router-ax3000t` stock layout |
| 无线驱动 | mt76 `39c960c3ada558b4c2e7915772483d3731573d09`，recipe release 2，`mt7915e` + `MT798X_WMAC` |
| 无线配套 | mac80211 backport 6.18.26；`kmod-mt7981-firmware` 与 `mt7981-wo-firmware 20260221-r1` 已装 |

这些版本分别来自[源码身份](../../manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json)、[补丁清单](../../reports/ax3000t-stock-openwrt-25.12.5/PATCH_MAP.md)和当日包数据库。Rust commit 不是 Linux/mt76 的源码版本。

从现存精确 buildroot 只读复制相关源码，961 个缓存文件与既有 `sources.json` 的 SHA256 一致；mt76 官方源码包 SHA256 与 recipe 的 `7a9f8ea2…2140eb` 一致。Linux 原文件固定到 v6.12.94，再逐项核对相关 OpenWrt 补丁；本次没有宣称完成整个内核重建或全部补丁重放。

原始配置、地址、源码缓存、逐核复算放在 ignored `private/network-research-20260929/{runtime,forwarding}/`；既有负载文件的哈希已包含在[正式测量数据](../../reports/ax3000t-stock-openwrt-25.12.5/DATAPATH_20260929.json)中。

## 2. 六种机制分别处理什么

| 机制 | 实际处理路径 | 本机现状 | 研究价值 |
|---|---|---|---|
| 交换芯片的桥转发 | 同一 LAN 内的有线端口之间，主要是二层交换 | 不能拿这种测速当 NAT 能力 | 作为端点/网卡检查，不作为 Rust 性能项目 |
| Linux 常规转发 | 首包、未卸载流及需回退的包，经过路由、conntrack、nft 等 | 始终保留，快路径未命中时使用 | 检查正确性和 CPU 热点，不重写 |
| 软件 flowtable（SFO） | 已建立、符合策略的转发流，在 ingress 查表，省去后续普通 IP/Netfilter 路径；仍用 CPU | `flow_offloading=1`，当前 nft 有 flowtable | 已使用，后续核对特定流命中 |
| MediaTek PPE / HFO | 将可支持的转发动作下发到硬件；IPv4 NAPT 和 IPv6 路由均有驱动路径 | `flow_offloading_hw=0`，PPE debugfs 存在 | 有线转发优先验证；不是仅加速 IPv4 NAT |
| WED | 连接 PPE 与无线 DMA，提供无线出口/入口相关卸载能力 | `mt7915e.wed_enable=N` | 当前尚未测过的候选，需单独评估成本 |
| Packet steering | 分配 CPU 的 NAPI 线程与软件接收处理 | 已开，见第 5 节 | 配置实验成本较低，不能等同硬件卸载 |

SFO 保存 NAT 信息并维持相应改写；分片、超 MTU、TCP FIN/RST 等仍可回常规路径。因此“首包要经过防火墙”和“后续每个包都经过原 forward 规则”不是同一件事。[Linux flowtable 文档](https://docs.kernel.org/6.12/networking/nf_flowtable.html)

这里的 HNAT 是 PPE 中的硬件 NAT 能力；当前走 Linux flowtable → MediaTek 驱动的集成路径，没有理由为这个名称再安装一套厂商 HNAT 栈。驱动同时定义 IPv4 HNAPT、IPv6 五元组和二层条目，能否使用还取决于产生条目的控制路径。[精确 PPE 驱动](https://github.com/gregkh/linux/blob/v6.12.94/drivers/net/ethernet/mediatek/mtk_ppe_offload.c#L270)

**测试服务器不能放在路由器自己上面来证明转发收益。** 本机终结的 HTTP、DNS、iperf 属于 input/output；客户端经路由器到另一台服务器才是 forwarding。

## 3. 上一轮 HFO 无收益的关键解释

已有结果：软件 → 硬件 → 软件各三轮；硬件候选相对六轮软件的中位数，整机 CPU +0.70%、下载 −5.30%、上传 −1.44%，没有满足 CPU 降低 15% 的收益门。小差异没有被定性为稳定退步。[完整结果](DATAPATH_20260929_RESULTS.md)

源码增加了两个重要限定：

1. mt76 `mt7915/main.c:1776` 检查 WED 是否 active；关闭时直接返回 `-ENODEV`，不会提供 `DEV_PATH_MTK_WDMA`。只有成功后才交出无线队列/BSS/WCID 路径。[精确 mt76 实现](https://github.com/openwrt/mt76/blob/39c960c3ada558b4c2e7915772483d3731573d09/mt7915/main.c#L1764)
2. Linux `mtk_ppe_offload.c:198` 优先接受 WDMA 出口；否则只接受相应有线 netdev/DSA 路径，其他出口在 `:231` 返回 `-EOPNOTSUPP`。所以只打开 HFO、仍关闭 WED，**并没有建立通向 Wi-Fi 客户端的完整 PPE 无线出口**。[精确出口选择](https://github.com/gregkh/linux/blob/v6.12.94/drivers/net/ethernet/mediatek/mtk_ppe_offload.c#L190)

已检索本版本全部相关 target/generic patches：只有 `736-04` 改了该 PPE 文件的统计处理，没有改上述出口分支；mt76 recipe 无附加 patch 目录。该判断没有借用较新的驱动行为。

而且本镜像含 `701` 补丁：配置 flowtable 时允许某设备返回 `-EOPNOTSUPP`，以便混合支持/不支持硬件卸载的接口并回退软件。因此 `nft` 接受 `flags offload` 本身也不能证明所有列出的设备都支持 HFO。[精确混合设备补丁](https://github.com/openwrt/openwrt/blob/f0a60eee2fe051741c643ea6118718aae1ef17fb/target/linux/generic/pending-6.12/701-netfilter-nf_tables-ignore-EOPNOTSUPP-on-flowtable-d.patch)

还有一处测量陷阱：`nf_flow_table_offload.c:955` 累加两个方向的成功回调数，只要不为零就可以设置 conntrack 的 `HW_OFFLOAD`。它不是“两个方向所有字节均由硬件转发”的证明；驱动还需要实际流量形成 PPE BIND 条目。[精确标志设置](https://github.com/gregkh/linux/blob/v6.12.94/net/netfilter/nf_flow_table_offload.c#L955)

所以整机连接表里出现 2～26 条 `HW_OFFLOAD`，最多证明相应连接至少一个方向的驱动卸载回调成功，还包括其他客户端。MediaTek 的 `mtk_foe_entry_commit()` 此时先加入软件跟踪表，后续 `__mtk_ppe_check_skb()` 才驱动硬件条目的实际绑定；因此它不能证明 networkQuality 的每条连接、两个方向及主要字节量都走了 PPE。

| 已被支持的结论 | 仍待验证的判断 |
|---|---|
| 当前 Wi-Fi + 宿舍上游组合，只开 HFO 没有可保留的 CPU 收益 | 独立有线 LAN→WAN 的 PPE 收益 |
| Rust 与保留的原版 fw4 在候选配置下生成相同规则 | WED + HFO 的完整无线快路径收益 |
| 内核接受 offload 标志，某些连接至少一个方向的驱动卸载回调成功 | 测速连接的两个方向是否 BIND、命中字节占比 |
| 无线桥接可达 797/628 Mbps 中位吞吐 | 无线瓶颈中 CPU、airtime、重传、排队分别占多少 |

## 4. 本镜像已经具备的能力与限制

**开启所需的构件已有，缺的是运行验收。** Filogic config 选择 `NET_MEDIATEK_SOC_WED`、RPS/RFS；MT7981 SoC 数据为 NETSYS v2、两个 PPE、支持 accounting。配套 DTS 有 WED、WDMA、WO 内存与控制节点；设备 recipe 已包含 WO 固件。[Filogic 配置](https://github.com/openwrt/openwrt/blob/f0a60eee2fe051741c643ea6118718aae1ef17fb/target/linux/mediatek/filogic/config-6.12)、[MT7981 SoC 参数](https://github.com/gregkh/linux/blob/v6.12.94/drivers/net/ethernet/mediatek/mtk_eth_soc.c#L5299)

| 精确修改输入 | 对本次判断的意义 |
|---|---|
| generic pending `701` | flowtable 允许软/硬能力混合的接口，配置成功不等于所有接口硬件命中 |
| generic pending `702` | MediaTek Ethernet 使用 threaded NAPI，包处理不必跟硬 IRQ 固定同核 |
| generic pending `736-03/04/05` | 改进 PPE 条目跟踪、二层流量统计及表初始化；不能套用裸 Linux 的统计实现 |
| generic backport `731/732/733` | 含 WED 扩展、正确 WED 引用及 DMA32 修正；不是“只装一个 6.12 原版驱动” |
| MediaTek `117`、`940/942/943/944` | MT7981 DTS 与 WO 内存、CPU boot/ILM/DLM 接口配套 |
| mt76 `39c960c3` | 提供 MT798x WED attach、TX/RX ring、forward path 与统计接口 |

补丁内容和顺序取自[固定 OpenWrt 源码](https://github.com/openwrt/openwrt/tree/f0a60eee2fe051741c643ea6118718aae1ef17fb/target/linux)。这些修正的存在不证明某个历史问题发生过；例如 DMA32 补丁针对大内存地址空间，不能推断本机 256 MiB RAM 曾受该问题影响。

WED 默认布尔参数为 false；`mt7915_mmio_wed_init()` 在驱动初始化时判断该参数，attach 成功后才改变 DMA 设备和 IRQ。参数文件可写不代表运行中把 N 写成 Y 就完成了 attach。正式试验应在驱动初始化前通过 `/etc/modules.conf` 的模块选项启用，并确认 attach/WO 加载结果；这是需要另行实施的启动配置实验。[精确初始化代码](https://github.com/openwrt/mt76/blob/39c960c3ada558b4c2e7915772483d3731573d09/mt7915/mmio.c#L633)、[OpenWrt WED 操作说明](https://openwrt.org/docs/guide-user/network/wifi/wed)

运行验收要同时看到参数、attach 状态、相应 RX/TX 活动和指定流的 PPE 条目。仅看到 `wed0` 目录也不够：本机在 `wed_enable=N` 时这个目录已经存在。

兼容与成本边界：

- **内存不是免费。** mt7915 配置 4096 个硬件 TX token、12288 个 WED RX token，并建立 DMA/page-pool 缓冲。实际增量需对比页池、不可回收内存与峰值，不能直接把 token 数当字节，也不能只比较 MemAvailable。DTS 预留的 WO 区域已属于基底配置，不能重复算为启用后的新增量。[token 定义](https://github.com/openwrt/mt76/blob/39c960c3ada558b4c2e7915772483d3731573d09/mt7915/mt7915.h#L63)、[RX 缓冲分配](https://github.com/openwrt/mt76/blob/39c960c3ada558b4c2e7915772483d3731573d09/wed.c#L32)
- **排队和观测会改变。** 真正由 PPE→WDMA 发送的流不再经过相同的软件发送路径；从这条路径推断，不能假设原软件 AQL/整形仍控制这些包。仍走 CPU 的包另论，不能把 `WED=Y` 简化成“全部流都不受 QoS”。SQM/HFO 要分实验，见排队研究。
- **二层桥接与三层路由不同。** 上次 Mac↔Windows 是同桥流量，没有进入 IP forward 的 `flow add`；单开 HFO 不是该测试的完整加速方案。`bridger` 可建立另一类桥接卸载，但当前未安装，优先级低于已有路由路径。[OpenWrt 桥接 WED 说明](https://openwrt.org/docs/guide-user/network/wifi/wed)
- **协议不是全包覆盖。** IPv4 options、安全路径、conntrack helper/seq-adjust 等会被跳过；PPE 驱动也会拒绝不支持的封装和动作。当前 WAN 是 DHCP，不应为 PPPoE、VPN 或多 WAN 的未使用场景先扩张实现。[精确资格检查](https://github.com/gregkh/linux/blob/v6.12.94/net/netfilter/nft_flow_offload.c#L282)
- **无线物理条件不由 WED 修复。** 干扰、信号、客户端能力和空口重传仍在；更宽信道必须另测。泛化 Wiki 的机型/频段说明不能替代该驱动的两个 PHY/队列分支，当前优先研究已测的 5 GHz。
- **队列不宜一起乱改。** 驱动自行设置 WED rings；没找到此版本必须手调 `txqueuelen`、RPS 或 qdisc 才能 attach 的依据。运行 `eth0` 有 16 TX 队列，实际 `wan` DSA 接口只有 1 个 TX 队列，两者不能混为一谈。

## 5. Packet steering：现成但不是自动最优

精确 OpenWrt `packet_steering` 服务读取 UCI，调用通用 ucode；后者按设备分配 NAPI/mt76-tx 线程和 RPS，参数 `2` 是所有 CPU，`0` 是关闭。它不会测量实时负载后持续再平衡，也没有在每个数据包上运行 ucode。[固定实现](https://github.com/openwrt/openwrt/blob/f0a60eee2fe051741c643ea6118718aae1ef17fb/package/network/config/netifd/files/usr/libexec/network/packet-steering.uc)

本轮只读快照：

| 对象 | 实际分配 |
|---|---|
| Ethernet NAPI 两线程 | CPU0 |
| Wi-Fi NAPI 与 `mt76-tx phy0` | CPU1 |
| `eth0` 的 RX RPS mask | `2`，即 CPU1 |
| 两个 AP 接口的 RX RPS mask | `1`，即 CPU0 |
| Ethernet/Wi-Fi 硬 IRQ 累计 | 都出现在 CPU0，但不能据此认定全部包处理在 CPU0 |

从上一轮原始 `/proc/stat` 重算得到以下各轮占用的中位数；每个单核以自身容量为 100%，不是整机百分比：

| 原负载窗口 | CPU0 | CPU1 |
|---|---:|---:|
| LAN Wi-Fi→Windows | 60.79% | 76.26% |
| LAN Windows→Wi-Fi | 32.83% | 72.14% |
| WAN 软件 A₁ | 43.38% | 86.33% |
| WAN 硬件 B、WED 关闭 | 49.79% | 81.74% |
| WAN 软件 A₂ | 51.71% | 83.82% |

这是“CPU1 较忙”的证据，不是“CPU1 已持续跑满”或“瓶颈已定位到某线程”的证据。统计包含 threaded NAPI 在进程上下文的成本，不能只看 softirq 百分比。复算使用现有 `network_profile.cpu_delta()`，原始文件和哈希不变。

因此 `packet_steering=1` 对照 `2` 值得做，但收益待测：RPS 跨核也有 IPI/cache 成本，双核上把所有工作放到所有 CPU 未必更快。`steering_flows` 对本机 socket locality 的优化也不等于 NAT 转发优化。[Linux RPS/RFS 说明](https://docs.kernel.org/networking/scaling.html)

## 6. 实验按成本和决策价值排序

所有实验固定九组件二进制、信道/带宽、客户端位置、端点版本与背景业务；先分别测方向，再测双向。首次 steering 与 HFO/WED 对照都保持路由器无 SQM；将来若选择 SQM，应在该配置下重新验证 CPU 分工。人工部分采用一次一个操作，其余准备与采集自动完成。

| 顺序 | 实验和对照 | 解决的问题 | 成本 |
|---|---|---|---|
| 1 | 相同无线↔有线桥接路径，steering `1→2→1`，HFO/WED 不动 | 当前 CPU 分工是否留有可用空间 | 低；需接收端开机，不需刷镜像 |
| 2 | 有线 LAN 客户端→独立有线 WAN 侧服务器，SFO `1` 固定，HFO `0→1→0` | 隔离无线/宿舍上游，证明 PPE 的实际收益 | 中；需要两个有线端点及隔离测试网络 |
| 3 | 同一个受控 Wi-Fi→路由→有线服务器路径，比较 WED/HFO 四个组合 | 区分 WED DMA 改变与真正 PPE 无线流卸载 | 中高；WED 需驱动初始化，需单独安排 |
| 4 | 胜出配置再测日常 WAN、双向满载与小请求并发 | 实验室收益能否转换为用户体验 | 中；上游不可控，结果作为外部有效性检查 |

纯有线 WAN 实验不能用同桥 LAN 测速冒充。现有 Windows 接 LAN 已可用；要隔离 NAT，还缺 WAN 侧受控有线端点/拓扑。宿舍上游不受我们控制，不能为了省设备把随机外网服务器当同等对照。本轮不要求用户现在重新接线。

四组合保持 SFO 开启：A=`WED0/HFO0`，B=`WED0/HFO1`，C=`WED1/HFO0`，D=`WED1/HFO1`。上次只测了 A/B；C/D 必须真实运行才能回答 WED 的问题。先排除明显无收益的单因素，再决定是否扩大矩阵。

每项开始前冻结：单流及四流、TCP 方向、预热、持续时间、随机/交替顺序；每条件至少 5 个完整窗口，以前后基线判定漂移。先跑短 pilot，只有有效路径成立才开展完整比较。

**命中证明必须对应测试流：**

1. 保存客户端/服务端实际五元组和 NAT 映射；地址只进入 private。
2. 在窗口内部读取对应 conntrack 的原/回复元组和 `OFFLOAD/HW_OFFLOAD`；这两个标志属于连接整体，方向命中要由下一步的 PPE 条目分别证明。
3. 在 `ppe0/bind` 与 `ppe1/bind` 找同一流的 BND 条目，记录包/字节差值；按匹配代码解释 `ib2` 出口，确认有线或 WDMA。只读 bind 即可，不写 debugfs 寄存器。
4. WED 同时检查 attach/WO 日志及 `wed0` 的 RX/TX 状态；目录存在、参数 Y、整机连接计数均不能独立充当通过条件。
5. 如果无法匹配流或统计不前进，标记“未证明命中”；即使吞吐变化也不直接归因于硬件。

PPE debugfs 输出包含原/新元组、状态、`ib2` 及累计字节；本版本还带 accounting 修正。以低频快照取差值并保留采集开销，避免为了证明卸载而高频遍历流表。[debugfs 实现](https://github.com/gregkh/linux/blob/v6.12.94/drivers/net/ethernet/mediatek/mtk_ppe_debugfs.c#L75)

建议冻结的判据：

- CPU 成本比较使用**相同交付吞吐**，由客户端/服务器的发送节奏控制限制在双方都能持续达到的速率，不在路由器上加整形器改变卸载路径；计算 busy CPU-seconds/GiB，另报最大吞吐。候选至少减少 15% CPU 成本，或在明确 CPU 受限时增加至少 10% 吞吐；不能把吞吐下降带来的 CPU 下降算收益。
- 最大吞吐重复窗口的中位数不得下降超过 5%；报告全部轮次及前后漂移，不能拿一次最快结果晋升。
- 同时测路由器管理 TCP 建连、跨路由路径往返及小请求完成时间；至少 1000 个有效延迟样本/条件才讨论尾部，失败单列。候选 p95 不得恶化超过 `max(2 ms, 基线的 10%)`，不增加持续超时。
- CPU 列总量、每核、NAPI/驱动线程、softirq；资源列 page-pool/Slab/不可回收内存及温度。WED 新增内存单独报告，不用一个未经测量的固定“省内存”承诺换 CPU 收益。
- 功能列 IPv4/IPv6、TCP/UDP、短连接、LAN 管理访问及现有隔离规则；驱动 reset、固件超时、接口错误计数和跨区意外放行均直接拒绝候选。

以上数值是**待冻结的工程验收标准**，不是本轮已完成的结果，也不是硬件性能保证。涉及配置与驱动初始化时，再按具体实验取得部署授权。

## 7. 工程取舍

| 值得做 | 暂时不做 |
|---|---|
| 给现有测量工具增加每流、双向 PPE 命中证据及每核成本 | Rust 重写 Linux IP/bridge/conntrack、PPE 驱动或 mt76 |
| 比较 steering 的现成选项；有证据再做小范围绑核调整 | 因 IRQ 集中 CPU0 就固定修改所有 IRQ/NAPI/RPS |
| 评估 WED + HFO，并明确 RAM、延迟、公平性代价 | 用“打开所有加速开关”取代受控比较 |
| 发现具体缺陷后回到 matching driver/upstream 修复 | 混入厂商 SDK HNAT、换固件 blob 或跳到主干碰运气 |
| 把验证通过的配置连同版本和路径证据纳入下一固件 | 为了局域网桥接跑分立即引入 bridger/新常驻服务 |

最先能形成决策的工作是：**补齐命中证据、试现成 CPU 分工、分离有线 PPE，再判断 WED 的收益是否值得它的资源与排队代价。** 这条路线复用成熟执行面，也最容易把结果带回现有九组件固件。
