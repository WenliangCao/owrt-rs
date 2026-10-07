# M6b TCP 内存设计研究

日期：2026-10-07。状态：设计研究，未实施产品优化。范围：OpenWrt 25.12.5 / dnsmasq 2.93 nodhcpv6，Rust 产品源码 `dc1b740d7973838e2ae7f098d0726b0484e55074`。本次只提交本文件。

## 结论与推荐

1. **峰值的主因是主动复制缓存的可变结构，不是每连接复制全部 DNS 记录。** `Arc<Record>` 共享载荷；槽位、HashMap 桶、规范名 key、每名索引 Vec 均复制。空缓存仍复制 448 KiB 槽位。4096 条 M6a 命中记录的视图为 **958,472 B = 936.008 KiB、8,194 次分配/连接**；miss churn 后为 **1,392,648 B = 1,360.008 KiB**，主要来自名字索引桶翻倍和更长的 key。20 份分别为18.282 / 26.563 MiB，尚未加父缓存、连接对象和 allocator 成本。下文给出目标机插桩与静态账的交叉核对。
2. **M6a 的 12–29 MiB“after-drain”不是 Rust 已排空后的长期保留量。** runner 只等 C 子进程归零，Rust 无子进程而直接采样；原始 cache/miss 窗口该时刻还剩 18–23 / 36–42 个 FD（空闲10个）。短窗口插桩已证明视图和缓冲全部释放，另有较小的 allocator 驻留；同M6a负载下，原产品在约41–47ms恢复空闲FD，60s PSS为cache **3.75 MiB**、miss **8.46 MiB**；诊断版1s起确认全部view已释放。导入事务同步消费，没有长期导入队列。
3. **推荐先验证“共享内容/索引分块 + 独立小型 LRU”，保留单 owner、现有 Cache 接口和事务导回。** 普通命中只更新连接自己的 LRU；过期、冲突、插入、CNAME 元数据或多答案轮转才复制相关内容块/索引分片。不能简单给整个 `Cache` 套 `Arc::make_mut`，也不能把 LRU 与内容一起按块复制。后两种做法分别在首次命中或随机命中时退化。
4. **allocator 处理从减少分配次数、拆开寿命开始，不先更换全局分配器。** 消除逐连接的 8,192 个小对象，完成网络与 stale refresh 后及时释放缓存/上游，仅让待排日志保留其所需上下文。任何替代 allocator 或专用 arena 都须作为单独候选测量；不能靠 `shrink_to_fit`、定时 reload 或更短连接寿命承诺归还内存。
5. **CPU 优势是硬门，内存估计不是承诺。** M6a steady 的 C/R3 CPU 为 local 27.343/20.139、cache 34.691/28.164、miss 229.163/138.789 µs/正确请求。分别低约 26.3%、18.8%、39.4%，但 Rust 的吞吐和延迟仍差；“CPU 更省”不能写成整体更快。候选必须同时保住 CPU/请求、尾延迟和服务进展。

## 证据、身份与研究边界

- 工作规则：[AGENTS.md](../../AGENTS.md)、[交付账本](DELIVERY_LEDGER.md) 的工作规则；线程边界：[ADR_THREAD_MODEL.md](ADR_THREAD_MODEL.md) 的单 owner 决策。ADR 后半的六线程拓扑是历史背景，当前实现以源码为准。
- 基线：[M6A_REPORT.md](M6A_REPORT.md) 的 TCP family 表和内存归因；[M6A_MEMORY_ATTRIBUTION.md](audits/M6A_MEMORY_ATTRIBUTION.md)。正式 135 窗口不重分类、不用本轮诊断替换。
- M6a 原始证据：`private/dnsmasq-rewrite/evidence/M6A/`；报告中的 `M6a/` 是既有路径拼写。正式汇总在 `freeze-c3402ba6/final-analysis.{json,windows.csv,comparisons.csv}`，每窗 smaps 在相应 `archives/`；布局在 `memory-layout-05-m6a/layout.json`。大小写敏感文件系统复现时应按归档清单定位，不能创建两套混用。
- 产品 ELF：`37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b`；镜像 C ELF：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。本轮起点 `e53903f1` 与上述产品源码在 `components/dnsmasq`、`components/ubus` 无差异。
- C 源码：`private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/`。本轮核对 `cache.c`、`dnsmasq.c`、`forward.c`、`rfc1035.c` 与已应用 OpenWrt 补丁的 `private/network-research-20260929/dns/dnsmasq-2.93-openwrt/src/` 字节完全相同。配方修订 `f0a60eee2fe051741c643ea6118718aae1ef17fb`，变体与补丁身份见 [OPENWRT_CONTRACT.md](OPENWRT_CONTRACT.md)。本文不引入未编译的 DNSSEC 验证、ipset/nftset 管道操作。
- 新证据统一前缀 **E = `private/dnsmasq-rewrite/evidence/M6B/tcp-memory-design/`**。`source-identity.json` 记录源码 SHA；`instrumentation.patch`、`m6b_alloc.rs`、源码包、构建收据、脚本、ELF、原始样本均留在 ignored/private，不提交实验代码。诊断工作树独立于 main。
- 所有新数字仅代表 Oracle AArch64、4 KiB 页、kernel `6.17.0-1020-oracle`。没有访问或改动物理路由器。

## 1. 当前 Rust 的内存所有权

### 1.1 接受连接到释放

`main.rs::finish_tcp_accept`（约 4053–4147）依次建立本地服务快照、`DnsDaemon::tcp_cache_view`、`DnsDaemon::tcp_snapshot`、日志上下文，放入 `Vec<PollTcpClient>`。生产线程数仍为 1。

| 所有者 | 复制/共享方式 | 何时释放、注意事项 |
| --- | --- | --- |
| `Cache::snapshot` / `Cache` | `#[derive(Clone)]`；`slots: Vec<Slot>` 全拷贝。每个 Entry 的 `Arc<Record>` 只增引用；Entry 的 authority Name 若存在则深拷贝；local CNAME target 的 Arc 共享 | 随 `PollTcpClient` Drop。父缓存后来逐出旧 Record 时，仍有视图引用的载荷必须保留，这是语义要求 |
| `names: HashMap<Vec<u8>, Vec<usize>>` | 桶、每个规范名 key、每个索引 Vec 都深拷贝；克隆索引按 len 而非原 capacity | 随视图释放。M6a 每名一个 A，父索引 capacity 4，克隆 capacity 1 |
| `reverse_chain` / `pending` / 标量状态 | Vec 克隆；LRU prev/next、slot generation、failed、long_names、lease_generation 独立 | M6a 无反向记录、accept 时无 pending，克隆两者不分配；不能推广为所有配置都是零 |
| `LocalDnsService` | `DnsConfig` 和 `Hosts` 深 clone；leases、interface records 为 Arc；临时构造的默认 leases/interfaces 随后被替换 | M6a `no-hosts`、简短配置，额外 heap 很小；真实大量 hosts 的深拷贝是另一个规模项，不能以本轮数字替它作上界 |
| `TcpDnsService` | routing rules/groups、source binding、policy/config 按连接创建；`TcpUpstream` 含每组 server 和持久连接 | 无线程、无共享上游会话；Drop/clear 关闭全部上游 FD。上游 TCP 内核收发缓冲不在进程 PSS 内 |
| `TcpFramer`、input、Writing frame | 初始空 Vec；input 在首次 Reading 时 resize 到4096 B（即使读到WouldBlock也保留容量），framer 保留所达容量；回复 frame 按实际长度创建 | 没有在 accept 时给每连接预分配 64 KiB 接收缓冲。大报文、分片和背压可扩大容量，需单独验收 |
| 上游 `Exchange` / `pending_query` | query/frame/reply Vec；一次在途交换；完成后 pending 被 take/drop，连接本身保留 | 不应把最大 65535 B 回复长度乘以所有连接当成普通 A workload 的实际值 |
| `TcpLogContext` | 80 B inline；共享目标描述符的 Rc，空 VecDeque，不复制父日志队列、不增加 FD | 当 `network_alive=false` 但 `finish_tcp=false` 时，当前实现保留整个 client。这是低概率但真实的寿命耦合 |
| `query_events`、MAC、stale_query | 按需 Vec；M6a 无 query log、无客户端 EDNS 身份、无 stale refresh | 不能忽略启用这些选项后的条件成本 |
| 父 `clients` 容器 | 连接对象 inline；本轮布局 `PollTcpClient=2536 B`，20 个连接使 capacity 增至 32 | `swap_remove` 不缩容，关闭后仍保留 **32×2536=81,152 B**；这不是 12–29 MiB 残留的解释 |
| `CacheTransaction` | commit 时复制已提交记录的 name/data/authority，CNAME 不携带 child target；一个临时变量 | `run_forward` 在返回 owner 前调用 `import_tcp_cache_transfer` 消费并释放；没有“等所有旧连接关闭”的队列 |

释放路径在 `main.rs::step_tcp_clients`（约 4149–4243）：处理转发/日志 → 标记 network_done、关闭下游 → flush/finish 日志 → `swap_remove`。stale 答复后的上游刷新尚在进行时，不能因为下游已关闭就提前销毁视图。退出、超时和错误也须经过相同资源边界。

### 1.2 4096 个短名 A 的精确账

单位为 allocator **requested bytes**，不含 allocator 元数据/空闲页，不是 PSS。M6a 名字 `q%04x.m6a.test` 的 wire key 长 16 B；RR payload 已共享。

| 一份 cache view | 字节 | KiB | 分配次数 |
| --- | ---: | ---: | ---: |
| 4096×112 B Slot | 458,752 | 448 | 1 |
| HashMap：8192 物理桶×(48 B key/value descriptor + 1 B control)，加布局尾部 | 401,416 | 392.008 | 1 |
| 4096×16 B canonical key | 65,536 | 64 | 4096 |
| 4096×8 B cloned singleton index | 32,768 | 32 | 4096 |
| **合计** | **958,472** | **936.008** | **8194** |
| Record/name/RDATA 新载荷 | 0 | 0 | 0 |

满父缓存原 requested 账为 1,433,640 B（1,400.039 KiB），因为还拥有 Record Arc、记录名/RDATA，且 singleton index Vec 的初始 capacity 为 4。空视图只有第一行。负缓存 authority name、多 RRset、reverse_chain 和旧载荷被视图钉住时需另加，不能套用 A-only 表。

20×空视图 = 8.75 MiB；20×满视图 = 18.282 MiB。故 local 的约 11 MiB 峰值在没有动态记录的情况下已经可以由槽位复制解释；cache 相比 local 多出的约 13 MiB 包括约 9.53 MiB 的索引/key/小 Vec requested、副本分配的 allocator 成本和父缓存。miss 不应沿用936 KiB：原生负载器构造 `u%012x.m6a.test`，wire key为24 B；churn后视图scope实测1,392,648 B，与458,752槽位＋802,824桶＋98,304 key＋32,768索引完全相等。桶分配由8,192变成16,384个物理桶，20份新增 **8.281 MiB requested**，已解释大部分hit→miss峰值差。槽位容量限制记录数，却不限制std HashMap在删除/插入历史下的桶容量；触发每次rehash的内部growth/tombstone细节未插桩。父桶同样翻倍。历史载荷仍需计量，但不是此差值的默认归属。

### 1.3 目标机实验

本轮两层实验均只在隔离 net/mount/pid namespace 内进行，通过既有 `oracle_build.sh`、唯一共享 Cargo target 和 `.dnsmasq-build.lock` 构建/串行运行。临时 allocator 包装**仍调用原 System**，按成功 alloc/alloc_zeroed/realloc 与 dealloc 的 Layout 记录 live requested bytes、分配/释放次数和尺寸分桶；不加每分配 header，不替换 malloc，不使用另一个 libc。接入 accept 各阶段的净 live 差，1 Hz 输出 client 数、client Vec容量、input/framer/log/upstream payload容量。构建 link map 表明实际链接的是 Rust 1.98.1 自带 `aarch64-unknown-linux-musl/lib/self-contained/libc.a`，其中有 `__malloc_context`、`__malloc_size_classes`、`__malloc_alloc_meta`（mallocng）。**SDK gcc作为linker不等于使用SDK的动态libc。** 诊断 ELF 增大了 text，另有1个诊断文件FD，不能直接用其PSS或CPU替代交付ELF。

第一层为归因控制：`E/oracle/private/meter-{local,hit,miss}/`，20条连接先hold、每条查一次、全部关闭，再5s预热＋60s负载（steady 2,000/s，末20s saturation），每连接100query重连；hit先UDP填4096条；结束后累计等待60s，再SIGHUP作**诊断干预**。这是为控制对象数设计的短窗口，不是M6a正式窗口。`samples.jsonl`、每个label的smaps/rollup、`heap.log`、`load.json`及`cleanup.json`保留全部结果。无query logging、无DHCP/helper/TFTP。

| 受控20连接、发完一条query后 | local | cache hit |
| --- | ---: | ---: |
| 无连接时live requested B | 471,780 | 1,448,914 |
| 20份cache view B | 9,175,040 | 19,169,440 |
| 本地config/hosts净新增：20×B | 20×407 | 20×237 |
| routing/upstream/policy净新增：20×B | 20×1,455 | 20×1,308 |
| client容器 B | 81,152 | 81,152 |
| input B | 81,920 | 81,920 |
| framer B | 880（44/连接） | 680（34/连接） |
| 日志queue payload B | 0 | 0 |
| **总live B（逐项相加精确等于全局计数器）** | **9,848,012** | **20,813,006** |
| 同时PSS / Anonymous KiB | 11,980 / 9,824 | 25,420 / 23,264 |
| 全部关闭后live B | 552,932 | 1,530,066 |
| 关闭后相对初态增加 | **只有81,152 B client容器** | **只有81,152 B client容器** |

local/config scope 10次分配、forward scope 12次；hit/miss分别9/10次。这是scope内成功分配次数，含被替换的默认leases/interfaces等临时对象，不等于最终存活对象数。cache scope的1 / 8194次和448 / 936 KiB则与结构账相等。miss第1000次accept实测`cache 1392648 8194`，证实churn后表扩大，不是把UDP静态估算外推给TCP。

短窗口miss的上游payload（`pending_query + Exchange.frame/reply`）1Hz采样合计最高1,148 B，query临时对象可能在采样间隙消失，不能称瞬时上界；upstream固定状态已包含在每连接1,308 B scope内。三组所有日志queue容量/载荷采样均0，排空后input/framer/upstream也均0。每连接Writing回复、解析、capture/import临时分配由全局计数器覆盖，但本轮未分别标记其瞬时峰值；普通A包下它们不是MiB级常驻项，大SOA等场景不能套这个结论。

**第二层：纠正“after-drain”的含义。** 审核冻结 `tools/dnsmasq/m6a_window.py:533–541` 发现它只等 `tree.child_processes == 0`，不等待Rust client/FD回到空闲值。C等待wait/pipe回收，Rust从一开始就是零child。下表直接取全部五轮R3的原始formal JSON；完整路径、时间差在 `E/m6a-drain-audit.json`，不是新实验：

| M6a R3场景 | r01 | r02 | r03 | r04 | r05 |
| --- | --- | --- | --- | --- | --- |
| local after-drain PSS KiB / FD | 2148/10 | 2144/10 | 2144/10 | 2640/10 | 2148/10 |
| cache after-drain PSS KiB / FD | 15968/19 | 15968/19 | 15124/18 | 18120/21 | 19360/23 |
| miss after-drain PSS KiB / FD | 26120/36 | 26124/36 | 28156/40 | 29392/42 | 29396/42 |

三组empty都是10 FD；after-drain距load-finished仅1.29–3.34ms。FD足以否定“已完全排空”的前提，但其数值不是精确的活视图数：close/drop与smaps读取会交错。原M6a没有60s后样本，不能从它单独判断永久泄漏。这个问题影响排空后内存解释，不推翻窗口内的CPU、吞吐、峰PSS或原135个窗口的方法记录。

补充的 `E/oracle/private/exact-{meter,control}-{hit,miss}/` 重用冻结M6a runner、native loadgen/upstream、精确镜像rootfs只读基底＋overlay；30s预热、120s测量、steady10,000/s＋末30s saturation、20客户端、100query、TTL3600/cache4096、与r01相同seed/1s timeout、CPU0/1/2/3和构建锁。`exact_window.py`仅增加诊断读取及排空后样本，不改负载/产品。使用 `--preflight` 明确标记研究用途；`--implementation rs`只为允许绑定实验SHA，**meter仍是opt3，不是M6a的opt-s组**。另两窗直接运行原37f85d22产品ELF，排除插桩导致回收的可能。它们是单次解释性复现，不是新性能资格。

下表为PSS KiB / FD；peak列只列PSS。四窗均通过runner原有质量检查，wrong/transport/timeout均0；诊断CPU不参与比较。

| ELF / profile | 采样peak | 原after-drain | 第一次附加采样：实际间隔 → PSS/FD | 约1s | 约60s |
| --- | ---: | --- | --- | --- | --- |
| 原产品 / cache | 24,908 | 14,272/17 | 41.453ms → 3,856/10 | 3,848/10 | **3,840/10** |
| 原产品 / miss | 33,576 | 28,156/40 | 47.089ms → 8,660/10 | 8,660/10 | **8,660/10** |
| 诊断 / cache | 25,420 | 18,628/22 | 44.117ms → 4,368/11 | 4,352/11 | **4,352/11** |
| 诊断 / miss | 34,208 | 30,032/43 | 45.926ms → 9,296/11 | 9,296/11 | **9,296/11** |

原产品与M6a的peak重现，未修改ELF也在约41–47ms后恢复空闲FD；60s真实保留PSS是cache **3.75 MiB**、miss **8.46 MiB**，而不是12–29 MiB。四个窗口均保留5s样本，数值与60s相同（原cache的1s至5s另减8 KiB file PSS）。`analysis.json`是机械汇总；每窗`proc-snapshots/{after-drain,drain-plus-0.01,drain-plus-0.1,drain-plus-1,drain-plus-5,drain-plus-60,cleared}.json`及同名smaps是原始出处。

heap日志1Hz，`proc_row.heap_line`只是该时刻最近一条，最多旧约1s；因此44ms附近仍显示20clients的旧heap行不能与已归零的FD/PSS强行配对。1s/5s/60s样本才用于判断live对象。时间列使用JSON的实际monotonic差，文件名`drain-plus-0.01`只是wrapper的名义等待，包含runner收尾后实际约44–46ms的延迟，不能称“精确10ms释放”。

**仍存在的真实保留是什么。** 诊断完整M6a负载在1s至60s，cache live=1,529,904 B、Anonymous=2,196 KiB；miss live=2,026,580 B、Anonymous=7,140 KiB。所有client=0，458,752 B槽位分桶只剩父缓存一份，query/log/upstream容量归零；重连没有留下视图或导入队列。前者约0.69 MiB、后者约5.04 MiB的“Anonymous减live requested”还包括allocator元数据/空闲空间、栈和未由Rust GlobalAlloc标记的少量libc对象，**不能把差额逐字节当作纯碎片**，但它远大于普通连接缓冲，且不属于存活视图。

miss在60s后执行SIGHUP，仅减少 **671,744 B** live，Anonymous却从7,140降至约1,692 KiB；父空槽位、802,824 B名字桶和client容器仍保留。这是“释放父cache小对象使大量分配空间可归还”的干预证据，支持mallocng的分配组/空闲空间被长命对象钉住，排除“20份视图仍存活”的解释；尚未逐meta/group证明具体内部策略。SIGHUP还改变服务缓存状态，**不是建议的产品回收机制**。

两个诊断准备失败也保留：`failed-rollup-parser`把smaps映射首行误作数值，及`failed-stderr-trace`因产品重定向stderr丢失诊断行；均停止并清理进程，未计入有效结果。修复只在研究脚本/临时构建里进行。证据包/验证/清理身份见末节。


## 2. 必须保持的 C 语义合同

以下编号用于候选方案和验收逐项对照。源码行号指上述 2.93 参考副本；Rust 对照以 `dc1b740d` 为准。

| 合同 | 精确 C 行为、边界 | Rust 必须保持 |
| --- | --- | --- |
| **S1 接受快照** | `dnsmasq.c:2102–2197`：普通 `-k` 路径先准备 MAC、pipe，再 fork；继承当时全部用户态 cache、hosts、DHCP、本地配置、routing/server 状态。父后续 UDP 学习、reload、lease publication 对已 fork 子不可见；反向也不直接可见 | 在接受流程既定快照点固定内容/索引/本地与路由代际，不能第一次 DNS query 到来才取“当前父缓存”。`-d` 不 fork，是独立的当前父状态模式 |
| **S2 固定时钟** | `forward.c:2367–2790 tcp_request(confd, now, …)` 的 now 参数在循环中不刷新。缓存查找 TTL、stale 判定、子新条目绝对 deadline 都用此值；连接实际受 150s alarm、100-query 上限约束 | 保持 `accept_clock`；父导入使用父当时的 now。不能以 wall-clock aging、提前 expire generation 或 idle 缩短连接替代。已有 1s TTL 等待 2.2s 的固定时钟合同 |
| **S3 子私有写入及读副作用** | 子命中会改 LRU/多答案轮转；过期/无效 CNAME 清理、冲突移除、逐出、pending、slot uid 全是私有。后续同连接可复用自己成功学到的记录，也会看到自己失败插入前已发生的移除 | “只有新增记录的 overlay”不够：必须表达删除、顺序、LRU、generation、referenced 和事务失败状态。普通子 cache hit/eviction 不回写父 LRU 或父指标 |
| **S4 导出集合与时机** | `forward.c:2716` → `process_reply` → `rfc1035.c:789–1209` → `cache.c:843–918 cache_end_insert`。每次成功 commit 发 `PIPE_OP_INSERT`、记录序列、长度 -1 终止标记；在下游 reply 前写 pipe，不等 EOF/100-query。父是否已消费由调度决定，不要求收到父 ACK | 只导出实际成功提交且未被丢弃的记录，含受配置允许的 A/AAAA、CNAME、negative/SOA/generic/reverse；不导出整缓存或 LRU/删除清单。非缓存源/CD/RA 等不 commit 路径可能已有子私有提取/移除；它们不导回。失败 commit 无事务；成功空事务必须保留 |
| **S5 有序事务** | `new_chain` 头插；`cache_end_insert` 按该链弹出。CNAME target 紧邻在 alias 前；`cache_recv_insert:985–1015` 按紧前的**父插入结果**重建 target。父再次插入头链并 commit，存在可观察的双重反序 | 保持捕获顺序和完整 RRset 轮转顺序；禁止 sort/dedup，禁止传 child EntryId/旧 local target/跨代际 slot pointer。空事务也调用父 start/end，清掉旧 pending |
| **S6 父当前状态与失败边界** | `cache_recv_insert:969–1056` 用父 now，`ttl=difftime(ttd,now)` 后走 `really_insert`，不再次 min/max clamp；与父当前 hosts/lease/CNAME 冲突。期间不回 poll，不交错另一查询。后段失败不撤销前段已发生的移除/逐出，未成功提交的新条目不可见 | 保持 `Cache::import_counted`、当前 local-match callback、绝对 expiry 和 parent-owned counters；不是数据库式全事务回滚。过期浮点转 unsigned 的 C 边界沿用已记录 oracle/显式 saturation，不宣称 ISO C 保证 |
| **S7 跨连接/EOF 顺序** | `dnsmasq.c:1935–1958` 每轮按 tcp pipe slot 扫描，就绪者处理一次事务后 return。每条 pipe FIFO；跨 pipe 由就绪和 slot 决定，**不是全局 accept 顺序或连接完成顺序**。EOF 在 -1 前则不 commit，但父已执行的移除可能存在。进程 slot 直到 child 已 wait 且 pipe EOF 两者都满足才释放（`:1632–1652`） | 保持单 owner 一次消费一个完整 typed transaction、同连接顺序；不新增跨连接排序等待队列，也不批到 close。当前 Rust typed transfer 并非可注入半条 pipe 的传输层，保留已有故障差异边界，别声称 Rust 实际复现了所有 C pipe 故障 |
| **S8 生命周期/副作用** | C 处理最多 100 query；150s 上限，stale reply 后可关下游再刷新；上游持久 TCP fd 在连接结束关闭；父计数来自真正导入，子本地指标不整体合并。日志 flush 可以延长子退出 | 保持单线程有界状态机、100-query/150s、stale refresh、上游复用/失效/关闭、日志目标快照、连接容量/指标。只在不再有 DNS 工作时释放 DNS 状态；日志 drain 仍保留其所需许可和目标 |

现有 runtime 守卫比概述更重要：`dns_tcp_cache_diff.py`、`dns_tcp_writeback_diff.py`、`tcp_stale_oracle.py`、`tcp_cd_policy_oracle.py`、`cache_transfer_diff.py`/`cache_transfer_rust_diff.py`、`cache_partial_eof_*`、`cache_reverse_transfer_*`。旧报告中“尚未接入”的历史状态不覆盖 M5 最终资格；测试内容和已知差异仍是设计参考。

## 3. 候选方案

### A（推荐验证）：内容与热 LRU 分离，内容块和名字索引分片 COW

**表示。** 保留 `Cache` 的调用接口和当前算法。将 Slot 拆为内容 `Option<Entry> + generation` 与单独的 LRU 链接；head/tail/prev/next 用 checked `Option<NonZeroU32>`，配置上限 5,000,000 可表示，零容量仍显式处理。每个 owner 私有两个链接数组（8 B/slot），而不是在每次命中复制包含 Entry 的块。

内容按64 slots一个固定数组块 `Arc<Block>`（最后一块填充、实际capacity另记），根指针8 B；name index 按固定 hash 的高位分成64个 `Arc<HashMap<…>>` 分片，保留稳定的 shard 选择种子，不在 clone 时重置。每个 Cache 拥有根指针数组，clone 根和 LRU。块/分片仅在具体写入点 `make_mut`。规范名 key 使用共享不可变 bytes；名字索引保持现有有序语义，用 singleton inline 与共享 Many slice 避免分片 detach 时逐名再分配。`Record` 继续共享，不把 mutable `Entry` 与它混为一体。64 是首个需要冻结验证的参数，不是已测最优值。

**为何不同于旧 chunk32。** [TCP_SNAPSHOT_CHUNK_RESULT.md](TCP_SNAPSHOT_CHUNK_RESULT.md) 的候选仍因 population CPU 和小容量 p95 被否决；本文不撤销结论。其“一次 mutable lookup 写 Slot 块”的问题在这里通过独立 LRU 避开；名字索引也不再全克隆。旧 `top` 方案首次 lookup 全复制的负结果仍有效。新机制必须重新做完整 gate，不能引用旧 correctness pass 冒充迁移通过。

**合同对照。** S1：accept 持有所有根，不再读父新根。S2：clock 仍在 client。S3：owner 私有 LRU，内容/索引每个 mutator 先 detach；reverse_chain、pending、long_names、lease_generation 同样按既有顺序独立。S4–S7：继续调用原 capture/import，只替换存储访问，不修改导出集合、时机和顺序。S8：生命周期不变，销毁最后一个根才销毁对应块；日志 drain 可另存小对象。

**内存模型。** N=4096、V=20，预计内容 slot 80 B（112−32）、每块约 5,120 B＋共享头，128 个根指针合计约 1 KiB/owner；LRU 32 KiB/owner。普通 fresh singleton A hit 不修改内容/索引，20 views 的结构增量约 **660 KiB**，相对现在 18.282 MiB 减少约 96%。小配置/连接 heap 另计。父布局及 hash 分片取整可能抵销部分 slot 缩小；先以现有父 requested 1.37 MiB 作为保守基数，必须用新 layout 校准。

miss 用实际 detached blocks/shards 和被钉住旧载荷计算：

`requested = parent + V×(LRU + roots + session) + 5136×D_content + ΣD_index_bytes + pinned_old_payload + transfer/scratch`。

D 是**所有 owner 根最终引用的额外唯一块版本数**，不是写操作总数，也不只是最后一连接的数。假设 20 个连接各插入 100 个单 A，slot 逐出大体连续，则每连接约 2–5 个内容块，加父版本共享约数百 KiB；随机 name 替换可能触及 64 个索引分片的约 50 个，索引 detach 仍可贡献数 MiB。先冻结的设计预算是 local/cache 峰值 **3–5 / 4–7 MiB PSS**、miss **8–16 MiB**，全部断连后 **3–6 MiB**；这些是验收目标范围，**不是已测收益或最坏上界**。分片容量、generation 分布与 mallocng 驻留必须在真实负载中核实；长时间 idle snapshot＋父满速 churn 可接近 V 个全索引/内容版本。

**CPU。** accept 从 O(N) 的 8194 次分配降为根数组/LRU的少量分配和约 32 KiB 连续复制；命中多一次分块地址计算，LRU 无 COW。插入多一次共享检查，首次写 block/shard 有复制成本，父 cache 填充也可能变慢。不能由删除 fork 推导进一步的百分比加速；要求全路径 CPU 门通过。

**文件/函数。** 主要 `dns/cache.rs` 的 `snapshot/new/clear/start_insert/insert_at_counted/commit_inner/import_counted/lookup/lookup_reverse/remove/free/unlink/link_head`、CNAME/authority/publication mutators；少量 `dns/daemon.rs::tcp_cache_view`、`main.rs::finish_tcp_accept/step_tcp_clients` 生命周期接线。`cache_engine.rs/cache_reply.rs` 尽量不改协议算法。Name key/index helper 保持 private，小接口，不引入通用持久集合库。

**风险/复杂度：中高。** 遗漏一个修改入口会破坏隔离；whole-cache reload 必须发布新根；CNAME slot generation不能因块复用错认；多 RRset 的 rotation 和 reverse 顺序尤其敏感。hash 分片容量和 O(N) expiry pressure scan 可能增加 miss CPU。已有拒绝证据要求先通过 primitive gate，不能直接迁移主产品。

### B：不可变版本根 + 连接稀疏差异视图（MVCC）

**表示。** accept 保存父 commit epoch/root，子只存 changed slots、tombstones、name/reverse ordering overrides、LRU link overrides、pending 和私有 generation。查找先差异再不可变基底；子新记录只进自己的差异，再以原 typed transaction 导回。父必须保留旧 root 或带版本的 slot/index/link；仅给现在的可变 HashMap 加 epoch 标记并不能提供旧快照。父历史按仍活跃的最老 epoch 回收，不能靠定时器丢弃。

**合同对照。** S1–S2：epoch＋fixed clock。S3：每种可变状态均能 override，删除必须遮住 base；LRU需完整可导航语义，不能仅维护“最近访问集合”。S4–S7：导回仍从成功 commit 的记录构造，不能把 overlay 全量 merge 入父；父冲突与先前失败前缀保持原算法。S8：完成 DNS 工作释放 epoch pin，保留日志所需内容；若 overlay 过大，**物化同一个旧逻辑视图**，不得偷偷换成当前父缓存。

**内存/CPU估算。** 100 次命中最多修改约 3×100 个链链接点；按带 hash 元数据的 48–96 B/override 预算约 14–28 KiB/连接，20 连接约 0.3–0.6 MiB。100 次 miss 另加约 15–40 KiB 的新记录/索引/删除 delta；多记录回复可远超此数，100 query 不是100 record。峰值目标与 A 接近（local/cache 3–6 MiB，miss 6–14 MiB），断连 3–6 MiB，**仅对短连接 A workload 的预算**。保留成本还有 `parent_write_rate × oldest_pin_age × bytes_per_version`；150s idle 连接可钉住极大量版本，这个项不能省略。

accept O(1)，普通查找至少增加 base/overlay 访问，每次 LRU hit 可能写多条 hash delta；父每次修改维护历史，恰好会伤到想保留的每请求 CPU。需要给 delta 物化门槛明确空间界与测量，不能在达到门槛时拒绝原本合法的 query。

**文件/复杂度。** 除 A 的 mutators，还要重写 `Cache::get/invalid/id`、迭代扫描、publication ordering、history 回收与 EntryId 域。高复杂度；父和子读路径几乎处处需要版本解析。现有 primitive/transfer gate 全部适用，另需 idle pin/churn、压缩旧 epoch、delta tombstone、物化前后完全同态测试。暂不推荐：收益潜力高，但比 A 更容易把协议实现变成版本数据库。

### C：保持私有视图，压紧连续存储并控制释放寿命

**表示。** 不共享可变 Cache；先压紧链接，再将视图名字索引改为连续 hash/索引数组，借用其持有的共享 immutable payload/key，不再每名分配一个 Vec key 和 singleton Vec。用显式 slot/offset 和有序 RRset 表保持顺序；大数组由普通 Vec/Box 拥有，整份视图 Drop 一次释放。第一阶段不写通用 allocator，不增加全局内存池。必要时再单独评估视图专用 mmap arena，其安全和释放合同单独审查。

**合同对照。** S1–S3：私有结构天然隔离，仍固定 accept/clock；连续表必须保留完整 RRset 顺序、删除和 CNAME slot identity。S4–S7：capture/import 不改。S8：完整 Drop；在 DNS 完成后可让日志 drain 脱离 cache。不能通过降低100-query/150s、驱逐尚存活视图或只保留“可能会问到的记录”节省内存。

**估算。** Slot 链接压到 8 B 后约 88 B/slot，即352 KiB；8192桶×16 B＋4096×4 B有序索引约144 KiB，另加控制字/容器，预算 **0.50–0.60 MiB/view**，20 份仍约10–12 MiB；empty view仍352 KiB。目标峰值 local **9–11 MiB**、cache **15–19 MiB**、miss **18–25 MiB**，断连 **3–7 MiB**。连续表实际 bucket layout 和 allocator释放尚未测量，这些数字是结构预算加基线/余量，不是空间上界。accept 仍O(N)复制，但逐名小分配消失，CPU可能下降；索引扫描/更新的改变也可能抵销收益。

**文件/复杂度。** `cache.rs` 的 names/reverse 索引与所有 reader/writer，可能需独立 private snapshot index helper；`wire.rs::Name`只暴露必要的借用比较，保持 wire 编码不变。中高复杂度，主要风险是索引顺序、删除和重建，而不是历史回收。它是 A 未通过 CPU门时可单独冻结的备选；不能把它当成只改几个 Vec 的小补丁。

### 方案比较与 allocator 决策

| 项目 | A 分离 LRU + 分片 COW | B 稀疏差异视图 | C 连续私有视图 |
| --- | --- | --- | --- |
| 普通 cache hit 接受成本 | 约33 KiB复制＋根引用 | O(1) pin | 约0.5–0.6 MiB复制 |
| 每次 hit 的新增工作 | 块访问，私有链更新 | overlay hash读写/历史解析 | 连续私有链更新 |
| 主要最坏内存项 | 很多不同 snapshot 导致块/索引全 detach | idle epoch 钉住高频父历史 | V×完整视图，较易预算 |
| 协议算法侵入 | 尽量保持 | 很大 | 索引算法改变 |
| 分配/释放策略 | System分配固定块；最后根引用释放，无跨连接空闲池 | System分配私有delta；父版本按最老pin批量释放，不按年龄强删 | System分配少量连续Vec；完整Drop；专用mmap arena仅作后续独立候选 |
| 本轮选择 | **先做隔离原型并严格验收** | 后备研究 | A失败后独立比较 |

allocator共同策略：先保留已交付的 `System`/musl mallocng；避免逐连接大批短命 small allocation 与长命父记录混居，减少需要分配/回收的总对象数。释放 DNS 状态不等于强制 PSS下降，仍要用 live-bytes和smaps双指标验收。不要把 glibc `malloc_trim` 当作 musl 接口；不要在 idle 时周期性重启或 flush cache 掩盖残留。全局 jemalloc/mimalloc 会增加依赖、二进制体积和跨 DNS/DHCP/TFTP 的风险，只有 A/C 在对象规模明显下降后仍未满足保留量目标，才冻结为单独对照；需同样的musl目标、ELF/APK和完整功能资格。普通 Vec的`shrink_to_fit`只调整请求容量，不能保证返回页。

## 4. 与条目结构瘦身的关系

- **强耦合：规范名 key和singleton index。** A的分片 detach 必须共享 key、内嵌单索引或共享多索引，否则复制一个 shard仍制造许多小分配。仅复用immutable key并保留`Record.name`原wire字节，不先改全局Name/API；大小写、binary label、日志与响应编码不能被强行规范化。索引必须保持顺序，不采用无序集合。
- **中度耦合：LRU/slot布局。** 将两个`Option<usize>`（共32 B）压到8 B并与内容分离，是A避免hit触发内容COW的关键。slot generation仍u64；不要为省字节缩短防ABA的generation。
- **弱耦合：小RDATA内嵌、Record allocation合并。** 当前快照已共享Record，所以给A/AAAA内嵌4/16 B主要节省父/历史载荷及transfer复制的分配，不能再把4096份RDATA乘20当视图收益。先保留Vec，不扩大本次迁移。日后从`cache_engine.rs`的借用packet slice直接构造；先Vec再转inline不能消除原分配。
- 已有 [TCP_SNAPSHOT_INLINE16_RESULT.md](TCP_SNAPSHOT_INLINE16_RESULT.md)、[TCP_SNAPSHOT_ONE_INDEX_RESULT.md](TCP_SNAPSHOT_ONE_INDEX_RESULT.md) 和 [TCP_SNAPSHOT_COMPOSITION_REVIEW.md](TCP_SNAPSHOT_COMPOSITION_REVIEW.md) 的拒绝/预测分别保留。它们基于更早布局，不能把各自最优数字相加当新方案通过。

## M6b 第1b CPU基线修订

M6a 的 CPU 数字保留为历史测量，不能继续作为方案 A 的 C 对照门。UDP
主循环修复提高了轮询频率，导致固定轮次工作在 TCP、reload、DHCP 和 UDP
请求中的占比发生变化；M6a 的约 20 µs/Rust、29 µs/C 只描述旧主循环。

Oracle 的第1b perf debug companion（同源、非交付 ELF）与中间矩阵结果已经
把 `SinglePoll::step*`、`wait_for_files`/`poll_fds`、logger flush 和循环内
metrics/UBus 调用列为新的归因候选。方案 A 的 CPU 硬门暂停到第1b
`d52d5cac` 完成短基线后再冻结。冻结时使用同一配置、同一镜像 C、同一
CPU/正确回答分母，定义
`u=(daemon cgroup CPU usec + TCP child CPU usec)/correct replies`，并要求：

* `median(u_A) <= 1.05 × median(u_R3_1b)`；
* `median(u_A) < median(u_C_1b)`，即保持相对**新** C 基线的 CPU 优势；
* 吞吐和 p95 不回退超过 5%，S1–S8 零新增差异，错误和 FD 泄漏为零。

在新基线冻结前，不得用 M6a 的 C/R3 数字判定方案 A 通过或失败。

## 5. 实施步骤与验收门

本节是后续实施依据，不表示本次授权修改产品。

1. **先修测量合同，再冻结实现基线。** 未来runner必须等Rust的client/view/pending-transaction计数归零，或至少FD回到经确认的空闲值并连续稳定；另外固定1s/5s/60s采样，不再把child=0视为Rust drain完成。本轮只记录这个修订需求，不修改工具。随后记录M5源码/ELF、精确C、toolchain/libc、工作负载和layout。先完成第1b短基线，再冻结上面的`C_1b/R3_1b` CPU门；S1–S8零新增差异；steady/saturation每正确请求CPU相对R3_1b不劣于5%，吞吐和p95不劣于5%，错误零；小容量150/空缓存不以大缓存收益豁免。性能门提前冻结，失败保留，不事后换中位数或挑重跑。
2. **在独立worktree做A最小存储原型。** 第一提交只分离LRU与内容访问，不改变wire/提取/事务；逐mutator清单证明detach。随后内容块、索引分片/共享key按可审查单元推进。保留parent无snapshot时的低成本路径；实际尺寸、分配次数、drop余额先于计时检查。没有把实验代码直接搬进main的许可。
3. **先跑精确C primitive和视图隔离门。** 复用`dns_cache_diff.py`、`cache_policy_transaction_diff.py`、`cache_answer_diff.py`、`cache_reverse_order_*`、`lease_cache_diff.py`、`cache_transfer_*`。必须保持retained snapshot前后全状态、TTL、flags、计数和RR顺序；让故意共享LRU/漏detach/调换CNAME顺序的负控确实失败。覆盖capacity0/1/150/4096及满缓存、长名限额、single/many、A/AAAA/CNAME/negative/SOA/generic/reverse、过期和stale、失败后pending。
4. **服务合同门。** `dns_tcp_cache_diff.py`：accept后父UDP填充不可见、同连接自写可见、后连接可见、TTL固定；`dns_tcp_reload_diff.py`和DHCP lease publication：旧/新代际；`dns_tcp_writeback_diff.py`：每query即时导回和真实父指标/冲突；`tcp_stale_oracle.py`/`dns_stale_refresh_diff.py`：下游关闭后刷新；`tcp_cd_policy_oracle.py`、`dns_do_cache_diff.py`、EDNS：extract-only、no-cache与源身份；`tcp_upstream_diff.py`/`tcp_caller_diff.py`：选择、复用、失败与超时。实际采用M5最终族driver/fixture，旧单脚本只是覆盖定位。
5. **资源和生命周期门。** `dns_tcp_ingress_diff.py`、`dns_tcp_daemon_diff.py`、`dns_tcp_capacity_diff.py`、`dns_tcp_accept_failure_diff.py`；100-query正常EOF、150s、RST/半帧/上游EOF/最大回复、慢读写、日志FIFO与重开、stale refresh、TERM。网络结束但日志排队时独立记录DNS状态释放及tcp gauge；不得为了节约内存提前宣布C意义上的slot可用。记录所有FD、线程/子进程、client/view/pinned-root/transaction计数。
6. **新增与设计直接相关的压力场景。** 20和配置上限并发；空/半满/4096/大缓存；固定同代际命中、随机多RR轮转、100query重连、单条150s idle snapshot＋父UDP连续替换、错峰accept＋父/子同名冲突、reload/lease更新与导入交错；每次记录live requested、块/分片/历史版本数量、PSS/Anonymous、峰和0/1/5/15/60s排空值。循环至少10批检查live余额不随重连总数增长。M6a A-only20client不能代替这些边界。
7. **新冻结后的正式性能资格。** 先确认C/R同配置/ELF和原生负载器100-query合同；最终沿用M6a完整9profile×C/R3/候选×5轮或事前明确批准的全量资格协议（135窗口），CPU包含C父子、PSS比较进程族、CPU0/1/2/3隔离、持共享构建锁，不并行build/test。普通A场景A的预算先作为待验证目标；实际未达则报告失败和原因，不降阈值。UDP/DHCP/reload也必须复测，因为parent cache和allocator改动会影响它们。
8. **功能/APK与交付。** 最终同ELF跑受影响M5全部族及M2/资源/压力/生命周期要求，绑定source/ELF/APK体积和行为差异。169项原有通过不自动覆盖新表示。router部署属于后续单独请求及恢复门；本设计不含部署动作。

## 6. 未确定事项与退出条件

- 诊断构建的分配计数不能作为CPU对照；新表示的CPU、tail和PSS都未测，不把模型当收益。
- mallocng具体meta/group的驻留分配没有逐组标记；本轮可区分Rust对象存活与页驻留，不能声称每页属于某个Vec或某个size class。若需要更精确的内部归因，下一步应在相同静态libc的临时构建记录group/live-mask与mmap/munmap，而不是换glibc跑heaptrack再外推。
- 多RR、巨大SOA、反向条目、hosts量、日志阻塞和长寿命视图的最坏界必须通过设计对应计数验收；不得仅以100query假定delta≤100records。
- A若未通过父population/UDP-miss或小缓存tail门，停止迁移并保留失败；再独立冻结C，或继续B的可行性研究。沿用旧候选拒绝结论，不拼接分别失败实验的最好部分。
- 本次结束要求：产品文件与起点一致，仅本文件入Git；实验源码/证据本地归档并逐文件SHA校验；Oracle本任务进程全部退出、运行目录删除；本任务临时worktree清理，不触碰其他会话分支或未提交文件。

## 7. 本次交付与清理收据

只新增本设计文档；main上的产品代码、测试工具、账本和其他会话文件未修改。归档源码与临时worktree全部154个component文件逐一相等；随后移除本任务detached worktree。Oracle每个有效窗口正常退出、未强杀daemon，四个cgroup均清空并删除；归档时无本任务进程/挂载，验证后已删除 `/home/ubuntu/dnsmasq-m6b-design-20261007/` 和传输tar。共享Cargo缓存依仓库规则保留。`E/oracle-cleanup.json`记录删除后路径不存在和进程为空；没有触碰其他运行目录或物理路由器。

原始tar保留numeric ownership、mode、xattr及特殊文件；本地`E/oracle/`为方便读取而仅提取普通文件，不能代替原tar的文件系统元数据。`local-verification.json`证明 **1,523个普通文件SHA全部匹配、1,623个元数据条目匹配**。归档前进程检查曾把自身sudo父进程误计为任务进程，修正ancestor排除后才通过；未据失败检查删除任何运行数据，记录在`archive-preflight-failure.txt`。

以下路径均相对于E；完整SHA用于核验本次结论，不要求把private证据入Git：

| 文件 | SHA256 |
| --- | --- |
| `oracle-evidence.tar.gz` | `b7183d0f2516c3fa0d6a6a2a2ac59c79a7a63837e60b8996e0fcde5e6bde3d48` |
| `source-identity.json` | `c655acf4b78de30b10d8673e1554f526ff1026877c51701c0fea2668dc5b9863` |
| `m6a-drain-audit.json` | `b356e5e490059a43f71426291ccdf08349a3ccf033a69df854ebceb413f3624e` |
| `oracle/private/build2/build.json` | `e7bbf9f9f881155f8472fd2a5fec8c7ad29073809ac8b8a1713ce1b1223baad8` |
| `oracle/allocator-identity.json` | `57fba3749a87dadf2fa6c93c9ae7795c76773183b7ee58a7104688d5c6d0f995` |
| `analysis.json` | `b05cb7845d3b3609b9231b856c681d7e891b28f2bfb8dfca565d915d0d37dc13` |
| `local-verification.json` | `b2a6f7f1f14640102c7f278a76df1c060f62c2b175f82c81fa89c3ebc320e922` |
| `oracle-cleanup.json` | `6a8d3cd55d1382816769220b2b4e7c5ca6af365cce9308179dbd926dc4efe813` |

诊断ELF为 `dd8bdc42446443f2b9522440c4b5580049b3112fdbfcd63ac6740529912f2585`，2,629,680 B；build2/link.map为 `21ff2e30fc709503c0e97989d7639a2675a4e4edc0fd2ee599366102f1767109`。原产品ELF未替换。复核可先运行private的`verify_archive.py`核验tar与清单，再运行`analyze.py`从原始JSON重建汇总；它们仅为本研究留档，不是提交的产品工具。
