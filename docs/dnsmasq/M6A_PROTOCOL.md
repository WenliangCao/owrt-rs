# M6a 冻结测量方案

2026-10-06，版本1。用户已接受M5体积。本方案提交后才开始任何性能试跑或正式测量；M6a只测量、归因，产品源码不修改。M6b须报告后另由用户决定。结果仅代表Oracle构建机，不代表物理路由器。

## 身份与环境

主组R3固定M5源码`dc1b740d7973838e2ae7f098d0726b0484e55074`、opt-level3 ELF `37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b`、1,929,256B。C固定镜像ELF `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。Rs由同一不可变源码、Rust1.98.1/同SDK/static/strip/panic-abort/no-unwind，仅opt-level改s，经`oracle_build.sh`和唯一共享Cargo目录构建；产物SHA/字节和全部source inputs写入冻结manifest。Rs仅性能对照，不能据此宣称功能或APK资格。

三个组均在同一精确OpenWrt25.12.5 rootfs只读共享基底的临时overlay内运行。每窗口独立net/mount/pid namespace、初始配置和缓存；不使用host库替代C镜像库。记录内核、CPU、页大小、HZ、工具版本、rootfs身份、ELF/source/工具/config SHA、种子和时间。Oracle4个CPU：daemon及其继承子进程taskset CPU0；原生DNS上游CPU1；原生负载器和reload的TFTP客户端CPU2；controller/采样CPU3。实际每个进程的allowed CPU核对，不设CPU quota。

正式窗口持有`/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock`，期间禁止任何其他构建、测试或fuzz；外部负载扫描持续执行，发现污染使该轮作废。子代理只访问本地源码和回拷证据，做分析/报告。OS必要服务保留，记录各核/proc/stat忙时、steal和负载器CPU，不将环境瓶颈误称daemon上限。归档/压缩在窗口之间进行。

## 固定配置和负载

通用DNS：daemon `127.0.0.1:15353`，唯一原生上游`127.0.0.1:15354`，cache-size4096、cache-rr=TXT、dns-forward-max1024、TTL/local-ttl3600、no-resolv、no-poll、关闭0x20编码、query logging关闭，不启用ECS/MAC/rebind等会改变输入的可选策略。keep-in-foreground、同root用户/组；stderr保留。全部DNS question IN；flags/ID/question/rcode及每个RR的owner/type/class/RDATA/合法TTL均校验。固定A `192.0.2.1`、AAAA `2001:db8::1`、TXT `m6a`，CNAME为`m6a.target`并有上述A终值。记录上游UDP/TCP requests/replies/drop与按phase的计数。

20客户端，UDP每client独立socket，TCP20个逻辑客户端保持连接复用，每socket最多1在途；相同源、轮次种子和名字算法用于三组。种子为`0x4d364100+round`，round=1..5。名字`q%04x.<prefix>`为重复bank，`u%012x.<prefix>`为每请求唯一名字；CNAME加`cname-`前缀。负载器记录完整发送/完成monotonic时间、状态和client/qtype/kind/phase，抽取固定有限raw请求/回复以独立验真。

正式窗口前的TCP合同澄清（第2次工具冻结，正式数据仍0）：首C pilot在1969次正确warmup后正常关闭连接，精确`config.h:20 TCP_MAX_QUERIES=100`／`forward.c:2457,2489`及Rust `main.rs self.queries==100`都限制每连接100次查询。三组客户端都按该上限复用、完成100个response后关闭并为下一请求重连，记录connections/reconnects。正常上限关闭不算错误，意外EOF/timeout仍保留行为结果；不能因此丢慢/坏产品窗口。保持原20客户端、rate、时长、轮次、阈值，不修改被测产品。实际首send→reply延迟不含connect以前的等待，scheduled lag和吞吐反映它；CG CPU包括窗口内重连触发的fork/缓存快照/回收，TCP结果代表100-query循环复用模型，不能称纯无重连稳定连接或独立握手吞吐。初版协议与失败pilot均保留。

| 正式profile | 负载与初态 | 120秒测量阶段 |
| --- | --- | --- |
| udp-hit | 4096纯A逐条预填；禁上游回答后4096正确命中、零上游请求证明；bank循环 | 前90秒目标10,000请求/s，后30秒20并发closed-loop |
| udp-miss | A，每请求唯一名字；缓存容量仍4096，实际转发/回复计数 | 同上 |
| dns-mixed | bank256，index=seq%256、每5个seq有1miss；每1280完整周期各key恰4hit/1miss。index%20为10A/5AAAA/3CNAME/2TXT，256bank实际130A/65AAAA/37CNAME/24TXT；报告actual类型与命中比例及尾部余数。先填全bank | 同上；不将256names冒称4096live entries |
| upstream-fault | 唯一A，目标1,000请求/s；测量t=30..60s上游静默丢包，其他时间正常。客户端timeout1s、20在途上限 | 分0..30、30..60、60..120s；不加饱和阶段 |
| tcp-local | 20持久连接，`localbank.m6a.test`本地域名规则固定A | 前90秒10,000/s，后30秒closed-loop |
| tcp-cache | parent先填/证明4096A，再accept20连接；上游禁回答，零上游请求 | 同上，C fork及Rust缓存视图成本不隐藏 |
| tcp-miss | 20持久连接，唯一A、相同TCP上游 | 同上 |
| dhcp-lease | 20固定MAC `02:00:00:6a:00:00..13`、CLID=1+MAC；loopback别名127.0.0.10..29/8，server127.0.0.1:67、client68；固定20host映射、lease3600、no-ping。DORA→renew→release循环 | 目标20完整cycle/s；release无ACK，单列send，停负载后在daemon仍活着时核验leasefile收敛为空；吞吐单位cycle/s，不能将release send当应答 |
| reload-concurrent | DNS目标1,000/s、bank256 A；TFTP固定1024B文件（第i字节=i%256）与每秒10 RRQ/完整ACK；每10秒把reload-proof.m6a.test从192.0.2.10顺次改到.21并HUP，测量内t10..110共11次；每次核验变更可见与完成时间；HUP后实际cache miss/上游量单列 | 120秒，DNS/TFTP正确量及间隙、reload发布延迟分别报告 |

七个场景族，其中TCP分三个profile，共9个正式profile。每窗口先同组同配置独立试跑：2秒warmup＋10秒测量，fault事件改为3..6秒、reload在3/6/9秒、饱和为最后3秒；标为pilot，绝不进入正式结果。试跑须计数、raw语义、CPU affinity、采样、daemon退出/FD/PID/挂载/cgroup回收通过。随后全新初态正式30秒预热＋120秒测量；不沿用pilot状态。预热、填充、验证、尾排空最多1秒和清理均不计正式吞吐。每轮原始binary/JSON/smaps/config及执行回执保留。

每profile至少5个有效轮次，每轮三组交错。整个固定顺序：round外层1..5，profile依上表顺序，组次序分别为`C,R3,Rs`、`R3,Rs,C`、`Rs,C,R3`、`C,Rs,R3`、`Rs,R3,C`。作废轮次原证据保留，在该组位置立即用fresh attempt重跑，不挑最快值；固定配置、时长、阈值不得因结果调整。工具正确性bug允许修，保存旧SHA/错误和受影响轮次、明确作废后重跑。

## 指标与资格

每阶段报告实际秒数、offered/完成/正确/错误/timeout/transport数，correct-in-window/实际时间为吞吐；错答和测量结束后才完成的请求不计吞吐。p50/p95采用全部正确latency排序的nearest-rank；每阶段至少10,000个正确样本才报p99。超时/错误及其时间分布另列；fault成功延迟有幸存者偏差，须同时看各阶段availability、timeout和恢复完成时间。steady latency从实际首send算，另报scheduled→send lag及调度未发/在途限制；closed-loop结果只称20并发完成量，不称开放式daemon绝对最大QPS。

daemon使用独立cgroup2；primary CPU为`cpu.stat usage_usec`阶段首尾差，含TCP子进程及已退出/回收CPU。每正确完成请求CPU=阶段CPU微秒/正确完成数，另列CPU秒及负载器/上游CPU。/proc树self+父waited-child和结束wait4只作交叉验证，避免双算。固定边界capture lag须≤250ms；缺cgroup或测量边界失败，该轮无资格，修环境/工具后重跑，不静默换口径。

CPU3按1Hz采parent与完整子树：RSS/PSS、FD、thread、child数。正式120s须≥118有效样本；报告sampled peak和四分位趋势，RSS树相加含共享页重复，PSS树才用于总内存比较；proc VmHWM单列。empty/filled/verified/after smaps和smaps_rollup保留。边界采样误差与cpu tick量化明确列出。记录原生负载器CPU、scheduled lag，若CPU≥90%单核或steady p95 send-lag>1ms，该阶段标为generator-limited，不能把吞吐差称daemon容量收益。该限制不删除数据；原结果和受限标签均进报告。

方法资格与行为结果分开。实际wrong/malformed/transport、异常timeout、DHCP末态或reload发布失败均保留在该轮行为表，错误不计正确吞吐；不能通过反复丢窗口隐藏产品失败。fault只将故障期间实际丢包造成的timeout单列预期；故障前/恢复后超时和恢复迟缓如实作为服务结果。loadgen执行/采样/cleanup、缺失上游计数或环境污染使方法无效，保留原轮、修工具后重跑；有产品行为错误只记录、归因、必要时限制该profile结论，不在M6a修改产品。reload发布探针10ms、控制循环约5ms且资源采样有成本，完整记录探测间隔；低于实际探测分辨率的差异不判收益。

## 事先固定的结论规则

每项保留三组5轮原值、median、min/max，R3/C、Rs/C和Rs/R3同轮配对。组内波动W定义为(max−min)/median；只有差值超过两组W的较大者、且至少4/5配对轮方向一致，才可判有收益/变差。其余写无显著差异或受限，不以均值/单个最快窗口下结论。

有收益门：正确吞吐median提高≥10%，或CPU/正确请求、p95降低≥10%；资源RSS/PSS降低≥10%且绝对差≥64KiB。变差门：吞吐降低≥5%，CPU/正确请求或p95增加≥10%；RSS/PSS增加≥10%且绝对差≥64KiB。新增错答/额外普通失败直接列变差与绝对数。各指标独立标记，收益伴随其他指标回退就列取舍，不笼统声称性能更好。每项给绝对QPS、CPU微秒/请求、延迟微秒及KiB代价；样本不足、generator-limited、边界不准明确限制结论。

Rs是否值得考虑切换：ELF至少节省10%，所有正常profile的median CPU/请求及p95代价≤5%、正确吞吐回退≤5%、无新增错误；至少4/5配对方向满足，且关键边界无generator限制，才写值得进行后续功能/包资格评估。否则保留opt3或写证据不足。即使满足，本轮也不更换交付ELF；Rs的APK/功能资格仍未完成。

## 内存归因与交付

以三组新empty/full-cache smaps/PSS、上述实际TCP树数据与同源码结构大小/capacity估算交叉验证。固定4096短名A；旁路诊断可另测cache0 idle、20持有租约、已满日志队列/启用helper的分配结构，但必须明确是诊断而非上述正式结果，不把插入数当live occupancy。优先不侵入冻结ELF的/proc；静态musl不以LD_PRELOAD声称捕获真实heap。type-size/allocator-request诊断复制件不改被测产品，若使用heap工具必须记录它的干扰并单列。按cache槽、Record/Arc、双名字/索引、RDATA、租约、监听、日志队列、helper、mapped file/code和未解释余量列账，C对应调用链/预分配/COW位置与误差写明；不强凑精确守恒。

每批实际结束即回拷全部证据、fullSHA/metadata核验后清理Oracle的可重建运行目录/overlay，原receipt/身份/日志恢复给后置门。按profile有效轮次数更新账本并提交工具/派生报告；产品及用户docs/prompts不动。最终`M6A_REPORT.md`含9profile×3组×5轮及阶段表、判定、s相对opt3代价、内存归因、按测量依据排序的M6b候选和全部失败/作废/异常链。报告提交后停止，等待用户决定M6b；不操作物理路由器。
