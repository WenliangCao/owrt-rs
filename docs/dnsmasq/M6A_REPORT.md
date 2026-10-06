# M6a 性能与资源报告（在途草稿）

本报告尚未完成。下列数据只取已回拷、已分析的首6个正式窗口：UDP hit/miss各组的第1轮；`formal_complete=false`。每个profile必须取得C、R3、Rs各5轮方法有效数据后，才按事先冻结的规则给出收益、回退或切换s的结论。后续正式窗口仍在执行；当前提交用于断线恢复，不是M6a结束验收。产品代码未改，M6b未启动，物理路由器未操作。性能结论只代表Oracle构建机。

## 冻结身份与证据

协议[版本1及TCP合同澄清](M6A_PROTOCOL.md)在对应正式数据开始前提交，正式采用`freeze-c3402ba6`。冻结[manifest](../../private/dnsmasq-rewrite/evidence/M6a/freeze-c3402ba6/manifest.json) SHA256为`885d7eda6fcec0e7b057682c7798a09dda67a9dfc2300b8d898cfb15c3d50f40`；协议SHA为`6ba6a9ea462713dd57ebab1600d8bd9375c70c38f510b3b88f19a580de62aa6e`。manifest绑定160份M5产品源码/构建输入、精确rootfs、R3/Rs构建收据、工具及原生ELF SHA。

| 组 | 来源与构建 | 被测ELF SHA256 | ELF字节 |
| --- | --- | --- | ---: |
| C | 精确OpenWrt25.12.5镜像musl C，匹配dnsmasq2.93源码 | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` | 不作为本轮构建变量 |
| R3 | M5冻结源码`dc1b740d7973838e2ae7f098d0726b0484e55074`，opt-level3 | `37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b` | 1,929,256 |
| Rs | 同一源码、同工具链/SDK/static/strip/panic-abort/no-unwind，仅opt-level改s | `8427b9ab9718e3645137db4670ef3afcb8d983a2b88bb997127224de39988a2a` | 1,613,864 |

Rs fresh构建通过统一`oracle_build.sh`和唯一共享Cargo目录；[构建收据](../../private/dnsmasq-rewrite/evidence/M6a/builds/opt-s/build.json)绑定实际产物。Rs比R3小315,392 B（16.35%）。这是体积事实；Rs仅性能对照，未做新的功能/APK资格，本轮不替换交付ELF。

Oracle是4核AArch64构建机，kernel`6.17.0-1020-oracle`、页大小4096 B、`CLK_TCK=100`。三组均在同一精确镜像rootfs只读共享基底的临时overlay及独立net/mount/pid namespace中运行。daemon和继承的TCP子进程固定CPU0；原生上游CPU1；原生负载器及reload TFTP客户端CPU2；controller与采样CPU3。实际affinity逐进程核对，不设CPU quota。正式窗口持共享构建锁，排除其他build/test/fuzz，记录外部负载和各核busy/steal；归档在窗口之间完成。

本草稿的[离线分析JSON](../../private/dnsmasq-rewrite/evidence/M6a/freeze-c3402ba6/partial-integrity-analysis.json) SHA为`0ab5b769e39ddc333dceb57f94a75d775a159cb6416ec7dce6a2aeaf7d85352f`，绑定state SHA`6e4ad4b2e94906569a79a286f183fb645db50d9c5ecb8cc8821e6e0cd1b47d07`。完整的各窗口/阶段原值见[机器结果CSV](../../private/dnsmasq-rewrite/evidence/M6a/freeze-c3402ba6/partial-integrity-analysis.windows.csv)，各指标对照资格见[对照CSV](../../private/dnsmasq-rewrite/evidence/M6a/freeze-c3402ba6/partial-integrity-analysis.comparisons.csv)。这三份是首6窗口的部分分析，不能称最终135窗口结果；最终收尾须替换为完整分析身份和归档门结果。

## 方法和读表规则

通用DNS配置为cache-size4096、cache-rr=TXT、dns-forward-max1024、TTL/local-ttl3600、no-resolv/no-poll/no-0x20-encode，query logging关闭；C/R3/Rs配置相同。20个逻辑客户端、每socket最多1个在途。每个正式窗口先全新独立2秒预热＋10秒pilot，再重建初态，30秒预热＋120秒正式测量；pilot、预填、验证、尾排空和清理均不计吞吐。

每profile5轮，round为外层、profile依冻结顺序执行；三组顺序为`C→R3→Rs`、`R3→Rs→C`、`Rs→C→R3`、`C→Rs→R3`、`Rs→R3→C`。不挑最快attempt。方法失败保留原轮、修环境或工具后fresh重跑；真实错答、timeout、DHCP末态或reload发布错误仍是有效坏产品观测，单列错误并排除出正确吞吐。

正确吞吐按阶段内真实完成数除以固定monotonic阶段秒数。正确latency来自该阶段实际首send的全部正确请求，包括后续阶段或窗口后才完成的请求；这些跨界完成另列，不能算进前一阶段吞吐。p50/p95为nearest-rank，阶段正确样本至少10,000才报p99。不得用平均延迟遮蔽尾部。steady还报告scheduled→send lag、scheduled未发与在途限制；closed-loop只表示20并发完成量，不是开放式daemon绝对最大容量。

CPU主数为独立daemon cgroup的`cpu.stat usage_usec`阶段首尾差，含已回收TCP child CPU；CPU/请求的分母为该阶段内正确完成请求。DHCP分母为完整DORA→renew→release发送的cycle，单位µs/cycle和cycle/s；release没有ACK，另检查负载结束后租约文件收敛为空，不能把release send计成独立应答。`/proc`树own＋已waited子CPU以及退出`wait4`只作交叉核对，不替代cgroup，也不重复加活跃child CPU。

边界capture lag必须≤250 ms，120秒至少118个1 Hz有效资源样本。RSS/PSS峰是采样峰，不是瞬时绝对上界；分别保留parent和完整process family的RSS/PSS/FD/thread/child及四分位趋势。C fork的RSS树合计重复包含共享页，PSS树用于总内存比较；VmHWM单列。负载器CPU≥90%单核，或steady p95 send-lag>1 ms时，标记generator-limited，数据照留，吞吐差不能宣称daemon容量收益。

TCP三profile均按精确C/R的每连接100-query上限复用并重连。CPU包含fork/cache view/回收和重复连接成本；延迟从真实首send计算，connect前等待由scheduled lag和吞吐反映。结果不能称20条永久连接，也不能当纯握手吞吐。reload发布探针为10 ms，controller循环约5 ms且资源读取会延迟观察；publication latency是观测上界，必须结合实际探测间隔，低于分辨率的差异不判收益。

收益/回退规则不随结果改变：组内波动`W=(max−min)/median`，差异须超过两组W较大者且至少4/5同轮方向一致。正确吞吐提高≥10%，CPU/正确请求或p95降低≥10%，才满足对应收益门；吞吐降低≥5%，CPU/请求或p95增加≥10%，才满足对应变差门。RSS/PSS变化须≥10%且绝对≥64 KiB。新增错答/额外普通失败直接列绝对数量及变差。p50/p99、FD/thread/child保留完整描述值，不补造协议未设的收益门。

## 首轮已归档原值：尚不足5轮

以下12阶段来自6个方法有效正式窗口。所有wrong/timeout/transport计数为0；latency单位µs，CPU单位µs/正确完成请求。`正确完成`按完成时间归属阶段；`正确latency样本`按请求首send归属阶段，因跨界和尾排空可不同。完整offered/skipped/跨界/晚完成、CPU秒、send lag和资源采样数仍保留在上述JSON/CSV。

| profile | 组 | 阶段 | 秒 | 正确完成 | 正确latency样本 | QPS | CPUµs/完成 | p50µs | p95µs | p99µs | RSS/PSS峰KiB | FD/thread/child | 限制 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| udp-hit | C | steady | 90 | 899,562 | 899,562 | 9,995.133 | 11.891 | 19.800 | 21.760 | 55.040 | 1,580/1,572 | 11/1/0 | 不足5轮 |
| udp-hit | C | saturation | 30 | 4,396,125 | 4,396,145 | 146,537.500 | 6.818 | 133.721 | 149.481 | 164.681 | 1,580/1,572 | 11/1/0 | generator-limited；不足5轮 |
| udp-hit | R3 | steady | 90 | 41,869 | 41,888 | 465.211 | 88.243 | 41908.947 | 43114.517 | 45255.815 | 3,528/3,520 | 10/1/0 | 不足5轮 |
| udp-hit | R3 | saturation | 30 | 13,988 | 13,989 | 466.267 | 87.763 | 42840.754 | 43280.158 | 44507.369 | 3,520/3,512 | 10/1/0 | 不足5轮 |
| udp-hit | Rs | steady | 90 | 41,845 | 41,865 | 464.944 | 92.028 | 41979.027 | 43004.956 | 44104.085 | 3,332/3,332 | 10/1/0 | 不足5轮 |
| udp-hit | Rs | saturation | 30 | 13,965 | 13,965 | 465.500 | 91.418 | 42888.795 | 43501.680 | 44732.490 | 3,332/3,332 | 10/1/0 | 不足5轮 |
| udp-miss | C | steady | 90 | 898,274 | 898,276 | 9,980.822 | 93.864 | 152.281 | 263.082 | 914.727 | 1,580/1,572 | 13/1/0 | 不足5轮 |
| udp-miss | C | saturation | 30 | 368,506 | 368,524 | 12,283.533 | 80.637 | 1601.373 | 1771.894 | 2073.377 | 1,580/1,572 | 13/1/0 | 不足5轮 |
| udp-miss | R3 | steady | 90 | 40,293 | 40,313 | 447.700 | 175.407 | 43622.001 | 44761.250 | 46362.864 | 3,868/3,860 | 11/1/0 | 不足5轮 |
| udp-miss | R3 | saturation | 30 | 13,422 | 13,422 | 447.400 | 179.015 | 44641.769 | 45186.134 | 46930.068 | 3,860/3,860 | 11/1/0 | 不足5轮 |
| udp-miss | Rs | steady | 90 | 39,972 | 39,992 | 444.133 | 193.664 | 43996.044 | 45107.774 | 46505.065 | 3,736/3,728 | 11/1/0 | 不足5轮 |
| udp-miss | Rs | saturation | 30 | 13,325 | 13,325 | 444.167 | 195.653 | 44976.173 | 45469.776 | 47214.991 | 3,736/3,728 | 11/1/0 | 不足5轮 |

首轮UDP hit和miss的R3/Rs出现约42–45 ms的成功响应p50/p95，同时正确吞吐较低，实际在途上限导致大量scheduled未发。这是必须保留并排查的观测，不从单轮给出冻结规则要求的五轮收益判定，也不在M6a修改产品。首轮C udp-hit closed-loop负载器为92.64%单核，已标generator-limited；不得把146,537.5 QPS称为独立证明的daemon最大容量。

## 九个profile的完整五轮汇总表位

下面每个数字格最终为`median [min,max]`，三组分别按各自5轮统计，并保留R3/C、Rs/C、Rs/R3同轮配对判断。当前格均pending，首轮原值只在上一表；不拿一个值重复填成5轮中位数或范围。

| profile / 阶段 | C：QPS；CPUµs；p50/p95/p99µs | R3：QPS；CPUµs；p50/p95/p99µs | Rs：QPS；CPUµs；p50/p95/p99µs | R3/C、Rs/C、Rs/R3指标判定及绝对代价 |
| --- | --- | --- | --- | --- |
| udp-hit / steady90 | pending | pending | pending | pending：每组各5有效轮后判定 |
| udp-hit / closed-loop30 | pending | pending | pending | pending：每组各5有效轮后判定 |
| udp-miss / steady90 | pending | pending | pending | pending：每组各5有效轮后判定 |
| udp-miss / closed-loop30 | pending | pending | pending | pending：每组各5有效轮后判定 |
| dns-mixed / steady90 | pending | pending | pending | pending：每组各5有效轮后判定 |
| dns-mixed / closed-loop30 | pending | pending | pending | pending：每组各5有效轮后判定 |
| upstream-fault / healthy0–30 | pending | pending | pending | pending：每组各5有效轮后判定 |
| upstream-fault / fault30–60 | pending | pending | pending | pending：每组各5有效轮后判定 |
| upstream-fault / recovery60–120 | pending | pending | pending | pending：每组各5有效轮后判定 |
| tcp-local / steady90 | pending | pending | pending | pending：每组各5有效轮后判定 |
| tcp-local / closed-loop30 | pending | pending | pending | pending：每组各5有效轮后判定 |
| tcp-cache / steady90 | pending | pending | pending | pending：每组各5有效轮后判定 |
| tcp-cache / closed-loop30 | pending | pending | pending | pending：每组各5有效轮后判定 |
| tcp-miss / steady90 | pending | pending | pending | pending：每组各5有效轮后判定 |
| tcp-miss / closed-loop30 | pending | pending | pending | pending：每组各5有效轮后判定 |
| dhcp-lease / cycle120 | pending | pending | pending | pending：每组各5有效轮后判定 |
| reload-concurrent / DNS120＋TFTP120＋11HUP | pending | pending | pending | pending：每组各5有效轮后判定 |

各profile的成功/错误、资源和副作用另表，避免把fault低可用性的幸存者延迟或DHCP/reload的不同工作单位混成DNS总均值。

| profile | C/R3/Rs有效轮数（分析快照） | 成功/错答/timeout/transport完整计数 | RSS/PSS峰median[min,max]、FD/thread/child | 额外合同与归因 |
| --- | --- | --- | --- | --- |
| udp-hit | 1/5/1/5/1/5 | pending | pending | 4096实际命中、测量上游0 |
| udp-miss | 1/5/1/5/1/5 | pending | pending | 唯一名、上游requests/replies对账 |
| dns-mixed | 0/5/0/5/0/5 | pending | pending | 130A/65AAAA/37CNAME/24TXT bank、实际4hit/1miss及余数 |
| upstream-fault | 0/5/0/5/0/5 | pending | pending | 故障预期timeout与恢复后异常分开；恢复时间 |
| tcp-local | 0/5/0/5/0/5 | pending | pending | 100-query reconnect数；parent/family及child CPU |
| tcp-cache | 0/5/0/5/0/5 | pending | pending | parent预填；快照/COW、reconnect、PSS及回收 |
| tcp-miss | 0/5/0/5/0/5 | pending | pending | TCP上下游两边连接/转发计数及child CPU |
| dhcp-lease | 0/5/0/5/0/5 | pending | pending | cycle、DORA/renew/release-send与租约最终空 |
| reload-concurrent | 0/5/0/5/0/5 | pending | pending | DNS/TFTP成功间隙、11次真实新host发布、HUP后miss |

最终完整机器表必须覆盖9profile×3组×5轮，以及steady/saturation、fault三段、DHCP cycle和reload各子指标。方法无效attempt、pilot以及真实坏产品观察均在独立attempt链保留；终版将填入最终CSV/JSON身份、全部有效轮计数和归档恢复验收门，不能只链接首6窗口的部分文件。

## s相对opt3的代价与是否切换

体积已证明减少16.35%；CPU、p95和正确吞吐代价仍待5轮正式配对。切换判据在结果前固定：正常profile中median CPU/正确请求与p95代价均≤5%，吞吐回退≤5%，无新增错误，至少4/5配对满足，而且关键容量边界未被generator限制，才可写值得进行后续功能/APK资格评估。当前证据不足，维持M5获准opt3身份；本轮不优化、不切换构建方式。

终版需要逐profile填入Rs−R3绝对CPUµs/请求（DHCP为µs/cycle）、p95µs和QPS代价、min/max与配对方向；同时列出是否受低吞吐瓶颈或generator限制影响。不能以ELF变小直接推断CPU更好，也不能以文件页RSS下降替代heap收益。

## 内存结构账与驻留差

结构级分析和精确C调用链见[完整内存归因](audits/M6A_MEMORY_ATTRIBUTION.md)。方法是冻结源码AArch64布局常量、诊断复制件的capacity/allocation-request观察、精确C record布局，以及未插桩冻结ELF的smaps交叉核对。诊断复制件不参与正式性能；sizeof/requested bytes不含musl class/header、空闲组、碎片、未驻留页或内核socket缓冲。没有用宿主allocator或LD_PRELOAD宣称测得静态musl的真实heap。

M6满缓存名称`q%04x.m6a.test`的wire/capacity为16 B。C启动预分配4096个136 B `crec`，75 B短name和地址内嵌，512个hash pointer桶；Rust预分配112 B Slot，但另有Arc<Record>、独立name/RDATA、canonical name键和每名Vec索引。

| 4096个A的requested存储 | C KiB | Rust KiB | 解释 |
| --- | ---: | ---: | --- |
| 固定record／Slot | 544 | 448 | Rust Slot已含Entry，不能重复加Entry |
| Arc header＋Record | 已含record | 288 | 每条72 B；name/RDATA Vec header已在Record内 |
| 原始name backing＋canonical键backing | 短名内嵌 | 128 | 两份16 B名字，各64 KiB |
| A RDATA backing | 地址内嵌 | 16 | 每条4 B另分配 |
| hash buckets／每名slot Vec／少量pending | 4 | 520.039 | Rust bucket约392 KiB＋单元素Vec capacity4约128 KiB |
| 合计，排除少量容器/allocator成本 | **548** | **1,400.039** | 差约852.039 KiB（213.0 B/配置slot） |

Lease、监听器、日志队列和helper的条件存储详见归因表：C lease本体160 B，Rust232 B加BTree索引、hardware/CLID/name backing及DNS发布副本；C listener64 B，Rust socket/Arc/listener约48 B requested但interface/config和Vec容量另算；Rust每个排队log约1064 B加allocator，队列空时无payload；helper owner144 B及按事件分配的context/frame。纯DNS满缓存未启租约/helper，不能把它们的容量上限记为实际占用；本轮query logging关闭，残留deque容量与映射页仍需单列。

C TCP fork继承缓存页并逐步COW，Rust普通TCP accept clone slots/name index，同时共享ArcRecord payload。M6短名下缓存快照requested约936 KiB/活连接；20连接约18.3 MiB仅为机制估算。实际100-query重连造成活连接数与allocator保留页变化，终版必须与正式family PSS、child/reconnect和回收后驻留对账，不把理论20连接上限写成实测常驻峰。

M5的已知3524/1660 KiB RSS差有历史守恒账：总差1864 KiB＝匿名差1228 KiB＋file页差636 KiB。它不是1864 KiB全部缓存heap，C填充后只增4 KiB也不代表C缓存只用4 KiB。M5记录名18 B、300秒窗口、配置/已触代码与M6名称/120秒负载不同；M5数据只作历史交叉核对，未借为M6正式轮次。

新M6终版驻留表仍pending：按C/R3/Rs的新empty/filled/verified/after full-smaps与每组5轮sampled peak分解anonymous、file/code、stack、heap/anon-mmap、allocator保留及未解释量。匿名映射不能直接贴成某个HashMap/Vec；无法对象级证明的余量保留未知及误差。Rs较R3的file页减少要归于不同code/data映射和触页，不能归为优化缓存条目。

| 新M6满缓存（KiB） | C | R3 | Rs | 解释／误差 |
| --- | --- | --- | --- | --- |
| empty RSS/PSS、Anonymous/File | pending | pending | pending | 同配置、正式身份的原始smaps |
| filled／verified RSS/PSS、Anonymous/File | pending | pending | pending | 4096有效动态A全命中、上游0证明 |
| 正式sampled RSS/PSS peak与quarter趋势 | pending | pending | pending | 1Hz峰，保留min/max及VmHWM |
| 缓存requested与匿名残差 | pending | pending | pending | 未知allocator/其他owner不强行扣到cache |
| TCP family PSS与reconnect/child数量 | pending | pending | pending | C共享页用PSS，Rust快照与回收分开 |

## 失败、作废、异常与恢复

全链索引见[M6a失败记录](audits/M6A_FAILURES.md)。下面全部保留原identity、命令、返回值和原证据；pilot/工具自检从未进入正式性能汇总。工具修复没有修改产品、rate、时长、交错顺序或收益阈值。

| 原失败／异常 | 定位与处置 | 对正式结果的影响 |
| --- | --- | --- |
| setup native严格Linux编译拒绝 | GCC-Werror指出TCP malformed分支的缩进歧义；明确控制流后重编通过 | 没有产生被测结果 |
| DHCP手工C pilot0成功/131timeout | argv错误地发往DNS15353；改为server67/client68，重试200/200 cycle、0错误/timeout且租约末态空 | 工具错误；两轮均excluded，不称C性能差 |
| 原tcp-local C pilot在1969次warmup正确后中断 | 两实现均每连接100 query；客户端误把正常EOF当中断，统一100-query复用/重连 | 正式前修复；原pilot retained，合同澄清不改变产品 |
| suite人工中断/prune恢复守卫失败 | 已完整归档但prune后未恢复gate，重启inventory失败；加prune intent和恢复、独立守卫复核通过 | 编排工具自检，非Oracle性能失败 |
| tcp374 udp-miss-R3 foreign suspect | 原PID/starttime/cmdline见证被exclusive门拒绝，当前证据无法确认来源；同manifest两次fresh pilot均通过 | 原拒绝保留，未改归属规则；不计正式 |
| TCP short-lived child snapshot ESRCH | 100-query重连时child已消失；snapshot只略过已知ENOENT/ESRCH竞态，cgroup CPU仍完整累计 | c340新工具冻结后重新pilot；原失败raw/meta保留 |
| 首轮C udp-hit closed-loop generator-limited | 负载器约92.64%单核；实际结果保留受限标签 | 方法有效；容量结论受限，不丢窗挑数 |
| 首轮R3/Rs UDP较高成功尾延迟、scheduled未发较多 | 原始latency/counts/CPU/资源保存；必须等五轮并作源码归因 | 方法有效观察，未优化产品、未先下最终收益结论 |
| 后续正式method失败或真实产品异常 | pending：最终从state attempt_history逐项追加 | 原轮/重跑与有效坏结果均保留 |

首6窗口的formal_command均returncode0、foreign_load为空，方法质量通过；wrong/timeout/transport为0。每批归档先完整SHA＋metadata本地核验，再清理对应Oracle可重建raw/overlay，并恢复receipt/JSON/log供后置门验证。最终报告必须列正式method作废数量、实际产品错误数量、重跑原因、完整135窗口数及最终cleanup/inventory门；当前未完成的项目不得写PASS。

## M6b候选：只归因，待正式数据排序

尚未实施任何候选。下面是待完整五轮确认的线索，最终按实际绝对代价/预计收益排序；机制推断不能冒称测得优化收益或给出固定承诺。

| 候选 | 当前依据 | 机制与待证明收益 |
| --- | --- | --- |
| 网络poll/定时器唤醒路径 | 首轮R3/Rs hit/miss均约42–45 ms成功延迟，daemon CPU仍远未满核；须核对全部正式轮及原始时间分布 | 排查固定等待、就绪事件与upstream/UDP批处理；预期降低服务等待，具体根因和收益pending |
| TCP缓存视图/代际共享 | 静态936 KiB/cache snapshot/活连接及每100 query重连；正式TCP CPU/PSS尚未完成 | 保持accept-time视图与child隔离，减少反复复制metadata；以实际clone/fork CPU和PSS差决定优先级 |
| canonical name、单元素Vec和bucket存储 | 同4096 A requested-byte账：Rust1400.039 KiB、C548 KiB；额外存储集中在index/Arc/双名字 | 更紧凑记录链接/共享name及small-payload存储；实际allocator残差仍未知，不能承诺全部852 KiB可回收 |
| DHCP租约与DNS发布副本 | Rust232 B本体和BTree/DNS名称索引较C160 B list额外分配；正式DHCP CPU/cycle、PSSpending | 依据实际规模和查找/更新CPU再选表示，不为省内存提前退回线性扫描 |
| opt-level s作为后续构建选项 | ELF省16.35%，完整CPU/p95/吞吐代价pending | 严格按已冻结切换门决定是否值得再做功能/APK资格；本轮不切换 |

## 收尾条件

本草稿不满足M6a结束条件。终版须完成9profile×3组×5有效正式窗口、逐阶段三组median/min/max及配对判定、s相对opt3代价、实测内存差与误差、全失败/异常链、最终完整CSV/JSON身份和归档门。报告终版提交后才停止，并等用户决定M6b方向；现阶段继续原冻结测量。
