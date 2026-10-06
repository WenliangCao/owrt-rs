# M6a 内存归因

产品始终是源码 `dc1b740d7973838e2ae7f098d0726b0484e55074`、opt3 ELF `37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b`。本分析不修改、插桩或替换被测 ELF。C ELF为 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`，使用精确匹配的 dnsmasq 2.93 nodhcpv6 源码；布局取 Linux AArch64 ABI，不能当成物理路由器上的驻留量或性能结论。

当前结构账和 M5 的旧 smaps 交叉核对已经完成。M6a 的新 smaps/性能采样身份与对照组身份由正式报告补入；下面明确区分目标布局、诊断复制件的容量观测与 M5 已有运行证据。

## 方法与误差

- [布局复现器](../../../tools/dnsmasq/m6_memory_layout.py) 以 `git show` 提取冻结源码到 ignored/private，追加 `size_of` 常量；本地 rustc 1.98.1 对 `aarch64-unknown-linux-musl` 做 opt3 LLVM IR 编译。没有运行诊断复制件作为性能被测对象。
- C 诊断复制精确上游 record 声明，用 Linux AArch64 的网络/基本类型 ABI shim，clang 生成 sizeof 常量；禁用 DHCP6、broken-RTC，启用 TFTP，与镜像 compile options 一致。没有把宿主 macOS 的 C ABI 当成镜像 ABI。
- 同一 64 位 rustc 在本地诊断复制件中填入 `c0000.cache.test` 至 `c0fff.cache.test` 的 4096 个 A；直接读 slots、name、RDATA、每名索引的 capacity。仅对该复制件的分配器记录大型 allocation request，交叉检查 HashMap slab 大小；不把 macOS 分配器的 chunk/RSS 当成目标 musl 数据。
- `sizeof` 不含目标分配器 header、size class、对齐空隙、空闲组、碎片、未驻留页、内核 socket/pipe 内存。capacity 也不等于 RSS。结构账单列未知部分，不用一个比例强行把全部 RSS 分配给缓存。
- M5 证据是 `smaps_rollup` 而非 full smaps，匿名部分可与逻辑预算对账，不能进一步区分 heap、stack、anonymous mmap；M6 full smaps 可增加映射归因，但仍不能仅凭它给每个 Rust 对象贴标签。临时请求分配和 allocator 保留页仍有不确定性。
- layout 为确定字节数；HashMap/Vec capacity 是该固定序列的实际观测。缓存 requested-byte 账误差主要来自少量 cache 容器/allocator metadata，以及未计入的网络/解析 scratch；驻留归因的未知项在下表保留到 KiB。M6 采样间隔之间的短峰值可能漏采，不能把采样峰值称为绝对上界。

本地原始诊断：`private/dnsmasq-rewrite/evidence/M6A/memory-layout-04/` 的 `layout.json`、两份 LLVM IR、build/native-build 日志。复制件和产物不进 Git。复现命令：

```sh
python3 tools/dnsmasq/m6_memory_layout.py \
  --repository "$PWD" \
  --source dc1b740d7973838e2ae7f098d0726b0484e55074 \
  --c-reference "$PWD/private/dnsmasq-rewrite/reference/dnsmasq-2.93" \
  --out "$PWD/private/dnsmasq-rewrite/evidence/M6A/memory-layout-new"
```

## 4096 个短名 A 的缓存账

冻结参考场景是 M5 满缓存：cache-size=4096、TTL=3600、no-hosts、no-resolv、同一个 IPv4 upstream、短名 `c%04x.cache.test`、每个地址 4 B、没有 lease、TFTP、helper 或 query 日志负载。M6 若使用不同名字/组合，必须重新按其实际 payload/capacity 算账。

C 的 `cache.c:176–196 cache_init` 在启动时一次分配 `cache-size * sizeof(struct crec)`，每个 record 的 LRU/hash 链接、过期时间、flags、地址与 75 B 短名字存储都在同一块。`cache.c:261–272 rehash` 使用至少64、按 `cache-size/10` 扩展的2次幂桶数，此处512桶。填入短名 A 不需要每条额外 name/payload allocation。

Rust 的 `dns/cache.rs:227–282` 同样预分配固定 slots，但 record 的 `Arc<Record>`、名字与 RDATA 分离；`cache.rs:649` 分配 Arc，`:801–805` 的 `names.entry(canonical_wire()).or_default().push(slot)` 另外保存 canonical 名字与每名 Vec 索引。`cache_engine.rs:1269–1273` 保存 `current.clone()` 与 `data.to_vec()`；短名 wire 是18 B，复制件观测 capacity 也是18。

| 部分 | C requested B / 4096 条 | Rust requested B / 4096 条 | 依据与边界 |
| --- | ---: | ---: | --- |
| 固定记录、expiry、LRU/flags/generation | 557,056 = 136×4096 | 458,752 = 112×4096 | C crec136；Rust Slot112 已含 Entry/option storage，不能再把 Entry72重复加上。C短name与A地址已在crec中。 |
| payload ownership header 与 Record | 包含在crec | 294,912 = 72×4096 | Record56＋Arc强/弱计数16；Arc与Slot独立。名字/RDATA Vec header已含在56中，下面只算 backing bytes。 |
| 每条原始 name backing | 短名包含在crec的75 B | 73,728 = 18×4096 | Rust `Name(Vec<u8>)` header24已在Record中；复制件capacity实测。C长名才另需504 B bigname，最多cache-size/10普通长名。 |
| canonical name index key backing | 名字复用crec | 73,728 = 18×4096 | Rust单独owned canonical Vec，额外名字副本。 |
| A RDATA backing | 16 B union内保存4 B A | 16,384 = 4×4096 | RustVec allocation；不能将C16 B union再加到136之外。AAAA Rust16 B；generic RR按实际canonical长度。 |
| hash table／name-to-record索引 | 4,096 = 512×8 | 401,416 | Rust HashMap4096项，capacity7168、8192物理bucket；每bucket两Vec header共48 B＋control区。复制件大型分配请求交叉检查。 |
| 每名字记录列表 backing | hash_next包含在crec | 131,072 = 4×8×4096 | 每个唯一名字一个Vec，只有1个slot但capacity4，含3个空位；上行header已计。 |
| pending／reverse backing | 链在crec | 32／0 | 单条插入pending capacity4；无PTR，reverse_chain未分配。 |
| 合计，排除少量容器对象/allocator成本 | **561,152 B = 548 KiB** | **1,450,024 B = 1,416.039 KiB** | Rust Cache容器208 B；被包含在更大的owner中，不能把它再当独立heap allocation。 |

Rust的 requested-byte 差为 **888,872 B（868.039 KiB，约217 B/配置slot）**。它不是每次命中产生的驻留增量，也不是全部 ELF/RSS 差。Rust fixed Slot 反而比 C crec 小24 B；主要额外存储在 ArcRecord、分离名字、HashMap 桶和单元素 Vec。

### b85 pilot 名长校准（诊断排除）

M6 b85 pilot 的夹具名字改为 `q%04x.m6a.test`。该字符串是14个ASCII字符；Rust `Name` 的 wire 表示是三个label-length字节、14个字符和一个root终止字节，共 **16 B**（pilot 的 `cache-proof.json`首尾名与 `wire-samples`可核对）。15 B只是不含root的长度字段加字符，不是Vec容量。因而 pilot 名字的原始与canonical backing分别是65,536 B（64 KiB），不是M5名字表的73,728 B；仅按该名字变化，Rust逻辑缓存预算为 **1,433,640 B = 1,400.039 KiB**，比C548 KiB多852.039 KiB。pilot实测 C/R3/Rs 的 full-cache驻留是1632/3520/3332 KiB RSS、1624/3512/3324 KiB PSS；R3与Rs匿名均1868 KiB，R3较Rs多188 KiB file页。该pilot的 `identity.json`明确 `excluded_preflight=true`、时长10 s、仅1轮，因此这里只校准归因方法，**不作为M6a性能结果，也不替代正式5轮**。

名字长度变化不能倒推完整RSS变化：M5与pilot名字backing请求相差16 KiB，但各自配置/路径和allocator/page状态也不同，不能隔离名字变化的实际RSS收益。pilot R3与Rs使用同一组名字，匿名相同只表明本诊断没有显示opt-level改变对象驻留量；R3/Rs的188 KiB file差属于不同ELF code/data映射和加载触页，不能记到缓存条目。C的cache-full full smaps能看到单一548 KiB匿名映射，与544 KiB `crec`分配加页对齐一致；Rust匿名映射被分成多段，不能仅按匿名段pathname给某一段指定HashMap或Vec。

## M5 smaps 的守恒账

旧证据来自 M5 同冻结 ELF 的 `archive-resources-final/plain/full-cache-300/{c,rust}/full/proc-snapshots/`；经过真实4096 live A填充、全命中核对、300秒窗口，最后两阶段驻留稳定。它只给 M6a 方法提供历史交叉核对，不能复用成新性能轮次。

| 阶段与部分，KiB | C | Rust opt3 | Rust−C |
| --- | ---: | ---: | ---: |
| empty RSS / PSS | 1,656 / 1,648 | 2,024 / 2,016 | 368 / 368 |
| empty Anonymous / Pss_File | 640 / 1,008 | 564 / 1,452 | −76 / 444 |
| filled RSS / PSS | 1,660 / 1,652 | 3,460 / 3,452 | 1,800 / 1,800 |
| verified、after-window RSS / PSS | **1,660 / 1,652** | **3,524 / 3,516** | **1,864 / 1,864** |
| verified Anonymous / Pss_File | 644 / 1,008 | 1,872 / 1,644 | **1,228 / 636** |
| empty→verified RSS增长 | 4 | 1,500 | 1,496 |
| empty→verified匿名增长 | 4 | 1,308 | 1,304 |
| empty→verified file增长 | 0 | 192 | 192 |

满缓存RSS比例2.123倍，但**1864 KiB总差 = 1228 KiB匿名差＋636 KiB文件页差**；不能把636 KiB可执行/映射file部分归给缓存条目。Rust filled→verified另增加64 KiB file，Anonymous不变，符合新触及缓存回答代码页，而不是又增加64 KiB cache heap。

按满载匿名部分对账：

| KiB | C | Rust | Rust−C |
| --- | ---: | ---: | ---: |
| 上述逻辑缓存 requested bytes | 548 | 1,416.039 | 868.039 |
| 观测匿名驻留 | 644 | 1,872 | 1,228 |
| 未由缓存requested-byte解释的匿名部分 | 96 | 455.961 | **359.961** |

这里的残差含缓存allocator开销，也含非缓存owner、转发request表、接收缓冲、解析scratch、stack和已释放后保留页；不能直接命名为“泄漏”或“碎片”。M5空缓存Rust的slot请求448 KiB已纳入564 KiB anonymous；C的544 KiB record预分配已纳入640 KiB，因此填充后C仅多1个4 KiB页，并不代表C缓存只用4 KiB。

作为分配器机制估算而非实测：若小allocation采用16 B单位的class并需内部元数据，72/18/18/4/32 B的五块请求可能分别占80/32/32/16/48 B，共208 B，相对144 B请求多64 B/条，即256 KiB/4096条。这个量级可解释相当部分残差；实际musl版本/class/group空闲比例未做对象级跟踪，**仍保留359.961 KiB未知，不能把此256 KiB估算当实际归因扣掉**。不能用宿主macOS allocator行为填补目标musl证据。

## 其他结构的条件账

以下是存储机制与按条件分配量。没有启用相应feature时，不把“可分配上限”当成实际满缓存占用。

| 结构 | C | Rust Linux64 | 容量／额外存储／实际边界 |
| --- | --- | --- | --- |
| DHCP lease本体 | no-DHCP6 `dhcp_lease`160 B，hwaddr16 B内嵌，linked list（`dnsmasq.h:864–895`、`lease.c:846–880`） | `Lease`232 B、`LeaseId`16 B、`ClientIdentity`56 B已含在232中；hardware bytes单独Vec | client-id/hostname/fqdn/agent/vendor bytes两侧按实际长度额外分配；Rust Vec headers比C pointer/length多，helper context可能另48 B＋Box allocation。M5纯DNS fullcache没有lease，贡献0。 |
| lease索引与timer | C list next包含在160 B，每次查找/expiry计算扫描；没有预分配dhcp-max个lease | LeaseStore80 B容器；BTreeMap<LeaseId,Lease>＋BTreeSet<(expiry,LeaseId)> | BTree每节点最多11keys，map叶约2744 B、internal约2840 B；expiry叶约280 B、internal约376 B。这是std B=6布局估算，须考虑节点占用率，不能简单按满节点平均套到20个lease。Rust不保留stale timer，renew先移除旧expiry。 |
| DHCP DNS发布 | C F_DHCP crec使用pointer-size记录并借用lease名字；无需普通短name75 B块（`cache.c:1742–1911`） | LeaseInput48 B、LeaseName48 B，inputs/entries保留名字副本；active Vec及forward/reverse/non_terminal index；LeaseNames264 B容器 | 名字隐藏后仍保留inputs以供reload重建；不能只算Lease232漏掉发布索引。TCP共享Arc代际，修改时copy-on-write。fullcache无DHCP发布。 |
| DNS listener | `listener`64 B同时含UDP/TCP/TFTP FDs、addr、iface、next（`dnsmasq.h:682–687`） | DnsSocket／DatagramSocket8 B；Arc<DnsSocket>24 B含计数；PollListener字段布局约24 B | Rust一组listener约48 B requested storage，排除配置/interface表、Vec spare与allocator成本；约24 B的PollListener由字段推算，未把估算标成compiler实测。socket内核缓冲不在proc RSS。 |
| 日志 | log_entry1048 B = header24＋payload1024；无async至少启动分配1项，可复用（`log.c:45–97`） | Logger176 B；队列Record40 B；format每条Vec capacity1024；两个VecDeque队列，TcpLogContext80 B | 空队列没有payload分配；已drain deque可能仍持有Record capacity。排队每条约1064 B＋allocator，debug echo另有队列。等待FIFO/socket时实际queue length/capacity应独立采样；不能把max_logs当当前length。生产无log-malloc global allocator。 |
| helper主owner | script_data104 B＋variable hostname/client/extradata buffer；C parent pipe，fork子进程执行脚本（`helper.c:54–79/85–105`） | Helper144 B、LeaseEventContext48 B、LeaseEvent136 B、ExtraData288 B、LeaseDelivery312 B | pending/incoming各Vec，frame上限65536 B按实际增长；ExtraData288是12个Vec header，bytes另计，事件消费后会释放。单owner不会新加线程；helper/脚本子进程PSS另采。fullcache配置未启helper，贡献0。 |
| forward／解析scratch | C frec/query stash/blockdata，blockdata每块48 B其中key40；freelist复用（`dnsmasq.h:493–496`、`forward.c`、`blockdata.c`） | UpstreamResolver固定receive Vec，transaction/socket/request多张HashMap和暂存Vec；完成/timeout释放或保留table capacity | 缓存填充会使这些表曾增长；它们与allocator已释放页不能仅靠cache逻辑账区分。要比较idle/post-fill/reload smaps和压力场景PSS，不把此残差全部算入“每条cache record”。 |

## TCP缓存快照是独立的内存候选

冻结Rust `main.rs:4068–4122` 非debug TCP accept保存 `daemon.tcp_cache_view()`；`cache.rs:252–255 snapshot` 调用 clone。ArcRecord及其名字/RDATA共享，slots、names bucket、canonical key和每名slot Vec主动复制。C普通TCP worker fork后继承页，先是COW；代码执行、LRU修改和malloc活动逐渐将部分页私有化。

原cache每名索引capacity4，**clone后的Vec以len1复制，而非capacity4**；复制件实际snapshot观测slot capacity4096、HashMap capacity7168、索引capacity合计4096。因此4096唯一名字的clone预算为：slots448 KiB＋HashMap物理桶约392 KiB＋canonical keys72 KiB＋索引32 KiB = **约944 KiB/连接**，另有container和LocalDnsService的hosts/config快照。不能直接套原cache的1040 KiB索引容量；20个连接约18.4 MiB是此cache部分的requested-byte机制估算，需实际TCP进程族smaps核验，不是已测峰值。

C parent＋20 child的RSS相加会把共享页重复计算；PSS相加才能正确分摊同一process family的共享页。正式报告应同时保留parent RSS/PSS、family RSS/PSS和进程数，不把C分叉开销遗漏，也不把共享页的多份RSS当成真实RAM重复占用。debug模式两侧均不同，不能让C普通fork与Rustdebug不快照作对比。

M6协议的20个TCP逻辑client不是无限寿命连接：精确C/R调用链都在每连接100个query后回收，负载生成器关闭/重连，因此正式CPU/PSS包含反复fork或cache view clone。M6 q名字下clone的key backing为64 KiB，预算约936 KiB/活连接；20活连接同时存在时约18.3 MiB只是结构预算，不代表整窗始终维持该值。需要在正式证据核对reconnect计数、C短命child采样消失、family PSS峰值和Rust回收后的allocator驻留，不能用“20永久连接”模型解释结果。

## M6a采样交叉核对与M6b候选边界

新采样建议保存 empty（4096 slots预分配后）、filled（完整填充）、verified（完整命中核对后）、after-window 的 full smaps与rollup，绑定PID/starttime/ELF身份；另外记录20个lease和20个TCP的family快照，配置feature开关保持一致。采集动作由主线程统一安排；本分析没有访问Oracle，不会在正式窗口加入构建或额外负载。

仅从现有结构账可提出以下M6b候选，排名尚须结合M6a实测CPU/尾延迟数据确认：

1. 唯一名字的canonical bytes与per-name Vec索引：144 KiB名字副本、128 KiB索引backing和约392 KiB桶，结构账显示潜在主目标；可能用共享名字/更紧凑单元素记录链接，必须保持多RR、大小写、LRU和CNAME generation语义。
2. TCP每连接快照：约944 KiB requested cache storage/连接；共享不可变generation或更紧凑COW metadata可能降低连接数增长项，必须保留C的accept-time视图、child修改隔离和parent cache传回合同。
3. ArcRecord＋小RDATA与独立名字allocation：每条72＋18＋4 B requested，合并存储/小payload内嵌可能减少class与group空隙；M5数据不足以把allocator残差准确分成各机制，不承诺固定净节省。
4. LeaseStore和发布副本：BTree索引占用率与232 B本体较C160 B大，是否值得调整取决于M6a DHCP查找CPU、20租约实际PSS和用户实际规模；不能为省内存提前退回线性扫描。

以上只做归因与候选记录，未实现优化、未变更产品，也未启动M6b。
