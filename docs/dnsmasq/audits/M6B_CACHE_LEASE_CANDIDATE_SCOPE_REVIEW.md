# M6b 后续缓存与租约候选：范围复核

2026-10-08。仅本地读冻结源码、文档和既有 E；没有 Oracle、构建、测试或优化实验。
被审查产品为无 A `e8b1d6c4`、独立 A `69bccf27`。A 尚未过资源/压力/45 CPU 全部门，
不合 main。本审查是候选评估完成的记录，不授任何产品收益或功能资格。

建议本轮先完成 A 的剩余门和最终验收，**不额外修改缓存条目或租约表示**。
A 已吸收 M6a 所列最大、强耦合的快照/索引候选；其余尚没有新基线上的成本占比和
净收益证据。最小的后续实验优先考虑缓存 lookup 的 canonical 临时分配，其次才是
租约发布代际内部名字共享。以下保留可验证的机制和门，不默默删掉剩余候选。

## 已被 A 覆盖，不能再次计入剩余收益

[M6a 内存账](M6A_MEMORY_ATTRIBUTION.md)对应 `dc1b740d`，4096 个16 B wire名 A：
C cache requested 548 KiB，Rust 1,400.039 KiB，差852.039 KiB。差额包括名字、桶、
Arc/Record 和 singleton backing；不是可直接回收的 RSS。五轮 Rust 空→满匿名增加
1308 KiB；636 KiB 级别的历史 file-page 差更不能由 cache 瘦身消除。

| M6a 候选 | A69bc 实现机制 | 还没有证明什么 |
| --- | --- | --- |
| 每 TCP 连接深拷贝 slot/index/key/list | `cache.rs:244–284`：私有 Slot16 B，content 与64个名字分片以 Arc 根共享；snapshot clone根和私有links/generation | 最终产品峰PSS、10批余额、churn驻留和45窗CPU仍待实际门 |
| singleton `Vec<usize>` backing | `cache_name_index.rs:8–16`：Empty/One内联；Many为 `Arc<Vec<usize>>`，唯一时原地修改，共享时COW | 不能引用旧独立singleton屏幕的正数作本A收益；旧屏幕因population CPU失败仍保留 |
| canonical key 在每个视图/分片clone重复分配 | `cache.rs:257,888`：`Arc<[u8]>`；分片clone共享key bytes，Many也共享 | 原始 `Record.name: Name(Vec<u8>)` 与canonical bytes仍是不同所有者；普通lookup仍会生成临时Vec |
| 大 HashMap 每视图主动clone | 64分片，仅写入相应分片时detach；保留RandomState与稳定高FNV分片选择 | 桶slack、删除/插入后capacity、最坏长期pin/churn没有因此消失；64个空根也有固定成本 |
| 网络结束后日志独占整个DNS状态 | 已将无DNS工作的cache/upstream/视图及时释放，日志保留其许可与目标 | S8/FIFO/stale/TERM的实际余额必须通过，FD归零不是heap归零的替代 |

历史 ae1 实际 layout scope为 snapshot **66,560 B、3次分配**，其中私有slots65,536 B
（含u64 generation与links）、两个根Vec合计1024 B；旧M6a满snapshot为958,472 B/
8194次分配。这是原语requested机制证据，不能把设计约33 KiB预测沿用为实现数字，
也不能当新69bc产品PSS/CPU结果。ae1到69bc这些存储文件未变，但fresh69bc资格仍重绑
重跑，详见[同源门recipe](M6B_TCP_A_CURRENT_SOURCE_GATE_RECIPE.md)。

## 仍有理论余地：按最小范围与风险排序

下面排序是适合后续独立实验的顺序，不是已测收益排序。任何候选都要先冻结、实测；
不能用一项的最好CPU和另一项的最好PSS拼最终候选。

| 顺位 | 最小候选、理论机制 | 正确性与机制门 | 最大风险、当前结论 |
| --- | --- | --- | --- |
| 1 | **只在 `Cache::lookup` 消除canonical临时Vec**。`cache.rs:1019` 调 `Name::canonical_wire`，后者对完整wire分配lowercase Vec；可保持public Name/owned index不变，仅用最多255 B的栈scratch产生同样borrowed key。A原语ordinary-hit实际仍4次allocation，其中此处至少1次是代码可定位的候选 | 现有core/policy/answer/EDNS/lease原语、binary/mixed-case/255 B名字、A/AAAA/CNAME/negative/generic、round-robin、过期删除和retained-view；负控改变lowercase须被拒。same-A companion证明allocation确少，产品UDP-hit/TCP-cache CPU和p95配对实测、0/150容量及miss插入不回退 | 只减少临时allocation，不消除存活名字；found/result Vec、packet和响应构造仍在。分片/hash/长度字节/二进制label必须相同，不能改记录wire大小写。CPU收益未知、RSS收益未证明；本轮不实施 |
| 2 | **LeaseNames代际内 inputs/entries 的同一原始名字共享**。`lease_names.rs:148–179,419`现保留两份Vec backing；共享immutable bytes，保留原始大小写和完整hidden inputs，canonical forward key仍独立 | 完整DHCP DNS publication/reload族、lease/cache primitive、旧TCP视图隔离、hidden-by-hosts后HUP恢复、重复名字/地址、reverse所有权、过期/stale、FQDN先于short、警告/ACK前发布及helper快照。分别证明1/20/150/满上限的live requested、构建CPU和更新峰值 | A没改LeaseNames；它已用Arc共享代际，新的共享主要省该代际内部payload，不是20份全复制。Arc header/引用计数及大小写canonical需求可能抵销短名收益；expiry/rotation仍必须reader私有。20条场景量级小，不适合先承诺PSS下降；本轮不实施 |
| 3 | **仅hardware bytes内联最多16 B**，不动client-id或LeaseStore索引。`dhcp/lease.rs:9–25`当前Vec有独立backing，valid限定≤16 B；C内嵌16 B | DHCP identity/leasefile restore/leasequery/relay/helper全部caller，htype为u32（不能窄成u8）、0/1/6/16/17边界、重复client/address、renew/release/expiry和序列；先测AArch64 Lease/Identity尺寸与allocation，后20/150/大租约配对资源/CPU | 新representation会触及公开ClientIdentity及多个caller。20条的本体差 `(232−160)×20=1440 B`，即使省小backing也不能解释M6a约768 KiB进程PSS差。不改BTree、无已测收益；本轮不实施 |
| 4 | **小A/AAAA RDATA内嵌**，保持generic/negative/SOA/CNAME合同和可变长fallback | target layout、完整core/answer/transfer/reverse原语、retained-view、mixed RR随机轮转、SOA/大RDATA、150/4096/16384资源及CPU/p95。必须从packet slice直接构造，先Vec再转inline不能证明消除分配 | Record的Name/RDATA已经随ArcRecord在视图间共享；不能将4096份RDATA再乘20。4096个A只有16 KiB backing，新增tag/Record尺寸可能抵销requested节省；allocator保留收益未知。旧inline16屏幕因150容量p95+8.63%失败，不据此直接采用；本轮不实施 |
| 5 | **HashMap桶容量/原始名字与canonical去重** | 必须先从新companion/正式窗口取得每分片len/capacity、unique版本数、名字长/大小写、多RR与churn账，再冻结单一候选；原查找/插入/反向bucket/顺序/失败前缀/所有代际门 | A已经把桶entry从两Vec描述符改变为Arc key+SlotIndices。按旧401,416 B slab预测剩余是错账。强制rehash/shrink会加CPU、改变capacity和allocator寿命；合并原始与canonical会影响二进制label、wire/log和多case名字。不得造generic interning pool或自研hash/arena；暂无最小已证收益方案 |

第1候选的scope故意只覆盖 lookup 一处；别顺手替换所有 canonical_wire、全局Name、
随机hasher或永久缓存查询key。若它不超过冻结波动/收益线，就撤回。四次allocation
来自历史原语scope，尚不能当完整daemon每请求分配总数或CPU百分比。

## DHCP：先尊重已有归因，再考虑表示

[M6a完整五轮](../M6A_REPORT.md#dhcp-listener-logging-and-helper-conditional-accounting)
只有20个固定MAC/CLID、150上限、每轮2400正确cycle，没有helper；不是满租约压力。
[M6b syscall归因](M6B_DHCP_SYSCALL_GAP.md)的历史6f诊断明确指出主要余差是接口元数据
重复查询及全接口扫描，而不是Lease232 B。新主循环已改这些路径，旧22.5 s idle CPU
和8822.7 µs/cycle回退不能被用来证明更换LeaseStore有效。

`LeaseStore` 的BTreeMap按 `(address, sequence)` 排，不是全局sequence；
`active_newest_first`（`lease.rs:850–854`）另外收集、按sequence倒序，维持C publication/
持久化顺序。把 `values().rev()` 当省分配的直接替换会改顺序，不能采用。
renew从expiry set移除旧key，当前没有stale timer增长。改成Vec线扫会损失大容量查找/
到期行为；增加额外sequence索引又增加存活内存。没有成本占比证据前，不为20条做这种
索引改造。若后来实测整代际重建显著，再以一次完整有序publication为独立scope研究。

C `cache.c:1742–1911` 的DHCP记录借用lease名字；Rust不能照搬这个借用，因为已接受
TCP视图要在父lease更新/删除后继续读旧代际。隐藏inputs保留、reader-local expiry/
rotation、ACK前发布、parent当前冲突和old/new view是接口合同，不是可删除副本。

## 本轮收尾与后续启用条件

本轮没有新增优化产品，故没有新的前后实测，也没有失败候选被冒称通过。
缓存/租约候选评估工作可记为“范围复核完成：A覆盖主要强耦合机制；独立余项收益
未证明，不扩本轮实现范围”。不能记“其余均无收益”或“内存已到C水平”。

原因可审查：A的产品resource/pressure/CPU硬门尚未完成；旧20视图深clone与singleton
账已过时；最小剩余项大多是瞬时分配或20租约下KiB以内量级；旧RDATA/singleton屏幕
保留了真实CPU/p95失败；70097历史27只是无A单轮归因，不具五轮显著性。
先获得A全部门和唯一最终135窗的剩余成本/波动，才知道进一步改动值不值得付出新的
source-bound correctness、资源和性能资格成本。

后继触发条件：最新A的allocation/CPU或full-cache/PSS存在具体可量化残余，且能把它
落到上表一个owner/调用处；root冻结一个最小候选、完整correctness与前后交错测量，
采用原协议收益/回退线、A的TCP≤1.05新无A且严格<C硬门及169零新增差异。
未达门就保留红证据撤回，不削预算。所有结论只代表构建机；物理路由器未碰。
