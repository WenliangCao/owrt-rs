# Scheme A 的有序索引 helper：强耦合部分补齐

2026-10-08。当前只准备source patch，正式27期间未生成、编译、测试或测量；A未main。基点70097无A不变，5f/b73 Vec-index原型以`archive/m6b/tcp-a-route-vec-index-b73c9d4a`保全。本文不把此前65KiB snapshot当新helper的detach、CPU或PSS证据。

## 纠正原型与选择

原型不是漏重放：NameIndex曾为 `HashMap<Arc<[u8]>, Vec<usize>>`，只共享规范key与Record；每个name的Vec在shard detach时深复制。这是最小原型偏离设计§4的强耦合helper，并不等于“inline/Many已实现”。旧3a短A/4096实际全64索引detach **368,000B/4,224 allocations**：4096个singleton Vec共32,768B，64个HashMap backing＋64个shard Arc合335,232B；parent singleton Vec容量4共131,072B，clone容量1共32,768B。旧低6bit FNV corpus每shard55–74个key，只有2个cap56、62个cap112。旧数字是历史/该corpus，不授新source资格。

现private `SlotIndices` 是 Empty / One(usize) / Many(Arc<Vec<usize>>)；空/单项无独立索引分配，shard clone共享规范key和Many薄Arc，具体写入先shard COW再Many COW。lookup迭代持有的临时Many克隆在rotation之前显式drop，唯一Many旋转不因临时观察者额外复制。有序push/remove/rotation及canonical key寿命保持原算法，generation仍u64。全局Name、RDATA、lease结构没有改。

曾准备Arc-slice版本；独立只读发现它的push/remove改长即使unique也每次重建Vec＋Arc，使同名n条commit变成O(n²)复制。root选择Arc<Vec>以保持唯一owner Vec的摊销增长与原地remove，避免这个已知成本。未采用的完整源/patch在 `E/M6B/tcp-a-index-slice-unadopted-20261008/`，manifest SHA `48bafa8b84053bd63d874c0ef7d0bc2073557a21f7aea59e3956c2c6f8e0c32c`，明确never compiled/tested/measured。

Many自身仍有两个对象（Arc中Vec descriptor＋Vec backing），有容量空隙；首次共享write复制Vec/Arc，push还可能增长backing。小RRset的Many开销不承诺比Arc-slice少，但singleton/shard detach避免逐名小分配，unique多记录增长不二次复制。enum/bucket尺寸**未知待实测**，不先称16B。key_shard改FNV高6bit，HashMap bucket随机hasher仍保留；高位分布/容量取整重新测量，不沿旧55–74分布推算。

## Mutator 清单与未执行的门

所有index写仍经names_for_mut/names_shard_mut：commit push、lookup有序匹配轮转、remove缩表/删空key、prepare_name按publication flags整体重排、clear发布新root。pending/free未进index；expiry/pressure/reverse/CNAME失效均汇入remove。reverse_bucket不改，生产不跨name-shard遍历生成wire顺序。

独立只读核对 `cache.c:312–340` insertion顺序与`cache_find_by_name:1179–1240`后续匹配移到首项前；新的原地rotate等价旧retain＋splice。publication中的DHCP/static flags仍由原prepare_name分组，不让helper重写其策略。新增source tests覆盖0/1/Many、父子order隔离、shared后unique rotation指针、实际Cache同shard另一key的detach后Many继续共享、canonical key在父clear后的子寿命。这些当前**尚未执行**。

fresh门必须重新跑：完整cache/transfer/lease/reverse/packet family；safe mutator负控；S1–S8服务；0/1/150/4096、Many2/3/64/大N的分配/rotation/push/remove与key寿命；资源/10批内部余额；新C/R3/A CPU45。layout tool已准备打印SlotIndices、HashMap及bucket payload tuple的真实AArch64尺寸、highbit shard分布，以及singleton/one→Many/Many clone/共享首rotation/unique rotation/remove allocations；另有Many2/3/64/1024连续build→共享clone→push→unique remove的真实scope与容量采集，不借旧3a收据。临时Meter新增明确System.alloc_zeroed/realloc转发，成功realloc才计Layout delta，失败保留原余额；避免旧GlobalAlloc默认realloc退化为alloc-copy-free改变Vec增长机制。输出allocations为成功alloc/zeroed/realloc请求数，不把它称libc内部malloc调用数。

## 内容块的另一项原型取舍

内容仍为 `Arc<ContentBlock { entries: Box<[Option<Entry>]> }>`，不是设计固定64-slot数组的一次Arc allocation。旧3a实测full4096 detach296,960B/128alloc：64个Arc wrapper和64个entry arrays，Entry72B；普通snapshot只clone roots、复制私有Slot16B，因此66,560B/3alloc不代表detach成本。该表示每次entry访问多一次Box指针，必须由CPU门判断，不由“共享”推导收益。

当前Box按实际尾块长度分配。由旧72B Entry/16B ContentBlock尺寸得到的**模型**：capacity1内容104B/2alloc；150按64+64+22为10,896B/6alloc；4096为296,960B/128alloc，roots/slots与allocator元数据另计。固定64数组Arc模型分别4,624B/1alloc、13,872B/3alloc、295,936B/64alloc；Box在小尾块省padding，在full4096额外1,024B和64次分配。新source/layout仍需实测核对，这里不为一次指针再扩大迁移范围，也不把模型写成新PSS。
