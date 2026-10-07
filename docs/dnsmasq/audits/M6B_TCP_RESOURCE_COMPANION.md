# TCP A 内部资源诊断 companion（准备，未验证）

2026-10-07。本分支从A `5f3d42b4` 建立，只有工具模板、生成器和本文；产品组件、main与账本均未编辑，未访问Oracle、未运行生成器、编译、测试或压力窗口。运行时必须指定最终冻结A的完整source commit与product ELF SHA，工具不写死5f。新增有序名字索引helper若使用Empty/One/Many，不改变本文root锚；其Many Arc不是content/index root，不能纳入根版本计数。

复用 [M6B_TCP_MEMORY_DESIGN](../M6B_TCP_MEMORY_DESIGN.md) 的ignored/private `E/M6B/tcp-memory-design/m6b_alloc.rs` 方法：原System分配器、成功Layout requested计数、无每对象header。旧instrumentation.patch只是定位来源，不原样搬回M5字段；新模板补齐每处unsafe与unsafe impl的SAFETY，alloc/alloc_zeroed失败不加余额，realloc失败保留旧块，成功只计尺寸delta而不假造free/new对象。它是诊断包装，提交产品和交付ELF必须关闭。

`tools/dnsmasq/m6b_resource_companion.py prepare` 从完整commit的Git archive导出fresh ignored copy，只在copy注入。收据保存archive/全部原源码/生成源码SHA、每个窄锚期望与实际计数、完整diagnostic.patch、generator与3个模板SHA；任一锚数量变化直接失败，禁止模糊补丁。`bind`必须绑定同源product build、product ELF、共享target的oracle_build.sh diagnostic build及different ELF SHA，另写新收据，不覆盖准备收据；status仍built-not-validated，不能变成产品功能/CPU/PSS通过。

所有内部API只存在于生成copy：

| 数据 | 来源／边界 |
| --- | --- |
| live requested、peak、成功alloc/zeroed/realloc/free、对象余额 | GlobalAlloc逐操作原样转发System，仅原子计数；包括Rust全局分配调用，不包含直接libc分配、mallocng元数据/空闲页、内核缓冲、栈或完整RSS/PSS。 |
| observer registry requested | scope仅围绕registry的HashMap操作；key/value为裸地址与标量，不拥有产品Arc/Vec。reserve/realloc/free与TLS最后释放都在scope内，allocator不进入registry、不使用TLS、不递归。单owner无其他线程，作用域不跨I/O/回调、不返回堆对象给产品；违反这些约束不能用observer相减解释余额。 |
| clients/G、dns_work Some、cache views、TCP pending、UDP pending | main在完整owner step返回后读实际字段／getter。log-only client保持G，work=None不访问DNS字段；typed capture/import在step内部同步消费，行内typed_transfer_inflight=0仅是该采样点源码合同，不是注入任意C pipe片段的实证。 |
| distinct content/index allocation版本 | 只包装cache.rs既有root Arc::new与make_mut窄锚。构造重用地址重置version；make_mut只有实际换地址才注册新版本。不加Weak／强引用／对象字段，因此不触发额外COW、改变Entry布局或延长root寿命。 |
| old pinned／private roots | parent在tcp_cache_view接受快照前标记root；采样当前父与所有views。曾见于父且当前仅view拥有的allocation版本记old pinned，child新detach且从未父拥有的记private；“old”描述allocation来源，不承诺私有owner后来没有原地改其内容。 |
| registry容量及成长 | 每样本prune不被任何当前owner观察的标量记录并shrink，避免10批/churn保留整个地址历史。单列len/capacity/requested；地址复用由所有窄创建锚覆盖，missing_creation_hooks非零即方法失败。不得仅以total-observer算数相减手填产品余额通过。 |
| 输入与日志等capacity | client Vec inline bytes、私有view LRU、cache pending/reverse、input/framer/Writing/WaitingMac/stale/MAC、query-event descriptors、上游query/frame/reply、accepted log队列与payload。不是逐字节穷尽账；本地config/hosts/lease/RR payload仍由总分配余额覆盖，需与静态布局/feature-off smaps交叉核验。 |

每行只输出标量JSON，不输出每轮地址/根派生数组；1Hz约数百KB／几分钟，不制造旧2GB wake明细。输出fresh regular trace文件，增加1FD；write失败退出为方法错误，不能改成成功。正常owner wait增加诊断timer，CPU、唤醒、吞吐、延迟和PSS会改变，**全部不参与产品资格**。不对nested DHCP probe加未消费的timer，以免诊断自身忙等；若被完整step延迟，只记录实际时间，不假称精确1s。

每个完整step都会判断drain转换，行内full_drained必须clients/work/views/TCP+UDP pending都0。实际完成busy→drained时开始0/1/5/15/60秒点，另保留1Hz；新负载取消尚未采完的上一drain周期。每行保留epoch、nominal与实际monotonic间隔，不能以晚到0点解释瞬时释放。G>0的log-only窗可由周期行观察work释放，不能当全部client排空。cache pending插入链是C语义状态，不是另一个异步事务队列，不据其非空制造产品重试或强制清理。

窗口结束后由root执行，以下仅计划命令（未运行）：

```sh
python3 tools/dnsmasq/m6b_resource_companion.py prepare \
  --repository "$M6B_REPO" --source-commit "$M6B_A_COMMIT" \
  --product-sha256 "$M6B_A_SHA" --out "$M6B_REPO/private/m6b-a-companion-01"
```

将完整输出传入Oracle fresh目录，保留准备收据，按统一oracle_build.sh/共享target串行构建生成copy；记录toolchain、opt3、feature-off、static libc和link map。运行namespace trace环境变量为 `DNSMASQ_M6B_RESOURCE_TRACE=/m2/diagnostic.jsonl`。迁移后bind可显式给 `--diagnostic-source-root`，但每个源码SHA仍须相等。

```sh
python3 "$TOOLS/m6b_resource_companion.py" bind --receipt "$PREP/receipt.json" \
  --diagnostic-source-root "$DIAG_SOURCE" --build-json "$DIAG_BUILD/build.json" \
  --diagnostic-elf "$DIAG_BUILD/dnsmasq-rs" --product-build-json "$PRODUCT_BUILD/build.json" \
  --product-elf "$PRODUCT_BUILD/dnsmasq-rs" --out "$PREP/bound-receipt.json"
```

构建后先验证下列方法controls，再跑设计已有11profile/至少10批。全部当前是**not run／balance unproven**，不得因准备代码提交而关闭内部余额门：

1. System分配/zeroed/成功原地或移动realloc/free尺寸与对象余额；失败realloc保持旧块及计数；计数hook无分配、日志或递归。observer scope的纯registry对象在reserve→grow→clear→TLS drop均平衡；scope外实际产品分配不能进入observer余额。
2. 相同source原型与copy的Slot/Entry/ContentBlock/NameIndex布局、Arc strong/weak计数一致；hold view后命中不detach、单块/单shard写只注册相关版本。刻意泛扫Many/Record Arc、漏创建锚、漏detach锚和地址重用都应被controls拒绝；不以record pointer当root。
3. 20连接、旧parent roots被churn取代、child private更新、reload与最后view释放，old/private计数符合真实强引用生命周期；10批后views/roots/pending归零或仅父常驻，单列registry容量/余额。用已知分配正控证明小对象漏drop会增加total而非observer，不能仅从PSS／两值相减证明无泄漏。
4. EOF/deadline/stale pending→import→log-only handoff，G1/work0可观察，stale refresh未完成仍work1；0/1/5/15/60 actual间隔满足目标。busy打断drain、FIFO阻塞与诊断write错误必须保留不完整周期及异常，不拼最快窗口。
5. 同源feature-off ELF的FD/PSS/smaps仍独立测，诊断加1FD及registry/格式化/计数/timer开销不能外推为产品CPU或PSS。全部trace、失败、receipt/ELF/source/patch逐SHA归档后才清远端。
