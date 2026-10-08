# M6b 独立方案 A：d8ddb22b 已回拷证据核对

本页是供主报告整合的派生增量，核对点为2026-10-08，基于本地已回拷文件。此次未访问Oracle，未构建、未执行测试，不新增运行资格。E指 `private/dnsmasq-rewrite/evidence/M6B/`；后续完整归档和新门结果须另行记账。

## 可直接并入主报告的结论

独立A源码为 `d8ddb22b3dcd3cce2eae44b0941f5c4095800b3c`，仍未合main。Oracle复制测试ELF的实际日志为库751通过、20 ignored（不计通过）；main首次51通过/1失败，使用独立TMPDIR重跑同复制ELF后52通过；UBus68通过。feature-off opt3产品ELF为1,957,928B，SHA `924bdfc240f1ef811c8eacb4035a7476f8581166469144b6e4a22a01449a2c71`，比无A 70097c66 opt3增加8,192B（0.42%）。这些结果仅确认构建和上述测试，不代表镜像服务门、资源门或CPU门通过。

实际Rust crate基础原语已完成：core21场景/22,571条命令、policy29场景/471条命令、EDNS155条命令（143 queries）、lease1,876条命令比较，均零差异/失败。core只归一化不同generic RR类型之间的相对次序；类型内顺序、值、expiry、negative、TTL、stale精确比较。lease日志打印时剔除了cases数组，不能凭当前prep日志声称“70 cases”。四组原语明确没有镜像C守护进程资格：core使用精确hash的C函数提取和ASan/UBSan；其余组为新编译driver链接匹配源版本的既有native C对象，没有重建全部C对象。

目标机layout探针实际执行1个指定ignored测试、exit0，同复制ELF前后SHA相同，collector再次核验所得JSON逐字节相同。4096条snapshot为66,560 requested B/3 allocations；全部名字索引分片detach为243,264B/128 allocations，全部内容块detach为296,960B/128 allocations，child drop为−606,784B，三个净值平衡。singleton零分配、Many clone零分配、首次共享rotation72B/2 allocations、unique rotation/remove零分配。视图隔离正控33/33；五负控均触发指定真实测试失败：discard content/index各4、禁rotation3、保留expired reverse2、reuse generation3。探针与负控是诊断门，不是产品PSS/CPU资格，不能替代内部余额10批、S1–S8镜像服务、资源/生命周期、压力或45窗CPU门。

## 身份与核对方法

产品与工具快照分离：产品d8ddb22b，工具 `022e5f22a1ac0a8ef48f1a1bce0d20f5eb6b6d06`。本地再次计算产品ELF SHA/size，与build.json一致；feature字段为空。原语prep receipt的159个base输入逐文件对Git d8ddb22b和product-source.tar核对，零差异；163个generated输入逐文件对本地prep source核对，零缺失、零差异。prepare receipt中的 `prepared-not-built-not-run` 是不可变准备时状态，不拿它当实际执行收据，执行结果来自后续日志与收据。

| 层次 | 已有执行证据 | 尚欠资格或保全 |
| --- | --- | --- |
| 产品构建与测试 | 751/52/68实际日志；opt3产品ELF SHA/size核对 | 产品tests的全套复制ELF/build/source-before收据尚未完整本地归档；main成功日志与失败日志分别保留 |
| core/policy/EDNS/lease | actual crate绑定、运行摘要、来源/driver/ELF hash，controller returncode0 | 四组原始输入/输出、C/Rust ELF及build receipts尚欠完整本地archive；lease cases长度待raw result.json确认 |
| layout | exit0 run-receipt、stdout、build/prep receipts；两次collector输出同SHA | layout复制ELF及全source/build目录尚欠完整本地archive；不是10批内部余额或产品PSS/CPU门 |
| 视图隔离正控/五负控 | actual-six-results及transport sidecar均给六组accepted、指定失败；controller.log含前三组完整收据 | 后三组本地目前仅聚合结果/sidecar，完整run/build收据、全部六组ELF/stdout/stderr仍待全量archive |
| answer/transfer/partial EOF/reverse补充原语 | 第一次补充执行在answer参数检查即拒绝，未开始corpus | 对照尚未因此取得资格；第二次及reverse以各自新收据记账，不能用旧pins充fresh |
| 镜像服务/内部余额/压力/CPU/最终验收 | 本核对点未提供通过证据 | 均不得记过，不降低预冻结门槛 |

视图正控controller完整绑定的复制lib-test SHA为 `482d1113c612b2dc6891010d3ad925cf1e9ba376669f781f4d977f8bed512abf`，build receipt SHA为 `a21ffcb236b71f97a948de0f40800d9e071f341702d0d6ac5da6d97a9602272f`。后续copied-lib原语须引用这一身份及完整source-before核对，不能引用其他A版本的lib-test。

## 结构账的适用范围

| 目标机类型 | 字节 |
| --- | ---: |
| Slot | 16 |
| Entry | 72 |
| Record | 56 |
| ContentBlock | 16 |
| Cache | 208 |
| SlotIndices | 16 |
| NameIndex | 48 |
| NameIndexEntry tuple | 32 |

snapshot由65,536B owner slots和1,024B root vectors组成。64个名字分片长度42–85，全部分布留在layout JSON。ordinary hit净requested16B/4 allocations也保留，不把单点helper“零分配”扩写为整体命中路径零分配。旧Vec-index 368,000B/4,224 allocations是历史原型结果，不能充新Arc<Vec> helper结果。计数探针使用POD TLS限定作用域并原样转发System，所得为requested结构账，allocator驻留、页粒度、内核内存均不在其中。

## 失败和传输异常

| 记录 | 已确认原因与处置 | 保全边界 |
| --- | --- | --- |
| a-linux-766-first-failed | main51/1，S8夹具向max1232 framer写`ff ff 01`，声明65535，实际TooLarge。d8只把夹具改为合法partial1232 frame `04 d0 01`，未改变产品限制或放宽断言 | 完整失败archive与manifest/local-verification/prune均在本地；含两复制测试ELF和原日志 |
| a-d8-tmp-collision-failed | d8 main51/1，mkfifo失败。上一panic留下FIFO，namespace PID1重复路径冲突；run_isolated不隔离/tmp。同复制ELF换独立TMPDIR后52/52 | 完整失败archive包括leftover.fifo元数据；不得将首次失败删改为通过 |
| a-d8-primitive-apple-metadata | 初次macOS tar附加`._`文件，严格source/build input SHA检查真实拒绝；不是原语corpus失败。新源码传输使用Python GNU_FORMAT tar、重建干净probes后四组执行通过 | 6,315路径/6,063普通文件完整失败archive，含源码、ELF与identity-rejection日志 |
| layout/guards stdin SSH通道 | 远端收据完成后stdin SSH通道未返回；核对远端无关联进程后仅终止owned本地SSH，controller rc255保留为传输异常。layout本地sidecar给run exit0；guards sidecar给全六结果，不能把controller rc255冒称产品失败或隐去 | local transport sidecar在本地；rc255来自主线程controller记录，本页未从空的layout controller.log重建它。各门完整raw仍待archive |
| fresh-lib-primitives-01输出路径拒绝 | 工具ROOT为tools-freeze；首次out在其外层private，answer parser拒绝“raw packets, logs and binaries must stay under ignored private/”，退出2且set−e止于第一命令，未执行任何该组corpus | 本地原script保留；controller.log为空，远端0.log/实际退出记录尚待完整回拷，不声称已完整保全。新out须在tools-freeze/private且使用fresh目录 |

以下三份已存在失败归档，本页重新计算archive及manifest SHA，与已有local-verification相符。既有验证报告注明type/mode/uid/gid/纳秒mtime/link/device/xattr全核验后prune；此次只重新核对SHA与报告身份，没有另跑metadata验证器。

| 完整失败archive | Archive SHA256 | 路径/普通文件 |
| --- | --- | --- |
| a-linux-766-first-failed | `1285a3b325e9da49018dcd9566b74a430aca7b6fa619f72d6002a71a8e13ece0` | 11/9 |
| a-d8-tmp-collision-failed | `5975ba44877183f80a7c1d701125b874adea9eaebe52eb817b5fba09a46a9f4d` | 12/9 |
| a-d8-primitive-apple-metadata | `c129b825ac4e0b854e0eb75807a4d754836c00ba3e4a332e1054f441fc42567c` | 6315/6063 |

## 本地证据SHA索引

路径相对E。原始证据不入Git；本表仅派生身份。

| 文件 | SHA256 |
| --- | --- |
| a-d8-product-prep-01/lib-tests.log | `66c1311c28d1bad3d805d23703bd7ba45338bc0124ee3176093d6e56521cebb3` |
| a-d8-product-prep-01/bin-tests.log（失败） | `dca70637c6768538e1edddb7dd8870ed2e8e27d465b8a769d195e782b172c7ef` |
| a-d8-product-prep-01/retry-main-02.log（成功） | `4c499826015626e3d1552c00f2e36ab0ab794cfc241856fd86f5381284e4e8a7` |
| a-d8-product-prep-01/ubus-tests.log | `3388fa0c5b0b89e215497c3e75ead9036fbbb86cfbcf277fc6d75227b15cab7b` |
| a-d8-product-prep-01/opt3/build.json | `1f643629c0f81e4d11b73cd541f596e32a78634d07c34ab6109de395554a79eb` |
| a-d8-primitives-prep-01/source-receipt.json | `0161a24ea2643c7480803e361bfe90e30a1717408016b20c3c354e0445d8bbcd` |
| a-d8-primitives-prep-01/primitive-core-01.log | `e8bed9ec9c1dd837849a01addde8a8946a0a8ad73497bff034aefdbb09c63d5f` |
| a-d8-primitives-prep-01/primitive-policy-01.log | `88749e32b3e01b566801658593713f55c3e444199bdf46a3a5599c88224f4194` |
| a-d8-primitives-prep-01/primitive-edns-01.log | `a2a31dc3745fae7109d0d3626bd0c7385edfc31cafba0dd9f5b5e986a107a6ba` |
| a-d8-primitives-prep-01/primitive-lease-01.log | `f2cb21a35a4d1d5c9ee0f127cc19c0289e48c2a0197bbd93b84f1c2aa035a57b` |
| a-d8-layout-prep-01/layout-report.json及layout-report-verify-02.json | `fd32ece8295e57f6ba0b85281979c2797b83c641c283c8e516dcab9ad21983b9` |
| a-d8-layout-prep-01/run-receipt.json | `b352a5a155616319e414a1419a38d3846ac0b4c6916c9a7326e514857b4fc135` |
| a-d8-guards-prep-01/actual-six-results.json | `176f1713d0ee228d74157d1928e7a0042d77b438c2b2c5d20e75b6280479ed87` |
| a-d8-guards-prep-01/oracle-controller.log | `2da091428be4592e1b5bc92474f61fe15ba5ccacf7ccd39361180f68bf009fc4` |

后续主报告可整合本页结论，但须以新完整归档manifest更新保全栏，并按每个新门的source/ELF重新登记。A全部门未过前仍不得合main。
