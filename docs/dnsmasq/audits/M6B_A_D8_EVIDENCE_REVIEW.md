# M6b 独立方案 A：d8ddb22b 已回拷证据核对

本页是供主报告整合的派生增量，核对点为2026-10-08，基于本地已回拷文件及随后完成的初始门完整归档。此次未访问Oracle，未构建、未执行测试，不新增运行资格。E指 `private/dnsmasq-rewrite/evidence/M6B/`；后继新门结果须另行记账。

## 可直接并入主报告的结论

独立A源码为 `d8ddb22b3dcd3cce2eae44b0941f5c4095800b3c`，仍未合main。Oracle复制测试ELF的实际日志为库751通过、20 ignored（不计通过）；main首次51通过/1失败，使用独立TMPDIR重跑同复制ELF后52通过；UBus68通过。feature-off opt3产品ELF为1,957,928B，SHA `924bdfc240f1ef811c8eacb4035a7476f8581166469144b6e4a22a01449a2c71`，比无A 70097c66 opt3增加8,192B（0.42%）。这些结果仅确认构建和上述测试，不代表镜像服务门、资源门或CPU门通过。

实际Rust crate基础原语已完成：core21场景/22,571条命令、policy29场景/471条命令、EDNS155条命令（143 queries）、lease70场景/1,876条命令比较，均零差异/失败。core只归一化不同generic RR类型之间的相对次序；类型内顺序、值、expiry、negative、TTL、stale精确比较。lease原prep日志打印时剔除了cases数组；随后完整归档的raw result.json已确认cases长度70，逐场景命令总和1,876。四组原语明确没有镜像C守护进程资格：core使用精确hash的C函数提取和ASan/UBSan；其余组为新编译driver链接匹配源版本的既有native C对象，没有重建全部C对象。

目标机layout探针实际执行1个指定ignored测试、exit0，同复制ELF前后SHA相同，collector再次核验所得JSON逐字节相同。4096条snapshot为66,560 requested B/3 allocations；全部名字索引分片detach为243,264B/128 allocations，全部内容块detach为296,960B/128 allocations，child drop为−606,784B，三个净值平衡。singleton零分配、Many clone零分配、首次共享rotation72B/2 allocations、unique rotation/remove零分配。视图隔离正控33/33；五负控均触发指定真实测试失败：discard content/index各4、禁rotation3、保留expired reverse2、reuse generation3。探针与负控是诊断门，不是产品PSS/CPU资格，不能替代内部余额10批、S1–S8镜像服务、资源/生命周期、压力或45窗CPU门。

## 身份与核对方法

产品与工具快照分离：产品d8ddb22b，工具 `022e5f22a1ac0a8ef48f1a1bce0d20f5eb6b6d06`。本地再次计算产品ELF SHA/size，与build.json一致；feature字段为空。原语prep receipt的159个base输入逐文件对Git d8ddb22b和product-source.tar核对，零差异；163个generated输入逐文件对本地prep source核对，零缺失、零差异。prepare receipt中的 `prepared-not-built-not-run` 是不可变准备时状态，不拿它当实际执行收据，执行结果来自后续日志与收据。

| 层次 | 已有执行证据 | 尚欠资格或保全 |
| --- | --- | --- |
| 产品构建与测试 | 751/52/68实际日志；opt3产品ELF SHA/size核对 | 全套复制测试ELF/build/log及源码快照已进入初始门完整archive；main成功与失败日志分别保留；未有镜像服务/CPU资格 |
| core/policy/EDNS/lease | actual crate绑定、来源/driver/ELF hash、raw结果及全部输入/输出，controller returncode0 | 完整archive已核验；lease70场景/1876命令确证；不等镜像服务资格 |
| layout | exit0 run-receipt、复制ELF、stdout、build/prep receipts；两次collector输出同SHA | 完整archive已核验；不是10批内部余额或产品PSS/CPU门 |
| 视图隔离正控/五负控 | 六组完整run/build/source-before收据、ELF/stdout/stderr现已回拷；全部accepted、指定失败 | 完整archive已核验，前三/后三组证据现齐全；不等服务或CPU资格 |
| answer补充原语 | 首次路径拒绝；第二次仅完成fresh C driver构建，identity及build receipt已保全 | answer目录无result.json，脚本的`--build-reference`分支构建后return0，尚未运行C/Rust corpus，不能记answer对照过 |
| transfer补充原语 | fresh C36场景、每runtime307观察、跨runtime差异0；copied Rust36场景/307观察全部匹配 | 完整raw/新C receipt已保全；属于原语门，不等镜像服务资格 |
| partial EOF补充原语 | fresh C9场景/171检查全部过；Rust第一场实际0 tests，随后FileNotFoundError，compared/matched均0 | 原始失败全部保全；Rust门未过，不把lib-test进程exit0当执行资格 |
| reverse补充原语 | 本核对点未见新的执行收据 | 不以旧pins替代fresh结果 |
| 镜像服务/内部余额/压力/CPU/最终验收 | 本核对点未提供通过证据 | 均不得记过，不降低预冻结门槛 |

视图正控controller完整绑定的复制lib-test SHA为 `482d1113c612b2dc6891010d3ad925cf1e9ba376669f781f4d977f8bed512abf`，build receipt SHA为 `a21ffcb236b71f97a948de0f40800d9e071f341702d0d6ac5da6d97a9602272f`。后续copied-lib原语须引用这一身份及完整source-before核对，不能引用其他A版本的lib-test。

完整初始门快照在 `E/full-archives/a-d8-initial-gates/`，archive SHA为 `1ac1eee5a1b259c66929e928b017da36008fae59bbf45a32409408eea332663f`，manifest SHA为 `540093a9ee42606b0408ca1d2376205531399235e4e62f7b8280f52984e9d659`，10,515 entries/9,753普通文件。local-verification为verified/fullmetadata true；本次再次计算archive/manifest SHA相符，并按六组guard收据重算各复制ELF、build、source-before、stdout/stderr hash，相符且binding_after=before。plain是现场完整snapshot，活跃源路径未删除，本页不声称prune。

后三组完整guard收据现补齐，全部实际exit101且指定失败命中：

| Guard | passed/failed | raw result.json SHA256 |
| --- | --- | --- |
| disable-rrset-rotation | 30/3 | `edb9a35a4496c050d3b20d1921a8192fd46e4e7b97e85b3a0a178fcbf3723461` |
| preserve-expired-reverse | 31/2 | `5dc459185640cf29c1720aec930f4096213b1b6df3181a4c9a9f7defd2a8790d` |
| reuse-slot-generation | 30/3 | `1699bc6800bb94cbd335295ac1d44d4ed9912748295688826454800e294fbaba` |

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
| layout/guards stdin SSH通道 | 远端收据完成后stdin SSH通道未返回；核对远端无关联进程后仅终止owned本地SSH，controller rc255保留为传输异常。layout本地sidecar给run exit0；guards sidecar给全六结果，不能把controller rc255冒称产品失败或隐去 | local transport sidecar及各门完整raw已本地保全；rc255来自主线程controller记录，本页未从空的layout controller.log重建它 |
| fresh-lib-primitives-01输出路径拒绝 | 工具ROOT为tools-freeze；首次out在其外层private，answer parser拒绝“raw packets, logs and binaries must stay under ignored private/”，退出2且set−e止于第一命令，未执行任何该组corpus | 原script和0.log已进入完整archive；0.log SHA为`ebd0c1c465796ff386b5b08eb12cd12984d9f31fb56f56963de8c4c049aa71f3`。第二次换tools-freeze/private后C构建完成，但answer对照仍未运行 |
| fresh-lib-primitives-02 partial Rust | 指定`dns::tcp_transfer::partial_eof_tests::exact_c_partial_eof_probe`实际运行0 tests（771 filtered out），进程exit0；driver读取未生成的输出时FileNotFoundError。result为compared0/matched0/failed1，不能当语义差异或产品门通过 | result、第一场probe.command/stdout/stderr和原4.log全部完整保全；需要正确测试入口并重跑 |
| 初始archive首次mkdir拒绝 | 在`/home/ubuntu/dnsmasq-m6b-20261007/private/archives`建目录Permission denied；sudo修正目录后archive成功。这是controller文件权限问题，不是产品失败 | 本地`a-d8-product-prep-01/archive-initial-gates-controller.log`保留拒绝；`archive-initial-gates-02-controller.log`记录成功SHA/entry数 |

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

补充原语raw路径相对完整快照plain，SHA如下：

| 文件 | SHA256 |
| --- | --- |
| private/primitive-lease-01/result.json（70场景） | `9901e636da5e27fbd6739476ec2122171dd57cfee1dc27acffc502525afc3ada` |
| tools-freeze/private/fresh-lib-primitives-02/answer/identity.json（仅C构建） | `f5127154183c2a1d8da88439608e570a156bd49d24b0b0ace6488dbc075baa72` |
| tools-freeze/private/fresh-lib-primitives-02/transfer-c/result.json | `128a131ac25c4d2b22863044a20388677a9763acc3e1ba9ded45cde338fdd940` |
| tools-freeze/private/fresh-lib-primitives-02/transfer-c/fresh-c-receipt.json | `10242bebd8d88269a114c2be434d05b0f6fa664f9d770e3277b61aae160006f9` |
| tools-freeze/private/fresh-lib-primitives-02/transfer-rust/result.json | `b66c5f537dfbbb5529890e882aa06a9fe81ebfe38bfcc9f96a48ebaa0cf6eb8d` |
| tools-freeze/private/fresh-lib-primitives-02/partial-c/result.json | `e51da27a6cee9b5e25d1755a59faf76f5e3e8d12cdb18af94988c9cb7febb119` |
| tools-freeze/private/fresh-lib-primitives-02/partial-rust/result.json（失败） | `29935cc25c7e16bbf8bd3fb60c6107f63472d3971088dc7fc5672e00aea22cbf` |
| tools-freeze/private/fresh-lib-primitives-02/partial-rust/no-op-eof/probe.stdout（0 tests） | `8051fcb7abbd3c230eaaf3bde65ce34cb672fb47763c32b183233e3e93f9ce3d` |

后续主报告可整合本页结论，并按每个后继新门的source/ELF重新登记。A全部门未过前仍不得合main。
