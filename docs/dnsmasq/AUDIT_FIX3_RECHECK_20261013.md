# FIX3 修复后的独立复核

日期：2026-10-13。审计当前 `fix/audit-20261011 = 74c6b4531111819439e38881ff9be7dc025d57ca`，比较标准仍为相对 `main = be531cee49e366bb5044443d473944dbea45b87e` 无新增功能回归、无明显性能/资源退步。上次审计提交为 `5e20291d`；之后两个产品提交为 `8c1cfefc`（共享应答路径）和 `f4722030`（raw 类型摘要）。

## 结论

**目前仍不能按原标准合入 main。修复是真的，“已经全部修好、可以合并”则不成立。**

N1 的 TCP known-name/NXDOMAIN 问题已经修复。N4 原探针中“查询类型完全不在配置里”的大幅放大已经消除，但同类型、不同名称的合法配置仍进入全表扫描。本轮 1,000 条 TYPE A 配置下，TCP 缓存命中 CPU 中位数 **31.720 → 118.558 µs/正确响应，增加 273.77%**，p95 增加 190.87%；三个配对均复现，相同配置的 UDP 对照没有同量增加。修复方自己的最终长窗口还保留了相对 main 约 13–14% 的累计 TCP CPU 增量；本轮独立重算一致，不能把它重新称为纯噪声或零回退。

N2 的权限收缩被有意保留以对齐 C；N3 重复初始化未处理；原体积预算仍失败。后两类的影响及 main 既有问题不能与 N1 修复混在一起宣称全部关闭。即使接受 N2 的权限取舍，N4 的剩余路径仍独立阻止合并。

## 状态表

| 项目 | 当前状态 | 本轮证据性质 |
| --- | --- | --- |
| N1：`filterwin2k` + warm CNAME TCP 的新 NXDOMAIN | 已修复 | fresh HEAD 重新运行原探针，与精确 C 对照 |
| N4：无关 raw 记录带来的 TCP 缓存命中扫描成本 | **部分修复，仍阻断** | type-absent 修复证据核验；另测 same-type/name-miss 合法配置 |
| 累计 TCP CPU 残余 | +14.03% / +12.86%，不是零退步 | 修复方两组各六对 120 秒窗口；本轮重新计算并校验原始文件 |
| N2：降权后不能读 root-only 普通 hosts | 有意保留 | 产品相关路径未改，修复方明确保留 C 对齐边界 |
| N3：configured hosts 重复初始化 | 未处理 | 产品相关路径未改；没有把旧峰值内存修复当成 CPU 成本已消除 |
| 构建/普通单测/RELRO | 本轮通过 | fresh release、846 单测、C/分支各三次实际映射与查询 |
| ELF/APK 预算 | 仍失败，main 已有 | 不把这个既有障碍作为本次差分合并的新增否决依据 |

## F1：P2，N4 的同类型、不同名称路径仍有明显回退

归属：**相对 main 是修复分支新增的持续成本；这次后续修复没有消除它，不是 `f4722030` 才新引入。** 它与 main 已有的 UDP 全表扫描区别明确。

新配置只将原探针的 `dns-rr=unused{i}.audit.test,65401,abcd` 改为合法 TYPE A：

```text
dns-rr=unused0.audit.test,1,c0000201
dns-rr=unused1.audit.test,1,c0000201
# ……独立名称，分别总计 100 或 1,000 条。
```

实际查询仍是此前的动态 A 缓存 bank，名字与上述配置都不匹配。C/main/当前版本均通过该配置的 `--test`，直接查询 `unused500.audit.test A` 的 UDP/TCP 都正确返回 `192.0.2.1`；不是无效记录制造的伪回退。4,096 条动态 A 逐条证明后禁用上游应答，再测缓存命中。[三方功能控制](audits/20261013/fix3_recheck/performance/same-type-smoke.json)。

代码依据：[local.rs:927](../../components/dnsmasq/src/dns/local.rs#L927) 先以 `has_raw_type(qtype)` 判断类型是否存在；存在时仍把整个 raw 列表交给 [add_raw](../../components/dnsmasq/src/dns/local.rs#L1292)，逐项比较类型并转换/分配名字键。TCP 的 [shared local-first 入口](../../components/dnsmasq/src/dns/daemon.rs#L1817)每次命中都走此路径。main 的 TCP cache-first 命中不付这次扫描。单一类型摘要能关闭原 type-absent 反例，却不能说明所有“名称不相关的配置”不再影响缓存命中。

本轮冻结 TCP 100 条、TCP 1,000 条、UDP 1,000 条三个场景，各 AB/BA/AB 三对，共 18 窗。1,000 query/s、20 clients、预热 3 秒、测量 15 秒；daemon/上游/生成器/控制器分别绑定 CPU 0/1/2/3。每窗计时前还直接验证 raw A 的 UDP/TCP 回答，确保配置没有被接受后忽略。结果为窗口中位数：

| 场景 | main CPU µs/正确响应 | 当前 CPU | CPU 变化 | main → 当前 p95 µs |
| --- | ---: | ---: | ---: | ---: |
| TCP / 100 条 TYPE A | 31.330 | 44.299 | **+41.39%** | 78.280 → 98.200 |
| TCP / 1,000 条 TYPE A | 31.720 | 118.558 | **+273.77%（3.738 倍）** | 78.401 → 228.042 |
| UDP / 1,000 条 TYPE A | 107.073 | 101.302 | −5.39% | 212.721 → 202.802 |

两个 TCP 场景均 3/3 对变差；1,000 条时两侧 CPU 相对 range 仅 5.20% / 8.79%，远小于效应。100→1,000 条时 main 命中成本近乎不变，当前版本从约 44 增至 119 µs；UDP 控制原本就做本地扫描，未出现同量的新增成本。源码机制与这组现象一致。没有做逐函数 profile 分摊，但这不是只凭源码猜测，也不依赖把 10% 设为用户可接受容差。三对给出实测描述，未声称小样本统计上的全面性能等价性。

18 窗合计 **324,000 次 warmup/measurement scheduled=sent=correct**；wrong/timeout/transport error/skip 均为 0。180 个 cgroup 节流证据点均为 0；逐窗方法、实际 ELF、同配对配置、4096 缓存证明、禁用上游应答后的零访问、初始及逐窗竞争负载检查全部通过。上游进程仍运行并计数；TCP 发包器每连接 100 次查询后重连，因此 CPU 包含正常连接成本，不是孤立 lookup 微基准。1,000 条 TCP 的 PSS 中位数 7,456→7,548 KiB，FD 都为 32；未把本次 CPU 回退写成内存泄漏或容量试验。[计划与完整 argv](audits/20261013/fix3_recheck/performance/same-type-plan.json)、[全部窗口数值](audits/20261013/fix3_recheck/performance/same-type-summary.json)、[计数与原始证据核验](audits/20261013/fix3_recheck/performance/same-type-counter-check.json)。

此问题在目标 C、main 和分支都接受的合法配置下发生，影响是持续 CPU 和查询延迟成本。它足以维持不合并结论。修复应覆盖“类型存在但名称不匹配”的本地查找，保留正确的本地记录优先级；不能仅用原 TYPE 65401 / A 的反例通过来关闭整个 N4。

## N1 与新共享路径的正确性

本轮 fresh HEAD 使用原 `filter_cname_tcp.py` 重跑 72 组（普通/debug、冷缓存、UDP 预热/同 TCP 连接预热、SOA/SRV、三轮重复）。**72/72 当前版本与 C 的完整 response 字典逐字相同**，预热响应、上游次数及健康状态也相同。保留完整报文和 TTL，未以 RCODE 单字段或 TTL 全部归一化替代原问题的验证。新 known-name 判断包含普通连接缓存快照、debug 父缓存，修复机制与结果一致。N1 可以关闭；去掉 filter 的旧 TCP known-name 缺陷也得到修复。

另外独立检查本地/缓存 TTL、EDNS/DO/畸形 additional、TCP 长度边界、上游 NX/TC/extended RCODE，以及既有 O2 终点路由差异。124 个 C/main/上次分支/当前分支案例中，123 个与上次分支全字段及上游次数相同，唯一变化修复了普通 warm A 名字的 TCP NXDOMAIN，改后与 C 一致。新观察器遇 C 的零长度 TCP frame 曾在解码阶段停止：保留先完成的 90 个案例，修正观察器后在新目录完成其余 34 个；没有把观察器错误当成产品故障或删除失败记录。[DNS 结果](audits/20261013/fix3_recheck/dns/summary.json)、[详细复核与命令](audits/20261013/fix3_recheck/dns/NOTES.md)。

未发现本次新增 DNS 功能阻断，但本轮没有把“Rust UDP=TCP”当成“等于 C TCP”。修复方的九个 O2 组合使用 C UDP 作为共用语义的允许差异，不能将其矩阵通过解释为全部等于 C TCP。本轮路由探针是连续查询流，仅两个代表重现原差异：C 不转发，main/上次分支/当前分支都转发，当前没有新增字段变化。另保留极限 65536 字节潜在响应下 C 发空 TCP frame、三个 Rust 版本返回 TC 的旧差异。未重跑所有时间、快照和并发交错边界。

## 修复方的性能证据经复核后仍说明有残余

这里使用的是修复方保留的最终类型摘要 release `0410d96c…`，不是本轮新构建 SHA。每组 100/1,000 条 TYPE 65401，TCP A 查询；1,000 QPS、20 clients，30 秒预热、120 秒测量，三对 AB、三对 BA。以配对 log 比计算几何均值和 t 区间（df=5）：

| 原配置 | 分支/main CPU 几何比 | 配对 95% 区间 | 平均绝对增量 |
| --- | ---: | --- | ---: |
| 100 条 TYPE 65401 | 1.140336 | [1.032327, 1.259645] | +4.415 µs/响应 |
| 1,000 条 TYPE 65401 | 1.128550 | [1.033532, 1.232304] | +4.236 µs/响应 |

每组 6/6 对增加。按该测量/统计模型，CPU 增加得到确认；区间下界低于 1.10，所以不能说“至少增加 10% 已获 95% 保证”。它也不能证明增量必然来自 static PIE、某个共享调用或与旧 S1 完全相同的根因。绝对约 4 µs/响应与 F1 的配置规模放大分别判断，不把两者重复计数。[独立统计复算](audits/20261013/fix3_recheck/performance/statistics-check.json)、[原完整窗口与方法](audits/20261012/fix3_repairs/performance/types-summary.json)。

修复记录本身也明确写了“不据此宣称满足原报告无明显性能退步的全面合并标准”。所谓“完成”，最多适用于它所声明的修复范围，不能推导为已达到本次合并门槛。

## 构建与证据身份

当前 HEAD 的 177 个产品/配方/打包输入，逐项与 Git、当前工作区及修复方冻结 types 输入一致，摘要为 `f6271f17755ff32cedbca5baaa822fbc356e9e1fa4491c485503006af9bf4ab1`。构建配方、linker wrapper、oracle_build、build_package 相比上次审计没有改动。[输入核验](audits/20261013/fix3_recheck/build/head-input-identity.json)。

| 本轮运行角色 | SHA-256 | 字节数 |
| --- | --- | ---: |
| exact-image C | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` | 269,305 |
| main（原冻结产物，本轮重新校验） | `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863` | 1,970,216 |
| fresh 当前 HEAD release | `25b7291d0074b8c7a854aa9f63f7b5edb12bc1315e60dd26f8f6eed36d362fd8` | 2,056,672 |

新源码在 `/home/ubuntu/dnsmasq-fix3-recheck-20261013/source`；Rust 1.98.1、opt3/LTO、feature-off，fresh release/tests 构建成功，769 lib + 77 bin = **846 通过，0 失败，23 ignored 未运行**。test-profile 与 release 分开。新 release 11 页 RELRO 全只读，三次 ASLR 基址不同，正常 UDP/TCP 查询及退出均通过。[本轮构建/单测/映射](audits/20261013/fix3_recheck/build/fresh-build.json)。

本轮没有重复两次 SDK 源码打包：相关输入未变，改为重核旧两次 SDK 的 ELF/APK、manifest/Map 与工具输入（137 个文件、106 项 SDK 输入、177 项源码输入均通过）。旧 SDK ELF 2,054,939 B、APK 1,117,233 B，同路径两次字节相同；原预算仍以 `size-target` 拒绝。[SDK 旧证据重核](audits/20261013/fix3_recheck/build/retained-build-rehash.json)。

跨源码路径的新旧 release 字节不相同，而且差异不限于 build-id；本轮不声称跨路径构建可重复或把旧测量冒充新 SHA 的执行。构建方式未变，本次没有证据将其定为新增构建阻断；关键 F1 使用的是本轮 fresh ELF 的真实运行结果。[路径/ELF 对照](audits/20261013/fix3_recheck/build/release-path-comparison.json)、[构建复核说明](audits/20261013/fix3_recheck/build/REVIEW_NOTES.md)。

此外，修复方最终功能、补充 hosts 与 32 个性能窗口的 **3,854 份保留原始文件**均重新计算 SHA 匹配。此操作只核实证据完整性，不冒称这些完整族都在本轮重新运行。[重核清单/结果](audits/20261013/fix3_recheck/retained-check.json)。

## 复现与范围

本轮新探针及派生证据位于 [fix3_recheck](audits/20261013/fix3_recheck/)。每次复跑使用新的输出目录，不覆盖原证据。F1 只改变审计 wrapper 的配置，不改产品；同一配对共用配置/速率/种子/工具，只有 ELF 和输出路径不同。正式计时前构建与 DNS 功能实验停止；3,854 份旧证据重核在首窗前约 70 秒完成，时间收据见 [coordination.json](audits/20261013/fix3_recheck/performance/coordination.json)。

F1 的参数化窗口入口是 [same_type_window.py](audits/20261013/fix3_recheck/performance/same_type_window.py)：`python3 same_type_window.py SOURCE 1000` 后接 `same-type-plan.json` 对应窗口 argv 中的原生工具、ELF/expected SHA、hit/TCP、rate=1000、clients=20、warmup=3、duration=15、CPU 绑定及全新 `--output`，并在 `run_isolated.sh` 内执行。完整配对驱动 [same_type_pairs.py](audits/20261013/fix3_recheck/performance/same_type_pairs.py) 固定了本轮 ROOT/PRIOR，重跑前需复制到新审计目录、调整 ROOT 并准备相同冻结输入，不能直接覆盖原目录。N1/边界的完整命令见 [DNS NOTES](audits/20261013/fix3_recheck/dns/NOTES.md)。

本次是对上次审计后十个产品文件改动的定向复核，没有重跑全部历史族、全部 23 个 ignored 测试或两次 SDK clean build。没有物理路由器、Cortex-A53 实机、部署/回滚、长时 soak、饱和容量、全部生产配置或跨工具链/页大小的资格证明。主线既有问题继续按原报告归属，不用它们替代 F1 的新增成本证据。没有改产品代码、合并分支、推送 GitHub 或接触路由器，用户原有未提交文档保留。

收尾重新核对 570 份本轮源码、产物、DNS 原始结果与全部 18 个性能窗口文件，全部摘要匹配；构建锁可取得并释放，没有本任务残留进程。[闭合收据](audits/20261013/fix3_recheck/closure.json)、[清单](audits/20261013/fix3_recheck/closure-manifest.json)。核验复用上次审计的参数化 `closure.py`，其 SHA 与收据一致。固件、SDK、二进制及完整原始测试目录继续留在 private，Git 只保存审计探针和派生报告。
