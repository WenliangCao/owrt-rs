# Rust 全项目审查（2026-10-22）

状态：逐文件审查、合理修复及最终主机门禁已完成。全部预标记ignored测试均以
各自所需fixture补测；差分中的4项既有C偏差及性能微路径成本单独保留说明。
dnsmasq、TLS后续改动在oracle恢复、最终门禁及补充差分完成后才提交。

本次审查基于 `a2cc00d6`（已完成 OpenWrt 25.12.6 源码适配），覆盖当前
**427 个 `.rs` 文件、218,390 行**，包括组件、平台层、测试、examples、fuzz
和独立工具。修复不包含刷写、部署或修改物理路由器。此前的
[25.12.6 上游及发布边界](OPENWRT_25126_UPDATE_20261022.md)继续适用；源码检查
不能替代新固件的发行资格与真机验证。

## 阅读范围与长期规范

[总账本](RUST_REVIEW_INVENTORY_20261022.json)逐文件记录当前行数、SHA-256、
全文阅读状态、核对规则 ID、具体结论及分组账本。脚本核验了 Git 跟踪集和
非忽略 `.rs` 文件集完全相同、427 条路径无重复、全部哈希和行数匹配，规则
ID 均来自官方文本。哈希验证不替代实际阅读；各分组保存分段阅读和后续补丁
复核依据。原始全文阅读后的格式化/补丁沿用明确的映射或变更审查链。

先前不足的 netifd、tools、fw4、reload-config、procd、rpcd 均已重新分段补读。
早期 `RUST_REVIEW_DNS_CONFIG_DHCP_20261022.json` 明确标记为被替代的历史记录，
不参与覆盖统计；25 个 config、10 个 DHCP 和15 个 owner 文件使用各自新账本。

| 范围 | `.rs` 文件 |
| --- | ---: |
| dnsmasq（含独立 platform/fuzz） | 173 |
| fw4 / httpd / logd | 15 / 11 / 3 |
| netifd / odhcpd / procd | 22 / 12 / 22 |
| reload-config / rpcd | 7 / 36 |
| shared platform / ubus / ubusd / uci | 18 / 10 / 16 / 20 |
| tools | 62 |

微软 [all.txt](https://microsoft.github.io/rust-guidelines/agents/all.txt) 共3,529行，
已按18个不超过200行的独立输出完整阅读。文本SHA、原始发布revision及分段
记录见[规范阅读记录](RUST_GUIDELINES_READING_20261022.json)。
`AGENTS.md` 与 [Rust 长期规范](../RUST_GUIDELINES.md)已将其用于后续开发、重构、
审查和维护，并要求全项目审查保留逐文件证据。

全文覆盖不等于所有推荐规则无例外适用。独立 crate/SDK 打包布局、既有协议
错误值、单线程所有权、musl allocator、CPU目标和 syslog/CLI 输出合同保留
明确理由；不为统一样式引入新的运行时、错误框架或大规模 API 迁移。
内存安全要求没有兼容性例外。

## 实施的改进

| 范围 | 修复与核对重点 |
| --- | --- |
| DNS 数据面 | 名称压缩指针/别名改写边界、RDATA 长度和 offset、buffer pool 清理、超时溢出；保持既有 cache/转发顺序和分配模型。`M-UNSOUND`、`M-PANIC-IS-STOP`、`M-STRONG-TYPES-GUARD`、`M-HOTPATH`。 |
| DNS 生命周期与公共 API | fork/信号前置条件、lease-init SIGPIPE 恢复、独立进程测试、错误 `Display/Error/source`、脱敏 Debug；分配失败 sweep 必须实际完成一次成功恢复。`M-UNSAFE`、`M-PUBLIC-DEBUG`、`M-PUBLIC-DISPLAY`、`M-TAUTOLOGICAL-TESTS`。 |
| HTTP/TLS | HTTP控制字符与分片边界；测试读者确实在片段间产生 `WouldBlock`，覆盖每个切分点。rustls 0.23.43→0.23.46、webpki 0.103.15→0.103.16；features不变。见[TLS审查](RUST_GUIDELINES_TLS_20261022.md)。 |
| ubus/ubusd | blob offset 溢出、Registry/Method不变量、精确帧读取和独立预期；FD probe 确实检查每个目录项错误，避免 `map().count()` 跳过检查。 |
| netifd | 非对象 dump 下溢、ioctl offset 越界、无线JSON完整控制字符转义、地址族前置条件；校正已过时的模块说明。 |
| procd/fw4/platform | 进程环境修改要求显式 unsafe 所有权契约；非UTF-8父环境原字节继承；退出子进程使用 `_exit`；PID1 fixture按子进程session检查；rc队列以9个任务和同步停止验证8槽宽度。三项实例/jail测试改为实际解析与dump断言。 |
| rpcd/reload-config/logd/UCI | signed最小值、状态低字节、CLI Unicode切片和大小计算边界；UCI超大预算立即过期、Unicode诊断截断不panic；脱敏敏感调试数据及保留错误来源。 |
| 工具与静态门禁 | 修复benchmark对超长close-delimited响应的静默截断；fuzz迁移到只读API并固定独立锁文件。Linux `mbx` 门禁覆盖默认/全部features、targets、文档、examples、fuzz及格式；进程测试使用私有namespace。 |

格式化集中在独立提交 `4b764651`，便于与逻辑修复分开审阅。

## 验证

所有 Rust 编译、测试、Clippy、Miri、基准均在 oracle 上通过 `mbx` 执行，固定
Rust 1.98.1（Miri使用另行记录的nightly）；Mac未产生target目录。最终输入、
命令、退出码及101份日志的哈希见[最终门禁记录](RUST_REVIEW_VALIDATION_20261022.json)。
1,654项输入在门禁前后完全一致，见[输入清单](RUST_REVIEW_INPUTS_20261022.json)。

| 检查 | 已完成结果 |
| --- | --- |
| 14个主crate | 默认及适用的all-features/all-targets测试、doctest；Clippy `-Dwarnings`；examples编译及格式检查。最终统一轮次见派生门禁记录。 |
| feature组合与fuzz | DNS和benchmark各两个单独feature均编译通过，补齐default/all以外组合；5个fuzz target通过锁定依赖编译，fuzz已进入长期check/fmt门禁。 |
| benchmark与Python工具 | benchmark默认15+3、全部features16+3次测试调用通过；相关Clippy、release、57项Python测试、3项C语法检查通过。仓库工具/发布harness及新版8项门禁测试通过。重复导入模块的调用数不当作独立测试数。 |
| HTTP/TLS .6 | 最终49场景、39项精确比较、零差异，含TLS1.2静态GET和32KiB CGI回显。TLS1.3与旧Rust基线比较，stock TLS provider不支持，未冒称stock一致。 |
| rpcd .6 | 34项/侧共68项通过；apply/snapshot/rollback故障恢复2+3+10=15项通过。 |
| UCI / fw4 | 最终musl产物：UCI554文件比较通过；fw4固定上游31项测试通过；74项输入保持一致。见[最终复验](RUST_UCI_FW4_VALIDATION_20261022.json)。 |
| netifd / procd .6 | restart/bundle两侧共26项通过，绑定最终musl artifact与118个输入。 |
| ubusd .6 | R83完整37行一致，R92 wire/ACL共44项通过。 |
| dnsmasq .6 | 4项配置driver的157案例全部一致；两种lease-init启动模式各跑C/旧Rust/新Rust，6场景通过，旧基线确实触发SIGPIPE失败。 |
| 特权测试 | DNS18个ignored namespace案例分别隔离；odhcpd私有ubusd恢复及IPv6 namespace两项通过。 |
| 独立C primitive | 四个driver全部执行：cache205/205、stale1100/1100、cache-transfer307/307匹配C；lease269项与原始Rust基线逐字节相同，含4项既有C差异。合计1881项观测，其中1877项匹配C。 |
| Miri | ubus blob10项、DNS wire23项通过；3项耗时用例明确过滤，未声称覆盖FFI、TLS密码实现或Linux内核接口。 |

首次门禁发现PID1测试错误地假设父进程组可见、Clippy SAFETY注释位置/测试模块
顺序、以及遗漏的fuzz私有字段访问，均修复后复测。首次rpcd C侧global sync
超过工具1秒socket预算；只将测试预算改为10秒/外层60秒，未改生产timeout或
预期。root所有的旧Python缓存造成一次工具门禁权限失败，改用任务私有缓存后
通过。rsync旧mtime命中旧测试产物的问题通过checksum同步和源文件时间刷新
消除；一次时间刷新与DNS编译冲突被mbx拒绝，保留失败并在稳定源码上重建。
失败日志不算通过，旧结果不替代最终artifact身份。

cache-transfer未绕过历史ELF或语料pins：从精确tarball和13份recipe/patch
重新验证148个源文件，以已固定source identity完整重编native/musl C对象，
执行36案例×两个runtime×三次，共216条trace；通过现有fresh-C receipt检查
后才运行Rust ignored driver。收据明确这次没有复用历史对象，也不冒称修改后
的primitive是stock镜像ELF。中间两次元数据生成错误保留，未修改预期结果。

## 性能与保留边界

[DNS完整样本](RUST_DNS_PERFORMANCE_20261022.json)保留五组配对及输入/ELF身份。
默认转发912.31→909.74ns（−0.28%）、0x20转发953.57→949.47ns（−0.43%）、
本地答复−0.72%、plain-cache +0.52%；分配次数、字节数、校验和相同。
合法backward压缩名称微操作20.71→22.72ns（+2.01ns，+9.73%），plain flip
+0.997ns（+2.92%）。这是保留必要别名安全检查的成本，不能表述为所有路径
零回退。早期较慢方案的完整样本仍保存在oracle，未选择性丢弃。

TLS安静窗口六组配对的CPU中位数变化：TLS1.2握手−0.20%、keepalive +0.07%；
TLS1.3握手−0.10%、keepalive +2.34%，均低于事先规定的5%阈值。
较早受并行构建干扰的+34.79%样本保留为不确定结果，不计通过。
这些是主机微基准/进程CPU证据，不能推导物理路由器端到端性能保证。

lease primitive 的4项C差异仅在已有 `layout_reuse` cohort：C保留了已复用
存储的CNAME关联，Rust清除过期关联。本轮269项Rust输出与`a2cc00d6`完全一致；
没有为追求C输出一致而引入旧存储别名行为。原始差异和负控制保留在
[primitive记录](RUST_REVIEW_DNS_PRIMITIVE_VALIDATION_20261022.json)。
UCI差分保留已明确检查的非UTF-8 rename边界：C保存原始delta，Rust拒绝该名称
且模型/文件不变；554文件一致性统计使用该显式兼容预期，未隐去差异。

保留一个既有测试限制：`main_hostsdir_init_tests`仍有50ms墙钟上限，在极端
调度停顿下可能误报；本轮未为它引入事件循环mock重构。Miri、feature编译和
主机差分也不证明所有硬件、目标架构、OOM时序与TOCTOU路径。完整源码阅读
和这些明确边界应一起保留，不能把它们改写成“全仓无问题”或“已可刷写”。
