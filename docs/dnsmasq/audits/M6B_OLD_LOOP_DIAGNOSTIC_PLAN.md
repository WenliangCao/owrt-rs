# M5 原主循环的事后诊断冻结方案

本方案只补 M6b UDP 根因的可复现计数，不改 M6a 原始表，也不追认已经遵守“修前先计数”的顺序要求。现有本地 E/M6B 的 108 个 wake/counter 文件中，25 个有实际数据的文件均来自已修复 UDP 的候选（max_batch=16、alloc_count=1、files_timeout_2ms=0）；340 个 identity/manifest/receipt 文件也未找到旧 M5 或 d82c50ff 的主循环诊断运行身份。源码审查与约465 QPS/42ms量级推断不能替代这份缺失的计数。未访问 Oracle 或旧会话记录。

## 源码与构建

- 基底：`dc1b740d7973`，M5冻结 opt3 原 ELF SHA `37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b`，1,929,256 B。
- 独立分支 `m6b/old-loop-diagnostic`，独立 worktree `private/dnsmasq-rewrite/worktrees/m6b-old-loop-diagnostic`。本分支只增加 `m6b-diagnostics` feature，默认关闭；交付 main 不合入这些旧源码。
- 保留原调度：每轮每 listener 一次 UDP receive、每次分配65,535 B、普通 Linux `wait_for_files` 只等原有 file fds，runnable时timeout0、否则timeout2；probe和ARP原来的poll不改。
- 从该分支提交构建不可变 git archive；使用主线程当前 `oracle_build.sh` 的共享锁/target，`ORACLE_BUILD_FEATURES=m6b-diagnostics`、opt3。记录编译器、source文件 SHA、构建源码提交、ELF SHA/字节数。先构建后独占运行；窗口内不构建、测试或fuzz。
- 运行变量统一为 `DNSMASQ_M6B_WAKE_METRICS=/m6a/wake-metrics.json`。feature-off省略模块、字段和全部计数hook。feature-on每秒原子替换JSON，并追加同一固定大小snapshot到`/m6a/wake-metrics.jsonl`；总和、min/max及18个固定histogram桶，不保留逐wait数组。

## 固定环境与窗口

镜像 C / Rust 构建机的共享只读 rootfs 基底与 M6b 协议一致；此项只运行旧Rust计数伴随ELF，不重新做C性能资格。daemon绑核0、upstream1、loadgen2、controller3。使用主线程当前已冻结的 `m6a_window.py`、native loadgen/upstream，运行前保存三者SHA及实际命令；同工具不得在两窗口之间修改。runner始终`--preflight --wake-metrics --allow-rust-identity-change`，每个attempt使用fresh输出并按完整归档/逐文件SHA校验规则保全后清理。

配置采用现有runner的`scenario=hit`逐字生成配置：cache-size4096、TTL3600、no-resolv/no-hosts/no-poll/no-0x20-encode、bind-interfaces/interface lo、listen-address127.0.0.1、原UDP/TCP端口和上游端口、安全检查保持原样。runner先fill-and-prove全部4096条并禁止上游，验证真实cache命中；请求为20客户端闭环、A查询、固定seed1295401217。

| 次序 | 目的 | warmup | measurement | rate | saturation | idle CPU | drain采样 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 低速pilot，确认计数、正确回答、取样与清理 | 2s | 10s | 100 QPS | 0s | 0s | 0、1、5、60s |
| 2 | 复现465 QPS瓶颈及无负载轮速 | 2s | 15s | 10,000 QPS | 0s | 60s | 0、1、5、60s |

其余参数固定：round1、timeout1000ms、cache-names4096、drain-timeout65s。错误回答不计为吞吐。先完成第1窗口的method gate、wrong/timeout/transport_error全0、cache证明、20客户端与隔离/绑核身份；失败即保留完整fresh失败，并先修测试/计数或输入夹具，不修改旧产品行为。第2窗口是排除正式资格的诊断，不能用插桩CPU/延迟与最终opt3/s作切换判定，也不占中间27或最终135的名额。

## 计数与事前预测

普通主循环计数和主file poll单独统计；`probe_poll_calls`与`arp_poll_calls`单列，DNS-only这两项必须0。每个 listener 记录step、receive attempts、原始收到包、字节、EAGAIN、空/truncated receive、其他错误、分配次数与字节。原始收到包不自动当成正确请求；正确数和错误数以load/wire检查为准。

以每秒snapshot的monotonic增量给出loops/s、polls/s、包/s、包/loop。固定桶对真实poll等待计时（计时在poll返回后立即结束，排除计数与fd分类开销），给出平均值以及p50/p95的桶边界，不把桶中点冒称精确分位。桶在2ms附近以50–100µs宽度分辨；每个poll必须落入恰好一个桶。

预先冻结的支持/反证边界：

1. 普通file poll实际DNS UDP/TCP fd数量最大值为0；低速和高负载时timeout2为主要非runnable等待，平均实际wait接近2ms。若普通阻塞poll含网络listener，原等待解释即反证。
2. 每listener原始包数不超过step次数；高负载主监听器接近一包/loop。若每listener可一轮收多包，原一包/轮解释反证。
3. 高负载loops/s、polls/s、包/s应处于约465–500量级；包/loop接近1。若轮速明显高于正确吞吐而raw包未丢，应继续归因单轮工作，不能强行声称2ms是唯一成本。
4. allocation count等于receive attempts，allocation bytes等于count×65,535；低速/空闲也可能因每轮探空而增长。计数字节是累计分配交通，不是live heap或RSS，不能当内存节省数字。

## 分析与保全

保留现有runner `wake-counters.json`、`load.json`、wire抽查、质量门、idle CPU、资源采样、配置、运行身份、stderr与退出/FD证据，以及overlay upper中的原始`/m6a/wake-metrics.json`和`.jsonl`。逐文件SHA验证后才清远端。工具 `m6b_old_loop_analyze.py` 用controller telemetry中的同一monotonic ID匹配原始JSONL，并选择测量两端各排除2秒后的distinct snapshots；只差分固定histogram，拒绝重复snapshot、反向counter、缺raw行、histogram总数与poll数不符、probe/ARP混入或listener拓扑改变。

```text
python3 m6b_old_loop_analyze.py --window RUN_OUTPUT \
  --history PRESERVED_UPPER/m6a/wake-metrics.jsonl --output FRESH_ANALYSIS.json
```

完整measurement正确吞吐和内部counter的短interior interval各自明确分母，不把两个时段强行相除。原M6a latency作独立交叉核对；本诊断仅构建机表现，物理路由器不碰。完成后给本分支archive tag，再依工作规则退休；运行失败和本地最初compile修正均保留，不能挑窗口。
