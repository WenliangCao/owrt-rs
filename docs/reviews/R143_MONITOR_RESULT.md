# R143：当前 R136 的 monitor 覆盖

**十窗 monitor 延迟方向未分辨，负项完整保留。** 同窗 R136/C 的 mean 比值中位变化为 **+6.096883%**，7/10 窗超过 +1%；p95 为 +4.600628%，p99 为 +7.563146%。按预冻结的六个单侧符号检验和 Holm 家族校正，全部校正 p=1，三项均未确认超过 ±1% 的方向。这不是等效、非劣或“没有退步”的证据。

| 延迟指标 | 比值中位变化 | <−1% / >+1% 窗口 | 原始 p（低 / 高） | Holm p（低 / 高） |
|---|---:|---:|---:|---:|
| mean（主项） | +6.096883% | 3 / 7 | 0.9453125 / 0.171875 | 1 / 1 |
| p95 | +4.600628% | 2 / 7 | 0.9892578125 / 0.171875 | 1 / 1 |
| p99 | +7.563146% | 4 / 6 | 0.828125 / 0.376953125 | 1 / 1 |

窗口间变化很宽：mean −19.973058%～+14.499763%，p95 −50.787085%～+63.623964%，p99 −79.157985%～+49.284024%；全部窗口和原始数组保留，未按波动删样本。统计单位为十个配对窗口，结论以窗口符号独立为假设；固定交替先后不证明没有时间相关，Holm 也不消除窗口间依赖。

描述性负项包括 **p50 +4.973578%，10/10 上升；daemon CPU/op +10.167565%，10/10 上升**。caller CPU/op 为 −0.342803%，位于预声明 ±1% 未分辨幅度带；outer wall/op 为 +6.098647%。p50、CPU 和 wall 没有事后加入显著性家族，也没有用 wall−CPU 推断等待或原因。

性能覆盖只使用 exact C 与原 generic R136 `ce3d1aa…`；没有被拒绝的 R142 候选。**10 窗、20 case、100,000 个周期、550 个原始文件全部核验**，原 `1705d989…` caller 固定 monitor n=5000/warmup=20、CPU0，daemon CPU1，同 socket/argv0，20 个 daemon 身份互异。全部原始数组、时钟、命令、ELF/library SHA、归档、stock 九组件身份、配置/挂载及清理门通过。独立标准库审计对 raw、七指标、六假设与 Holm 结果逐项一致；其 SHA 为 `3f9bde3546c1ec94f61782b1bbf791f0438c0f638ea04a5050d6dd93a3cf4ffe`。

原 caller 只开一个 monitor、小 payload，延迟包含逐 owner poll、收包及内容校验，数组未预触页；这不是纯 daemon 时间或全部 monitor 场景。旧 R131 数据没有拼入本轮，R136 既有无 monitor 注册慢尾不被取消。本轮是覆盖记录，不作候选采用或部署决定。

独立内存系列原 `memory-01` 在首个 C caller 启动时因本地 ELF 模式 0644 导致 Permission denied；JSONL 为零字节，R136 尚未开始，没有内存测量值。原失败及五项清理/同 boot/配置/生产身份/挂载门证据保留。只修正模式为 0755，helper SHA 未变；[启动修复记录](R143_MEMORY_STARTUP_FIX.md) 和元数据 proof 绑定新的同规则三窗 `memory-plan-02`，不是按结果追加样本。

修复后 **3 个内存配对窗、6 case、96 个快照、165 个原始文件全部通过核验**；每侧八阶段、1s/5s 实际等待、十个完整镜像、FD 恢复和进程身份均通过。下表单位均为 KiB；三窗以及各阶段的 1s/5s 数值相同。768 KiB 大镜像之后，停止 monitor 但保持连接、以及完全断连后的结果也都维持表中数值。

| 内核字段 | empty C | empty R136 | 大镜像后/停止/断连 C | 大镜像后/停止/断连 R136 | 后者 R136−C |
|---|---:|---:|---:|---:|---:|
| VmRSS | 916 | 500 | 1688 | 500 | −1188 |
| RssAnon | 72 | 44 | 844 | 44 | −800 |
| VmData | 44 | 48 | 816 | 48 | −768 |
| VmHWM | 916 | 500 | 3104 | 3508 | **+404** |

驻留的正项是：断连后相对各自 empty，C 的 RSS/Anon/Data 都保留 **+772 KiB**，R136 三项都回到基线。负项也保留：R136 的内核 VmHWM 字段比 C 高 **404 KiB**；相对自身 empty 的增量为 R136 +3008/C +2188 KiB，差 **+820 KiB**。empty VmData 也为 R136 比 C +4 KiB。完整 JSON 包含全部大小阶段、64 组配对和所有 150 个正向进程内字段增量。

这些是进程驻留及内核高水位字段，不能当精确分配峰值、heap/PSS、系统独占内存节省或泄漏证明。三窗只作描述，没有资源预算或内存接受决定，也没有把内存正项用于抵消延迟/CPU 负项。

内存独立审计对 165 文件、六组身份/FD/等待、96 快照、64 组配对及所有正增长逐项一致，另一次主分析派生也逐字节相同。独立审计 SHA `f81acb3376af73fbcb64ae338a98ac21339a3b43c080b12cc2f255769792f7ac`；对照器初次字段名读取修正记录保留，原数据和冻结分析器未改。

[完整性能 JSON](r143-monitor-results.json) 保留每窗原值、全部比值、方向数、范围和精确分数 p 值；[完整内存 JSON](r143-memory-results.json) 保留全部快照和增长。[冻结计划](R143_MONITOR_PLAN.md) 与[分析器](../../tools/r143/analyze_router.py) 未改。性能计划 SHA `af7052bbb3fa302ca16aab4f614a366f24e850907af8dcfd297f87e6204c9589`；性能 JSON SHA `70146ac910b4e21907918b7525a3e3deeabbeed376d4f7ac10bdc9f985970858`。正式内存 plan-02 SHA `d99d33f4487dea695ef5c22d468b50ca1e13cbb20e009d45a3739e19fcb0f516`；内存 JSON SHA `108d43de55aa597937d4d6e0e48783cff3b872f919daa7e9fe8dc72124ddd7f1`。原始、失败启动及独立审计证据在 ignored `private/r143/`。

```sh
python3 tools/r143/analyze_router.py private/r143/monitor-01 \
  --plan private/r143/monitor-plan-01/plan.json --output private/r143/rederived-monitor-new.json
python3 tools/r143/analyze_router.py private/r143/memory-02 \
  --plan private/r143/memory-plan-02/plan.json --output private/r143/rederived-memory-new.json
```
