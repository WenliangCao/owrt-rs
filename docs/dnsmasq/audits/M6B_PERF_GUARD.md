# M6b 低成本性能回归门

状态：工具接口已实现，只执行离线负控，未访问 Oracle。模板 `tools/dnsmasq/m6b_perf_guard_inputs.example.json` **不可直接运行**；没有预填任何测量阈值，也没有生产通过证据。

## 冻结输入与调用

最终功能输入添加 `"perf_guard_plan": "/absolute/private/perf-guard.json"`。plan schema 为1，`frozen=true`；`basis` 写用于冻结阈值的原始窗口/manifest/报告依据。三个 cap 必须全部显式给出：

- `udp_p50_max_ns`：纳秒，必须大于0且不超过协议保护线1,000,000 ns。
- `idle_cpu_max_seconds`：60秒无负载窗口实际 daemon cgroup CPU 增量上限，单位秒。
- `tcp_peak_pss_max_kib`：确定保持20连接时的 PSS 与短负载采样 PSS 的最大值上限，单位 KiB。

后两项不设默认值。null、缺项、非有限数字、未冻结 plan 都拒绝。`native_manifest` 指向已在窗口之外编译原生 `m6a_loadgen`/`m6a_upstream` 的既有 M6 manifest，写完整SHA；工具核验该 manifest、两份 ELF 及其中 C 源SHA与本次冻结工具树相等。guard 不构建任何东西。

`m5_final_validation prepare` 将 plan、native manifest、helper ELF 和源码加入冻结 assets；M6b 必须为 feature-off 产品 build。`perf-guard` 是固定必需阶段，package/lifecycle 前置门与 summary 自动要求它；M5 默认8阶段原合同保留。调用 `run --phase perf-guard --exclusive-window`，实际 job 为：

```text
python3 m6b_perf_guard.py --inputs PLAN --expected-plan-sha SHA
  --elf ELF --expected-elf-sha SHA --build-json BUILD_JSON
  --source-commit FULL_COMMIT --image-root EXACT_IMAGE --out FRESH_PRIVATE_OUTPUT
```

## 固定负载与观测

两个 fresh exact-image 窗口，均20客户端、2秒预热＋10秒负载、10,000施加QPS、无 saturation、cache4096、TTL3600、全A查询。沿用原窗口的 complete-wire 校验、100-query TCP重连、cgroup CPU、1Hz smaps/resources、FD稳定排空和清理合同。daemon/upstream/loadgen/controller 为 CPU0/1/2/3，不启用 wake、diagnostics feature、perf 或 strace。guard 自己持共享构建锁，持续检查 foreign build/test/fuzz；外层 final controller 要求 exclusive-window，但不重复取得同一锁。

UDP hit 窗口先填满/逐名证明4096记录并关闭上游回答；在无客户端时测完整60秒 idle CPU，再跑短负载。p50从全部正确 measured binary latency records 按 nearest-rank 计算，含窗口后才完成的正确请求；实际 correct/sent 与二进制条数必须相等，至少1000正确样本、覆盖20客户端，warmup/measured错误与timeout均须0。原始wire样本另作精确内容/TTL核验。idle CPU只用同一 cgroup `usage_usec` 的实际差值，不额外加一次子CPU。

TCP cache窗口增加工具侧20连接前奏：逐连接取一个精确缓存答复，全部保持打开，证明daemon FD比空闲值恰好多20、无child、单线程，再保存完整 smaps、PSS 与wire。关闭全部连接并完成稳定drain后，才跑短负载。PSS cap使用 `max(确定20连接时PSS, 短负载1Hz采样peak)`；这是低成本采样保护线，**不冒称连续内核瞬时峰值**。20连接前奏失败时保留partial wire/错误和drain，不能用19连接样本通过。

## 失败与证据

`result.json`给出 source/ELF/plan/build/helper身份、两条原始命令、观测值、三个 cap/布尔结果和全部失败。只有所有数据完整、正确、清理正常且三个保护线均通过，`passed`才为true。窗口错误、负控、缺样本、身份或输入变化都保留为失败；不用默认阈值补缺测、不拿最快窗口替换。外层沿用 final archive 的完整SHA/metadata回拷与prune规则，guard不自行删除raw。

保护门只防明显塌方，不能替代正式135窗口、五轮波动与尾延迟分类；结论只代表构建机，不代表物理路由器。阈值须由主线程在看到真实最终候选数据后冻结；这篇文档和模板没有设定其值。
