# Scheme A 增量 CPU 门：冻结接口与离线分析

状态：工具和方案准备；**未访问 Oracle、未执行性能窗口、未给方案 A 授予资格**。
本文件补充 [M6b 协议](../M6B_PROTOCOL.md) 和 [TCP 设计](../M6B_TCP_MEMORY_DESIGN.md)，不修改其数值阈值。
工具为 [m6b_tcp_cpu_gate.py](../../../tools/dnsmasq/m6b_tcp_cpu_gate.py)，只有 `plan` 和 `analyze`，没有执行入口。

## 被测身份和前置门

| 组 | 身份 | 用途 |
| --- | --- | --- |
| C | 精确 OpenWrt 镜像 dnsmasq 2.93；ELF `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` | 同配置的新参考数据 |
| R3_new | 第 1b 就绪分派/helper 修复后的无 A 产品；完整 40 位源码提交、独立 source freeze、build receipt、ELF SHA/字节 | 当前 opt3 CPU 基线 |
| A | 与 R3_new 区分的 A 产品源码提交、source freeze、build receipt、ELF SHA/字节 | 方案 A 增量 |

两份 Rust receipt 都必须是 `oracle_build.sh` 的 feature-off `release`、`opt_level=3`，使用唯一共享 Cargo target。源码输入逐文件核验；源码 remap 和私有 link-map 路径以外的 flags 必须一致。`R3_new` 必须对应新 common M6b manifest 的 r3，不能用 M6a 的旧 `dc1b740d` 数据替代。A 在 `m6a_window.py` 内使用 `--implementation r3` 仅为可执行文件分派适配；计划、收据和结果始终标为 **A**，从不标为 Rs/opt-s。

冻结前必须已有同一 A source/ELF 的资格汇总：`primitive`、`view-isolation`、`service`、`resource-lifecycle`、`pressure`、`small-cache-150`、`empty-cache`、S1–S8。每条 `passed=true` 均指向实际 evidence 文件和完整 SHA，不能用尚未执行的清单代替。资源/压力门仍需设计要求的 15 秒样本和 10 批重连余额检查；本 CPU 子矩阵的共同 runner 保存 0/1/5/60 秒样本，不替代它们。

## 固定 45 窗口

每轮按 `tcp-local → tcp-cache → tcp-miss` 执行，每个 profile 内交错三组，五轮顺序沿用共同协议：

| 轮 | 组顺序 |
| --- | --- |
| 1 | C → R3_new → A |
| 2 | R3_new → A → C |
| 3 | A → C → R3_new |
| 4 | C → A → R3_new |
| 5 | A → R3_new → C |

三组采用同一 `m6a_window.py`、原生 loadgen/upstream 和镜像 rootfs。配置直接保存 `config_for(tcp, profile)` 的完整字节；cache-size4096、TTL3600、DNS forward limit1024、20 客户端、100-query 重连合同、施加 10,000 QPS 不变。local 使用配置本地回答；cache 实际填满并验证 4096 个 A 名字且禁用上游；miss 使用原生负载器的未命中名字和固定合法上游回答。

每窗先执行共同短 pilot（2 秒预热、10 秒负载、末 3 秒 saturation、5 秒 idle、同排空采样），再执行 **60 秒无负载 CPU、30 秒预热、120 秒负载**；正式负载前 90 秒 steady、末 30 秒 saturation 分开算。负载器结束并关闭后，Rust 必须回到预热前实测 FD 数、无子进程并连续三个独立 20ms 间隔观察稳定，再保存 0/1/5/60 秒排空值。C 的 FD 异常同样报告，不用 child=0 冒称 Rust 排空。

绑核固定 CPU0 daemon（含 C children）、CPU1 upstream、CPU2 native generator、CPU3 controller。窗口持共享构建锁，禁止其他 build/test/fuzz/perf/strace；正式 ELF 和窗口不启用 wake/diagnostics。pilot/formal 的完整 argv、实际 ELF、配置、CPU affinity、开始/结束时间和 foreign-load 记录必须保留。分析器核对实际窗口时间顺序，静态交错计划不能替代执行证据。

## 事前预算与结果解释

CPU 定义为 `u=daemon cgroup usage_usec delta / 本阶段内正确完成请求`。cgroup 已计 C children，**不再加 child CPU**；proc 只作交叉核验。原始正确请求延迟全部保留，跨阶段/迟到处理沿用 `m6a_analyze.py`；p95 不先求窗口平均，p99 的样本门也不变。

每个 profile 的 **steady 和 saturation 各自**都必须满足五轮中位数：

- `median(u_A) ≤ 1.05 × median(u_R3_new)`，并且 `median(u_A) < median(u_C)`；
- `median(QPS_A) ≥ 0.95 × median(QPS_R3_new)`；
- `median(p95_A) ≤ 1.05 × median(p95_R3_new)`。

A 的 ordinary wrong/timeout/transport error、FD 泄漏必须为零，包括 pilot。C/R3_new 的真实错误保留为基线观察，使用正确回答分母并逐组报告，不伪造方法无效，也不把它们直接称为 A 回退。任何组的真正强杀/异常退出或清理残留都是终止失败；明确环境污染导致的强制清理仍是方法无效，可以 fresh 重跑。

收益/回退分类复用冻结的 W、4/5 同向和幅度门。generator-limited 时只限制 QPS 收益分类；CPU/p95 和 observed QPS 数值预算仍机械执行，不豁免 A。工具另明确列出 `numeric_passed`、`cpu_budget_passed` 和 `throughput_qualification`。生成器限制使吞吐资格未获证明时，整体为 `unproven` 并写明原因，45 行仍是方法有效的数据；这不等于 CPU 预算失败或通过被放宽。

必须有 45 个完整、方法有效、每组五轮的对应窗口。不能以一个 C/R3 baseline 对五轮 A，也不能替换一轮真正失败的尝试来选最快窗口。方法无效的尝试保留完整原始文件、收据、SHA/元数据验证后，才允许原位 fresh attempt；下一窗口前完成归档门。最终 9×3×5 的 C/最终opt3/最终s仍是另外一次资格，不能拼入本门或用本门取代。

## 输入与输出接口

`inputs.json` 是 private 下的脱敏来源绑定。所有 `path/sha256` 引用必须是实际存在的文件，SHA 为完整 64 位；示意占位符不能通过冻结：

```json
{
  "common_manifest": {"path": "/…/private/common/manifest.json", "sha256": "<full64hex>"},
  "groups": {
    "R3_new": {
      "source_commit": "<full40hex>",
      "source_freeze": {"path": "/…/no-a/freeze.json", "sha256": "<full64hex>"},
      "build": {"path": "/…/no-a/private/opt3/build.json", "sha256": "<full64hex>"},
      "elf": {"path": "/…/no-a/private/opt3/dnsmasq-rs", "sha256": "<full64hex>", "bytes": 0}
    },
    "A": {
      "source_commit": "<different-full40hex>",
      "source_freeze": {"path": "/…/a/freeze.json", "sha256": "<full64hex>"},
      "build": {"path": "/…/a/private/opt3/build.json", "sha256": "<full64hex>"},
      "elf": {"path": "/…/a/private/opt3/dnsmasq-rs", "sha256": "<different-full64hex>", "bytes": 0}
    }
  },
  "prerequisites": {"path": "/…/private/a-prerequisites.json", "sha256": "<full64hex>"}
}
```

source freeze 采用共同工具的 `source_commit/source_root/source_files`。prerequisite JSON 包含 `source_commit`、`elf_sha256` 和 `gates`，后者每个必需键为 `{"passed":true,"evidence":{"path":"…","sha256":"…"}}`。

由 root 核验实际来源并准备共同 manifest 后，才生成不可覆盖的计划；下面命令只产生 JSON/argv，**不执行窗口**：

```sh
python3 tools/dnsmasq/m6b_tcp_cpu_gate.py plan \
  --inputs private/tcp-a-cpu/inputs.json \
  --output-root /home/ubuntu/…/private/tcp-a-cpu \
  --output private/tcp-a-cpu/plan.json
```

执行适配器必须按 `schedule` 串行消费，source/build/features 不另行猜测。`state.json` 用 `plan_sha256` 绑定计划，`windows[job_id]` 含显式 `valid_attempt` 和全部 `attempts`。每个尝试保留 `attempt/group/source_commit/elf_sha256/protocol_sha256/plan_sha256`、`methodology_valid`、`pilot_passed`、两份结果 SHA、`pilot_command/formal_command`（精确 argv、started_ns、finished_ns、returncode、foreign_load）以及既有 `archive.local_verified`。C 的 source_commit 为 null，Rust 为各组完整提交。ELF 身份还核对实际 process-identity，不能只相信命令参数。

方法与行为分开记账：常规回答错误不清除 `methodology_valid`；旧 runner 的 accepted=False 只有在完整独立 raw 检查和全部采样质量字段都通过、失败明确来自产品行为时，才可解释为方法有效的失败观察。负载/采样/协议/环境不成立的仍为方法无效。即使旧收据只有 valid_attempt=null，来源正确且环境干净的原始真实失败也会被扫描并保留，不能下一轮悄悄替换。

本地完整 SHA/元数据核验后，从 `runs/job/attempt-N/formal` 或 `archives/job/attempt-N/plain/formal` 读取原始 binary latency、send-lag、wire samples、资源和 receipt；分析无网络访问：

```sh
python3 tools/dnsmasq/m6b_tcp_cpu_gate.py analyze \
  --plan private/tcp-a-cpu/plan.json \
  --root private/tcp-a-cpu/archived-private \
  --output private/tcp-a-cpu/analysis.json
```

输出包含全部窗口、六组 profile/phase 预算、A/C 与 A/R3_new 的原始五轮值/W/绝对和相对代价、逐组成功/错误计数、idle CPU、失败/全部尝试/missing jobs，以及 `qualified/unproven/failed/incomplete`。文件不覆盖旧实验。资格只描述 Oracle 构建机；不触碰物理路由器。

## 离线验证

16 项 CPU 门测试和共同 analyze/window/suite 回归 **49/49 通过**；独立只读复核无阻塞缺陷。覆盖 5% 边界、严格低于 C、cgroup 单次计量、A/Rs 误标、feature-on/s 错用、缺少前置门/窗口、污染后清理、真正强杀、错误答案、基线 pilot/receipt 错误、FD/child-only 排空、实际交错顺序、generator-limited、部分质量字段和选较快重跑等负控。全部为离线工具验证，不代表 A 性能预算已通过。
