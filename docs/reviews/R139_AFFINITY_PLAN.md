# R139：原始 caller 的注册慢尾与 CPU 放置诊断

本计划在测量前冻结。使用 R136 全矩阵的原始 benchmark `0ca42fbafe08b7ace0aaa90f78c08c9c0f69022a64f6d5073ab6ceb77a88e693`，精确 C `cfb83044…` 与 R136 `ce3d1aa…`；不重编译 caller 或 daemon。`85dd537…` 定向 caller 与 R137 分相 caller 不混入。

四个串行保护窗口，每窗 C/R136 × caller 允许 CPU0–1、固定 CPU0、固定 CPU1，共 24 case。daemon 始终固定 CPU1，argv0 `/sbin/ubusd`，默认 ACL，socket `/var/run/ubus/ubus.sock`。每 case 启动新 daemon，仅运行原 `register-cycle SOCKET 1 8 10000 20 PID`；注册 1 方法原本也是全矩阵的第一条负载。两组条件顺序及各自逆序平衡位置和 C/R136 先后，具体顺序写入 JSON。

原 ELF 的 `exec-cpu` 设置并读回自身 mask 后 exec；每窗在计时前实际运行两种 helper，检查继承到 shell 的 mask。原 `exec-cpu-as` 启动 daemon，其 live ELF、argv、CPU mask、PID/starttime 的前后证据留存。每个 caller 的完整启动 argv 以 NUL 分隔留存，原始父 shell 的 CPU0–1 allowance 也记录并断言。**不轮询计时 caller；没有其独立 live mask 快照或逐周期迁移记录。** caller 固定 mask 的依据是精确且经前置验证的 helper、所记录命令与成功退出；此限制必须进入结果。

主诊断为 register_1 p95。令 `g[w,p] = 100 × (R136[w,p]/C[w,p] − 1)`：

- 原 allowance 的四窗 `g` 中位数严格大于 5%，且至少 3/4 窗 `g > 0`，才记原慢尾复现。
- 固定放置分别计算 `d[w,p] = g[w,p] − g[w,allowed]`。四窗中位数绝对值至少 10 个百分点，且至少 3/4 窗严格同号，才记放置敏感信号。
- 未复现时，放置效应不能解释原正式慢尾；复现且出现信号也只说明放置敏感，不能确认跨核唤醒、抢占等具体机制，不构成运行时修复或部署依据。

所有 24 case、所有逐窗 gap/interaction、mean/p50/p95/p99、daemon/caller CPU 均完整报告。只运行冻结四窗，不据结果删窗、重试、改门或加窗。后续负载或架构实验须独立计划，不追加到本集合。

复用 [r95 保护驱动](../../tools/r95_device_smoke.py) 与 [串行 runner](../../tools/r134/ubusd_router_finish.py)。已有精确 R136 实机 events/FD 正确性门为前置，不重复 55 项单测。全部六项健康/清理标志、生产 C 身份与配置/boot/mount 稳定、空对象、原始归档与展开文件一致性均需通过。任何失败保留并停止；不改生产服务、CPU governor、IRQ、sysctl 或全机调度设置。

计划生成器：[make_affinity_plan.py](../../tools/r139/make_affinity_plan.py)。冻结计划为 ignored `private/r139/affinity-plan-01/plan.json`，采集输出为 `private/r139/affinity-01/`。生成器只核对已有文件并写计划，不连接设备或运行测量。
