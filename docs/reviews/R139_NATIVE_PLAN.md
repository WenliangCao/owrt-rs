# R139：原生 libubus caller 的独立注册诊断

使用新独立 `register-libubus-latency` caller，链接与镜像匹配的 libubus/libubox 接口并在实机使用精确镜像动态库；旧 CPU-only caller 保留不变。**只有新 caller 精确 ELF 的 Oracle C/R136 功能 smoke 通过，才生成冻结计划。** smoke 必须核对完整签名、循环成功、末尾清空、CPU 亲和性和精确库/daemon 身份；n=100、warmup=20 仅作功能前置。

四个串行窗口，各包含 C/R136 两侧，先后顺序为 C→R136、R136→C、R136→C、C→R136，共八例。每例新 daemon、caller CPU0、daemon CPU1，运行 `register-libubus-latency SOCKET 10000 20 PID`，仅 1 方法注册。daemon 保持精确 C `cfb83044…`、R136 `ce3d1aa…`，argv0 `/sbin/ubusd`、默认 ACL、socket `/var/run/ubus/ubus.sock`；原 `0ca42…` benchmark 只作 `exec-cpu[-as]` helper。新 caller 通过驱动 `--event-benchmark` 传入。

同一 native caller 内令每窗 `g = 100 × (R136/C − 1)`。主诊断为 p95：四窗配对变化中位数严格低于 −5% 且至少 3/4 窗降低，记 lower；严格高于 +5% 且至少 3/4 窗上升，记 higher；其余 unresolved，不证明等效。完整报告八例及 mean/p50/p95/p99、daemon/caller CPU 的所有四个配对差值。不删例、不重试、不改门、不追加窗口。

caller 保留逐周期原始 wall 样本、整轮两进程 CPU 时钟与完整签名前后检查。整轮 CPU 包含读钟/循环开销，不扣除探针开销。**这是独立 caller 的覆盖诊断，不能比较 native 与 Rust caller 的绝对延迟，也不能撤销旧正式慢尾负项或据此采纳候选。**

复用既有 r95 保护器、r134 串行 runner、精确 R136 的 events/FD 正确性门；不重编译 daemon，不重复既有单测。每窗前后核对 caller/daemon/helper ELF 与四项镜像动态库，保存 daemon live identity/argv/affinity/starttime、caller 启动 argv、退出与空对象证明。全部六项健康/清理门和原始归档一致性仍必需。

生成器 [make_native_plan.py](../../tools/r139/make_native_plan.py) 只写计划。默认计划 `private/r139/native-plan-01/plan.json`、结果 `private/r139/native-01/`；`--caller` 与 `--smoke` 明确指定最终本地产物和通过记录。主线程仅在当前 affinity 四窗结束且清理核验后启动，本工具不自动运行或追加采集。
