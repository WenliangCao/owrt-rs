# M6b 诊断 trace 与正式窗口合同

2026-10-07。仅修改工具，未运行 Oracle 窗口。旧 trace 与旧失败保留，必须在新工具冻结、新 manifest 和新 attempt 中复测。

## 正式产品与诊断伴随构建

M6b manifest 必须显式记录 `instrumentation.diagnostic_only`、`wake_metrics` 和两份 build receipt 的 `features`。正式 135 窗口以及普通 pilot 使用同一个 feature-off 产品 ELF；不能附加 `--wake-metrics`、perf 或 strace。feature-on 的 `m6b-diagnostics` 只属于独立 diagnostic-only freeze，不允许由 `m6a_suite run` 跑正式窗口。即使一个 feature-off ELF 做 perf/strace 诊断，这个窗口也必须 `--preflight`，结果不能替代其未插桩的 CPU、延迟或资源资格。

wake 计数只允许 diagnostic-only companion 的短 pilot，并有独立 ELF SHA、build receipt 和 manifest。不能在每个正式窗口重复保存累计等待数组。镜像 C 没有 Rust sidecar，不把缺失计数写成实测零。

`verify_controller()` 将**实际执行**的 suite/intermediate 文件 SHA 与 manifest 的 `tools_files` 比较；仅检查冻结目录存在正确文件还不够，因为外部 mutable runner 可能执行另一份实现。intermediate receipt 另保存真实 runner 路径和 SHA。

## trace 范围和每请求分母

旧 hooks 在 `run_window` attach，从 2 秒 warmup 前一直覆盖负载、idle CPU、drain 和保留量采样。只用 15 秒 measurement.correct 作为分母，无法代表这些 syscall 的完整成功工作量。旧数字保留为范围错配的诊断，不用于收益判定。

新 hooks 在 cache 填充与 idle CPU 结束后启动，先确认 strace 的 `TracerPid`，再启动负载器；perf 同样须在负载启动前保持运行。负载器退出后等 FD 稳定 drain，然后立即停止 trace，后续 0/1/5/60 秒保留量采样不带 trace。保存 ready、load epoch、drain barrier 和 stop 的实际 monotonic 时间；`scope_complete` 要求 ready 不晚于 `warmup_start_ns`，stop 不早于 `load.run_end_ns`，工具不提前退出或被强杀。

分母固定为 `load.warmup.correct + load.measurement.correct`，包含测量窗后才完成的正确请求。每 syscall 计数、总 syscall 和 EAGAIN 均除以这个数；它是 **warmup＋测量＋尾排空期间的摊销诊断成本**，包括 drain/空闲调用、失败工作，以及 reload/TFTP 的背景事件，不能表述为 15 秒正式吞吐或未插桩 CPU。零正确请求时输出 null，不能除零。DNS 单位为正确请求；DHCP 单位为正确 DORA/renew/release cycle。

`strace -f -C -ttt -T -s 0` 同时保存完整原始返回和原生汇总。只从完成返回行计 syscall；`<unfinished ...>` 在对应 `<... resumed>` 返回时才计一次。原始 `= -1 EAGAIN` 按 syscall 保存精确 errno 计数，不能把 `strace -c` 的 errors 列当作 EAGAIN。raw 文件、SHA、每 syscall 计数和分母一起归档。strace 本身显著影响被测进程，所以它只做归因，不能进入性能分类。

## 中间矩阵与恢复

`m6b_intermediate --diagnostic perf|strace` 在独立 fresh freeze 中使用 2 秒 warmup＋15 秒 steady、0 秒额外 idle、固定 0 秒排空样本；fault/reload 使用原 pilot 的控制时间。诊断与普通 27 窗口不能在一个 state 中混用。每个 attempt 都是 fresh 输出，原失败继续保留；诊断窗口记 `diagnostic_valid_windows`，不增加正式有效窗口数。

新 runner 启动时先恢复 pending archive gate，完成原始包回拷、全 SHA/metadata 验证、prune 和 gate 恢复后，才能标记旧 attempt 有效或调度新 attempt。daemon/upstream/loadgen/controller 仍固定 CPU0/1/2/3；perf/strace 固定 CPU3。共享构建锁、foreign-load 守卫和每次 manifest/tool/ELF 验证保持；foreign perf、strace 与 M6b runner 也属于污染。

离线检查覆盖分母、unfinished/resumed、EAGAIN、失败工具停机、formal feature-off 命令、diagnostic-only 拒绝、外部 runner SHA、foreign tracer 和 pending archive 恢复；真实 attach、退出与 syscall 原生汇总仍需新 Oracle pilot 验证。
