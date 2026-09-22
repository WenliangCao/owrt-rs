# R127：R124 当前 ELF 的路由器广覆盖矩阵

R124 ELF `42435a31e2917186fb353e2c70143f4b3f6d82ec3dd53265bf6d826897b69926` 与精确 C
`cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88` 各跑 8 个新 daemon 窗口，
顺序为 C、R124、R124、C 的四轮交错，共 16 窗口。每窗 5000 次、20 次预热；daemon 固定 CPU1，
同一个新编译 benchmark/caller，daemon argv0 统一为 `/sbin/ubusd`。

**恢复审计勘误：原报告“caller 固定 CPU0”不成立。** 已识别脚本 `fd9ba22c…ca` 确实通过
`exec-cpu-as 1` 启动 daemon，helper 会检查自身 affinity 后 exec，因此 daemon CPU1 和统一 argv0
有启动链证据；但 provider、串行 caller 和四客户端 caller 都由脚本直接启动，没有显式绑定 CPU0。
`lookup-fixture`/`rpc-fixture` 内部也不设置 affinity，raw 未保存这些客户端的实际 mask。
全部 16 窗的脚本和 helper 身份一致。数值保留为这种客户端调度条件下的实机观察，不能描述成
daemon/client 分别隔离在 CPU1/CPU0 的受控比较，也不能仅据此将大幅并发差值归因于 Rust 的批量路径。

严格 benchmark 每个操作都检查返回内容：path lookup 检查完整有序路径列表、数量、非零唯一 ID、
跨请求稳定 ID 和 `ping/{n:Int32}` 签名；pathless `*` 也检查全部返回对象。invoke 检查完整
`OBJID + DATA(ok=1)` 字节和无 FD。四客户端 lane 的每客户端原始延迟均保留；其 daemon 区间有重叠，
报告只取一个代表区间，绝不相加。

| lane | C 中位 mean µs | R124 中位 mean µs | R124−C 中位 |
|---|---:|---:|---:|
| lookup 单对象 | 48.12 | 44.82 | −5.7% |
| lookup 全量 64 | 522.39 | 349.10 | −32.2% |
| lookup prefix 64 | 511.10 | 336.33 | −33.5% |
| lookup 全量 128 | 1082.57 | 704.61 | −34.7% |
| 四客户端单对象 | 148.84 | 136.93 | −10.3% |
| 四客户端全量 64 | 2489.37 | 1004.03 | −59.5% |
| 四客户端 prefix 64 | 2556.68 | 995.21 | −61.4% |
| 四客户端全量 128 | 4536.60 | 1765.13 | −59.6% |
| invoke 单对象 | 89.92 | 83.60 | −6.0% |
| invoke 四客户端 | 261.88 | 230.90 | −11.0% |

每个 lane 只有四个交错 block 比值，不计算置信区间或总体显著性；p50/p95/p99 和每次 latency_ns
保留在机器结果中。此组记录 R124 在上述实际启动和调度条件下的 lookup/invoke 耗时均低于 C，
不能外推到注册、事件之外的路径或所有应用负载。Rust 当前批量/借用路径可能有助于并发优势，
但客户端 CPU 未控制，本组不能分离批量效果与调度影响。
仍需通过注册和连接规模检查确认没有内存或功能代价。

第一组 cohort 在第 4 窗上传脚本时 SSH 断线，未启动 daemon；其失败证据保留且不和正式 16 窗拼接。
正式 cohort 的所有窗口 cleanup/boot/config/生产身份/mounts 检查通过。最终生产 PID 869 仍为 C，
所有 `/tmp/r95-check-*` 已清理。

[机器结果](r127-ubusd-matrix-results.json)保留所有原始窗口摘要、lane、计数和限制。
本组不是最终接受判定，也不包含注册和高连接内存曲线。
