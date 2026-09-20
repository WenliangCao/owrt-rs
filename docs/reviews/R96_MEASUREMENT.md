# R96：断电后重新核验与 CPU 计量

2026-09-20，用户恢复任务。已重新确认新 boot 的九组件均为生产 C、客户端/AP/LAN/WAN/DNS/HTTPS
正常。重新读取并完整验证五份离线备份和两份恢复镜像，生成本次 boot 的 recovery gate；旧 gate 不复用。
没有部署、切换组件或改动固件。[派生验证记录](r96-cpu-clock-validation.json)。

## CPU 时钟补充

旧 `/proc/PID/stat` 计数继续保存，不改变历史定义。新增 libc `clock_getcpuclockid` / `clock_gettime`
读取整个进程的 CPU 时钟，包括工作线程，不包括子进程；snapshot 同时保存内核报告的分辨率。
读取失败、PID 更换、时钟倒退或分辨率改变会使检查失败，不伪造值或静默退回 tick。
外部时钟读取依据 [Linux 接口文档](https://man7.org/linux/man-pages/man3/clock_getcpuclockid.3.html)，
并核对 [Linux 6.12.94 的进程组 CPU 采样实现](https://github.com/gregkh/linux/blob/v6.12.94/kernel/time/posix-cpu-timers.c)。
目前 FFI 明确限于 64 位 Linux ABI。

串行记录 `cpu_clock_ns` 和 `client_cpu_clock_ns`。分析新增：

- `subject_own_cpu_clock_us_per_op`：主体所有线程，不含子进程。
- `dependency_own_cpu_clock_us_per_op`：依赖进程自己的线程。
- `client_cpu_clock_us_per_op`：客户端，不和主体合并。

并发窗口只取统一外层快照差，分母包含四客户端预热；不累加重叠的主体窗口。
已有 `subject_cpu_us_per_op` 仍包含其原定义中的 reaped children。
短命进程及子进程树仍需独立计量，不能用新字段冒充整个调用树 CPU。

SDK 编译的两个时钟测试已在路由器通过：测外部存活子进程、区分休眠与忙循环、退出后拒绝读取；
测进程中已结束工作线程的 CPU、拒绝越界 PID。另以原候选做 200 次基本查询/调用验证字段与清理。
该短验证中 invoke 的旧主体 tick 值为 0，新时钟为约 39.4 µs/op，说明零 tick 不能解释为零成本；
此数仅验证计量能力，不作为性能比较。

标称纳秒分辨率不代表每个操作有纳秒级准确度。计数读取本身有开销，包含在采样边界的工作需要
一致处理；所有比较侧必须使用同一新客户端身份，不与旧客户端的历史窗口合并。
新增采集参数 `--benchmark` 只向本轮临时目录上传客户端，记录并验证其 SHA；原设备工具不覆盖。
精确驻留内存/PSS、峰值和整栈性能仍未因此解决。
