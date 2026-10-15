# F/E 产物固定后的启动门

精确 F 已生成并保留离线副本，见
[`f-e-artifact-identity.json`](f-e-artifact-identity.json)。完整正确性仍在运行；
本记录不授予提前暂存或性能启动资格。准备阶段没有执行以下健康流程。

- F source：`3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`。
- F ELF：`b7926bcf39cd7f33b4f0c110315ddc1ad719b39427bec53430ea05aeacd781fc`，
  2,136,859 bytes，与 E 同大小。
- 本工具工作树已独立复制并重核 `private/perf-opt-20261015/sdk-f/` 的
  ELF、link map、build receipt；`inputs-fe/dnsmasq-f` 是同一 ELF。
- 工具源、九项测量 ELF/script 重新逐项核对准备清单，均未改变。

完整原始正确性门通过、回执绑定以上 F 后，设备 owner 执行新的实时
preflight 和下述健康基线，再暂存并启动。Oracle owner 可同时开始其
独占 110 窗口；两环境独立，不共享运行目录或混合统计。

## 新健康基线流程

复用已固定 `perf_opt_device_run.py` 的 `production_identity`、
`guard_start`、`guard_check`、`guard_stop` 和 `external_health`；不引入新
健康探针或改变原 guard ELF。用新的 `private/perf-opt-20261015/health-fe/`
保存本次原始记录和 summary；目录若已存在，先核其状态，不覆盖。

1. 确认生产 file/live SHA 是 `8472be5a…`、精确一个匹配进程及其
   PID/starttime；任务根无 STOP、active group 或本任务活程序，权限
   `0700`/root，内存不少于 65,536 KiB。核 guard 和全部旧暂存身份，
   确认离线 exact C、部署版、E、旧 loadgen 备份仍可读且 SHA 匹配。
   不把之前只读盘点的路由条目当成双栈健康结果。
2. 使用独立 label，如 `candidate-f-vs-e-health-<time_ns>`，调用
   `guard_start(production_pid, label, 200)`。现有函数给 guard 的总上限
   是 3,600 秒；同时启动本地 `external_health` 双栈 HTTPS 检查。
   此时没有性能测试组，尚不运行 E/F 或新 loadgen。
3. 采集至少 125 秒，约每 5 秒检查 guard 身份、无 STOP 和外部健康失败。
   guard 保持原 DNS/LuCI/路由/内存/生产身份检查；整机 CPU 仅记录。
4. 达到时长后，使用 `guard_stop` 按 PID/starttime 终止自己启动的 guard，
   停止本地 HTTPS 线程并收齐日志。要求最后事件为 `monitor_stopped`，
   `elapsed_s >= 120`，生产身份不变、STOP/active group 仍不存在。
   **不要将 guard 的总期限直接设为 125 秒**：现有 guard 达到 deadline
   会写 STOP 并返回 2。正常健康采样结束应使用已有的显式 SIGTERM 路径，
   不需要清除 STOP，也不改变该安全行为。
5. 从实际 `dns_ok=1` 样本按原 nearest-rank 规则计算 p95；要求没有
   `dns_ok=0`。HTTP 实际检查必须为原 guard 接受状态，未调度样本的
   `-1` 不计为失败；内存/生产身份/路由检查必须成功。HTTPS 每个已开始
   的 IPv4/IPv6 检查都须 exit 0、HTTP 200，不丢弃失败或取消记录。
6. 新 `summary.json` 保持 controller 已有输入字段：`valid`、
   `elapsed_seconds`、`dns_samples`、`dns_p95_ms`、`dns_max_ms`、
   `http_samples`、`http_max_ms`、`threshold_ms`、`raw_sha256`。
   阈值按原公式 `ceil(max(200,10*dns_p95_ms))`，大于 700 则调查后再定，
   不直接放宽。另保留 HTTPS、guard stderr、开始/结束生产身份和各文件
   SHA 的回执。任何异常保留原始数据和 STOP，不自动重试或清除停止门。

## 暂存与启动身份

健康门通过后，按协调者授权，仅原子替换自有 `/tmp` 中的三个比较输入：
`dnsmasq-c=E`、`dnsmasq-rust=F`、`m6a_loadgen=f7c7d8e9…`。每项 `.new`
文件在重命名前核 SHA256/权限；其余工具身份完全沿用准备清单。
`/usr/sbin/dnsmasq` 与生产配置不变。另存 stage 回执，不覆盖旧阶段记录。

启动回执必须绑定 F source/ELF/build、完整正确性回执、E ELF、工具快照、
fresh health summary、最终生产 PID/starttime 与 ELF，以及实际完整命令。
使用 [`F_E_NEXT_ROUND.md`](F_E_NEXT_ROUND.md) 中的 110 窗口命令，
`--rust-hash` 填本记录的完整 F SHA；不传 `--scenes`。

准备阶段的 `run_frozen=false` 历史记录保留。只有上述资格、健康、暂存
与最终启动身份全部就绪后，新 launch 回执才可声明可启动；单独的 SDK
构建成功或离线 SHA 匹配不等于验收通过。
