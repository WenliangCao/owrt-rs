# R93 RPCD glob 高精度 Oracle 复核

2026-09-15。四侧四轮、288 个观测全部正确；6 个授权/拒绝负载提高至 N=200000，其余 12 项保留 N=20000。
这是 Oracle AArch64 SDK 诊断，不是 AX3000T 实机结果；候选未合入。

| 负载 | control CPU | candidate CPU | CPU 配对变化范围 | control 延迟 | candidate 延迟 | 延迟配对变化范围 |
|---|---:|---:|---:|---:|---:|---:|
| session_access | 9.425 | 9.425 | -2.618%…7.937% | 35.930 | 35.958 | -1.529%…6.185% |
| session_access_c4 | 5.473 | 5.398 | -8.772%…1.852% | 49.406 | 49.565 | -6.281%…3.645% |
| session_access_granted | 9.800 | 9.375 | -5.556%…-3.590% | 36.225 | 35.921 | -1.455%…-0.663% |
| session_access_granted_c4 | 5.798 | 5.398 | -8.696%…-4.800% | 49.505 | 49.180 | -8.699%…-0.449% |
| session_access_64 | 10.300 | 9.750 | -6.311%…-4.390% | 36.604 | 35.770 | -3.247%…0.291% |
| session_access_64_c4 | 5.948 | 5.598 | -8.264%…1.739% | 49.010 | 49.311 | -3.368%…7.282% |

## 结论

- `session_access_granted` 串行 CPU 中位 9.80→9.38 µs，四轮均为 186–198→186–188 ticks；延迟四轮配对方向为 −2.54%、+0.29%、−3.25%、−2.22%。
- `session_access_granted_c4` CPU 中位 5.80→5.40 µs，延迟四轮均下降约 0.06–4.61%；这是最清晰的授权快路信号，但仍是同机 Oracle 构建。
- `session_access_64` CPU 中位 10.30→9.75 µs，延迟三轮下降、一轮上升；`session_access_64_c4` CPU 中位 5.95→5.60 µs，延迟两轮下降、两轮上升。
- denied `session_access`/`_c4` 方向仍混合；未授权并发延迟不能当作快路收益。
- 所有焦点样本 CPU 已高于 100 ticks，计时分辨率明显优于前一轮；仍不做统计显著性或归因声明。

## 验证边界

- 16 个 side samples、288 workload records 的 raw、身份、固定请求数、warmup、CPU 算术、子进程 tick=0 和清理均通过；C/R89/source05/control/candidate hash 未变。
- 完整验收门仍来自 `R93_RPCD_GLOB_VALIDATION.md` 的 22/22；该候选没有修改总线 deadline、回收或登录逻辑。
- 结果只支持“授权快路有针对性 CPU/延迟信号”，不足以合入或称全面胜过 C/R89；下一步必须在路由器 Wi-Fi 同夹具运行四侧对照。

[逐轮派生数据与身份](r93-rpcd-glob-focused-oracle.json)。
