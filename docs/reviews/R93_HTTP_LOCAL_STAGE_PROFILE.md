# R93 HTTP 本地阶段剖析

2026-09-15。两份独立源码副本分别取正式 R89 `d9c1048` 与 source05 `7d5cb38`，在 macOS 上用 Rust 1.98.1 release、独立 Cargo target 和相同 profile example 运行。没有访问路由器，也没有修改主源码。

## 结果

单位 ns/请求，四轮交错中位数。

| 响应 | 阶段 | R89 | source05 | source05/R89 |
|---|---|---:|---:|---:|
| 512 B | `parse_buffered` | 463.95 | 520.03 | +12.09% |
| 512 B | `parse_reused_deadline` | 699.88 | 777.58 | +11.10% |
| 512 B | `lookup` | 1300.32 | 1316.57 | +1.25% |
| 512 B | `serve_static_reused` | 10717.80 | 10388.05 | −3.08% |
| 512 B | `parse_reused_lookup_serve_static_reused` | 13278.69 | 12890.64 | −2.92% |
| 16 KiB | `parse_buffered` | 462.32 | 544.86 | +17.85% |
| 16 KiB | `parse_reused_deadline` | 745.61 | 822.16 | +10.27% |
| 16 KiB | `lookup` | 1293.22 | 1373.89 | +6.24% |
| 16 KiB | `serve_static_reused` | 11251.17 | 11366.67 | +1.03% |
| 16 KiB | `parse_reused_lookup_serve_static_reused` | 13623.51 | 14519.20 | +6.57% |

分配、重分配、超时系统调用和传输写入计数在对应阶段保持一致；因此本机结果指向解析/匹配计算成本，而不是新增分配或系统调用。512 B 的完整组合阶段反而略低，说明 macOS 结果不能直接解释 AX3000T 上 7 µs 的整条请求差额。

## 结论边界

- 结果支持先检查 source05 请求解析热路径，尤其是新增 header 控制字符扫描；它不能单独证明该扫描是路由器退步的唯一原因。
- `serve_static_reused` 没有显示稳定退步，暂不优先修改静态文件输出或 `Served` 分派。
- Darwin allocator、libc、调度、socket 和代码生成均不同于 OpenWrt musl/AArch64；这只是筛选诊断方向，不能替代 AX3000T 对照。
- 原始 CSV、源码哈希、构建日志和独立 target 记录在 `private/r93/http-local-stage-profile-01/`，未纳入 Git。
