# R93 HTTP Oracle 五侧初筛

2026-09-15。**20/20 样本完成，112,000 次响应字节与状态正确，0 错误。**
这是 Oracle AArch64 的单轮 namespace/loopback 初筛；不是 AX3000T 实机性能，也不是已合入候选的收益验收。

## CPU：缓存候选值得继续验证，仍未追上停放场景的 C

单位 µs/请求；括号为实际 daemon CPU ticks（100 Hz）。每侧每档仅一次。

| gap | C | R89 | source05 | worker-cache | parser-cache（head） |
|---|---:|---:|---:|---:|---:|
| 0 ms | 43.5 (87) | 31.5 (63) | 32.5 (65) | 32.5 (65) | 32.5 (65) |
| 40 ms | 37.5 (3) | 62.5 (5) | 50 (4) | 62.5 (5) | 62.5 (5) |
| 60 ms | 50 (4) | 275 (22) | 275 (22) | 150 (12) | 137.5 (11) |
| 80 ms | 50 (4) | 287.5 (23) | 287.5 (23) | 150 (12) | 137.5 (11) |

60/80 ms 时，source05 的 22/23 ticks 降到 worker 的 12/12、head 的 11/11。
此下降幅度值得复核；C 两档均为 4 ticks。worker 与 head 仅差 1 tick，不能据此确定追加 parser-cache 的独立收益。
0 ms 中三个 SDK Rust 侧均为 32.5 µs/请求；40 ms 的各侧差值仅 1–2 ticks，不作细小胜负判断。

## 平均延迟

单位 µs；完整 p50/p95/p99、原始 latency 数组与资源快照在证据中。

| gap | C | R89 | source05 | worker-cache | parser-cache（head） |
|---|---:|---:|---:|---:|---:|
| 0 ms | 163.45 | 57.95 | 58.90 | 59.44 | 59.04 |
| 40 ms | 127.52 | 134.92 | 130.83 | 131.53 | 134.16 |
| 60 ms | 138.34 | 283.97 | 278.86 | 219.22 | 200.11 |
| 80 ms | 143.90 | 296.19 | 300.71 | 229.46 | 226.82 |

## 资源与测量边界

- 输入严格保持 16 KiB 全零静态响应、4 客户端、gap0/40/60/80，hot20000、paced800；固定 C/R89/source05/worker/head 顺序，仅一轮。
- CPU 使用包含已退出 worker 的 `/proc` 进程 ticks；没有改用主线程 schedstat。全部 waited-child ticks 为 0。paced 档 1 tick 对应 **12.5 µs/请求**。
- 2 ms 线程观察器会增加线程相关开销；线程出生数只是下界。客户端/观察器 CPU 不包含在 daemon CPU 中。Oracle 仍有正常后台服务；此次没有其他 owned 压测或构建并行。
- 所有 Rust 侧 FD 均为 7，C 为 8。worker/head 测后快照为 5 线程，1 秒和 2 秒后均回到 1；source05/C/R89 这些快照均为 1。
- worker/head 测后 RSS 范围分别 1124–1152/1128–1148 KiB；2 秒后分别 1012–1040/1016–1036 KiB。相较各自 workload 前仍多 160–184/160–184 KiB；source05 为 148–168 KiB，C 为 8 KiB。不能宣称全面省内存。
- 上述只是 before/after/1s/2s 窗口；不包含此前 64 连接保持 200 ms 的场景。
- C/R89 是精确镜像/正式历史产物；三个 SDK Rust 侧为 Oracle 诊断构建，不是 canonical CI 发布。完整身份在配套 JSON。

## 工具修复与证据完整性

旧 runner 在第一个 C 样本完成后，向 root-owned raw 写 `derived.json` 失败。
新 runner 将每样本 derived/checksum 与原子 results checkpoint 写到 ubuntu-owned parent，拒绝已有输出目录和 per-sample 文件覆盖。
raw 不做 chmod/chown 或改写；driver 源码与输出 owner/layout 元数据随新运行冻结，并保留 PARTIAL/错误边界。

权限回放以 uid1001 读取旧 root-owned、不可写 raw，经过同一严格 derive/writer；重复 derived 写入被拒绝、checkpoint 替换通过。
旧 PARTIAL 的 53 个文件 SHA、UID/GID、mode、mtime 完全一致；回放样本不计入新数据。

全新 pilot 的 20 个 raw COMPLETE、二进制/工具/fixture/dependency/harness/boot 身份、成功响应/样本数、内外墙钟与 CPU 区间校验全部通过。
结束后逐样本重新 derive 并核对全部 raw 哈希、完整下载文件集合（602 文件加 manifest），owned namespace/daemon/client/benchmark 进程为空。没有物理设备访问。

- [完整派生结果与身份](r93-http-oracle-pilot.json)
- 私有归档：`private/r93/http-worker-experiment/five-side/resume2-20260915.tar.gz`
- 归档 SHA256：`2ced2bf230c6c325340ac0a51a8857f7a2fca3872315acc079dacf44f091e946`
- 原失败样本与 traceback 继续保留在原 `pilot-20260915-01-partial.tar.gz`，未混入此矩阵。

下一步由主任务决定更长 Oracle 复核或实机窗口；本次未启动长轮，未合入任何 HTTP 性能候选。
