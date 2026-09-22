# R128：R124 当前 ELF 注册路径

在路由器上以同一严格 Rust benchmark/caller、CPU1 daemon、统一 `/sbin/ubusd` argv0，
对精确 C 与 R124 各执行 8 个新 daemon 窗口，C/R124/R124/C 反序四轮，共 16 窗口。
每个 ADD/REMOVE 周期都构造并发送真实对象，预热和测量外均严格核对 ADD 回复、完整方法签名、REMOVE 回复、
最终 lookup 为空；测量保留逐次 latency_ns、p50/p95/p99、daemon/client CPU。

| fixture | C 中位 mean µs | R124 中位 mean µs | 四块配对 R124−C 中位 |
|---|---:|---:|---:|
| 1 method × 8-byte name | 96.99 | 100.42 | +3.1% |
| 16 methods × 8-byte name | 108.00 | 107.56 | −1.3% |

1-method 的第 4 个 C 窗出现 319 µs mean、p99 2128 µs，其他 C 窗约 96–105 µs；该异常保留，
没有删除或重跑。四块的原始差值为 1-method −52.0%、+5.4%、+4.5%、+1.6%，16-method
−37.3%、+1.1%、+0.5%、−3.1%。因此不能把 16-method 的小幅中位下降当成稳定胜出，
也不能用异常窗选择性清除 1-method 的退步。

所有 16 窗 cleanup、boot/config/生产身份/mounts 检查通过；最终生产仍为 C，临时命名空间已清理。
本组不包含事件 fanout、查询/调用矩阵之外的连接规模内存，也不作 R124/R123 推导或总体接受判定。
[机器结果](r128-ubusd-registration-results.json)保留每窗、每 fixture 的 p50/p95/p99、逐次 latency、原始哈希和限制。
