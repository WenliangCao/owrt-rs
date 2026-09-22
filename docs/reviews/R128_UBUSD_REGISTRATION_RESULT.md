# R128：R124 当前 ELF 注册路径

**恢复审计勘误：本组没有落实原先声称的 daemon CPU1 和统一 argv0。**
`r128_ubusd_registration.sh` 虽设置了 `OWRT_UBUSD_NORMALIZED=1`，但它自己的 `--workload`
分支直接执行 `"$bin" -s "$socket"`，没有进入 `isolated.sh` 的归一化启动分支。
C 的启动 argv0 为 `/sbin/ubusd`，R124 为 `/tmp/bin/ubusd-rs`；daemon 和 caller 都未显式绑定 CPU。
`register-cycle` 内部及其计量函数没有设置 affinity；本组 raw 快照也没有记录实际 CPU mask 或 cmdline，
因此不能追认固定核心、迁核情况或统一启动条件。脚本 SHA `8429a90a…50abb` 与全部 16 窗记录一致。
原始数据、异常窗口和下面的描述统计全部保留，但 **+3.1% 不能作为已隔离实现差异的注册退步结论**，
−1.3% 也不能作为受控条件下的优势。后续比较必须重新冻结、落实并记录启动条件，不能混入本组。

在上述实际启动条件下，同一严格 Rust benchmark/caller 对精确 C 与 R124 各执行 8 个新 daemon 窗口，
C/R124/R124/C 反序四轮，共 16 窗口。
每个 ADD/REMOVE 周期都构造并发送真实对象，ADD 检查成功 STATUS 并解析一个 OBJID，REMOVE 检查成功 STATUS；
**这不是逐周期完整回复字节校验**。完整方法签名、路径及对象 ID 只在计时前的一次 lookup 中核对，
预检周期之后和全部计时周期之后检查 registry 为空。`Connection::remove_object` 不逐周期核对
REMOVE DATA/OBJTYPE，ADD 也不检查回复的全部属性或额外帧。测量保留逐次 latency_ns、p50/p95/p99、daemon/client CPU；
精确协议字节兼容性需要由独立单测和协议差分门支持，不能从这个计时 caller 的成功状态推导。

| fixture | C 中位 mean µs | R124 中位 mean µs | 四块配对 R124−C 中位 |
|---|---:|---:|---:|
| 1 method × 8-byte name | 96.99 | 100.42 | +3.1% |
| 16 methods × 8-byte name | 108.00 | 107.56 | −1.3% |

1-method 的第 4 个 C 窗出现 319 µs mean、p99 2128 µs，其他 C 窗约 96–105 µs；该异常保留，
没有删除或重跑。四块的原始差值为 1-method −52.0%、+5.4%、+4.5%、+1.6%，16-method
−37.3%、+1.1%、+0.5%、−3.1%。因此不能把 16-method 的小幅中位下降当成稳定胜出，
也不能用异常窗选择性清除 1-method 的观测差值。尚未控制的 affinity 和启动路径是额外混杂因素；
它们是否解释这些差值以及解释多少，本组证据不能回答。

所有 16 窗 cleanup、boot/config/生产身份/mounts 检查通过；最终生产仍为 C，临时命名空间已清理。
本组不包含事件 fanout、查询/调用矩阵之外的连接规模内存，也不作 R124/R123 推导或总体接受判定。
[机器结果](r128-ubusd-registration-results.json)保留每窗、每 fixture 的 p50/p95/p99、逐次 latency、原始哈希和限制。
