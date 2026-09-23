# R140：A53 编译候选的 Oracle 功能门

**精确 A53 release ELF 的 wire、FD 和限定恢复门通过；同源 SDK/A53 单测 55/55 通过。** 本轮只有编译目标变化，没有运行时源码修改；这些是功能结果，没有进行 Oracle wall 性能筛选，也没有执行路由器任务。

| 检查 | 结果 |
| --- | --- |
| SDK release/A53 单测 | 55/55 |
| 八项既有 wire，含 `remove_reply` | 精确 C、R136、A53 逐字一致 |
| 六项 FD | C/R131 控制一致；A53 通过既有 read-ahead 契约 |
| `ubusd_halfclose`、`ubusd_lookup_delete` | A53 所有检查通过；C 的既有失败按原门保留 |

候选 SHA-256：`d491a90b8c4c518648d7aa034acd64b0046ea6c2e6c46c19fda3229bf9285488`。构建控制逐字重现 R136 `ce3d1aa…`，两个构建的完整源码清单一致。功能运行前后核对源码与全部输入未变，单测覆盖的 20 个 runtime/Cargo 文件与冻结 release 源码一致。

单测在独立 mount/PID namespace 中恢复同一 canonical 源码路径，以匹配 SDK、Rust 1.98.1、release **test profile** 构建。Cargo fingerprint 核实单测与 A53 release 的有效 `RUSTFLAGS` 逐项相等，包括唯一新增的 `-Ctarget-cpu=cortex-a53`。单测 ELF 独立于被 wire/FD/recovery 实测的 release ELF，不混用两者身份。

复用原 probe `5500effd…`，没有新增功能案例。wire 的第二控制为 R136；FD 第二控制明确保留 R131，避免把 read-ahead 行为错误套入 C-exact 契约。三项常规逐帧 FD 行为与 C 一致，三项手工帧仅声称符合已接受契约。恢复门仍记录 C 的半关闭回复缺失、lookup-delete 崩溃等既有失败，不改写为 C 全部通过。

本次固定流程无失败步骤或重试。**141 个证据文件与归档逐项一致**，包括冻结输入、脚本、源码身份、有效编译参数、单测日志、三方 transcript 和恢复原始结果。完整脱敏身份与核验结果见 [派生 JSON](r140-correctness-results.json)，可用 [本地校验器](../../tools/r140/analyze_correctness.py) 重算。原始归档位于 ignored `private/r140/correctness-01.tar.gz`。
