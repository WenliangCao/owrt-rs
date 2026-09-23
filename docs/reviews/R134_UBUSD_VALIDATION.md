# R134 ubusd 验证进度

冻结候选为 `98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0`，
518,867 字节。固定 SDK/编译目录重建与原候选逐字相同；后续注释修正重建也相同。
这里的结果来自 Oracle，**不构成路由器性能验收**。

| 正确性检查 | 结果 |
| --- | --- |
| AArch64 musl 单测 | 55/55 |
| R36 root/non-root、R83 ACL、R42 fuzz、R41 限制、R92 recovery | 6/6 |
| 事件、对象事件、monitor、release、UTF-8、monitor lookup、方法 ACL | C/R131/R134 七组逐字一致 |
| FD 六场景 | 三个 sender-framed 与 C 一致；三个手工构帧按显式契约，均单次交付、无泄漏 |
| prefix 背压、流水线、ACL 撤销 | 3/3，保留 R93 修复 |
| grouped/interleaved/monitor/slow | C/R131/R134 共 12/12，目标、顺序、字节与清理通过 |
| 新扩展矩阵夹具 | C/R134 各 100 次的 15 条负载 smoke 完成 |

慢读者洪泛确实触及有界丢弃，排空后各再交付 8 条事件，FD 恢复基线。
不同发送批次下的存活帧数是 C 542、R131/R134 574；这不是逐帧丢弃位置相同的声明。

本轮还修复了 gate 脚本吞掉失败退出码的问题。现在任一门失败、缺 COMPLETE 或
R92 `passed != true` 均返回失败。第一次运行单测时误把静态 ELF 交给动态加载器，
测试尚未开始就失败；直接执行后 55 项通过，两个日志均保留。

复核发现原 FD 探针对三个手工用例只记录 C 差异，未断言新契约。补强后的探针
恢复 C/R131 全六案严格检查，并给 R134 独立的契约模式：bundled 与 body+next
必须为 `[0,1]`；仅 body 附 FD 时，根据前缀是否已独立读取允许 `[0,0]` 或 `[1,0]`。
新 Oracle 门已通过，运行时 ELF 未变。原先宽松探针的通过记录不作为契约证明。

派生身份及检查范围见 [JSON](r134-ubusd-oracle-results.json)。原始日志在 ignored
`private/r134/verification/` 和 `private/r134/stress-verify-01/`。
有限正确性测试不能证明“没有任何 bug”；FD 和 ID 机制边界见
[合同](../contracts/ubusd.md)。

路由器测试按冻结 R134 规则收集：15 条查询/调用/注册/对象事件负载，ABBA × 4，
每侧 8 窗；另以精确镜像 libubus 的直接 SEND 测试补足对象事件矩阵没有覆盖的路径。
主矩阵只比较 C 与 R134，不能据此直接宣称优于 R89 或 R131。
