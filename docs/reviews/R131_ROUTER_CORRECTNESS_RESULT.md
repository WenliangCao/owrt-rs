# R131 实机正确性补测

两个 AX3000T 隔离窗口均通过。目标 musl 测试程序在路由器本机执行，
**53 条单测全部通过，无过滤、忽略或失败**。随后精确 C、R124、R131 分别运行：

| 检查 | 实机结果 |
| --- | --- |
| 对象事件、普通事件、monitor、释放、UTF-8、monitor lookup、方法 ACL | 七组输出三方逐字节相同 |
| FD 帧边界 | 六个对抗场景三方逐字节相同，见证请求通过 |
| FD/对象回收 | FD 回到基线，最终对象表为空 |
| 生产与清理 | C 身份、boot、配置、宿主 mount 不变；临时目录及所属进程清理通过 |

实际 release ELF 仍为 `c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a`。
新增单测 ELF 为 `29f057776f75c5bdddf4c1c9a6577a192d2362d5ce015ab9b79f3c869a69a3b3`；
测试分支新增的 `client.rs`、`server.rs` 测试之外，运行时代码与 release 源提交 `4e45d2e` 相同。
原始归档与展开文件逐项哈希对账，测试计数、probe 身份、每组输出与门结果已离线核验。

新增第二/第三帧内短写覆盖也在原 R124 helper 上通过，故不能称为修复了已证实的 R124 bug。
在当前 batch ≤16 KiB、发送队列上限 1 MiB、空队列计数为零的约束下，
第一个未完成帧不会因队列上限被丢弃；新 helper 的相关防御性注释不能替代缺陷复现证据。

这些正确性场景没有统一 daemon 的 argv0 或 affinity，不使用其耗时作性能结论；
进程证据为启动文件哈希及受控生命周期，也不冒充性能矩阵中的完整 live mapping 核验。
通过既有测试不能证明不存在未知 Bug，也不能代替九个最终 Rust 组件的组合验收。
Oracle 的六组功能/恢复门及精确 ELF 系统调用计数另见[构建机补测](R131_UBUSD_CORRECTNESS_SUPPLEMENT.md)。

[冻结计划](r131-router-correctness-plan.json) · [结果与归档指纹](r131-router-correctness-results.json)

原始证据保存在 `private/r131-supplement/router-correctness-existing/` 和
`private/r131-supplement/router-correctness-fd/`。生产始终为 C，未部署候选。
