# M6b 最终验收的方法失败与修订

最终产品源码仍为 `889fe4f5`，opt3 为 `791a7c33…`。本页记录方法边界，
不把原失败改成通过，也不替代完整最终资格。

DHCP identities 的第一次完整运行在第26步返回红色：
`identity-ignore-phases--offer-ack-inform` 第三行的 option51 为 C 600 秒、
Rust 599 秒；其余报文字节、名字、租约、peer 和清理一致。
原参数只作一次单 case 确认，结果为通过。

原始文件的纳秒 mtime 与 raw leasefile 提供独立边界证据：两侧 lease
到期秒都是 `1791573197`；C 请求/响应位于 `1791572597.9807…` 秒，
Rust 位于 `1791572598.0025…` 秒。故各自整数请求秒与到期秒的差
恰为600和599。C `rfc2131.c:1805–1812` 与 Rust
`dhcp/state.rs:1119` 均返回 `expires-now`，没有新的产品语义差异。

工具提交 `2489b0ed` 为该族保存 pre-request raw leasefile、匹配的 ciaddr、
到期秒和请求前后墙钟。只有当报文 option51 为唯一4字节字段、其到期秒
确实来自对应 raw leasefile，且隐含请求秒落在该侧观察区间内时，才归零
option51的值作跨运行比较。其他字段、顺序、名字、peer、租约和清理
仍严格比较；没有全局±1秒容差。四项本地测试覆盖独立秒相位、跨秒、
错误时间、缺失/篡改/重复租约见证、逆序时钟、无限租约及其他字节不变。
该工具没有额外声称墙钟跳变或长暂停保护。

修订使用独立 tools archive 和 selected-family override；原始 tools、
identity、失败目录、确认结果和25个同 ELF 已通过族的收据保持原身份。
`dhcp-identities` 整族149个服务 case 与原 parser 计划 fresh 执行，
未挑选一个绿 case 替代全族。此修订未改变产品/包构建输入，亦没有
导入旧 `284376c4` ELF 的13步结果。

其他准备阶段的方法记录同样保留：`8bd80024` 的新 TFTP 测试夹具
误用 Rust 不支持的字节转义，编译失败后由 `889fe4f5` 修正并本地解析，
其后 Linux测试及精确C配对实际通过；UDP修复测试初次遇到宿主 `/tmp`
旧 FIFO 与 namespace PID1 重名，只改用 fresh task-owned TMPDIR
作一次确认，没有删除共享文件或改产品。

证据为 `E/M6B/final-889fe4f5/preflight/` 下的
`dhcp-identities-red-01.txt`、`dhcp-identity-diff-01.jsonl`、
`dhcp-inform-clock-files-01.jsonl`、`dhcp-confirmation-*`、
`dhcp-inform-tool-tests.log`、`inform-fixture-prepare.log`，以及独立
`identity-inform.json`、`inform-tools.tar`。原始运行完整归档索引在最终
报告收尾时列出；未完成的后续门仍为未执行。

## Hosts 大文件的采样完成条件

接口族 `hostsdir-large-owner` 首次及一次原参数确认均通过所有健康回复检查，
但没有采到查询前后hosts FD均打开的交集。原工具在该断言前丢失samples，
不能仅凭它的 `infrastructure` 标签判断产品。修订754d1c1b／42d0bf00先
保存原始健康/FD/单调时钟采样，再执行原断言；三项负控验证红色仍为红，
且证据保留。独立该方法观察已取得严格的Rust while-open健康阳性。

完整fresh族的新证据进一步表明采样停止条件过早：唯一样本的查询健康，
`file_active=false`、`file_still_active=true`，但控制器已经结束采样。
“同路径read日志”可来自先前排队读取，不能证明本次1MiB源已经结束。
工具21e6646d要求新 `one.records.test→192.0.2.8` 已发布、且当前源FD
关闭后才结束采样；保留原来的1MiB、8秒deadline、健康及while-open合同，
没有把负载做大或丢掉资源见证。四项本地负控包括旧记录、仍打开的源、
重开FD、缺交集、不健康和未结束线程；受影响完整族fresh执行中。

上述运行/采样原始结果仍保持原判定。修订只修改工具，不修改冻结ELF；
本次未确认新的hosts服务产品缺陷，也不把独立单case阳性冒称完整族通过。
证据入口为preflight下 `hostsdir-large-owner-*`、`hostsdir-confirmation-*`、
`hosts-large-observed-samples.jsonl`、`hosts-full-observer-red-01.txt`、
`hosts-observer-tests.log`、`hosts-completion-tests.log` 与三个独立tools archive。
