# R140：七条正式负载的命令与 fixture 功能 smoke

**Oracle 上精确 C 与 A53 候选各执行七条既有命令，14 例全部通过。** 每例 100 次、20 次预热，保持原调用者 ELF `0ca42fb…`。这只验证命令、返回值与 fixture，不设置或应用任何性能门。

直接从正式 `tools/r140/formal.sh.in` 生成脚本，只替换固定产物哈希、顺序为 C→A53、次数由 10,000 改为 100。parent/caller/provider 允许 CPU 0–1，daemon 固定 CPU 1，均在既有 Oracle namespace 中运行。

覆盖 register_1、register_16、event_1、event_8、event_nomatch、lookup、invoke。最后两项复用同一精确 caller 的 `serve SOCKET 1` 创建唯一 `bench.target`，并验证 `ping {"n":1}` 返回 `{"ok":1}`。每例成功数 100、错误数 0；全部原始样本保留，但不比较性能数值。

daemon 和 provider 前后 PID/starttime、argv、ELF、亲和性一致；provider fixture 前后保持唯一对象，退出后对象表清空，两个进程的退出、日志与 namespace COMPLETE 均通过。原始归档和展开文件逐项核对一致。正式计划仍须单独冻结，不能把这些短样本合入正式性能窗口。

- [脱敏验证结果](r140-lane-smoke-results.json)
- 原始归档：ignored `private/r140/lane-smoke-01.tar.gz`
- 冻结 smoke 输入：`private/r140/lane-smoke-input-01/`
- 本地核验脚本：`private/r140/verify_lane_smoke.py`，其哈希记录在结果中

没有访问路由器或修改已通过的 [A53 正确性结果](R140_CORRECTNESS_RESULT.md)。
