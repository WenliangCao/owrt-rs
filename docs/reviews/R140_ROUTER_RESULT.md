# R140：A53-only 编译未通过性能门，保留 R136

**拒绝本次编译候选作为性能升级。** 八窗七负载 mean(A53/R136) 的等权几何均值中位数为 **0.9952765124（−0.472349%）**，仅 **5/8 窗下降**；未达预冻结的 `<0.98` 且 `≥7/8` 主门。21 项延迟否决为零，不证明等效，也不能替代主门。没有挑窗、重跑、补窗或部署。

候选 `d491a90b8c4c518648d7aa034acd64b0046ea6c2e6c46c19fda3229bf9285488` 与 R136 同源码，唯一构建变化为 `-Ctarget-cpu=cortex-a53`。原配方控制逐字节复现 R136，30 项 source hash 和有效 flags 证明一致。Oracle 功能门、原 caller 七负载 smoke、实机 wire/FD 及同一个 A53 单测 ELF 的 **55 项测试全部通过**。

关键负项仍在：register_1 p95 对 R136 **+14.302%，5/8 上升**，对同期 C **+29.291%，8/8 上升**。前者未满足 7/8 否决方向门，但也没有修复注册慢尾。event_nomatch p95 对 R136 −13.904% 只有 6/8 下降，不能据这一项推翻主门或撤销原 R136 四项正式负值。

CPU 也没有补偿收益：对 R136，七项 daemon CPU 中位变化只有 lookup 下降（−0.769%），其余为 **+0.126%～+1.905%**。CPU 按冻结规则仅报告，没有新增硬门。

产物更大：A53 **531,155 字节**，R136 514,771 字节，增加 **16,384 字节（3.183%）**。每个 daemon 的七负载前后快照中，A53−R136 的同窗 VmRSS 差中位数都为 **+60 KiB**，RssAnon 差中位数都为 **0 KiB**；不能把多出的 VmRSS 称为匿名增长或系统总内存增量。四项同进程增长中位数为 R136 12/A53 8 KiB，仅描述本轮时点；完整 JSON 保留全部 87 个正向资源差值。

**完整性通过：8 窗、168 case、1,680,000 个测量周期、1,480 个原始文件全部纳入并核对归档。** 37 个冻结输入、生成脚本、九组件 stock 健康、boot、身份和清理门均通过。mean/p50/p95/p99 从纳秒数组重算，daemon CPU 使用 process clock，无 tick 回退。独立校验的 84 组配对、168 case 六指标、24 组驻留、87 个正差和八个几何均值与主 JSON 完全一致；其初次旧 caller 字段假设错误及修正记录保留，未改原始数据。

原 caller 没有 live 迁移/逐周期调度记录，自身 CPU 仅有 delta，provider CPU 未混入 daemon，也未以 wall 减 CPU 推导等待。本轮是原 caller 的五条注册/对象事件加一对象 lookup/invoke 哨兵；未重测完整 SEND、空闲连接、大消息、扇出或长期内存。等权是工程选择，不代表真实流量分布；R136 的完整内存证据不能直接转移到新 ELF。

[完整公开 JSON](r140-router-results.json) 包含全部逐窗原值、两个控制下的所有指标、正负项、资源快照与证据哈希。[冻结计划](R140_ROUTER_PLAN.md) 和[分析器](../../tools/r140/analyze_formal.py) 未改。复现到新文件：

```sh
python3 tools/r140/analyze_formal.py private/r140/formal-01 \
  --plan private/r140/formal-plan-01/plan.json --output private/r140/rederived-new.json
```

计划 SHA-256：`4d8895115cefbd10974663087d968c5c41deca51f2515375a02ceb29b7c3e8ef`。主 JSON SHA-256：`e47c2df02e1891b573afb9699a8a1f12451111140b8332e526dcd5ee8f97d5ce`。原始与独立审计证据在 ignored `private/r140/`；未拼接 Oracle 或历史性能样本。
