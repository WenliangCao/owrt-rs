# R141：固定 PGO 候选未通过五路径筛选

**本次 generic profile-use 候选不进入路由器性能验证，保留 R136。** 预冻结规则要求两个 CPU 对各自通过主门；其中一对未过，另外还触发一项延迟否决。没有重训、选择 profile、补 block 或追加候选。

主门是每 block 五条注册/对象事件路径 mean(PGO/R136) 比值的等权几何均值，仅使用 split 放置；四 block 中位数须严格 `<0.99` 且至少 `3/4` 下降：

| caller/daemon CPU | 几何比中位数 | 变化 | 下降 block | 主门 |
|---|---:|---:|---:|---|
| 0/1 | 0.985583708459 | −1.441629% | 3/4 | 通过 |
| 2/3 | 0.992955554029 | −0.704445% | 4/4 | 未通过 |

后一对落在预先声明的 ±1% 未分辨区间，不能称明确幅度或等效。60 项 mean/p95/p99 检查中，**2/3 对、pair_allowed、event_nomatch p99 为 +16.615691%，4/4 上升**，触发 `中位 >+3% 且 4/4 上升` 的否决；逐 block 为 +2.521%、+30.914%、+18.673%、+14.559%。该条件下 PGO p99 为 53.721/66.401/59.480/53.201 μs，R136 为 52.400/50.721/50.121/46.440 μs。

CPU 的正项完整保留：全部 20 个 CPU 对/放置/路径组合的 daemon CPU 中位变化为 **−2.247%～−8.824%**，每组均 4/4 下降。CPU 按冻结规则仅报告，不能替代延迟门。PGO ELF 为 **621,267 字节**，比 R136 514,771 字节增加 **106,496 字节（20.688%）**；本筛选没有重做长期或完整内存验证。

候选 SHA `70e7174c648ef676800a5f03d557ba7a0e1f07de2450c5d0d6ed334d3aa862eb`，训练 profile SHA `566a73250308a19e97715b40ff2b2f4043f07ed836b89b205d50d810ef07c4f8`。同源码 generic 控制逐字节复现 R136，八类训练只合并一次；有效 flags 仅增加 profile-use 与缺失 profile 警告。[独立功能门](R141_CORRECTNESS_RESULT.md) 的 55 项单测、8 项 wire、6 项 FD、2 项恢复全部通过。

**完整性通过：240 case、2,400,000 个测量周期、940 个哈希清单内文件全部核验。** 使用原 R135 caller `85dd537a…`、两个 CPU 对、四个正反 block、两种放置、C/R136/PGO 三侧；未过滤样本。延迟由原始纳秒数组重算，CPU 由 process clock 重算；身份、实际 affinity、命令、空日志与清理均通过。独立审计对 240 case 指标、240 组配对、八个 30 位几何均值、60 项否决和 940 个文件逐项复算，与主 JSON 完全一致。精确启动命令、detached launcher 身份和审计证据留在 ignored `private/r141/`，采集完成后 launcher 已退出。

本结论只覆盖这个固定 profile 对五条注册/对象事件路径的筛选；未测 lookup、invoke、monitor、大消息或长期负载，不能扩展为 PGO 对这些负载没有收益。两 CPU 对仍共享宿主资源；等权不是实际流量权重，Oracle 排名不代表路由器结果，也不能撤销 R136 既有实机慢尾。没有把 R140 的证据转移给 PGO。

[完整 JSON](r141-screen-results.json) 保留 240 case 六指标、两控制下全部 240 组逐 block 比较、八个几何均值、全部否决检查及证据 SHA。[冻结计划](R141_SCREEN_PLAN.md) 和[分析器](../../tools/r141/analyze_screen.py) 未改。manifest SHA `c44d6460349bcf75d48e0e97e7086140a77709e133f455fc8c5891f5974da670`；JSON SHA `5006d6340dcc5ff121696118ac680255271afe58769ccca70dde598708cbf55f`。

```sh
python3 tools/r141/analyze_screen.py private/r141/screen-01 \
  --output private/r141/rederived-new.json
```
