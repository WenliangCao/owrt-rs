# R144：caller 回复借用未通过固定筛选

唯一 72-case Oracle 系列完成，全部数据和清理校验通过，但 **C、R136 两个延迟主门均未通过**。
不采用该 caller 候选；正式 shared runtime 与 generic R136 保持原样。少量 CPU 或尾延迟下降
不能代替预定主门，也不能归为 daemon 优化。

依照[冻结规则](R144_SCREEN_PLAN.md)，每个 block 对三个 lane 的 mean 新／旧比取等权几何
平均，六个 GM 的中位必须严格小于 0.99 且至少 5/6 下降，两 daemon 分别都须通过。

| 固定 daemon | 主 GM 中位变化 | 下降 block | 主门 |
| --- | ---: | ---: | --- |
| 精确 C | −0.428828% | 4/6 | 未通过 |
| R136 | +0.307948% | 2/6 | 未通过 |

两个主结果均在包含边界的 ±1% 未分辨区间内；这不是等效性结论。**18 项延迟否决为 0**，
不改变主门失败。下面均为六个配对新／旧比值的中位变化，负值表示新 caller 较低。

| daemon／lane | mean | p95 | p99 | daemon CPU/op | caller CPU/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| C register_1 | −0.8102% | −0.9772% | −1.5704% | −0.0379% | −1.3769% |
| C lookup_1 | −1.1477% | −0.9433% | +0.1637% | −0.6977% | −1.1608% |
| C invoke_1 | +0.2978% | −0.3644% | +1.4892% | −0.2923% | +0.5917% |
| R136 register_1 | +0.2467% | +0.1149% | −0.5854% | −0.1456% | +0.1976% |
| R136 lookup_1 | −0.6939% | +0.3810% | −2.1268% | −0.3316% | −0.3841% |
| R136 invoke_1 | +0.2577% | +1.7489% | +2.0446% | +0.2515% | −0.2435% |

C 注册 caller CPU 在 6/6 block 下降，但 R136 三个 lane 的 caller CPU 中位变化均在 ±1%
内；R136 invoke 的 p95/p99 均为 5/6 上升，保留这些负项。provider 固定旧 caller 且 CPU
不含在上表两项 CPU 内。完整 72 个 case 的七项指标、42 组配对比值、12 个 GM 和全部门
结果见[脱敏 JSON](r144-screen-results.json)，未筛选窗口或补采。

候选为 `7adea868…`，旧 caller 精确重现 `85dd537a…`；18 个编译输入只差 conn.rs，49 项
候选共享库单测通过，详见[构建与正确性](R144_CALLER_BUILD_RESULT.md)。daemon 固定精确 C
`cfb83044…`／R136 `ce3d1aa…`。先完成独立 12-case 功能 smoke（N=10、warmup=20），再冻结
72-case 正式系列（6 block、N=10000、warmup=20）。每 case 新 daemon、daemon CPU1、caller
及旧 provider CPU0、同一独占 socket 和 argv0。回复验证沿用原命令；对象表、进程身份、
库与 ELF、affinity、日志和退出／清理均通过，smoke 核验 286 文件，正式核验 1706 文件。

首次 manifest 生成在采样前因远端归档路径缺少已核验的 test ELF 停止；补传相同 SHA 的
既有测试 ELF 后生成成功。没有修改工具或构建，没有产生失败性能样本。12 个 smoke 和
72 个正式用例均为首次 workload 完整通过。

| 证据 | SHA-256 |
| --- | --- |
| smoke manifest | `817e24d90a5c2e3c747b2ed277a4dac8f040ee75bafb2809f961c02db843f12d` |
| smoke 派生结果 | `ca0b70485014ed7809c8f268c241d651900bd250b09706b638d93cbc8d35e9a4` |
| 正式 manifest | `5d4fb15b346d1574242ab75f7ead4ed332ab64aaaff82181b9a9ec3005864f69` |
| 正式规则 | `235cba130a8030fadac38ce9e48205c546cbd150bc19988d28068eb6a71c0503` |
| 脱敏全量结果 | `ffb1a632c22b0b7e9dc8f6470f58cba52a63f556f60fa3d0e402b110a84f9138` |
| 私有原始归档 | `43a549a562b6af29fbc15f78088cda3c979d32df1133f334f5db31b6549a96fd` |
| 独立审计结果 | `4eaf82053436b6815aea17e5a720800ba5576271e1bed0049b257cdbab2c22e6` |
| 独立／主派生比较 | `3dc5454ebe3a6387ed0abae3a3b1fdaa5348156a980b7a484e98b81dd9512f97` |

Oracle 与下载后主分析输出逐字相同。独立审计只用标准库从 72 份 raw 重算全部七项指标、
42 组的全部六个比值、12 个 GM（30 位）及 18 项否决，与主 JSON 完全一致；1706 项文件
哈希、live argv、CPU、映射身份及清理全部通过，私有归档的 2004 个文件与本地证据一致。
原始 PID、路径和文件留在 private，本报告只发布必要身份及派生结果。
本轮是固定 caller 的 Oracle 工程筛选，不给出显著性或实机采用结论；
旧 caller 下 R136 的注册慢尾及 R140–R143 的既有负项继续有效。没有路由器操作。
