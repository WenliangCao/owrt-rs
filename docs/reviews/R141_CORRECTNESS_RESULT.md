# R141：profile-use Oracle 正确性通过

候选 `70e7174c648ef676800a5f03d557ba7a0e1f07de2450c5d0d6ed334d3aa862eb`
首次通过既有全部功能门；原 generic R136 源码不变，仅增加 profile-use 与 missing-function
诊断 flags。训练 profile 为 `566a73250308a19e97715b40ff2b2f4043f07ed836b89b205d50d810ef07c4f8`。

| 检查 | 结果 |
| --- | --- |
| OpenWrt SDK musl release 单测 | 55/55；20 个运行时及 Cargo 文件身份吻合。单测使用与候选完全相同的 RUSTFLAGS、规范源码路径和 profile，测试 ELF 独立构建；构建日志没有 profile 警告。 |
| wire | 8 个既有场景：exact C、R136、候选逐字相同，包含 REMOVE reply。 |
| SCM_RIGHTS / FD | 每个实现 6 案例：exact C、R131 控制、候选。前三个真实 sender framing 相容；后三个 handcrafted 案例保持已接受的 read-ahead 合约与无泄漏断言。 |
| 恢复 | `ubusd_halfclose`、`ubusd_lookup_delete` 候选全部检查通过；exact C 已知失败仍按原门保留。 |

没有新增测试、放宽断言、失败后重跑或改动运行时代码。wire 使用 R136 控制，FD
使用原 R131 控制，保留两者不同边界，未重复早期错误的 FD 控制替换。

[复核器](../../tools/r141/analyze_correctness.py) 逐项验证构建及 profile 身份、单测
flags、三个实现的 transcript、恢复分类和完整证据归档；[脱敏结果](r141-correctness-results.json)
保留全部 143 个证据文件的 SHA256。原始归档 SHA256 为
`de7b958be7ee3f1da8b4de0128f6c9c5e39fb48c62680e48ffc4a026e5a851f1`。

这是 Oracle 功能结果，没有比较性能门或路由器操作；训练和功能通过均不意味着性能
改善或采用候选，须继续执行独立、未插桩的冻结筛选。
