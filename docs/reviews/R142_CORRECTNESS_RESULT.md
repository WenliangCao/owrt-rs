# R142：monitor 候选 Oracle 正确性通过

候选 `367badc11fb93b25208cda041048133b8439e1c703c2cb07d740312cc140db54`
通过全部功能门。控制精确重现 generic R136 `ce3d1aa…`；两个快照各 30 文件，只有
`ubusd/src/server.rs` 不同，构建 flags 相同，没有叠加 A53 或 PGO。

| 检查 | 结果 |
| --- | --- |
| SDK musl release 单测 | 56/56；包含新增真实双 monitor、重复注册、独立序号 wrap、快直写／慢排队及 scratch 覆盖回归。单测与 release flags、规范源码路径一致。 |
| 原 wire | 8 案例在 exact C、R136、候选间逐字相同。 |
| 原 FD | C、R131、候选各 6 案例；原 framing 合约及已接受的 handcrafted read-ahead 差异不变，witness 与无泄漏检查通过。 |
| 原恢复 | 候选 halfclose、lookup-delete 全通过；原 C 已知失败仍按原分类保留。 |
| 原生 event helper | 原 `1705d989…` ELF，grouped/interleaved/monitor 各 100＋20 预热、slow 192 次；C/R131/候选共 12 案例通过，内容、顺序、序号、清理、队列丢弃及恢复检查不变。 |
| 新 monitor 协议补充 | C/R136/候选各生命周期＋慢读者两案，共 6 案例首次通过。重复 add、remove/readd、注册后断连、完整镜像字节和序号、FD 不镜像、连接存活时 witness EPIPE 均通过。 |

慢读者固定 128 次 16 KiB PING 生成 384 条镜像，三方本次均收到 204 条；所有幸存帧
字节／顺序正确，快读者完整接收，恢复 PING 各收到三条镜像。相同幸存数是观测结果，
并非门槛；门槛仅要求实际触发有界丢弃且完整恢复。所有功能任务首次完成，无重跑调参。

[离线复核器](../../tools/r142/analyze_correctness.py) 验证 411 个证据文件、构建和单测
身份、旧 transcript、恢复分类、旧 helper 原始 JSONL 和新协议检查结果。
[脱敏结果](r142-correctness-results.json) 保留完整文件 SHA 清单；私有归档 SHA256：
`474723f897600342ac48134756fc718b081f630c7b8f5c232c77bc2874f91b1d`。

新 Python 探针在运行时逐帧断言，不是完整 packet capture；这份结果没有性能排名、
heap/RSS 接受结论或路由器操作。内存和冻结性能系列必须单独验证。
