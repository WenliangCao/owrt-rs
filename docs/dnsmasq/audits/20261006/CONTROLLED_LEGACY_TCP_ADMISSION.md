# M5 legacy local-service TCP 入队边界

2026-10-06。原local-service-bare/remote-v4-1的C104 reset、Rust EOF没有定义到达/拒绝先后。恢复已有强入队探针到原16个denied TCP输入：bare/net/CLI-net/CLI-host各4个，加transport-specific tcp_scheduling=queued；所有scenario/probe/row ID及count保持，UDP与原explicit queued/idle FIN不变。没有改Rust产品，没有引入EOF/RST宽容。

同一ELF37f85…7f7b实际先跑bare全部18观察，后跑四个受影响场景共72配对观察；每侧16个拒绝TCP都记录kernel receive queue41 bytes（完整framed question），errno104且termination reset，C/R全部语义与守卫零差异。既有38个腐化/缺项自检仍全部拒绝，包括queued有数据却EOF、缺kernel queue证明、源地址/IPv6观察/覆盖缺失。已有SIGSTOP、真实kernel RX queue、SIGCONT helper未改；新schedule由observer和guards共同按transport读取，C/R运行上下文一致。

两个selected运行都因没有执行该option其他required scenarios而closed=[]、退出1；result.failures=[]且实际观察18/72全部通过。这里明确是有限对照，没有把部分执行说成完整matrix资格，最终fixture revision仍须全next matrix fresh重跑。全部证据SHA+metadata核验后清理远端，详见[完整收据](controlled-legacy-tcp-admission.json)。原未控制时序的红由root最终报告保留；没有重新分类成与C的产品行为差异。
