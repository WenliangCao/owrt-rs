# R126 路由器正确性结果

候选 ELF `a07a9f2882e27dee14c3f538d35a4c13fe30e9abe8f8f2b2f22150b06a64eb2c` 未安装到生产，
只由 r95 隔离命名空间运行。基线 R124 ELF 为 `42435a31e2917186fb353e2c70143f4b3f6d82ec3dd53265bf6d826897b69926`。

- FD boundary wireprobe：通过，C、R124、R126 输出完全一致，清理和健康检查通过。
- 事件/监视器/ACL/释放/UTF-8 回归：通过，C、R124、R126 输出完全一致，清理和健康检查通过。
- R126 Linux 单测 ELF 在路由器 guard 内执行，49/49 通过；同一事件回归再次通过。
- 每个窗口之后 boot、配置、生产身份、mounts 均一致；最后生产 PID 869 仍是 C，临时 `/tmp/r95-check-*` 全部不存在。

期间保留了五个没有执行到候选的失败记录：一次上传时 SSH 断线，四次调用者类型不匹配（把事件 wireprobe 当成 benchmark，或反之）。
它们不是 R126 失败；每次均由 guard 清理并通过健康检查。正确的事件 wireprobe SHA 是
`bcad2d4652b81c6c252b61f4bd8dd8424f85bd19bea2dd848236640967fdca26`。

这些是行为回归，不是性能验收。Oracle 48 样本的 A/A 校准在八对象、64-held pair 超出预冻 ±0.5% 门，
所以没有把 R126 性能系列带到路由器，也没有声称这项改动提升了路由器耗时或 CPU。
[机器可读结果和失败证据索引](r126-router-results.json)。
