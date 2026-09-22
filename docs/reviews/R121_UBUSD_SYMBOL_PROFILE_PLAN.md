# R121：先定位热点，不改运行逻辑

固定 C、R109、R115 发布 ELF，在 Oracle 只做 CPU 热点诊断；保留现有 FD 契约。
本轮不创建优化候选，不把构建机结果作为路由器性能结论。

- R109/R115 用相同 release 配置附加 linker Map；完整 ELF SHA 必须复现历史发布版。
  已满足。C 未剥离伴随文件的 allocated section 内容按加载地址与原 ELF 校验。
- 用已验证的 `user-event-perf-v3`（`d8240a8f…00e7`），预热后 enable/ACK，
  循环结束 disable/ACK。单监听者匹配事件，daemon CPU 1 / caller CPU 0。
- `perf record` 只附加 daemon PID，cpu-clock 499 Hz、无 callgraph；同时保留用户态、
  内核态样本、原始 IP、DSO 和丢样/节流记录。丢样或校验失败不作热点比较。
- 工具先做三版本短 smoke，验证 payload、采样开关、动态 C 的精确库映射和进程清理；
  smoke 不并入结果。正式诊断每段 500000 次、预热 5000 次，低连接/64-held 各两段；
  第二块反转版本和规模顺序。无重复到满意为止的选样。
- 输出平面函数自身热点；内联代码只能归属于包含它的符号，不伪称完整调用树。
  报告未知地址比例。用 exact linker Map 或经代码字节校验的 ELF 符号映射，不能套用普通 debug 构建地址。
- C 通过镜像 musl loader 启动；Rust 静态 ELF 直接启动。固定 argv[0]，
  验证实际 executable mapping，不能将 C 的 loader `/proc/PID/exe` 当成 daemon 身份。
- 只对大的、重复出现的热点提出下一项可反证假设；用户态指令减少 3% 不是通用硬门，
  约 1% 的不确定差异也不写成统计等价。任何优化结论仍需物理路由器隔离验证。

来源：[perf record 控制接口](https://github.com/torvalds/linux/blob/v6.17/tools/perf/Documentation/perf-record.txt)、
[GNU ld Map 与 local symbols](https://sourceware.org/binutils/docs/ld/Options.html)。
原始 ELF、Map、perf.data 和日志保留在 ignored `private/r121-symbol-profile/`。
