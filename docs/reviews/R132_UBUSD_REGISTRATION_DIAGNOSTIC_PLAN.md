# R132：先定位注册回退

R131 的八监听事件收益保留，但两个注册场景的 p95 回退门失败。
本轮首先定位原因，不因多跑窗口而改写 R131 的失败判定，也不先提交新的 daemon 变体。

测量对象固定为上一轮精确 C、R124、R131 ELF；Rust 符号使用对应 linker map，
C companion 只有在加载地址对应的 `.text` 字节一致时才使用。未知符号保留未知。
测试调用者从原 `owrt-benchmark register-cycle` 增加独立编译 feature，
只在预热后的循环外加入 perf enable/disable ACK，保留原 ADD/REMOVE 方法签名、路径与调用闭包。
原路由器 benchmark ELF 不替换，不把新诊断 caller 的时间并入旧结果。

两套 Oracle 诊断分别冻结机器计划及工具/产物哈希后运行：

| 仪器 | 循环/预热 | 排列 | 用途 |
| --- | --- | --- | --- |
| `perf record cpu-clock`，997 Hz，无 callgraph | 300000 / 5000 | 1、16 方法各 C/R124/R131/R131/R124/C，共 12 窗 | daemon 用户/内核 self PC 和函数热点 |
| 同步 `perf stat` | 100000 / 5000 | 同上，共 12 窗 | 用户态 instructions、branches、branch-misses、cycles；context-switches、migrations |

daemon CPU1、caller CPU0、daemon argv0 `/sbin/ubusd`，每次使用相同 daemon/socket 路径。
采样从 disabled 开始，调用者等待 enable ACK 后读取循环起始时钟，循环及结束时钟完成后等待 disable ACK。
入口签名检查、预热、最终空注册表检查不在采样区间内。
计数拒绝不支持的事件和 multiplexing；profile 记录并拒绝丢样/节流。
小规模 smoke 只验证仪器，失败及修正全部保留，不混入正式窗口。

检查范围：前后 PID/starttime、CPU 绑定、实际可执行映射及 inode/SHA、调用者身份、
原始逐次样本、perf 命令/退出码与所有子进程清理。只清理 runner 自己创建的资源。
正式窗口数固定；样本不足或噪声过大时如实记为无法归因，不追加窗口追求想要的方向。

这套诊断只用于找出值得修改的工作，不作 AX3000T 的性能结论。
路由器只读检查显示当前镜像没有 perf 程序，也未暴露 perf sysctl/event-source 节点；
本轮不为采样更换内核或安装软件。任何新运行时方案仍需独立正确性检查与路由器隔离比较。
新的门槛在候选确定后另行冻结，不能从 Oracle 指令数直接宣布实机注册 p95 已修好。

特别区分三种结论：源码/汇编证明执行了哪些操作；PMU 记录实际总指令与分支；
self-PC 采样指出热点但不代表函数调用次数、内联归属或因果。
只有这些证据共同支持的方向才进入下一个候选，不再凭猜测换控制流或内联提示。

同步接口与采样选项依据 Linux v6.17 官方
[perf-record](https://github.com/torvalds/linux/blob/v6.17/tools/perf/Documentation/perf-record.txt)
和 [perf-stat](https://github.com/torvalds/linux/blob/v6.17/tools/perf/Documentation/perf-stat.txt)；
Oracle 当前使用 perf 6.17.13、aarch64 内核，与路由器硬件不是同一测量平台。
