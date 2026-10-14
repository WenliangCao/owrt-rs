# B1 最终 SDK ELF 验证

`summary.json` 全部运行时结果使用最终 SDK 包内 ELF
`0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728`，
与精确镜像 C `097a9e21…cab87` 对照；测试源码冻结于 `807db8a1`。

- 原审计 30,000 条 hosts、`VmSize + 1 MiB` 限制：两边实际出现 ENOMEM，
  daemon 存活、配置记录继续回答、解除限制后 HUP 恢复、正常退出。
- 同样 30,000 条无压力控制：两边最后记录可查。Rust RSS 15,912 KiB；
  本轮合成场景不能作为路由器常态内存结论。
- 文件/hostsdir、展开开关共 8 个实现组合，每个两次资源失败：UDP 配置名与
  DHCP 租约名、DHCP ACK 保持可用；解除限制后 TCP/UDP 新 hosts 均恢复。
  C 压力中的 TCP child 可失败，Rust 本例仍可应答；没有宣称压力中逐报文相同。
- 正常回归：hosts/坏 token/目录/诊断/启动 DHCP 8 对；48 MiB 注释文件 3 对；
  启动 helper 顺序 3 对；启动 DHCP gate 1 对；hosts generation/cursor
  204 次查询/实现，零差异，包含多地址轮转、PTR、重载、IPv6、TCP 快照与字面点。
- 同一冻结源码另编 AArch64 musl debug 测试，5 个分配故障测试通过；它不是
  包内 release ELF。owner 连续失败后恢复其他 source 的状态测试属于完整 binary suite。

Rust 不保证压力下的逐条 hosts 集合与 C 相同：单条分配失败可跳过记录，
暂存或发布失败可保留旧 source/快照；连续两次复制失败后，下一次增量更新先
恢复仍有效的 daemon 视图，避免覆盖其他 source。没有新增自动重试循环。

[收集脚本](collect.py) 只读取 Oracle 保留结果并检查断言。
[派生汇总](summary.json) 包含原始结果/strace/测试日志路径与 SHA、完整重跑命令、
源码/工具身份和限制。第一次正常边界运行缺少冻结包未包含的历史文档 fixture，
在启动 daemon 前失败；随后从同一提交提取原 fixture，借 `PYTHONPATH` 重跑成功，
该准备错误也保留在汇总中。未接触物理路由器。
