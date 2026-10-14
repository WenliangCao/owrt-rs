# 最终 SDK ELF：TCP 内存与 HUP 快照两门

2026-10-14，冻结源码 `b587282081b72ea0f96cf909e0f70b0bc8de9372`，实际 SDK 包内 ELF SHA-256 `50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c`，2,124,571 B。**两个独立配对的 64 MiB 进程树资源门通过；没有重现原 TCP 内存崩溃。** [派生结果](final-sdk-memory-review.json) 保存 PSS、内核峰值、OOM、客户端、地址及清理证据。

本次无新构建。测试前独立复制最终包内 ELF 并核验，收尾原 payload 与副本 hash 不变。C 为精确镜像 ELF `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`，两门均实际重新跑 C 和 Rust。每个 daemon 全进程树共享 64 MiB cgroup、swap=0；Oracle 独立 network/mount/PID namespace，不是设备当前可用 RAM，也没有操作路由器。

| 用例 | 精确 C | 最终 Rust |
| --- | ---: | ---: |
| 30k 名字 / 60k repeated-address A：启动 PSS | 6,872 KiB | 25,560 KiB |
| seed held + 父 UDP warmup 后 PSS | 11,950 KiB | 26,272 KiB |
| 20 条新连接完成后 PSS | 9,616 KiB | 26,688 KiB |
| warm 全程 `memory.peak` | 17,186,816 B | **26,759,168 B** |
| 50k 单 A：初始 PSS | 5,884 KiB | 25,028 KiB |
| 20 条旧连接持有时 PSS | 8,404 KiB | 26,024 KiB |
| HUP 后保留 10 旧 + 10 新连接 PSS | 13,392 KiB | 38,756 KiB |
| HUP 全程 `memory.peak` | 15,982,592 B | **49,471,488 B** |

PSS 是所有实际进程的比例驻留页之和，避免 C fork 页重复统计；`memory.peak` 是 cgroup 的内核峰值，两者统计范围不同，不能相加。warm 的 PSS 不是单调序列：第 20 条新连接前按 C 连接上限释放了 seed，原 driver 保留这一操作。

第一门复用 `hosts_rotation_memory.py --names 30000 --warmup --budget-mib 64`，保持原 repeated-address 输入，未启用 unique-address 或 rolling。父进程先完成 30,000 次 UDP warmup；双方均 **20/20 新 TCP、UDP 健康、进程存活**，20 对记录的完整 wire 相同。它没有重跑此前 2,000 次 rolling，也不代表完整 F10 合同已关闭。

第二门复用 `full_tcp_hosts_cgroup.py --budget-mib 64 --hup` 的输入和操作：50,000 hosts、20 个旧 TCP，HUP 改变全部地址，逐一查询 20 个旧连接，再关闭 10 个、建立 10 个新连接。双方均 **旧 20 个全部为 `192.0.2.1`，新 10 个全部为 `192.0.2.2`**，随后 UDP 健康、daemon 存活。该旧工具按答案地址后缀断言；没有把它冒称完整 wire 协议比较。

四个 daemon 的 `oom`、`oom_kill`、`oom_group_kill` 均为 0，正常清理退出 0，cgroup 中无剩余进程，全部 `cgroup_removed=true`。

## 工具与失败保留

warm driver 与冻结源码逐字一致，SHA-256 `66f29e7cf865072124b6773d56f3f63cf064cd629ab7e673f769aa924be4a758`。旧 HUP driver SHA-256 `677eeb44625e8bbc20d4ae6d7e534192e23a8dc5ea7d0270c92c3915e60a8dc2` 没有 PSS 采样；私有副本仅导入 warm 工具已有的进程树 `stats`，在 ready、old20、HUP/new10 后采样，未改输入、预算或原地址断言。正确副本 SHA-256 `db3e329eaeb1daea3f71d479e36c2bde95cd8833869338a295cfa18570cfff05`。

首次 HUP 私有采样副本漏了字段引号，C old20 之后因 NameError 退出；原工具和产品无关。失败脚本、命令和 stderr 保留，未计通过；修正后使用全新 `hup-retry/private` 完整重跑双方。最终还独立检查全部连接、地址数量、存活、UDP、内存事件和 cgroup 清理，没有仅依赖旧 HUP 脚本退出 0。

## 证据与收尾

Oracle 完整目录 `/dev/shm/full-merge-final-memory-20261014/`；本地 `private/final-sdk-memory/`。全目录归档包含原始结果、失败尝试、输入 ELF、原/改驱动及生成 overlay，SHA-256 `1aa405cc10cec57549c4e7471971339862b2db5643274ff223d4a454f7887d3f`；已回拷核验，全部普通归档文件逐字核对。Linux overlay 的 5 个特殊节点保存在归档内，未在 macOS 创建。

收尾没有本任务所属进程或宿主可见挂载残留，候选前后 hash 一致。该结论限于上述两门，不扩大为任意并发数、任意多代 hosts、长期无泄漏、全局 OOM 或硬件部署资格。
