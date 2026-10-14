# 最终冻结候选：trial 两项独立恢复验收

2026-10-14，最终 `19bd6162` 候选与冻结 trial 脚本重新配对执行 **rollback-killed、deadline 两项，均通过**。[派生收据](integrated-trial-review.json) 保存身份、实际客户端结果、故障注入位置、运行时间和原始 hash。这是两项恢复边界验收，不替代完整 trial 矩阵，也不构成产品整体或物理部署通过。

| 输入 | SHA-256 |
| --- | --- |
| 最终 Rust ELF，2,089,440 B | `fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b` |
| 精确镜像 C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| `tools/dnsmasq/deploy/dnsmasq-trial` | `dfa94d52cb132a181d78b8a0471b49868d9d3dd8bf9f79b00839edbd649f8b74` |
| `tools/dnsmasq/test_trial_oracle.py` | `f3ce62bceb4d80bbb8061de7fb2e9c9c3dd14d2a401ad5ad7bd8838c6cc560cd` |

Oracle 上执行的 trial 和 harness 均逐字核对 `19bd6162e1b33c92a1e5ea26e864497800c7cfed` 的 Git 内容；运行前后身份不变。运行底座是精确镜像 **C ubusd/logd/procd/netifd 和原装 init/ujail**，不是[独立 Rust9 组合验收](integrated-stack-review.md)的支撑栈。每个常驻支撑进程均保存实际 ELF hash；两组结论没有混用。

| 场景 | 新执行结果 |
| --- | --- |
| rollback-killed | 在 rollback 请求已写、candidate bind 仍存在、`deadline.pid` 与 `watch.pid` 尚在时，ptrace 观察真实系统调用边界并单次 SIGKILL；被杀 rollback 退出 `-9`。剩余 owner 自动恢复实际运行的精确 C，客户端 DHCP OFFER/ACK 与 UDP/TCP DNS 全通过，最终 helper pidfile 清空。整轮约 14.80 秒 |
| deadline | 以 20 秒未确认 deadline 启动最终候选；候选实际运行且客户端正常，随后自动恢复实际 C，客户端 DHCP 与 UDP/TCP DNS 继续通过。整轮约 28.59 秒 |

两轮都先验证初始 C 客户端，再验证候选和恢复后 C；恢复判断核对 `/proc/PID/exe`，不只看磁盘文件、PID 或命令返回。harness 在恢复后断言 candidate bind 已移除。没有替换产品命令、修改 init/procd/ujail 或伪造恢复结果。

全部实验位于 Oracle 私有 mount/network/PID namespace，以独立 veth 客户端发包；没有操作路由器。收尾没有所属进程或宿主可见挂载残留，候选、trial 和 harness hash 均保持不变。

原始证据位于 Oracle `/dev/shm/full-audit-resume-20261014/stack-trial/`，本地 `private/full-audit-20261014/resume/stack/trial/`。派生 JSON 列出 `final-evidence.tar.gz` 完整 hash。旧审计和修复方的原始结果保持原状；本轮只增加新证据。
