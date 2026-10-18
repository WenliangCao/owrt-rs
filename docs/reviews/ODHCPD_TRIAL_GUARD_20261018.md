# odhcpd 有限试运行恢复门

2026-10-18：最终工具版本在 Oracle 的隔离环境 **6/6 场景通过**，生成器
3 项测试通过。试运行材料已生成，尚未由本工具连接或修改路由器。
此项只验证恢复可靠性，不增加性能测量；用户已接受首条 RA 的小幅差异。

工具是 `tools/odhcpd_trial_prepare.py`、`tools/odhcpd_trial.sh`，隔离验证为
`tools/odhcpd_trial_selftest.py`，输入拒绝测试为 `tools/test_odhcpd_trial.py`。
生成器只允许输出到 ignored `private/`，不调用 SSH。

## 试运行行为

输入绑定精确候选、C ELF、备份、bounded helper、预期 boot ID、原 init 和
odhcpd-update 哈希。设备 preflight 还核对当前 UCI 文件、ROM C、原 procd
服务实际 PID/启动时刻/ELF、dhcp 对象，以及无重叠守卫和可归属的 tmpfs。
普通文件软链接或试运行目录内额外挂载不予放行。

候选只通过 `/tmp` 文件 bind 到 `/usr/sbin/odhcpd`。独立 `setsid` 守卫自身
执行 bind 和原 `/etc/init.d/odhcpd restart`，SSH 调用者不拥有激活与守卫之间
的危险空隙。stdin 是 `/dev/null`，输出留在私有目录，忽略 HUP；300 秒期限用
单调 uptime。没有持久启动项、UCI 改写、整机重启或其他服务 stop/restart。

超时、手动恢复、候选退出、守卫 TERM，以及成功确认，都会停止 odhcpd、
卸载唯一属于该 token 的 bind、通过原 init restart C。完成必须同时证明：
无 bind、活动路径 C 哈希正确、procd 管理的 C PID 和启动时刻稳定、dhcp 对象
可调用、原 UCI 哈希未变。恢复失败保留锁和证据，不标记成功、不自动重启机器。

**确认是试运行结束，不是晋升**：外部客户端健康结果须带本次 token、boot、
候选 SHA 和原始客户端证据摘要；guard 验证回执后立即恢复 C。最终状态
`restored-confirmed` 才表示试运行成功结束。不存在确认后无人维护的临时覆盖。

## 隔离验证

使用精确 v0.2.3 提取 rootfs 的副本，真实 procd-rs、ubusd-rs、BusyBox、原
odhcpd init 与触发器。新的 mount/net/PID/UTS/IPC namespace 内 procd 为
PID 1；真实 tmpfs、bind、unmount 和 service restart，不模拟这些关键动作。
只配合成 UCI，客户端健康确认是合成回执，不据此声称真实客户端通过。

| 场景 | 验证 |
|---|---|
| 前置拒绝 | 错 boot、候选损坏、试运行目录额外挂载均未激活，原 PID 保持 |
| SSH 等价调用者丢失 | launcher 与 guard session 不同；杀 launcher 后守卫仍按期限恢复 C |
| 成功确认 | 错 token 健康回执被拒；正确回执立即恢复 C并保存证据摘要 |
| 手动恢复 | 活动期间请求恢复，C 实例和 dhcp 对象恢复 |
| 候选崩溃 | SIGKILL 候选后恢复，原 procd respawn 未留下 Rust 进程 |
| 守卫 TERM | EXIT 恢复路径完成，同样核对 C、对象与配置 |

首轮 6/6 通过后，工具复查补上 shell 条件调用时 tmpfs 检查的显式失败返回，
以及子挂载/软链接拒绝。最终同批 6 场景重新执行通过，包含新增拒绝断言。
没有改动候选程序或重跑性能。两次原始输出均保留。

候选 SHA256：`79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55`。
C SHA256：`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
原 init SHA256：`4d59c3687e7cacee9e7b82ba9433fa815aafeb8f94af4c6926993653009e0fa4`。
helper SHA256：`21609fa0e03e4a4595e74d266235a9566f2cc37f71571ad9315900d3def5cb49`。

Oracle 证据：`/home/ubuntu/odhcpd-rs-20261018/private/guard-test-01/`、
`guard-test-02/`；最终摘要和日志归档到本地
`private/odhcpd-20261018/trial-tools/guard-test-02-evidence.tar.gz`。
本地私有包为 `private/odhcpd-20261018/trial-tools/device-trial-01/`，其
`receipt.json` 保存 token、boot、输入摘要与具体操作命令，均不进入 Git。

下一步只需主线程重核当前 boot/配置未变，按用户既有授权执行短时试运行，
由真实 LAN 客户端验收 IPv6 地址、默认路由、DNS 和连通性。通过后另做镜像
资格；此恢复门不代表已经完成真实设备试运行或下一版本发布。

## Fable 最终 SDK 的重新验证

Fable F1–F5 修复后的 SDK ELF
`c7c5f1f9e79ea80febe696d6c758db8d3463d1e4b94c7a002f1aa597b9c3ea30`
已用相同工具在新私有目录重新执行上述 **6/6 场景**，生成器 **3/3 测试**。
本轮没有失败、重跑或工具变更，没有新增性能测量。所用 C、原 init、触发器、
v0.2.3 procd/ubusd 和 bounded helper 身份与上文一致；没有把旧 ELF 的通过
结论直接转授新 ELF。确认仍使用合成客户端回执，不声称真实客户端已验收。

新原件位于 Oracle `/home/ubuntu/odhcpd-rs-20261018/private/guard-fable-01/`。
本地日志/结果：`private/odhcpd-20261018/trial-tools/guard-fable-01-evidence.tar.gz`，
SHA256 `36716b2eeb0acd06c0bf236e27190e6ae62bba4d548d3be765b1fcf448ffd3ef`。

新 300 秒材料为 `private/odhcpd-20261018/trial-tools/device-fable-trial-01/`，
已复核本地副本的全部输入摘要。其 `receipt.json` 绑定新 ELF、最新已核对备份、
预期 boot 和具体命令；内容仍在 ignored private 中。该包仅已准备，路由器操作
由主线程独立执行，未在本项离线验证中发生。旧材料与旧结果保留为历史。
