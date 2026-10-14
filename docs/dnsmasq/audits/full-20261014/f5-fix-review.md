# F5 修复：总线重启后自动恢复管理对象

2026-10-14。修复分支 `fix/dnsmasq-f5-ubus-20261014` 从 `340ed73e` 创建。**修复方新跑 7 个精确镜像/Rust9 场景全部通过，另保留 2 个旧 Rust/精确 C 对照；主审仍须对合并后的最终产物独立验收。** 没有直接改 main、推送、操作路由器或安装生产包。[派生收据](f5-fix-review.json) 保存各场景、身份、权限负控、时延与证据 hash。

## 完整失败边界与修复

此前把 F5 主要归因于 ACL 不完整，遗漏了更早的一层：**原装 ujail 的 ubus 快捷项把单个 socket inode 固定绑定进 jail**。新实测即使补齐 ACL 和 daemon 重试，fixture 的新 socket 已为 inode 34，运行中 jail 仍为旧 inode 18，无法连到新总线。该失败保留为 `restart-3`，不是被删掉的测试器失败。

匹配 procd `jail/jail.c:2705–2707` 的 `-u` 仅设置 mount namespace 并绑定 `/var/run/ubus/ubus.sock`，不另设 UID、capabilities 或网络权限。包 init 改为 `procd_add_jail dnsmasq log`，并明确只读绑定 `/var/run/ubus`。其余 jail 参数和 mount 保留。新测试确认父目录 inode 不变，重启后 jail 和 fixture 都看到新 socket；以 root 经 jail 路径创建文件也得到 **EROFS(30)**。实际 daemon 仍 UID/GID 453，effective/permitted capabilities 均为 `0x3400`。

另外两个失败边界同时修复：

- 包 ACL 只给 `dnsmasq` 用户新增精确 `dnsmasq.dns` publish 权限；保留原 `dnsmasq` 与三个 hotplug 方法权限，没有 `dnsmasq*` 或其它通配。
- 已运行的 daemon 不再因注册失败永久清空 `ubus_name`。连接失败或注册拒绝均按一秒退避，并把 deadline 纳入空闲 poll；每个断连周期的缺连接/注册错误日志有界。成功重连重新创建两个对象，不保留旧 object/type ID。

运行期一次尝试的 HELLO 和两次注册共用 **100 ms 总预算**，并继承 STOP 取消。否则新增的周期重试可能反复把主循环阻塞数秒。启动时的原注册失败退出契约保留；错误配置没有被静默改为“后台慢慢试”。

## 冻结身份

| 输入 | 身份 |
| --- | --- |
| Rust 编译源码 | `b0c386e2ce820587ca16a164673b33d130b1a570`，647 个跟踪输入逐项核对，零缺失/不一致 |
| 被测 Rust ELF | `35e65ff5f3d848471feecd8e0bf12a5a5d386ec517cc389566fd186230c9c706`，2,089,440 B；SDK musl release/static PIE，未封装 APK |
| 包 init 修复 | `cde1db23`；此提交只改 init，没有改变上述 Rust 源码/ELF |
| 完整代码与工具交接点 | `5761bfc60f108fe9a5e7a3b7220e5cb783e3596a`；其全部 `components/` 与编译源码完全相同 |
| 精确 C ELF | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 修复前 Rust 对照 | `340ed73e` / `edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d` |
| Rust9 | 复用此前从 `e9d89b17` 新构建、源码已经核对的 9 个 ELF；每轮再核对安装 hash，并记录实际使用的 ubusd/logd/procd/netifd/rpcd 进程 hash |

## 实际验收

| 新场景 | 结果 |
| --- | --- |
| 总线停 3.3 秒后重启 | 没有 DNS/DHCP 流量帮助重连；约 0.813 秒内同一 daemon 自动恢复两个对象，metrics 正常。随后两次真实 veth DHCP/UDP/TCP 客户端均通过，ACK 事件恰好两条、真实 ACK counter 恰好增加 2 |
| 总线重启时暂缺 `.dns` ACL，之后 SIGHUP 重载 ACL | 拒绝期 DNS/DHCP 正常、未留下半注册的主对象、错误日志只有一条；恢复精确权限后约 0.414 秒恢复双对象与相同客户端/事件检查，无需重启 dnsmasq |
| 启动/ACL 负控 | UID 453 可以发布两个精确对象；`dnsmasq.extra`、`dnsmasq.dns.extra`、`dnsmasqevil`、`service` 以及 nobody 发布 `dnsmasq` 均被拒绝，实际 ubusd status 为 2。初始权限拒绝和第二对象被占用均退出 5；第二注册失败清理了第一对象 |
| 无 socket 时 TERM | 约 2.2 ms 退出；故障期间没有忙循环或逐次重复日志 |
| socket 存在但不发 HELLO | 600 次 UDP/TCP 查询零失败，另有真实 DHCP 客户端通过；单次目标连接约 100 ms，TERM 约 2.3 ms |
| HELLO 后首注册不答 | 598 次 UDP/TCP 查询零失败，DHCP 通过；TERM 前确认目标进程已发 1 个注册请求，约 2.3 ms 退出 |
| 第一注册成功、第二注册不答 | 598 次 UDP/TCP 查询零失败，DHCP 通过；TERM 前确认目标进程已发 2 个注册请求，约 2.2 ms 退出 |

三种 stalled-bus 场景共 **1,796 次 DNS 查询**，最大查询时间约 **101.1 ms**。这里明确保留同步重连的故障预算，没有宣称零时延或完全异步恢复。连接观察通过实际 `SO_PEERCRED` 核对目标 UID/PID；首/次注册杀点分别有完整请求数见证。

对照没有改写成通过修复：旧 `340ed73e` 即使用新的目录绑定，临时 ACL 拒绝后仍永久失去对象，修复权限和正常业务都不能恢复。精确 C 即使采用新 init/ACL，空闲时没有自主恢复；业务唤醒后只恢复主 `dnsmasq` 对象，`.dns` 仍缺失，DNS/DHCP 保持健康。Rust 自动恢复两个对象是有意修复这些 C 共有边界。

Linux musl 单测 **lib 789 passed / 20 ignored，bin 78 passed / 3 ignored**。首次 bin 执行受共享 `/tmp` 遗留 FIFO 影响，77 passed/1 失败；使用独立 tmpfs 重跑后通过，原失败与日志保留。

旧 `ubus_daemon_diff.py` 原本要求冲突消失后永久禁用。`72e843ed` 仅对这两个恢复观察加入严格的 C 缺陷/Rust 恢复 guard：完整双对象签名、30 个真实 metrics 字段及增量、DNS 和精确日志；启动、冲突存在期和半注册清理仍严格比较。使用精确镜像 C ELF/库的新 recovery 执行 **67/67 checks，13 个观察**。该辅助对照的 native build 只提供 ubusd/客户端，没有拿重编 C dnsmasq 替代镜像。全套新计数为 346，本轮没有冒称已重跑全部套件。

## 复验、范围和收尾

主工具为 `tools/dnsmasq/test_ubus_recovery.py`，须经 `run_isolated.sh`。输入显式指定 `--image-root`、`--rust-binary`、`--rust-sha256`、`--source-commit`、`--support-bins`、包 `--init`/`--acl`、`--publish-probe` 和新的私有 `--output`。场景见 `--help`；私有 `run.py` 与每轮 `.command.json` 保留本次准确命令。发布探针由提交的 `ubus_publish_probe.rs` 编译，构建命令及其 ELF hash 单列保留。

本次验证默认对象名；自定义 `enable-ubus` 名称仍需管理员明确配置对应 ACL，不以通配权覆盖。目录绑定假设正常 ubusd 重启只替换 socket；重建整个父目录不在此证明内。未做真机、完整 APK 或全局 OOM 试验，未据此宣告其它已知问题关闭。

原始目录为 Oracle `/dev/shm/full-merge-f5-20261014/`、本 worktree 的 `private/f5-ubus/`。`evidence-final.tar.gz` SHA-256 为 `f4f060ff9b60eecd7659b83c769c3ebfa988a688a02ad6a4a2cb13743a411068`，已回拷并逐项验证阶段配置归档内容。确认无所属活进程或挂载后，只清理了本任务 24 个已完成阶段的可重建 rootfs/overlay（48 个目录）；源、工具、ELF、日志、配置归档和失败证据均保留。独立收尾/清理收据见派生 JSON。
