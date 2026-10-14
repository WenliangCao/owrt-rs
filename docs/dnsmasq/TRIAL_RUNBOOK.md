# dnsmasq-rs 真机试运行

本流程取代 [DEPLOY_RUNBOOK](DEPLOY_RUNBOOK.md) 中的受监护控制器，用于在 AX3000T 上**临时**试运行 dnsmasq-rs。执行前需要用户单独授权。

## 为什么换掉原控制器

[上线前复核](PREDEPLOY_RECHECK.md)发现原控制器在回退途中被杀会卡在「没有任何 dnsmasq」的状态（R1），把 C 的正常 TCP 子进程误判为冲突实例（R3），监护本身停止调度时无人接手（R5）。这些问题都来自同一个根源：控制器要接管 procd 实例、自己维护状态机。逐个修补会继续引出新的边界。

新方案只用 [`tools/dnsmasq/deploy/dnsmasq-trial`](../../tools/dnsmasq/deploy/dnsmasq-trial)（POSIX sh）：

- **不接管 procd：** 把候选 ELF bind mount 到 `/usr/sbin/dnsmasq`，由原装 init、procd、ujail 照常启动。odhcpd 的 hosts 信号、LuCI/UCI 修改、`/etc/init.d/dnsmasq reload` 都走原路径。
- **不写闪存：** 候选、回退请求和锁文件只放在 `/tmp`，bind mount 不跨重启。**路由器重启一定回到 C。**
- **回退可重试，并保留独立恢复进程：** `rollback` 先留下临时请求，用镜像自带的 `flock` 串行卸载和原装服务重启。只有 mount 已消失、所有 dnsmasq 进程都匹配 `/rom` 中的 C、且本地 DNS 能回答时，才取消计时器和健康监护。监护不会因 mount 消失而退出；它会继续处理回退请求，直到确认 C 健康。恢复命令在独立进程组中运行，单次杀死恢复进程后，仍在运行的监护或计时器会重试。幂等本身不能保证跨进程中断恢复；FULL-TRIAL-1 已证明旧版本提前取消两个 helper 会丢失自动回退。
- **两道互相独立的自动回退：**
  1. **到期回退：** 启动候选之前先起一个计时器，到期未 `confirm` 就回退，恢复失败或进程被杀后继续重试。
  2. **健康监护：** 每 5 秒检查一次「所有 dnsmasq 进程都是候选 ELF，且本地名字能在 3 秒内解析」，连续 3 次失败就回退。崩溃先由 procd 重启；连续崩溃耗尽重启次数、进程卡住或不再应答，都会触发回退。
- **最后兜底：** 两个 owner 都失效，或 `confirm` 后唯一的健康监护停止调度时，仍需手动执行 `dnsmasq-trial rollback` 或重启路由器。新脚本不宣称 R5 在这些情况下消失。

## 验证

在 Oracle 上的精确镜像 rootfs 中验证，使用镜像自带的 ubusd、logd、procd、netifd、init 和 ujail，并用独立 veth 上的真实客户端检查 DHCP 租约和 DNS。每个用例都按 `/proc/<pid>/exe` 的哈希确认实际运行的程序，而不是看命令返回值。工具为 [`test_trial_oracle.py`](../../tools/dnsmasq/test_trial_oracle.py)。

| 用例 | 过程 | 结果 |
| --- | --- | --- |
| confirm-rollback | 启动 → 确认 → 12 秒后仍是候选 → 回退 → 再次回退 | 通过；两次回退后都是 C，客户端正常 |
| deadline | 启动后不确认，20 秒到期 | 通过；自动回到 C |
| crash | 候选运行中把一个立即退出的程序叠加挂载上去，再杀掉候选 | 通过；procd 重启失败后监护回退到 C |
| hang | SIGSTOP 所有候选进程 | 通过；监护回退到 C |
| watch-killed | 杀掉健康监护 | 通过；到期计时器仍回退到 C |
| partial-rollback | 杀掉监护和计时器，手动卸载 mount 后 Rust 仍在运行，再执行 rollback | 通过；回到 C |
| reload | 候选运行中执行 `/etc/init.d/dnsmasq reload` | 通过；同一进程继续服务，客户端正常 |

FULL-TRIAL-1 的当前修复另外覆盖真实脚本中的单次 SIGKILL：回退请求写入后、确认后的卸载与重启之间、以及两个 helper 文件清除后。精确镜像、命令和新结果见 [trial 修复证据](audits/full-20261014/TRIAL_FIXES.md)。原始七用例记录如下，不能替代上述中断验证。

七个用例共进入试运行阶段 16 次，全部通过。另有 3 次在试运行开始之前失败：测试框架启动阶段，原装 C 没能给测试客户端发出 DHCP OFFER（`DHCP message 2 unavailable`）。这发生在 `dnsmasq-trial` 运行之前，与本脚本无关，属于既有测试框架的启动时序问题；失败记录保留在 `final/`、`rerunB/`。

候选为预部署修复的 SDK 包内 ELF `0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728`。原始证据在 Oracle `/home/ubuntu/dnsmasq-trial-20261014/private/`。

## 已知、接受的残余风险

- **hosts 重载的极端内存失败（复核 R2）：** 只在人为限制地址空间、并一次性重载 30,000 条 hosts 时出现。真机上 Linux 内存超额分配，这种失败基本表现为 OOM，而非 malloc 失败。即使发生，也会被 procd 重启，或被监护回退。试运行接受这一项，正式替换前再修。
- **ubusd 重启后 ubus 对象丢失（审计 B5）：** C 版也一样。执行 `/etc/init.d/dnsmasq restart` 即可恢复。
- **监护的检查范围：** 健康检查只看 DNS 应答和进程身份，DHCP 由操作者在观察窗口内确认。

## 步骤

需要用户授权后执行。全程经 Wi-Fi 管理即可。

1. **离线备份（仍在 C 上）：**
   ```sh
   umask 077; sysupgrade -b /tmp/predeploy-backup.tar.gz
   ```
   拷回电脑，确认能解开、哈希已记录。同时在电脑上保存候选 ELF 和本脚本，并记下它们的 SHA-256。
2. **上传与核对：** `scp` 候选 ELF 到路由器 `/tmp/dnsmasq-rs`，脚本到 `/tmp/dnsmasq-trial.sh`。`/tmp/dnsmasq-trial/` 是脚本运行目录，不能用作上传文件名。在路由器上执行并与电脑记录核对：
   ```sh
   chmod 755 /tmp/dnsmasq-trial.sh
   sha256sum /tmp/dnsmasq-rs /tmp/dnsmasq-trial.sh
   ```
   执行权限用于计时器和监护重新调用脚本。
3. **启动（默认 10 分钟内必须确认）：**
   ```sh
   sh /tmp/dnsmasq-trial.sh start /tmp/dnsmasq-rs <候选SHA256> OpenWrt.lan 127.0.0.1 600
   ```
4. **约 3 分钟观察窗口：** 手机或电脑重新连 Wi-Fi，确认拿到地址、能上网、能打开 LuCI；`sh /tmp/dnsmasq-trial.sh status` 显示候选在运行；`logread | grep dnsmasq` 没有异常。
5. **决定：**
   - 一切正常，想继续试：`sh /tmp/dnsmasq-trial.sh confirm`（健康监护继续运行，直到重启或回退）；
   - 有任何疑问：`sh /tmp/dnsmasq-trial.sh rollback`。
6. **结束试运行：** `rollback` 或直接重启路由器，都会回到 C。

这一步只是试运行：不修改安装包，不写闪存。正式替换（安装包、开机自启）另行决定。

## 2026-10-14 第一次真机试运行

授权后在 AX3000T（OpenWrt 25.12.5 r33051，已运行 5 天）上执行。离线配置备份 `b0a10121…` 与租约快照已拷回电脑 `private/trial-20261014/`，候选 ELF `0d5a4769…` 与脚本 `45d38901…` 在电脑、路由器两端哈希一致。

- **13:48:59 启动**：候选由原装 procd/ujail 运行，主进程 RSS 2.25 MiB，单线程。
- **约 6 分钟观察**：经路由器的 DNS 查询（UDP/TCP、A/AAAA、本地 `OpenWrt.lan` 与公网名）、网页访问、WAN 状态均正常；日志无异常。
- **发现**：未缓存名字的 TCP 查询超时。`netstat` 显示 dnsmasq 到运营商 IPv4 DNS `82.144.41.8:53` 的 TCP 连接停在 `SYN_SENT`；运营商 IPv6 DNS 的 TCP 正常。回退到 C 后同一测试：C 也有 3/5 超时，也卡在同一个 `SYN_SENT`。这是运营商 IPv4 DNS 不接受 TCP（10/08 体检已记录），**不是 dnsmasq-rs 的缺陷**。两边成功数不同（Rust 0/5、C 2/5）样本太小，可能与上游选择或缓存有关，下次试运行再对比。
- **手动回退**：一次完成，C 恢复运行，mount 已卸载，临时文件清除，路由器回到原状。
- **脚本修正**：回退后残留一个到期计时器的 `sleep` 子进程（无害，父进程已被杀，不会再触发回退）。已改为按进程组终止，Oracle 上 confirm/deadline/watch-killed/partial-rollback 复测通过。
- **未做**：没有让客户端重新获取 DHCP 租约（下次需要手机重连 Wi-Fi 验证）。
