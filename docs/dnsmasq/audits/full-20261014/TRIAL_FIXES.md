# FULL-TRIAL 修复证据（2026-10-14）

本报告针对 `main=e9d89b17d72a58b723cce88038ceaa1be58d7f8c`，在独立分支修复；未 push、未合并 main、未操作物理路由器。所有测试使用 Oracle 的隔离 PID/mount/network namespace、精确镜像的 init/procd/ujail 和独立 veth DHCP/DNS 客户端。原始证据保留在 Oracle `/dev/shm/full-trial-fix-20261014/private/`，未删除既有证据。

输入身份：

- 精确 rootfs：`/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`。
- C `/usr/sbin/dnsmasq` SHA-256：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
- fresh Rust：`/home/ubuntu/full-audit-20261014/private/release/dnsmasq-rs`，SHA-256 `e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`。本修复不修改 daemon ELF。
- 原脚本：`/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq/deploy/dnsmasq-trial`，SHA-256 `179eefcf190a95984109cad53d08c3de02c633672e8bf46ae65e3a50c2c7ab21`。
- FULL-TRIAL-1 修复脚本：`/dev/shm/full-trial-fix-20261014/dnsmasq-trial`，SHA-256 `dfa94d52cb132a181d78b8a0471b49868d9d3dd8bf9f79b00839edbd649f8b74`。

## FULL-TRIAL-1：恢复 owner 的生命周期

独立 fresh 重放原脚本：25 秒 deadline；用 ptrace 观察未改动的真实脚本，在两个 helper PID 文件删除后、卸载前仅杀死一次手动 rollback 进程。再等待 35 秒后，原 Rust PID 仍运行、bind 仍挂载、C 数量 0、helper 文件为空。再手动 rollback 后，精确 C 和真实 DHCP OFFER/ACK、UDP/TCP DNS 恢复。原反例证明丢失自动恢复；不把仍正常运行的候选描述为已断网。结果：`baseline-kill/result.json`。

原因：旧脚本在任何恢复操作前终止两个 owner；监护还会在 mount 消失时直接退出，无法接手卸载后被杀的恢复进程。可重复执行不等于进程中断后仍有人执行。

修复：先写 `/tmp` 回退请求，使用镜像自带 `flock` 串行恢复；deadline/watch 保持为独立 owner，恢复命令运行在另外的进程组，失败或被杀后仍会重试。watch 在 mount 消失后继续接手。只有 mount 已消失、所有 dnsmasq 进程的实际 ELF 都为精确 C、且配置的本地 DNS 探测成功，才终止 helpers。`confirm` 拒绝已经请求回退的试运行。文档撤回“幂等就不存在 R1、R5”的过强结论。

当前结果（每个成功恢复均核对 ELF 哈希和真实 DHCP、UDP/TCP DNS）：

| 用例 / 原始目录 | 检查 | 结果 |
| --- | --- | --- |
| `fix-request` | 写入回退请求后、mount 仍存在时单次 SIGKILL | 两 helper 尚存；自动恢复 C |
| `fix-confirmed-rollback-killed` | confirm 后，仅 watch 存在；卸载后、重启前单次 SIGKILL | watch 接手，自动恢复 C |
| `fix-rollback-cleanup-killed` | 与原反例相同的两个 PID 文件清除窗口单次 SIGKILL | 此时 mount 已消失、C 已通过健康检查；客户端仍正常 |
| `fix-confirm-rollback` | confirm 后持续运行，再两次 rollback | 通过 |
| `fix-deadline` | 正常到期 | 通过 |
| `fix-crash` | 候选叠加立即退出程序，procd 重启失败 | watch 恢复 C |
| `fix-hang` | 候选 SIGSTOP | watch 恢复 C |
| `fix-watch-killed` | 健康监护被杀 | deadline 恢复 C |
| `fix-partial-rollback` | 两 helper 被杀、卸载后仍运行 Rust，手动 rollback | 通过 |
| `fix-reload` | 原装 reload | 原 PID 继续运行，客户端正常，随后回退成功 |
| `fix-rollback-c-dns-loss` | 回退后 C ELF 已正确，但临时丢弃 DNS 流量直到手动尝试超时 | 尝试返回 1，回退请求与两个活 owner 均保留；恢复 DNS 后自动完成，真实 DHCP/UDP/TCP 通过 |

本次共 11 个修复后用例通过。DNS 丢包负控制只改隔离 namespace 中的防火墙，不改 C 或 init/procd。

新增故障用例位于 `tools/dnsmasq/test_trial_oracle.py`。ptrace 只观察 syscall 停点并发送一次 SIGKILL；不替换脚本、init、procd 或 ujail。原有 crash 用例有意叠加崩溃程序，其余用例使用上述 fresh Rust。

限制：确认后不再有 deadline；如果唯一 watch 本身死亡或停止调度，仍需人工回退/重启。两个独立 owner 都被杀也不在单次恢复进程中断的保证内。脚本健康门检查身份和 DNS；真实 DHCP 的恢复由本测试客户端验证，现场确认仍需客户机重连。

## 可直接重放的命令

以下全部在 Oracle build host 上执行，不能在路由器上执行。目录名必须未被使用；原始路径只读。`CASE` 可取上表对应的测试名（`fix-request` 对应 `rollback-killed`）。

```sh
BASE=/dev/shm/full-trial-fix-20261014
TOOLS=/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq
CASE=confirmed-rollback-killed
OUT="$BASE/private/acceptance-$CASE"
sudo -n env PYTHONPATH="$TOOLS" sh "$TOOLS/run_isolated.sh" \
  python3 "$TOOLS/actual_config_network.py" \
  --source-root "$BASE/private/network-source" \
  --router-cidr 192.168.1.1/24 --output "$OUT-network" -- \
  python3 "$BASE/test_trial_oracle.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust-binary /home/ubuntu/full-audit-20261014/private/release/dnsmasq-rs \
  --trial "$BASE/dnsmasq-trial" --case "$CASE" --output "$OUT"
```

原反例命令使用相同网络入口，把最后的 Python 程序换为 `/home/ubuntu/full-audit-20261014/private/trial_review.py --case rollback-killed --output "$OUT"`。该审计程序固定读取原脚本。完整已运行 argv 另保存在 `private/fix-*.command.json`；`fix-suite.json` 为七个原场景和两个额外中断场景的汇总。

## FULL-TRIAL-2：照文档上传与调用

独立 fresh 重放原文档路径：把原脚本作为文件上传到 `/tmp/dnsmasq-trial`，执行 start 后出现 `File exists`、`Not a directory`、`copied candidate hash mismatch`，退出 1。C 保持运行。证据：`baseline-path/result.json`。

修复只改文档的上传与所有调用路径为 `/tmp/dnsmasq-trial.sh`，并明确 `chmod 755`，让独立 helper 可以再次执行脚本；`/tmp/dnsmasq-trial/` 保持为运行目录。本项不再改动产品脚本，FULL-TRIAL-1 的固定脚本哈希保持不变。

`documented-path` 用例把候选和脚本实际复制到文档的 `/tmp` 路径，从 0644 脚本开始按文档 chmod/hash/start/status/confirm/rollback，start 使用文档的 `OpenWrt.lan 127.0.0.1 600` 原样参数。合成 fixture 在 `/etc/hosts` 额外提供 `OpenWrt.lan` 别名，保留真实 veth 客户端检查用的 `lifecycle.lan`。另试错误上传 hash，必须在切换前退出 1，并再次检查 C 的真实 DHCP/UDP/TCP DNS。

- 修复脚本 + 修复文档路径：`fix-documented-path-2/result.json`，通过。
- 原 `179eef…` 脚本 + 修复文档路径：`fix-path-original-script/result.json`，通过，证明路径修复独立成立。
- 首次 `fix-documented-path/result.json` 的文档命令已完成，但新测试在额外的错误 hash 负控制中把 name 参数误改为零串，断言失败；已修正为 hash 参数并完整重跑。保留该失败证据，不计为产品失败或通过用例。

复测使用前述命令，设置 `CASE=documented-path`。独立验证原脚本时将 `--trial` 换为上文原脚本绝对路径。
