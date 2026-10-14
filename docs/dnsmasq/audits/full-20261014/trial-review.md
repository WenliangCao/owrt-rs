# 当前 trial 机制独立审计

冻结 `main=e9d89b17d72a58b723cce88038ceaa1be58d7f8c`。2026-10-14，全部实验在 Oracle 独立 network/mount/PID namespace、精确镜像 C 用户空间和真实 veth DHCP/DNS 客户端执行，未在物理路由器注入故障。产品、trial、init、procd、ujail 均未修改。

## T1：取消全部恢复者后再恢复 C，单次进程退出会留下无人接管的 Rust（P1，恢复门阻断）

`tools/dnsmasq/deploy/dnsmasq-trial:62–71` 先 `stop_helpers`（取消 deadline/watch），再卸 mount，再 restart C。`TRIAL_RUNBOOK.md` 将“再执行一次 rollback 能恢复”扩大成了“回退中断问题不存在”。

**新实测：** 正常启动 fresh main Rust，设置 25 秒未确认期限，先通过真实客户端 DHCP OFFER/ACK 和 UDP/TCP DNS。执行正常手动 rollback；ptrace 只观察真实 shell 系统调用，在两个 helper PID 文件已删除、尚未卸载的窗口，向 rollback 进程注入一次 SIGKILL。等待 35 秒（已超过原期限）：原 Rust PID 仍在、bind mount 仍在、C 实例为零、helper PID 文件为零。再人工执行一次 rollback 后，真实 C ELF 恢复，DHCP/UDP/TCP 全通过。[派生证据](trial-kill.json)、[复现工具](trial_review.py)。

本用例没有停止或破坏 Rust，因此**没有实测断网**；直接证实的是未确认期限与自动恢复保证失效。若同窗口发生于故障触发的回退，已无自动恢复者，这是代码路径推断。P1 针对恢复门的重要性与后果，不表示进程在家庭环境一定被杀或已测得发生率。当前脚本仍能正常完成许多未受中断的回退；幂等和可靠自动接续是两个不同性质。

修复要求：恢复 C 并核对协议健康前，保留独立的恢复责任者；对卸载前、卸载后、停止 Rust 后、启动 C 前后的中断做精确故障测试。不要只把文案改弱或无限加监护进程。已交独立修复会话 `43a9d004`，本审计分支不改脚本。

## T2：照当前 runbook 上传的脚本路径与运行目录相撞（P2）

`TRIAL_RUNBOOK.md` 步骤 2/3 指定脚本 `/tmp/dnsmasq-trial`，脚本第 18 行却把 `DIR` 固定为同一路径。按文档原样放置脚本后运行 `sh /tmp/dnsmasq-trial start ...`，fresh Oracle 实测退出 1：

```text
mkdir: can't create directory '/tmp/dnsmasq-trial': File exists
cp: can't stat '/tmp/dnsmasq-trial/dnsmasq': Not a directory
dnsmasq-trial: copied candidate hash mismatch
```

C 持续运行，不会把这个启动拒绝写成断网。实际影响是公开步骤不能执行，且最后错误误导为 ELF 损坏。原 `test_trial_oracle.py` 把脚本安装在 `/usr/sbin/dnsmasq-trial`，因此没有覆盖文档给用户的路径。[派生证据](trial-path.json)。修复要求：规范脚本/状态目录的不同路径，加入照文档执行的验收。

## 身份及重放

- fresh main ELF：`e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`（SDK linker Cargo release，尚未经 APK 封装）。
- C ELF：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
- 当前 trial：`179eefcf190a95984109cad53d08c3de02c633672e8bf46ae65e3a50c2c7ab21`。
- Oracle 根：`/home/ubuntu/full-audit-20261014/private`。复现工具固定使用本轮冻结源码、release 和保留的精确 rootfs，不自动挑选“最新”二进制。

```sh
BASE=/home/ubuntu/full-audit-20261014/private
sudo -n sh "$BASE/source/tools/dnsmasq/run_isolated.sh" \
  python3 "$BASE/source/tools/dnsmasq/actual_config_network.py" \
  --source-root /home/ubuntu/dnsmasq-trial-20261014/private/pgkill/network-source \
  --router-cidr 192.168.1.1/24 --output "$BASE/FRESH-network" -- \
  python3 "$BASE/trial_review.py" --case rollback-killed --output "$BASE/FRESH"
```

换为 `--case documented-path` 重放 T2；每次用新的输出目录。`passed=true` 表示测试和清理完成，**不表示产品缺陷通过**；判断取决于明确的 `rc` / `after_deadline` 字段。结束时 fixture 执行手动恢复/进程清理，最外层 namespace 退出后没有主机或路由器挂载残留。
