# R2 + TCP + trial 共同候选（2026-10-14）

共同源快照为 `397cecb67f3ff71ad352de80220834a6a5e78103`，分支 `fix/dnsmasq-full-integrated-20261014`，worktree `/Users/USER/Developer/owrt-dnsmasq-full-integrated`。所有独立任务分支保留，未合并 main、未 push、未操作物理路由器。

| 原独立提交 | 集成后的提交 | 内容 |
| --- | --- | --- |
| `68f96cf3` | 原样保留 | 资源不足时释放未完成 hosts 代，再记录诊断 |
| `98bc6b58` | 原样保留 | hosts 重载失败仍清理转发缓存 |
| `936514cd` | `7b8942bc` | 共享 TCP hosts/config 快照 |
| `22fe5dd9` | `7ddb5439` | TCP 快照保留默认 hosts 来源 |
| `18d83527` | `592fe269` | C 健康前保留 trial 恢复 owner |
| `fd62cf85` | `397cecb6` | 上传脚本路径与运行目录分离 |

唯一文本冲突在 `hosts.rs` 的 non-terminal 祖先分配逻辑。保留 TCP 的 `records`/`rotations` 共享结构，将 R2 的失败传播放在 `records.non_terminals` 的 `try_copy`/`try_reserve` 分支：两种失败均设置 `allocation_failed` 出参。`ReadStats` 失败标记、`try_insert` 的 Result 与出参、parser 提前终止、释放未完成代和失败时清缓存均保留。TCP 作者额外只读逐段核对了两个版本到组合版本的差异，未发现共享结构或失败传播丢失。

## 共同制品

- Oracle source：`/dev/shm/full-integrated-fix-20261014/private/source`。
- 独立构建 target：`/dev/shm/full-integrated-fix-20261014/target`。
- release ELF：`/dev/shm/full-integrated-fix-20261014/private/release/dnsmasq-rs`。
- ELF SHA-256：`e2b075617d39cafa7d9443abfabbd18f9d2602dc0b535eed6393ac62ee9bbf77`，2,085,344 bytes。
- trial script：上述 source 下 `tools/dnsmasq/deploy/dnsmasq-trial`，SHA-256 `dfa94d52cb132a181d78b8a0471b49868d9d3dd8bf9f79b00839edbd649f8b74`。
- 对照 C：精确 OpenWrt 25.12.5 rootfs `/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`，SHA-256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。

所有下述原始目录均在 `/dev/shm/full-integrated-fix-20261014/private/`。构建参数、日志和哈希保存在 `release/build.json`；源提交在 `source-commit`。debug 测试制品独立保存在 `tests/`，不作为交付 daemon。

## 共同 ELF 的 TCP 验证

| 用例 | 结果 |
| --- | --- |
| `tcp64`：50k hosts、cache=1000、20 条查询后保留的正常 TCP，cgroup 64 MiB | C/Rust 均 20 条成功、UDP 仍健康、无 OOM/kill；Rust 最终 23,605,248 bytes |
| `tcp64-hup-2`：相同预算与连接，再 HUP，保留旧连接并新建连接 | C/Rust 均通过；旧 TCP 返回旧代，新 TCP 返回新代；Rust peak 46,776,320 bytes，无 OOM/kill |
| `tcp-memory`：0/10k/50k hosts，0/1/10/20 条 TCP | 全部正常；50k 时 Rust PSS 从 24,124 增至 24,592 KiB，增量 468 KiB；C 从 6,152 增至 8,535 KiB |
| `tcp-snapshot` | HUP 旧/新连接、inotify、IPv4/IPv6、轮转与配置等 42 个观察值全部与精确 C 一致 |

TCP 原反例和独立修复证据仍由独立 TCP 分支保存；这里验证同一共同 ELF，未用独立 TCP ELF 代替。

首次 `tcp64-hup` 在启动 daemon 前因验收工具使用 namespace PID 1 构造固定 cgroup 名，与前一用例的空目录碰撞而失败。随后采用 TCP 审计工具的随机唯一 cgroup 目录版本，保持 64 MiB 和 workload 不变，完整通过；原失败日志保留。TCP 脚本、每次 argv 和汇总位于 `tools/`、`tcp-*.command.json`、`tcp-suite-final.json`。

## 单元测试

同一源快照构建的 lib 测试 787 通过、20 ignored。bin 测试需要网络隔离；首次普通执行有两个隔离环境断言失败。进入 `run_isolated.sh` 后，先前全局 `/tmp` 中的 PID 1 FIFO 又导致一个夹具冲突。最终在该隔离 mount namespace 内单独挂载 tmpfs `/tmp` 后重跑，不删除既有 FIFO 或证据。最终 bin 78 通过、3 ignored，结果见 `unit-bin-private-tmp.log`；命令使用 `tools/private-tmp.sh` 包装测试制品。上述环境失败不能作为产品通过证据，也不将其归为 daemon 缺陷。

## 重放 TCP 门

以下只在 Oracle build host 上执行，OUT 必须为新路径。

```sh
BASE=/dev/shm/full-integrated-fix-20261014/private
TOOLS="$BASE/source/tools/dnsmasq"
OUT="$BASE/acceptance-tcp64-hup"
sudo -n env PYTHONPATH="$TOOLS" sh "$TOOLS/run_isolated.sh" \
  python3 "$BASE/tools/full_tcp_hosts_cgroup.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust "$BASE/release/dnsmasq-rs" --output "$OUT" --budget-mib 64 --hup
```

内存矩阵将脚本替换为 `full_tcp_hosts_memory.py`、末尾选项替换为 `--rows 0,10000,50000`；42 项语义将脚本替换为 `full_tcp_hosts_snapshot.py` 并移除末尾预算/HUP选项。

## 共同 ELF 与脚本的 trial 验证

`trial-suite.json` 的 12 个用例全部通过，每个结果都记录共同 ELF `e2b07561…`、脚本 `dfa94d52…` 与精确 C 身份：

- 原有 confirm-rollback、deadline、crash、hang、watch-killed、partial-rollback、reload。
- 写入请求后、confirm 后卸载完成但重启前、两个 helper PID 文件清除后三个单次 SIGKILL 窗口。
- C ELF 已正确但 DNS 不响应直到尝试超时的负控制：恢复 owner 保留，DNS 恢复后自动完成。
- `/tmp/dnsmasq-trial.sh` 文档路径的 chmod/hash/start/status/confirm/rollback 与错误上传 hash 边界。

各恢复均通过真实 veth DHCP OFFER/ACK 和 UDP/TCP DNS，未以命令返回值替代客户机健康。每个用例原始结果位于 `trial-<case>/result.json`，确切 argv 位于 `trial-<case>.command.json`。启动脚本 `run_trial_suite.py` 与网络源夹具保留在同一 private 目录。单独复测可用：

```sh
CASE=confirmed-rollback-killed
OUT="$BASE/acceptance-trial-$CASE"
sudo -n env PYTHONPATH="$TOOLS" sh "$TOOLS/run_isolated.sh" \
  python3 "$TOOLS/actual_config_network.py" \
  --source-root "$BASE/trial-network-source" \
  --router-cidr 192.168.1.1/24 --output "$OUT-network" -- \
  python3 "$TOOLS/test_trial_oracle.py" \
  --image-root /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
  --rust-binary "$BASE/release/dnsmasq-rs" \
  --trial "$TOOLS/deploy/dnsmasq-trial" --case "$CASE" --output "$OUT"
```

R2 的共同 ELF 完整资源矩阵、shared DHCP、held TCP/cache expiry 由主修复对话独立执行并另行回交；本报告不将独立 R2 ELF 结果当作共同候选已通过。共同制品、构建日志、TCP/trial 原始结果与测试工具另外备份到本 worktree 的 Git 忽略路径 `private/full-integrated-fix-20261014/evidence.tar.gz`，避免仅依赖 Oracle tmpfs。
