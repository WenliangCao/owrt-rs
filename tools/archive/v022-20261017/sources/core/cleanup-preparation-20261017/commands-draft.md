# Oracle 清理命令草案

仅供 root 在成功发布/部署后明确发出清理信号时使用。当前未执行；不要在现场验收过程中运行。
允许删除的只有已盘点的两个任务根与下列六个本轮临时目录。SDK、stock、Rust、主源码库、永久备份及所有 Docker 服务/数据不在命令内。

1. 先核对 `local-tool-evidence.json`（25 controller、0 独有工具缺口），确认所需最终/回滚资产的永久副本可用；已有完整归档可复用，不重复打包。用户已明确原始测试数据无须保存，root 确认发布后可一并删除 native-final raw archive；派生报告与小收据已保留。不要再复制、移动或重打包这些 raw。
2. 重新核对这两个精确根下没有使用者、没有子挂载；任务必须已结束。发现任何使用者或挂载就停止，不自动 kill/unmount。Docker完全不操作。检查时只针对白名单路径，不广扫其他服务数据。
3. 只在实际执行时记录 `df` 前后结果。以下 `du`/`df` 与删除命令尚未执行。

```sh
# Run on Oracle only, after the root's explicit post-release cleanup signal.
set -eu
unified_task=/srv/owrt-archive/unified-work
old_safe_task=/srv/owrt-archive/dnsmasq-work
[ "$(readlink -f "$unified_task")" = "$unified_task" ]
[ "$(readlink -f "$old_safe_task")" = "$old_safe_task" ]
# Before continuing, inspect active users and submounts for these exact paths.
# No automatic process termination, unmount, Docker command or global cache purge.
# Save measurements outside both task roots, e.g. stdout redirected by the local caller.
df -B1 /srv/owrt-archive/build-home /dev/shm
sudo -n du -x -s -k "$unified_task" "$old_safe_task"
sudo -n rm -rf --one-file-system -- "$unified_task" "$old_safe_task"
sudo -n rm -rf --one-file-system -- \
  /tmp/owrt-archive-v022-slot-04 \
  /tmp/owrt-archive-v022-slot-01 \
  /tmp/owrt-archive-core-slot-03 \
  /tmp/owrt-archive-v022-slot-02 \
  /tmp/owrt-archive-v022-slot-03 \
  /tmp/owrt-archive-core-slot-04
df -B1 /srv/owrt-archive/build-home /dev/shm
```

`/dev/shm` 本次检查为空，不提供任何删除命令，尤其禁止 `rm -rf /dev/shm/*`。
248 个 `fw4rs.*` 临时夹具只记录在 `tmp-classification.json` 的精确路径列表；若 root
将它们纳入退休范围，逐路径确认仍是原夹具且无使用者后处理，禁止用全 `/tmp` 通配。
25 个更早的 source/bundle/fixture 不在本次命令草案内；没有重做 refs 审计。

构建 cache 的 24 个精确路径在 `oracle-caches.json`，总量已经包含于两个任务根，
若只先清 cache 就使用该列表，不叠加宣称节省量。全局 `.cargo`、`.rustup` 保留。

本草案不承诺任何实际腾出量。最终报告以执行时同一文件系统的 df 前后值为准，
并说明并发写入、稀疏文件、硬链接或快照使其可能不同于预备 du。
