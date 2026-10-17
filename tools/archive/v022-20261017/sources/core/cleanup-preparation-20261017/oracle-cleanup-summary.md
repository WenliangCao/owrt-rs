# Oracle 清理准备（只读，尚未授权删除）

统一实验目录 4.843 GiB；旧 safe 目录 6.564 GiB。这是 `du` 分配量，不是预计腾出空间。未取 df、未删除。

| 范围 | 已观察占用 | 发布后处置草案 |
| --- | ---: | --- |
| `/srv/owrt-archive/unified-work` | 5,078,336 KiB | root 发成功发布后的退休信号后，核必要永久副本及无进程/挂载，再整树清理 |
| `/srv/owrt-archive/dnsmasq-work` | 6,882,432 KiB | root 发成功发布后的退休信号后，核必要永久副本及无进程/挂载，再整树清理 |
| 两树内 24 个 Cargo/SDK 构建目录 | 4,503,060 KiB | 已含在上两行；可生成缓存，不重复计数 |
| 6 个本轮 `/tmp` startup/profile 目录 | 42,772 KiB | 精确路径列在 JSON；完成归档/退役后清理 |
| 248 个 `fw4rs.*` fixture | 6,816 KiB | 只用已盘点路径，执行前确认无使用者；不写通配删除 |
| 25 个更早 `/tmp` 源码/bundle/夹具 | 261,120 KiB | 本次不纳入删除草案，避免扩大任务与重复 refs 审计 |
| `/dev/shm` | 空 | 不生成删除命令；不删除以后出现的文件 |

保留：精确 stock 镜像/rootfs、SDK/ImageBuilder、Rust toolchain/Cargo registry、原厂源与既有证据基座、永久备份和主源库。对应路径在 JSON 的 `protected_roots`。全局 `.cargo` 不按本轮 build cache 处理。

**Docker 完全排除**：不运行 docker 命令，不查询/停/删容器、服务、镜像、volume、网络，不删除任何 Docker bind 数据；不执行 system prune。

本轮最终镜像与回滚镜像在实验树中的重复副本，只有确认永久本地/正式发布资产仍保留后才随实验树退休。旧失败目录继续保留到同一退休信号；不再为可生成的路径适配脚本堆新归档。工具与报告核对见 `local-tool-evidence.json/.md`。

已经存在的完整 raw/profile/CI archives 可复用，本次只列路径/大小，不回传或新建大归档。命令草案在 `commands-draft.md`，实际执行时才取 df 前后值。

工具核对完成：25 个 controller 全有本地精确副本、Git/历史 Git 或既有归档/固定源重建依据，独有缺口 0。无需新增工具归档。

root 后续明确：用户允许发布后删除全部原始测试数据，包含现有 native-final raw archive；派生报告与小收据已保留，无须 bulk 镜像或移出任务根。删除仍等待 root 最终 Latest 信号。
