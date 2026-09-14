# R92 发布身份、设备保留包与回退

运行时发布提交固定为 `ca1a9121df0380448a19d474e29796066b6734e8`，
[release-image 34874442503](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/34874442503)。
后续测试工具、注释和报告提交不改变已部署的二进制身份。九组件、七个 APK、core archive、
生成镜像及两层 manifest 的 SHA 链见
[canonical_build.json](../reports/ax3000t-stock-openwrt-25.12.5/R92_parts/canonical_build.json)。
生成镜像只校验产物，本轮没有刷写固件。

R92 已在 2026-09-14 23:27:33 UTC 完成最终设备核验，overlay 可用 28936 KiB。
R89/R90/R92 各 29 个文件与 7 个 APK 已逐项验证，六个诊断文件已清理。

## 保留策略

| 内容 | 设备位置 | 用途和保留条件 |
|---|---|---|
| 精确 C 原件 | `/rom`，核心组件另有 `.c-orig` | 自动回退、failsafe、原版对照；始终保留 |
| 正式 R89 | `/root/r89-before-r90` | 本轮固定性能基线；保留到新的基线明确被接受 |
| 已接受 R90 | `/root/r90-before-r92` | 上一完整验收版本，包含旧 APK；保留到后续版本完成同等验收 |
| 当前 R92 | `/root/r84` | 活动包、身份清单、启动切换与原版回退工具；保留 |
| 更旧三包 | 已离线归档 | `r84-prior-r86`、`r84-prior-r87`、`r84-prior-r89` 在完整读回和逐文件 hash 核验后删除 |
| 本轮诊断工具 | `/root/r92-diagnostics` | 所有测量完成、逐文件身份核验后删除；本机 private 保留 |

原始归档、配置、overlay、恢复镜像和二进制仅在 ignored `private/r92/` 保存。
Git 保存的只是工具、合同、无秘密的身份摘要及派生报告。
最终保留包文件数、APK 数、空闲存储和清理证明见
[deployment.json](../reports/ax3000t-stock-openwrt-25.12.5/R92_parts/deployment.json)。
不以删除 C/R89/R90 来改善本轮内存测量或存储成绩。

## 回到 C

使用本包的 `stack-switch.sh stage stock` 后冷启动；整套切换不热重启 ubusd。
下一次 Rust 部署由 `stage rust` 安装 900 秒未确认回退；客户端健康、候选身份与新 boot
满足门后才 `confirm`。计时器只在到达 init 时运行，更早的 PID 1 启动失败依靠已校验的
离线恢复资料；见 [恢复手册](RUNBOOK_AX3000T_RECOVERY.md)。

脚本没有 `status` 子命令。状态使用 `verify rust`/`verify stock`，并检查
`/etc/r84-pending`、`/etc/r84-reverting`、`/etc/p6-pending`、`/etc/p6-reverting`、
`/etc/init.d/r84-canary`、`/etc/rc.d/S99r84-canary` 是否已清除；`/etc/r84-confirmed` 可保留。

## 回到 R90

**仅交换 bundle 目录不够。** 本次 APK 包版本号与旧版相同，`installed.sha256` 对实际
`/usr/sbin` Rust 文件校验；必须先重新安装 R90 保存的七个 APK，才能 stage/confirm R90。

后续回退窗口按以下顺序执行：

1. 核对离线备份、R90/R92 产物、客户端健康、空间和当前过渡标志，保留当前 R92 包。
2. 逐文件校验 R90 `apk.sha256`，再以
   `apk --no-scripts --no-network add --allow-untrusted --force-reinstall /root/r90-before-r92/apk/*.apk`
   安装旧 APK；核验其 `installed.sha256`。安装阶段旧进程和已生效 CLI bind mounts 可继续保留
   当前身份；不要提前把它们的旧进程身份当作安装失败。
3. 把已校验的 R90 包放到 `/root/r84`，另存当前 R92 包；目录移动须防止覆盖或嵌套已有目录，
   第二步移动失败须恢复原布局。不要直接对另一个目录调用 stage 并留下错误的 `/root/r84`。
4. 使用同样的冷启动窗口、900 秒 C 回退、≥180 秒连续客户端健康和最终 30 秒观察，
   核对新进程的 R90 身份后再确认。

上述升级/恢复机制在独立镜像中通过 `offline-switch` 5/5、`offline-apk-upgrade` 4/4；
本轮实际部署是 R90→R92。R92 的最终验收不意味着为了报告再执行一次 R92→R90 的物理回退。
