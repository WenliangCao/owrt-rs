# AX3000T stock / OpenWrt 25.12.5：H1.0 准入报告

> H1.0 状态：通过
> 物理设备状态：未准入
> 日期：2026-09-01
> 历史快照：当前进度已完成 H1.3a 离线 recovery candidate；H1.3b 未授权，见 `H1_3A_RECOVERY_DESIGN.md`

## 1. 判定

H1.0 的离线准备已完成：exact image、stock/ubootmod 边界、V1 artifact、分阶段授权、只读
命令、私有证据边界、停止/回退条件和恢复层级已经固定并由机器 gate 互相校验。

这个“通过”只表示计划可以进入下一次授权审查。以下 gate 全部仍是 false：H1.1a 设备只读、
H1.1b boot environment 读取、私有备份、reboot/failsafe 演练、tmpfs shadow、APK 安装、
bind-mount canary、任何 device write 和 firmware flash。本阶段没有连接或修改路由器。

## 2. 新增控制

| 控制 | 结果 |
|---|---|
| exact image / V1 identity | 固定并由输入 manifest hash 约束 |
| stock layout | 明确排除 `ubootmod` `.itb` 和 U-Boot conversion |
| 只读观察 | 12 条命令冻结为 H1.1a/H1.1b 两批；批准数为 0 |
| boot environment | 只允许八个 fixed-source 变量；必须先闭合 `fw_env.config`/MTD/source |
| 私有数据 | raw output、MTD dump、配置、MAC/校准/密钥全部仓库外 |
| 备份工具 | 原 image 缺少 `nanddump`；matching signed feed 已离线提取单一 binary，未传设备 |
| 恢复 | reboot/failsafe、UART/initramfs、raw restore 分层，不互相冒充 |
| 首次 canary | WAN 断开、独立有线管理、五分钟、零配置变化/零 event、结束必回退 |
| firmware | H1 永久禁止 flash、sysupgrade、MTD/UBI write 和 `.itb` |

## 3. 为什么现在不能安装

旧 RUN 证据只证明 2026-08-31 当时的 release/board/rootfs，不包含真实 `/proc/mtd`、NAND/
switch 变体、UBI volume、overlay headroom、boot branch 或恢复演练。V1 则只在服务器的一次性
rootfs 和 mount namespace 中完成，没有覆盖硬件、driver、bootloader 或现场管理路径。

因此直接安装会跳过四个尚未证明的边界：设备仍是同一身份、stock 存储仍与 source 相符、
备份能对应本机、candidate 失败时操作者能从独立路径恢复。APK 本身默认禁用并不消除这些
现场前提。

## 4. 当前开放项

H1.0 的机器 manifest 保留 13 个 pending prerequisite：

- H1.1a：新鲜运行身份、MTD/NMBM、overlay headroom；
- H1.1b：boot environment branch；
- H1.2：known-good artifacts 离线副本、本机私有备份、第二份 hash 一致的副本；
- H1.3：独立有线管理、power-cycle、failsafe；
- H1.4：tmpfs shadow；
- H1.5：默认禁用安装；
- H1.6：现场 canary window。

这些 item 只能由对应阶段的新证据关闭，不能手工把 status 改成 `verified`。

## 5. Gate 验证

正向运行输出：`h1_0_gate_passed=true`、`physical_device_admitted=false`、
`approved_device_commands=0`、`open_prerequisites=13`。

负向测试全部被拒绝：

- 把 H1.1a 从 `not_authorized` 伪造成 `approved`；
- 把 V1 gate 改为 false，同时协调更新 readiness 中的输入 hash；
- 向只读命令加入 `reboot`，同时协调更新 readiness 中的输入 hash。
- 把 backup tool 改成已传入设备，同时协调更新 readiness 中的输入 hash。

最后两项证明 gate 不只依赖文件 hash；它还重新检查 V1 语义和十二条逐命令固定 hash。

另一个方法纠正：对直接下载的 `nand-utils` APK 运行 standalone `apk verify` 得到
`UNTRUSTED signature`；这不能直接解释成官方 package 不可信，因为 APK v3 的信任链绑定在
签名 repository index。随后改用 exact image key 验证 `packages.adb`，再让 matching SDK 的
apk-tools 从该 repository 安装到 disposable usermode root，且没有使用 `allow-untrusted`。
提取的 `nanddump` hash 同 APK file entry 一致。机器记录见
[h1-backup-tool.json](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-backup-tool.json)。

## 6. 下一步

H1.0 当时的下一步是 **H1.1a**，只执行十一个 identity/storage/tool metadata 命令（H1.1b
的第十二条 `fw_printenv` 不执行）。该阶段现已另行授权并完成；本报告保留 H1.0 结算时的
gate 状态，当前结论见 `H1_1A_OBSERVATIONS.md`。

H1.1a 不上传 APK、不读 raw MTD payload、不重启、不安装工具、不 mount，也不刷 firmware。

## 7. 证据

- [H1 runbook](../../docs/H1_RUNBOOK.md)
- [H1 只读计划](../../docs/H1_READ_ONLY_PLAN.md)
- [只读命令 manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-read-only-commands.json)
- [H1 readiness manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-readiness.json)
- [H1 backup-tool manifest](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-backup-tool.json)
- [H1 gate](../../tools/h1_readiness_gate.py)

官方恢复资料仅作为 REF：AX3000T 设备页描述 stock bootloader TFTP、UART/initramfs 和
device-specific backup；failsafe 文档明确其用途是配置/overlay 恢复，不能修复 broken
kernel。runbook 不把这些 REF 冒充本机已演练的 RUN 证据。
