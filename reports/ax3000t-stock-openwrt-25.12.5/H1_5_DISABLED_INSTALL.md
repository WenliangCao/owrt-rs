# AX3000T stock / OpenWrt 25.12.5：H1.5 默认禁用安装

> 日期：2026-09-02
> 状态：`complete_installed_disabled`
> 设备效果：精确 APK 已持久安装；候选未启用、零 mount、零真实 ubus、零重启、零刷机

## 结论

H1.5 已通过。V1 冻结的 `owrt-reload-config-0.1.0-r1.apk` 已通过设备本地 SHA-256
复核并用 `apk --no-network` 安装到实际 Xiaomi Mi Router AX3000T。安装后 switch 输出
`disabled` 并返回约定退出码 3（`status=disabled`）；原 `/sbin/reload_config` 仍是正在生效的
实现。

这一步没有让 Rust candidate 取得任何控制权。`/proc/self/mountinfo` 中目标 mount count 为 0，
执行脚本不包含真实 ubus 调用，配置树和 `/var/run/config.md5` 的前后哈希完全一致。设备没有
重启，更没有写固件、bootloader 或 raw flash。

## 精确安装结果

| 项目 | 结果 |
|---|---|
| package | `owrt-reload-config` `0.1.0-r1` |
| arch / origin | `aarch64_cortex-a53` / `feeds/base/owrt-reload-config` |
| installed size | 348,430 bytes |
| candidate | 346,531 bytes，SHA-256 `b49b054f…15f75`，`root:root 0755` |
| switch | 1,836 bytes，SHA-256 `ce7ef658…90bdf`，`root:root 0755` |
| switch state | `disabled` / exit 3 |
| original dispatcher | SHA-256 `f1527a79…4e15`，前后不变 |
| runtime mount | 0 → 0 |
| H1.5 `/tmp` 残留 | 0 |

APK 声明的三项 installed file list 与设备完全一致：package list、switch 和 candidate binary。
binary 与 switch 的文件大小之和恰好等于 348,430-byte installed size。APK 原文件和设备原始
输出继续保存在 Git 忽略区；Git 只记录哈希、计数和脱敏结论。

## 持久变化与不变量

本阶段明确授权的 package-only 写入已经发生：installed DB、world 和 scripts archive 的哈希
按安装结果变化，overlay 可用空间在最终成功轮次从 58,692 KiB 变为 58,480 KiB。triggers
保持空文件哈希；没有额外 trigger 面。

以下运行态不变量保持精确相同：

- `/etc/config` tree：`c5710594…d44a`；
- `/var/run/config.md5`：`b77e0e99…c163`；
- `/sbin/reload_config`：`f1527a79…4e15`；
- APK triggers：`e3b0c442…b855`；
- mount count：0。

因此 H1.5 证明的是“包能在精确设备上正确安装且默认不接管”，不是“candidate 已替换生产
dispatcher”。

## 首轮 fail-closed 与方法修正

`run-01` 已完成实际安装，post-install 明确打印 disabled，但 owner/mode 检查错误假设目标
BusyBox 有 `stat` 命令，因而在 `installed-files` 断言停止。harness 自动执行 switch disable
和 offline `apk del`，runner 再执行幂等 emergency rollback；package、candidate、switch、
dispatcher 和 mount 状态均恢复。

精确复核随后发现，apk 重建 `scripts.tar.gz` 时把 333 个成员规范化为 327 个，去掉了
`urngd`、`usign` 和 `wifi-scripts` 的 6 个历史重复成员。功能状态虽然已经回退，归档字节却
没有精确恢复。我们没有掩盖这一点，也没有把 package absent 当成完整回滚。

设备不可变 `/rom` 中的原归档匹配冻结 SHA-256 `4a5fd6b5…45bfc`。它被复制到同目录固定临时
路径、验证哈希后原子替换；`run-02` 的安装前 identity gate 再次观察到该精确哈希。随后执行
工具被加固：owner/mode 使用实测可用的 `ls -ldn`；harness 和 runner 的失败路径都会恢复并
复核 scripts archive 及全部冻结状态。preflight 的九类负向篡改以及最终 review 的十一类负向
篡改全部被 gate 拒绝。

## Gate 与下一步

`h1_5_disabled_install=true`。artifact、设备身份、installed files、default-disabled、配置、
baseline、dispatcher、triggers、mount、清理和失败恢复 gate 均通过。

`h1_6_canary=false` 仍然成立，原因有两个：

1. H1.5 授权不继承到 activation；
2. H1.4 已观察到真实 baseline 中存在 `network` drift。现在启用 candidate 后第一次真实执行
   可能投递 `network config.change`，不能把它当成“零变化 canary”。

在解决 drift 的测试设计并取得新的明确授权之前，不执行 enable、bind mount 或真实 ubus。

## 证据

- [H1.5 observations](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-5-observations.json)
- [H1.5 preflight](../../archive/stage-gates/H1_5_PREFLIGHT.md)（已归档）
- [H1.4 device shadow](H1_4_SHADOW.md)
- [H1 runbook](../../archive/stage-gates/H1_RUNBOOK_2026-09-02.md)（已归档）
- [device harness](../../tools/h1_5_disabled_install_device.sh)
- [SSH runner](../../tools/h1_5_run.py)
