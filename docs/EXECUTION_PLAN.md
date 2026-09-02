# Rust-native OpenWrt Control Plane：执行计划

> 版本：3.0（2026-09-02 阶段审计后重写；v2 全文见 [archive/stage-gates/EXECUTION_PLAN_v2_2026-09-02.md](../archive/stage-gates/EXECUTION_PLAN_v2_2026-09-02.md)）
> 状态：R05 候选已在实机 shadow 通过并以 disabled 安装；H1.6 canary 等待 drift 收口与授权

## 1. 目标与边界

目标不变：以真实镜像、匹配源码和脱敏运行态为依据，逐个职责决定保留、包装或用 Rust 重写。
不重写 kernel、驱动、nftables、hostapd、dnsmasq/odhcpd。

设备边界由 [决策 0006](decisions/0006-use-a-no-disassembly-device-validation-profile.md) 固定：
只有 Wi-Fi、Ethernet 和现有 SSH。拆机、UART、TFTP/U-Boot、raw NAND、刷机不在执行路径上，
普通"继续"不能恢复它们。

每一步按**实际爆炸半径**决定要多少验证，不按阶段编号套同一套仪式。R05 的可变状态只有
可重建的 tmpfs baseline，切换是 reboot 即失的 bind mount，因此它的门槛是"能观察、能 disable"，
不是"能恢复 bootloader"。

## 2. 已完成

| 阶段 | 结论 | 记录 |
|---|---|---|
| I0 | 17 项职责分类完成；唯一完整替换候选 R05 `/sbin/reload_config` | [I0_FINAL_REPORT](../reports/ax3000t-stock-openwrt-25.12.5/I0_FINAL_REPORT.md) |
| C1 | 合同 C1-01 冻结，11 个参考用例 | [config-change-dispatch](contracts/config-change-dispatch.md) |
| R1 | Rust 候选 11/11 合同、6/6 故障与原实现一致 | [R1_IMPLEMENTATION](../reports/ax3000t-stock-openwrt-25.12.5/R1_IMPLEMENTATION.md) |
| V1 | 官方 SDK package，默认 disabled，bind mount 切换 | [V1_VALIDATION](../reports/ax3000t-stock-openwrt-25.12.5/V1_VALIDATION.md) |
| H1.4 | 实机 `/tmp` shadow 通过，发现 baseline `network` drift | [H1_4_SHADOW](../reports/ax3000t-stock-openwrt-25.12.5/H1_4_SHADOW.md) |
| H1.5 | 精确 APK 已安装，switch 保持 disabled，原实现不变 | [H1_5_DISABLED_INSTALL](../reports/ax3000t-stock-openwrt-25.12.5/H1_5_DISABLED_INSTALL.md) |
| drift 探针 | drift 只有一项：`network.globals.packet_steering`，2026-09-01 22:00 CEST 经 rpcd/LuCI 路径写入 | [H1_6_DRIFT_PROBE](../reports/ax3000t-stock-openwrt-25.12.5/H1_6_DRIFT_PROBE.md) |

## 3. 2026-09-02 审计：哪些工作偏离了原意

1. **H1.2 / H1.3a / H1.3b 物理恢复链**（raw NAND 备份、只读 NMBM kernel patch、recovery
   initramfs、UART RAM boot）。它假设了用户从未提供的拆机和 UART，并把 bootloader 层恢复
   当成 tmpfs 级组件的前置。未执行到设备，已移入 `archive/h1-physical-recovery/`。
2. **每阶段一套 preflight / review / gate 脚本，以及 README、runbook、计划、报告四处复写
   同一状态**。验证成本与爆炸半径不成比例，且 gate 脚本本身成了需要维护的代码。已移入
   `archive/stage-gates/`；`tools/` 只保留会重复运行的采集与差分脚本。
3. **1066 行的计划 v2**。已归档，本文件取代。

保留且有效：I0 证据链、C1 合同、R1 候选、V1 package、H1.4 shadow、H1.5 安装。

## 4. 下一步

1. **收口 drift**（需用户授权，一条 SSH 命令）：在设备上执行一次**原始** `/sbin/reload_config`。
   这是 OpenWrt 的常规操作，预期恰好投递一个 `network` config.change，procd 据此 reload
   `network`（netifd 已加载同一配置，差分为空）和 `packet_steering`（幂等重写 rps_cpus）。
   之后 baseline 与当前配置一致。不用 reboot 重建 baseline，爆炸半径更大且没有必要。
2. **H1.6 canary**（需单独授权）：`owrt-reload-config-switch enable` → 手动调用
   `/sbin/reload_config` 数次确认稳态零事件 → 修改一个无 trigger 的 synthetic package 确认恰好
   一次事件 → `disable` → 复核原实现、mount count 0、baseline 未损坏。整个窗口内 SSH 保持
   在线；异常时 `disable`，最坏情况 power cycle 清除 volatile mount。
3. **N1**：H1.6 通过后，再按 [REPLACEMENT_BOUNDARY](../reports/ax3000t-stock-openwrt-25.12.5/REPLACEMENT_BOUNDARY.md)
   选下一个职责（候选是 R13 rpcd、R15 logd 的包装）。在此之前不创建新 crate。

## 5. 仍未授权

任何非只读 SSH 命令、原始 `reload_config` 的手动调用、switch enable、bind mount、真实 ubus
事件、APK 安装/卸载、reboot、固件写入。R01/R03/R08/R12/R17 继续禁止触碰。
