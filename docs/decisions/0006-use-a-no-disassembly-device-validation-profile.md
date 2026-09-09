# 决策 0006：实体设备验证采用无拆机路径

> **现状（2026-09-09）**："不重启"部分已被 0016 撤销；此后 R23、R74–R80 的受控重启窗口均在 0016 的救援边界内执行。无拆机/无 UART 的边界仍有效。

> 日期：2026-09-01
> 状态：已定
> 阶段：H1 边界重规划

## 背景

用户明确固定了实体设备能力边界：只提供现有 OpenWrt 上的 Wi-Fi、以太网和 SSH，不拆机、
不购买或连接 USB-UART、不焊接或接触主板测试点。此前 H1 把 raw NAND 私有备份和 UART
RAM boot 串成 R05 canary 的前置链，导致一个不接管启动、网络或持久配置的组件被更深层
bootloader/NAND 恢复能力阻断。

这个顺序与已经冻结的失败边界不一致。R05 的可变状态只有可重建的 tmpfs baseline；V1 的
切换是 bind mount，不覆盖原 `/sbin/reload_config`，普通 reboot 后自动消失。UART 能证明的
是 broken kernel、UBI 或 bootloader 层恢复，而 R05 shadow/canary 不触碰这些层。

## 决策

1. H1 的实体设备访问永久限定为 Wi-Fi、以太网和现有 SSH。只要本决策有效，拆机、UART、
   主板测试点、TFTP/U-Boot、raw NAND dump 和固件写入都不属于执行路径。
2. H1.2 raw backup 与 H1.3b UART RAM boot 保留为历史研究记录，但标记为
   `not_applicable_under_no_disassembly_policy`，不再是 R05 的前置门，也不冒充已完成。
3. H1.3a 的离线 recovery candidate 保留在 Git 外作为已完成研究产物，但不传入设备、不启动，
   也不为后续阶段提供隐含授权。
4. 下一阶段只允许 H1.4 的**离线 preflight**：冻结 SSH/tmpfs shadow harness、命令、hash、
   停止条件和清理证明。当前重规划不授权连接设备、传输 binary 或执行命令。
5. H1.4 若另行授权，候选只进入 `/tmp`，只读取真实配置的脱敏/哈希派生信息；配置副本、
   baseline 副本和 fake ubus 全部位于独立 tmpfs 目录。不得调用真实 ubus 事件投递，不得
   修改真实 `/var/run/config.md5`、UCI、mount、服务或网络。
6. H1.5 disabled install 与 H1.6 短时 bind-mount canary 继续各自需要新授权和新 gate。
   H1.6 的回退只允许显式 disable，必要时使用普通 power cycle 清除 volatile mount；不把
   UART、failsafe 或刷机写成自动回退。
7. R01 procd、R03 启动编排、R08 无线、R12 ubusd 和 R17 升级/重启继续是禁止触碰项。
   缺少深层恢复能力会继续阻止任何扩大到这些职责或其他可能破坏启动/管理路径的工作。

## 后果

- 项目可以在不拆机条件下继续完成 R05 的真实设备 shadow 验证，并在后续单独决策低风险
  canary；不会把“未验证 bootloader 恢复”误写成“整个项目无法继续”。
- 项目不能宣称验证了 raw NAND、UBI、kernel 或 bootloader 恢复，也不能安全扩大到可能让
  设备无法启动或失去唯一管理路径的职责。
- 任何未来改变这一边界都必须由用户明确撤销本决策；普通“继续”不能恢复 UART/刷机路径。
