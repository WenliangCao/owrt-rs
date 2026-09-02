# archive

2026-09-02 阶段审计后从执行路径移出的材料。保留是为了可追溯，不再作为任何阶段的输入或前置门。

## h1-physical-recovery

H1.2 raw NAND 备份预检、H1.3a 只读 recovery kernel patch 与 initramfs overlay、H1.3b UART RAM boot
预检及其 gate 脚本。这条链假设了拆机和 UART，而用户从未提供；决策 0006 已把设备接入固定为
Wi-Fi、Ethernet 和现有 SSH。这些工作没有执行到设备，也不代表已验证的恢复能力。

## stage-gates

每个阶段各配一份 preflight、review 和 gate 脚本，再把同一结论复写进 README、runbook、
计划和报告。这套仪式与 R05 的实际爆炸半径（tmpfs baseline、reboot 即失的 bind mount）不成比例。
保留 1066 行的执行计划 v2 与 H1 runbook 快照供查阅；当前计划见 `docs/EXECUTION_PLAN.md`。

保留在 `tools/` 的只有仍会重复运行的采集与差分脚本（`h1_4_*`、`h1_5_*`、`i0_*`、`r1_*`、
`v1_*`、`c1_*`）。

## 路径说明

`manifests/` 中已有 JSON 的 `path` 字段记录的是归档前路径，其 SHA-256 针对文件内容，不因移动
而失效。查阅时按本目录重新定位即可，manifest 本身不改写。
