# AX3000T stock / OpenWrt 25.12.5：H1.4 真实设备 tmpfs shadow

> 日期：2026-09-01
> 状态：`complete_passed_with_live_baseline_drift`
> 设备效果：只通过现有 SSH 在 `/tmp` 传输和执行；零持久写入、零真实 ubus、零 mount、零重启

## 结论

这一步有真实意义：V1 的同一 346,531-byte candidate 已在实际 Xiaomi Mi Router AX3000T 的
CPU、musl loader、BusyBox、UCI、真实配置文件集合和真实 baseline 上运行。H1.4 四步 shadow
合同全部通过，临时文件被删除，原 dispatcher、配置树、baseline、package database 和 mount
状态前后完全一致。

同时发现一个不能掩盖的现场事实：当前 `/var/run/config.md5` 与当前 `network` 的规范化结果
不一致。candidate 在共享 baseline 副本上准确地产生一个 fake `network` event；只在 shadow
中推进 baseline 后，下一次运行稳定为零事件。这不是 candidate 的不兼容，而是当前设备已有
的 baseline drift。真实 baseline 没有被“顺手修复”。

## 四步结果

| 步骤 | compared/new | changed | fake ubus | 结果 |
|---|---:|---|---:|---|
| 共享 baseline drift | 19/19 | `network` | 1 | 通过，shadow baseline 前进 |
| 吸收后稳态 | 19/19 | 无 | 0 | 通过，baseline 字节等价 |
| 新建 synthetic package | 19/20 | 无 | 0 | 通过，保留 creation-silent |
| 修改 synthetic package | 20/20 | `h1_shadow_probe` | 1 | 通过，恰好一次 |

每轮七个含点备份文件都继续产生 `uci show` exit 1/空规范化条目，证明 C1 中冻结的 dotted-name
行为在真实设备上没有被“修复”或扩大触发面。

## 实机不变量

成功 run 前后同时满足：

- board/release/revision/target/kernel 精确为
  `xiaomi,mi-router-ax3000t`、25.12.5、`r33051-f5dae5ece4`、
  `mediatek/filogic`、6.12.94；
- 原 `/sbin/reload_config` SHA-256 仍为
  `f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15`；
- 实机 baseline SHA-256 仍为
  `b77e0e99672ee504d1ee1183f14b8ba8cfe92f6c546aa585f7efc784d2b0c163`；
- `/etc/config` tree、`/lib/apk/db/installed` 和不存在的 `/var/run/uci` 状态不变；
- `/sbin/reload_config` mount count 始终为 0；candidate 和 switch 没有安装；
- 所有 stderr 为空，harness cleanup 与 runner post-cleanup 都通过。

配置内容没有离开路由器；私有 evidence 只保存身份行、hash、package 名称、计数和 candidate
JSONL trace。Git 中不包含 candidate binary 或原始 run 输出。

## 失败闭环与自我纠正

最终通过前有五次 fail-closed 尝试，每次都完成清理和事后身份验证：

1. 新版 OpenSSH 默认 SFTP，但 OpenWrt 不提供 `sftp-server`；改用设备已有的 legacy
   `/usr/bin/scp`，即本机 `scp -O`，没有安装新服务。
2. harness 只有退出码，无法定位断言；增加预枚举、无内容的 `failed_step`。
3. 粗标签把失败定位到第一组 run，但粒度仍不足；继续拆成执行/事件/trace/baseline 子断言。
4. 证明 candidate 已执行，失败是“共享 baseline 必须零事件”的假设。
5. 只输出 package 名称和 trace，确认唯一 drift 是 `network`；最终将 drift 观察与稳态验证拆开。

关键点是没有为了让 gate 变绿而忽略 `network`，也没有调用真实 dispatcher 来改变 baseline。
最后一次组合 precheck 又暴露了 shell 未启用 fail-fast：preflight 报告 marker 失败后 provisional
commit 仍被执行。该 marker 已恢复，全部 gate 在 `set -e` 下重跑后 amend 同一阶段 commit；
没有把后续 review gate 的成功冒充前一个 gate 的成功。

## Gate 与后续边界

`h1_4_device_run=true`，candidate hardware/ABI、shadow 合同、cleanup 和不变量 gate 全部通过。
但 `h1_6_canary_ready=false`：如果现在让 candidate 对真实 baseline 调用真实 ubus，它会投递
`network` event。如何对齐该 baseline 必须另行决定并明确授权，不能在本阶段偷偷做。

review gate 从六次私有 run 的固定 hash 重新推导公开结论。八类负向篡改全部拒绝：伪造真实
ubus、持久写入、H1.5/H1.6 gate、新建事件、cleanup、下一阶段授权和 live baseline hash。

下一步 H1.5 是安装默认 disabled 的 APK。它不取得控制权，但会写 overlay 和 package database，
因此本轮 tmpfs-only 授权不能继承；当前仍为 `not_authorized`。即使以后 H1.5 通过，H1.6 仍须
先关闭 `network` drift 的真实事件风险。

## 证据

- [H1.4 observations](../../manifests/ax3000t-stock-openwrt-25.12.5/h1-4-observations.json)
- [H1.4 preflight](../../archive/stage-gates/H1_4_PREFLIGHT.md)（已归档）
- [H1 runbook](../../archive/stage-gates/H1_RUNBOOK_2026-09-02.md)（已归档）
- [compatibility contract](../../docs/contracts/config-change-dispatch.md)
