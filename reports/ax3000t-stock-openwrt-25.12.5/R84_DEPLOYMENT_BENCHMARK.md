# R84：最新 Rust 发布与原版 OpenWrt 对照基准

2026-09-10。**发布包、回退工具和基准工具已准备并通过离线验证；实体路由器尚未部署，
实机性能对比尚未测量。** 当前等待恢复连接就绪。下文的验证次数来自构建机，不作为路由器性能结论。

## 已推送与构建

- R81 修复提交 `9183a5da3ea488763d580f15b76261e3d0e8df2c` 已推送到 GitHub `main`；
  [CI 34474592321](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/34474592321) 通过。
- `9f66043` 递增六个 APK 版本，确保设备会安装本次修复。
- `b8b0dc3` 修复发布清单漏记 `owrt-fw4` 的问题：包名匹配原先不接受数字；新增七包完整性断言。
- 两次 canonical `release-image` 均通过：
  [34475612300](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/34475612300)、
  [34477008696](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/34477008696)。
  **六个发货二进制、七个 APK 全部逐字节相同**。第二次清单包含全部七包。

| APK | 新版本 |
|---|---|
| owrt-uci | 0.1.0-r7 |
| owrt-reload-config | 0.2.0-r7 |
| owrt-logd | 0.1.0-r7 |
| owrt-httpd | 0.1.1-r6 |
| owrt-fw4 | 0.1.0-r7 |
| owrt-rpcd | 0.1.0-r11 |
| owrt-switch | 0.1.0-r2（未改） |

六个组件使用 CI APK 的发货二进制。procd、ubusd、netifd 沿用现有直接部署机制，使用
R83 最终验证过的精确 musl 二进制；其构建来源与 SHA-256 分开记录。
九个原件的 SHA-256 已在镜像提取目录和设备 `/rom` 之间逐一核对；三个 `.c-orig` 也与 `/rom` 相同。
完整清单见 [preparation.json](R84_parts/preparation.json)。镜像、APK、二进制与备份均留在 Git 外。

## 部署准备与恢复条件

用户已明确授权部署和 benchmark。仓库 [AGENTS.md](../../AGENTS.md) 同时要求
“a verified recovery gate”；[决策 0016](../../docs/decisions/0016-reboot-verification-and-rescue-boundary.md)
明确要求人在设备旁、网线接到 lan4，并有备用上网途径。

只读核验时，lan2/lan3/lan4 的 carrier 都是 0，Mac 经 en0 使用该路由器上网；
人是否在场、有线救援与备用上网仍待确认。PID 1 启动失败时，开机后才启动的自动回退计时器无法执行，
所以这一条件仍适用于本次更换 procd。救援步骤见
[AX3000T 手册](../../docs/RUNBOOK_AX3000T_RECOVERY.md)：mesh 键进入 failsafe，lan4 接入，
`mount_root` 后执行 `/bin/sh /root/r84/stack-switch.sh rescue`，再同步并重启。

现有配置、overlay、八个关键分区备份可读，官方 OpenWrt 三份镜像及小米 RD03 恢复镜像的 SHA-256
均已校验。另将当前 overlay 和配置/访问文件直接从设备读取为本地私有压缩包，并采集了 r23 pre 状态。
备份目录：`private/backup/2026-09-10-r84-pre/`。读取过程未在路由器上创建备份文件。

部署包位于本地忽略目录 `work/r84/deployment/`，已包含 APK、九个组件、基准辅助程序、
原件/候选/已安装文件校验清单和整套冷切换脚本。**尚未上传或安装到设备。**
计划安装方式是校验 APK 后使用 `--no-scripts --no-network --allow-untrusted`，随后一起冷启动接管。
原件始终保留；本任务不需要刷写生成的固件镜像。

`tools/r84_stack_switch.sh` 覆盖全部九个组件：

- 改动下一次启动的入口、标记和 init 使能状态，原运行进程继续持有原 inode。
- 新 Rust 启动未确认时，在 S99 启动后的 900 秒恢复全部九个原件并重启。
- 确认检查真实 `/proc/<pid>/exe` 和一次性命令入口；拒绝未重启的确认与过期计时器。
- `tools/r84_window.py` 可在 Mac 脱离对话进程运行；先检查现态，再暂存、重启，连续验证客户端健康
  180 秒并完成末次观察，才解除回退。失败的暂存不会落入重启分支。

## 离线验证

| 验证 | 结果 |
|---|---|
| 九个组件 × 原版/Rust 的隔离运行 | 18 种组合通过；相同客户端与原版依赖 |
| 实际 canonical httpd 发货文件的 r14 差分 | 61 请求通过 |
| 原生基准客户端的响应校验测试 | 1 个 Rust 测试通过 |
| LAN HTTP 客户端：余数计数、失败状态、HTTP 200 内 RPC 错误、预热后失败、新建连接计数 | 5 个测试通过 |
| 原生客户端：失败命令、错误正文、消失的 PID、RPC 错误 | 均使测量失败 |
| namespace 命令结束/启动器死亡 | 后代进程全部回收，宿主挂载未改变 |
| APK 安装 | 保持服务未接管；安装后的六个文件哈希与 CI 清单一致 |
| 整套切换与恢复 | 保留原件、拒绝早确认/旧计时器、恢复失败保留待回退状态、整套自动回退、无 ubus 的 rescue 均通过 |

原始离线验证留在构建机 `/home/ubuntu/r84-verify/`。新增 `make check-benchmark` 与 CI 步骤，
持续校验计数和失败判定。R83 已记录的 22 个异常 HTTP 边界差异仍按原报告解释；这里的 61 请求通过
不代表这些边界差异消失。

## 实机测量方案

实现与复现入口见 [benchmark/README.md](../../tools/benchmark/README.md)。

1. **单体**：uci、reload-config、logd、httpd、fw4、rpcd、ubusd、procd、netifd 分别对照原件。
   其他依赖固定为镜像原版；各侧四次运行，以 C/Rust 交错顺序减小时序影响。netifd 在独立网络空间
   控制虚拟接口，procd 使用监督模式。UCI 写入和 reload 基线放在独立 tmpfs。
2. **整体**：同一设备、镜像、配置和执行面，九处入口全部原版与全部最新 Rust 的冷启动对照。
   顺序为 Rust、原版、原版、Rust，结束于最新 Rust；每个启动窗口五轮负载与负载前后各 120 秒空闲采样。
   包括单客户端管理请求、四客户端混合负载、TLS 持续连接和新建连接，并记录启动恢复时间。

记录成功请求数、原始延迟样本、p50/p95/p99、吞吐量、被测进程 CPU 增量、客户端 CPU、RSS/匿名常驻内存、
文件描述符/线程、整机可用内存、温度以及运行文件和配置摘要。混合负载的进程 CPU 使用单独的总时间窗口，
避免重复相加各客户端重叠的计数。

原镜像不提供 `smaps`/`smaps_rollup`，因此不会报告未测得的 PSS/USS，也不会把相加后的 RSS 当成独占物理内存。
二进制文件体积与原版动态库、ucode、模板、插件分别说明。内核转发和硬件卸载保留，此基准的结论范围是
控制面开销及端到端管理请求。

**实机结果栏暂不填数值。完成恢复条件核验、部署、四个系统窗口和单体运行后，再以真实设备数据更新本文。**
