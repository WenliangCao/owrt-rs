# R90 第一批续接点（用户要求暂停，2026-09-13）

目标：解决第一批 netifd/procd 生命周期问题，并检查 R89 优化成果没有回退。
已修复 8 类问题；源码与测试提交 `ae51db4e453417184260c368f7d4d7a2727b133f`，
分支 `codex/r90-lifecycle` 已推送。不要重新开始排查；先阅读
[R90 报告](../reports/ax3000t-stock-openwrt-25.12.5/R90_BATCH1_LIFECYCLE.md)。

## 固定产物

- 正式构建成功：[release-image 34753661051](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/34753661051)。
- procd SHA256 `2720dc66876e0ea53b6dab75ff6bd827466563dce5030eac931f8a5b7c5a22ee`
- netifd SHA256 `e8a18c5bf3c2f07aca6704a97030e64ed760e2a41f9a0d0139cb797588c3f4b9`
- 其余七组件与 R89 正式产物逐字节相同，可按身份复用。
- 本机产物：`private/r90/canonical/`、`private/r90/core/`。
- 本机原始证据备份：`private/r90/oracle-evidence/`。

## 构建机 oracle

工作目录 `/home/ubuntu/r90-batch1`：

- `source/`：修复提交完整源码；工具链 `1.98.1-aarch64-unknown-linux-gnu`。
- `baseline/`：冻结 R89 正式二进制；`candidate/`：开发构建；`canonical/`：本轮正式产物。
- `raw/green-v4`：12 场景双侧通过；`raw/red-accepted`：R89 12 场景中 10 个报红。
- `raw/r90-adapter-v1`：netifd_suite 新增适配器独立通过。
- `raw/hotplug-v2`：原版/开发候选通过；`raw/hotplug-red`：R87 正式 procd 准确报队列停滞。
- `raw/regression-v1/results.json`：开发构建已完成的旧回归结果。
- `raw/canonical-validation/results.json`：正式候选的单元与 clippy 通过；netifd 完整回归未结束。
- `validate-canonical.py`：完整功能验证命令清单，继续时换全新输出目录。
- `deployment-r90/`：已准备的部署包；manifest 明确未部署、当前备份未核验。

停止时已终止仍运行的 R90 validator 进程树，未完成目录标记 `PAUSED_BY_USER`。
只接受 results.json 中确实结束且 exit=0 的门；不能把中断日志视为完整通过。

## 下一步，按此顺序

1. 使用 `canonical/` 完成剩余功能验收：netifd 完整 30 项（含 r90），procd 的
   r90 service-state、hotplug（`R90_HOTPLUG_PROBE=1`）、tick、busy、r65/r83/r71/r72/r75。
   参考 `validate-canonical.py` 的精确 rootfs、examples 和配置路径；新建输出目录，保留中断记录。
2. 重跑离线部署/回退自测。首轮 `raw/offline-switch` 因清单相对路径错误失败，
   `deployment-r90/bundle.sha256` 已修正为相对 bins 目录的文件名，尚未复测。
3. 确认无构建、功能测试并发，再测性能：

   ```sh
   sudo -n python3 /home/ubuntu/r90-batch1/source/tools/benchmark/compare_lifecycle.py \
     /home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files \
     /home/ubuntu/r90-batch1/baseline /home/ubuntu/r90-batch1/canonical \
     /home/ubuntu/r90-batch1/raw/performance-01 --iterations 30000
   ```

   脚本使用冻结客户端，四轮/侧的交错顺序，共 procd 8 + netifd 14 项；检查请求
   成功、身份、夹具、netifd 子进程已回收。保存平均与尾延迟、CPU、RSS/fd/线程，
   与 R89 对照，异常先调查。`raw/benchmark-smoke` 仅是 1000 次的工具试跑，不是验收。
4. 更新 R90 报告并提交派生证据。若准备上机，先给用户具体候选和结果，再请求
   独立 Wi-Fi 部署授权；核验备份、回退、身份和客户端健康。当前路由器完全未动。

注意：R88 netifd 审计混用了较新上游。精确源码是 `private/upstream-ref/netifd-ref`
（与构建机 cbb83a18 Git checkout 的 SHA256 一致）。F10 在原版中同样存在，本轮
清 task_killed 属有意改进，测试显式记录这项差异。不要回到较新的 proto-ext.c 当规范。
