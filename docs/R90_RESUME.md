# R90 第一批续接说明（2026-09-13）

**离线验收已完成，下一步是获得独立授权后的实机验收。**
先看 [R90 报告](../reports/ax3000t-stock-openwrt-25.12.5/R90_BATCH1_LIFECYCLE.md)。
不要重新排查已修的八类问题，也不要重复已完成的正式构建和整套构建机测试。

## 固定候选

- 运行时代码：`ae51db4e453417184260c368f7d4d7a2727b133f`，分支 `codex/r90-lifecycle`。
- 正式构建：[release-image 34753661051](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/34753661051)，成功。
- procd SHA256 `2720dc66876e0ea53b6dab75ff6bd827466563dce5030eac931f8a5b7c5a22ee`
- netifd SHA256 `e8a18c5bf3c2f07aca6704a97030e64ed760e2a41f9a0d0139cb797588c3f4b9`
- 其余七组件与 R89 正式产物逐字节相同。
- 本次续接仅修正性能汇总脚本的两处证据文件名，并增加按组件复核的参数；未修改运行时代码。

## 已完成，不需重跑

- 正式候选：netifd 30/30；新增生命周期 12 场景 × 两侧符合各自合同；procd 功能回归通过。
- 同源码单元测试 netifd 156、procd 74，以及两组件 clippy 通过。
- 原版 C busy 对照丢失一条末尾日志，原始失败保留；正式候选另行补跑通过。
  `acceptance-02/procd/FAILED` 因该 C 对照而存在，不能因此误判候选失败，也不能说两侧都通过。
- 离线安装/回退 5/5。部署包九个二进制身份已核验。
- R89/R90 正式产物 22 项性能矩阵，每侧四轮，共 528 万次请求全部成功。
  常驻 RSS 中位数、fd、线程数相同；netifd 平均延迟变化 −1.27%～+2.15%。
- procd 尾延迟另做固定 CPU 2,3 的八项复核，192 万次请求全部成功。
  原先 system_info_c4 的 p95 +14.99% 未复现（复核 −0.77%）；另一负载仍有波动。
  结论是未发现跨环境一致的 CPU/常驻资源退化，**不能保证所有实机尾延迟无回退**。
- 二次 helper 清理专项：镜像原版约 5013 ms，正式候选约 72 ms。

## 证据位置

构建机 `oracle` 的 `/home/ubuntu/r90-batch1`：

- `source/`：正式构建提交的原始快照；335 个组件/工具/工具链文件校验一致。
- `baseline/`：R89 正式产物；`canonical/`：R90 正式产物；不要误用开发构建 `candidate/`。
- `validation-tools/benchmark/`：修正后的汇总工具与未改动的采集/分析工具。
- `raw/acceptance-02/`：完整功能结果、原版 busy 失败与候选补跑、离线回退、测量前检查。
- `raw/performance-02/`：完整 22 项矩阵，有 `COMPLETE`。
- `raw/performance-procd-affinity/`：固定 CPU 的 procd 复核，有 `COMPLETE`。
- `raw/green-v4` / `raw/red-accepted`：开发绿证 / R89 10/12 场景红证。
- `raw/hotplug-red`：R87 正式 procd 队列停滞红证。
- `deployment-r90/`：准备好的部署包，状态 `prepared_not_deployed`。

本机镜像：`private/r90/oracle-evidence/`、`private/r90/deployment-r90/`。
正式构建原始产物在 `private/r90/canonical/`，核心二进制在 `private/r90/core/`。
可入 Git 的派生数据在报告旁 `R90_parts/`，原始文件和二进制不入 Git。

旧的 `PAUSED_BY_USER` 目录、首轮 checksum 路径错误、`performance-01` 汇总路径错误均保留，
不替代完整验收。测量前已清理已结束测试遗留的 chroot 子进程，并确认无构建/功能测试并发。
旧套件的自动清理能力可留到后续测试工具批次补强。

## 下一步

1. 先获得独立的 Wi-Fi 实机部署授权。当前物理路由器未修改，备份核验标记仍为 false。
2. 在写入前核验当前离线备份、恢复材料、候选身份、自动回退与管理客户端健康；不要求 LAN 线。
3. 使用同一正式候选完成 AX3000T 冷启动、功能与 R89 性能对照，特别跟进 procd 并发尾延迟。
4. 达到恢复与客户端健康门后才确认部署，保存并更新实机报告。

R88 netifd 审计曾混用较新上游；精确参考为 `private/upstream-ref/netifd-ref`
（匹配 `cbb83a1857407a28a63dc09412a1f209195914ef`）。F10 在镜像原版也存在，
清 task_killed 是明确记录的改进，不要重新把较新的 proto-ext.c 当部署规范。
