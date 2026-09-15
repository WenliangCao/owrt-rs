# R93 双基线与实机比较入口

2026-09-15。初始双基线计划及接续索引；本轮 source05 九组件实机矩阵已完成，见
[74 项/888 观测清单](r93-source05-device-matrix.json)。隔离组件运行保持生产 R92，未重启。

## 固定身份

| 对象 | 身份与可复用产物 |
|---|---|
| 精确原版（报告简称 C，包含 fw4 等原版脚本） | OpenWrt 25.12.5 `r33051-f5dae5ece4`，AX3000T stock 布局，kernel 6.12.94。官方 sysupgrade SHA256 `a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea`；实机使用 `/rom` 和已校验 `.c-orig`，构建机使用该镜像的 pristine rootfs。 |
| 正式 R89 | 运行时提交 `d9c10483d95590143f9d6a1f41310e2a13e63fb3`，release-image `34724293710`；部署包 SHA256 `a655b1356905c9434d5c53362c93722e0e8d93175f1b196d28f86ee42f632791`。设备保留 `/root/r89-before-r90`；离线归档 `private/r92/device/recovery-01/r89-before-r90.tar.gz`。 |
| R92 增量参考 | 运行时提交 `ca1a9121df0380448a19d474e29796066b6734e8`，release-image `34874442503`。本地二进制在 `private/r92/deployment-r92/bins/`；设备最后已验证活动包为 `/root/r84`。 |
| R93 source05 测量基线 | 冻结源码归档 SHA256 `6f8700bf5af4ca80a9113b5624229bde3e373f53553dec4dc95524dba33abd7c`，九个 SDK recipe 诊断产物身份见 [矩阵清单](r93-source05-device-matrix.json)。该组不含后续 `3262a56` prefix 修复或任何私有性能候选，不能把当前 HEAD 视为被测源码。 |

R89 最后一条报告提交 `39e5d89`、R92 最后一条报告提交 `6bb1226` 均不是各自正式运行时提交。
R89 canonical-build 中的 `deployed: false` 是构建时状态；其后的 deployment 证明包含四个已完成窗口。
二进制是否可当基线以 hash 为准，不能仅凭目录名或重复使用的 APK 版本号判断。

身份完整表见 [镜像入口](../../manifests/ax3000t-stock-openwrt-25.12.5/intake.json)、
[匹配上游 revisions](../../manifests/ax3000t-stock-openwrt-25.12.5/source-baseline.json)、
[R89 正式构建](../../reports/ax3000t-stock-openwrt-25.12.5/R89_parts/r89_canonical_build.json)、
[R89 部署](../../reports/ax3000t-stock-openwrt-25.12.5/R89_parts/deployment.json) 和
[R92 九组件 C/Rust hash](../../reports/ax3000t-stock-openwrt-25.12.5/R92_parts/canonical_build.json)。

## 已有比较的可用范围

- R92 同批三侧组件矩阵：九组件、74 workloads，每侧四轮；原版依赖、夹具、客户端和 subject hash 有校验，适合定位组件差异。构建机结果不能代替路由器成绩。
- R92 四整机窗口：相对同批 C，固定整批 CPU −23.39%，mixed 吞吐 +12.05%，mixed CPU/操作 −14.20%。
- 对历史 R89 的 mixed 吞吐 −3.73%、mixed CPU/操作 +4.35%、HTTP lane CPU +9.38%、log lane CPU +29.49% 是真实观察差额，但日志正文与进程历史未冻结，不能全部归因于代码。
- 同机临时 HTTPD 对 R89 的自身 CPU 增幅约 1.42%/1.66%；固定 logd 语料没有复现整机日志增幅。紧密请求不能覆盖 50 ms 停放/线程重建，gap 也不是 RTT。
- RSS、MemAvailable、文件页驻留分开报告；保留 C/R89/R90/R92 文件，不能靠删除基线副本改善候选成绩。单次差值或正负号计数不是显著性检验。

数据与限制见 [独立复核](R92_INDEPENDENT_REVIEW.md) 和
[R92 性能报告](../../reports/ax3000t-stock-openwrt-25.12.5/R92_PERFORMANCE.md)。

## 下一次最小公平矩阵

1. **组件三侧**：C、正式 R89、冻结候选，每组件每侧四轮，沿用工具平衡顺序；只替换被测组件，其余依赖保持原版。五个 daemon `ubusd/rpcd/procd/netifd/httpd` 跑已有 expanded matrix；`logd/uci/fw4/reload-config` 跑原有基本矩阵。即完整 74 workloads，不把未变更组件默认为必胜。
2. **缺口负载**：HTTP 保留 tight loop，并加跨 50 ms 边界的持久连接间隔、fresh HTTP/TLS、背压/关闭后 fd/thread/RSS 回落；logd 用固定正文、固定最终交付检查、固定流订阅者。压力正确性先过，再计性能；失败请求不进入成功样本。
3. **整机三侧同批**：至少两次独立冷启动/侧，交错顺序，例如候选→C→R89→R89→C→候选；每 boot 同样五轮、前后各 120 s idle、固定操作和输入。相同配置、客户端、双核、监听端点及恢复文件保留策略。三套身份分目录采集，禁止覆盖历史窗口。每项报告均给 C 和 R89 两个差值及各轮范围；局部未赢就保留未通过项。

组件重用命令（示例，不是已执行记录）：

```sh
python3 tools/benchmark/run_candidate.py CANDIDATE/procd-rs PRIVATE_NEW/procd \
  --component procd --matrix --interface en0 --access wifi \
  --baseline-bundle /root/r89-before-r90 --baseline-label r89 --repeats 4
```

其他组件替换名称；`logd/uci/fw4/reload-config` 省略 `--matrix`。
工具仍有内部 `r84` side key，使用 `--baseline-label r89` 输出正确身份。
原版、R89 和候选须使用同一份冻结 `owrt-benchmark`/`ns-exec`，工具会拒绝不一致。

## 复用恢复门与命令

新的物理窗口仍须核验当前配置、离线配置/overlay/保留包、恢复镜像、候选 manifest 与二进制、空间及客户端健康；旧 R92 gate 的成功不能替代这些当前状态核验。
已有离线门为 `tools/r84_switch_selftest.sh` 和 `tools/r92_apk_upgrade_selftest.sh`。
原始恢复资料位于 ignored `private/r92/device/recovery-01/`；只公开派生身份。

```sh
# 当前只读健康检查
python3 tools/r84_device_probe.py --mode rust --interface en0

# 已准备且核验通过的活动 bundle：冷切换、900 s 未确认回退
python3 tools/r84_window.py rust --interface en0 --result PRIVATE_NEW/rust-1/health.json
# 原版对照窗口用 stock；工具要求新 boot、连续 180 s 健康及最后 30 s 观察
python3 tools/r84_window.py stock --interface en0 --result PRIVATE_NEW/stock-1/health.json

# 仅在该窗口 health.json 已通过且身份仍相同后采集
python3 tools/benchmark/run_window.py rust PRIVATE_NEW/rust-1 --interface en0
```

`r84_window.py` 包含 reboot 与 confirm；900 s timer 在 init 后运行，更早 PID 1 失败仍靠离线救援。
R89/候选切换需先重新安装对应七个 APK（同版本必须 `--no-scripts --no-network --allow-untrusted --force-reinstall`），再核验 installed hash 和安全调整 `/root/r84`，仅换 bundle 目录不够。
`stack-switch.sh` 没有 `status`：使用 `verify rust`/`verify stock`，并核验 pending/reverting/canary 清除。
完整顺序见 [发布与回退](../R92_RELEASE_AND_ROLLBACK.md)；失联入口见 [恢复手册](../RUNBOOK_AX3000T_RECOVERY.md)。
`r92_finalize_device.py` 会清理文件，不能作为重复的只读检查调用。
