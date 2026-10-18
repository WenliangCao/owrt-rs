# v0.3.0 固件守卫与回滚材料

精确 v0.3.0 镜像的 **23/23 守卫分支、2/2 PID1 回滚交接**一次通过。
新的回滚配置包已离线生成并回传 Mac，原备份 **46 个成员的内容和元数据全部
不变**，13 个 C 恢复文件完整。本项没有物理路由器访问、性能采样或闪存写入。

输入来自 CI `39124795974`，源码
`6fb236a3d3cae4c1fa2e0c80e8f0aae552437bd2`，包 `0.3.0-r1`、布局
`native-eleven`，odhcpd SDK 为 `589226a1…`。与独立 boot/image/APK 资格使用
同一解包 rootfs；执行前后全部输入及源 rootfs 身份未变。

| 输入/材料 | SHA256 |
|---|---|
| v0.3.0 image | `75c55bd57fd5908b89dce4e0239e1ec1cada36f3b94ae6d141a69b0a83472cfd` |
| 最终 manifest | `85baf34ed4f912b2c8355478361b4b839241e220fa64480ee8a2fe4145d688ad` |
| 回滚 v0.2.3 image | `02b6a3283140126a9c7d3ccc0404afe42077924b6b1229b3b96859cf449d8606` |
| 原配置备份 | `b8702654472e3aec26c233e30f1ad2192e351d4d572965768c880c945562b650` |
| 新回滚配置包，14,099,434 bytes | `b0ac8c1405160eaa4d2fd1c281d72898c425f0b6e735c3bb985de8c48eaa9631` |
| 配置包 metadata | `ea1a3a014752240d9e98bdfa52af13bec87bf54e3f2c85d6ac13c1812eb4d984` |
| 离线资格证据归档 | `cedbd3190a23156cc517f79ec3655b92ef58de8207423fd7f311590256b18249` |

使用镜像对应源码的 `native_trial_guard_selftest.py` 和
`native_trial_handoff_check.py`。前者模拟时钟、健康、sysupgrade/reboot，实际
执行完整 C 恢复；后者运行真实镜像 PID1、ubusd、sysupgrade 及验证器，只将
`upgraded` 换成静态记录器。正常交接 6.70 秒，真实服务 `term_timeout=70`
时交接 71.89 秒；两者均只有一次提交、实际 argv/备份完整，没有 C bridge 或
强制重启。**不执行 stage2，不验证物理刷写。**

两组通过后，`native_trial_prepare.py` 才生成配置包。包内保留完整原备份与
精确 v0.2.3 回滚镜像，13 文件恢复清单另绑定恢复脚本和清单自身，共 15 个
恢复身份条目。新 token 仅在 private metadata/armed 中，不进入 Git。
首次确认期限 600 秒、已确认后失去健康期限 300 秒，遵循既有守卫规则。

Oracle 原件：`/home/ubuntu/odhcpd-image-v030-20261018/guard-checks/`。
本地材料：`private/odhcpd-20261018/v030-guard-recovery/`，包含
`guard-evidence.tar.gz`（41 项命令、日志、结果与编排脚本）、
`trial-config.tar.gz`、`trial-config.tar.json` 及摘要；本地副本已逐项复核。
部署阶段仍由主线程核对当前 boot、配置和客户端健康并执行，本文不提前记录
刷写或发布结果。
