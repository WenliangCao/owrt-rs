# v0.2.4 最终镜像离线恢复资格

本文保留审计前镜像的历史证据；Fable 全部修复后的当前镜像结果在末节，
没有沿用旧 ELF 的通过结论。所有结果均为离线资格，不代表已刷机或发布。

## 审计前镜像（历史）

2026-10-18：精确 CI 镜像的 **4 组离线恢复检查全部通过**，本轮无失败或重跑。
这不是部署许可：按用户后续指示，**v0.2.4 不刷机、不发布，待独立审计完成并
处理结论后再继续**。组件真实 trial、完整 boot 和此项恢复资格分别留证。

输入为 CI `39111043955`、源码
`4acf1c80e2dfeab7247b6de85694977ae2873894`，布局 `native-eleven`，包版本
`0.2.4-r1`。恢复目标沿用已验 v0.2.3，没有重新下载或替换历史产物。

| 输入 | SHA256 |
|---|---|
| 最终 image，14,121,248 bytes | `eb96dd90d23f4f35f8ccdee2ec01b1c2f5cf828b47ebb87671fe297caa7f9ed3` |
| 最终 manifest | `5ea03b4aa90fb8f1a5b211166c360555a3a8a5b0a865c2eaceca56e02792d0ec` |
| 统一 APK | `c0ea5d23ef6d2b49a0dfbcaa0a381edcbf2409df9d1fa54d79a1e89b4168475e` |
| 回滚 v0.2.3 image | `02b6a3283140126a9c7d3ccc0404afe42077924b6b1229b3b96859cf449d8606` |
| bounded helper | `21609fa0e03e4a4595e74d266235a9566f2cc37f71571ad9315900d3def5cb49` |

| 现有工具 | 结果 |
|---|---|
| `native_image_check.py` | 8/8：两种配置迁移、损坏恢复输入拒绝、非法恢复源拒绝、挂载目标拒绝、完整 C 恢复与重复执行、型号元数据验证 |
| `native_apk_fixtures.py` + `native_package_reinstall_selftest.py` | 10 个原 owner 包 payload，含 `odhcpd-ipv6only=2026.06.29~5d7be43f-r1`；原包/统一包两种真实重装通过，8 个“返回成功但未执行重装”负控全部被拒 |
| `native_trial_guard_selftest.py` | 23/23：确认、期限、坏输入、失败恢复、单次 C bridge/回滚限制和竞争分支 |
| `native_trial_handoff_check.py` | 2/2：正常交接 7.94 s；服务真实 `term_timeout=70` 的交接 71.49 s；客户端提前返回后仍只有一次提交，无重复升级、C bridge 或强制重启 |

原包 APK 是由精确 stock rootfs 重建的未签名 payload 夹具，仅用于
`--no-scripts` 文件所有权/修复检查，不称为原始发行签名包。
guard 分支测试模拟时钟、健康、sysupgrade 和 reboot，但实际执行完整 C 文件
恢复。handoff 使用真实镜像 PID1、ubusd、sysupgrade、验证器和升级库，仅将
`upgraded` 换为静态记录器，验证实际 argv 与配置备份；**不执行 stage2、写闪存
或物理重启**。所有运行均在 Oracle 私有副本/namespace，无路由器访问或性能采样。

执行前后复核共享源 rootfs 的 11 个 ELF、2 个配套文件、13 个 C 恢复文件，
以及 image、manifest、APK、rollback、helper、测试工具，身份均未变化。
各组独立输出，最多两组并行，源 rootfs 始终只读。总执行时间约 80 s。

Oracle 原件：`/home/ubuntu/odhcpd-image-v024-20261018/recovery-checks/`。
本地摘要、62 项命令/日志/结果与编排脚本：
`private/odhcpd-20261018/v024-recovery/recovery-checks-evidence.tar.gz`，SHA256
`029975b61de1c251fdc152381cf304a8c696169a02751a777159941a9705794d`。
完整调用参数、每个工具摘要和每条命令退出码保存在归档内；无私有配置、镜像或
二进制进入 Git。后续决定依据独立审计结论，不将本报告标为 ready-to-deploy。

## Fable 最终镜像（当前）

CI `39115006321`、源码 `e1cf7890f5ec2edbf5670f97e035f328fa569685`
产出的新 `native-eleven` 镜像，已在全新目录重新通过四组离线资格。
内置 odhcpd 为最终 SDK
`c7c5f1f9e79ea80febe696d6c758db8d3463d1e4b94c7a002f1aa597b9c3ea30`；
C 恢复脚本为
`96d6677abebc2a14012f1ab43f885cf614c96f73bcc189005674bfbda0d81abc`。
此前 `76705b92` 候选未启动恢复批次，没有被计为通过。

| 当前输入 | SHA256 |
|---|---|
| image，14,131,488 bytes | `e669c44cd5eadbf29605304fbe295c73673502d32a8e0364ad9e0692f12315a8` |
| manifest | `c738b05adc5f143e98b9ead6601289d71e4f704699548f7734faea61e9eab6b3` |
| 统一 APK | `c5e7a298d5fc535b2950e5acb86395bf64d2f622bf04a1647b279c2f933031ff` |

回滚 v0.2.3 image 和 bounded helper 重新核对，仍为历史表中的同一身份。
使用当前镜像和源码所带同一组工具，结果如下：

| 检查 | 新结果 |
|---|---|
| image/迁移/C 恢复 | **9/9**，新增“从十一组件恢复清单删去 odhcpd”负控，必须在任何替换前拒绝；完整 13 文件恢复仍成功 |
| APK | 10 个原 owner payload；**2 项真实重装、8 项负控**全部通过，包含 odhcpd 原 owner |
| 固件守卫 | **23/23** |
| 真实 PID1 回滚交接 | **2/2**，正常 10.11 s，70 s 服务停止延迟场景 71.54 s；单次提交、实际 argv/config 完整，无 C bridge 或强制重启 |

本轮首次执行全部通过，无失败或重跑，总计 82.15 s；没有性能测量。
执行前后 image、manifest、APK、回滚材料、工具与共享源 rootfs 的
11 ELF、2 integration files、13 C 恢复文件身份均未变化。测试边界同历史段：
私有命名空间、真实恢复/重装与 PID1 handoff，`upgraded` 为记录器，不执行
stage2 或写闪存。新的有限试运行 guard 6/6 与生成器 3/3 结果另见
[试运行恢复门](ODHCPD_TRIAL_GUARD_20261018.md#fable-最终-sdk-的重新验证)。

新 Oracle 原件：`/home/ubuntu/odhcpd-image-fable-v024-20261018/recovery-checks/`。
本地 63 项结果、命令、日志及编排脚本：
`private/odhcpd-20261018/v024-fable-recovery/recovery-checks-evidence.tar.gz`，
SHA256 `eefdb482e0215045a7d68f93cde930816388090beccfb3cfd346bbe372c34eb1`。
真实设备试运行、完整刷写与发布状态由各自记录确认，本节不预先宣称部署完成。
