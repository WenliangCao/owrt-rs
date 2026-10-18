# v0.2.4 最终镜像离线恢复资格

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
