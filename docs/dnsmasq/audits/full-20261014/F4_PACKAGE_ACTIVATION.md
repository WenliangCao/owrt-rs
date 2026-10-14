# F4：APK 成功事务的实际激活

2026-10-14。产品基线 `340ed73e`，独立分支
`fix/dnsmasq-full-f4-20261014`。**已修复本轮正常升级、重装和降级仍保留旧运行 ELF
的问题，并把发布版本提升到 2.93-r4。** 未合入 main、未 push、未操作物理路由器。
本页是 F4 独立验收，不代替最终 F4/F5/F10 组合源码的 SDK 构建及统一验收。

## 一行产品修改及其合同

`dnsmasq.init` 将 `procd_set_param file $CONFIGFILE` 改为
`procd_set_param file $CONFIGFILE $PROG`。APK 仍执行精确 SDK 生成的原有
post-install/post-upgrade，调用 init `start`；没有新增包脚本或守护进程。

匹配 C procd 的 `service/instance.c:971,1083–1114,1420` 将文件路径及内容 MD5
纳入实例变化比较；Rust procd 的 `instance.rs`、`sys.rs::file_md5` 保留该合同。
哈希由外层 procd 读取，无须给 dnsmasq UID 453 或 ujail 新增权限。
MD5 用于变化检测，交付身份仍以 SHA-256 核验。

- stock→候选：文件依赖集合增加程序，实例必须切换。
- 候选 ELF 改变：文件内容摘要改变，实例必须切换。
- 候选→原 stock 或 M5：旧包 init 恢复仅配置文件，集合变化也触发切换；
  不依赖已经被替换掉的候选 postinst。
- 相同字节重装及未改配置 reload：实例不变，实测保留 PID 与启动时钟。
- 首装、账户创建、卸载停机与 conffiles：保留原 SDK 合同。

这是 service 配置提交时的变化检测，不是后台文件监控或 APK 原子性方案。

## 产物与发布版本

| 对象 | 身份 |
| --- | --- |
| frozen 产品源码 | `340ed73e83e58ba845e0a645eb21e9ead0d0f108` |
| 包内 Rust ELF | `edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d`，2,089,440 B |
| r4 APK | `bc7bd1514ededb1e9f5350a31487e767346cbf407a1b625f30f1f6c779bcde77`，1,134,350 B |
| 精确 stock C | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 接受的 M5 r2 APK | `bfed44eaf49703745a2c08a8ee1fbc5325b44f833d07baee2224a0084a6ee8aa` |
| M5 r2 包内 ELF | `37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b` |

默认 recipe、build 和 lifecycle 工具使用 r4；显式 r2/r3 仍可复现历史流程。
精确镜像 APK 的 `version -t` 实测 r4 同时大于 r2、r3，不会把新修复仍发布为旧 r2。

本轮真正执行匹配 SDK 的 prepare/compile/APK 包装，但采用 `package-frozen-elf`
模式，不重新 codegen 或 strip；包内 ELF 与已验证输入逐字一致。r4 包的源码/配方
输入 digest 为 `0b5ff08fe82b087556fdffc019a63940b5ee5a0daf4d0a3cfbe55e32cf380b1a`。
SDK recipe 已恢复。旧 ELF≤1,000,000 B、APK≤700,000 B 数字门仍在工具中返回失败，
原 exit 1 与两个实测大小完整保留；预算解释由 F7 单独处理，不把 size-target
失败写成编译/身份通过失败，也不声称最终 SDK 源码构建已经完成。

## 真实 APK 生命周期与客户端

`m4_package_lifecycle.py --automatic-activation` 的最终 r4 运行 **14 阶段通过**：
stock 升级、相同候选重装、卸载、缺账户首装、移除后装回 C、再次升级、直接降 C，
以及真实 M5 r2→r4、直接降 M5 和移除后恢复 M5。所有服务阶段检查外层
`/proc/PID/exe`、ujail、UDP/TCP，应有的新进程与配置保留，不能只看包数据库或磁盘。

唯一显式 restart 是**准备未修的旧 M5 基线**。第一轮未执行这一步时，工具正确检出
stock→旧 M5 后仍运行 C `(deleted)`，原失败保留。修正后仅允许固定的
`stock-to-m5-baseline` 标签使用该准备操作；M5→r4、r4→M5/stock 都必须自动激活。
不能把旧包之间的已知缺陷算成新候选已修，也不能用准备操作掩盖候选激活失败。

另以精确 stock procd 和当前 Rust procd 分别执行 **8 阶段真实 veth 客户端**：
初始 C、升 r4、相同字节重装、未改 reload、直接降 C、再次升级、坏包失败和原包修复。
每步都取得真实 DHCP OFFER/ACK，核对 DNS/网关选项，执行独立 UDP/TCP 查询，并保存
安装数据库、磁盘 ELF、运行 ELF/PID/启动时钟三个视图。两组全部完成，未补手动
restart；正常直接降级时三个视图同时为 C，重装/reload 保持原 PID。

Rust procd ELF 为 `9db9917e1fad24a7a4717ddfbcd3ba824f5d3d697b9f873fb40172812be87957`。
它计算文件摘要时整体读取 ELF，因此存在约 4 MiB 的瞬态内存增量；本轮 VmHWM 与
各步 RSS 已逐项记录，稳定 RSS 回到约 0.8 MiB。C procd 逐块计算摘要，约 1 MiB
常驻。这里是一次管理路径观察，不是 CPU 性能基准或全局 OOM 资格。

## 失败事务：明确保留的 APK 边界

截断 r4 APK **不是在安装前检查阶段被拒绝**：两组均进入 Reinstalling，在提取
`usr/sbin/dnsmasq` 时报告 `Connection aborted`、返回 1。随后 `dnsmasq` 安装数据库
项实际消失，而磁盘和旧运行进程仍为 Rust，且 DHCP/UDP/TCP 继续健康。
因此“还有一个健康进程”不能证明安装一致或已回退。下一步单列为 stock **修复安装**，
不能误称直接降级；修复后数据库、磁盘、运行 ELF 和客户端一起恢复为 C。

更早一版网络工具在坏包后才执行所谓直接降级，命名混淆了恢复安装。该原始结果
没有删除；最终两组已将正常直接降级移到故障之前，并加入逐步三层身份记录。

ENOSPC 专项使用同源 F4 的 r2 包装阶段 APK、16 MiB 私有 tmpfs overlay，留
131,072 B 后实际执行升级及降级。两次均在提取程序时 ENOSPC；升级还报告数据库
写失败，分别返回 2/1。记录中安装版本、磁盘程序和旧 PID 保留。这里没有在人工
诊断 restart 前执行客户端探针，不补称这一窗口的 DNS/DHCP 已通过。释放空间后，
离线原包修复加显式 restart 能恢复 C；这不是自动恢复证明。

这些结果只界定所测失败阶段；不承诺任意中途 SIGKILL、断电、UBIFS 或满闪存下
APK 原子回退。README 与当前 trial runbook 已明确失败安装不能视为回退完成，
恢复仍依赖已验证的 C 入口、空间、管理通路、离线原包和最终客户端确认。

## 工具边界、证据与收尾

25 个包工具测试和 6 个历史 M6b 测试通过。组合工具的三个独立选项只允许明确差异：
`--automatic-activation` 的 `$PROG` 依赖、`--dns-object-acl` 的精确 `dnsmasq.dns`
publish，以及 `--ubus-directory-mount` 的只读 socket 目录。负控制拒绝权限通配符、
root 用户、扩大到整个 `/var/run`、读写 mount 或额外 procfs；没有放开整个 init/ACL。
本页产物只含 F4，后两项的组合包资格仍须最终执行。

[派生结果与 SHA 索引](f4-package-activation.json)。原始资料已放在持久主仓库
`private/full-merge-f4-20261014/f4-evidence-final.tar.gz`，SHA
`290d42588e437dc1915b6077d1d32bb5914ca9f9b55d243800242e44edaafe48`；12 份 rootfs
身份另存 `rootfs-identities.tar.gz`，SHA
`5c9eedeb9b7ad42d2c4ad17ff5de371409b62ed901d403a42df86ecf4553f263`。本地逐项复算一致。
Oracle 原始任务目录为 `/dev/shm/full-merge-f4-20261014/`。

确认无本任务进程或宿主挂载后，仅删除 17 个自有可重建 rootfs/rootfs-overlay，
约 54.8 MB；原始结果、配置/源归档、APK、ELF、日志和失败收据保持。没有触及其它
任务的 target/证据。最终统一源码 SDK 构建、F5/F10 组合和真机均不在本页通过范围。
