# v0.3.2 实际 CI ELF 运行时回归

**新候选没有运行时回退：4 个 no-proc 案例通过、16 个 FD 场景无新增失败、
3 次实际 RELRO/NX/ASLR 验证和 40 次启动验证通过。** helper 的既存低 FD
失败仍逐项记录，不将它们算成通过，也不据此宣称性能改善。

本轮比较新候选与已发布 v0.3.1，重新采集全部运行时对照。历史 K 是 v0.2.1 性能
研究基线，本轮不复用其 FD、启动或性能结论。旧 startup driver 的 `k` 参数只是
保留的角色名，结果显式标为 `baseline-v031`；启动耗时/CPU 只保留原始值，不作
性能接受判断。

模型与预测：新 ELF 的布局可能变化，但 no-proc 自执行、FD 压力后的恢复、静态
PIE 保护和真实 helper 回调不得回退。两种 no-proc 模式均应成功；FD 2/3/4/8
各模式精确施压，候选不能新增 v0.3.1 没有的压力/恢复/限额还原失败，resolver 必须全部通过；
三次启动检查实际 RELRO/NX/ASLR；双方 helper/resolver 各十次，总共四十次启动，
检查完整 FD、凭据、回调和子进程回收。任何新失败停止，保留失败目录。

`tools/dnsmasq/v032_runtime_qualification.py` 绑定 CI manifest、212 个产品输入、
源码摘要、ELF/APK 和对照 hash，再运行冻结源树中的已有工具。镜像 C 来自精确
OpenWrt 25.12.5；所有命令在 Oracle 私有 mount/net/PID 边界内执行，没有物理
路由器访问或 `/proc/kmsg` 读取。

- product commit：`a170caa5d74f928186d63e6c4d879688deee3a4c`
- source digest：`c3daefd7b94be1e42120f6ae9cec7c56264ed2dc430639ceea5d63812d151725`
- CI run：`39323876403`
- candidate ELF：`2a22f6327d81e25c8bf9e891d21842e5ef0d33ec074e5004506388f3b616e2a2`
- v0.3.1 ELF：`0421a5d02a4b5e8fb23c60572f0de113628fe1b2d88ebc92485a9359d9d80244`
- manifest：`ae9b7a99b9b45162628a53ecfa808f51f49bc814e8ada42458b0e224188553aa`

startup observer 从冻结 `device_selfexec_lifecycle.c` 在 Oracle 用
`cc -O2 -std=gnu11 -Wall -Wextra -Werror` 重新构建，单独记录新工具 ELF 身份，
未冒用已清理的旧工具 hash。m6a_upstream、nice10 和 namespace helper 复用此次
训练工具目录的已重建产物。所有身份和原始结果在
`/home/ubuntu/v032-dnsmasq-20261019/qualification-prep/`。

首轮 `private/runtime-01` 把“每档限额都必须恢复”加成了比旧 gate 更强的断言，
在 v0.3.1 对照即失败：helper 两个 FD 空位时进程退出，已无法还原限额；3/4/8
空位压力回调失败但限额和后续操作恢复。所有档位的 DNS 健康均 20/20，resolver
全部通过。该实际边界保留为失败行；后续比较候选能否保持对照已成功的每项行为，
没有把既存 helper 失败冒充成功。`runtime-01` 未删，完整双方对照重新执行。

`private/runtime-02` 的双方 no-proc、FD 与 shipping 已通过。两边 resolver 四档
全部成功，helper 四档均保留失败标记；候选没有丢失对照任何压力操作、恢复、
限额还原成功项，全部 DNS 健康为 20/20。候选实际 RELRO 为只读、栈不可执行，
三个进程映射基址各不相同。

该轮 startup 的第一个对照组在启动 daemon 前被 C observer 的路径 guard 拒绝：
工具要求 fresh `/tmp` 路径，新 wrapper 却给了 `/home` 下的结果路径。修正只影响
startup 夹具位置，前述已完成且绑定同一 ELF 的结果保留，不伪装成产品红例。

修正后 `private/startup-final/result.json` 的四组均 exit 0，原 validator 对
40/40 次启动全部通过；双方 helper 每次回调均为 2，十次计数数组完全一致；
全部子进程已回收。该收据 SHA-256 为
`6584a73490167a5c7f75488b46b805ff4d2a573eb2aa5c938a08fb3f35f57b55`，
原始 runtime 树复制至同目录 `runtime/` 永久保留。

`collect_v032_runtime.py` 重新校验所有身份、完整 FD 矩阵、未回退的逐项成功、
shipping 和 startup，生成独立 `private/runtime-qualified.json`，SHA-256：
`4473d4540206f5b51762da7598b770a9fb4cac578e962cd319cf7b2208bca583`。
它绑定旧 wrapper 的失败收据和各个已完成阶段，不改写 `runtime-01/02` 的失败状态。
44 families/67 jobs 与 F23/F25 是另行绑定的资格收据，不包含在本报告计数中。
