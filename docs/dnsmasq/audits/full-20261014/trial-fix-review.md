# Trial 修复独立验收

2026-10-14，主审独立验收修复方提交 `18d835273a534a1e38f42d3c1f2319fca28ce146`（恢复生命周期）与 `fd62cf85`（文档路径）。原 main `e9d89b17` 不变；本文件不把未合入的分支写成 main 已修好。

**F3 原中断反例和 F6 文档路径问题在这些提交中通过独立验收。** 新脚本SHA `dfa94d52cb132a181d78b8a0471b49868d9d3dd8bf9f79b00839edbd649f8b74`；daemon 仍为本轮基线fresh ELF `e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0`，没有把协议/资源修复混入。新运行6个隔离场景均退出0，每次都核对真实C ELF和独立veth DHCP OFFER/ACK、UDP/TCP DNS。

| 独立新运行 | 实测 |
| --- | --- |
| rollback-killed | 写回退请求后、仍挂载时杀死一次恢复进程，存活owner自动恢复C |
| confirmed-rollback-killed | confirm后只剩watch；卸载后、restart前单次SIGKILL，watch自动接续 |
| rollback-cleanup-killed | 原反例“两个helper清理后”杀点，此时已是健康C，客户端持续正常 |
| documented-path | 从0644脚本开始，照新文档chmod/hash/start/status/confirm/rollback成功；错误上传hash被切换前拒绝，C仍健康 |
| rollback-c-dns-loss | 真实C ELF正确但DNS被隔离防火墙丢弃，恢复尝试返回1，两个owner和请求保留；取消丢弃后自动完成恢复 |
| deadline | 未确认到期自动恢复C |

[独立结果与原始hash](trial-fix-review.json)。执行脚本在修复分支中，主审先审读后运行；Oracle实际harness SHA与`fd62cf85`的Git内容逐字一致。ptrace只观察真实系统调用并单次SIGKILL，没有替换init/procd/ujail或伪造恢复状态。主审使用全新`trial-fix-review-*`目录，未把修复方已有结果重算成新执行。

静态复核确认：回退请求放在tmpfs；`flock`串行恢复；deadline/watch等待独立进程组的恢复尝试，失败/被杀后继续接续；watch不再因mount消失而自行退出；只有卸载完成、所有daemon是精确C且本地DNS通过，才取消owner。文档脚本改为`/tmp/dnsmasq-trial.sh`，不再与`DIR=/tmp/dnsmasq-trial`冲突。

这只关闭已验收的恢复窗口，不声称无限故障容错。confirm后唯一watch本身退出或停止调度、两个owner同时失效、内核/硬件故障仍需人工恢复；新文档明确保留这些限制。脚本健康门只验证身份与DNS；本轮测试额外验证了DHCP，但脚本不会持续自动发现只有DHCP故障的情况。实际观察窗口仍须真实客户端验收。

所有新运行使用精确镜像stock init/procd/ujail的Oracle隔离用户空间；不是硬件试运行、不是修复后daemon与最新Rust9的最终组合资格。没有据此在家庭路由器启用分支脚本或候选。完整正式交付仍需冻结组合身份并验证。
