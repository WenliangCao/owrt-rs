# Fable 审计修复与新候选验收

F-1、F-2 已修复，F-3 至 F-5 同批完成。统一新 SDK ELF 一次通过全部 **129 项
实包检查**、此前审计的定向回归及最终镜像全部夹具；新 ELF 的真实客户端短时
试运行 **13 次检查、连续 123.739 秒通过**。确认后已恢复精确 C，配置与 boot
均未改变，临时挂载和守卫已归档清理。当前仍是 v0.2.3＋C odhcpd。

v0.2.4 的完整镜像及 v0.2.3 自动回滚配置包已准备并核验；**尚未刷机、发布或
合并主线**。旧 ELF 的 125 秒试运行没有转授给新 ELF，也没有新增性能优化、
性能采样轮或 odhcpd PGO。

## 修复与覆盖

| 问题 | 实现 | 新 SDK 验收 |
|---|---|---|
| F-1 | netifd 错型字段按 C policy 视为缺省；未知客户端接口先看模式；单接口坏 patch 跳过并记录，LAN 绑定不受影响 | 无 WAN dhcp 段、未知 WWAN、整数 leasetime 的启动和实包均通过 |
| F-2 | 重复设备检查在候选提交前；无 `services()` 致命错误路径 | 别名冲突被拒，原 PID/对象/DNS/NA 保留，纠正后 reload 生效 |
| F-3 | 非法 UCI host 逐条跳过并记录；ubus 输入仍严格 | 合法 host 分配/改名导出继续，非法 ubus 请求返回实际状态 2 |
| F-4 | 按精确 C 的内部有效模式维护 sticky ignore 名单，短锁同步，不受命令队列满影响 | disabled WAN/aux 通知不 dump，active LAN/unknown 正常，模式重读后名单更新 |
| F-5 | dump 独立 2 秒期限；reply/notify 维持 100 ms；协议循环不等 worker | 250 ms 启动/运行期完整 dump 生效，PID/对象不重建，RS/DHCP 继续服务 |

修复提交 `4e40ab54`、`bba626e9`；SDK 源提交
`e2adbe1c2bc32cdfbaef5ea4fa01acc81e9385ba`。
F-4 源码细节与 Fable 建议的表述不同：C 的 `ignore` 由 odhcpd 模式控制，并非
直接读取共享 UCI `ignore`。本轮保持 C 语义，避免 active LAN 被共享字段误滤；
Fable 原报告保持原文，处理依据见[覆盖计划和完整结果](ODHCPD_FABLE_FIXTURE_20261018.md)。

## 精确产物与离线资格

| 产物 | 身份 |
|---|---|
| SDK ELF | 802,928 B；`c7c5f1f9e79ea80febe696d6c758db8d3463d1e4b94c7a002f1aa597b9c3ea30` |
| 完整镜像 | 14,131,488 B；`e669c44cd5eadbf29605304fbe295c73673502d32a8e0364ad9e0692f12315a8` |
| 镜像源码 | `e1cf7890f5ec2edbf5670f97e035f328fa569685` |
| 镜像 manifest | `c738b05adc5f143e98b9ead6601289d71e4f704699548f7734faea61e9eab6b3` |
| v0.2.3 回滚镜像 | `02b6a3283140126a9c7d3ccc0404afe42077924b6b1229b3b96859cf449d8606` |

[SDK CI 39114432614](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/39114432614)
与[镜像 CI 39115006321](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/39115006321)
通过，严格编译警告为零。其余十个 ELF、内核与既有 integration 文件均与
v0.2.3 一致。十一组件、十三份 C 恢复文件及恢复脚本均逐一核对。

- 60 项普通单测，以及真实隔离 socket、精确私有 C ubusd 两项 I/O 夹具通过。
- baseline 20、extended 62、Fable 新 47，共 129/129 一次通过；19 条基线报文
  与精确 C 原件一致，33 条扩展报文与此前资格原件一致，无新增未解释差异。
- 此前审计的 DHCPv6 五事件、控制层两个故障/恢复场景、动态 hop limit 和一次
  ENOBUFS 故障场景均在最终 ELF 重跑通过；具体闭合见[审计汇总](ODHCPD_AUDIT_20261018.md)。
- 最终镜像原 S35odhcpd 启动、真实 veth RA/SLAAC/NA/PD、lease/hosts/trigger DNS
  联动通过。修改 UCI 后经原 init reload，原绑定租期 120→600、DNS 更新且进程
  身份稳定；实际 LuCI 租约/功能接口通过，并由独立审计者复核原始报文与 RPC。
- 最终镜像恢复 9 项、APK 两种真实重装与 8 个负控、守卫 23 项、PID1 回滚交接
  2 项通过；新版有限试运行守卫 6 项及生成器 3 项也重新通过。见[恢复报告](ODHCPD_V024_RECOVERY_20261018.md)。

从已完成功能夹具的同阶段快照读取三 NA＋一 PD 的 RSS：新 ELF **812 KiB**、
精确 C 原件 **1112 KiB**，满足两倍上限。这是现有功能原件的资源预算核对，
不是新性能批次，不把旧 ELF 的首包时延重新标成新候选实测。

## 新 ELF 短时真机试运行与回滚准备

重新取离线备份并核对精确 C、原 init/update、boot、19 个 UCI 文件与候选身份。
备份为 46 个成员、9,662 B，SHA256
`b8702654472e3aec26c233e30f1ad2192e351d4d572965768c880c945562b650`。
独立守卫先设 300 秒期限，再进行单文件 bind 与原 init restart。

真实 en0 客户端 13 次检查连续 **123.739367 秒**全部通过：新 RA 接收时间晚于
候选激活；GUA/ULA 地址、IPv6 默认路由、向收到的 RDNSS 直接作 TCP IPv6 DNS
查询、双栈 HTTPS、LuCI 与原路由器健康条件均正常。全窗候选 PID/start/ELF
保持不变。没有主动重配客户端或强制 DHCPv6 续租，分配/续租合同由上述实包及
整机虚拟客户端夹具覆盖；既有 Mac UDP DNS 限制仍未改写为通过。

健康回执绑定本次候选与原始 JSONL 摘要；确认后 guard 状态为
`restored-confirmed`，实际受管 C ELF 和 dhcp 对象恢复，客户端完整健康再次通过。
前后配置归档逐字节相同；24 个设备证据文件已逐哈希核对后清理临时目录与锁。
设备证据归档 SHA256：
`e6194c05091ded9f9367818b715956c41c7daf75cb4f2c5c5f70fe41f2cafb2b`。
原始私有证据在 `private/odhcpd-20261018/fable-trial-01/`。

完整固件回滚配置包离线生成于 `private/odhcpd-20261018/deploy-prepared/`，保留
原 46 个成员全部内容和元数据，绑定精确 v0.2.4 镜像、v0.2.3 回滚镜像及十三份
C 恢复文件。14 份离线救援原件重新核验，19 个 UCI 与 12 个受保护文件已核对；
备份省略的两个 stock 默认文件与当前 ROM/新镜像一致。包 SHA256：
`a71b889d1ef610165fb131db40532137b0a923403211eac1de59bb3dce5e4b7a`。
材料已达到可 staging 状态，但本轮没有上传完整固件、执行 sysupgrade、发布 Release
或解除主线合并暂停。C/Rust 共有的中断 netlink dump 边界仍按本机范围保留在审计报告中。
