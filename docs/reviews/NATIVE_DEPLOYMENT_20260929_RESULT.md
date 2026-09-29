# 九组件一体化固件真机部署结果

2026-09-29。**AX3000T 已保留配置刷入完整九组件 Rust 固件，连续客户端验收和用户物理断电复测通过，没有触发 C 回退。** 用户随后要求结束试验并清理，临时保护已移除。固定回溯节点为 [AX3000T Rust9 v0.1.0](https://github.com/WenliangCao/owrt-control-plane-rs/releases/tag/ax3000t-rust9-v0.1.0)。

执行前冻结[部署计划](NATIVE_DEPLOYMENT_20260929_PLAN.md)，工具提交 `c00f9f7`。固件为[正式构建 36592957923](https://github.com/WenliangCao/owrt-control-plane-rs/actions/runs/36592957923)，源码 `a4053dd5d4b4b2dbed3ff8a56d595aeabd33e0d0`，统一包 `owrt-control-plane 0.1.0-r2`。镜像 SHA256：

`144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720`

## 真机验收

18:39:54 CEST 发起原版 `sysupgrade -f`，约 **80.2 秒**后首次通过完整健康检查；随后 **15 个连续健康样本、跨度 182.45 秒**全部通过，于 18:44:19 确认。观察由电脑上的独立进程完成，跨越 Wi-Fi 断连。旧 sysupgrade 客户端在 PID1 移交时收到连接关闭；成功判据是新启动身份、镜像内容与后续健康检查。

| 检查 | 结果 |
|---|---|
| 镜像落地身份 | 真机 `/rom` 的 **910 个普通文件哈希**与正式镜像解包结果全部一致；**164 个软件包版本**也一致 |
| Rust 运行身份 | 六个守护进程的运行映像、九个标准入口及 ROM 文件符合正式 manifest |
| 统一所有权 | 九个入口均归 `owrt-control-plane-0.1.0-r2` 所有 |
| 配置 | **19 份 `/etc/config` 文件和 9 份额外保护文件**逐字节不变，包含 LED cron、密码、SSH 主机密钥和 TLS 证书/私钥 |
| 服务 | 原 log、rpcd、network、uhttpd 服务启用；旧六组件服务和 boot-enable 标记消失；fw4 检查通过 |
| 客户端与无线 | Mac 重新获得 DHCP 租约，双频 AP 正常并接入 LAN 桥，管理 HTTP/HTTPS 内容一致 |
| 外网与 IPv6 | DNS A/AAAA、路由器 HTTPS、独立 IPv4/IPv6 ping 和 IPv6 HTTPS 均通过；客户端具有全局 IPv6 地址 |
| watchdog | 运行正常 |
| 自动保护 | guard 内容符合已验证载荷；首次确认后仍运行，健康启动计数已清零，未发生回退 |

DNS/外网 HTTPS 沿用路由器侧探测，原因是客户端的 VPN 过滤限制；客户端 DHCP、LAN 路由和管理 HTTP/HTTPS 从实际 Mac 验收。上表先记录 sysupgrade 重启，后续物理复测单列；本轮没有重新进行性能跑分。

## 存储变化

`/sbin/uci`、`/sbin/fw4`、`/sbin/reload_config` 的三个绑定挂载均已消失。LuCI 的挂载查询只剩正常的 `/rom`、`/tmp`、`/overlay`、`/`、`/dev`，不再把三个命令显示成额外存储项。

| `df -k /overlay` | 刷入前 | 确认后 |
|---|---:|---:|
| Total | 62,044 KiB | 59,060 KiB |
| Used | 5,084 KiB | 276 KiB |
| Available | 53,752 KiB | 55,728 KiB |

可用空间净增 **1,976 KiB（约 1.93 MiB）**，达到约 **54.42 MiB**。程序进入只读根文件系统后，overlay 的使用量下降，同时其总容量随 rootfs 增大而减小；因此不能直接把 Used 的全部下降当作净节省。这些数字包含仍保留的临时保护。

## 物理复测与最终清理

用户在回复间隙自行断电并重新连接电源和 WAN，报告重启后很快恢复上网，未遇到旧问题。设备出现新的 boot ID，九组件运行身份仍为正式 Rust；该启动后 10 秒启动保护，56 秒记录连续健康并清零计数。客户端健康检查再次通过，没有 C 回退。用户未执行预设的等待时间系列，本报告记录为一次成功的非定时物理复测。

按用户要求，先核验离线备份、救援镜像、运行身份和健康状态，再停止保护并归档全部文件；归档中的 10 个普通文件逐个核对 SHA256。随后移除试验目录、启动服务和临时锁，六个守护进程的 PID 与映像不变，九组件和配置再次核验，清理过程没有重启。

清理后 overlay Used 为 **72 KiB**，Available 为 **55,932 KiB（约 54.62 MiB）**，比刷写前净增 2,180 KiB。重新保存了不含试验文件的配置备份。运行中已无 guard 或采集进程；常规恢复保留镜像内的 `owrt-recover-c`。

## 部署保护的历史记录

部署时保护文件位于 `/root/owrt-native-trial/`，由 `S01owrt-native-trial` 启动。没有启用抓包或连续状态采集器，helper 只负责给健康命令设置执行时限。以下保留执行时的规则，当前已清理。

首次十分钟内需要电脑侧确认，现已完成。此后 LAN/WAN、双频无线和 WAN 连通探测构成的健康检查持续失败 **300 秒**，或连续 **3 次**启动未恢复健康，会验证专用 C 原件与恢复工具，准备九组件 C 栈，再强制重启。健康启动连续三次本机探测通过后清零计数。确认不会撤掉后续启动保护。

真机 guard 记录的关键时刻为启动后 11 秒开始保护，231 秒收到客户端确认，237 秒确认健康并清零计数。该保护从 PID1 执行 S01 开始生效；更早的引导或闪存问题仍使用[救援手册](../RUNBOOK_AX3000T_RECOVERY.md)中的 failsafe/TFTP。当前 `/rom` 已是 Rust，C 原件在 `/usr/libexec/owrt-stock/`。

## 证据与失败保留

新鲜配置备份保留 45 个原始成员，新增保护时逐个比较内容与元数据；未被 sysupgrade 保存的原样 `/etc/sysupgrade.conf`，已核对原 ROM 与最终镜像默认值相同。两份新备份均校验 gzip、成员内容和 SHA256，两份离线救援镜像重新验明身份。

guard 的九个分支通过原镜像 shell 与实际 C 恢复工具检查。第一个测试因模拟 `/proc` 缺少 `mountinfo` 被拒绝恢复，原失败记录保留；补齐环境后的最终结果通过。配置恢复/服务迁移、真实原生 PID1 启动加 guard，以及 C/Rust sysupgrade 移交也分别通过隔离测试。这些离线故障演练不冒充物理回退实测。

[机器记录](../../reports/ax3000t-stock-openwrt-25.12.5/NATIVE_DEPLOYMENT_20260929.json)保存身份、样本数、空间和恢复边界。原始启动日志、910 文件哈希、私有配置归档、备份、guard 证据与完整客户端时间线位于 ignored `private/native-deploy-20260929/`，未加入 Git。
