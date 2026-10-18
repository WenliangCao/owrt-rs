# odhcpd-rs 真机短时试运行

**试运行通过：13 个客户端健康样本连续通过 124.986 秒，随后已恢复 C。**
当前固件仍是 v0.2.3；这不是 v0.2.4 刷机或正式发布结果。

用户接受[已记录的首主动 RA 时间差](ODHCPD_LATENCY_PLAN_20261018.md)，授权本次
短时试运行。候选为 source `d0ef9f04` 的精确 SDK ELF，790640 字节，SHA256
`79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55`，与此前
[20＋62 项隔离功能资格](ODHCPD_PROTOTYPE_20261018.md)使用的字节一致。

## 客户端验收

通过[客户端工具](../../tools/odhcpd_client_health.py)从实际 Mac `en0` 检查；
每个样本均验证 procd 管理的候选 PID、启动代次与真实 `/proc/PID/exe` 哈希。
整个窗口是同一候选进程，`dhcp.ipv6ra` 和 `dhcp.ipv6leases` 正常。

- 所有13个样本均有可用GUA、ULA及经`en0`的IPv6默认路由。
- `ipconfig getra` 记录5个不同的激活后接收时刻，分别约在激活后2、14、20、
  55、118秒；RA源属于路由器LAN，router lifetime有效。这证明实际客户端收到
  了候选RA，不只是路由器端生成了包。这些不是独立首包性能样本。
- 直接以客户端IPv6地址为源，向收到的RA RDNSS执行TCP/IPv6 DNS AAAA查询，
  每次成功。系统DNS继续使用本机代理；没有修改或宣称绕过该配置的日常行为。
- 绑定`en0`的IPv4/IPv6外网HTTPS均成功；双栈LuCI HTTPS返回正确静态内容哈希。
  现有全健康门同时验证WAN/WAN6、DHCPv4客户端租约、两个无线AP及桥、watchdog、
  路由器DNS/HTTPS和本地HTTP/HTTPS。
- DHCPv6只读取现有地址与`ipconfig getv6packet`缓存回复，没有主动Renew、
  重新配置客户端或制造断网。本次不能单独证明真实客户端完成了新的DHCPv6交换；
  DHCPv6协议动作的覆盖来自隔离资格，不能混写为本机主动验收。

## 恢复与证据

激活前已有离线备份和经过[隔离验证的守卫](ODHCPD_TRIAL_GUARD_20261018.md)。
本次300秒守卫只临时绑定替换odhcpd、通过原init管理该服务；确认健康后执行恢复。
最终状态为`restored-confirmed`，恢复的C ELF SHA256为
`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。

恢复后完整v0.2.3 native客户端健康门通过，boot ID与原十组件manifest身份未变；
配置备份前后SHA256完全一致，即归档逐字节相同。临时试运行目录和锁已清理。
没有刷机、重启整机或将临时绑定作为永久安装。

原始证据仅保存在 ignored `private/odhcpd-20261018/trial-live-01/`。离线复核
确认健康凭据绑定JSONL哈希、13条pass后正常complete、无failure；设备归档24个
文件逐一匹配保存的哈希，包含候选/C ELF、守卫状态与恢复记录。公开报告不包含
客户端地址、DUID、MAC、PID、boot ID或试运行token。

本结果允许继续下一版本集成；该版本的最终镜像资格、刷机和正式发布仍须各自完成。
没有追加性能轮，也没有把用户接受性能差异改写成原性能门已通过。
