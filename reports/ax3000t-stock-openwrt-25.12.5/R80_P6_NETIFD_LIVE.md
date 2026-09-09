# R80：P6 完成 —— netifd-rs 是设备的常驻网络管理器

> 2026-09-09 21:02:57 确认。候选 netifd-rs md5 `86c4e1641a4af2ab1f215de323a3ee6b`
> （提交 00dee60 的树，oracle `~/netifd-r59`，cargo 1.98.1，aarch64-musl）。
> **终态：/sbin/netifd = netifd-rs，C 原件保留在 `/sbin/netifd.c-orig`（031a542b，= /rom）。
> 回退 = `mv /sbin/netifd.c-orig /sbin/netifd` + reboot；failsafe 走 /rom。**
> 至此设备控制面全部为 Rust：uci、reload-config、logd、httpd、fw4、rpcd、procd（PID 1）、ubusd、netifd。

## 四次窗口，两处只有真机才暴露的缺口

| # | 时间 | 候选 | 结果 | 根因 |
|---|---|---|---|---|
| 1 | 15:26 | ebee54cb | 有 Wi-Fi 无网，canary 480 s 回退 | DSA 口 16 s 才注册，rs 只在建桥时 enslave 一次，br-lan 空、lan 不上（R78 修） |
| 2 | 19:27 | 60dcff02（接手会话） | **网络全健康**，无人 confirm，480 s 回退 | 确认环节：写报告的会话已断（R79 补记） |
| 3 | 20:30 | 60dcff02 | 有 Wi-Fi 无网：客户端有租约、`dig @路由器` 无应答，路由器本地查询 REFUSED | rs 从不写 `/tmp/resolv.conf.d/resolv.conf.auto`，dnsmasq 无上游（00dee60 修）；手动 undo 回退 |
| 4 | 20:58 | **86c4e164** | **T0+60 s 首过、连续 183 s 全过、T0+243 s confirm** | — |

窗口 #3 的探针只报了"fail"没记原因，浪费了一轮；编排器现在把探针的 `{"error": …}` 记进日志。

## 窗口 #4 证据

- 编排器 `tools/p6_window.sh` 脱离会话运行（`nohup`），全程日志 `/tmp/p6-window.log`：
  预检 C 启动探针过 → 上传到持久 /root 并核 md5 → stage（900 s canary）→ reboot →
  T0+60 s ssh 可达并首过 → `p6_client_probe.py` 每 15 s 一次连续 183 s 全过（本机 DHCP 租约、
  经路由器的 A/AAAA 解析、经路由器 Wi-Fi 的 IPv4/IPv6 HTTPS、双 AP 在 br-lan、运行中 netifd
  = 候选）→ confirm → 30 s 后复核再过。
- 设备终态（up 4 min）：40 个 ubus 对象**与 C 基线逐行相同**、14 running、双 AP、5 客户端、
  5 租约；`resolv.conf.auto` 与 C 写出的**逐字节一致**（wan/wan6 各两条 nameserver +
  `search hotzone.de`）；br-lan 成员 lan2 lan3 lan4 phy0-ap0 phy1-ap0；本次启动 netifd 0 错误、
  0 次 hostapd/netifd 重启。
- 期间用户观察到的三次断网 = 窗口 #3 重启、手动回退重启、窗口 #4 重启，均为有意操作；
  confirm 后无重启。

## 离线门槛（候选 86c4e164，全部一次通过）

148 单测；套件 24/24（含 r64 晚到端口、r79 无线数据面）；r63 设备真配置 up/down/absent/late/
late16 五档 identical（late 夹具改为端口 admin-down 后确定性绿，见 R79 补记）；
`p6_switch_selftest` 四模式；r49/r52 新增 resolv.conf.auto 逐字节比较且非空；
红证：缺写入的 60dcff02 在 r49 恰好红在该段。

## 记录在案

- **路由器自检 ≠ 客户端可用**：窗口 #2 的 T+300 快照显示一切健康，窗口 #3 同一状态下客户端
  没有 DNS。验收必须站在客户端做（本机租约、经路由器解析、经路由器出网）。
- **确认动作不能依赖聊天会话**：控制机在被测路由器的 Wi-Fi 上，重启必然断会话；窗口 #2 因此
  丢掉一个好候选。编排器脱离会话 + 设备侧 900 s 自动回退，两边兜底。
- **ubus 状态齐 ≠ 文件写了**：wan 的 dns-server 在 ubus 里是齐的，文件却是 0 字节。r49/r52 此前
  只比 ubus 与内核，从未比过 netifd 写出的文件。
- 设备 /root 里保留：`p6-switch.sh`（当前版）、`netifd-rs`（86c4e164 副本）、窗口 #2 的证据文件；
  接手会话留下的 `p6-switch-final.sh` 是同一脚本的旧名。
