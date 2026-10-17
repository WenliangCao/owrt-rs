# odhcpd-rs：本机服务范围与实施边界

v0.2.3 已完成发布、上机及恢复验收；本任务不修改该版本的镜像/标签。当前先在
独立 Linux namespace 实现和对照，生产仍运行精确 C odhcpd。遵守 AGENTS.md：
Rust 构建/测试只在 Oracle 或 CI，备份/固件/实际客户端数据只进 ignored private/。

精确 C commit `5d7be43f8b9dec0eb47e245cfab81108bb131273`，运行/ROM/镜像 ELF
SHA `53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
匹配源码是行为参考，现役只读观察是配置权威；不是改用上游 master 或新协议解释
来扩大范围。接口、调用方、失败边界已在 [控制合同](../contracts/odhcpd-control.md)、
[RA 合同](../contracts/odhcpd-ra.md)、[DHCPv6 合同](../contracts/odhcpd-dhcpv6.md) 固定。

## 实际输入与功能范围

- LAN：RA server、SLAAC、显式 M/O flags、DHCPv6 server，租期 12h；实际内核
  有 GUA /64、ULA /60 和 link-local /64。RA 的 ULA PIO 发 /64，状态仍保留 /60。
- global：maindhcp=0，leasefile=/tmp/odhcpd.leases，hostsdir=/tmp/hosts，
  piodir=/tmp/odhcpd-piodir，leasetrigger=/usr/sbin/odhcpd-update，loglevel=4。
- 3 个 IA_NA、0 个 IA_PD、0 个静态 host；IA_PD 仍是用户明确要求，不能省去。
  当前客户端均未接受 Reconfigure；首版不提供其认证/主动推送，也不假装接受。
- system 配置了 POSIX timezone 和 TZDB zone；C enable_tz 默认开启，两个 DHCPv6
  字符串选项属于有效本机行为。实现它们，不引入时区数据库。PXE/NTP/DNR/PREF64
  等未用扩展不加入本版，也不得将其配置静默标为支持。
- shared UCI 的 dhcpv4=server/start/limit 属 dnsmasq；maindhcp=0 时 odhcpd
  有效 v4 模式 disabled。拒绝真正启用 odhcpd DHCPv4，以及 RA/DHCPv6 relay/hybrid
  和 NDP 代理配置。保留内核 NDP，不实现用户态代理或中继。

只读 intake 原件在 `private/odhcpd-20261018/intake/`。首次内存单点：C RSS
1132 KiB、RssAnon 136 KiB；这是当前状态背景，不代替最终同条件内存对照。

## 简单实现分工

一个普通 poll 事件循环：直接 socket/rtnetlink、现有 owrt-uci/owrt-ubus，沿用
init、odhcpd-update、dnsmasq 和 netifd 协议脚本。不加异步框架、持久数据库或
通用服务层。小型共享类型只表示 IPv6 前缀、内核地址/路由、接口和时钟。

1. config/control：UCI 读取及显式拒绝边界、dhcp 三个 ubus 方法、netifd dump/
   subscribe 生命周期。断线重连后重建对象和订阅；不能继续沿用失效 object ID。
2. RA：报文字段、RS 校验/回复、主动广告调度、默认路由消失、旧 PIO 零寿命及
   piodir 原子保存/恢复。实际地址/期限权威来自 rtnetlink，不只复制 WAN dump。
3. DHCPv6：NA/PD 分配与请求状态、默认和有效 DNS/时区选项、leasefile/hosts/
   leasetrigger、旧地址/前缀零寿命、PD 路由跟踪和撤销。只复用低层传输。
4. runtime/kernel：包 ancillary data、ifindex/设备生命周期、netlink dump/event
   及丢包重同步、信号与上述模块的直接连接。任何配置拒绝在对外服务前发生。

参考 C 的两个边界必须在报告保留：其运行时 ubus 不自动重连，Rust 明确增强；
其 M flag 条件可能漏删旧 PD 路由，不能照抄这个条件来声称满足正确废止。租约
文件是导出而非 DHCPv6 重启恢复数据库；PIO 目录位于 tmpfs，只承诺进程重启恢复。

## 验收与实验纪律

成本模型：首主动 RA 主要是 C 固定 1s 定时器；RS/DHCPv6 回复是包处理和系统调用；
内存是常驻代码页、配置/租约/前缀状态。先完成真实 C 包/状态对照，再测候选；
不把热循环 CPU 或省进程数代替首包时间，不设固定微秒门槛，不训练 PGO。

冻结一次可复用的 C/Rust 隔离输入：相同 UCI、内核地址/路由、虚拟客户端和控制
事件，保留真实报文、文件、ubus 输出与单调时钟。只归一化非语义的事务 ID/时间，
不抹平地址分配、选项、寿命、状态码或路由差异。每个实验先记录预测、仪器分辨率、
样本和停止条件；功能失败原件保留，修复后只重跑受影响项。

必须通过：首主动 RA、首 RS 回复、首 DHCPv6 回复不慢于同条件精确 C；WAN down/
前缀变化时旧 PIO 和 IA 正确废止、旧 PD 路由撤销；同条件内存不超过 C 两倍；
ubus 断线重连后对象、订阅、dump 和前缀同步恢复。覆盖无 /64 下游 PD 容量、ULAs、
寿命到期、Release/Decline、多个 IAID、重复通知、配置拒绝、状态文件和 trigger。
网络等待/协议计时与处理成本分开报告，任一未验证项不得写成完成。
