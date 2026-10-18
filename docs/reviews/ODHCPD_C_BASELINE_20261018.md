# odhcpd 精确 C 隔离基线

20 项协议/状态检查通过；C 的旧 PD 路由残留和运行时 ubus 不重连均已复现。
这是 Oracle 上的功能基线，尚未运行 Rust，也未通过物理路由器首包/内存验收。

固定产物是现役 v0.2.3 rootfs 中的 C odhcpd，SHA256
`53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`；
匹配源码 `5d7be43f8b9dec0eb47e245cfab81108bb131273`。工具是
[odhcpd_baseline.py](../../tools/odhcpd_baseline.py)，最终运行使用的脚本 SHA256
`c82ee8da08e5432e00009ecdfc3da51664fd2294fe5f133f3fb405cebffb83fb`。
原件位于 Oracle `/home/ubuntu/odhcpd-validation-20261018/c-baseline-05/`，
本机 ignored `private/odhcpd-20261018/c-baseline/` 留存全部轮次包/文件/日志。

## 环境和单次首包观测

Oracle Linux 6.17/aarch64，独立 mount/net/PID namespace，复制 rootfs，私有
`/tmp` tmpfs、只读 sysfs、私有 ubusd 与 ucode netifd provider。真实 veth
客户端处于第二个 netns；无产品 socket mock，无物理路由器访问。UCI 使用本机
模式、12h 租期、loglevel=4、POSIX/TZDB 时区；仅地址/MAC/DUID/触发脚本为固定
合成输入。客户端固定 link-local，内核 GUA /64、ULA /60 为无限期限。

| 记录 | 最终固定序列 |
|---|---:|
| daemon exec 前时刻到首主动 RA | 1003.665 ms |
| 首 RS 发出到 RA 收到 | 0.223 ms |
| 首 Solicit 到 Advertise | 0.481 ms |
| 首 Request 到 Reply | 0.320 ms |
| Information Request 到 Reply | 0.162 ms |
| 3 个 NA + 1 个 PD，VmRSS / RssAnon | 1112 / 116 KiB |

使用 `CLOCK_MONOTONIC`，报告分辨率 1ns；原始包 hex、发送/接收时间和 RA
hoplimit ancillary 均保留。计时包含客户端调度、内核路径和协议处理；首主动 RA
包含 exec/初始化。单次不估计噪声，不能据此设微秒门槛或宣称候选更快。
后续比较需要同条件 C/Rust 对照，不以这些单点替代正式时间/内存门。

## 已覆盖与发现

- 首主动 RA、RS、M/O、默认路由存在/删除；GUA 与 ULA 线上 PIO 均 /64，
  ULA reject route 产生 RIO。默认路由删除后 router lifetime=0，PIO/DNS 保留。
- NA 与 PD 四步、NA 续租、Rapid Commit、多 IAID、Information Request、未知
  Renew 的 NoBinding、单播 Renew 的 UseMulticast；PD 仅从 ULA /60 返回 /62。
- 12h 本机时区选项 41/42、leasefile、hosts、trigger。初始空映射和首个命名 NA
  各触发一次，纯续租和纯 PD 不增加 trigger。
- 连续有池的前缀 A→B（先 add B 再 del A）：旧 PIO、旧 IA_NA/IA_PD 返回零寿命；
  新前缀有效。Release 删除当前 PD route，Decline 正常返回；旧 PIO 经 daemon
  重启后仍发送零寿命。SIGHUP、provider 对象重建和 ubus 重启也保留观测。
- C `__apply_lease()` 没校验来源前缀长度，绑定 ULA /62 时额外安装超出 GUA /64
  池的 /62 route。M flag 开启时，前缀变化未删旧 PD route，Release 也只删当前
  前缀对应 route。Rust 必须满足用户的正确撤销要求，不能复制这两个 C 缺陷。
- C 运行时 ubus 重启后 `dhcp` 返回 Not found，RS 仍得到回应；Rust 的重连是
  有意增强。当前 provider 重建记录证明对象/协议仍可用，尚未用 dump 计数证明
  每次重订阅，不能将其写成完整生命周期通过。
- 无限期内核地址有一个源码边界：IAADDR/IAPREFIX wire preferred/valid 是
  43200 秒，T1/T2 仍为 1350/2160；`dhcpv6-ia.c:657,664` 只给有限内核期限
  做 max clamp。内部租约期限仍受 2700/5400 floor 限制。不能将 RA 的
  2700/5400 直接套到无限期地址的 DHCP wire。
- PIO 文件与 `dhcp.ipv6ra` 的 prefix 保留接口地址 host bits；线上 PIO 才清零。
  文件/JSON比较不得悄悄清零来隐藏差异。

## 仪器修正与保留范围

没有选择性删掉失败轮。01 在复制设备文件时停住，尚未启动服务；改用 `cp -a`。
02 功能跑通，但 `/tmp` 在磁盘上，fsync 使 DHCP 等待明显增加，不用于时间比较。
03 改为私有 tmpfs并固定 link-local，确认先 del A 再 add B 的短暂无池窗口可令
C 丢弃 PD 绑定并返回 NoBinding，原件保留为不同事件序列。04 固定 replacement
为 add B→del A，20项通过，仍是诊断 loglevel=7。05 只还原实际 loglevel=4，
为最终复用基线。未修改产品、未跑热循环、未做 PGO 或性能选优。

## 复用及尚未验收项

在 Oracle 以全新输出目录运行（必须不存在）：

```sh
sudo -n python3 tools/odhcpd_baseline.py \
  --rootfs /home/ubuntu/owrt-v023-20261017/private/native-final-0a925bcc/rootfs \
  --out /home/ubuntu/odhcpd-validation-20261018/c-new
```

候选加 `--daemon /absolute/path/odhcpd-rs`，只替换复制 rootfs 内的 ELF。每次
最多180秒，失败保留结果；`--summarize results.json` 只重放离线检查，不发包。
`results.json` 的 checks 是共同协议要求，`observed_boundaries` 单列 C 差异，
不把 C 的残留路由/不重连当作 Rust 必须复刻的断言。

仍需在同夹具扩展：有限寿命到期、无PD池/耗尽、NA+PD同包、Rebind/Confirm、
畸形TLV/错误server-ID、add_lease、非法模式拒启、损坏PIO、明确provider dump/
订阅计数、ubus断线后的DHCP服务与状态同步。这一基线不宣称合同全量验收完成。

当前模型得到支持：主动 RA 由1秒timer主导，DHCP的文件持久化介质会显著影响
首回复。下一步最有信息量的工作是将 Rust ELF 接入同一套真实包与内核状态序列，
先看语义差分和明确增强，再冻结同条件首包/内存比较；不依据单点展开性能优化。
