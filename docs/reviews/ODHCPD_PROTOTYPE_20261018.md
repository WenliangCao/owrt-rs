# odhcpd-rs 首次完整隔离对照

共同检查 C/Rust 均 20/20，19 个收到的协议报文逐字节相同；同时发现两个尚待
修复的状态接口差异。旧 PD route 清理、拒绝越界 PD route 和 ubus 对象重连三项
明确增强均已实测。此轮不是最终部署或性能验收，没有访问物理路由器。

精确 C SHA `53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
Rust source `0fdd3ffa`，静态 AArch64 ELF SHA
`88bbcc6a93f8227bb67b214a3a757c360e133cef68afc4c12a7134876d2d5652`。
使用 [同一个夹具](../../tools/odhcpd_baseline.py) 和
[C 基线计划](ODHCPD_C_BASELINE_PLAN_20261018.md)，未改变 UCI、协议输入、
事件顺序或判断规则。原件 Oracle `/home/ubuntu/odhcpd-validation-20261018/`
下的 `c-baseline-06`、`prototype-01`、`prototype-02`；本地 ignored
`private/odhcpd-20261018/prototype-01/` 保存归档与双方 results.json。

## 仪器修正

`prototype-01` 在启动时 ENOENT，3秒内无首RA，立即停止。只读定位到提取的
squashfs `/dev` 只有 console，而生产启动会挂 devtmpfs；C 使用 getrandom
未触发缺陷，Rust 显式打开 `/dev/urandom`。在复制的私有 rootfs 内补上 null、
zero、random、urandom 字符节点后，重跑一次 C06 与同 ELF 的 Rust02。无产品
修改，失败轮保留且不作为性能样本。工具的超时清理使用 `unshare --kill-child`。

## 结果与两处差异

- 所有19条收到的 RA/DHCPv6 payload hex 完全相同，未归一化事务ID、寿命、
  地址或选项。共同20项包含前缀零寿命、时区、纯续租/PD不增加trigger等。
- C 在 ULA /62 绑定时额外安装超出 GUA /64 池的route；Rust没有该route。
  C 在前缀变更及Release后残留两条旧PD route；Rust均正确删除。
- ubus重启后 C 的 `dhcp` 对象消失，Rust恢复对象；两者RS仍有回复。本轮未
  证明恢复后每次provider dump/订阅的顺序，也未覆盖ubus断线期间的DHCP续期。
- **待修复：Decline 后 ubus 导出。** `released_state`、`after_hup`、
  `provider_recreated` 中，隔离的NA在两侧都有全零DUID、assigned=`0x9ed`、
  valid=3600。C 的 `ipv6-addr` 仍含两个当前地址，preferred=2700、valid=3600；
  Rust输出空数组。此差异不能被“共同检查全通过”掩盖。
- **待修复：daemon 重启后的导出时机。** 两者内存leases均为空，但C保留旧
  leasefile两行直到后续状态事件；Rust立即清空，并额外调用一次trigger
  （本序列累计C=7、Rust=8）。主线程决定这两处均按C修复。
- 其余文件差异是顺序运行导致的绝对expiry/time值；hosts与普通续租trigger一致。
  原始时间未删除，不能据此推断有限期限行为已经等价。

## 单次时间和同阶段内存

| 观测 | C | Rust |
|---|---:|---:|
| exec前到首主动RA | 1005.182 ms | 1004.608 ms |
| 首RS到RA | 0.210 ms | 0.160 ms |
| 首Solicit到Advertise | 0.664 ms | 0.140 ms |
| 首Request到Reply | 0.358 ms | 0.096 ms |
| 3NA+1PD VmRSS | 1112 KiB | 804 KiB |
| 同阶段RssAnon | 112 KiB | 92 KiB |

Rust RSS为C的72.3%，本序列内存满足两倍边界。时延只留作观测：尚无C/C噪声
标定，不据单点宣称最终“首包不慢”。没有热循环、PGO或性能选优。

复跑命令只改变 ELF 和全新输出目录：

```sh
sudo -n python3 tools/odhcpd_baseline.py \
  --rootfs /home/ubuntu/owrt-v023-20261017/private/native-final-0a925bcc/rootfs \
  --daemon /home/ubuntu/odhcpd-target-20261018/aarch64-unknown-linux-musl/release/odhcpd-rs \
  --out /home/ubuntu/odhcpd-validation-20261018/prototype-new
```

## 下一步固定验收计划（尚未实施）

成本模型仍是首主动RA的1秒timer、事件循环调度与包/文件操作；本轮主要降低了
协议集成的不确定性。下轮先验证两处状态差异的修复，然后把剩余风险压成同夹具
四个独立case，不能用正常NA路径替代边界：

1. 有限preferred/valid、所有PD池消失、Renew/Rebind旧前缀、Release/Decline后
   路由和导出；Confirm在链上/不在链上、未知绑定。每个动作记录包与内核状态。
2. LAN down/up、ifindex替换、link-local替换；PIO跨daemon重启、损坏/过期文件。
   验证旧socket不继续发包，旧PIO零寿命与新PIO有效性。
3. `add_lease`合法/非法输入、provider删除/重建与带计数dump、ubus断开期间
   RA和DHCP继续服务、重连后新对象/订阅/数据生效。乱序或旧dump不得覆盖新状态。
4. 未支持的NDP/relay/hybrid/有效DHCPv4在服务前明确拒启；本机maindhcp=0共享
   dhcpv4=server正常启动。畸形TLV、错误server-ID、单播/错误RS无状态污染。

每case新目录，输入/预期先写入工具，失败保留，只重跑受影响项。当前暂停扩展，
等待主线程分配，避免并行改同一工具。

正式时延/内存方法预案：先在目标环境以精确C做3组C/C成对冷启动，记录相同阶段
首主动RA、首RS、首DHCP回复的自身差值和范围；相同间隔、相同配置/地址、相同
事件顺序，不清全机cache或改governor。随后固定3组C/R成对启动，交替先后顺序，
不额外挑样。判断使用实际C/C波动范围和clock分辨率，不设固定微秒门；超出噪声
的变慢立即报告，落在噪声内写“本轮不可分辨”，不宣称测到改善。协议等待与包
处理等待分列。内存在0租约、3NA+1PD、前缀变更及ubus重连四个固定阶段读取
VmRSS/RssAnon，按相同阶段比较，门仍是Rust RSS不超过C的2倍。最终物理路由器
验证须另按项目恢复门授权；Oracle单点不代替该门。
