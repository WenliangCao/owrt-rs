# WAN6 断开撤销报文：精确 C / 最终 Rust 离线对照

**结论：PASS。本次实际输入对应的事件触发、RA 撤销语义及相关报文字段一致，
未发现实质差异。** 此结论满足用户新增的精确 C 对照条件；没有重新解释 Mac
延迟为产品故障，也没有将保留地址写成已经删除。

仅只读源码、既有夹具及现有抓包；未连接物理路由器、未运行新实验或发包，
未修改产品。

## 身份和实际输入

- C：源码 `5d7be43f8b9dec0eb47e245cfab81108bb131273`，Oracle 只读
  `owrt-evidence/ax3000t-stock-openwrt-25.12.5/sources/components/odhcpd`，
  本次重新核对 HEAD；精确 ELF
  `53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82`。
- Rust：最终镜像源码 `6fb236a3d3cae4c1fa2e0c80e8f0aae552437bd2`，
  ELF `589226a178668c0e53fa8db5ff726e2b4e69464f9521355fad229b1862c3043e`。
  本次核对的 router/kernel/main/config 与该镜像源码无差异。
- 实际窗口：旧 LAN GUA 仍在内核，但 deprecated、preferred=0，剩余 valid
  约 6448 秒；WAN 默认路由消失；ULA 仍有效；本机 RA flags=0xc0、默认路由
  override=0、hop limit=64、MTU=1500、preferred/valid 上限=2700/5400。
- 原件：ignored `private/odhcpd-20261018/wan6-withdraw-live-01/`。
  `observations.jsonl` index 77/78 对应内核弃用；`prefix.jsonl` 第16行、包15，
  时间 **2026-10-18 12:51:13.137775 UTC**，是下表的 Rust 实际输出。
  抓包 SHA256：`51014e71df991ad846df6e6cdcbb7194312c505d6d5f332397445d92ce23ced4`。

## 同输入源码推导与实包逐项核对

表中 C 路径相对于其 `src/`；Rust 路径相对于 `components/odhcpd/src/`。

| 项目 | 包15实测 / 两实现同输入结果 | 精确 C 依据 | Rust 依据 |
|---|---|---|---|
| 变化事件 | preferred 变零或默认路由增删后重设 1000 ms RA timer | `netlink.c:219–234,612–613`；`router.c:252–265` | `kernel.rs:69–75,177–198`；`main.rs:470–481`；`router.rs:84–85` |
| IPv6 / ICMPv6 | link-local 源，目的 ff02::1，IPv6 hop limit 255；ICMP type134/code0，内核生成 checksum | `router.c:127–145,658–659,1095–1105`；`config.c:315`；`odhcpd.c:348–355` | `netio.rs:152–155`；`main.rs:251–255`；`router.rs:313–314,382–384` |
| RA header | Cur Hop Limit=64，flags=0xc0，reachable=0、retrans=0 | `router.c:661–684` | `router.rs:315–325` |
| Router Lifetime | **0**：没有默认路由，即使旧 GUA 的 valid 尚未耗尽 | `router.c:324–348,715–717,878–881` | `router.rs:161–188,321–323` |
| PIO 排序 | 有效 ULA 在前、deprecated GUA 在后 | `netlink.c:663–668`，ULA priority1、deprecated GUA priority0 | `kernel.rs:111–122` |
| ULA PIO | 线上 /64，L=A=1（0xc0），preferred2700、valid5400 | `router.c:780–801,815–827,854–856` | `router.rs:201–225,236–237` |
| 旧 GUA PIO | /64，L=A=1（0xc0），**preferred=valid=0** | `router.c:840–851` | `router.rs:216–237`，零初始化后撤销分支不写正寿命 |
| SLLAO / MTU | 本机 LAN MAC；MTU1500 | `router.c:686–693`；`config.c:1553–1565` | `router.rs:326–335` |
| ULA RIO | /48、medium、长度24B、valid5400 | `router.c:330–342,1021–1058` | `router.rs:174–184,340–358` |
| RDNSS | 本机 ULA DNS 地址、寿命5400，**不随 router lifetime 归零** | `router.c:788–812,892–918`；`odhcpd.c:369–403` | `router.rs:201–214,360–369`；`dhcpv6.rs:108–136` |
| Advertisement Interval | 600000 ms | `router.c:351–360,1069–1072` | `router.rs:289,376–377` |
| 选项顺序 / 长度 | 1,5,3,3,24,25,7；ICMPv6 共152B | `router.c:393–407` 的 iovec 顺序及上述选项长度 | `router.rs:326–377` |

RDNSS 仍为5400并非遗漏撤销：两实现都先以旧 GUA **尚存的 valid** 计算
最高有效期，再将该 GUA 的线上 PIO 改为0/0。旧 valid 约6448，按5400上限
截断，因此 DNS5400与 PIO0/0 同时出现。ULA 的 /48 reject route 独立于 WAN
默认路由，RIO 保留同样符合双方路径。

发送后，两实现均恢复正常随机周期，而非按一秒持续重发：C
`router.c:1116–1123`、Rust `router.rs:88–94`。事件的一秒定时规则一致；
没有重新测试已接受的亚毫秒取整差异，也不要求随机间隔样本数值相同。

## 既有精确 C 实包佐证及结论边界

只读重查既有原件，确认 `events.identity.sha256` 均为精确 C 的 `53e534…`：

- `oracle:/home/ubuntu/odhcpd-validation-20261018/c-baseline-05/results.json`，
  `events.wan_down_rs`：router lifetime0、flags0xc0、hop64，旧 PIO0/0，
  当前 PIO2700/5400；原件 SHA256
  `e46b01cc9fe250ba8eedfd0b861e5e2eb91f06a1256196a8e7b1f14cd7e749d4`。
- `oracle:/home/ubuntu/odhcpd-validation-20261018/extended-c-01/finite/results.json`，
  `events.race_unsolicited_withdraw`：无需 RS 的主动 RA 包含旧 GUA PIO0/0，
  L/A 保持0xc0；原件 SHA256
  `1dd973b38a16d21d5c0759c0f5c7b97dc0f336ce9f3bdaa5a6d15edf98a49d2e`。

这些既有夹具分别佐证默认路由删除、旧前缀撤销和主动事件路径；不是本次物理
WAN6窗口的第二份 C 抓包。实际窗口的组合条件由上表精确源码逐项推导，符合
用户允许的源码对照方式。比较涵盖协议字段、选项顺序和寿命含义，不把不同
场景的合成地址或内核 IPv6 flow label 当作需要逐字节相同的常量。

**最终判断仍为 PASS：对于包15的实际 WAN6 断开状态，精确 C 会产生相同的
撤销报文语义；没有发现需要停止后续发布的 C/Rust 撤销差异。**
