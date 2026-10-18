# odhcpd-rs 独立审计（Fable，2026-10-18）

**结论：当前候选还不能替换 C 上线。** 在并行审计已确认的 2 项 P1、6 项 P2 之外，
本次新增 **1 项 P1、1 项 P2、3 项 P3**；三组并行修复中 `fa882f1c`、`9be8f5fc`
复核成立，`e33fa56c` 成立但留有两个缺口（即新增的 P1/P2）。性能与资源没有阻断项。
修复后必须用新 ELF 重走 82 项实包夹具和短时真机试运行，旧 ELF 的 125 s 结论不可转授。

## 范围与方法

- 起点 `d4f59f4e`（协议源码等同 `d0ef9f04`），审计期间并行会话推进到 `4908d026`；
  下列结论均已按 `4908d026` 源码复核，行号指该提交。
- C 参考 `5d7be43f8b9dec0eb47e245cfab81108bb131273`，逐函数对照
  `router.c`、`dhcpv6-ia.c`、`dhcpv6.c`、`ubus.c`、`netlink.c`、`config.c`、`odhcpd.c`。
- 通读全部 6.9k 行 Rust；两条复现用 `cargo test` 在 Oracle 独立目录
  `/home/ubuntu/odhcpd-audit-fable-20261018`（`components/odhcpd/tests/audit_repro.rs`，
  未提交）对 HEAD 源码运行，同目录产品单测 47+5 项通过。
- 只读路由器一次：`ubus call network.interface dump` 8,217 B，空载；未改任何设备状态。
  读取了 `private/odhcpd-20261018/intake/network-dump.json` 的字段类型，不摘录地址。
- 没有新性能样本、PGO 或 Mac 构建。

## 新发现

### F-1 / P1：netifd dump 里一个无 `config dhcp` 段的 DHCP 客户端接口使整份配置失效

位置：`config.rs:250-266`（未知接口也走严格 `apply_pool`），`config.rs:317-340`
（`text()` 对整数值返回错误），`main.rs:258-292`。

本机 intake dump 中 `wan` 的 `data` 为 `{dhcpserver: string, leasetime: int}`；
`udhcpc` 的 `dhcp.script` 固定写入整数 `leasetime`。它今天没有触发，只因为
`/etc/config/dhcp` 恰好有 `config dhcp 'wan'`（禁用池，跳过解析）。删掉这一段，
或新增任何没有 dhcp 段的 DHCP 客户端接口（`wwan`、中继口等），`apply_network`
即返回 `leasetime: expected string`。C 的 `ubus_apply_network → config_parse_interface`
用 `blobmsg_parse` 解析，类型不符当作缺省，逐接口失败也不影响其他接口。

后果随版本不同：`e33fa56c` 之前 `reload()?` 把错误抛到 `run()`，退出 4，procd 重启，
重复失败后 procd-rs（`procd/src/main.rs:367`）停止重启；`e33fa56c` 之后 `reload()`
把整份 dump 当作“配置被拒绝”保留旧配置，但启动时 pool 还没有 `l3_device`，
于是**永远不会创建 RA/DHCPv6 服务**，只有一条 warning 日志。

复现（HEAD 源码）：

```rust
let mut config = Config::from_packages(&dhcp_with_lan_server, None, None).unwrap();
let data = json::parse("{\"dhcpserver\":\"192.0.2.1\",\"leasetime\":60}").unwrap();
config.apply_network(&[NetworkInterface { name: "wwan".into(), device: Some("eth1".into()), up: true, data }])
// => Err(ConfigError("leasetime: expected string"))
```

修复方向：对没有 UCI 段的接口只解析决定模式的字段（`ra`、`dhcpv6`、`ndp`、`master`、
`ifname`），类型不符一律视为缺省，与 `blobmsg_parse` 同义；`apply_network` 按接口
粒度跳过并记录错误，不让单个接口否决整份 dump。回归至少要把 intake 形状的 `wan`
data 放进 config 单测和 `odhcpd_baseline.py` 的 provider dump（现夹具 dump 只有 lan）。

### F-2 / P2：同一设备上两个启用池仍会让进程退出

位置：`main.rs:294-313`（`services()` 返回 `Err`），上抛 `main.rs:289`（`reload`）、
`main.rs:465`（`refresh_kernel`）到 `run()`。

`e33fa56c` 只把 socket 打开失败和配置解析失败改为局部容错，这条校验仍是
`io::Error` 并被 `?` 传到主循环。触发输入是常见的别名接口（如 `lan6` = `@lan`）
再配一个 `dhcpv6 server` 的 dhcp 段：两个池的 `l3_device` 都是 `br-lan`，dump 一到
进程退出 4。C 对每个 iface 分别 setup，不退出。拒绝这种配置可以保留，但应和其他
配置错误一样走“拒绝 reload、保留现役服务”的路径：把检查并入 `apply_network`
之后、替换 `self.config` 之前的校验，而不是在 `services()` 里以错误返回。

### F-3 / P3：单条非法静态 host 让整份配置不可加载

位置：`config.rs:605-669`，调用链 `Config::load → from_packages → host_from_json`。
奇数长度 DUID、非法 MAC/IP/名字中的任一条都使 `Config::load` 失败：启动时退出 4
（随后 procd 停止重启），reload 时整份新配置被拒绝。C `set_lease_cfg_from_uci`
只跳过该条并记日志。复现：`config host` + `option duid '0001000123456'`
→ `Err(ConfigError("invalid hexadecimal value"))`。LuCI 的输入校验让它不常见，
故 P3。修复方向：host 段按条跳过并记录，其他字段保持严格。

### F-4 / P3：订阅通知没有按 `ignore` 过滤

位置：`control.rs:301`。C `ubus.c handle_update` 对 `ignore=1` 接口（本机 `wan`）
的通知不重新 dump；Rust 任何通知都 dump，随后 `reload()` 重读 UCI、三次 netlink
dump 并在 1 s 后发一条主动 RA。本机 netifd-rs 对 wan 续租不发 `interface.update`
（`DHCP_EVENT_REBOOT_20261017.md`：0 次），所以今天没有可见影响；换回 C netifd
或出现频繁更新的 ignore 接口时会放大 reload/RA 频率。修复方向：配置保留 `ignore`，
worker 解析通知的 `interface` 字段后决定是否置 `dump_needed`。

### F-5 / P3：ubus worker 的 100 ms 单一期限覆盖 netifd dump

位置：`control.rs:18`、`control.rs:255-258`；`owrt_ubus::request_with_data` 用一个
期限覆盖发送和全部回复帧。dump 超时即拆掉整条会话（`dhcp` 对象消失、1 s 后重连再
dump）。若开机高负载下 netifd-rs 的 dump 持续超过 100 ms，守护进程会在没有
`l3_device` 的状态下反复重连而始终不服务。空载路由器 dump 为 8.2 KB，BusyBox
`date` 无毫秒分辨率，开机负载下的耗时未测。修复方向：dump/invoke 用 1–3 s 期限，
100 ms 只留给 reply/notify；或 dump 失败不拆会话、按退避重试。

## 对并行修复的复核

- `fa882f1c`（CR-1）：改为“先读 1 字节再 `try_recv`”。不变量是“socket 字节数 ≥
  队列事件数”，唯一例外是 worker `try_send` 与 `write` 之间的瞬时窗口，而此时
  `try_recv` 必能取到该事件；多余字节只造成一次空唤醒，32 条 drain 预算用尽后仍有
  字节可唤醒。成立。
- `e33fa56c`（CR-2/CR-3/RA-1/KERNEL-1）：socket 失败按接口隔离并在任何内核事件或
  reload 时重试；errno 4/11/16/105 的快照错误一秒后重试，期间 `reconcile` 跳过以免
  用旧路由表否定刚 ACK 的 PD 路由；`pending_config` 与 `add_lease` 保序；
  `hop_limit` 改为每包读 sysctl，与 C 一致。成立，但 F-1、F-2 两条仍能让整份 reload
  失效或进程退出。
- `9be8f5fc`（DHCP-1/DHCP-2）：每次成功回复重解析 host 覆盖或池默认租期而不改已承诺
  的 deadline；地址选项按 IA 类型编码，IA_PD 的 `/128` 撤销为 IAPREFIX。单测覆盖
  NA/PD × 三种 host 策略。成立。

## 已核对、与 C 一致而不列为缺陷的点

- NA IID：DUID 末 6 字节作 `jrand48` 种子、两次取值拼 64 位（第二次 `& UINT32_MAX`）、
  `0x100 + try % size`、保留 IID 与 hostid 跳过、顺序探测 100 次，逐项与 `assign_na` 一致。
- 无 Rapid Commit 的 Solicit 把已绑定租约降为 60 s offer：C 同样 `bound=false,
  valid_until=now+60`。
- `br-lan` 失去 IFF_RUNNING 时清空全部租约、关闭 RA socket 并发最终 RA：C
  `handle_rtm_link → reload_services → dhcpv6_ia_setup_interface(false)` 同样释放。
- PD 路由网关只在租约创建时记录 `peer`：C 唯一赋值点 `dhcpv6-ia.c:1210`。
- RA：`maxival = min(ra_maxinterval, 最短 valid)`，`max < min` 时的无符号回绕让间隔
  随机到 2^31 ms——两边同一怪癖，最长持续到该地址过期触发新事件；`RouterLifetime`
  5400、前三条 16 s 上限、RDNSS/valid_prefix/RIO 规则、PIO 排序与去重均一致。
- DNS 地址选择与 `odhcpd_get_interface_dns_addr6` 一致；信号用 musl `signal()`
  带 SA_RESTART，netlink 阻塞 recv 不因 SIGHUP 变成 EINTR 退出。

## 性能与资源

成本模型：空闲时每秒一次唤醒做到期清理（C `valid_until_cb` 同为 1 s）；每次 netifd
通知一次 reload（重读 3 个 UCI 文件、3 次 netlink dump、解析 8 KB JSON），1 s 后一条
主动 RA。本机 WAN6 ifupdate 5 分钟 23 次（中位间隔 3.8 s），RA 频率由此决定，
C 相同，试运行客户端 2 分钟收到 5 条 RA 与此吻合；这是既有网络特征，不是 Rust 回归。

| 同夹具（Oracle，已有批次） | C | Rust |
|---|---:|---:|
| 首 RS→RA / 首 Solicit / 首 Request 中位 | 0.251 / 0.431 / 0.427 ms | 0.167 / 0.180 / 0.141 ms |
| exec→首主动 RA | 1002.7 ms | 1003.7 ms（用户已接受） |
| VmRSS 四阶段 | 1116–1132 KiB | 812–820 KiB |
| RssAnon | 108–116 KiB | 84–92 KiB |

Rust 多一个 128 KiB 栈的 worker 线程，静态 ELF 790 KB。按模型估计每次 reload 在
A53 上低于 5 ms CPU，占比低于 0.1%；真机 CPU 未直接测，但没有需要性能轮的信号。

## 上线判定与剩余步骤

1. 修 F-1、F-2（必需），F-3～F-5 建议同批；修复都在 `config.rs`/`main.rs`/`control.rs`
   的错误处理边界，不涉及协议报文。
2. 新 SDK ELF 重跑 baseline 20 + extended 62、`4c4339b5` 的 reload/LuCI 夹具，
   并把 F-1 的 dump 形状与 F-2 的别名池加入夹具。
3. 再做一次短时真机试运行后，才讨论 v0.2.4 刷机。
