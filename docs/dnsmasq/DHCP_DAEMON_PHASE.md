# DHCP local daemon 接线

这是一项进行中的组合功能门，不是完整 DHCP 服务等价或生产验收。
`LocalProvider` 把配置、Linux 接收接口、context、状态机、ICMP 与 reply options
接在一起，取代原入口按首个地址池静态构造所有回复的实现。

- `dhcp.c:40–98`：监听 `INADDR_ANY:67`，之后按接口和 `listen-address`
  admission；默认独占绑定，允许广播，`IP_MTU_DISCOVER=DONT`、`IP_TOS=CS6`。
  原来只绑第一个 listen-address 的方式会漏收初始广播，也不能正确服务多接口。
- `dhcp.c:340–364`：`getifaddrs` 快照、`SIOCGIFADDR` primary、必要时 secondary
  优先回调。纯 context 完成与持久状态见 `DHCP_CONTEXT_PHASE.md`；每次请求
  只把所选范围交给状态机，再按源配置 index 保存 epoch。
- `rfc2131.c:2751–2830`：reply timers 来源于实际 Outcome 的租期；netmask、
  broadcast、router、DNS 来自实际 context，只有 DNS port=53 时给默认 DNS。
  1/28 不受 PRL 限制，3/6 受 PRL 限制。实现细节见 `DHCP_REPLY_PHASE.md`。
- ICMP 使用 `IcmpProbe`，包含 C 的缓存、高负载/no-ping/loopback 规则；不再
  无条件把候选地址当成空闲。错误停止本次分配但仍返回 prune/name Outcome，
  主循环记录该错误。明确的 C 行为差异及多 1 个 entropy FD 成本见
  `DHCP_PROBE_PHASE.md`。
- ARP preparation 的 warning 由主循环消费 RuntimeEvent；完整边界与后续证据
  以 ARP 阶段文档为准。

`interfaces.rs` 的 unsafe 限定为 getifaddrs/list 生命周期、if_indextoname 和
SIOCGIFADDR；返回值全部复制为 Rust 值，列表由 RAII 一次释放。`net_abi.c`
验证 Linux 64-bit 布局/常量，已通过构建机 native 编译运行及匹配 SDK 头编译。
隔离 Linux loopback snapshot/primary/无效 ifindex 测试 1/1；证据在
`private/dnsmasq-rewrite/interfaces-20260930/`。SDK wrapper 的 runas.so 预加载
警告不隐藏；该编译退出 0，不代替最终 ELF/APK 构建。

`tools/dnsmasq/dhcp_daemon_smoke.py` 只能通过 `run_isolated.sh` 执行。它在私有
netns 的 67/68 端口上运行真实 daemon，固定源合同预期验证第二个池的广播
DISCOVER→SELECTING ACK、INFORM 空 PRL、T1/T2、mask/broadcast/router、DNS
端口约束、CS6 TOS、独占端口及关闭后重绑。最终已跑版本为 5/5；注入错误租期
得到 1 个已经完成检查通过、1 个失败、exit 1，其余检查未跑不计通过。原始
阶段结果在 `private/dnsmasq-rewrite/dhcp-main-20260930/`。工具已补充 binary/
config/tool SHA256，下一次冻结源码回归使用这个身份版本。

这些是 Rust 主入口组合 smoke；C 原语/context/timer/ICMP 差分分别有独立工具。
**不能将其相加称为完整 C/Rust daemon service differential**。租约文件真实
恢复/持久化、静态 host/tag/FQDN、周期到期和 DNS/hotplug/script 发布、relay/
PXE/leasequery、动态接口完整生命周期及默认权限降级仍是未关闭合同。

当前接口快照每个请求重新读取，另保留一个 ioctl control socket；池数组仍为
当次选中 context 的拷贝。尚无相对 C 的 CPU/吞吐/内存收益结论。这是功能基线，
之后只能在同配置/容量/安全检查下测量并决定是否优化这些成本。
