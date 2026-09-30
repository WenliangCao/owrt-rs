# DHCPv4 服务边界阶段

本阶段实现了从受限 UDP datagram 到 DHCP 状态机的无 socket 接线边界。它
不是完整的 `dhcp_reply()`、relay 或 OpenWrt 服务替代，也没有修改物理设备。
目标镜像仍是 AX3000T / OpenWrt 25.12.5 / dnsmasq 2.93-r1 `nodhcpv6`。

| C 源码位置 | 行为与不变量 | Rust 实现 | 验证 |
|---|---|---|---|
| `dhcp.c:130-177,248-250` | DHCP/ PXE 使用独立接收 fd；短于固定 BOOTP 头的 `recvmsg` 结果丢弃；接收数据在有界缓冲中处理；`IP_PKTINFO.ipi_addr` 决定广播判定，`ipi_spec_dst` 保留本地源地址，接口索引必须能解析 | `dhcp::service::dispatch`，明确拒绝 `<236` 或 `>16384` 字节；Linux `receive_once` 保留 pktinfo、peer、IP-header 目的地址和本地地址，并拒绝 interface index 0 | `short_and_oversized_datagrams_are_rejected_before_state`；Linux target check；隔离 loopback `receive_once_admits_loopback_pktinfo_and_preserves_addresses` |
| `rfc2131.c:117-156`; `dhcp.c:248-250` | 只接受 `BOOTREQUEST`、`hlen<=16`、`htype=0` 时 `hlen=0`；DHCP 选项 53 才要求 RFC1048 cookie | `Packet::parse`，由 `dispatch` 统一转为 `DispatchError` | `packet` 单测与 `dhcp::service::tests::malformed_request_is_rejected_without_panicking` |
| `dhcp.c:251-264` | `giaddr=255.255.255.255` 是本地测试扩展：匹配上下文前清零，发送时恢复；普通非零 `giaddr` 经 relay | `Route::RelaySource` / `Route::Relay` / `Route::Local`，保留原值供发送方处理 | `preserves_relay_source_extension_and_normal_giaddr` |
| `rfc2131.c:564-697` | 无消息类型为 BOOTP；BOOTP 要求 MAC，并按静态/动态策略交给 BOOTP 分支；未知 option 53 走 C 的无回复默认分支 | `DispatchKind::Bootp` / `Unsupported`；后续调用 `state::bootp` 与 `encode_bootp_vendor` | `dispatches_bootp_leasequery_and_regular_dhcp`；完整 reply 未接线 |
| `rfc2131.c:877-1055,2360-2557` | PXE vendor 是已配置前缀匹配；4011 专用 fd 也进入 PXE 路径 | `DispatchKind::Pxe`，`Packet::pxe_vendor` 复用前缀规则 | `pxe_listener_and_vendor_prefix_are_explicit_dispatches`；PXE 选单/代理/4011 reply 未接线 |
| `rfc2131.c:1066-1235` | 消息类型 10 为 DHCPLEASEQUERY，ACL/租约查找/响应由 RFC4388 状态实现 | `DispatchKind::LeaseQuery`，后续调用 `lease_query::query` | `lease_query` 原语单测；ACL、wire reply 未接线 |

`Ingress` 是 recvmsg/pktinfo 适配器的输入：监听器类型、接收接口索引和目的
地址是否单播。`Dispatch` 保留借用的 `Packet`、路由和分类；该函数不产生
回复、不变更租约、不打开 socket，使调用方能先完成接口/context/tag/relay
策略，再调用 `state::request`、`state::inform`、`state::decline` 或
`state::release`。这保持了 C 中“先 prune，再 `dhcp_reply`，写租约与 DNS，
最后发送”的所有权边界，避免把未经上下文选择的 datagram 误当成 ACK。

当前未完成的服务合同：Linux 接口变化与桥接别名；真实 UDP 67/4011 listener、端口/权限和
事件循环；relay 上游转发与回复识别；广播、单播、ARP 注入；完整
`dhcp_reply` 的 context/tag/config/FQDN/options/overload；leasefile、脚本和
DNS 同步；PXE proxy/menu、TFTP；procd/ujail/ubus/reload/metrics。现有
`tools/dnsmasq/dhcp_differential.py` 与 `dhcp_state_differential.py` 的 C
oracle 仍只覆盖原语和隔离状态调用，不能将本阶段称为功能等价或生产验收。

验证：

```sh
PATH="$HOME/.rustup/toolchains/1.98.1-aarch64-apple-darwin/bin:$PATH" \
  cargo test --manifest-path components/dnsmasq/Cargo.toml --lib dhcp::service
```

本阶段新增 5 个 dispatch 单测；本次补充了一个真实 Linux `recvmsg`/`IP_PKTINFO`
loopback smoke（仅 `lo`、非特权临时端口），要求通过
`tools/dnsmasq/run_isolated.sh` 执行，当前 macOS 主机未运行该 Linux-only 用例。
目标 musl check 与 clippy 已通过；完整 crate 回归由主代理在整合后运行。
