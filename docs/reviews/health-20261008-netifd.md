# 2026-10-08 WAN6 输入回放与 netifd 修复

结论：13 个捕获输入中的 5 个已经省略 WAN GUA，全 C 栈也有同类症状；尚未证明具体上游触发因素，也未排除真实网络反馈。隔离回放发现两个 **我们的兼容缺陷**：遗漏 offlink 子网的 unreachable route，以及 PD 下游的 source unreachable rule。初次修复提交 `1cabb7fc`；最终审查又发现自然到期会使新增规则残留，必要的 PD timer 修复为 `d72928c9`。这些差异均不是此次地址抖动已证实的根因。

## 参考与边界

- 分支基于部署源码 `a4053dd5`；没有引入 main 的 dnsmasq 或 ubus 改动。
- C oracle 是 OpenWrt 25.12.5 镜像 `/sbin/netifd`，SHA-256 `8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90`；源码参考为 `cbb83a1857407a28a63dc09412a1f209195914ef`。
- 执行主机为 oracle，aarch64，Linux `6.17.0-1020-oracle`。C/Rust 分别使用独立 PID/net/mount namespace 与独立 rootfs 副本；未操作物理路由器。
- 原始捕获及完整内核/ubus/日志结果保存在主仓库 `private/health-20261008/netifd/` 和 oracle 的 `/home/ubuntu/health-20261008-netifd/private/`，不进 Git。公开清单为 [health-20261008-netifd.json](health-20261008-netifd.json)。

## 已关闭项

LAN 前缀顺序在 `a4053dd5` **已经修复**：祖先提交 `d7bfcf83` 将 ULA/协议前缀更新改为 C `list_add` 头插，保留独立 WAN vlist 排序。`ip.rs` SHA-256 与 9 月 29 日验证清单一致（`a5b55593…`）。当前回放的 LAN `ipv6-prefix-assignment` 顺序与 C 相同；不是需要再修一次的问题。

C `interface-ip.c:717–775` 给 offlink 非 host 地址配置优先级 `2147483647` 的 unreachable subnet route；Rust 原来只写 `IFA_F_NOPREFIXROUTE`。C `interface_set_prefix_address()` 给有上游归属的下游 assignment 配置优先级 `4200000000`、源前缀与输入设备受限的 unreachable rule；Rust 原来没有这条规则。两项都用于阻止不匹配流量回到默认上游。

原始 13 输入回放的 r2 红差分连跑 **4/4 一致**：每步少 6 条 offlink null route、少 1 条 PD source rule；地址、flags、sysctl、ubus 和 hotplug 内容相同。注意 5 次 GUA 缺席时 C 仍保留其 null route：匹配 C 的旧地址删除分支在设置 `v6` 之前检查 mask，因此 IPv6 /64 在协议撤回时不会删 null route。这是原版行为，修复保留它；接口完整 disable 另行删除已跟踪地址的 null route。

修复补齐这两个内核路径，并保持：续租不重复加 rule；PD 撤回、移除 assignment、LAN/WAN down 时撤销；地址应用失败不加 rule、不谎报已启用 local address；随后成功更新可恢复；显式到期更新撤销新增 source rule；`d72928c9` 进一步按 C 的每秒 timer 在没有后续输入时删除过期 PD、相关 route 和 source rule。修复不屏蔽 `ifupdate`、不去重输入、不替换 odhcp6c。

## 验证

| 验证 | 结果 |
|---|---|
| Linux netifd 单测（包括 2 个新增 wire/null-route 测试） | 172 通过 |
| 比较器反向突变/空捕获/寿命容差/顺序测试 | 最终 5 通过（Python 工具单测；原 4 项也在 Linux 通过）；地址、flags、route、rule、sysctl、updated 的内容变化均能失败 |
| 原 13 输入，DAD 关闭 | 修复后核心内容相同 |
| 原 13 输入，DAD 开启、固定整数秒输入节拍 | timer 修复后重跑通过：14 对稳定状态内容相同；LAN/WAN6 uptime 基线相差 1 秒，在既定容差内；hotplug、ifupdate、调用返回相同 |
| DAD 开启的调用后立即地址采样 | 两侧内容相同；tentative 数量序列 `7,0,0,1,0,1,0,0,0,1,0,1,0`，所有稳定快照为 0 |
| 11 个生命周期扩展步骤，r2/初次修复各 4 轮 | 历史结果：新增保护 route/rule 子断言 4/4 相同，完整比较 9 条差异；其中 timer 缺口已在最终审查补修 |
| 6 秒 PD 后不再发送任何 notify，等待 8.2 秒 | 自然到期：修复前红 4/4，修复后所有内容绿 4/4；source rule 均从 0→1→0 |

每个快照比较 IPv6 地址/flags/寿命、全部 IPv6 route/rule、all/default/WAN/LAN 的全部 IPv6 sysctl、WAN6/LAN ubus 状态。只有正数寿命/uptime 数值允许最多 2 秒差异；不会抹除无穷寿命、preferred=0、ubus assignment/rule 顺序或 updated 字段。route dump 在同优先级、不同设备间可能交换展示顺序，按完整路由多重集合比较，保留全部字段及重复数；比较器修正为 `66b9a384`。原始输入地址数量为 `6,5,5,6,5,6,6,6,5,6,5,6,6`。

生命周期顺序是：13 个原始输入后，PD 撤回、重授、valid=0、重授、删除/恢复 LAN ip6assign、LAN down/up、无效 preferred>valid 导致地址应用失败、同一 PD 恢复有效寿命、WAN6 down。C/Rust source reject rule 数量同步为 `…1,0,1,0,1,0,1,0,1,0,1,0`，没有续租重复规则或新增规则残留。

工具入口：

```sh
sudo -n python3 tools/health_20261008/netifd_replay.py \
  --rootfs MATCHING_ROOTFS --candidate NETIFD_RS \
  --capture PRIVATE_UBUS_MONITOR --out FRESH_PRIVATE_OUTPUT --dad on
```

加 `--lifecycle` 扩展边界；它对完整差异返回非零，同时在 JSON 单列 `protection_differences`，不能把子断言的绿改称整体全等。该回放固定等待内核收敛，不是性能基准。正式 CI 二进制的最终批测及身份由总报告记录，本报告中的候选 hash 是独立定向测试产物。自然到期用同一工具的 `--natural-expiry` 模式：只发送一个 valid/preferred=6 秒的 PD，随后无更新，8.2 秒后采样；与 `--lifecycle` 的显式 valid=0 更新分别验收。

## 自然 PD 到期：最终审查后补修

初次扩展只测了显式 `valid=0` 输入，不能替代没有后续输入的自然到期。新增 source rule 没有内核 expires；因此旧 timer 缺口会让本轮新规则静默残留，不能简单归入范围外的既有风险。

四次红差分一致：6 秒 PD 到期后，C 的 source rule 数量为 `0,1,0`，初次修复版为 `0,1,1`；Rust 还保留过期 PD/assignment 记录及相关两条 route。`d72928c9` 补齐匹配源码 `interface_ip_valid_until_handler()` 的 PD 部分：每秒检查 UP 接口、严格 `valid_until < now`；删除过期 PD/null route、设置 IUF_PREFIX，复用 assignment 撤回路径删除 local address、LAN route 与 source rule，不主动新增 ifupdate。

修复后自然到期四次完整内容比较均通过；Linux 172 项 netifd 单测及 5 项比较器单测通过，原 13 输入的 DAD 开启回放重新通过。测试二进制 SHA-256 为 `6ec3a645982155cd98d47473060369df36e768af7011b816593cdee575591aa8`；新证据在 JSON 的 `natural_expiry_followup`，原试验记录保持不变。原输入 PD 未更换、valid 最小 6263 秒，不含本次新增短租期边界。

## 本轮仍未关闭的既有差异

**LAN down/up 的桥生命周期**：C 删除 br-lan，Rust 保留；C 的 WAN prefix assigned 投影与 Rust 不同，再启动后 ifindex 也不同。r2 同场景连续 4 轮确认，新保护 route/rule 的删除、恢复相同。未把这个既有桥生命周期扩成当前热修。

初次修复的四轮扩展均保留相同 9 条差异，是 timer 修复前的历史结果；不能继续将其中 PD timer 项列为未修，也不能把初次扩展整体称为全等。最终自然到期补测单独记录，没有用它冒充完整扩展序列重跑。

## 被否定或受限的结论

- “LAN ULA 优先仍未修”不成立，r2 源码已包含修复。
- “5 次不含 GUA 的输入证明没有任何反馈”不成立；缺失 route/rule 是真实差异，但没有证据证明它们导致 odhcp6c 下一次输入改变。
- 最初 DAD 开启试验有 1 次 `updated/prefixes` 与 hotplug 差异，来自固定 sleep 累积跨不同整数秒：输入 lifetime 的 2 秒变化恰好抵消其中一侧期限更新。最终使用相同单调时钟相位、3 秒间隔，记录并限制调度偏差；没有过滤通知内容。
- 假协议 handler 只建立接收状态，按捕获顺序将原始 payload 送入真实 `notify_proto`；没有运行真实上游 RA，也不把重放节拍当成原现场时间。主机内核也不是路由器 6.12 内核。虽然保存了完整 netlink 日志并比较了立即/稳定地址采样，未逐条比较所有 netlink 消息时序。因此可以排除**这些捕获输入在本试验内的可见稳定内核差异**，不能宣称排除了任意瞬态、DAD 冲突或真实 RA 闭环影响。

IPv4 offlink、多个重叠 PD 的完整组合未在这 13 个 IPv6 输入中实测，不能扩大本回放覆盖声明；本轮只有相关编码单测与源码审查。
