# UDP live ACL 接线

状态：独立源码补丁，基无 A `3d4dbc839c7d7dcf590e207379e40b74442f890b`。**未构建、未运行测试、未访问 Oracle**。公共 `main.rs` 由 root 统一整合并移植到 A `0d8379b693ca54773a638a0336ee5fbe8658143c` 及其后继；不能凭本文关闭镜像门或 CPU 门。

精确 C 调用链和3个普通镜像 caller见 [ACL caller 门](M6B_INTERFACE_ACL_NEW_CALLER.md)，NEWADDR gate见 [发布合同](M6B_NEWADDR_PUBLICATION_CONTRACT.md)。参考仍是 nodhcpv6 镜像 `097a9e21…` 的匹配2.93源码。

## 机制与接口

| 边界 | 实施 |
| --- | --- |
| 无 ACL、已匹配明确 listen-address、静态 IPv4信任 | `udp_needs_ingress_name` 返回 false，沿现 `listeners::admit`。不新增 ioctl、socket或名称分配。未匹配 literal 的明确 ACL仍走 live 判定。 |
| live source / name | actual receive 后保已有 local-service source 检查；`DnsSocket::ingress_name` 复用现收包 fd 调 `net::interface_name`，SIOCGIFNAME / 栈16。pure `udp_acl_name` 按 C name/literal/exclude 判定，literal 匹配胜过 exclude；不把 loopback 直接当 name 匹配。 |
| failed live ACL | 同 fd 的 SIOCGIFFLAGS 仅为 loopback exception 查询。失败只禁 loopback，IPv4 label仍可判定。非 CLEVERBIND 才 `enumerate_interfaces(true)`；bool表示本 caller确需接口列表，跳过无 interface-name/domain 的旧早返。 |
| 异步 continuation | `PendingUdpAdmission` 保存原 token、listener Arc、Incoming源/目的/index、原 query 和 loopback资格；至多1包，既有 collector busy gate 阻止新增 DNS admission。collector自身fd/runnable/3秒绝对deadline负责醒，不加计时器或线程。 |
| 发布与恢复 | 仅合法 failed-ACL receive caller枚举，而非恢复 NEWADDR eager publication。完成后按新 selected list 做 loopback或IPv4 index/destination label exception；通过后才进入原 query_id/log/EDNS/forward。它不复用跳过 admission 的 `PendingInterfaceUdp`。 |
| latch与早期失败 | enumerate latch在 control socket之前，early failure / same-turn latch使用旧列表exception，不同步 getifaddrs、不二次清空重试。既有 collector后期错误发布合同不改。 |
| 跨平台 | live入口与PendingUdpAdmission限Linux64；其它平台保原 admission路径。 |

`SinglePoll::step_udp` 的既有64KB接收缓冲复用和UDP预算不动；仅把准入后的原函数体提为 `process_admitted_udp`，异步恢复也走同一体。新增名称/flags使用栈 ifreq，两个 unsafe 均附存储、fd和写入范围的 SAFETY 说明；无新依赖。

Packet_SRC / route saved-query 的 invalidation仍紧接成功recv、discarded datagram或真实read错误；最终 WouldBlock保留刚完成send的重发资格。live ioctl不访问 DNS packet scratch；pending packet的源/目的/index独立保存，恢复前不再 receive / invalidate。现DHCP/TFTP/TCP/reload每轮预算和唤醒顺序未改。实际 CPU、延迟和RSS增量交 CPU45与最终135测，本文不估计吞吐。

## 已准备未执行的 owner 门

- `udp_live_ingress_accepts_a_real_received_index_absent_from_the_old_snapshot`：真实UDP/实际kernel ingress，旧列表为空；live `lo` name仍答正确host record，且不生成collector或发布snapshot。明确literal和无ACL再用必不能SIOCGIFNAME的index验证零ioctl shortcut，不改变其它来源状态。
- `udp_alias_admission_collects_without_publication_rules_and_resumes_the_original_packet`：private netns实际新增 `127.0.0.42 label lo:acl42`，未配置 interface-name/domain。真实收到的同一包先park，collector完成后原包源/目的/内容不变，正确响应且local_answered恰1，没有第二包提供唤醒。alias RAII清理，测试拒绝无`DNSMASQ_TEST_ISOLATED=1`的运行。

root须统一 build/tests、新鲜 TMPDIR、实际复制 ELF身份，并跑 `m6b_interface_acl.py` 的 late-device / recreated-device / late-label C/A三配对。随后受影响 interface/domain、既有 route scratch/clear/resend门、动态/DAD无 traffic4场景在新同源候选上复测。原始失败保留，工具和本文本身不给功能/CPU资格。
