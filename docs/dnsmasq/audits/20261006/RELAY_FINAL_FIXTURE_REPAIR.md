# M5 relay 最终夹具修复

2026-10-06。旧最终候选80a721…7dc1c的普通relay174行首次统一运行有缺包。实际send/recv/SIOCSARP与地址事件证明是两个夹具问题；没有修改Rust产品，也没有增删场景或放宽wire/count。修复后37配置、174报文、40语法、4绑定模式完整C/R配对零差异；actual recheck的11报文及4语法负控全拒绝。完整SHA、metadata核验与失败记录见[收据](relay-final-fixture-repair.json)。dc1b/37f85新最终ELF的正式全族仍是独立fresh运行，旧校准不替代该资格。

| 问题 | 独立实际证据 | 修复与严格边界 |
| --- | --- | --- |
| 自动IPv6 link-local DAD改写relay地址代际 | ip -ts monitor抓到client0在07:53:46.399、server0在07:53:47.231发布NEWADDR；C primer在07:53:45.975。此前15行诊断中，两侧缺行均实际recvmsg完整报文后没有sendmsg、更没有SIOCSARP。C netlink.c406–410为任意NEWADDR/DELADDR排EVENT_NEWADDR；Rust snapshot变化也清已学习relay索引。接口down/up会再次生成同类事件。 | 只在已断言隔离且仅lo的IPv4测试namespace，设置未来veth的addr_gen_mode=IN6_ADDR_GEN_MODE_NONE(1)，保存实际配置和namespace。IPv6协议/loopback仍开启；既有显式IPv4增加、删除、接口重建场景全部保留。模式常数由Oracle Linux if_link.h实际核对。 |
| 跨UDP socket的actor扫描伪造总序 | two-addresses的ptrace actual sender C/R均1067(giaddr.3)→67(giaddr.1)、sendmsg各返回244；SO_TIMESTAMPNS实际kernel入队也同序。旧actor逐FD扫描和分批take有时显示67→1067。 | 每个接收socket启用AArch64 SO_TIMESTAMPNS_OLD，保留全部raw接收时间与包。按真实kernel时间恢复序列，并在evaluate独立重建observed/echo、检查时间与完整wire/source/destination/count。没有按端口、payload或地址排序。 |
| 120ms一次采样没有等待实际producer结果 | 原缺行延长到2秒仍有recv无send，证明主要原因是代际失效；跨FD采样则暴露实际观测顺序问题。 | 阳性最多2秒等待实际完整计数，收到后继续原120ms观察额外包；zero cases固定250ms完整观察。所有实际count仍精确匹配C且不允许多包。 |

DAD隔离后的ordinary-reply15行，C/R每个wire/source/destination/count相同；arp-failure两侧真实SIOCSARP均返回-22(EINVAL)，随后sendmsg244并实际下游1，排除原来对Rust发送失败的猜测。multi-address两行的actual sender与kernel receive顺序相同，证明无须改产品迭代顺序。

保留了最初full174的ARP失败、单profile复现的C不稳定缺包、两个带syscall/地址代际的诊断、DAD修复后的跨FD假顺序红、最终timestamp全矩阵绿。成功的selected诊断会遇旧full-negative-controls要求split-request的StopIteration；这些只记录actual行和witness，不记为完整资格。最终full没有此错误。六批诊断/全矩阵均全SHA+metadata验证后清理远端原始目录，原失败没有删掉；新最终formal的controller/locked JSON按规则另保留。
