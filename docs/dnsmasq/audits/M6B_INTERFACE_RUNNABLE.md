# M6b 接口事件与期限审计

2026-10-07。独立 no-A 工作树，基于 main `c8eee08e`。只读精确 `dnsmasq-2.93` nodhcpv6 参考，核心提交 `2c9a17ca`；没有访问 Oracle、没有触碰 TCP A 或用户 prompts。

## 必需合同与逐源接线

| 来源 | 精确 C | Rust setter | runnable / deadline | consumer | 已准备测试 / 尚缺实际门 |
| --- | --- | --- | --- | --- | --- |
| Linux multicast startup | dnsmasq.c363–373/1167–1168，无条件netlink init/poll，包括port0 | `RouteWatch::new` | fd POLLIN | independent `step_route_events` | port0 actor；实际TFTP/DHCP资格待root |
| subscription | netlink.c68–71，IPv4/6 ROUTE＋IFADDR=`0x550`，无LINK | `bind_groups` | one multicast socket | event scanner | pure group mask test已类型检查 |
| membership EPERM | netlink.c73–86，只有EPERM重试groups0 | `bind_groups` | 不建立重试循环；其它bind/getsockname失败exit5 | startup error | EPERM→0、EINVAL不fallback、第二bind失败负控；实际syscall故障门待root |
| RTM_NEWADDR / DELADDR | netlink.c406–410→EVENT_NEWADDR→network.c1778–1810 | `NetworkEvents.address`→`interface_refresh.request` | 可消费时立即runnable；collector busy时保留flag，依collector fd/deadline进展 | serve在新网络admission之前完成snapshot、bind动态增删及publisher更新 | port0/no-DNS-file-owner、held-hosts actor；actual idle add/del/readd工具已准备 |
| address＋DHCP relay | network.c1793–1796始终清relay4 iface_index；nodhcpv6不做IPv6 lease rebuild | `invalidate_relay_interfaces` | 不触发全量DHCP reload | next relay packet按当前接口选择 | 仍须镜像relay/interface族；不能把addr当全量lease重发布 |
| qualified route | netlink.c388–404，kernel NEWROUTE/unicast/link scope/main或local table | `NetworkEvents.route`→`DnsFiles.request(Route)` | file owner的真实排队runnable，FIFO忙时保留 | 非force resolver selection，既有clear-on-reload规则 | route predicate/混合datagram负控；route-only完整C门待root |
| queued watch while files busy | C异步netlink不由resolver file ownership控制 | `step_route_events`在hosts/interface/DHCP file early-return外读 | 每owner turn一datagram，剩余kernel数据仍POLLIN | 各consumer单独pending，addr不请求Route | held-hosts actor；实际FIFO＋addr并发门待root |
| initial DNS DAD | network.c1184–1208/1294–1303；dnsmasq.c1112–1115/1224–1231：unfinished dad最多1秒复查 | startup captured `pending_static_dns` | `InterfaceRefresh.retry_at`进normal poll；done后撤销 | mature snapshot→late bind；static不因后来新增地址建立新listener | one-second/remove timer actor、mature bind error不成为永久DAD timer |
| dynamic DAD | 当前地址代际保留tentative、完成事件或DAD deadline | dynamic refresh更新tentative DNS列表 | 仅仍tentative/未回来的captured pending有1秒deadline | 当前代际late bind | actual DNS DAD idle工具已准备 |
| TFTP DAD / port0 | network.c1094–1118，DNSport0仍可建TFTP69 | TFTP pending_listener_addresses；dynamic policy刷新pending | 同一1秒deadline，与DNSport独立 | shared listener owner / `finish_shared_listener_attempt` | actual static port0 TFTP DAD工具已准备 |
| shared transport completion | network.c iface->done，任一DNS/TFTP成功，独立失败不撤成功FD | `finish_shared_listener_attempt`＋bound_listeners latch | done撤pending；mature单纯失败不永久100ms扫描 | 原late-bind诊断、persistent_unowned和owned_explicit保持 | 原M5 listener/TFTP shared部分成功矩阵仍须fresh复跑 |
| interface records / domain / source index | 枚举时更新当前interface语义，TCP仍保accept-time快照 | changed snapshot请求existing InterfaceCollector | collector fd/runnable/deadline；queued addr不在旧collector完成后抢先admission | publish interface/domain records / source indices，server address check | 需要interface-record、DNS files、TCP accept隔离族fresh门 |
| malformed / user sender | netlink.c114–144截断拒绝、只接kernel sender | `read_events`验证sockaddr/长度；scanner完整header边界 | 不制造addr/route | 保持旧发布 | parser负控已类型检查；actual接收fault门待root |
| NLMSG_ERROR | netlink.c382–386，非0日志、ACK0无动作 | `NetworkEvents.errors` | 消费完该datagram，不伪造其它事件 | `netlink returns error`诊断 | errno/ACK0 parser；实际日志对照待root |
| ENOBUFS | C非阻塞drain，ENOBUFS再次drain（netlink.c359–370） | `route_retry_at=now` | 下个有界owner turn继续读取；EAGAIN撤重试回真实fdwait | 不制造addr、route、snapshot resync或full reload，不输出NLMSG_ERROR诊断 | ENOBUFS/EAGAIN误发布actor负控已类型检查，actual fault gate待root |
| other read error | C multicast读取终止当次drain | 可见错误，error-only 1秒冷却watch | 避免永久POLLERR busy-spin | 下一次有界read | 冷却/诊断尚无actual C资格，必须专项验证，不能写成已通过 |
| non-Linux fallback | 当前实现无RouteWatch | 原100ms fallback保留 | 非Linux仍原park/scan | 同原consumer | 不将Linux测量外推此平台 |

普通Linux配置没有永久100ms interface scan，也没有人为ARP90秒timer。地址、路由、DAD及接收错误分别有自己的来源与consumer；port0也保留监视能力。snapshot失败保留旧发布，并用仅错误路径的一秒重试，不假装新代际成功。

## 真实无流量 actor gate

`tools/dnsmasq/m6b_interface_idle.py --side both --image-root ... --rust-binary ... --out FRESH_PRIVATE`：两个精确镜像隔离namespace分别跑C/Rust，四case为dynamic DNS add/del/readd、dynamic port0 TFTP add/del/readd、static DNS＋TFTP DAD、static port0 TFTP DAD。观察仅使用/proc socket inventories与ip地址flags；在绑定证明前不发送DNS/TFTP请求。每次poll保存实际时间、完整socket集合、网络flags、ELF身份和cleanup；错误/超时保留，不挑最快窗口。此工具尚未在Linux执行，不作为任何族的关闭证据。

本地已执行：host `pending_listener_retry_requires_unfinished_initial_address` 1测试、actor工具2负控；AArch64-musl `cargo check --tests`通过，只证明Linux测试类型检查。实际Linux actor及镜像C所列服务/错误门尚未执行。

## 独立未关闭来源：NEWROUTE 的 saved-query resend

C `dnsmasq.c1694–1697`调用`resend_query()`再非force `poll_resolv`；`forward.c3292–3296`只重发仍保存的最后一份query。当前Rust `RouteWatch`原来只有resolver request；本补丁没有把所有pending transaction或普通fast-retry冒充这个入口，`dns/upstream.rs`未找到同等route-trigger saved-query接口。该已有缺口由root单独交forward审计，需真实kernel qualified route（手工route可能nlmsg_pid非0而不合C条件）阳性、原query/source/socket/wire对照后另修，不能默默遗留或混入interface deadline提交。
