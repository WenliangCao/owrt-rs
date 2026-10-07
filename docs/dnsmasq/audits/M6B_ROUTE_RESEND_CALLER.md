# EVENT_NEWROUTE 的 UDP resend caller

2026-10-07。只读核对产品基点 `7dc3ef814c73e1b5c68cc15ed265808926cc9bb5` 与精确参考 `dnsmasq-2.93`；未访问 Oracle、未运行虚拟 route 门、未修改产品。该报告识别普通 caller 缺口，不能替代镜像 C 对照。

## 精确 C 合同与现状

`netlink.c:388–402` 仅对 kernel header `nlmsg_pid=0`、`RTM_NEWROUTE`、`RTN_UNICAST`、`RT_SCOPE_LINK`、`RT_TABLE_MAIN|RT_TABLE_LOCAL` 排 `EVENT_NEWROUTE`；一批消息内 `STATE_NEWROUTE` 合并。`dnsmasq.c:1235–1264` 先读 netlink/事件，再在 `:1310` 左右处理 DNS listeners；事件消费者 `:1694–1698` 先 `resend_query()`，再 `poll_resolv(0,1,now)`。`no-poll` 只限制后者，不取消 resend。

`forward.c:548–550` 在一次 UDP `sendto` 成功后保存最近一个成功目标的 `srv_save`、实际 `fd_save` 和 `packet_len`；`daemon->packet` 本身保存实际送出的 query（包括改写的 ID、名字和 EDNS）。all-servers 时是最后一次成功发送。`forward.c:3292–3297` 只重发这一个包，`server_send:137–143` 沿用原 fd/目标/bytes，并执行原 `retry_send` 规则；不新增 frec、换 ID、改 recipient、计 forward action、产生普通 forward log/dump 或推进 fast-retry delay。重复有效 route 事件可以再次重发同一包，resend本身不清标记。

Rust `dns/filewatch.rs::RouteWatch::read_events/qualifying_route` 已有同类型谓词及 kernel sender 检查；`main.rs::step_dns_files` 的 route 分支只有 `files.request(ReloadReason::Route)` 与 `retry_bound_listeners=true`。`dns/upstream.rs` 的成功发送路径未保存最近可 resend 包，`dns/daemon.rs` 未提供 resend caller。这是已有 route 事件普通行为缺口，不是 fixed/fast-retry timer 缺口。不能用重发所有 pending、重新提交 query 或增加周期 timer 补它。

### C 清除 / 覆盖边界

| C 位置 | 行为 | Rust 对应边界建议 |
| --- | --- | --- |
| `forward.c:1628` | `receive_query` 入口，在读包/解析/本地答案之前清 save | 主 owner 对实际 UDP listener 读尝试的入口清 saved UDP，不只在 upstream submit；local、cache、invalid/rejected query也覆盖 C共享packet。无 readiness的普通 step不能凭调用清掉它。 |
| `forward.c:1169` | `reply_query` 实际 recv 尝试后清 save，含不匹配/坏包/recv error | upstream实际 read事件消费者清，不能只在完整 authenticated reply后清。 |
| `forward.c:654` | 每个到期 fast retry先清，再从stash恢复；成功forward重新保存 | retry计划的实际执行前清，成功send再保存新精确包；仅查询下一due不清。 |
| `forward.c:1071` | reply处理产生的DNSSEC重试显式“不 resend” | 镜像 nodhcpv6构建是否包含 DNSSEC以编译身份为准；不能将该专用 `server_send` 当普通send保存。 |
| `forward.c:3315–3316` | `server_gone(saved_server)` 清 save | server record实际删除时清；仅routing exclusion不等于record退役。保存token而非可复用raw fd，socket释放/替换后不得借新FD重发。 |
| `forward.c:2465`（debug父进程TCP） | TCP下一query读入共享packet前清；普通fork child只影响自己的copy | 单owner Rust应只在debug parent对应路径清父save；普通TCP私有query不能清父UDP save。 |
| `network.c:1030`、`dnsmasq.c:2065` | wildcard TCP accept在fork之前调用TCP pktinfo，父packet scratch被覆盖（debug/普通均如此）；NOWILD/CLEVERBIND分支不调用 | Rust相应wildcard accept前清父save；已accept child的私有query不因这个边界清父save。接口枚举本身不等于特定TCP pktinfo调用。 |
| `cache.c:1644` | `cache_reload`借packet做by-address hash时清save | HUP/完整cache-hosts重载的父作用；不能以旧pending仍在就保留save。 |
| `loop.c:57` | `loop_make_probe`覆盖packet，清save | 真实loop-probe生成入口清；不以timer轮询代替。 |
| `tftp.c:925/974/1020` | TFTP OACK/DATA覆盖；`srv_save`随DATA改存transfer用于prefetch | 至少失效Rust saved UDP；不能把C的 `void *srv_save` 非DNStransfer指针当UDPserver。该共享别名的route行为需独立精确镜像复现，未复现不宣称额外故意差异或通过。 |

Rust传输所有权比C显式：建议最多保存一个 `{ServerId, SocketToken, destination, exact_packet}`，使用有界且可复用的packet buffer。发送前检查token仍指向原socket/存活server；保存绝不能额外延长pending或socket生命周期。路由事件先消费resend再应用resolv源更新，沿用既有单owner/fd背压；不调用 `dispatcher.note_sent` / `note_forwarded_action`。若以EAGAIN队列代替C阻塞重试，该队列必须有原socket POLLOUT与有界原重试合同，并单独过owner门，不能静默新造永久任务。

## 最小虚拟 route 门（待执行）

用构建机独立 namespace 和镜像rootfs；C/Rust分别运行同配置 `no-resolv/no-hosts/bind-interfaces/cache-size=0`，UDP监听loopback，唯一可控upstream。无fast-retry、DHCP、TFTP或外部traffic。先建立并up一条dummy link，确保其创建事件全排空后再发送query；不触物理router。

1. 可控upstream收第一query但不回。保存逐字packet、source address/port、ID/question与timestamp，不依赖普通query log。客户端不自行重试。
2. `ip addr add 198.18.252.1/24 dev <dummy>` 使kernel生成connected route。旁路NETLINK_ROUTE witness必须记录sender pid0以及消息header pid0/type24/table254|255/scope253/type1；只有命令成功不够。daemon无新DNS请求时，应收到第二包，目标、source port和wire与本组第一包一致。
3. 第二包才返回正确answer，核对client恰好一个正确reply、pending/FD最终排空；query/forward action计数仍是一笔，route resend没有额外普通forward日志。C与Rust各自wire相等，跨组随机ID/bit20不要求逐字相同。
4. `no-poll` 同场景仍须重发；重复有效kernel route仍可再重发。双 pending以确定顺序收A再B，route只重发B；all-servers只重发最后成功目标。
5. 负控：第一包后先处理本地/cache或invalid UDP query、未匹配upstream packet、HUP/cache_reload、server实际删除；再次有效route均不得重发旧包。NOWILD/CLEVERBIND的普通TCP accept/私有处理不能清父UDP save，wildcard accept的父pktinfo路径与debug共享query路径须清。
6. 手工 `ip route add ... dev lo scope link` 常携带ip进程的header pid，必须保留witness；非零pid时不能期待resend。`tools/dnsmasq/m5_dns_files.py` 已有 `route-event-poll/no-poll` fixture区分 manual-route 与dummy address kernel-route，但它们只核对resolv切换，没有hold/drop UDP resend门，不能复用为该caller通过证据。

上述第1–3步足以先证明普通缺口；后续逐条绑定clear/all-server/debug边界。所有步骤当前是计划，没有实际镜像或Linux资格。
