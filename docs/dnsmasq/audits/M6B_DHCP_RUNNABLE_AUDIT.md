# M6b DHCP 逻辑工作与 poll 兴趣审计

2026-10-07，无A主线 `c8eee08e` 起点。范围是 DHCP bank/ethers 输入、packet 接口 dump、包等待和租约 alarm；不修改每包 fresh 地址合同，不增加跨包 cache。UBus/信号/EDNS/neighbor/TCP MAC 和主loop HUP优先级由其他独立补丁负责。本审查不访问 Oracle。

发现两类真实来源错误：`file_reload_pending` 无条件报告 runnable，可越过正在等 FIFO 的 bank/ethers reader；主 poll 收集 queued DHCP 的 POLLIN及维护 deadline，但 `step_dhcp` 在 helper init、HUP/file工作或 global接口代际等待时根本不能消费它们。per-packet地址 dump分步推进期间，原包仍在 DHCP kernel queue，也不能继续当新的可消费 readiness。

本补丁使用当前状态，删除 provider 保存的上一轮 `file_runnable`，并将 packet接口 fd/runnable 与文件输入分开；`step_dhcp` 与主 poll 共用 `dhcp_packet_work_allowed()`。已有 `7bd0f4e3` deferred-reply POLLOUT实现保留；只有 packet consumer当前能到达flush时才收集该兴趣。

## 来源、优先级与消费者

| 来源/生产者 | 当前状态与等待 | 真正消费者与前置条件 | 改动/核查 | source actor测试 |
| --- | --- | --- | --- | --- |
| `start_file_owner` / `DhcpFiles::begin_reload` | StaticHosts→StaticOptions→Directories、regular read/scan为逻辑工作；无watch fd也要续步 | `step_dhcp_files`→`step_files_with_watch_readiness`→`DhcpFiles::step_with_watch_readiness` | `DhcpFiles::runnable()`直接查询current job/busy/watch，不依赖上一轮FileStep | `static_bank_plan_finishes_from_logical_turns_without_watch_or_network_fd` 实际读/发布option bank |
| active bank FIFO/char job | 只等待其 POLLIN/HUP；busy generation不代表立即工作 | 上述consumer先处理active job，不能跳到后面的reload/watch | current runnable以active job的wait_readiness优先，FileStep也复用这一状态 | 既有 `fifo_waits_without_owner_work_and_parses_partial_line_at_eof`扩展current状态断言，实际writer/data/EOF及完整发布 |
| `reload_data_files` late queued reload | idle file owner可begin；active FIFO时queued flag必须保留但不能强制timeout0 | provider `step_files`在ethers结束后、files不busy时才清flag并begin | `files_runnable()`与consumer保持ethers→active bank→queued reload/idlewatch次序 | `queued_reload_waits_behind_active_fifo_then_restarts_after_publication` 实际两代FIFO，验证第二代option替换first |
| active `ethers_read` | ethers regular reader可续步；ethers FIFO等待fd | provider最先step ethers，完成后发布，然后下一轮才bank reload | ethers当前runnable优先于queued bank flag | `active_ethers_fifo_has_priority_over_queued_bank_reload` 实际ethers writer/EOF/host安装与后续bank保持 |
| dynamic directory kernel/buffered event | kernel输入只看watch fd；已缓冲事件/scan/regular job不需要新的POLLIN；activeFIFO优先 | DhcpFiles idle watch turn→live generation→完整update | currentAPI保留 `DirectoryWatch::runnable`；不让buffer越过activebank | 既有 `watch_input_waits_for_its_fd_but_buffered_events_continue_without_readiness`扩展currentAPI，实际inotify batch之后用 `watch_ready=false` 发布host |
| packet `prepare_packet_interfaces` | fresh `Ipv4Snapshot` Send逻辑续步，Read/SendBlocked等自身fd；queued DHCP保持不消费 | `step_dhcp`在所有packet前置门打开时推进，完整DONE后才消费一个packet；`finish_packet_interfaces`清代际 | 新 `packet_interfaces_pending/runnable/append_packet_interface_fds`；不把它伪装file runnable。dump waiting时不收集DHCP socket兴趣 | `fresh_packet_interface_dump_is_separate_from_file_runnable` 实际两次netlink dump、清掉snapshot后packet_addresses拒绝旧数据；`pending_packet_snapshot_wakes_from_its_dump_instead_of_unread_dhcp` 实际kernel queue与dumpfd续步 |
| queued DHCP/PXE input及pending reply | 当前consumer可达才收集listener兴趣；pending reply保持已有POLLOUT而不改sender | `step_dhcp`前置门：global interface不busy、helper init/error空、pendingHUP空、DHCP files不busy | 同一个 `dhcp_packet_work_allowed` 用于step与主poll；interface dump pending时由其自己的fd推进，listener暂不入waitset | `helper_init_keeps_queued_dhcp_and_due_maintenance_off_the_wait_set` 实际queued packet＋init/error两门；`global_interface_generation_keeps_queued_dhcp_until_its_publication` 实际collector代际；runtimeFIFO测试见下一行。pendingHUP真实caller由主线程HUP优先级门继续验证 |
| runtime bank FIFO＋queued DHCP | file fd等待；屏蔽不能消费的DHCP输入，不阻塞普通DNS | file generation先发布，再打开packet gate | 不改变文件读取/更新顺序或合法报文合同；timer也要服从相同packet gate | `held_dhcp_bank_fifo_does_not_spin_on_queued_packet_and_dns_still_replies` 实际DNS A答复、queued DHCP保留、DHCP fd集合缺失、EOF后消费原包 |
| lease persistence `AlarmAction::At/Immediate` / pending_alarms | 当前packet/maintenanceconsumer可达才收集deadline；阻塞file/helper/globalinterface时到期alarm保留，不强制poll0 | `step_dhcp`先tick、再has_input/packet；`LocalProvider::tick`先file_work门、observe due、逐一consume pending alarm、prune/file/DNS/script | 主poll `next_maintenance`与packet consumer共用前置门；不改变expiry/completion顺序 | `due_lease_alarm_prunes_without_packet_and_waits_behind_file_work` 实际lease/expiry与file generation；`lease_alarm_without_network_traffic_expires_and_rewrites_the_lease_file` 实际deadline、无send的UDP peer、租约文件写空 |

## C 合同和有意边界

精确 `dnsmasq-2.93/src/dhcp.c:352–364` 和 `netlink.c:154–258` 要求每个 DHCP packet使用 fresh完整地址集合；`dhcp.c:372–377` 在reply/send前保持prune、lease file、DNS更新顺序。本补丁不合并不同packet的快照，保留持有netlink/ioctl fd及EMFILE边界。地址dump拆分仍是单owner，不能为匹配C低poll数恢复同步阻塞。

C `dnsmasq.c:1606–1612 EVENT_ALARM` 的 prune→file→DNS路径来自alarm而非下一网络包；Rust `maintain/observe_alarm/tick` 继续保存到期alarm，下一可运行turn处理，不在file generation未发布时跳过前置门。文件/ethersFIFO非阻塞其他DNS/TFTP是既有明确行为差异；本补丁只防空转，不丢pending reload、queued packet或alarm。

## 实施与验证状态

- 产品改动仅 `dhcp/files_runtime.rs`、`dhcp/daemon.rs`、`main.rs`；公共main补丁在独立工作树，由主线程整合。没有重做pending reply sender。
- 新增10个source actor测试，扩展2个既有file/watch/FIFO测试。测试通过真实setter与消费者变化（写FIFO/关闭writer、生成inotify输入、netlink dump完成、lease expiry/file写入）验证，不把getter与手写镜像函数相等当资格。
- 本地 `cargo check --target aarch64-unknown-linux-musl --manifest-path components/dnsmasq/Cargo.toml --lib --bin dnsmasq-rs --tests` 已通过，只有既有warnings。macOS不能执行Linux测试ELF；**Linux runtime、镜像C服务门和性能窗口尚未执行，不记为通过**。
- 正式整合后仍须实际Linux运行这些source tests，fresh过DHCP文件/identity/lease/relay/PXE/reply-delay与M2、FIFO健康、helper/HUP优先级、expiry无流量门。HUP pending的真实same-wake caller由主线程及helper补丁负责；C原持writer会阻塞父owner的边界继续按既有差异表分类。

## 故障注入与回归用途

旧provider的 `file_reload_pending || last_runnable` 会在queued-reload/FIFO actor的第一段失败；旧主poll无条件DHCP兴趣会使helper-init、global-interface和runtimeFIFO actor观察到DHCP fd仍在waitset（时间下限另作辅助，不凭scheduler慢延掩盖spin）。漏掉新的packet-interface fd接线会使真实dump actor无法消费原packet；把地址缓存复用到下一packet会使清代际的原语失败。禁用alarm deadline接线会使无流量expiry actor在固定4秒上限内无法写空leasefile。
