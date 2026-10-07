# Route resend：main caller 接线

2026-10-07。独立 no-A 分支 `m6b/route-resend-main-caller`，基点 `c600506b`。临时 cherry-pick 库 `8183902d` 为 `31d2abc6` 仅供组合编译；本次交付提交只包含main、独立main测试文件和本审计。未访问Oracle或物理router。

| 精确 C 边界 | main 接线与范围 |
| --- | --- |
| `dnsmasq.c:1694–1698` NEWROUTE | `apply_network_events` 先调用 `DnsDaemon::resend_udp_query()`，再向DNS files登记Route；`no-poll`不跳过。复用库精确有界send retry，不新增query/forward action/发送队列。 |
| `forward.c:1628` UDP共享packet入口 | 真正recv成功后、长度/ACL/header检查之前清；包括oversize及成功recv但pktinfo/trunc被丢弃的 `Ok(None)`。hard error含EINTR清。Rust批量接收额外末尾WouldBlock只探空，必须保留本批最新成功forward；TimedOut无payload分支也保留。 |
| `forward.c:2465` debug TCP共享query | Reading消费新bytes或已buffered帧之前清，覆盖partial/ignored/malformed；WaitingMac恢复后answer_query再次清。普通私有TCP query不清父saved UDP。 |
| `network.c:1030` / `dnsmasq.c:2065` wildcard TCP pktinfo | 实际accept之后、调用tcp_interface之前清，包括随后被admission拒绝的连接。bind-interfaces/bind-dynamic分支不清。 |
| `cache.c:1644` cache_reload | `reload_data`在实际reload_hosts之前清；只排HUP不提前清。库reload_hosts也清，重复失效无副作用，pending transaction不取消。 |
| `tftp.c:925/974` / `:711–713` 实际构造 | 根据实际 `RuntimeEvent::Send { id:Some, packet }` 的DATA/OACK/read-error payload清；普通listener错误和TidError使用独立workspace，不据notice清。 |
| `tftp.c:679–684` 到期时get_block、无send | `TimedOut`对应非final/OACK/netascii到期的构造；有saved UDP时C srv_save不可能仍等transfer，不能使用TFTP预取命中。octet final-ACK的offset越过EOF、不写scratch路径是Rust `Completed`，不清。Failed/Discarded终态本身不是构造证明，不泛清。 |

TFTP只失效saved UDP，不复制C `void *srv_save` 的server/transfer别名。闲轮、最后ACK、wrong-TID没有相应packet构造就不清；没有借源审查冒称这些Linux/TFTP组合门已执行。

新增5个组合测试：真实UDP入包→owner→真实上游保存，不手工设置save；验证poll/no-poll route同packet/source port、末尾探空仍可resend，local/cached/short/QR/oversize/admission拒绝均失效；真实bound普通TCP私有query保留、wildcard accept失效；真实TCP单字节partial输入在debug消费前失效；实际full-reload消费者清但保留pending。debug consumer模式仅在测试client选择，以免修改进程全局DEBUG_MODE干扰并行测试；它不是CLI debug模式端到端资格。

本机macOS AArch64/Rust1.98.1实际 `cargo test --bin dnsmasq-rs route_resend_owner`：**5 passed，0 failed/ignored**。Darwin没有Linux route actor，host测试以真实owner UDP/TCP/HUP消费者后调用库resend观察真实UDP状态；Linux编译使用实际 `apply_network_events` 和owner poll。`cargo check --tests --target aarch64-unknown-linux-musl`通过；此处没有运行Linux、netlink或镜像C。

本地完整stdout/stderr保存在本worktree `private/evidence/route-main-caller/`。a01初版测试编译因误用wire Question别名及collector方法名失败，修正测试后host与Linux类型检查分别fresh重跑通过；a01日志保留，不归为产品缺陷。root须在新的统一ELF上跑实际Linux tests、基本route/已有clear caller及受影响镜像门，不能导入旧3e/7bdb通过身份。
