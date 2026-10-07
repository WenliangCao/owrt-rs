# M6b readiness 调度复核与修复收据

复核基线为产品 `7396663d`（ledger `9213eed4`）；独立修复分支为
`m6b/readiness-audit`，修复提交 `b435f046`。只在本机做检查与测试，未启动
Oracle 并行 build/test/fuzz；物理路由器未操作。

## 真实缺口

| 基线缺口 | 触发与结果 | 修复 |
| --- | --- | --- |
| upstream 只有 fd ready 才推进 | `append_poll_fds` 给出 fast-retry、loop-probe、fixed-lifetime、empty-error retry 或已排队结果的 deadline；poll 到时返回 0，`upstream_ready=false`，`poll_udp_completions` 被跳过。到期 deadline 之后会形成零 timeout 空转 | 单独保存 upstream 自身的 deadline；fd ready 或该 deadline 到期均推进。不能把其他 subsystem 的较近 timer 当作 upstream 自己的 timer |
| TCP idle expiry 被 readiness 跳过 | `Reading`/`Writing` 不检查 connection 的 150s deadline；无网络事件时到期客户端仍占 slot | client deadline 到期无条件进入 bounded step，关闭 network fd 并进入日志回收 |
| `network_done` 的日志与 slot 未回收 | network 已关闭、stream=None，原 phase 的 fd 永远不再 ready；TCP 私有日志队列不能 flush/finish，日志 FD 与 admission slot 被长期保留 | `network_done` 独立推进；第一次关闭保留原强制 finish，后续只按日志 POLLOUT 或 FIFO retry timer 排空，空队列可立即释放 slot |
| DHCP probe 内部使用外层旧 readiness | `wait_during_probe` 自己执行 poll，却未保存其 revents；内部 UDP/TCP/TFTP dispatch 因外层 fd gate 跳过。probe 期间的新 DNS/TFTP 不再运行 | 本次 probe 独立 poll 后发布准确 readiness。仍不读取 UBus、DHCP socket 或 reload 文件，不重入借用中的 DHCP provider |
| TFTP pending MAC 不计 active transfer | pending RRQ 存于 listener pending 队列，`active_transfers()==0`；neighbor 完成不是 TFTP fd 事件，deadline/fallback 都不能触发 `step_tftp` | 窄只读 `has_pending_work` 包含 pending MAC；neighbor ready 与保留的 250ms timer 均推进。公共 poll 使用保存的 due，避免每次组 fd 都重新推迟 timer |
| DHCP timer 与地址 dump ready 未归属 DHCP | lease alarm 不在公共 poll deadline；provider address fd 在 file 类，而 socket gate 只识别 DHCP/PXE 范围 | 加入 `next_maintenance` 和 provider fd interests；文件 bank 未完成时不把初始化 due 变成忙等。原 `has_input` 保留 pending reply/queued packet 接线 |
| TCP 只存 fd、丢失 revents | 仅 POLLOUT 也能授权后续 Reading；一次写完后多做一次 EAGAIN receive。新 accepted fd 可能复用旧 fd 数字 | 保留 fd+revents，重复 fd 取 mask OR；现有 client 保存本次 poll slot/revents，新 accept 从零开始。read/write/upstream 各自消费其方向；内存中的完整 frame 无需网络 readiness，新的 answer 仍可立即 send |

TCP upstream 原 `step` 内部再执行一次 `poll(...,0)` 已改用 owner 的确切
wait mask。尚未就绪的 upstream 等自己的 fd/timer；不能把 downstream
POLLIN 当成 upstream ready，也不能把 upstream POLLIN 当成 downstream
read ready。TCP 的八步公平预算与每连接100-query合同保持原样。

## 已执行本机验证

- `cargo check --manifest-path components/dnsmasq/Cargo.toml --bin dnsmasq-rs`：通过。
- 同一命令加 `--target aarch64-unknown-linux-musl`：通过，覆盖 Linux `main.rs`。
- 上述 Linux bin check 加 `--features m6b-diagnostics`：通过。
- `cargo check --manifest-path components/dnsmasq/Cargo.toml --tests --target aarch64-unknown-linux-musl`：通过，覆盖新增 Linux tests 的类型检查。
- `cargo test --manifest-path components/dnsmasq/Cargo.toml --bin dnsmasq-rs`：本机12/12通过。
- `git diff --check`：通过。

本机是 macOS；Linux target check 只做类型检查，不链接、不执行。已有
unused/clashing-extern warnings 未改变。不能把上述检查称为 Linux 行为门。

新增真实 binary 回归：

1. POLLOUT 完成 answer 后，不消费同 socket 尚未取得 POLLIN 的数据。
2. 已缓冲 TCP frame 无 readiness 仍解析，生成的 answer 立即发送。
3. Linux idle client 到期与 `network_done` log-complete client 无 fd ready 仍释放 slot。
4. 同 fd 多 interests 的 revents 合并，POLLOUT 不授权 read；新 accept 的 events 为零。
5. 无 upstream 回包时，20ms fixed deadline 经公共 poll timer 唤醒后清空 transaction。
6. DHCP probe 内部收到新的 UDP DNS，使用该内部 poll 的 revents 返回正确本地答复。
7. TCP network 关闭后，日志 FIFO 无 reader→retry timer→reader 接入→日志排空→slot释放。
8. 已有 isolated TFTP pending-MAC 回归增加 `active=0` 时仍有 pending work 的断言。

## Oracle 后验门

主线程合入修复后统一从新源码构建 test/release ELF。先执行完整 Linux
`--lib --bin dnsmasq-rs` tests（新增 binary 回归不能只跑 `--lib`）；再在
`run_isolated.sh` 下单独运行需要 namespace 的 TFTP pending-MAC 测试。
随后用同一个新 release ELF 执行：

- `dns_retry_failure_diff.py`：fast-retry timer、timeout 与恢复；
- `m5_dhcp_network.py`：实际 probe/reply-delay 期间 DNS/TFTP/TCP、signals/reload defer、地址 dump 与租约维护；
- `m5_tftp.py`：unique-mac、fallback、retransmit/timeout 与 completion；
- `m5_logging.py`：async TCP 私有队列、blocked FIFO、reopen 与错误回收；
- TCP stale/CD/capacity/accept 与100-query边界服务门；
- 第1b短基线：UDP hit、TCP local/cache、reload、DHCP与idle CPU。

上述门尚未由本代理执行；主线程必须保留失败/重跑和新 ELF 身份。性能
结论仅代表 Oracle 构建机，最终135窗口仍只在最终候选运行。

## 主线程实际 Linux 后验（4816b19f，非最终资格）

Oracle 单一共享 target 构建并实际执行库710通过/20 ignored、入口20通过；另在run_isolated下实际执行三个TFTP ignored tests全部通过，其余17 ignored不计。新增最后ACK/ACK-timeout后helper逻辑completion无需另一个网络包、连续两DHCP frozen callback/背压不空转、EOF到waitpid之间有限回收均已执行。helper修复的C依据是dnsmasq.c:1177–1194 pre-poll搬队列与tftp.c:1029–1043完成排队/释放。

新产品feature-off opt3 SHA `9acccc6068a2734945271b687ca48f35ddfbc96fa1aa91d575af63317aec262b`，1,941,544B；s SHA `781cf6d739c61bf3bb0fc02d7ee332f4bd87d864cb8f61b7fe203bc3ab403b6c`，1,626,152B。E/M6B/helper-ready保存source.tar、build receipts、link map、实际ELF和全部测试日志。本地SHA/尺寸与build receipts相等。

真实镜像C service-03仍在执行，已通过option_matrix_next、helper；未完成族不称通过。service-02控制器漏link_map binding在展开命令前退出，零测试执行，错误日志/原控制器SHA保留后fresh重跑，未覆盖原失败。未插桩基线manifest `79ebd42c…` 已准备但尚未执行；A服务和CPU硬门仍待过。

TFTP实际全族fresh重跑已通过（276.383s）：30普通、5故意reference、6安全syntax，result SHA `bc3b9710dce0aa1edd717c6bef9f42bb689e295eb0afd2a7715518c881278ba0`。两侧completion-script-once均精确2条V4/V6回调，final-ack-timeout-script-once均精确1条回调；各退出/FD/网络清理及负控保持。dump原族也通过。其余服务门继续，整包尚未关闭。

ARP后续全族service-03未通过：78个C观察，Rust只有dhcp-scriptuser-applied在health UDP回答后立即数FD时19→20。独立同ELF fd-probe-01捕获额外fd19=/proc/26/net/if_inet6，50ms和1s后完整集合回到原19个；它来自health后进行的同步接口snapshot，不是持久泄漏。原守卫未确认owner排空，测试器将以完整FD集合持续稳定作边界，永久泄漏和同数量换FD负控不得放行；未fresh重跑前ARP仍失败。service-03全证据SHA+metadata本地核验后远端prune，archive SHA `f108d6e8d0b864e7cc8dc2774b75c985952ea4e5f3066dc20cb74fd021a00557`。

service-04新冻结工具在同4816/9acc ELF上fresh过完整ARP族（452.119s、result SHA f6210364896acbc3b766f111080246c0fb741e1a7b890ef7fbd00fd32d5afcf0）和DHCP reply-delay（33.019s、066898b40d65b8f68021e8ebc798eb4573c7cb5a7d8cadaf363f0f2b3135308a）。FD工具cd4ca634对C/R完全同规则，保留完整identity连续稳定、每次样本/race和6个永久泄漏/替换/PID复用负控；没有放宽FD数量或默许原失败。DNS文件/UBus/cache及helper收尾仍在执行。
