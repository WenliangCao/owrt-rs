# UDP forwarding owner 唤醒组合测试

2026-10-07，独立 no-A 分支 `m6b/udp-owner-tests`，产品基点 `7dc3ef814c73e1b5c68cc15ed265808926cc9bb5`。只有测试接线与测试文件改变；未修改 main、生产传输算法或访问 Oracle。

新增六个测试均沿真实 `append_poll_fds → poll → 零等待消费` 路径，使用本机真实 UDP socket。完成事件不是直接塞入 deque；正常回复由 production receiver 产生。错误边界只复用既有受控 IO seam，所有 admission、cancel、socket release、计数和消费仍运行生产代码。

| 测试 | 实际合同 |
| --- | --- |
| `queued_real_completion_wakes_owner_after_its_last_socket_is_released` | 实际查询与合并的两个 recipient，真实上游回复；先收取而保留 completion，全部网络FD已释放后 append 仍给当前deadline；空FD poll 后交付完整wire一次，随后恢复空闲期限。 |
| `queued_terminal_error_wakes_without_an_fd_and_is_consumed_only_once` | 注入POLLNVAL使生产取消路径释放最后FD并产生错误；空FD owner仍立即消费，错误不误计 unanswered、不重复交付、不残留零期限。 |
| `fast_retry_deadline_wakes_quiet_owner_and_retransmits_the_same_request` | upstream不发任何reply，owner只因40ms retry期限醒；同socket、peer、ID与payload真实重发；成功retry计第二次forward action，之后不是立即busy；真实回复完成与回收。 |
| `owner_retry_send_failure_releases_fds_and_counts_its_fallback_once` | 初次真实发送后，仅将重试目的port改0，形成实际同步send错误；无收包也按retry期限消费错误，background local fallback仅一次，全部FD回收。 |
| `empty_error_retry_timer_reenables_fd_and_consumes_a_real_queued_datagram` | 连续空POLLERR/SO_ERROR通过既有seam注入，第三次禁止recv；使用受控时间保证FD抑制窗，真实datagram在socket排队；空FD timer poll到期后重新登记、真实收包，两个recipient均保留，deadline/counters不变。 |
| `owner_fast_retry_deadline_completes_a_real_daemon_query_without_new_client_input` | 真实DnsDaemon handle_udp、期限登记、owner poll与daemon.poll；不依赖第二个client请求即重发、恢复客户端原ID、交付正确A、发布cache一次并排空。 |

本机 Rust 1.98.1 / macOS AArch64 实际运行：`dns::upstream::` **42 passed**（含新5），`dns::daemon::poll_tests` **8 passed**（含新1），0 failed/ignored。修改的两个独立测试文件 rustfmt 与 git diff --check 通过。`cargo check --tests --target aarch64-unknown-linux-musl`通过，有基点既有warnings；这是类型检查，未运行Linux测试。

```sh
CARGO_TARGET_DIR=private/local-target cargo test \
  --manifest-path components/dnsmasq/Cargo.toml --lib dns::upstream::
CARGO_TARGET_DIR=private/local-target cargo test \
  --manifest-path components/dnsmasq/Cargo.toml --lib dns::daemon::poll_tests
CARGO_TARGET_DIR=private/local-target cargo check \
  --manifest-path components/dnsmasq/Cargo.toml --tests --target aarch64-unknown-linux-musl
```

原始本地日志在此worktree的 `private/evidence/udp-owner-wake/`。初版测试有两处测试代码错误：误把Message.records方法当字段（编译拒绝）；误把成功fastretry的forward action期望写成1（实际2，符合C `forward.c:579`），4/5 transport通过后该断言失败。修正后按上述两个完整相关scope重跑通过，失败不归为产品缺陷。全crate格式检查另发现基点大量已有格式差异，未展开修改；只检查新增/修改的测试文件。

这六项不是Linux `PollOwner::wait_for_files/wait_during_probe`或镜像C资格。root仍须在最终Linux同ELF执行新增测试与实际owner链，并重跑受影响镜像族；不能将本机UDP/poll结果写成路由器性能、Linux执行或完整M6b通过。
