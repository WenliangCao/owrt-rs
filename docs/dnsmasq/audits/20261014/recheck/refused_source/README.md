# REFUSED：独立源码定位与系统调用故障对照

2026-10-14，工作树产品基线 `aa8f12dbe514acab3feb979e86bd6a7accb15cd1`。
本子审计不修改产品代码，不在物理路由器上运行负载；正式 1,000 QPS 的真机配对和
实际内核错误归因由总复核执行。这里的证据不能单独替代同负载真机对比。

## 已证实的结果

精确镜像 C（SHA256 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`）与
本次最终 Rust（SHA256 `0d5a476923c5da514662068950f2057b1d7500d9b9bfd0a1ad5a757ff12dc728`）
面对相同的上游 UDP `sendto` 失败，行为一致。Oracle 独占网络 namespace 内，分别对
首个上游发送注入 `EPERM`、`ENOBUFS`、`ECONNREFUSED`，每种测试无 OPT / 有 OPT 两种请求，
共 12 个故障用例。C / Rust 的无 OPT 回答完全同字节 `RCODE=5`；有 OPT 的回答也完全同字节，
包含 **EDE=23（Network Error）**。失败请求没有到达合成上游；下一条不注入的请求均得到
`NOERROR` 且确实到达上游，证明该错误回退会取消当前事务，不会破坏后续转发。

工具先为每个 ELF 运行无注入校准，确认首个上游 UDP 发送为第三个 `sendto`；前两次是
启动阶段的 netlink 操作。逐用例的 strace 确认只有到 `127.0.0.1:15354` 的一次发送被注入。
两个 ELF、上游报文和配置保持相同，strace 没有改动产品源码或二进制。

派生证据：[send-error-controls.json](send-error-controls.json)。
可复现实验工具：[`recheck_send_error_injection.py`](../../../../../../tools/dnsmasq/recheck_send_error_injection.py)。
原始完整输出保留在 Git 忽略的 `private/dnsmasq-recheck-refused-source-20261014/oracle/`，
Oracle 原件在 `/home/ubuntu/dnsmasq-recheck-refused-source-20261014/`。

## REFUSED 路径与排除范围

| 路径 | Rust 位置 | 线索及对本次压力问题的意义 |
| --- | --- | --- |
| 非法/不可提取的问题 | `dns/udp_query.rs:35–48` | REFUSED + EDE24。旧压力错误包保留 ID / 合法问题，不能用此路径解释。 |
| 没有匹配上游 | `dns/daemon.rs:1076–1099` | REFUSED + EDE14。固定上游没有配置更改；要用 OPT 诊断直接区分。 |
| 转发表/重复请求容量 | `dns/daemon.rs:1115–1151`、`dns/forward.rs:347–392` | REFUSED，无 EDE，并限频写 `Maximum number of concurrent DNS queries...`。历史服务日志没有此信息；20 个并行 UDP 客户端本身不证明表从未积压，但也不能把 1,000 QPS 直接等同于容量 150。 |
| 全部 socket / 发送尝试失败 | `dns/daemon.rs:1154–1172`、`dns/upstream.rs:1365–1445` | REFUSED + EDE23。上述精确 C / 最终 Rust 运行证据证明该回退等价。 |
| 上游自身回答 REFUSED | `dns/forward.rs:556–565` | 审计合成上游仅产生正常 A / AAAA / CNAME / TXT 回答；源码没有生成 REFUSED 的路径。 |

上述路径使用 EDE 的条件是客户端已有 OPT。原审计无 OPT，`0x8185` 单靠报文无法区分
无路由、表满或发送失败；因此必须新增诊断观测，不能凭原来的 13 包推断原因。

精确 C 的 `forward.c:524–587` 在 `allocate_rfd` / 所有上游 `sendto` 失败后释放 `frec`，
设置 `EDE_NETERR`，再走本地错误回答；`forward.c:592–604` 只在原请求含 OPT 时附加 EDE。
本地匹配实现参考文件 SHA256：`forward.c=ac05784d4233ed10bd166da5fe91e464afecf2883d3c2a0063305d3e81692f95`，
`network.c=8229872d30a2fb2d86ec9a9e550e51fbb8d8d97926e7a02b0137f2a7b40c40c9`；
最终语义判断以该精确 C ELF 的上述执行结果为准。

## 随机性、端口和容量

- `forward.rs:399–408` 对活跃上游 DNS ID 碰撞重新取随机数。并非碰到一次就 REFUSED；
  `IdSpaceFull` 也不进入 `daemon.rs` 的 GroupFull / DuplicateFull REFUSED 分支。
- 原审计配置为 `server=127.0.0.1#15354@127.0.0.1`，没有 min-port / max-port。
  `source_sockets.rs:337–369` 显式 bind `127.0.0.1:0`，由内核选择临时端口；
  C `network.c:1367–1410` 相同。这不等于手动随机选中一个已占用端口便失败。
- `upstream.rs:1210–1258` 的随机 socket pool 用完后会复用兼容 socket，否则开临时 socket，
  不直接因为 pool 的 75 个槽满而 REFUSED。OS socket / bind / send 的真实错误仍可走 EDE23。
- 发送瞬时错误会进入 `send_udp_with_retry`；`EINTR` / `EAGAIN` 与其他 errno 有不同处理，
  `EPERM`、`ENOBUFS`、`ECONNREFUSED` 均会在单上游配置下立即回退，已用 exact ELF 对照。
- 查到的是并发容量门槛，没有按 QPS 主动拒答的限速器。

## 实际 errno 观测工具的边界与校验

[`recheck_syscall_observer.c`](../../../../../../tools/dnsmasq/recheck_syscall_observer.c) 是只读 ptrace 观察器：
只接受 cmdline 包含调用者独占 `/tmp/ROOT/` 的指定测试 PID，附着前后验证 starttime；
不追踪子进程、不注入失败、不修改报文；最长 300 秒后自动 detach。记录 socket / bind /
sendto / sendmsg 的失败 errno，sendto 的目标地址和当时的报文；每条记录同时保留
REALTIME / MONOTONIC / MONOTONIC_RAW / BOOTTIME，避免把内核日志时间直接与另一时钟混用。
性能数据不可取自带 ptrace 的窗口。

Oracle 控制证明：错误 ROOT 在附着前被拒绝；独占合成进程的 192 次真实 sendto 失败被记录；
2 秒到期后进程仍存活，`TracerPid=0`。见 [observer-controls.json](observer-controls.json)。
这项控制运行在无网络的独立 namespace，因此得到 `ENETUNREACH`；它只证明观察器能记录
内核返回错误与正常脱离，不把该 errno 当作真机压力根因。

**判断界线：** EDE23 能把错误定位到 socket / send 层；它本身不能区分 conntrack、内存、
路由或 FD 故障。若真机实际失败 `sendto` errno、对应报文、同窗 conntrack drop 与内核日志
能对应上，再结合这里相同错误的 exact C / Rust 对照，才能判断那批拒答是不是与 C 一致。

## 原审计时钟关联补充

原审计 51 个 Rust REFUSED 与 17 个 C 回答校验失败的独立钟差校准、完整配对、
歧义和固定平移负控制见 [historical-clock.md](historical-clock.md)。该部分使用后来独立
采集的 R 时钟模型，C 窗口作外部验证，不利用旧错误反向拟合模型；历史结论限于强时间
关联，直接 errno 与包级因果链由总报告的新配对诊断提供。
