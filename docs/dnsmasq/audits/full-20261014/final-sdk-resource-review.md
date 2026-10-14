# 最终 SDK ELF 的 reload 资源边界独立复核

2026-10-14。源码 `b587282081b72ea0f96cf909e0f70b0bc8de9372`，执行的是
真实 SDK 包内 ELF：SHA-256
`50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c`，
2,124,571 B。**三项指定 reload 边界全部通过**；没有将较早 Oracle 或
340ed ELF 的结果转签。APK/源码/SDK/strip 的独立身份复核另见
[release-budget-review.md](release-budget-review.md)。

本报告只记录 reload 资源边界的六次新 daemon 执行，精确 C/Rust 各三次。
TCP 50k/60k 的 cgroup 资源门由另一审计方运行并单独记录，未加入本报告
数量；这里也不是完整功能族、全资源或真机资格。

全部实验在 Oracle 私有 network/mount/PID namespace，以合成 hosts 和
loopback DHCP 客户端运行。镜像 C SHA-256 为
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。
每个进程核验实际 `/proc/PID/exe` 身份。原 driver 和全量 census wrapper
与先前审读版本完全一致，分别为 `a0fd9f5a…37ade`、`cfa0b912…fd9da0`。

| 场景 | Rust 两轮 ENOMEM | Rust hosts 结果 | 服务及恢复 |
| --- | ---: | --- | --- |
| 无 held TCP，inotify 2,000→6,000，自身 VmSize+1,024 KiB | 2 | 每轮源 EOF 后 1 次 ENOMEM；完整旧代 | UDP/新 TCP、配置/lease DNS、DHCP ACK 均通过；解除限制后保持旧代，下一 close-write 正常恢复 |
| held TCP，HUP 2,000→30,000，自身 VmSize+1,024 KiB，TTL/cache | 2 | UDP/新 TCP 保留旧代样本，held 接受快照不变 | 两轮未过期缓存均被清除，UDP/新 TCP取得新上游地址；DHCP和正常 HUP 恢复通过 |
| held TCP，无限制，inotify 2,000→6,000 | 0 | UDP/新 TCP依次完整 new/next1 样本；held保持旧代 | 配置 DNS、lease DNS、DHCP及最后恢复全部通过 |

受限 inotify 的 EOF/ENOMEM trace 切片在客户探针前采集，确实覆盖了读完整
个 source 后的失败；不把其归到某个未经栈跟踪确认的具体分配调用点。
随后解除限制，**不写 hosts、不 HUP**，逐个查询 old/new/next1：

| 实现 | old 存在 / 2,000 | new 存在 / 6,000 | next1 存在 / 6,000 | 错误地址 / 查询错误 |
| --- | ---: | ---: | ---: | --- |
| 最终 SDK Rust | **2,000** | **0** | **0** | 0 / 0 |
| 精确 C | 0 | 0 | 6,000 | 0 / 0 |

这项全量结果确认最终 Rust 没有复发旧 19bd 的 partial publication。
其它大代的原子性只由首/中/末样本判定，不冒称全量证明。正常 close-write
之后两侧 UDP/TCP 都发布 recovery 名，旧/失败代样本消失。

HUP 的 TTL=2 正控先确认到期取新地址，再缓存 TTL=60 的地址，在未到期
时改变上游并执行失败 hosts HUP。Rust 的 UDP 和新 TCP 都立即得到新
上游地址。C 在同相对限制下总计 36,205 个 ENOMEM，hosts 部分装载、新
TCP 失败；配置 UDP DNS、DHCP及 UDP 缓存清除通过，解除限制后新 TCP
恢复。driver 的 C 一般 `passed=true` 不包含压力新 TCP，未把它解释为
所有服务健康。另两个 C case 零 ENOMEM，完整更新及恢复通过。

所有六个 daemon 都在测试停止前存活，正常退出 0；进程存活只是必要
条件，发布内容、缓存和服务回复分别核验。审计复核器从 raw 重新解码
667 条记录的 DNS 回复，并逐对重解码 census 的 28,000 组 request/reply，
核对 ID、问题、唯一预期 A 答案、计数及文件摘要。

原始证据在 `/dev/shm/full-merge-final-reload-20261014/private/`；本地持久
归档 `private/full-audit-20261014/resume/f7/final-reload/evidence.tar.gz`，
SHA-256 `9cf0b4fdfd74e6cbb2f528dae6ae4f131a8461a1192cf6e237a0c466cf2ca588`。
包含工具快照、raw 报文、进程身份、stderr、syscall trace 和结果，排除
可重建 staged rootfs；逐 case 数字和哈希见
[final-sdk-resource-review.json](final-sdk-resource-review.json)。未修改产品、
未构建新 ELF、未操作物理路由器。
