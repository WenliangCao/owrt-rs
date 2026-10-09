# M6b 最终冻结验收停点（2026-10-09）

最终 opt3 ELF 的统一功能回归发现一个普通产品缺陷：配置接口白名单时，UDP 丢弃发往未显式列出的 loopback 地址的合法查询，而精确镜像 C 正常回答。原参数单次确认重现相同结果。本轮按用户的产品冻结规则停止，没有边测边改产品，也没有完成 M6b 交付。

冻结源码为 `284376c484cf0d3d5d0b2a1d6e3fb9325cc0ec28`。main 随后合入的 health 热修复 `16ac3ceaff66c77846a4e36d3eff1d3cb204866c` 与 dnsmasq 产品无关，冻结身份仍绑定上述源码及实际 ELF。两个产品均关闭 diagnostics feature。

| 产品 | SHA256 | ELF 大小 |
| --- | --- | ---: |
| 最终 opt3 | `e53fbdcb7cb29e0ac0d2d5bcfaa9c5f284849af2114f8d37720bb644485c6c79` | 1,962,024 B |
| 同源 s | `6cb5bcbe3ea2677e4e898a94e90f5407611bbdd0591d44a183344c36d519d09c` | 1,642,536 B |

44 族、68 步的完整回归运行到第 14 步 `m5_listeners-paired` 返回红色；前 13 步通过。listener 批次完成 163 cases、3,534 observations，共 28 failures：14 个 Rust `lo-extra-udp` reference guard 失败，以及对应的 14 个 C/Rust 配对差异。原 predicate、失败结果及失败时产品身份保留，没有放宽门槛或把失败改作方法无效。

随后仅对 `interface-wildcard` 作一次原参数确认：1 case、25 observations、2 failures，C 和 Rust 的 daemon 退出码均为 0。对 UDP `127.0.0.2`，C 返回 `ready.test -> 192.0.2.53`，TTL 为 0；Rust 没有回答。相同目标的 TCP 查询两侧均回答正确。这是稳定的 UDP admission 差异，单次确认后没有继续同参数复跑。

生产调用链是 `main.rs:4471` 的 `udp_acl_name`。`listeners.rs:237` 只匹配显式接口名单，没有沿用 C 隐式加入 loopback 接口的规则；失败后转入 `listeners.rs:248` 的 exception 又要求接口快照中的地址精确等于目的地址，因此 `127.0.0.2` 不能靠仅有 `127.0.0.1` 的快照放行。匹配 C 的 `network.c:501` 在接口限制存在时自动加入 loopback 名称，`forward.c:1787` 的 `iface_check` 因此允许该查询。

原 `listeners.rs:370` 的 `admit` 路径已包含隐式 loopback 允许条件，`listeners.rs:607` 的测试也验证了它；但精确 Linux 生产 caller 走的是另一条 `udp_acl_name` 链。这些原测试没有覆盖产生本次失败的实际 caller。该缺陷属于普通有效配置和正常查询，不是已接受的行为差异，也不是延期极端输入范围。

`E = private/dnsmasq-rewrite/evidence`。冻结和失败证据均留在
`E/M6B/final-284376c4/`：`product-freeze.json`、两个 `release-*/build.json`、
`preflight/listeners-red-summary-01.json`、`preflight/listeners-confirmation-01.json`、
`final-controller/`、`oracle-closure-01.json` 和 `stop-decision.json`。

| 完整归档 | 字节／entry 数 | archive SHA256 |
| --- | --- | --- |
| `archives/functional-red-01/archive.tar.gz` | 48,033,579 B／32,489 | `91e303b79fe88ed1c8e06242699384d0b70ef1ed9fd20af31e2722d115c17653` |
| `archives/listener-confirm-01/archive.tar.gz` | 2,207,350 B／193 | `18c5244e5026ae5fa96c9c5a7e4f8ce00394bf9315d9aa8048e6edf9f3f9b7ca` |

两目录各有 `manifest.json`、`local-verification.json`、`prune.json` 与
`plain/`。本地已逐文件核验 SHA、类型、mode、uid/gid、纳秒 mtime、链接、
device 和全部 xattr；原 tar 保留 overlay upper 与 special 对象。
核验后清除远端对应 upper，恢复普通报告供原收据复核，没有删除未归档证据。
7 项控制器／identity 文件已另经本地 SHA 核对；收尾观察本轮剩余进程为 0。
13 个族级收据保留原 ELF 与 predicate，整体功能 summary 仍为失败。

本轮没有修改产品。完整 M2、targeted 门、资源矩阵与压力门、正式 135 窗口、最终 perf guard、APK 安装/升级/卸载/回滚、最终报告和退役清理均未执行；此前的本地准备及静态盘点不计作运行通过。M7 真机和延期第 4 包仍未执行。物理路由器未操作，不能据此停点宣称最终统一验收或 M6b 交付完成。
