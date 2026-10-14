# FULL-R2 独立修复复核

日期：2026-10-14。主审基准仍为 `e9d89b17`；本文件单独复核修复分支，
不把分支结果写成 main 问题已关闭。未修改产品、未提交、未操作物理路由器。

**`68f96cf3` 修好了原 hosts ENOMEM 中止及已测相邻边界，但不能单独放行：
失败 HUP 留下了本应清除的未过期转发缓存。** 后继 `98bc6b58` 的静态修改
针对这个问题正确；本文当前阶段尚未获得其冻结 ELF，不能把静态审查算作
运行验收。

## 身份与独立新运行

| 项目 | 实际对象 |
| --- | --- |
| 被执行修复 commit | `68f96cf3fb6e0b17f4fc6a9df768c85d1d79a954` |
| 修复 ELF SHA256 | `b65c06c561a9a852ec42222a5a31be493c742f14d8bc454dbeab22542b26b490` |
| 构建 | 2,081,248 B，Rust 1.98.1，SDK-linker AArch64 musl static PIE、opt3；不是新 APK |
| 精确镜像 C | `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` |
| 源码核对 | 提供的 `source-fixed` 中 172 个 component/linker 输入与 Git commit 全相同 |
| 构建边界 | 源码副本没有 `rust-toolchain.toml`；builder 显式使用 `+1.98.1`，没有隐瞒缺项 |

全部实验在 Oracle 私有 network/mount/PID namespace。复用已提交原探针时，
没有改产品或故障条件；新增探针的原始代码、报文、完整结果留在
`private/full-audit-20261014/r2-fix-review/` 和 Oracle
`/dev/shm/full-audit-r2-verify-20261014/private/`。派生数值及 SHA 索引：
[r2-fix-summary.json](r2-fix-summary.json)。

对冻结的 fixed test ELFs 另作独立新运行：lib **784 passed / 20 ignored**，
main binary **78 passed / 3 ignored**。修复方报告的其他场景不计入这些独立
执行数量。

## 原中止修复成立，持久压力下保留旧代也得到完整扫描证明

直接用主审原 `recheck_hosts_limits.py`，初始 2,000 hosts，替换为 30,000，
每侧限制为各自 `VmSize + headroom`，没有预先 TCP 查询改变原内存布局：

| headroom | C ENOMEM / 退出 | 修复 Rust ENOMEM / 退出 | 解除限制并 HUP 后 |
| ---: | --- | --- | --- |
| 256 KiB | 25,800 / 0 | 30 / 0 | 两侧 UDP/TCP 均恢复 |
| 512 KiB | 22,836 / 0 | 117 / 0 | 两侧 UDP/TCP 均恢复 |
| 1,024 KiB | 18,036 / 0 | 15 / 0 | 两侧 UDP/TCP 均恢复 |

三个 Rust 都在测试停止前保持存活；与主审基准同点 SIGABRT 的反例相对。
新 `ReadStats::allocation_failed` 区分插入/解析分配失败和 EOF/普通重复，
读取在当前 8 KiB chunk 后停止；`read_hosts_with_notices` 返回 Err，先丢弃
未发布 generation，再恢复旧 owner 视图，避免持有失败大集合时格式化
完成日志。原 `hosts_read` 调用链的中止被这一释放顺序确实避开。

独立追加多文件事务：初始 `preold` + 2,000 `old` + `postold`；依次改成
`prenew` + 30,000 `new` + `postnew`，在 +1 MiB 限制下 HUP。解除限制但
**不再 HUP**，每侧逐一查询全部 2,000 个旧名和 30,000 个新名：

| 实现 | 旧名存在 | 新名存在 | 地址错误 | pre/post 来源 |
| --- | ---: | ---: | ---: | --- |
| C | 0/2,000 | 11,913/30,000 | 0 | 按 C 的逐条部分装载行为更新 |
| Rust | **2,000/2,000** | **0/30,000** | 0 | `preold/postold` 保留，`prenew/postnew` 不可见 |

64,000 个响应的原始 framing/报文及逐批 digest 已保留。随后两侧正常 HUP
加载三个 recovery 来源全部成功。这个检查证明已测失败事务没有把较早
成功读取的 `prenew` 与旧大 hosts 混成发布代，强于仅检查首/中/尾三点。
Rust 的保留旧代策略与 C 部分发布并不相同，应作为明确恢复合同，而不是
宣称资源不足时所有可见行为逐字一致。

## 诊断日志和既有 TCP 的正向控制

在原替换输入中交错 30,000 条 `invalid-address`，日志写真实普通文件；
256/1,024 KiB × C/Rust 四个新运行均存活并能恢复。Rust 分别处理 3,177 /
6,196 条 bad-address 诊断后停止本次读取，日志只出现 initial 2,000 和
recovery 1 的 hosts completion，未出现声称失败 30,000 条已加载完成的
completion。未复现“同一 chunk 中的诊断再次使 daemon 中止”。

另用预先接受的 TCP 连接跨越失败 HUP、解除限制和正常 recovery HUP。
既有 TCP 的旧 hosts 视图在 C/Rust 均保持，新的 Rust UDP/TCP 继续使用
完整旧 generation。受限条件下 C 的新 TCP 查询会失败，解除限制后恢复；
这个差异单独保留，不能把 C 的新 TCP 失败算成通过或与进程中止混为一谈。

## 68f 的阻断：失败 HUP 没有清除动态缓存

新独立 TTL/HUP 控制先证明 TTL=2 的旧缓存会正常到期，再填入 TTL=60 的
`hup0.expiry.test`，将上游地址从 `.12` 改为 `.13`，随后执行必定失败的
hosts HUP。结果：

| 失败 HUP 后 UDP | 地址 | TTL |
| --- | --- | ---: |
| 精确 C | `198.51.100.13` | 60 |
| `68f96cf3` | **`198.51.100.12`** | **58** |

Rust 新 TCP 也取得旧 `.12`；原连接的 hosts 快照仍正确，因此不是整个
测试失效。`68f` 的新错误返回在 `main.rs::reload_hosts_data` 提前退出，
绕开唯一执行 `cache.clear_counted()` 的 `daemon.reload_hosts()`。
这会让管理员用 HUP 清除错误/过时转发答案时，在 hosts 内存不足情况下
继续看到旧地址，直至 TTL 到期。原中止虽消除，HUP 行为不能因此退化。

后继 `98bc6b58d9b5d8077e2abefd2867bbf380d07c79` 新增
`begin_hosts_reload()`，在读取 hosts 前清 forwarded cache/counters，成功
后只发布 hosts；静态上覆盖了上述早退分支，也保留旧 hosts 与 in-flight
forwarding 的所有权。它必须绑定后继 ELF 新复跑上述反例后才可关闭。

新增缓存边界还应包含 cache-size=1,000/10,000、held TCP、初始 1/2,000
hosts 以及 256/512/1,024 KiB 余量：现有 `Cache::clear` 会
`Arc::make_mut` 共享内容块并重新分配 name shard roots，held TCP 下清空
操作本身需要分配。本文仅指出有源码依据的待测边界，**尚未将其冒称为
后继 ELF 的已复现中止**。

## 仍需限定的“整代不完整”表述

一个独立 source-bound musl allocator probe 对 `68f` 的 `hosts.rs` 注入
**一次**分配失败：`expand-hosts` 的 domain callback 使用与 main 相同的
`try_copy(suffix).ok()`，首个 suffix 分配失败被转换为 `None`。结果只有
`short`，缺少 `short.example.test`，但 `stats.allocation_failed=false`。
这项边界在修复前已存在，既不是本轮新增回归，也不是 shipped daemon 的
黑盒复现；不能据此否定原持久 ENOMEM 修复。但 callback 的无域名与分配
失败仍无法区分，所以不应把这轮结果表述成“任何不完整 generation 均不会
发布”。若恢复合同要求这一点，需传播域名派生失败并补相应服务级测试。

这份复核未覆盖整个进程所有 allocator failure、全局 OOM、所有 hostsdir
路径及十组件组合。没有新的 CPU/性能结论。当前主审 main 的 R2 保持原
状态；`68f` 仅证明原中止已修，`98bc` 运行验收及综合分支结果另行追加。
