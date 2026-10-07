# Scheme A：新 readiness 基线上的独立候选

2026-10-07。状态：本地原语和布局证据已完成；镜像服务、资源、压力和 CPU 门未运行，A 不在 main。root 仍在修 UDP-only 基线的 TFTP/helper runnable 和健壮性，实际无 A product commit 尚待给出；届时 A 要以同一基线重建、全门 fresh 重跑，不提前 rebase 或合入。所有内存数字为 requested allocation / 类型布局，不冒称 Oracle PSS 或路由器表现。

## 保存与重建

旧 A 分支 tip `a9f069a4` 保存到 `archive/m6b/tcp-scheme-a-pre-readiness-20261007`，472 个原始证据文件保存在 `E/M6B/tcp-a-pre-readiness-preservation/evidence.tar.gz`，archive SHA `923dfbf6f8a89ed7dcae8574cc7b7df16f54aaca1883efb3f8e11dbc79b135f6`。

新分支 `m6b/tcp-a-ready` 从无 A 的产品 `6f3bed3de272162bf3cbbb0914de4c5367e324fb` 创建，独立 cherry-pick 存储和 COW 视图测试（`65256826`、`7e975ab6`），没有 merge main 后再受旧 revert 抵消。`896d3d73` 补 retained-view 的 negative authority / reverse expiry / lease generation / RRset rotation / clear 与 capacity 0/1/150/4096；`285e0947` 才是 checked compact-link 表示修订。u64 generation 没有缩短。

E = 仓库 ignored `private/dnsmasq-rewrite/evidence/`。原 56 B Slot 原型及全部布局证据另保存到 `archive/m6b/tcp-a-slot56-readiness-20261007`（tip `07aa3f46`）和 `E/M6B/tcp-a-slot56-preservation/`：完整 211 文件 archive SHA `a3f5d5d6480704ea57c8f98f2c10c0f5149e5f22537daaf9fc3697e35091cf92`。不能用其结果替代 compact revision 的资格。

## 实际布局：纠正预测与首个原型

原设计文档的约 32 KiB 私有 LRU、约 660 KiB/20 views 是模型，首个原型没有达到：每 Slot 有 block/offset/gen 和两个 `Option<usize>`，实际 56 B；它每 view 复制 225 KiB。根据主线程授权在设计 A 表示内修正，去掉冗余 block/offset，用 slot/64 定位；prev/next 为 checked `Option<NonZeroU32>`、generation 仍 u64。生产 scalar 已在 `config/scalar.rs:138` 将 cache-size 限制为 5,000,000；primitive 在分配之前也检查 u32 link range，0/1 与最大生产索引有独立测试。

| 4096 短名 A | 原 56 B Slot 原型 | compact revision `285e0947` |
| --- | ---: | ---: |
| AArch64 Slot / Entry / ContentBlock | 56 / 72 / 16 B | 16 / 72 / 16 B |
| owner Slot array | 229,376 B | 65,536 B |
| content/index root vectors | 1,024 B | 1,024 B |
| **snapshot 新 requested bytes / allocations** | **230,400 B / 3** | **66,560 B / 3（65 KiB）** |
| 20 个同代际 view 结构增量 | 4.395 MiB | 1.270 MiB |
| ordinary singleton hit retained bytes | 16 B（返回 EntryId Vec） | 16 B（返回 EntryId Vec） |
| 全部 64 name shards detach | 368,000 B / 4,224 allocations | 同左，未再优化 |
| 全部 64 content blocks detach | 296,960 B / 128 allocations | 同左，未再优化 |
| 全 detach child Drop net requested | −895,360 B | −731,520 B |

65 KiB/view 包括 32 KiB links、32 KiB u64 generations 与 1 KiB roots，不再宣称它是设计预测的 33 KiB/view。COW name shards 仍使用 `HashMap<Arc<[u8]>, Vec<usize>>`：detach 共享规范名 payload，但每个 singleton Vec 又分配；4096 个 singleton 的 capacity 总和由 parent 16,384 缩到 clone 4,096，4,224 次分配含 4,096 个小 Vec、64 个 HashMap backing 和 64 个 shard Arc。未实现 inline-singleton/shared-Many，也未改 Name/RDATA/DHCP 第 3 项。

测量方法：`m6b_tcp_a_layout.py` 从精确 commit 创建 ignored diagnostic copy；LLVM sizeof globals 给出 `aarch64-unknown-linux-musl` 布局；native 64-bit System-forwarding allocator 计量 clone/hit/detach/drop scopes。它不替换产品 allocator，不包含 allocator metadata/页碎片/其他 daemon 状态。compact layout JSON SHA `4f05c9393747f53b11237e02eaade46d6540958f389598cc02b746ac81cb804e`，完整目录 `E/M6B/tcp-a-ready-285e0947/layout-01/`；target/native 命令、源码输入 SHA 和 stdout/stderr 均保留。

## compact revision 本地重跑

| 门 | 新证据 | 结果 |
| --- | --- | --- |
| full host lib / bin | `local-full-tests-01` | 618 passed / 8 ignored；bin 12 passed。Linux Oracle 单元尚未重跑。 |
| cache / transfer / view isolation | `cargo test --lib dns::cache` | 49 passed / 1 ignored；capacity、lease、negative、reverse、generation、COW 与 transaction。 |
| 精确 C extracted primitive | `cache-primitive-01` | **21** 场景、22,571 commands、0 mismatch；summary SHA `c137b35be19ffd3396d3825122250c9243e5fdbb5623ce1b6c58b259ae1480cc`。旧文字的“20 场景”是计数错误。 |
| safe mutator negative controls | `guards-02` | 5/5 拒绝：detach 丢 inherited content、detach 丢 name index、禁 RRset 轮转、保留过期 reverse、复用 generation。每变体都实际执行 31 tests 后失败，编译失败不计负控通过。 |

`guards-01` 的 content 变体生成器写错 Rust 表达式，编译失败而不是执行 tests；整个 receipt 标为 failed，原源码/stdout/stderr 保留。修正生成器后以新目录 `guards-02` fresh 重跑，result SHA `3dbca6037e6541e23fe945cf88440ddcb6536cd2958007782ed46ee0b7b18bcf`。这些变体安全地模拟状态损坏，不注入共享可变 alias/UB，不能冒称已执行“漏 detach 后跨 owner 写内存”的 unsafe 负控。

## 真正镜像服务门与未闭合缺口

服务主入口为 M5 最终 driver：`m5_final_validation.py → families → m5_dns_cache / m5_edns / dns-files / m5_dns_endpoints / m5_interface_records / logging-all-scopes`。`m2_rootfs.prepare()` 校验 C `097a9e21…cab87`，两组执行同精确 rootfs 的 chroot，`process_identity()` 核验实际 `/proc/PID/root` 与 ELF SHA。native reference/deps 只供工具编译依赖；旧九脚本默认硬断言 **bba5… native C**，不因目录改名为097而变成镜像门。

| 合同 | 现有实际镜像覆盖 | 仍未运行的新补证 |
| --- | --- | --- |
| S1 accept snapshot | 父 UDP 学习/替换、其他 TCP、HUP cache/hosts、lease added/renamed/released、routing/interface generations | 旧 cache caller connect 后先发 `accepted-health`，不拒绝“首 query 才 snapshot”。新 `m6b_tcp_accept_snapshot.py` 以 image UBus `tcp_connections=1` 确认 accept，然后父 learn/replace，才发 child 首 DNS；**未在 Oracle 运行**。 |
| S2 fixed clock | TCP fixed TTL、expiry/stale、late import、真实 3.2 s lease TTL | 150 s 生命周期仍待执行。 |
| S3 private effects | 子插入、轮转、debug parent、capacity/conflict/order矩阵；本轮 retained-view 原语 | 不能把所有 parent UDP 失败前缀写成 child mutator 的实际镜像证明。 |
| S4/S5 export/order | A/AAAA/PTR/CNAME/negative/SOA/generic、held-connection即时导回、RRset/反序 | 逐 query parent counters、成功空 transaction、失败无 transaction 专项仍待补镜像证据；已有 primitive 不能冒称 mirror IPC。 |
| S6 current parent | local import conflict、absolute expiry、lease publication、capacity recovery | 导入失败 prefix 的实际 TCP 专项仍待补。 |
| S7 cross-connection/EOF | 其他连接插入、stale EOF、typed transfer 正常顺序 | 跨连接竞争 slot 顺序；C partial pipe 的故障边界仅 source/primitive，不声称 Rust typed transfer实际具备半条 pipe。 |
| S8 lifecycle | stale refresh、parent progress、TERM cleanup、logging FIFO/rotation、endpoint reuse | 100-query EOF、150 s、RST/half-frame、slow reader/writer、配置上限/accept EMFILE、view/pinned roots 余额。 |

全缓存族资格仍要求 536 actual cases / 512 required 和 8 个独立 C reverse-order补充，不能将 `--only` 部分结果当整族闭合。两个 S1 caller 只是补门，offline witness guard 的 1 test（12 个 corruption variations）已通过，不是 actual C/R 通过。

## 执行与 CPU 硬门

先由 root 冻结 M6b functional-mode 工具和新 source-bound reviews/manifest，再使用 prefixless `git archive --format=tar "$SOURCE_COMMIT"`（PAX comment为commit）与 fresh source path 构建；旧 `--prefix=source/` archive 不满足 final prepare 的路径身份。source/ELF/build/link-map/工具/镜像/runtime/SDK/资产/44-family registry 全部绑定；不导入旧 M5 completed receipts。s 只做同源性能对照，不当功能 ELF。

```sh
sudo -n python3 "$TOOLS/m5_final_validation.py" run --manifest "$MANIFEST" \
  --phase families --attempt 1 \
  --family m5_dns_cache --family m5_edns --family dns-files \
  --family m5_dns_endpoints --family m5_interface_records --family logging-all-scopes

sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/m6b_tcp_accept_snapshot.py" run \
  --image-root "$IMAGE" --rust "$A_ELF" --expected-rust-sha "$A_SHA" --side c --out "$OUT/first-query-c"
sudo -n sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/m6b_tcp_accept_snapshot.py" run \
  --image-root "$IMAGE" --rust "$A_ELF" --expected-rust-sha "$A_SHA" --side rust --out "$OUT/first-query-a"
python3 "$TOOLS/m6b_tcp_accept_snapshot.py" compare \
  --c "$OUT/first-query-c" --rust "$OUT/first-query-a" --out "$OUT/first-query-comparison.json"
```

CPU 增量门基于 root 将冻结的 **新无 A readiness R3**，不能用旧 M6a 20 µs 替代。每窗 `u = daemon cgroup usage_usec / correct replies`；cgroup **已经包括 C 子进程 CPU，绝不再相加 child CPU**。按最新版 M6B_PROTOCOL 修订，A 满足 `median(u_A) <= 1.05 × median(u_R3_new)`，并保持 `median(u_A) < median(u_C_new)`（同新配置的镜像 C）；吞吐/p95不得退 >5%，errors/FD leaks=0、S1–S8零新增差异。proc child CPU只作 component accounting交叉检查。CPU/服务/资源/压力门均未测，不称通过；失败保留所有同候选结果，不拼不同 revision 的最好窗口。

本轮只操作本地独立 worktree；root 独占 Oracle 诊断。物理路由器未访问。
