# 独立方案 A：S1–S8 服务与资源生命周期执行清单

2026-10-08。本文件只读核对当前源码／canonical registry／工具接口，未访问 Oracle、未构建或运行测试，未修改公共账本。main 产品仍无 A。root 已实际取得 d8ddb22b 的 751 lib / 52 main / 68 UBus、基础 core/policy/EDNS/lease、layout 和视图正负控结果；这些不替代下面尚未执行的服务、资源和 CPU 门。

## 唯一被测身份

- A source：`d8ddb22b3dcd3cce2eae44b0941f5c4095800b3c`。
- feature-off opt3 product ELF：`924bdfc240f1ef811c8eacb4035a7476f8581166469144b6e4a22a01449a2c71`，1,957,928 B。
- Oracle source：`/home/ubuntu/dnsmasq-m6b-20261007/a-fresh-d8ddb22b/source`；ELF/build/map：同目录的 `../private/opt3/{dnsmasq-rs,build.json,link.map}`。
- link map SHA：`f7d8d6dbd252b1d78e3ac1b83d8d471762a17a3e7e162b5a61a51ba51b038242`。
- 镜像 C：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`，同镜像 overlay。native `bba5…` 是原语／helper，不能作为本层 C daemon。

上述 A build 由本机 `E/M6B/a-d8-product-prep-01/opt3/build.json` 核对；运行前 root 再核实际 ELF、build/map、source archive/PAX、产品输入、冻结 tools、registry 和镜像文件。只用此 A ELF，不拿诊断 companion、s 或历史 766 ELF替代。所有输出 fresh/private，失败与旧 ELF 的证据保留。

## 先退役过时的 Rust partial-pipe 入口

当前 d8 和 main 的 `dns/mod.rs` 都没有 `tcp_transfer` 模块，产品没有 byte Receiver。旧 `cache_partial_eof_rust_diff.py` 的 `dns::tcp_transfer::partial_eof_tests::exact_c_partial_eof_probe` 不存在；0 tests 之后缺少 `rust-states.jsonl` 是过时入口失败，**不是通过，也不要求重新实现已退休 Receiver**。账本“早期阶段与退休分支”已记 TCP 流式导入 `dff7a39` 于2026-10-01退休、未合产品。旧脚本／原始故障保留为历史研究，当前 Scheme A 将这个 Rust transport gate 标 `retired/not-applicable`。

当前实际路径是：

`main.rs::TcpDnsWork::run_forward`（2633–2703）→ `DnsDaemon::tcp_view_extract`（1780–1803）→ `CacheContext` 提取／`Cache::capture_commit_counted`（855）→ `Option<CacheTransaction>`；有成功事务便同步调用 `DnsDaemon::import_tcp_cache_transfer`（1832）→ `CacheContext::import_transfer` → `Cache::import_counted`（937）。导回发生在本次 forward 返回和下游 Writing 之前，使用父当前时间／local 状态。一份完整 owned Vec 在单 owner 中消费，无字节传输、长度解码、IPC EOF或异步导入队列。成功空事务与失败无事务仍不同；父途中移除／逐出不因后段失败回滚。

C 是另一边界：`cache.c:843–918` 的 commit 写 `PIPE_OP_INSERT`、记录和 `ssize_t -1`；`cache.c:952–1056` 的 `cache_recv_insert` 在 op/长度/name/ttd/flags/address 的 `read_write` 失败时返回0，只有完整 -1 marker 才 commit。纯 C `cache_partial_eof_oracle.py` 的9个切点仍有效，但没有对应当前 Rust 生产入口；可作 C-only 参考，不能填入 A passed。

实际上游 socket EOF属于 `forward.c:2087–2178 tcp_talk` 的旧连接关闭／有限重连，以及 Rust `dns/tcp_upstream.rs` 的持久网络 exchange。下面 `m6b-tcp-upstream-eof` 验 old socket EOF→fresh reconnect EOF→fallback→父缓存命中，**不替代 C 内部 pipe 截断**。S4–S7 有效证明由 fresh capture/import library transfer、完整 cache 服务和 accept/failure-prefix/cross-completion caller组合提供。

## 服务：完整 canonical 六族，27 steps

按此顺序独立串行运行，每族保留完整 argv/result/checks/inventory/timeout，不用 `--only` 代替整族：

| 顺序／family ID | steps | 本层目的 |
| --- | ---: | --- |
| `m5_dns_cache` | 12 | fresh镜像 C/A全场景；8次C reverse变体；`m5_dns_cache_qualify`；`qualify-dhcp-caller` |
| `m5_edns` | 3 | C/A run和compare；接受时身份、缓存策略、MAC/ECS与TCP合同 |
| `dns-files` | 1 | `m5_dns_files.py`完整paired；hosts/servers/resolv重载、FIFO、已接受TCP快照 |
| `m5_dns_endpoints` | 4 | syntax、service、local archive gate、精确C source-row audit；路由／server generation |
| `m5_interface_records` | 6 | syntax、service、qualify及3个closeout；已接受接口／lease／synth代际 |
| `logging-all-scopes` | 1 | 完整paired scopes；已接受目标、FIFO／backpressure／TERM、副作用与计数 |

最小 spec 用最新冻结工具的 `m5_final_validation.commands` 展开**原 registry**，不调用最终 `prepare/run` 冒充完成 final reviews/perfguard/package。`tools_root` 可与产品源树分开。代码块只生成27 jobs，并不执行：

```python
# root在Oracle上填真实路径；spec/result均存fresh private。
import json, pathlib, sys
sys.path.insert(0, M6B_TOOLS)
import m5_final_validation as controller
registry = json.loads((pathlib.Path(M6B_TOOLS) / 'm5_final_families.draft.json').read_text())
spec = {
    'source_root': M6B_A_SOURCE, 'tools_root': M6B_TOOLS,
    'source_commit': 'd8ddb22b3dcd3cce2eae44b0941f5c4095800b3c',
    'elf': M6B_A_ELF,
    'elf_sha256': '924bdfc240f1ef811c8eacb4035a7476f8581166469144b6e4a22a01449a2c71',
    'image_root': M6B_IMAGE, 'runtime_root': M6B_RUNTIME,
    'family_registry': registry,
    'bindings': {'reference_source': M6B_C_SOURCE, 'link_map': M6B_A_MAP},
}
order = ['m5_dns_cache', 'm5_edns', 'dns-files', 'm5_dns_endpoints',
         'm5_interface_records', 'logging-all-scopes']
jobs = []
for family in order:
    selected = dict(spec, selected_families=[family])
    jobs.extend(controller.commands(selected, 'families', pathlib.Path(M6B_A_SERVICE_OUT)))
assert len(jobs) == 27
# 每job实际执行且exit=0后，使用现有严格checks与完整inventory检查：
# controller.check_result(pathlib.Path(job['result']), job['checks'], job.get('inventory'))
```

root 的独立 A identity receipt应绑定上述 spec、registry/tool/source/ELF/build/map/archive/image SHA和每job的 argv/result/raw SHA／exit／checks／inventory。该 receipt不是最终 `m5_final_validation` completion，不伪造 final reviews、44族完成或169统一复测。若工具／夹具变化，保存原失败并冻结新工具，fresh复跑受影响族；产品变化则所有前置证据须重新绑定／复跑。

Endpoint第三step会等待本地实际归档；root需另一通道 pack→下载→verify-local→供 proof，不跳过直接source-row audit。具体命名和proof格式见 [M5最终验收 endpoint 归档门](../M5_FINAL_VALIDATION.md#endpoint-本地归档门)。

## 五个 accept／父前缀／完成顺序 supplements

```sh
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_accept_snapshot.py" run \
  --side c --source-commit "$M6B_A_COMMIT" --expected-rust-sha "$M6B_A_SHA" \
  --image-root "$M6B_IMAGE" --rust "$M6B_A_ELF" --out "$M6B_A_OUT/accept-c"
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_accept_snapshot.py" run \
  --side rust --source-commit "$M6B_A_COMMIT" --expected-rust-sha "$M6B_A_SHA" \
  --image-root "$M6B_IMAGE" --rust "$M6B_A_ELF" --out "$M6B_A_OUT/accept-a"
python3 "$M6B_TOOLS/m6b_tcp_accept_snapshot.py" compare \
  --source-commit "$M6B_A_COMMIT" --expected-rust-sha "$M6B_A_SHA" \
  --c "$M6B_A_OUT/accept-c" --rust "$M6B_A_OUT/accept-a" --out "$M6B_A_OUT/accept-comparison.json"
```

完整五case不可缩减：`accept-before-parent-learn`、`accept-before-parent-replace`、`parent-import-failed-prefix`、`child-eviction-parent-counters`、`cross-connection-progress`。实际 parent UBus `tcp_connections=1` 见证 accept-before-first-query，不把 connect/sleep 当接受快照点；cross的第二accept原始metrics也必须验。compare核同候选/source声明、immutable镜像 provenance、完整5cases、query/reply、raw metrics、上游事件、时序及30负控。

source_commit在supplement里是冻结声明；source→ELF仍必须由外层 archive/product build 证明，不能只凭CLI文本授资格。supplement不替代完整 cache family。

## public 11资源／生命周期 profiles

资源执行时 Oracle不并行构建、测试、fuzz或其他负载；同A product ELF、镜像C分别fresh namespace串行。一次完整 run即可覆盖11profiles，不传 `--profile` 缩减：

```sh
python3 "$M6B_TOOLS/m6b_tcp_pressure.py" plan --out "$M6B_A_OUT/pressure-plan.json"
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_pressure.py" run \
  --side c --source-commit "$M6B_A_COMMIT" --expected-rust-sha "$M6B_A_SHA" \
  --image-root "$M6B_IMAGE" --rust "$M6B_A_ELF" --out "$M6B_A_OUT/pressure-c"
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_pressure.py" run \
  --side rust --source-commit "$M6B_A_COMMIT" --expected-rust-sha "$M6B_A_SHA" \
  --image-root "$M6B_IMAGE" --rust "$M6B_A_ELF" --out "$M6B_A_OUT/pressure-a"
python3 "$M6B_TOOLS/m6b_tcp_pressure.py" compare \
  --source-commit "$M6B_A_COMMIT" --expected-rust-sha "$M6B_A_SHA" \
  --c "$M6B_A_OUT/pressure-c" --rust "$M6B_A_OUT/pressure-a" \
  --out "$M6B_A_OUT/pressure-public-comparison.json"
```

| profile尾名 | 实际覆盖／不可扩大结论 |
| --- | --- |
| `100-query` | 两个忽略帧不计query；100个普通完整回复后EOF，99时G1 |
| `half-frame` | 1字节长度头及不完整32字节body的下游EOF；无回复且回收 |
| `rst-forward-import` | 上游已持有时下游RST；成功完成仍父导入一次／无live-freed并命中 |
| `upstream-eof` | 四个真实上游query事件，old/fresh EOF→fallback；逐原始wire/ID核对、父导入命中 |
| `slow-write` | 下游请求分段；不完整时不回答，父UDP进展，补齐后回复 |
| `slow-read` | 100个约48KB TXT回复，真实下游背压/G1，父进展，随后100th EOF |
| `capacity-20-30` | 两监听地址20→30实际G，31st排队，已有连接／父继续进展，释放后31st回答 |
| `idle-pin-150` | 已接受旧cache/hosts，140次父churn+HUP；140s仍旧视图、最近query不延长150s绝对寿命 |
| `reconnect-0` | cache disabled，10批×20连接 |
| `reconnect-150` | small cache，10批×20连接／父churn／子旧视图 |
| `reconnect-4096` | capacity4096、10批×20连接；每批仅64双A seed=128 records与200父churn，**不证明实际4096满载或半满** |

各侧自己的 idle FD targets连续3次、间隔20ms确认；排空要求实际 `tcp_connections=0`、FD回原集合、child=0/thread=1连续3次；之后固定0/1/5/15/60秒资源样本。PSS/RSS是完整观察，不要求C/A逐值相等。对C统计包含父/子，不以Rust无子进程就视为已排空。`complete_profiles=11`、missing/semantic differences为空、`public_resource_gates_passed=true`才关闭这一公开层；`qualified=false`和`internal_balance_qualification=false`必须原样保留。

## S1–S8 逐项归属与剩余硬门

| 合同 | 本次实际入口组合 | 尚不能借这些结果宣称的边界 |
| --- | --- | --- |
| S1 accept snapshot | full cache/EDNS/files/endpoints/interface；accept learn/replace；idle-pin150 | 不能用首次query才取父状态；static/library snapshot不代替实际accept见证 |
| S2 fixed clock | full cache的accept expiry／zero clock/stale；idle-pin150 | 不能用wall-clock TTL／缩短寿命省内存 |
| S3 child private mutation | fresh view正负控＋full cache RRset/reverse/CNAME；child-eviction counters／reconnect | 子命中／rotation不合并父LRU或全部child metrics |
| S4 export set/timing | fresh transfer library＋full cache的CD/RA/stale/generic/negative；RST-import／父hit | 成功空事务必须导回；失败extract无commit；typed完整事务不证明native半pipe故障 |
| S5 ordered transaction | fresh transfer/CNAME/negative/reverse＋full cache实际wire和8C reverse variants | 不能sort/dedup或传child EntryId给父 |
| S6 current parent/failure prefix | fresh transfer＋failed-prefix/child-eviction supplements＋lease TCP caller | 不允许database式回滚已发生的父移除／逐出 |
| S7 completion/EOF order | cross-completion supplement＋full cache/import timing；fresh库有序import | dead Receiver切点retired；upstream socket EOF不是IPC EOF；不新加全局accept FIFO |
| S8 lifecycle/side effects | public11＋full logging FIFO/TERM；full cache stale refresh；d8 main实际log-only/stale测试 | G1/work0和内部view/root/live requested须诊断实测；FD恢复不能证明对象余额 |

public11之外仍有普通硬门，不把它们悄悄记为passed：source-bound companion的方法正负控、完整／半满／大RDATA缓存的**实际占用**、idle snapshot下父持续churn及root版本、10批内部余额、log-only G1/work0及stale pending1→0、accept EMFILE与恢复。现有 ENOSPC/EMFILE最终压力、完整M2/APK lifecycle仍在最终收尾，不由11profiles替代。既有 `m5_dns_cache` 本身的zero/full-capacity场景与公共reconnect容量也不等于完整内存占用矩阵。

诊断准备／构建／绑定入口已有：

```sh
python3 "$M6B_TOOLS/m6b_resource_companion.py" prepare \
  --repository "$M6B_REPO" --source-commit "$M6B_A_COMMIT" \
  --product-sha256 "$M6B_A_SHA" --out "$M6B_A_DIAG_PREP"
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' ORACLE_BUILD_LINK_MAP=1 \
  sh "$M6B_TOOLS/oracle_build.sh" "$M6B_A_DIAG_SOURCE" "$M6B_A_DIAG_BUILD" release
python3 "$M6B_TOOLS/m6b_resource_companion.py" bind \
  --receipt "$M6B_A_DIAG_PREP/receipt.json" --diagnostic-source-root "$M6B_A_DIAG_SOURCE" \
  --build-json "$M6B_A_DIAG_BUILD/build.json" --diagnostic-elf "$M6B_A_DIAG_BUILD/dnsmasq-rs" \
  --product-build-json "$M6B_A_BUILD/build.json" --product-elf "$M6B_A_ELF" \
  --out "$M6B_A_DIAG_PREP/bound-receipt.json"
```

bind只证明产物链，不是balance通过。按 [resource companion方法与controls](M6B_TCP_RESOURCE_COMPANION.md) 用真实trace（`DNSMASQ_M6B_RESOURCE_TRACE=/m2/diagnostic.jsonl`）逐项验收；此诊断ELF额外FD／registry／timer／allocator计数影响运行，不能用它替代本A ELF的功能、CPU或PSS。当前仅prepare/bind入口，没有一键内部controls／balance资格分析器，root须保留实际controls/trace/失败和显式结论，不手填public qualified。另需route basic/clears、HUP/idle-interface新actor及最终same-ELF重跑；debug C UBus缺陷按既有独立guard处理，不能抹掉失败。

最后CPU45的prerequisites固定为 primitive、view-isolation、service、resource-lifecycle、pressure、small-cache-150、empty-cache、S1…S8；全部证据绑定同一A source/ELF才可plan。硬门 A CPU≤1.05×新R3且严格<C、QPS≥.95×R3、p95≤1.05×R3、A errors/FD=0不变。最终135窗口、44族／M2／资源／压力／APK仍在A全部门通过与main整合之后，任何本清单子集结果不替代最终验收。
