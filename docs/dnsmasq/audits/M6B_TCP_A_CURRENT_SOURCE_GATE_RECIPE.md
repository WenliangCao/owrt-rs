# A69bc：共同服务修复后的原语、隔离与 companion 复绑定队列

2026-10-08。本次仅本地读 Git、工具、文档和既有证据；没有访问 Oracle、构建或运行门。
这是 root 串行执行的 recipe，不是通过报告。main 仍无方案 A。

## 身份与重跑边界

| 对象 | 本次身份 | 既有证据的有效范围 |
| --- | --- | --- |
| 无 A 产品 | `e8b1d6c411fba324888e3e202c0c133156afbed4` | 新 CPU45 的 R3 对照；不得留旧 1bd common/s |
| 独立 A 产品 | `69bccf2738f2c07cbc6d8b8a950015d4cea10af3` | 全部门过前不合 main |
| A opt3 | controller 输出 SHA `21937fa33b2552801278ea6cb15f0e13cb733824e4cd236382f968a1c1c4324b`，1,962,024 B | root 仍须核实际 `pair-udp-acl-01/a/private/opt3/build.json`、ELF 与 map；此处没有替代核验 |
| 历史 A | `ae1cdba6bd03cf4e28b566c31f610a31020824de` / SHA `e2900727…` | 旧原语、隔离、layout、companion 通过仍是历史，不能改 source_commit/ELF 字段充新资格 |

`git diff ae1cdba6 69bccf27 -- components/dnsmasq components/ubus` 为 9 个文件：
`dns/files_runtime.rs`、`listeners.rs`、`main.rs`、`net.rs`，加 hostsdir init、neighbor tail、
NEWADDR、stale-log、UDP ACL 五个入口测试模块。存储和协议主体的 `dns/cache.rs`、
`dns/daemon.rs`、`cache_engine.rs`、`cache_reply.rs`、`tcp_service.rs`、`tcp_upstream.rs`、
`tcp_exchange.rs`、`wire.rs`、`logging.rs` 逐字节未变。

这说明无需扩大原 corpus/预算；**不说明旧 whole-crate source maps 已绑定新产品**。
`rust_lib_probe.validate`、layout 和 guards 收据包含两组件所有文件；最新 main/网络文件
变化会使旧 map 不等。companion 更直接采样新主循环，所以必须重新生成、构建、bind、
运行六个方法 controls。后面的 10 批、交错、S8 与资源门必须用这个新 companion。

| 门 | 最新源上的实际动作 | 不能代替的动作 |
| --- | --- | --- |
| core/policy/EDNS/lease | fresh primitive prepare → locked build → 原四个 driver | 只改旧 source receipt；只跑库单测 |
| answer/transfer | 在新 positive copied lib 上原 driver，保留 metrics 与完整 36-case transfer | 复用 ae1 Rust transcript |
| reverse | 新精确 adapter build/run 原21case；另新 sidecar build/run/collect | 排序、任意 permutation、把 relation pass 当 strict 全通过 |
| layout | fresh prepare/build、实际 ignored test、collect | 用旧 66,560 B/3 alloc 数字充新结果 |
| 视图隔离 | 六个 fresh variants build/run：positive + 五负控 | 编译失败、0 test、只看名称列表算负控通过 |
| companion 方法 | fresh prepare/build release+probe-tests、bind 新产品、实际六 controls/layout | `prepared` / `built-not-validated` 当内部余额通过 |

C 的源码、ELF、corpus与这些共同修复无关。可复用下列原始 C 输入，**由当前 driver
逐文件/ELF/compiler/source receipt 验证，任何缺失或变更都拒绝**；不是复用旧 Rust
结果，也不是复用正式 CPU 窗口。CPU45 仍执行新的 C/R3/A 五轮。

## 已成功的原驱动位置

本地 E=`private/dnsmasq-rewrite/evidence/M6B`：

- `pair-reverse-fixed-02/build-a-primitive-gates-01.sh`：统一锁内构建四例、layout、六 variants、companion。
- `a-ae1-primitives-prep-01/run.sh`：四例完整 argv。
- `pair-reverse-fixed-02/run-ae1-positive-lib.sh`：answer（含 metrics）、transfer、positive。
- `a-ae1-guards-prep-01/run-negative.sh`：五 mutation 负控。
- `a-ae1-layout-prep-01/run.sh`：`--run-probe`、`--collect-probe` 两实际阶段。
- `a-ae1-resource-prep-01/bind-controls.sh`：新 product/diag bind、六方法 controls。
- `a-ae1-order-sidecar-prep-03/build-run.sh`：relation driver；首次非 root collector 权限失败保留，后续 root collector 通过。

这些脚本绑定旧 ae1，不能直接运行后称 latest。以下明确使用 fresh 名字。

## 已有本地 prepare 与两项剩余准备

root 已实际生成以下四份 fresh prepare；**不要重跑或覆盖它们**。它们尚未 build/run，
所以不授通过资格。本地只读逐项核过：四份receipt的163个dnsmasq/ubus输入均与
Git69bc完全相同；未因此运行任何门。传输时保持每份完整目录（receipt、archive、patch、source 全保留）。

| 本地 E/M6B | 本recipe Oracle 目录（`pair-udp-acl-01/a/private/` 下） |
| --- | --- |
| `a-69bc-primitives-prep-01` | `primitive-prep-01` |
| `a-69bc-layout-prep-01` | `layout-prep-01` |
| `a-69bc-guards-prep-01` | `guards-prep-01` |
| `a-69bc-resource-prep-01` | `resource-prep-01` |
| `a-69bc-reverse-prep-01`（下面准备，未执行） | `reverse-prep-01` |
| `a-69bc-order-sidecar-prep-01`（下面准备，未执行） | `order-sidecar-prep-01` |

下面只提供尚需 root 准备的 reverse 与 sidecar 入口，未实际执行。若 root 已生成二者，
直接用已有 fresh 目录，不能重复prepare。工具必须同root四份prepare使用的当前快照，
不得退回旧 A tools。初始化本地变量：

```sh
M6B_REPO=/Users/USER/Developer/owrt-control-plane-rs
M6B_A_COMMIT=69bccf2738f2c07cbc6d8b8a950015d4cea10af3
M6B_A_SHA=21937fa33b2552801278ea6cb15f0e13cb733824e4cd236382f968a1c1c4324b
M6B_E="$M6B_REPO/private/dnsmasq-rewrite/evidence/M6B"
M6B_T="$M6B_REPO/tools/dnsmasq"
M6B_EXACT_C_SOURCE="$M6B_REPO/private/dnsmasq-rewrite/reference/dnsmasq-2.93/src"
```

sidecar prepare 需要精确 C `cache.c` 的**本地既有副本**。root 选择先前已校验副本的实际
绝对目录；不能下载另一 revision 或拿产品 C 当参考源。

```sh
python3 "$M6B_T/m6b_reverse_order_sidecar.py" prepare --repository "$M6B_REPO" \
  --source-commit "$M6B_A_COMMIT" --reference-source "$M6B_EXACT_C_SOURCE" \
  --out "$M6B_E/a-69bc-order-sidecar-prep-01"
```

原 strict reverse 没有独立 prepare CLI。依已成功 ae1 准备方式，仅向 fresh Git export
添加精确 cfg(test) adapter；下面保存原 archive SHA、产品两组件 map 与生成 map，不改产品。

```sh
python3 - "$M6B_REPO" "$M6B_A_COMMIT" "$M6B_T" "$M6B_E/a-69bc-reverse-prep-01" <<'PY'
import hashlib, json, subprocess, sys, tarfile
from pathlib import Path
repo, commit, tools, out = sys.argv[1], sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
assert not out.exists(); out.mkdir()
archive = out / 'product-source.tar'
with archive.open('xb') as stream:
    subprocess.run(['git', 'archive', '--format=tar', commit], cwd=repo, stdout=stream, check=True)
source = out / 'source'; source.mkdir()
with tarfile.open(archive) as stream:
    assert stream.pax_headers['comment'] == commit
    stream.extractall(source, filter='data')
sys.path.insert(0, str(tools))
from rust_lib_probe import source_files, digest
before = source_files(source)
cache = source / 'components/dnsmasq/src/dns/cache.rs'
old = cache.read_bytes(); assert b'mod reverse_transfer_gate' not in old
adapter = source / 'components/dnsmasq/src/dns/cache_reverse_transfer_gate.rs'
assert not adapter.exists(); adapter.write_bytes((tools / 'cache_reverse_transfer_probe.rs').read_bytes())
cache.write_bytes(old + b'\n#[cfg(test)]\n#[path = "cache_reverse_transfer_gate.rs"]\nmod reverse_transfer_gate;\n')
receipt = {'source_commit': commit, 'base_archive_sha256': digest(archive),
           'base_compilation_files': before, 'generated_source_inputs': source_files(source),
           'diagnostic_only': True, 'product_edits': False,
           'adapter_sha256': digest(adapter), 'status': 'prepared-not-built-not-run'}
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
PY
```

将已有四份及新reverse/sidecar完整 prep 用 Python `tarfile.GNU_FORMAT` 归档，完整上传后先 SHA 核验再解包。
不要带 Finder `._`，不在 scp 未完成时解包，不覆盖旧 ae1/raw。
工具用 root 新冻结的完整 `tools/dnsmasq`（含 imported helpers/templates），另记录工具
commit/逐文件SHA。建议 Oracle `pair-udp-acl-01/gate-tools-current` 与
`pair-udp-acl-01/a/private/` 下按表布局；原产品 source/ELF 仍留原处。

## Oracle 共用变量与源绑定检查

以下队列由 root 上传脚本后 `ssh -n oracle sh FILE` 串行执行。每命令stdin为空。
不同时跑服务/资源窗口或其它 build/test/fuzz。shared target唯一
`/home/ubuntu/dnsmasq-cargo-target`；各构建经原 `oracle_build.sh` 锁。

```sh
set -eu
M6B_PAIR=/home/ubuntu/dnsmasq-m6b-20261007/pair-udp-acl-01
M6B_TF="$M6B_PAIR/gate-tools-current"
M6B_T="$M6B_TF/tools/dnsmasq"
M6B_P="$M6B_PAIR/a/private"
M6B_B="$M6B_P"
M6B_O="$M6B_TF/private/a69bc-gates-01"
M6B_PRODUCT="$M6B_PAIR/a/private/opt3"
M6B_OLD=/home/ubuntu/dnsmasq-m6b-20261007/a-fresh-d8ddb22b
M6B_CBASE="$M6B_OLD/tools-freeze/private/fresh-lib-primitives-02"
M6B_REF=/home/ubuntu/dnsmasq-rewrite-20260929
M6B_STRICT_C="$M6B_OLD/gate-tools-6943/private/reverse-01/c"
M6B_SIDECAR_C=/home/ubuntu/dnsmasq-m6b-20261007/pair-reverse-fixed-02/a/private/order-sidecar-c-03
```

执行前比较 fresh prep 的原 map 与产品 `build.json.source`，将结果保存为 fresh join。
这补上部分 primitive driver只验证probe自洽、没有读取产品ELF的边界。

```sh
python3 - "$M6B_T" "$M6B_P" "$M6B_PRODUCT" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from rust_lib_probe import source_files, digest
from m6b_primitive_assets import source_files as primitive_files
from m6b_resource_companion import compilation_files
p, product = Path(sys.argv[2]), Path(sys.argv[3])
build = json.loads((product / 'build.json').read_text())
source = Path(build['source']); components = source_files(source)
commit = '69bccf2738f2c07cbc6d8b8a950015d4cea10af3'
elf = product / 'dnsmasq-rs'
assert digest(elf) == '21937fa33b2552801278ea6cb15f0e13cb733824e4cd236382f968a1c1c4324b'
assert build['kind'] == 'release' and build['opt_level'] == '3' and build['features'] == ''
assert any(r['path'] == elf.name and r['sha256'] == digest(elf) and r['bytes'] == elf.stat().st_size for r in build['artifacts'])
map_record = build['link_map']; assert digest(product / map_record['path']) == map_record['sha256']
for path, key, actual in [
    ('primitive-prep-01/source-receipt.json', 'base_compile_inputs', primitive_files(source)),
    ('layout-prep-01/probe-receipt.json', 'product_source_inputs', components),
    ('guards-prep-01/result.json', 'source_inputs', components),
    ('reverse-prep-01/receipt.json', 'base_compilation_files', components),
    ('order-sidecar-prep-01/source-receipt.json', 'product_source_inputs', components),
    ('resource-prep-01/receipt.json', 'original_compilation_files', compilation_files(source)),
]:
    row = json.loads((p / path).read_text())
    assert row['source_commit'] == commit and row[key] == actual, path
join = {'source_commit': commit, 'product_elf_sha256': digest(elf),
        'product_build_sha256': digest(product / 'build.json'), 'component_maps_match': True,
        'qualification': False, 'status': 'source-join-only-not-built-not-run'}
with (p / 'source-join.json').open('x') as stream:
    json.dump(join, stream, indent=2); stream.write('\n')
PY
```

## 串行 build 队列

```sh
mkdir -p "$M6B_TF/private"
mkdir "$M6B_O"
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' sh "$M6B_T/oracle_build.sh" \
  "$M6B_P/primitive-prep-01/source" "$M6B_B/primitive-build-01" primitive-probes </dev/null
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' sh "$M6B_T/oracle_build.sh" \
  "$M6B_P/layout-prep-01/source" "$M6B_B/layout-build-01" probe-tests </dev/null
for M6B_V in positive discard-content-on-detach discard-index-on-detach disable-rrset-rotation preserve-expired-reverse reuse-slot-generation; do
  ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' sh "$M6B_T/oracle_build.sh" \
    "$M6B_P/guards-prep-01/$M6B_V/source" "$M6B_B/guards-build-01/$M6B_V" probe-tests </dev/null
done
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' sh "$M6B_T/oracle_build.sh" \
  "$M6B_P/reverse-prep-01/source" "$M6B_B/reverse-build-01" probe-tests </dev/null
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' sh "$M6B_T/oracle_build.sh" \
  "$M6B_P/order-sidecar-prep-01/source" "$M6B_B/order-sidecar-build-01" probe-tests </dev/null
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' ORACLE_BUILD_LINK_MAP=1 \
  sh "$M6B_T/oracle_build.sh" "$M6B_P/resource-prep-01/source" "$M6B_B/resource-diag-build-01" release </dev/null
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' ORACLE_BUILD_LINK_MAP=1 \
  sh "$M6B_T/oracle_build.sh" "$M6B_P/resource-prep-01/source" "$M6B_B/resource-control-build-01" probe-tests </dev/null
```

## 原语与隔离实际 run 队列

以下输出必须fresh。每条保留stdout/stderr/完整receipt，不只保留counts。
例示函数每次先建唯一TMPDIR，免网络namespace PID1退出后遗留同名FIFO。

```sh
m6b_isolated() {
  M6B_TMP=$(mktemp -d "$M6B_P/tmp-gate.XXXXXX")
  sudo -n sh "$M6B_T/run_isolated.sh" env TMPDIR="$M6B_TMP" "$@" </dev/null
}
python3 "$M6B_T/dns_cache_diff.py" --reference-source "$M6B_REF/reference/dnsmasq-2.93/src" \
  --rust-binary "$M6B_B/primitive-build-01/m6b-cache-core" --rust-source-root "$M6B_P/primitive-prep-01/source" \
  --rust-source-receipt "$M6B_P/primitive-prep-01/source-receipt.json" --rust-build-receipt "$M6B_B/primitive-build-01/build.json" \
  --output "$M6B_O/core" >"$M6B_O/core.log" 2>&1 </dev/null
python3 "$M6B_T/cache_policy_transaction_diff.py" --reference-build "$M6B_REF/c-native-01" \
  --rust-binary "$M6B_B/primitive-build-01/m6b-cache-policy" --rust-source-root "$M6B_P/primitive-prep-01/source" \
  --rust-source-receipt "$M6B_P/primitive-prep-01/source-receipt.json" --rust-build-receipt "$M6B_B/primitive-build-01/build.json" \
  --out "$M6B_O/policy" >"$M6B_O/policy.log" 2>&1 </dev/null
python3 "$M6B_T/cache_edns_diff.py" --reference-build "$M6B_REF/c-native-01" \
  --rust-binary "$M6B_B/primitive-build-01/m6b-cache-edns" --rust-source-root "$M6B_P/primitive-prep-01/source" \
  --rust-source-receipt "$M6B_P/primitive-prep-01/source-receipt.json" --rust-build-receipt "$M6B_B/primitive-build-01/build.json" \
  --out "$M6B_O/edns" >"$M6B_O/edns.log" 2>&1 </dev/null
python3 "$M6B_T/lease_cache_diff.py" --reference-build "$M6B_REF/c-native-01" \
  --rust-binary "$M6B_B/primitive-build-01/m6b-cache-lease" --rust-source-root "$M6B_P/primitive-prep-01/source" \
  --rust-source-receipt "$M6B_P/primitive-prep-01/source-receipt.json" --rust-build-receipt "$M6B_B/primitive-build-01/build.json" \
  --output "$M6B_O/lease" >"$M6B_O/lease.log" 2>&1 </dev/null
python3 "$M6B_T/cache_answer_diff.py" --with-metrics --output "$M6B_O/answer" \
  --oracle-command "$M6B_CBASE/answer/local-answer-oracle -C $M6B_CBASE/answer/cache.conf" \
  --oracle-identity "$M6B_CBASE/answer/identity.json" \
  --rust-test-binary "$M6B_B/guards-build-01/positive/lib-dnsmasq_rs" \
  --rust-source-root "$M6B_P/guards-prep-01/positive/source" \
  --rust-build-receipt "$M6B_B/guards-build-01/positive/build.json" >"$M6B_O/answer.log" 2>&1 </dev/null
python3 "$M6B_T/cache_transfer_rust_diff.py" --baseline "$M6B_CBASE/transfer-c" \
  --fresh-c-receipt "$M6B_CBASE/transfer-c/fresh-c-receipt.json" --out "$M6B_O/transfer" \
  --rust-test-binary "$M6B_B/guards-build-01/positive/lib-dnsmasq_rs" \
  --rust-source-root "$M6B_P/guards-prep-01/positive/source" \
  --rust-build-receipt "$M6B_B/guards-build-01/positive/build.json" >"$M6B_O/transfer.log" 2>&1 </dev/null
for M6B_V in positive discard-content-on-detach discard-index-on-detach disable-rrset-rotation preserve-expired-reverse reuse-slot-generation; do
  m6b_isolated python3 "$M6B_T/m6b_tcp_a_guards.py" --run-variant "$M6B_V" \
    --plan "$M6B_P/guards-prep-01/$M6B_V/variant-plan.json" \
    --rust-test-binary "$M6B_B/guards-build-01/$M6B_V/lib-dnsmasq_rs" \
    --rust-source-root "$M6B_P/guards-prep-01/$M6B_V/source" \
    --rust-build-receipt "$M6B_B/guards-build-01/$M6B_V/build.json" \
    --out "$M6B_O/guards-$M6B_V" >"$M6B_O/guards-$M6B_V.log" 2>&1
done
```

原strict reverse输出有已知layout-sensitive case，所以单独执行并保存其真实rc，不能
在`set -e`下把已知ordering差异误作基础20case失败，也不能把非零吞掉说全通过。

```sh
if m6b_isolated python3 "$M6B_T/cache_reverse_transfer_rust.py" \
  --baseline "$M6B_STRICT_C" --fresh-c-receipt "$M6B_STRICT_C/fresh-c-receipt.json" \
  --source-commit 69bccf2738f2c07cbc6d8b8a950015d4cea10af3 \
  --rust-test-binary "$M6B_B/reverse-build-01/lib-dnsmasq_rs" --rust-source-root "$M6B_P/reverse-prep-01/source" \
  --rust-build-receipt "$M6B_B/reverse-build-01/build.json" --out "$M6B_O/reverse-strict" \
  >"$M6B_O/reverse-strict.log" 2>&1; then
  M6B_REVERSE_RC=0
else
  M6B_REVERSE_RC=$?
fi
printf '%s\n' "$M6B_REVERSE_RC" > "$M6B_O/reverse-strict.exit"
```

root核原20稳定case `compared=184, matched=184, differing_states=0, failures=[]`，再保留
12-row完整strict差异。若新增稳定差异或其它失败，停该门修复，不能继续编资格。
relation sidecar只解释实际bucket/mix/chain/LRU，不覆写此strict结果。

```sh
m6b_isolated python3 "$M6B_T/m6b_reverse_order_sidecar.py" run-rust \
  --source-receipt "$M6B_P/order-sidecar-prep-01/source-receipt.json" --rust-source-root "$M6B_P/order-sidecar-prep-01/source" \
  --rust-test-binary "$M6B_B/order-sidecar-build-01/lib-dnsmasq_rs" --rust-build-receipt "$M6B_B/order-sidecar-build-01/build.json" \
  --c-baseline "$M6B_SIDECAR_C" --fresh-c-receipt "$M6B_SIDECAR_C/fresh-c-receipt.json" \
  --out "$M6B_O/reverse-sidecar" >"$M6B_O/reverse-sidecar.log" 2>&1
sudo -n python3 "$M6B_T/m6b_reverse_order_sidecar.py" collect \
  --source-receipt "$M6B_P/order-sidecar-prep-01/source-receipt.json" --rust-source-root "$M6B_P/order-sidecar-prep-01/source" \
  --rust-test-binary "$M6B_B/order-sidecar-build-01/lib-dnsmasq_rs" --rust-build-receipt "$M6B_B/order-sidecar-build-01/build.json" \
  --c-baseline "$M6B_SIDECAR_C" --fresh-c-receipt "$M6B_SIDECAR_C/fresh-c-receipt.json" \
  --rust-run "$M6B_O/reverse-sidecar" --out "$M6B_O/reverse-sidecar-result.json" \
  >"$M6B_O/reverse-sidecar-collect.log" 2>&1 </dev/null
```

如果当前sidecar C验证因旧raw已prune/实际源路径不存在/模板变化而拒绝，原拒绝保留；
按 `a-ae1-order-sidecar-prep-03/build-run.sh` 的原126C进程在fresh目录重建重跑，再用新
C receipt。**strict C与sidecar C的 `tool_sha256` 不同，二者不得互换。**

## layout、companion与后续交接

```sh
m6b_isolated python3 "$M6B_T/m6b_tcp_a_layout.py" --run-probe \
  --receipt "$M6B_P/layout-prep-01/probe-receipt.json" --probe-source-root "$M6B_P/layout-prep-01/source" \
  --build-json "$M6B_B/layout-build-01/build.json" --test-elf "$M6B_B/layout-build-01/lib-dnsmasq_rs" \
  --test-log "$M6B_B/layout-build-01/probe.stdout" --test-stderr "$M6B_B/layout-build-01/probe.stderr" \
  --run-receipt "$M6B_B/layout-build-01/run-receipt.json" >"$M6B_O/layout-run.log" 2>&1
python3 "$M6B_T/m6b_tcp_a_layout.py" --collect-probe \
  --receipt "$M6B_P/layout-prep-01/probe-receipt.json" --probe-source-root "$M6B_P/layout-prep-01/source" \
  --build-json "$M6B_B/layout-build-01/build.json" --test-elf "$M6B_B/layout-build-01/lib-dnsmasq_rs" \
  --test-log "$M6B_B/layout-build-01/probe.stdout" --test-stderr "$M6B_B/layout-build-01/probe.stderr" \
  --run-receipt "$M6B_B/layout-build-01/run-receipt.json" --report "$M6B_B/layout-build-01/layout-report.json" \
  >"$M6B_O/layout-collect.log" 2>&1 </dev/null
python3 "$M6B_T/m6b_resource_companion.py" bind \
  --receipt "$M6B_P/resource-prep-01/receipt.json" --diagnostic-source-root "$M6B_P/resource-prep-01/source" \
  --build-json "$M6B_B/resource-diag-build-01/build.json" --diagnostic-elf "$M6B_B/resource-diag-build-01/dnsmasq-rs" \
  --product-build-json "$M6B_PRODUCT/build.json" --product-elf "$M6B_PRODUCT/dnsmasq-rs" \
  --out "$M6B_P/resource-prep-01/bound-receipt.json" >"$M6B_O/companion-bind.log" 2>&1 </dev/null
m6b_isolated python3 "$M6B_T/m6b_tcp_internal.py" controls \
  --bound-receipt "$M6B_P/resource-prep-01/bound-receipt.json" \
  --build-json "$M6B_B/resource-control-build-01/build.json" \
  --layout-report "$M6B_B/layout-build-01/layout-report.json" --out "$M6B_O/companion-controls" \
  >"$M6B_O/companion-controls.log" 2>&1
```

root每阶段核完整库存、实际退出/负控、SHA/source/maps，archive本地SHA+metadata后才prune。
把新summary绑定 `69bccf27` 和 `21937fa3…`，并列历史ae1数字、strict差异和失败；不改旧证据。

成功后的参数交接：`M6B_DIAG_BUILD=$M6B_B/resource-diag-build-01`、
`M6B_BOUND=$M6B_P/resource-prep-01/bound-receipt.json`、
`M6B_CONTROLS=$M6B_O/companion-controls/controls.json`，继续
[M6B_TCP_A_INTERNAL_RUNPLAN](M6B_TCP_A_INTERNAL_RUNPLAN.md)、
[M6B_TCP_INTERLEAVED_GATE](M6B_TCP_INTERLEAVED_GATE.md) 和
[M6B_TCP_A_SERVICE_RESOURCE_GATE](M6B_TCP_A_SERVICE_RESOURCE_GATE.md) 的所有实际门。
本recipe既不授service/resource/pressure资格，也不填CPU45的15项前置为真。
最新无A同源s和fresh common按[CPU freeze](M6B_TCP_A_FIXED_BASELINE_FREEZE.md)更换身份执行；
不再增加新27窗口，最终含A才一次完整135。所有测量仅构建机；物理路由器未碰。
