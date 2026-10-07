# M6b A 原语执行入口（准备，未授资格）

2026-10-08。tool-only 基点 `45895827c1b4411ce73c5cfd05b1a8a484ea9856`。本轮没有生成 probe 源、编译、执行测试或访问 Oracle；正式 27 窗口结束后才能执行本文件入口。方案 A 产品未合入 main。不得引用旧 A / M6a 证据为本候选授资格。

## 构建边界

`oracle_build.sh SOURCE FRESH_PRIVATE_OUTPUT primitive-probes` 只构建四个静态 example：

- `m6b-cache-core`：原 `dns_cache_diff.py` 的 21 场景、22,571 命令集合；公开 Cache API，实际 `dnsmasq_rs` crate。
- `m6b-cache-policy`：策略／事务实际 crate bridge。
- `m6b-cache-edns`：EDNS 实际 crate bridge。
- `m6b-cache-lease`：租约／cache publication bridge。

四个 example 必须全部存在。构建限定 release、opt3、feature-off、`aarch64-unknown-linux-musl`；统一 `/home/ubuntu/dnsmasq-cargo-target`。Cargo package clean、构建、复制与源码 before/after 核对均在同一锁内。不得构建 main 产品来替代 bridge，不用绝对 `#[path]` include 或 shim 重造 Cache。生成源必须是 ignored 的原组件副本，基点、生成 compile-input 集合、工具与窄补正身份都记录在准备收据。

`build.json` 的 `kind=primitive-probes`、`source_files`、`source_before_sha256`、四个 `{path,bytes,sha256}` copied ELF 和 release 参数必须与准备收据一致。旧 driver 使用明确 `--rust-binary`、`--rust-source-root`、`--rust-source-receipt`、`--rust-build-receipt`，只编译 C harness；不会另建 Rust target 或隐式编译产品。`--local-native` 是显式本机旧适配器，拒绝 `/home/ubuntu/` Oracle 路径，不具有 Oracle 资格。

## 精确 C 身份与原语 scope

core C reference 固定为 patched 2.93：`cache.c` SHA `51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`，`dnsmasq.h` SHA `318942419598f037a97611efbdea5aebba1e384b9a1ba5f7eded091c86e0e228`。其实际函数提取、宏／variant、编译 argv、compiler version、compiler ABI macros、harness／ELF SHA 全部另存。C harness 使用 ASan/UBSan。每场景的输入、C/Rust stdout/stderr 和全部 mismatch 都保留；不挑最快或仅通过样本。

这是 native 的**源码／编译 ABI／变体原语对照**，不是运行镜像 C daemon。native `bba5…` 和镜像 `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87` 不得互相替代。generic RR 仅规范跨类型组顺序；单类型 RRset 次序、数据、expiry、negative、reply TTL、stale 精确比较。服务 S1–S8 仍用镜像 C + 同一个 A 产品 ELF。

## 最小可执行路径（正式窗口结束后）

下面变量全部由 root 绑定到冻结输入／fresh private 路径；源码和准备收据可从本机搬至 Oracle，但内容哈希必须相同。`M6B_TOOLS` 是新冻结工具目录，不能从旧 A 树取旧工具覆盖主线 r3。每次输出路径都 fresh。

```sh
python3 "$M6B_TOOLS/m6b_primitive_assets.py" \
  --repository "$M6B_MAIN" --source-commit "$M6B_A_COMMIT" --out "$M6B_A_PRIMITIVE_PREP"
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' \
  sh "$M6B_TOOLS/oracle_build.sh" "$M6B_A_PRIMITIVE_SOURCE" "$M6B_A_PRIMITIVE_BUILD" primitive-probes
python3 "$M6B_TOOLS/dns_cache_diff.py" \
  --rust-binary "$M6B_A_PRIMITIVE_BUILD/m6b-cache-core" \
  --rust-source-root "$M6B_A_PRIMITIVE_SOURCE" \
  --rust-source-receipt "$M6B_A_PRIMITIVE_PREP/source-receipt.json" \
  --rust-build-receipt "$M6B_A_PRIMITIVE_BUILD/build.json" \
  --reference-source "$M6B_C_REFERENCE_SRC" --output "$M6B_A_CORE_OUT"
python3 "$M6B_TOOLS/cache_policy_transaction_diff.py" \
  --rust-binary "$M6B_A_PRIMITIVE_BUILD/m6b-cache-policy" \
  --rust-source-root "$M6B_A_PRIMITIVE_SOURCE" \
  --rust-source-receipt "$M6B_A_PRIMITIVE_PREP/source-receipt.json" \
  --rust-build-receipt "$M6B_A_PRIMITIVE_BUILD/build.json" \
  --reference-build "$M6B_C_PRIMITIVE_BUILD" --out "$M6B_A_POLICY_OUT"
python3 "$M6B_TOOLS/cache_edns_diff.py" \
  --rust-binary "$M6B_A_PRIMITIVE_BUILD/m6b-cache-edns" \
  --rust-source-root "$M6B_A_PRIMITIVE_SOURCE" \
  --rust-source-receipt "$M6B_A_PRIMITIVE_PREP/source-receipt.json" \
  --rust-build-receipt "$M6B_A_PRIMITIVE_BUILD/build.json" \
  --reference-build "$M6B_C_PRIMITIVE_BUILD" --out "$M6B_A_EDNS_OUT"
python3 "$M6B_TOOLS/lease_cache_diff.py" \
  --rust-binary "$M6B_A_PRIMITIVE_BUILD/m6b-cache-lease" \
  --rust-source-root "$M6B_A_PRIMITIVE_SOURCE" \
  --rust-source-receipt "$M6B_A_PRIMITIVE_PREP/source-receipt.json" \
  --rust-build-receipt "$M6B_A_PRIMITIVE_BUILD/build.json" \
  --reference-build "$M6B_C_PRIMITIVE_BUILD" --output "$M6B_A_LEASE_OUT"
```

`M6B_C_PRIMITIVE_BUILD` 是 hash/variant 固定的 matching-source C 原语构建输入，不是镜像 daemon 的资格身份。core、policy、EDNS、lease 都必须实际执行完整 corpus；必要负控的失败输出也保存，不能仅 prepare/build 后写通过。

## 固定执行顺序与尚未覆盖的门

1. frozen A 组件源码与四 bridges 收据 → `primitive-probes` 构建 → 四原语完整差分及原始失败保存。
2. A actual lib test ELF（`probe-tests`）的精确 cache-answer、transfer、retained-view 正控；五个安全 mutation 负控，每个变体使用独立冻结源／构建收据。编译失败不能当负控成功。
3. A 产品 opt3 ELF 的 canonical `m5_dns_cache`（完整族）、`m5_edns`、`dns-files`、`m5_dns_endpoints`、`m5_interface_records`、`logging-all-scopes`，补五个 accept/import/cross-completion caller、route caller。
4. 公共资源／生命周期 11 profiles，EOF 原始事件、自己的 idle FD 连续稳定、固定排空采样；`qualified=false` 不能手改通过。
5. ignored source-bound companion 的内部 view/content/index/pending/live-requested 和 10 批余额；满4096、half/full、大报文实际占用不得由配置 capacity 推断。
6. 前五层 complete、同 source/产品 ELF 绑定后才能 CPU45；最终候选另按完整135窗口和最终 M5/M2/资源/压力/APK 验收。

没有运行的门均为 open。此工具批次不覆盖最终 APK r3 / opt3 guard / source-counter 的主线新工具，不改变产品、账本或资格计数。
