# M6b copied lib-test 原语入口

日期：2026-10-08。基线 `45895827c1b4411ce73c5cfd05b1a8a484ea9856`。
本提交只修改工具和本审计，未改产品、main 或账本；**未访问 Oracle、未运行本地测试、未编译、未给任何 A 原语或服务授予资格**。Oracle 的 27 个正式窗口继续独占。

## 四个 lib-test 调用入口

四个工具共同接受 `--rust-test-binary`、`--rust-source-root`、`--rust-build-receipt`。copied 模式三者必须显式提供，不能与 `--local-native` 混用，也不会调用 cargo/rustc、添加新 target 或修改 source。新 [rust_lib_probe.py](../../../tools/dnsmasq/rust_lib_probe.py) 只做来源/ELF校验、构造 argv 和重新核验，不构建或运行。

| 工具 | 精确 ignored test | 保留的输入/范围 |
| --- | --- | --- |
| `cache_answer_diff.py` | `dns::daemon::cache_tests::exact_c_oracle_driver` | `DNSMASQ_CACHE_ORACLE_INPUT`；原 CNAME/SOA/negative/wire/metrics corpus、校准、计数负控及归一规则不变 |
| `cache_transfer_rust_diff.py` | `dns::cache::transfer_tests::exact_c_transfer_probe` | `DNSMASQ_CACHE_TRANSFER_CASE/NOW`；36 case、307 state；同一原语 corpus |
| `cache_partial_eof_rust_diff.py` | `dns::tcp_transfer::partial_eof_tests::exact_c_partial_eof_probe` | `DNSMASQ_PARTIAL_EOF_CASE`；9 case，保留 whole-frame24／stream27 state及不能表示的 native end-sentinel 分类；仍要求 isolated/lo |
| `cache_reverse_transfer_rust.py` | `dns::cache::reverse_transfer_gate::exact_c_reverse_transfer_probe` | `DNSMASQ_REVERSE_TRANSFER_CASE/NOW`；原 reverse/ordering corpus。copied 源必须已包含 exact cfg(test) adapter，工具不再临时注入或修改 cache.rs |

argv 固定为 `COPIED_ELF TEST --ignored --exact --nocapture --test-threads=1`。忽略测试不是普通 suite 的通过项；没有匹配输出会被原计数/状态守卫拒绝。serial libtest 可能把 `test TEST ... ` 放在首条 stdout 前，工具只剥离这个精确 harness 前缀后按原 oracle 前缀取行；不改 payload，不放宽比较。

## copied ELF 的来源合同

校验口径沿用 `oracle_build.sh probe-tests`：

- build `kind=probe-tests`、`opt_level=3`、`features=""`、`diagnostic_only=true`；`cargo_target_dir=/home/ubuntu/dnsmasq-cargo-target`；
- 明确 source root 与 receipt.source 一致；dnsmasq/ubus components 的全部文件 SHA 与 receipt.source_files 相等，按既有规则排除 target；组件及源文件/目录不能是 symlink；
- receipt 旁 `probe-source-before.json` 的完整 SHA 和内容与 build.source_before_sha256/source_files 相等；
- 单个 `lib-dnsmasq_rs` artifact 的 SHA/字节一致；请求的 ELF 为 private 下不可变副本，拒绝共享 Cargo 输出；
- ELF64、little-endian、ELF version1、AArch64 `e_machine=183`；
- 结果保存 build receipt SHA、source-before SHA、全部 source_files、ELF SHA/字节及 verifier SHA；各次执行前后重新核验，源/产物/收据变化立即拒绝。

这与 standalone examples 的 `primitive-probes` 构建/来源合同分开，不能互填 receipt；也不能拿产品 `dnsmasq-rs` ELF 冒充 lib-test ELF。Oracle 只通过统一构建入口，下面是**待运行命令**，本次未执行：

```sh
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' \
  sh "$TOOLS/oracle_build.sh" "$FROZEN_PROBE_SOURCE" "$FRESH_PRIVATE_BUILD" probe-tests
```

legacy cargo 分支仍保留，但必须显式 `--local-native`。源、out、工具ROOT、cwd、home、cargo路径落在 `/home/ubuntu` 时拒绝；已知 `/home/ubuntu/dnsmasq-cargo-target` 存在时也拒绝，不能把路径改成 `/tmp` 规避 Oracle 限制。reverse legacy 仍须显式 `--source` 私有源副本。copied transfer 拒绝 `--target`，它只能属于 legacy 本地构建参数。

## fresh C 与历史额外回归

transfer/partial 两个 receiver 新增显式 `--fresh-c-receipt PATH`，仍要求 `--baseline DIR`。fresh 模式依赖整合时加入的 `c_primitive_receipt.validate_fresh(base,receipt,primitive)`；没有 fresh receipt 时仍走所有历史 pins，不能自动放宽。

| 原语 | fresh C 合同 | 历史路径 |
| --- | --- | --- |
| transfer | `primitive=cache-transfer`；父线程维护的 fresh C builder 保存完整 C source/编译ABI/argv/inventory；native 与 SDK target 各3次共216个 stdout，逐case六份完全相等，36case307 observations；receipt 重新核验 | 保留 PLAN `7502e674…`、IDENTITY `96fc7eed…`、STDOUT digest `6624663c…`，仅作为历史额外回归 |
| partial EOF | `primitive=cache-partial-eof`；按既有 native-only9case各一次，实际 native ELF183及 native size 切点；原始 stdout、trace、wire、exit和各校准均绑定；没有扩大 target/repeat矩阵 | 保留 PLAN `9bbf0d1f…`、RESULT `aaf68255…`，仅作为历史额外回归 |

两者的旧 PLAN pin 在 fresh 模式继续生效，保证同一 corpus 而不是扩矩阵；fresh 只用新生成的 C identity/result/stdout SHA，不能借用历史 C 结果。新 C builders/helper 由父线程维护，本提交不重复修改 `cache_transfer_diff.py`、`cache_partial_eof_oracle.py`、`c_primitive_receipt.py`。必须先整合该依赖，再使用 fresh 入口。

所有 C 对照都标为 **exact-source primitive**。历史 native reference `bba5…`、重新链接的 native/SDK oracle 及这些 receipts 不是镜像 `/usr/sbin/dnsmasq` 的 `097a9e21…`。fresh 原语也不能代替 A 同 ELF 的 S1–S8 daemon 服务、资源/生命周期、压力和 CPU 门。

## 执行 recipe（未执行）

先在正式窗口结束后，按父线程 C builder 配方对原 corpus 新运行一次，得到 `fresh-c-receipt.json`；再通过上面的统一 `probe-tests` 构建复制 lib ELF。source可为已冻结生成的 cfg(test) probe copy，必须明确记录它与产品源的差异。普通 answer/transfer 使用现有 ignored test；reverse需要在构建前准备其精确 test adapter。

```sh
python3 "$TOOLS/cache_answer_diff.py" \
  --output "$FRESH_ANSWER_OUT" \
  --oracle-command "$FRESH_C_ANSWER_COMMAND" --oracle-identity "$FRESH_C_ANSWER_IDENTITY" \
  --rust-test-binary "$FRESH_PRIVATE_BUILD/lib-dnsmasq_rs" \
  --rust-source-root "$FROZEN_PROBE_SOURCE" --rust-build-receipt "$FRESH_PRIVATE_BUILD/build.json"

python3 "$TOOLS/cache_transfer_rust_diff.py" \
  --baseline "$FRESH_C_TRANSFER" --fresh-c-receipt "$FRESH_C_TRANSFER/fresh-c-receipt.json" \
  --out "$FRESH_TRANSFER_OUT" \
  --rust-test-binary "$FRESH_PRIVATE_BUILD/lib-dnsmasq_rs" \
  --rust-source-root "$FROZEN_PROBE_SOURCE" --rust-build-receipt "$FRESH_PRIVATE_BUILD/build.json"

sh "$TOOLS/run_isolated.sh" python3 "$TOOLS/cache_partial_eof_rust_diff.py" \
  --baseline "$FRESH_C_PARTIAL" --fresh-c-receipt "$FRESH_C_PARTIAL/fresh-c-receipt.json" \
  --out "$FRESH_PARTIAL_OUT" --stream-format \
  --rust-test-binary "$FRESH_PRIVATE_BUILD/lib-dnsmasq_rs" \
  --rust-source-root "$FROZEN_PROBE_SOURCE" --rust-build-receipt "$FRESH_PRIVATE_BUILD/build.json"
```

answer/partial 的 out 仍受工具 ROOT/private 既有限制；不为此放宽。ROOT 取整合后的主线工具树，Rust source root 取独立冻结 A/probe 源，避免误读主线无 A 代码。每次使用新的 out，失败原始数据保留。

## 明确 open 与本次核对边界

| 路径 | 本次状态与缺口 |
| --- | --- |
| policy transaction / EDNS / lease | standalone binary、生成的 private bin source及CLI配置路径，不是现有 ignored lib-test；由 sibling 的 `m6b_primitive_assets.py` 与三个 standalone adapters处理，不能接本 lib-test receipt |
| clipped | 复用 `cache_edns_diff.build` 的 standalone driver，现有 libtest name不存在；需 standalone asset recipe/相应入口整合，本次未宣称已迁移 |
| `cache_metrics_diff.py` | 外部 `cache_metrics_probe.rs` 先 cargo lib再rustc且有 `--sizes` 和stdin接口；没有同一 ignored libtest入口。本提交未迁移，该 legacy Oracle 构建路径仍 open，不能运行它冒称统一probe-tests |
| `cache_name_presence_diff.py` | 动态替换 standalone metrics source，使用CLIcapacity/stale/stdin；没有同一 ignored libtest入口。同样 open，本提交未迁移或放宽接口 |
| reverse fresh C | copied libtest入口可用，原reverse C pins保留为额外回归；本次新增 fresh receipt仅覆盖父线程明确指定的transfer/partial，reverse新C执行资格仍 open |
| build / negatives / execution | 本次按授权只静态阅读与 `git diff --check`；没有 Python测试、语法编译、cargo/rustc/cc或Oracle执行。所有 runtime/负控须在正式窗口结束后实际跑，未跑不能算通过 |

仅依据源码核对了选项互斥、四个 exact test/env、copied 路径绕过 cargo、native Oracle 拒绝、ELF/source-before/源 symlink 和 fresh/historical 分支。没有用这些静态结果关闭任何原语、169项或性能资格。
