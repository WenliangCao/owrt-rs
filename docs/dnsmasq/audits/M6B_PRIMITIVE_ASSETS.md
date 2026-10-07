# M6b frozen Rust primitive assets（工具准备）

2026-10-08。独立tool-only分支 `m6b/a-primitive-adapters`，基点 `45895827`。只改公共helper、policy/EDNS/lease旧driver入口和lease probe穷尽枚举；没有产品/main.rs编辑，没有运行prepare、编译、测试或Oracle。当前资格为not run。

| 静态Cargo example／复制artifact | Rust来源与命令ABI | caller |
| --- | --- | --- |
| `m6b-cache-core` | parent `dns_cache_diff.primitive_rust_source()`；actual crate import，无local shim/绝对module path | parent维护core21 bridge |
| `m6b-cache-policy` | 原RUST_DRIVER，仅在ignored copy改pub入口名、补UncheckedReply.upstream_name；RESET/P/Q frozen clock、wire与真实cache counters | `cache_policy_transaction_diff.py`，显式选择policy而非builder默认edns |
| `m6b-cache-edns` | 原RUST_DRIVER，ignored daemon模块独立入口，补当前CacheContext.filter_rr；RESET/P/Q、maximum、OPT/stale/EDE | `cache_edns_diff.py` |
| `m6b-cache-lease` | `lease_cache_probe.rs`实际公开Cache/Publication API；capacity/no-round参数，B/I/L/C/H/D/Q | `lease_cache_diff.py`；新增Reverse枚举仅补编译穷尽，forward-only corpus无reverse期待 |

policy/EDNS原driver需要daemon私有API，不能伪造外部Shim或拿产品ELF冒充probe。prepare从完整commit Git archive生成fresh ignored copy，只追加两个不同pub entrypoint与四个examples；main.rs保持原字节，产品树不改。基础／生成编译输入、完整archive、driver/tool SHA、example SHA/ABI以及三项窄API补正进入source-receipt。

所有Rust构建仅由parent的 `oracle_build.sh SOURCE FRESH_OUTPUT primitive-probes` 完成：唯一共享target、opt3、feature-off，四静态examples全部在锁内build/copy。公共helper的source_files口径与该builder相同：dnsmasq/ubus全部regular component文件（排relative target），以及存在的root Cargo/lock/rust-toolchain/.cargo文件；symlink拒绝。新的NameIndex helper也是component冻结输入。

`validate_binary(binary, source_root, source_receipt, build_receipt, probe_name)`不生成、不编译：核完整source receipt/四example ABI、实际source SHA==generated inputs==build.source_files、sibling probe-source-before.json SHA/map、shared-target build kind/settings、四artifacts exact集合及每个SHA/bytes；所选ELF须64-bit little-endian AArch64。返回binary_sha256、source commit及source/build/example/ABI链供summary记录。原prepare路径可不同于迁移后的Oracle source root，逐文件SHA仍必须相同。

三个旧standalone drivers现在必须提供四个copied inputs；Rust资产先validate，再复制到fresh out/rust、复核SHA，每次执行前后查复制ELF，整个run结束重新核冻结绑定。它们不再执行cargo/rustc，不创建target，不复制ROOT组件，不默认编main/无A。旧 `--cargo` 仅为CLI兼容保留，copied路径不调用它；`--c-only`仍可取得匹配源码C primitive参考，但不能写Rust通过。helper为parent core保留显式desktop local-native守卫，已知Oracle目录／共享target环境不得用/tmp绕过；三standalone不提供该自编回退。

匹配C仍从验证过的exact-source/native object/header recipe生成小primitive。它们不是SHA097镜像daemon。`cache_policy_service_diff.py`本来就接受产品--rust且不编译Rust，此次不改、不把四examples塞给服务；真服务继续canonical镜像rootfs driver。answer/transfer/partial/reverse copied ignored-libtest由另一个独立adapter负责。

窗口结束后的计划CLI（本次均未执行）：

```sh
python3 "$TOOLS/m6b_primitive_assets.py" --repository "$LOCAL_GIT_REPO" \
  --source-commit "$FINAL_A_COMMIT" --out "$LOCAL_GIT_REPO/private/m6b-primitive-source-01"
```

将完整generated source与source-receipt转入fresh Oracle目录；parent core getter45b85ee3及primitive-probes builder必须先整合。共享锁内构建四artifact后，各caller传以下四参数，另照原CLI提供匹配C reference build与fresh private out：

```sh
--rust-binary "$PROBE_BUILD/m6b-cache-policy" \
--rust-source-root "$GENERATED_SOURCE" \
--rust-source-receipt "$PREP/source-receipt.json" \
--rust-build-receipt "$PROBE_BUILD/build.json"
```

policy使用上述name；EDNS改m6b-cache-edns，lease改m6b-cache-lease。source preparation、source-before witness、build/ELF/source SHA、C source/harness/objects、完整stdout/stderr与失败均留档，不挑后来的成功覆盖旧失败。必须实际完成core21、原语及现有view/isolation门，不能把工具提交当资格。

计划负控：错source commit/source SHA、漏filter/upstream-name适配、错example ABI、缺/多artifact、before witness改变、错ELF machine/endianness、binary复制后改变、source/工具执行中改变都须拒绝。凡copied参数完整的路径，故意把cargo/rustc替换为不可执行文件也不得触发它们；无Rust资产不能偷偷编ROOT。当前仅静态读码准备，未运行这些controls。
