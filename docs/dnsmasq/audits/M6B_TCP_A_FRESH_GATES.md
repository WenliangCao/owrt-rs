# Scheme A：70097 无 A 基线上的 fresh 执行入口

2026-10-07。本文件是执行准备，不是通过收据。本地仅读码/准备patch/报告，Oracle正式27baseline独占。当前A产品状态 `5f3d42b48de395fc64b511687144ffa50e989913`，基点已冻结无A `70097c66`；A未main、未有fresh原语/服务/资源/压力/CPU资格。旧 `3a64b45d` 的21/22,571与65KiB均保留历史、不复用。

2026-10-08补注：5f/b73是已保全的Vec-index原型，后续按原设计§4强耦合补齐One inline/Many Arc<Vec>与高位shard，见[Index helper取舍](M6B_TCP_A_INDEX_HELPER.md)。下面SHA表准确绑定5f组件与旧layout脚本，是重建入口历史；执行前必须重新冻结完成helper/companion的最终A source/tool SHA，不用该表冒充新source资格，先跑全部fresh门。

## 产品边界与身份

从70097独立重放A存储bffb1127、view/COW测试f5d12d17/3c12c538、compact c5d9a3a9，以及S8 2ef80a05/02934ed1。5f3d42b4将新route/MAC/HUP/8-step/64-step tests的DNS字段改入`dns_work`；外层poll_slot/ready_events/log_context不移动。重放S8时拒绝旧accept-MAC下游POLLIN回退，normal/probe继续等MAC deadline/neighbor，正常buffer/log完成沿用新runnable guard。两次initial check失败为旧test字段（host cache_debug、Linux HUP service），不是产品功能失败；只做机械字段迁移，最终fresh check尚未执行。旧A tip def78581和证据保全于`archive/m6b/tcp-a-4816-def78581`。

| 输入 | 当前SHA256（准备身份，执行时重新冻结） |
| --- | --- |
| cache.rs | `a56c3e1d0469b6cbf2d33ef0906327d9f47fb5e5b35e0d799489a2fe9c5c7708` |
| cache_tests.rs | `ca3b3f50794e275aae61d923fbc6f76971e5cdb18d38925f9511d5da9c4ead2d` |
| main.rs | `c54d5d88e056c117d9c0bbbe025fae44b48bf2f1ea001eceaa7000c5ee534b26` |
| main_route_resend_tests.rs | `0d2ae1f0392bae65118cc1e93b4e67e6144b25a0eedb1343ec65145906252797` |
| dns_cache_diff.py | `fba37db2b9d5ea0c372e8e451205cfbac875a835117ddb452cbed5d22ba6d353` |
| m6b_tcp_a_guards.py | `3c65c46ec9bda20155b0b460e8a7695d87fc18bfa527291ac4ac3e179bb4570b` |
| m6b_tcp_a_layout.py | `da09d9d96ebfe1cc58552926a49bba8f650186c991cb26f78cf5055a51d88cf3` |
| m6b_tcp_accept_snapshot.py | `5221372a332ebdc08d1bb92d83619bf4a89800fc7ec8098e034c0bdeff24eeeb` |
| m6b_tcp_pressure.py | `761c27b3ba323350951e07d613aa491ae6f68becd0c2e0d1807e73c03ecf1718` |
| m6b_tcp_cpu_gate.py | `6fd0f2f8f75c0320e8c31018dc442df3c2ca5cd2d72a51168f7d6a76ead91049` |
| m6b_tcp_cpu_run.py | `c68092561031f767b973d945136309f6075b6afadae793b290f96fbf2019b0f8` |
| oracle_build.sh | `da324a0b37e8b3ad2f96cf80ef37410709b8cd76d1626011630e838d52948a75` |

无A opt3 SHA `34b3b80a39ea619f616f9d003372640d6dc0af35d5941788ae15aa64c07a3050`、1,949,736B；C `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`。A ELF/SHA/体积**未知**，不能借旧A ELF。当前A tree的m5_final_validation SHA `efae760c…`是70097历史工具；最终source-bound控制器须由root采用包含最新opt3硬门0594a930与最终recipe的冻结tools tree，不倒退到旧版本。共同模式/registry/资产/工具及callerSHA都重新冻结。

## 固定顺序

1. **fresh product primitive / isolation。** 精确C extracted原语与copied实际crate bridges按[统一原语入口](M6B_TCP_A_PRIMITIVE_ENTRIES.md)执行；actual lib-test的retained-view/transfer/reverse/lease/COW正控与5安全负控分别冻结source/build receipt。Linux default/diagnostics `--tests` check。诊断layout重新测量32KiB links＋32KiB generations＋roots，不从旧布局表授资格。
2. **Oracle构建同source product opt3。** baseline结束后，prefixless git archive/PAX commit、fresh源目录，经唯一oracle_build.sh/共享target和锁，保存实际build/ELF/map/input hashes；实际Linux lib/main/ubus tests。feature-off产品而不是diagnostic ELF作为下一层被测对象。
3. **精确镜像服务合同S1–S8。** 同一个A opt3 ELF跑M5 canonical相关族、补accept-before-first-query/父counter prefix/跨连接完成顺序、route basic/已写clears与新wake tests。旧bba-native九脚本只供定位，不能改名当097镜像C。新source无deferred行为差异，最终169全族仍在main最终freeze重复。
4. **资源/生命周期。** 同product ELF C/A paired，固定100-query/150s/RST/half-frame/old→fresh EOF/slow-reader/writer、20→30上限、0/150/4096与10批重连。固定0/1/5/15/60排空样本；自己的idle FD身份连续3次归零、G/子进程/线程及PSS/RSS观察。S8日志阻塞时DNSWork回收不提前释放G；actual Linux FIFO/TERM/stale门另绑定。
5. **压力/内部余额。** 公共C合同与source-bound诊断companion分开。11profile pressure目前public_resource_gates可判，但**qualified=false**：view/root/pending/live-requested未观测，不能手填通过。新diagnostic仅ignored源copy（System原样forward原allocator，不header/新分配器），1Hz聚合计数，记录20/上限view、content/index distinct/old-pinned roots、pending、live requested、S8 work=None/日志G与10批余额。该工具正在准备，不可先跑CPU45或用native一次drop/旧3a冒充这个门。full/half/大缓存实际占用需观测，capacity4096不等于已满4096。
6. **CPU45。** 前五层same source/ELF收据通过后再冻结同配置C / R3_new / A各3 TCP profiles×5轮=45，轮次交错，30warmup/120load（90steady+30saturation）、idle60、fixeddrain0/1/5/60；daemon0/upstream1/load2/control3。每正确回答cgroup CPU只计一次，A≤1.05R3_new且严格<C_new，吞吐≥.95R3、p95≤1.05R3，A errors/FD=0。diag不能入CPU分子，既有27不是A的C/R3五轮对照；不得拼最好实验。

## 可直接定位的命令（正式27结束后才执行Oracle）

下面都是准备命令，当前未执行。root提供已冻结环境变量，不复用旧out目录。

```sh
# core/policy/EDNS/lease必须先准备四实际crate bridges，统一primitive-probes锁内copy；
# 具体收据/命令见M6B_TCP_A_PRIMITIVE_ENTRIES.md，不在Oracle调用direct rustc/cargo。
# 以下local-native仅本机旧适配器，不能替代copied库和Oracle资格：
python3 "$M6B_A_SOURCE/tools/dnsmasq/m6b_tcp_a_guards.py" --local-native \
  --repository "$M6B_MAIN" --source "$M6B_A_COMMIT" --out "$M6B_LOCAL_OUT/guards"
python3 "$M6B_A_SOURCE/tools/dnsmasq/m6b_tcp_a_layout.py" --local-native \
  --repository "$M6B_MAIN" --source "$M6B_A_COMMIT" --out "$M6B_LOCAL_OUT/layout"

# guards/layout的private target-dir仅用于本机诊断，不能在Oracle绕过唯一共享target。
# Oracle实际target改用[M6B_TCP_A_TARGET_PROBE.md]的prepare/build/run/collect；此处local-native不能在Oracle运行。
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' sh "$M6B_TOOLS/oracle_build.sh" "$M6B_A_SOURCE" "$M6B_A_BUILD" tests
sudo -n sh "$M6B_TOOLS/run_isolated.sh" "$M6B_A_BUILD/lib-dnsmasq_rs" --test-threads=1
sudo -n sh "$M6B_TOOLS/run_isolated.sh" "$M6B_A_BUILD/bin-dnsmasq-rs" --test-threads=1
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' sh "$M6B_TOOLS/oracle_build.sh" "$M6B_A_SOURCE" "$M6B_A_UBUS_BUILD" ubus-tests
sudo -n sh "$M6B_TOOLS/run_isolated.sh" "$M6B_A_UBUS_BUILD/lib-owrt_ubus" --test-threads=1
ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_FEATURES='' ORACLE_BUILD_LINK_MAP=1 sh "$M6B_TOOLS/oracle_build.sh" "$M6B_A_SOURCE" "$M6B_A_RELEASE" release

sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_A_FUNCTIONAL_MANIFEST" \
  --phase families --attempt 1 --family m5_dns_cache --family m5_edns --family dns-files \
  --family m5_dns_endpoints --family m5_interface_records --family logging-all-scopes

sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_accept_snapshot.py" run \
  --side c --image-root "$M6B_IMAGE" --rust "$M6B_A_ELF" --expected-rust-sha "$M6B_A_SHA" --out "$M6B_A_OUT/accept-c"
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_accept_snapshot.py" run \
  --side rust --image-root "$M6B_IMAGE" --rust "$M6B_A_ELF" --expected-rust-sha "$M6B_A_SHA" --out "$M6B_A_OUT/accept-a"
python3 "$M6B_TOOLS/m6b_tcp_accept_snapshot.py" compare \
  --expected-rust-sha "$M6B_A_SHA" --c "$M6B_A_OUT/accept-c" --rust "$M6B_A_OUT/accept-a" --out "$M6B_A_OUT/accept-comparison.json"

python3 "$M6B_TOOLS/m6b_tcp_pressure.py" plan --out "$M6B_A_OUT/pressure-plan.json"
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_pressure.py" run \
  --side c --image-root "$M6B_IMAGE" --rust "$M6B_A_ELF" --expected-rust-sha "$M6B_A_SHA" --out "$M6B_A_OUT/pressure-c"
sudo -n sh "$M6B_TOOLS/run_isolated.sh" python3 "$M6B_TOOLS/m6b_tcp_pressure.py" run \
  --side rust --image-root "$M6B_IMAGE" --rust "$M6B_A_ELF" --expected-rust-sha "$M6B_A_SHA" --out "$M6B_A_OUT/pressure-a"
python3 "$M6B_TOOLS/m6b_tcp_pressure.py" compare \
  --expected-rust-sha "$M6B_A_SHA" --c "$M6B_A_OUT/pressure-c" --rust "$M6B_A_OUT/pressure-a" --out "$M6B_A_OUT/pressure-public-comparison.json"

# 待内部balance实际闭合，prerequisites必须全绑定同A product source/ELF；不会自动授资格。
python3 "$M6B_TOOLS/m6b_tcp_cpu_gate.py" plan --inputs "$M6B_A_CPU_INPUTS" \
  --output-root "$M6B_A_CPU_COMMON/private" --output "$M6B_A_CPU_COMMON/private/tcp-cpu-plan.json"
sudo -n python3 "$M6B_TOOLS/m6b_tcp_cpu_run.py" --plan "$M6B_A_CPU_COMMON/private/tcp-cpu-plan.json"
python3 "$M6B_TOOLS/m6b_tcp_cpu_gate.py" analyze --plan "$M6B_A_CPU_COMMON/private/tcp-cpu-plan.json" \
  --root "$M6B_A_CPU_COMMON/private" --output "$M6B_A_CPU_COMMON/private/tcp-cpu-analysis.json"
```

CPU common-root必须fresh、gate/adapter/suite/cleanup/controllers全部包含新冻结SHA；不能对baseline27的既有state改expected_windows。每attempt全归档、逐SHA/metadata核验后才能下一窗，强制清理/异常保留。sampler/allocator报告只代表构建机；最终merge A之前全部硬门实际通过，CPU失败保留这一个候选证据并停给用户决定，不择优拼接。

2026-10-08入口补正：tool-only依赖批次提供fresh copied primitive／lib-test／supplement接口；本表旧source/tool SHA仍为历史准备身份。执行前用当前工具与最终A源码重新freeze。上面local-native guards不是Oracle负控资格，必须使用每variant的locked build/run收据；原语、public压力、内部余额和CPU仍逐层open，未编译/未跑不能先写passed。
