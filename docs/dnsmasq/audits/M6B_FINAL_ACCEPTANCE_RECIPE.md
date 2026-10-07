# M6b 最终同 ELF 统一验收执行配方

2026-10-07。只读核对基点 `58eaf93d`，独立最终工具提交 `0594a930`；本文是执行准备，**未运行 Oracle、未构建产品、未执行任何最终门**。只执行了下述两个本地工具负控。此工作不改变第1包收尾点，不阻挡无A新基线或方案A；最终方案A语义/资源/CPU门通过、合入且全部产品修复完成后，root才使用本配方。

## 被验收身份与冻结输入

唯一功能对象是最终 **feature-off opt-level 3** ELF。同源s只参加独立正式性能比较，不能代替功能／资源／APK对象。镜像C固定完整SHA：`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`，由 `m2_rootfs.STOCK_SHA256`、prepare的实际image ELF和各族check共同绑定。

| 输入 | 确切字段／规则 |
| --- | --- |
| 模式 | `validation_mode="m6b"`；固定七阶段，不能选小子集；新fuzz-build/fuzz标excluded-not-required，不是通过 |
| 源码 | `source_root/source_commit/source_date_epoch/source_archive`；完整40hex commit；prefixless `git archive --format=tar`，PAX comment必须是该commit。prepare比对全部产品／工具／fuzz文件SHA |
| 产品 | `elf/elf_sha256/build_json`；oracle_build release、共享target `/home/ubuntu/dnsmasq-cargo-target`；完整64hex SHA和实际bytes；`features=""`、`opt_level="3"` |
| 链接map | `bindings.link_map` 必须为该build.json同目录link.map，SHA在build receipt一致；TFTP／接口fault门需要它 |
| 44族 | `family_plan`原样复制最终源码的 `m5_final_families.draft.json`；schema1、complete=true、无pending；**44 canonical families／68具体steps**，不删族、不缩checks/inventory、不拿旧family completion |
| 两个最终审查 | `deferred_review/safety_review`各自source_commit等于最终commit，complete=true、ordinary_unresolved=[]；重新审查本轮产品，不只替换旧JSON的commit |
| 镜像／运行配置 | `image_root`精确OpenWrt 25.12.5 rootfs；`runtime_root`原运行root；captured配置 `var/etc/dnsmasq.conf.cfg01411c` SHA须等于 `dhcp_plan.source_config_sha256`；完整4个DHCP profiles |
| UBus | bindings的`ubus_image_runner/ubus_image_identity`为精确镜像runner及五个镜像文件；`ubus_reference_build/ubus_native_c_sha=bba5…`只供native helper，不作为行为C。实际匹配source另填`bindings.reference_source` |
| 包资产 | `sdk/stock_apk`、2个`variant_apks`、5个`variant_dependency_apks`；M6b `package_release=3`，`previous_package`为已接受M5 r2的原APK/ELF/source完整固定身份；prepare锁原APK SHA，不重建旧包 |
| 性能守卫 | `perf_guard_plan` schema1、frozen=true、非空basis；3个caps必须正有限数：udp_p50_max_ns≤1,000,000、idle_cpu_max_seconds、tcp_peak_pss_max_kib；模板仍null不可执行。native_manifest完整SHA、两份helper ELF及其C源必须匹配最终工具树 |
| CPU／体积 | `cpus=[0,1]`用于旧资源pair的独立C/R核；perfguard固定daemon/upstream/load/controller=0/1/2/3。budget保持原1,000,000B ELF／700,000B APK；记录原始size失败，M5既有接受与M6b增量最终决定分开 |

最终控制器为 `tools/dnsmasq/m5_final_validation.py`，M6b阶段顺序固定为 `families,m2,perf-guard,resources,pressure,package,lifecycle`。只有package/lifecycle在代码中自动要求所有此前阶段；root仍按下面顺序执行，不能以先跑package或缺少前置completion绕过。正式135窗口、方案A硬门与新增route/wake补证属于独立前置证据，控制器summary不会替代它们。

## root的可执行配方（现在未执行）

以下变量由root在最终freeze时填实际绝对路径；不填写中间候选，不用M5旧ELF。源码archive须在可信Git checkout生成并复制／解包到fresh source目录；不加tar prefix。所有输出在对应source/private中。

```sh
set -eu
M6B_SOURCE=/home/ubuntu/M6B-FINAL/source
M6B_RELEASE=/home/ubuntu/M6B-FINAL/private/release
M6B_SOURCE_ARCHIVE=/home/ubuntu/M6B-FINAL/source.tar
M6B_FINAL_COMMIT=FULL_FINAL_40_HEX_COMMIT
M6B_FINAL_EPOCH=FINAL_COMMIT_UNIX_TIMESTAMP
M6B_GUARD_PLAN=/home/ubuntu/M6B-FINAL/private/perf-guard.json
M6B_M5_APK=/home/ubuntu/M6B-FINAL/private/accepted-m5/dnsmasq-2.93-r2.apk
M6B_INPUTS=/home/ubuntu/M6B-FINAL/private/inputs.json
M6B_OUTPUT="$M6B_SOURCE/private/m6b-final"
M6B_TOOLS="$M6B_SOURCE/tools/dnsmasq"

# 可信Git checkout上的archive命令；随后由root复制/解包到M6B_SOURCE。
# git archive --format=tar "$M6B_FINAL_COMMIT" > "$M6B_SOURCE_ARCHIVE"

# 全部正式性能窗口外构建；同一锁中构建并复制，map与ELF属于同次build。
env -u DNSMASQ_M6B_WAKE_METRICS ORACLE_BUILD_FEATURES= \
  ORACLE_BUILD_OPT_LEVEL=3 ORACLE_BUILD_LINK_MAP=1 \
  sh "$M6B_TOOLS/oracle_build.sh" "$M6B_SOURCE" "$M6B_RELEASE" release

# guard/reviews应已由root真实填写；这里只生成输入，未伪造审查或caps。
python3 - "$M6B_SOURCE" "$M6B_RELEASE" "$M6B_FINAL_COMMIT" \
  "$M6B_FINAL_EPOCH" "$M6B_GUARD_PLAN" "$M6B_SOURCE_ARCHIVE" "$M6B_INPUTS" "$M6B_M5_APK" <<'PY'
import hashlib, json, pathlib, shutil, sys
source, release = map(pathlib.Path, sys.argv[1:3])
commit, epoch, guard, archive, output, m5_apk = sys.argv[3:]
spec = json.loads((source / 'tools/dnsmasq/m5_final_inputs.example.json').read_text())
private = release.parent
family = private / 'family-replay.json'
shutil.copyfile(source / 'tools/dnsmasq/m5_final_families.draft.json', family)
build = json.loads((release / 'build.json').read_text())
assert build['kind'] == 'release' and build['features'] == '' and build['opt_level'] == '3'
elf = release / 'dnsmasq-rs'
spec.update(validation_mode='m6b', source_root=str(source), source_commit=commit,
    source_date_epoch=int(epoch), elf=str(elf),
    elf_sha256=hashlib.sha256(elf.read_bytes()).hexdigest(), build_json=str(release / 'build.json'),
    source_archive=archive, budget=str(source / 'tools/dnsmasq/m5_final_budget.json'),
    family_plan=str(family), deferred_review=str(private / 'deferred-review.json'),
    safety_review=str(private / 'safety-review.json'), perf_guard_plan=guard, cpus=[0,1], package_release='3',
    previous_package={'path': m5_apk, 'package_id': '2.93-r2',
        'apk_sha256': 'bfed44eaf49703745a2c08a8ee1fbc5325b44f833d07baee2224a0084a6ee8aa',
        'elf_sha256': '37f85d22e29591e722096b6ccd48f8eb85d63d248af606b939f86f7109ce7f7b',
        'source_commit': 'dc1b740d7973838e2ae7f098d0726b0484e55074'})
spec['bindings']['link_map'] = str(release / 'link.map')
# 示例的image/runtime/SDK/M2/APK/UBus路径必须由root在此核实或修正。
with pathlib.Path(output).open('x') as stream:
    json.dump(spec, stream, indent=2); stream.write('\n')
PY

python3 "$M6B_TOOLS/m5_final_validation.py" prepare --inputs "$M6B_INPUTS" --out "$M6B_OUTPUT"
M6B_MANIFEST="$M6B_OUTPUT/identity.json"

sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_MANIFEST" --phase families --attempt 1
sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_MANIFEST" --phase m2 --attempt 1
sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_MANIFEST" --phase perf-guard --attempt 1 --exclusive-window
sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_MANIFEST" --phase resources --attempt 1 --exclusive-window
sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_MANIFEST" --phase pressure --attempt 1 --exclusive-window
sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_MANIFEST" --phase package --attempt 1
sudo -n python3 "$M6B_TOOLS/m5_final_validation.py" run --manifest "$M6B_MANIFEST" --phase lifecycle --attempt 1
python3 "$M6B_TOOLS/m5_final_validation.py" summary --manifest "$M6B_MANIFEST"
```

`families`内endpoint归档等待需要root另一执行通道配合，见下一节；不能让前台阻塞后忘了供proof。其他普通族可用重复`--family ID`分批，但最终需同一freeze的全部44族aggregate；失败复跑用新`--attempt N`。工具／夹具修订须新的工具freeze及fresh受影响族，不在冻结树原地编辑；不得把旧M5/M6a、旧ELF或旧候选结果导入最终资格。

## 每阶段检查表（全部待执行）

| 阶段 | 确切job入口／结果 | root必须核对 |
| --- | --- | --- |
| families | canonical 44族/68steps，实际argv在prepare的commands.json | 44个`family:ID`和aggregate `families.passed=true`；完整steps/result SHA/checks/inventory；同source/ELF/manifest；包括cache的8次独立C reverse及lease/TCP caller、191 endpoint rows；不能只看顶层进程exit0 |
| m2 | `m2_dns_diff.py` 7 profile：udp-cache/expiry/tcp/failure-recovery/strict-order/all-servers/representative-mix；`m2_dhcp_suite.py`完整4 profile；`actual_config_network.py → m2_lifecycle.py` C/R各一次 | DNS differences/failures=[]、unexecuted=0；DHCP每个final-profile comparison errors=[]、实际C/R ELF集合准确；真实init/HUP/UCI/odhcpd/stop全部passed |
| perf-guard | `m6b_perf_guard.py`，`cache-guard/result.json` | 同opt3 feature-off identity；20client、warmup2s/load10s、10k施加QPS、无saturation；warmup/measured错误0，至少1000正确latencies并覆盖20client；60s实测idle CPU；确实hold20 TCP且FD+20/单线程/无子；PSS=max(hold20,1Hz短窗peak)；三个cap均过 |
| resources | `m3_soak.py pair` mixed-300；`cache_full_resource.py pair` full-cache-300 | 两组各实际≥300s、1Hz/20client、correct accounting/cleanup；满载先跑4095负控，再4096逐名live A证明，上游禁答且无额外upstream；initial/final occupancy均过；报告RSS空/填满/全扫描/Q4 median与增长，accepted只是采集和cleanup，不自动认定内存收益 |
| pressure | `run_isolated.sh → m3_soak.py pressure --scenario enospc --scenario emfile --duration-seconds 300 --timeout-seconds 3600` | 每scenario×C/R实际错误触发、恢复与清理，normalize比较equal；300是每侧deadline，不写“暴露300s” |
| package | `runuser -u ubuntu → build_package.py --frozen-elf --freeze-manifest …` | APK usr/sbin/dnsmasq SHA等于已验收ELF；postprocess none，不重新codegen/strip；SDK recipe恢复；artifact SHA/bytes/payload/metadata正确。只size-target失败可保留artifact继续生命周期，budget failure原样报告 |
| lifecycle | `run_isolated.sh → m4_package_lifecycle.py`，实际安装路径被执行 | stock r1→candidate r3及接受过M5 r2→r3真实upgrade（同版force-reinstall另列）、fresh install/account、uninstall/config保留、remove后stock/M5 rollback、direct stock/M5 downgrade；candidate ELF SHA准确；post-upgrade脚本与stock一致；两个variant solver互斥及五deps，只模拟不安装variants |
| summary/报告 | summary.json、M6B_FUNCTIONAL_REPORT.draft.md | seven required missing_phases=[]、functional_validation_passed=true；另外人工合并正式135／A硬门／新route&wake证据、每项前后/C分类、M6a更正、s代价、所有失败/重跑、体积/RSS与未解差距到M6B_REPORT.md；未经M7不称生产验收 |

资源pair是C/R各用不同核、各fresh namespace并行的旧资源合同，**不是正式M6吞吐比较**；load与controller继承该侧核。perfguard／正式测量才用四角色不相交核。正式、guard、资源和压力期间Oracle不并行build/test/fuzz；exclusive-window只检测已知进程，仍需root协调。guard自己持共享Cargo锁，外层不重复锁；资源/压力由外层持锁。

## Endpoint archive gate操作

44族运行到 `m5_dns_endpoints/archive-gate.ready.json` 时，syntax/service已完成，local-archive-gate等待本机full-metadata验证。默认全族路径是 `$M6B_OUTPUT/runs/families/attempt-1/m5_dns_endpoints`；如果分组执行，从该group的commands.json读取实际路径，不猜组hash。

对syntax和service各执行：Oracle root用 `m5_option_matrix_archive.py pack --run ENDPOINT/name --archive ENDPOINT/name.tar.gz --manifest ENDPOINT/name.manifest.json`（archive/manifest放在run外）；下载到本机；本机用 `m5_final_archive_gate.py verify-local --archive LOCAL/name.tar.gz --manifest LOCAL/name.manifest.json --plain LOCAL/name --out LOCAL/name.local-verification.json`。只在真实verified=true/full-metadata、SHA均核对后，上传proof到对应Oracle的`name.local-verification.json`；Oracle执行 `m5_option_matrix_archive.py prune --run ENDPOINT/name --manifest ENDPOINT/name.manifest.json > ENDPOINT/name.prune.json`；然后把已验证本机plain普通文件/原report恢复到原name路径。gate必须核对异host proof、archive/manifest/prune SHA、原result SHA才能继续191-row audit。不能手写proof、跳过prune witness或伪造相同hostname验证。

所有其他成功／失败原始目录也按pack→本机verify全部SHA+metadata→prune保存，不只归档summary。保留最终source archive、ELF/build/map、输入/reviews、identity/commands/completed、全部尝试、APK和生命周期、overlay upper（xattr/whiteout/links/mode）以及本地验证收据。变更产品后必须新freeze，至少全部受影响族再次实际执行；最终统一链始终绑定最后同一ELF。

## 已发现旧绑定／工具缺口与处置

- `M5_FINAL_VALIDATION.md`开头M5未完成、M6未执行和体积未接受是旧时点文本；它的fuzz命令只适用于m5。M6b应选上面的模式与七阶段；不能把旧说明当本轮结果。`m5_final_assets.json` 30GB和旧路径也是历史观察，本次未访问Oracle验证。
- prepare/guard原来只强feature-off，可能误把s当最终功能ELF。工具提交 **0594a930** 已加opt3硬门；prepare只针对mode=m6b，M5原policy不变；guard同时绑定release/feature/opt/SHA/bytes。两个最小本地负控实际通过：s/z/int3/null/diagnostics拒绝，M5旧policy保持，guard错误SHA/size拒绝。证据 `E/M6B/final-opt3-tool-guard-0594a930/manifest.json` SHA `853889d394f8b371831d5f786b1dc299a7b08463d9c764d8c397e4fd226bee5c`。没有Oracle执行资格。
- `perf_guard_inputs.example.json`仍未冻结且三个caps为null；不能为了prepare通过填臆测数字。root用实际修后基线／A／最终数据冻结basis、native manifest与caps；保护线不是正式收益阈值，guard失败不能挑最快窗口替换。
- UBus `bba5…`是native helper硬绑定；**行为C仍097a…**。若旧helper路径失效，须重新生成/冻结相同合同的helper资产，不能改reference为nativeC；不得移除五个image文件核验。
- 已补独立tool-only r3版本与旧M5资产绑定：M5默认r2合同保留，M6b使用r3、原stock8阶段＋接受过M5升级/回滚6阶段。完整SHA、接口、执行配方和未执行边界见[M6B APK升级范围](M6B_APK_RELEASE_UPGRADE.md)；不能继续把M5 r2→M6b同版r2称upgrade。
- 固定预算／`size_acceptance=pending-user-after-report`仍是机械分类，不能覆盖用户已接受的M5历史，也不能偷偷接受M6b新增体积；保留size-target失败、完整reviewable APK并让用户在M6B报告后决定增量。`summary.m6_performance_executed=false`描述这个功能控制器范围，正式135证据另行汇总。
- canonical44族中的dns-files route case原本不证明saved UDP resend。新的basic poll/no-poll、已写wake actor和方案A S1–S8补门须以最终身份单列重放/绑定，不把旧44族通过冒称这些新增caller已过；后续新边界保持独立open，不反向扩大第1包收尾点。

本文没有实测结果；性能结论只限构建机。物理路由器未访问。
