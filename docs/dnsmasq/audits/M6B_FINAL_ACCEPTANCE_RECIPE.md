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

## 2026-10-08 补充：正式135与guard的准备顺序

本节只读核对 `62497a16` 的工具接口，未访问Oracle、未构建、未执行测试；没有填写未测caps，也没有授予最终资格。当前A `69bccf27`仍是独立分支候选，不能直接冒称下面的最终main候选。

存在一个准备依赖：`m5_final_validation.prepare`要求guard plan已经冻结；而guard的caps仍须真实修后数据。正式135先使用独立的**产品身份receipt**，不依赖final功能控制器的identity。等正式数据和实际20连接PSS依据齐备，再冻结guard和两个真实源码review，最后prepare七阶段功能验收。不得为了先生成final identity填临时阈值，或后来原地改已冻结plan。

固定执行顺序是：A全部门通过→main整合/全部产品修复结束→同源码opt3与s构建→独立product-freeze→`m6a_suite prepare --m6b`→唯一135→本地分析/冻结guard→`m5_final_validation prepare`→七阶段。native prepare会用`cc -O2 -std=c11 -Wall -Wextra -Werror`编译两份helper，必须在正式窗口之外；guard本身不构建helper。

假定下一节的最终路径变量已填写，另设同源码s输出`M6B_S_RELEASE`和本地证据`M6B_LOCAL_PERF`。以下命令是配方，当前未执行：

```sh
# 两构建都在窗口外、统一oracle_build；不增加diagnostics feature。
# opt3先按下一节release命令实际完成；此处只再构建同源s。
unset PYTHONOPTIMIZE
M6B_S_RELEASE=/home/ubuntu/M6B-FINAL/private/release-s
M6B_IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
env -u DNSMASQ_M6B_WAKE_METRICS ORACLE_BUILD_FEATURES= \
  ORACLE_BUILD_OPT_LEVEL=s ORACLE_BUILD_LINK_MAP=1 \
  sh "$M6B_TOOLS/oracle_build.sh" "$M6B_SOURCE" "$M6B_S_RELEASE" release

python3 - "$M6B_SOURCE" "$M6B_FINAL_COMMIT" "$M6B_SOURCE_ARCHIVE" \
  "$M6B_RELEASE" "$M6B_S_RELEASE" <<'PY'
import hashlib, json, pathlib, sys, tarfile
source, release, small = map(pathlib.Path, (sys.argv[1], sys.argv[4], sys.argv[5]))
commit, archive = sys.argv[2:4]
sys.path.insert(0, str(source / 'tools/dnsmasq'))
import build_package
digest = lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
files = build_package.inputs(source)
extra = {str(p.relative_to(source)): digest(p)
         for folder in ('tools/dnsmasq', 'components/dnsmasq/fuzz')
         for p in (source / folder).rglob('*')
         if p.is_file() and not p.is_symlink() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
with tarfile.open(archive) as stream:
    assert stream.pax_headers.get('comment') == commit
    archived = {m.name: hashlib.sha256(stream.extractfile(m).read()).hexdigest()
                for m in stream.getmembers() if m.isfile()}
assert all(archived.get(name) == sha for name, sha in {**files, **extra}.items())
builds = {}
for label, folder, level in [('r3', release, '3'), ('rs', small, 's')]:
    elf = folder / 'dnsmasq-rs'
    receipt = json.loads((folder / 'build.json').read_text())
    assert receipt['kind'] == 'release' and receipt['features'] == ''
    assert receipt['opt_level'] == level and receipt['source'] == str(source.resolve())
    assert receipt['cargo_target_dir'] == '/home/ubuntu/dnsmasq-cargo-target'
    assert receipt['artifacts'] == [dict(path='dnsmasq-rs', bytes=elf.stat().st_size, sha256=digest(elf))]
    builds[label] = dict(path=str(folder / 'build.json'), sha256=digest(folder / 'build.json'))
freeze = dict(schema=1, frozen=True, scope='final product identity; no functional completion claimed',
    source_root=str(source.resolve()), source_commit=commit, source_files=files,
    elf_sha256=digest(release / 'dnsmasq-rs'), source_archive_sha256=digest(archive),
    archived_extra_files=extra, builds=builds)
with (source / 'private/product-freeze.json').open('x') as stream:
    json.dump(freeze, stream, indent=2); stream.write('\n')
PY

python3 "$M6B_TOOLS/m6a_suite.py" prepare --m6b \
  --root "$M6B_SOURCE" --source-commit "$M6B_FINAL_COMMIT" \
  --r3 "$M6B_RELEASE/dnsmasq-rs" --r3-build "$M6B_RELEASE/build.json" \
  --rs "$M6B_S_RELEASE/dnsmasq-rs" --rs-build "$M6B_S_RELEASE/build.json" \
  --image-root "$M6B_IMAGE" --product-freeze "$M6B_SOURCE/private/product-freeze.json"

# Oracle独占窗口；每job内部fresh pilot→formal，固定交错，不能加profile/group过滤。
sudo -n python3 "$M6B_TOOLS/m6a_suite.py" run --manifest "$M6B_SOURCE/private/manifest.json"
```

在本机另一通道启动归档watcher；source是上面实际Oracle root，不能填写旧27/45或旧M6a root。它已经把proof经ubuntu staging后sudo install到root-owned目录：

```sh
M6B_LOCAL_PERF=/Users/USER/Developer/owrt-control-plane-rs/private/dnsmasq-rewrite/evidence/M6B/final-135-FINAL_COMMIT
python3 tools/dnsmasq/m6a_archive_watch.py \
  --remote-root "$M6B_SOURCE" --local-root "$M6B_LOCAL_PERF"
# 最后一窗归档和prune完成后，本机跑离线分析；保留全部attempt，不选最快窗。
python3 tools/dnsmasq/m6a_analyze.py --evidence-root "$M6B_LOCAL_PERF" \
  --output "$M6B_LOCAL_PERF/analysis.json"
```

正式链结束须核`state.status=complete`、`formal_valid_windows=135`、全部9×3组合各5个有效窗，以及analysis的`formal_complete=true`和`valid_counts`。`m6a_analyze`结果中的method固定沿用M6a统计文字，报告必须同时链接manifest里的M6B协议SHA和本轮identity，不能把method字段当旧M6a ELF身份。行为错误保留为回退；方法无效的fresh重跑与原失败都保留。

guard plan的`native_manifest.path`使用本轮`$M6B_SOURCE/private/manifest.json`及其实际SHA；不能用`product-freeze.json`替代，因为它没有`native`与`tools_files`。两份helper和C源码通过guard的`inputs()`锁定。三caps仍留模板null，待root按真实UDP/60秒idle/20连接hold与短窗PSS证据冻结，`basis`应列原始路径、SHA、候选身份和阈值推导；正式TCP采样峰值不能单独冒称确定保持20连接的PSS。需要补采时使用当前feature-off ELF和现成native helper，在正式窗口之外单列证据。不得据guard失败改cap再将同轮记为通过。

## 最终资产预检（不启动窗口）

下列清单由当前接口静态核出。Oracle存在性/执行许可仍须root在正式前核实；旧`m5_final_assets.json`是历史观察，不能当本轮已验证。`m5_final_validation.prepare`本身只hash/展开commands，不跑产品或build，可在guard/reviews完成后作为最后一遍强预检。

| 资产 | 必须保留／核实的具体对象 | 缺口会出现的位置 |
| --- | --- | --- |
| 最终源码/构建 | prefixless Git PAX archive及commit comment；完整source/tool/fuzz字节；opt3/s build.json与ELF；opt3同次link.map | 两prepare均校验source/build/artifact；final prepare要求map在build.json同目录、receipt SHA一致 |
| 原生测量工具 | 本轮native manifest、`private/native/m6a_loadgen`、`m6a_upstream`、两份`.c`；Oracle `cc`；四核与cgroup2 | suite prepare编译native；run要求CPU集合恰0/1/2/3；guard核源码/ELF SHA，不现场编译 |
| 精确镜像/运行root | 镜像dnsmasq SHA097a…；完整rootfs文件；runtime cfg01411c；M2 plan四profiles与source_config SHA | M2完整7 DNS/4 DHCP/两lifecycle，不能拿测试overlay改shared base |
| UBus镜像runner | runner、image-identity.json及同目录`usr/sbin/dnsmasq`,`lib/libc.so`,`lib/libubus.so.20251202`,`lib/libubox.so.20260213`,`lib/libgcc_s.so.1` | `verify_reference`逐文件SHA且runner文本必须执行identity父目录绝对路径；不能随意搬runner后保持旧identity |
| UBus原生helper | `c-native-01/dnsmasq/dnsmasq` SHA bba5…；完整deps目录，尤其include/lib与`deps/sbin/ubusd`；Oracle `cc` | native只供helper；行为C仍镜像097a…；ordinary350及helper编译依赖不能删 |
| C对应源码 | 完整2.93 `src`目录，含option.c/cache.c/headers，原目录字节锁 | endpoint191-row审计；query-id-wrap source control；UBus/native边界归因 |
| SDK | 精确25.12.5 SDK目录及其父目录原`.tar.zst` SHA；`sdk_inputs()`列全部wrapper/隐藏.bin/runas.so/loader/toolchain；实际musl交叉gcc | final prepare和package双校验；query-id-wrap在families阶段也需SDK gcc（不只package需要SDK） |
| 包资产 | stock r1；2 variants＋5 solver deps；接受过M5原r2 APK | prepare锁所有字节；r3 lifecycle14阶段；variants只solver，不安装 |
| 审查/守卫 | 当前final commit的deferred/safety JSON（complete=true、ordinary_unresolved=[]）；frozen guard plan、三实测caps/native manifest | reviews须重新审查本轮代码，不能仅替换旧commit；null caps明确拒绝 |
| 库存/预算 | final源码原canonical44族/68steps registry、原1,000,000B ELF/700,000B APK预算 | 不删族/check/inventory；size-only失败保留完整artifact继续14stage，不接受新增体积 |

M5原APK本机仍在`E/M5/final-20261006/dc1b740d7973/archive-package-final/plain/build/dnsmasq-2.93-r2.apk`。本次仅核路径/stat：1,065,071B；已有固定身份见APK配方，root上传后须再次实际核SHA `bfed44eaf49703745a2c08a8ee1fbc5325b44f833d07baee2224a0084a6ee8aa`，不重建旧包。所有镜像、ELF、APK、SDK和raw保持private，不进Git。

实际最终argv以`m5_final_validation prepare`生成的`commands.json`为准；placeholder库存核定只有常规source/tool/image/ELF/commit/out之外的`link_map`,`reference_source`,`sdk`和四个UBus bindings。`ubus_image_runner_sha`/`ubus_image_identity_sha`由prepare的verified reference生成，不需用户猜填。七阶段的controller命令见下一节；M2/resources/pressure/package/lifecycle的leaf argv和结果check见每阶段表，不另写简化runner。

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

最终controller以root运行，ENDPOINT通常root-owned。proof、prune收据及verified plain tar先scp到ubuntu可写的独立staging，再`sudo -n install`/`sudo -n cp`到规定文件名；plain用sudo解包恢复。prune命令的stdout也要由root shell写入ENDPOINT，不能以ubuntu shell直接重定向到root-owned目录。不要chmod原raw绕过权限，因为mode/ownership本身属于完整metadata门。whiteout/device/FIFO等special对象只留原GNU/PAX tar；plain只用于原report/source-row audit。

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
