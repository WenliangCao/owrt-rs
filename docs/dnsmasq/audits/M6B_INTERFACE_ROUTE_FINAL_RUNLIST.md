# 最终冻结前：membership fault 与 route clears 执行清单

2026-10-08，只读准备，未访问 Oracle、未构建或运行测试。没有改产品或主账本。
本清单不阻塞独立 A 的服务、资源或 CPU 门；root 在正式性能窗口外串行安排。
核对基点 `858064aa`，route debug 修正 `25936b66` 已在该工具树。

## 同一产品的绑定

当前独立 A 为 `ae1cdba6bd03cf4e28b566c31f610a31020824de`，feature-off opt3
SHA `e29007279f74165ffd08afc1d590fe6974db4be0624aa0bfe69aecdc5e827695`，1,962,024 B。
产品源、build 和 map 由现有 `pair-reverse-fixed-02/a` 提供。
历史 d8/924b、70097/34b、诊断 companion 或 s 不能填入此组。
如果此后产品变更，改用新的完整 source freeze/ELF/build/map并 fresh 重跑受影响门；不能仅改 CLI commit。

两个新增工具都**没有** `--source-commit/--build-json/--link-map` 入口：
membership 用实际 ptrace subject SHA，route 再加显式 `--expected-rust-sha`；
source→ELF/build/map 必须由外层精确 Git source freeze 和产品 receipt 补证。
不需要为 fault 本身重建 ELF，map 也不是这两个 syscall/caller 工具的定位依据。

root填以下路径；`GATE_TOOLS` 必须是含25936修正及当前依赖的不可变工具快照，
`GATE_FREEZE` 必须是由精确 Git commit 导出并已验证的 A source freeze，不能临时从目录现状自签。

```sh
GATE_PAIR=/home/ubuntu/dnsmasq-m6b-20261007/pair-reverse-fixed-02/a
GATE_SOURCE="$GATE_PAIR/source"
GATE_RELEASE="$GATE_PAIR/private/opt3"
GATE_ELF="$GATE_RELEASE/dnsmasq-rs"
GATE_COMMIT=ae1cdba6bd03cf4e28b566c31f610a31020824de
GATE_SHA=e29007279f74165ffd08afc1d590fe6974db4be0624aa0bfe69aecdc5e827695
GATE_IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
GATE_C_SOURCE=/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93/src
GATE_TOOLS=/ABSOLUTE/PATH/TO/FROZEN/tools/dnsmasq
GATE_FREEZE=/ABSOLUTE/PATH/TO/ae1-source-freeze.json
GATE_OUT="$GATE_SOURCE/private/interface-route-final-01"
mkdir "$GATE_OUT"
```

开窗前保存绑定，结束后在同样输入上保存 `binding-after.json`，二者逐项一致才采用结果。
下面仅校验已有冻结，不构建、注入或制造通过结果；普通 release build没有逐文件source map时，
原 Git archive/PAX和source freeze是必需的另一个来源，不能用receipt里的目录名替代。

```sh
python3 - "$GATE_SOURCE" "$GATE_RELEASE" "$GATE_COMMIT" "$GATE_SHA" \
  "$GATE_FREEZE" "$GATE_TOOLS" "$GATE_IMAGE" "$GATE_C_SOURCE" \
  "$GATE_OUT/binding-before.json" <<'PY'
import hashlib, json, pathlib, sys
source, release = map(pathlib.Path, sys.argv[1:3])
commit, wanted = sys.argv[3:5]
freeze_path, tools, image, reference, output = map(pathlib.Path, sys.argv[5:])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
freeze = json.loads(freeze_path.read_text())
build_path, elf, mapping = release/'build.json', release/'dnsmasq-rs', release/'link.map'
build = json.loads(build_path.read_text())
assert freeze['source_commit'] == commit and pathlib.Path(freeze['source_root']).resolve() == source.resolve()
assert freeze['elf_sha256'] == wanted and freeze.get('without_tcp_scheme_a') is False
assert freeze['source_files'] and all(not (source/name).is_symlink()
    and sha(source/name) == digest for name, digest in freeze['source_files'].items())
assert build['kind'] == 'release' and build['features'] == '' and build['opt_level'] == '3'
assert pathlib.Path(build['source']).resolve() == source.resolve()
assert build['cargo_target_dir'] == '/home/ubuntu/dnsmasq-cargo-target'
assert [row for row in build['artifacts'] if row['path'] == 'dnsmasq-rs'] == [
    {'path':'dnsmasq-rs', 'sha256':wanted, 'bytes':elf.stat().st_size}]
assert sha(elf) == wanted and elf.stat().st_size == 1962024
assert build['link_map'] == {'path':'link.map', 'sha256':sha(mapping)}
c_sha = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
assert sha(image/'usr/sbin/dnsmasq') == c_sha and (reference/'netlink.c').is_file()
tool_files = {str(path.relative_to(tools)):sha(path) for path in sorted(tools.rglob('*'))
    if path.is_file() and not any(part in ['private','__pycache__'] for part in path.relative_to(tools).parts)}
assert all(name in tool_files for name in ['m6b_netlink_membership_fault.py',
    'm6b_route_resend.py','m5_listeners.py','m5_dns_cache.py','m2_rootfs.py',
    'm2_rootfs_image.py','test_single_poll_service.py','dns_service_probe.py','run_isolated.sh'])
value = {'source_commit':commit, 'source_root':str(source), 'source_freeze_sha256':sha(freeze_path),
    'source_files':freeze['source_files'], 'elf_sha256':wanted, 'elf_bytes':elf.stat().st_size,
    'build_json_sha256':sha(build_path), 'link_map_sha256':sha(mapping),
    'image_c_sha256':c_sha, 'reference_netlink_sha256':sha(reference/'netlink.c'),
    'tool_files':tool_files, 'scope':'startup membership and ordinary route callers; no performance result'}
with output.open('x') as stream:
    json.dump(value,stream,indent=2,sort_keys=True); stream.write('\n')
PY
```

上述完整commit/size是当前 A 固定门，后续最终ELF应整体换成新冻结身份。
Python不能用`-O`或`PYTHONOPTIMIZE`；原工具包含实际资格断言。

## 两个 startup errno：一个 fresh pair

```sh
sudo -n python3 "$GATE_TOOLS/m6b_netlink_membership_fault.py" \
  --side both --image-root "$GATE_IMAGE" --rust-binary "$GATE_ELF" \
  --out "$GATE_OUT/membership-01" \
  >"$GATE_OUT/membership-controller.log" 2>&1 </dev/null
```

`both`的外层自行调用`run_isolated.sh`，C/R分别 fresh sibling namespace；不再套一个共享namespace。
每侧含两个case，不能只跑C或把请求注入当实际覆盖：

| case | syscall与实际判定 |
| --- | --- |
| `membership-eperm` | live AArch64 `bind(200)` 的sockaddr_nl family16/groups550被唯一注入；跳过kernel产生实际ENOSYS，再返回-EPERM。随后**同FD真实**groups0 bind成功，再真实getsockname204成功、groups0/auto port>0；继续启动，`ready.test` A=.53完整health wire/实际ELF身份和TERM exit0、forced=false。 |
| `membership-einval` | 同一550入口唯一注EINVAL，**没有**同FDgroups0 fallback或getsockname；启动exit5、cleanup exit5且非强杀。 |

采用条件：两侧`result.json.passed=true`、顶层`passed=true`且rows相等；每侧实际trace `completed=true`
并复核`check_trace`要求；每条`trace.elf_sha256`分别097/e290。raw sockaddr、entered/exited时钟、
actual/injected return、stdout/stderr、health、identity与cleanup全保留。参考为精确 `netlink.c:68–86`，
Rust生产入口为 `main.rs RouteWatch::new → dns/filewatch.rs bind_groups`。
如果ptrace/权限/ABI不适用，保留失败并标未完成，不把fallback源码或offline测试填成pair通过。

## route clears：fresh完整六case两侧

```sh
python3 "$GATE_TOOLS/m6b_route_resend.py" plan --batch clears \
  --out "$GATE_OUT/route-clears-plan.json" </dev/null
sudo -n sh "$GATE_TOOLS/run_isolated.sh" python3 "$GATE_TOOLS/m6b_route_resend.py" run \
  --batch clears --side c --image-root "$GATE_IMAGE" --rust "$GATE_ELF" \
  --expected-rust-sha "$GATE_SHA" --out "$GATE_OUT/route-clears-c-01" \
  >"$GATE_OUT/route-clears-c-controller.log" 2>&1 </dev/null
sudo -n sh "$GATE_TOOLS/run_isolated.sh" python3 "$GATE_TOOLS/m6b_route_resend.py" run \
  --batch clears --side rust --image-root "$GATE_IMAGE" --rust "$GATE_ELF" \
  --expected-rust-sha "$GATE_SHA" --out "$GATE_OUT/route-clears-a-01" \
  >"$GATE_OUT/route-clears-a-controller.log" 2>&1 </dev/null
python3 "$GATE_TOOLS/m6b_route_resend.py" compare --batch clears \
  --c "$GATE_OUT/route-clears-c-01" --rust "$GATE_OUT/route-clears-a-01" \
  --expected-rust-sha "$GATE_SHA" --out "$GATE_OUT/route-clears-comparison.json" \
  >"$GATE_OUT/route-clears-compare.log" 2>&1 </dev/null
```

固定六case：local-udp、invalid-udp、unmatched-upstream、hup、keep-bound-tcp-private、debug-tcp-query。
只有ordinary bound TCP要2个逐字同wire/source port上游包，其他五项要1包和完整2秒不重发见证；
各侧client恰好1正确答复、forward1、原完整idle FD身份3×20ms恢复、真正kernel qualified route。
详细action消费计数和源码位置沿用[M6B_ROUTE_RESEND_PROTOCOL](M6B_ROUTE_RESEND_PROTOCOL.md)，不重新放宽。
顶层`caller_contract_passed=true`、`c_reference_contract_passed=true`、`differences=[]`且6完整库存才采用；
clear的预定`cleanup_answer=true`不是basic resend成功，不能只看旧`resend_contract_passed`。

debug case必须实际`-d`、两侧config**无enable-ubus**而有log-queries，forward动作来自完整append日志。
由owned TCP四元组/inode/ESTABLISHED/FD集合、client SHUT_WR/server EOF再回held集合证明消费/排空；
不是用失效UBus gauge或sleep。C `dnsmasq.c:2187/drop_ubus_listeners`的debug原版缺陷仍保持既有分类。
旧70097 C前5成功/第6夹具失败只是历史；不拼进这组fresh6case，也不覆写归档红色原始数据。
若工具改变，冻结新工具、fresh复跑受影响全批；在报告中保留所有attempt，不挑最快/最有利窗口。

## 哪些附带输入和边界仍不能扩大

| 入口 | 必须填的冻结资产／资格边界 |
| --- | --- |
| `m5_interface_records.py`实际分配失败caller | `--allocator-map`必须是同产品`build.json`旁的`link.map`，R3取真实realloc符号PC/NULL返回；C取镜像libc calloc。canonical syntax/service中都已传`{link_map}`；只给旧map或跳过配置不授资格。枚举fault-before-clear/empty/partial是另一个真实ptrace入口，不是membership替代。 |
| `m5_tftp_errors.py`实际allocation caller | `--link-map`同build/ELF，R3定位malloc，C定位镜像libc calloc；file syscall errno另走真实file tracer。membership/route不读取这份map，外层仍记录map一致。`m5_script_arp.py --allocator-map`同理。 |
| `m5_dns_endpoints.py --audit-evidence` | `--reference-source`是匹配2.93的src目录，且原syntax/service/archive gate已实际完成；source-row审计不能替代runtime wire。不能用native bba5 C来冒充行为097。 |
| 最终`m5_final_validation prepare` | `bindings.reference_source/link_map`、`deferred_review/safety_review`均重新核最终source；两个review的source_commit必须最终40位、complete=true、ordinary_unresolved=[]。不是把M5旧reviewJSON的commit改为A。此清单前置门不伪造最终review完成。 |
| synthetic短header／未知startup event／child-crash EOF | 精确`dnsmasq.c:613–625/1460–1485/1490–1558`，M5已有source-review＋typed-reader/library断言；没有live malformed-frame注入。与真正`startup-error-frame-interrupt`、opaque/overlong PID/log error-frame生产caller区分，不能因logging整族通过把这些source-only行改称runtime。 |
| C部分TCP import pipe EOF | C `cache_partial_eof_oracle`实际参考有效；当前Rust同步完整CacheTransaction，没有byte Receiver生产入口，旧partial_eof lib filter/0 tests不可授A资格。实际TCP网络EOF、capture/import和服务caller分别证明其现有边界。 |
| runtime ENOBUFS／其它recv errno/POLLERR | membership只是startup bind；`finish_route_read` ENOBUFS→EAGAIN现有code actor不是生产syscall注入。真实watch必须由550 inode/fd选中，C recvmsg212/R recvfrom207 consume及下一实际EAGAIN/ppoll另留证。Rust一秒cooldown和附加read-error日志没有由这两个startup case授C一致资格。安全NLMSG_NOOP peer被内核拒绝时保留拒绝，不伪装kernel sender或制造生产addr/route来绕过。 |
| route其它open/source-only | server删除、wildcard accept-only、双pending最后包、all-servers末次send、重复route、fast-retry/probe各是独立open；TFTP共享void* srv_save别名仅source-only。新增6case不覆盖它们，不反向扩大已关闭第1包或A路线。 |

成功/失败全部raw和overlay upper按GNU metadata完整archive→本机逐SHA/metadata核验→prune；
source archive、ELF/build/map、source freeze、before/after绑定、冻结tools、argv/controller日志、
两工具原始结果均保留。最终统一报告只把实际完成且同最终身份的条目列通过。
这里没有性能结果，物理路由器未访问。
