# 资源02：真实分配余额与有效 HashMap 容量

2026-10-08。measurement-only 工具修正；产品、固定 workload、warm 和预算不变。
资源02原结果保持失败。新计数、原六方法 controls 和同源 fresh companion 尚未在 Oracle
构建或执行；本提交不能给任何 A 资源／CPU 门授予资格。

## 已证实的方法边界

原 `m6b_resource_roots.rs::m6b_finish_root_sample` 记录 `roots.capacity()`，随后
`m6b_tcp_internal.py::BALANCE_FIELDS` 将该值要求严格等于结构预热 baseline。
原红色观察：registry_len=128，baseline有效capacity152，b00=156；b01–b09/final
有效capacity在147–155间变化。b00已先因这个字段失败。后面的真实requested
余额又多128B，不能用前一个方法缺陷豁免。

本地已有 Rust1.98.1 的 primary rust-src。`library/std/src/collections/hash/map.rs:484`
调用base.capacity；`library/vendor/hashbrown-0.17.1/src/raw.rs:1324`返回
items+growth_left。`raw.rs:3224`删除遇DELETED时不增加growth_left；EMPTY才恢复它。
`raw.rs:850`的shrink_to只在最小bucket数低于当前bucket数时重建。
因此该值是可插入元素的有效下界，tombstone可以改变它而不改变allocator请求字节。
它不能当作allocated capacity或泄漏量。

工具保留原registry_capacity原始值，并增加明确的
registry_capacity_semantics=effective-insertion-lower-bound。严格余额改核真实
observer_registry_requested、live_requested_including_diagnostic和live_objects；
product_live的精确减法、根计数、全部owner/transaction归零和其它容量守卫不变。
旧trace缺少该明确语义或新的scalar字段不能被新collector默默重新解释。

registry-growth负控同时令observer requested与total requested增加1B，保持
product_live完全相同，必须仍被拒绝。原known-one-byte/object、根与owner负控保留。
现有六个copied method入口不增加或改名；snapshots/detach入口内部增加确定性
真实HashMap对照：固定hasher使128项同cluster，删除内部key后在另一EMPTY group插入，
保持len128；有效capacity下降而live/observer bytes、objects及alloc/realloc/free均不变。
这个实际Rust断言仍待root新copied lib执行，不能把尚未执行写成通过。

## +128B的决定性下一步

同源A79e的SinglePoll已有poll_fds与ready_fds两条Vec<PollFd>；PollFd的repr(C)
字段是i32/i16/i16，64位Linux为8B。ready_fds每turn clear+extend保留已分配容量。
原trace没记录这两个Vec。若ready容量16变32，requested差恰为128B、对象数仍相同；
一次20连接warm并不证明一次poll已同时出现20个ready。这只是待实测归属假设。

新增poll_fd_bytes、ready_fd_bytes仅读取capacity乘size_of，无reserve、clone、format
String、root array或product Arc变化。hook在poll.step成功返回后采样，正常owner
poll_fds已从局部fds恢复。字段纳入严格余额，增长不会被当作已通过。

root用真实product build receipt中的SHA重新prepare新目录、build release+copied
probe、bind、实际原六controls，然后以原fixed workload和fresh输出诊断。
逐row核对total requested、observer requested、两Vec bytes与对象／根／owner变化，
保留全部attempt及0/1/5/15/60样本。不能先改变warm、删批、扣去ready容量或放宽1B门。
如果+128无法被实际新计数归属或继续增长，仍按失败推进审计和协议处置。

## Fresh prepare接口（仅计划，未执行）

工具必须从包含本提交的完整freeze读取，不使用被覆盖的旧prepared目录：

```sh
M6B_DIAG_TOOLS=/absolute/reviewed/tools/dnsmasq
M6B_PRODUCT_BUILD=/absolute/local/actual-product-build.json
M6B_NEW_PREP=/absolute/repository/private/dnsmasq-rewrite/evidence/M6B/a-79e-resource-counters-prep-01
M6B_PRODUCT_SHA=$(python3 - "$M6B_PRODUCT_BUILD" <<'PY'
import json, re, sys
r = json.load(open(sys.argv[1]))
assert r['kind'] == 'release' and r['opt_level'] == '3' and r['features'] == ''
assert r['cargo_target_dir'] == '/home/ubuntu/dnsmasq-cargo-target'
assert len(r['artifacts']) == 1 and r['artifacts'][0]['path'] == 'dnsmasq-rs'
s = r['artifacts'][0]['sha256']; assert re.fullmatch('[0-9a-f]{64}', s)
print(s)
PY
)
python3 "$M6B_DIAG_TOOLS/m6b_resource_companion.py" prepare \
  --repository /absolute/repository \
  --source-commit 79e29d7de66c57fcdbfa2c98b9bec05675c30462 \
  --product-sha256 "$M6B_PRODUCT_SHA" --out "$M6B_NEW_PREP"
```

读build receipt不等于验证source/ELF；原bind和完整source maps仍必须实际核对。
这里不预填产品或诊断SHA，不创建新source/build/bind/controls通过收据。
第4包继续延后M6b；物理路由器未操作。
