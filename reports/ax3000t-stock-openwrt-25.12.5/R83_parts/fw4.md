# R83 · fw4：R81-F17（`config defaults` 非法选项）

日期 2026-09-09。参照：`oracle:/home/ubuntu/stage4/firewall4`（upstream ucode firewall4，
`root/usr/share/ucode/fw4.uc`）、设备 rootfs
`oracle:~/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files`。
构建/测试目录 `oracle:~/r81-fw4`（本机只编辑，不在 oracle 上改代码）。未接触路由器。

## 1. 结论

**F17 成立**，且 `R25_ROUND5.md §3.1` 的 DEVIATION 描述**不成立**：

| | R25 §3.1 声称 | 实测（修复前） | ucode 真实行为 |
|---|---|---|---|
| `config defaults` 有非法选项 | fw4-rs "按 ucode 自己的默认值继续并给出完整规则集" | 全 None 的 `Defaults` → `policy null;` + 空 `reject with icmpx type `，`print` 退 **0**，nft 拒绝整个规则集 | 打印该选项的 warning，然后 `Reference error` 回溯，**退 254、stdout 一个字节都没有** |

ucode 不存在"降级到内建默认值"的模式：strict（`-S`，设备 `/sbin/fw4` 用的就是
`utpl -S`）与非 strict 两种方式跑出来都是同一个 254。所以修法是**照样中止**，
不是照 R25 说的降级。

## 2. 证据（ucode 实跑）

`/sbin/fw4`（设备 rootfs）每个动作都是 `utpl -S /usr/share/firewall4/main.uc`，
即 strict 模式；`run_tests.sh` 同样是 `ucode -S -T,`。用上游 mock 布局把
`tests/mocks/uci/firewall.json` 的 defaults 段改坏后 `ACTION=print`：

```
----- bad_input (flags='-S')     rc=254   stdout_lines=0  stderr_lines=15
[!] Section @defaults[0] option 'input' specifies invalid value 'bogus'
Reference error: left-hand side expression is not an array or object
In [anonymous function](), file ./root/usr/share/ucode/fw4.uc, line 1978, byte 12:
  called from function [arrow function] (./root/usr/share/ucode/fw4.uc:751:73)
  ...
 `        if (defs.synflood_protect === null)`
  Near here -------^
----- bad_bool  (flags='-S')     rc=254   stdout_lines=0   ( option 'drop_invalid' ... 'notabool' )
----- bad_list  (flags='-S')     rc=254   stdout_lines=0   ( option 'input' must not be a list )
----- bad_input (flags='')       rc=254   stdout_lines=0   ← 非 strict 同样崩
----- baseline  (flags='-S')     rc=0     stdout_lines=269
----- no_defaults (flags='-S')   rc=0     stdout_lines=248 ← parse_defaults({}) 的内建默认值
```

机制（`fw4.uc:866-902` / `1942-1984`）：`parse_options()` 任何一个选项失败即
`return false`，`parse_defaults` 紧接着 `defs.synflood_protect === null` 解引用布尔
`false` → 未捕获异常 → 解释器退 254。`load()` 里 `parse_defaults` 在渲染与写
statefile 之前，所以什么都不会输出。

修复前的 fw4-rs（同一 fixture，`defaults.input = "ACEPT"`）：

```
print rc=0 lines=197
78:  type filter hook input priority filter; policy null;
87:  type filter hook forward priority filter; policy null;
94:  type filter hook output priority filter; policy null;
108: meta l4proto tcp reject with icmpx type  comment "!fw4: Reject TCP traffic"
109: reject with icmpx type  comment "!fw4: Reject any other traffic"
$ nft -c -f out.nft  →  syntax error, unexpected policy / unexpected type ...   nft_check_rc=1
```

即 F17 描述的"nft 拒绝规则集、但 `print` 退 0"完全复现。

## 3. 修法（`components/fw4`，3 处）

- `src/sections.rs` `parse_defaults()` → `Result<(), ()>`：删掉
  `parsed.unwrap_or_default()`（F17 指的就是这一行），失败即 `Err`，**不再**存下全 None
  的 `Defaults`；重复 defaults 段仍是 warning + `Ok`（ucode 在解引用前就 `return`）。
- `src/sections.rs` `load()` → `Result<(), ()>`：两处 `parse_defaults(..)?`，把中止
  按 ucode 的时序传出去（后面的 zone/rule/include 一律不再解析，也不会多打 warning）。
- `src/main.rs`：`render()` → `Option<String>`，新增 `const UCODE_ABORT: i32 = 254`
  （ucode 未捕获异常的退出码，shell `/sbin/fw4` 靠 `set -o pipefail` 原样传出）。
  各动作按 shell 的真实语义收口：`print`/`check`/`start` 退 254，`restart` 走
  `die("The rendered ruleset contains errors, not doing firewall restart.")`（shell 里
  `QUIET=1 print | nft -c -f -` 的 pipefail 就是这么落到 `die` 的）。
  `start` 现在在写 `fw4.state` **之前**就返回，F17 说的"nft 失败前已写 state → 之后
  `fw4 start` 说 already loaded"随之消失。

保留的偏差（无法忠实复刻，已在代码注释里写明）：ucode 那 14 行解释器回溯不伪造，
fw4-rs 的 stderr 只有 fw4 自己的 warning。因此 `QUIET=1 fw4 print` 在 ucode 下仍打
回溯、在 fw4-rs 下静默退 254（`die()` 本来也受 QUIET 抑制，与 crate 既有约定一致）。
`emit.rs:181` 的 `unwrap_or_default()`/`emit.rs:194` 的 `None => "null"` 未动：
`state.defaults` 现在只能来自成功的 `parse_defaults` 或不会失败的
`parse_defaults({})`，`policy null` 在二进制里已不可达（由下面的测试守着）。

## 4. 测试与门禁

**单元测试**（`src/sections.rs` 末尾新增 `mod tests`，审计的 `tools/audit/r81_fw4_defaults_fallback.rs`
已按实测行为改写并删除；原文件的期望是"降级到内建默认值"，与 ucode 不符）：

- `defaults_invalid_option_aborts`：4 种坏选项（policy / bool / list / limit）经
  `load()` 必须 `Err(())` 且 `state.defaults` 仍是 `None`。
- `defaults_valid_and_missing_render_real_policies`：有效 defaults 与"完全没有
  defaults 段"两种输入必须 `Ok(())`，渲染结果不含 `policy null`、不含空
  `icmpx type  `，且含真实的 `policy drop;` 与 `reject with icmpx type port-unreachable`。

红证（把 `Some(parsed?)` 换回 `Some(parsed.unwrap_or_default())`，其余不动）：

```
test sections::tests::defaults_invalid_option_aborts ... FAILED
assertion `left == right` failed: expected an abort for "input":"ACEPT"
  left: Ok(())   right: Err(())
test result: FAILED. 12 passed; 1 failed
```

**新门禁 `tools/r83_fw4_defaults.sh`**（POSIX sh，`dash -n` 通过）：同一份 fixture
同时喂 ucode 参照与 fw4-rs，逐字节比 stdout、比退出码，stderr 去掉解释器回溯后再比。
本节这一版是 7 例 = 5 个中止例（坏 policy/bool/list/limit/int）+ 2 个对照例
（有效 defaults、无 defaults 段）；§6 把它扩到 12 例。哨兵：中止例要求参照方**确实**是 rc 254 且 stderr 有
`Reference error:`（上游哪天不崩了门禁就红，而不是与死掉的参照方"一致"）、两侧
stdout 必须为空、参照方必须打出选项 warning（否则说明 fixture 没被读到）；对照例要求
两侧 rc 0、stdout 相同且 >50 行并含真实 input policy（两侧同为空过不去）。

修复后（连跑 3 次，全部相同）：

```
== bad_policy: ucode rc=254 stdout=0B stderr=15L | fw4-rs rc=254 stdout=0B stderr=1L
== bad_bool:   ucode rc=254 stdout=0B stderr=15L | fw4-rs rc=254 stdout=0B stderr=1L
== bad_list:   ucode rc=254 stdout=0B stderr=15L | fw4-rs rc=254 stdout=0B stderr=1L
== bad_limit:  ucode rc=254 stdout=0B stderr=15L | fw4-rs rc=254 stdout=0B stderr=1L
== bad_int:    ucode rc=254 stdout=0B stderr=15L | fw4-rs rc=254 stdout=0B stderr=1L
== good:       ucode rc=0 stdout=5028B stderr=2L | fw4-rs rc=0 stdout=5028B stderr=2L
== no_defaults:ucode rc=0 stdout=4716B stderr=0L | fw4-rs rc=0 stdout=4716B stderr=0L
r83 fw4 defaults: 7 cases compared, 0 failures / PASS
```

红证（同一份预修复二进制）：`25 failures`，其中每个中止例都报
``FAIL[...]: rendered `policy null;` ``、`exit code 0, reference 254`、
`fw4-rs printed a ruleset`；两个对照例仍绿（证明门禁不是一律判红）。

**回归**：

- `tools/r09_fw4_check.py`（上游 31 个 testcase）：`Ran 31 testcases in 31 files, 0 failures`。
- `tools/r29_fw4_fuzz.py --seed 3 --cases 120`：`cases=120 differing=0 ucode_crashed=13`（与 R25 同数量级，无回归）。
- 二进制行为核对（mock fixture，`defaults.input=ACEPT`）：`print rc=254`、`check rc=254`、
  `QUIET=1 print` rc=254 且 stdout/stderr 均 0 字节、`/var/run/fw4.state` 未生成。
- `cargo test`：13 passed / 0 failed（§6 追加 include 单测后 14 passed）。

## 5. 遗留

1. `fw4 start` 中止后，shell 版会因为 `ACTION=includes` 再跑一遍 load 而**第二次**打出
   同一条 warning 和回溯；fw4-rs 只打一次就退。未复刻（复刻等于为了错误路径重跑整个 load）。
2. ucode 那 14 行解释器回溯不伪造（见 §3），所以 `QUIET=1 fw4 print` 在 ucode 下仍打回溯、
   在 fw4-rs 下静默退 254。r83/r29 的 stderr 比较都相应地剥掉回溯。
3. `cargo clippy --all-targets -- -D warnings` 在本 crate**仍红**：唯一一条是
   `src/sections.rs:1873`（`parse_include` 那个 `match` 臂里的 `collapsible_match`），
   `git show HEAD` 里逐字相同（本轮只在同函数里改了返回类型，没碰这个分支），
   属 R81 §6 记的既有风格提示，落在 fidelity 敏感的 include 分支上，本轮不动。
   `cargo fmt --check` 全 crate 278 处 diff（本轮前 276）：仓库没有 `rustfmt.toml`、
   CI 也不跑 fmt，既有代码整体按 ~120 列写，本轮新增代码与之一致。

## 6. 追加：`config include`（同一失败类，已修）

协调方指示后在同一 crate 内一并修掉——机制与 F17 完全同形，只是换了一个 section 类型。

**证据（ucode 实跑，同上游 mock 布局）**：

```
----- inc bad position  rc=254 stdout=0B
[!] Section @include[0] option 'position' specifies invalid value 'BOGUS'
Reference error: left-hand side expression is not an array or object
In [anonymous function](), file ./root/usr/share/ucode/fw4.uc, line 3220, byte 12:
----- inc bad type      rc=254 stdout=0B   ( option 'type' specifies invalid value 'yes' )
----- inc path missing  rc=254 stdout=0B   ( option 'path' is mandatory but not set )
----- inc enabled 0     rc=0   stdout=4716B  ( [!] Section @include[0] is disabled, ignoring section )
```

即 `fw4.uc:3220` 的 `if (!inc.enabled)` 解引用 `parse_options()` 的 `false`，与
`parse_defaults` 一模一样。修复前 `sections.rs` 的注释写着"a failed parse falls into the
disabled branch"——不成立：ucode 从不在失败时打 "is disabled"，而是直接中止；fw4-rs
不但继续渲染（4.7 KB 规则集、退 0），还多打了一条 ucode 没有的 warning。

**修法**（`src/sections.rs`，最小）：`parse_include()` → `Result<(), ()>`，
`let Ok(..) = parsed else { warn "is disabled"; return }` 改成 `parsed?`；ucode 自己那
6 条 "ignoring section" 早退全部照旧（改成 `return Ok(())`）；`load()` 两处调用加 `?`
（配置里的 include 段，以及 `auto_includes` 扫 `/usr/share/nftables.d` 合成的那些）。
合成对象的 `position`（`ruleset-pre`/`table-post`/`chain-pre` …）走 `parse_enum` 的前缀
匹配全部有效，不会误中止——由 r09 的 `05_automatic_includes` 与 r83 的 `inc_disabled`
对照例守住。

**门禁与测试**：

- `tools/r83_fw4_defaults.sh` 从 7 例扩到 **12 例**：新增 4 个 include 中止例
  （坏 position / 坏 type / 坏 bool / 缺 REQUIRED path）+ 1 个对照例
  `inc_disabled`（`enabled 0`，ucode 自己的 "ignoring section" 路径，两侧 rc 0 + 规则集）。
  哨兵与 defaults 例完全一致（参照方必须真崩、对照方必须真出规则集）。
- `src/sections.rs` 新增单测 `include_invalid_option_aborts`：4 种坏选项 `load()` 必须
  `Err(())` 且 `state.includes` 为空，`enabled 0` 必须 `Ok(())`。
- 红证（只把 `parsed?` 换回原来的 disabled 分支，其余不动）：

```
== inc_bad_position: ucode rc=254 stdout=0B | fw4-rs rc=0 stdout=4716B
  FAIL[inc_bad_position]: exit code 0, reference 254 / stdout differs / warnings differ / fw4-rs printed a ruleset
   （inc_bad_type、inc_bad_bool、inc_no_path 同）
r83 fw4 defaults: 12 cases compared, 16 failures
test sections::tests::include_invalid_option_aborts ... FAILED
```
  5 个 defaults 中止例与 3 个对照例在这次红跑里**仍绿**——门禁不是一律判红。

**`tools/r29_fw4_fuzz.py` 不再跳过 ucode 崩溃用例**（顺手关掉 R81-H05 记的那条）：
`if crashed:` 从 `continue` 改成照样比 **rc + stdout**（stderr 不比，回溯不伪造），
不一致就 `bad += 1` 并打 `CRASHDIFF`，`ucode_crashed` 计数保留。这条比较自己的红证是
本轮早先用 `/tmp` 临时副本跑出来的 3 条 `CRASHDIFF case0033/0052/0090:
exit 254 vs 0, ucode stdout 0B vs fw4rs 7947/7669/5574B`——正是这三个 include 用例。
修完之后：

```
seed 3: cases=120 differing=0 ucode_crashed=13
seed 4: cases=120 differing=0 ucode_crashed=9
seed 5: cases=120 differing=0 ucode_crashed=17
```

39 个崩溃用例现在逐个比过 rc+stdout 且全部一致（`ucode_crashed` 非 0 证明新分支确实
被走到了，不是空跑）。

**追加后的全量复跑**（同一个二进制 `e39cdcfd…`）：

```
cargo test                                → 14 passed; 0 failed
tools/r09_fw4_check.py                    → Ran 31 testcases in 31 files, 0 failures
tools/r83_fw4_defaults.sh（连跑 3 次）    → 12 cases compared, 0 failures / PASS
tools/r29_fw4_fuzz.py seed 3/4/5          → differing=0（见上）
dash -n tools/r83_fw4_defaults.sh         → ok
```

## 7. 产物

```
aarch64: components/fw4/target/aarch64-unknown-linux-musl/release/fw4-rs
         md5 5e07365d3bf48943b29d125212fdbb9b   size 1118264
host x86_64: components/fw4/target/release/fw4-rs
         md5 e39cdcfda7a784309a719c334c19e124   （§6 的门禁都是对这个二进制跑的）
```

`cargo +1.98.1 build --release --bins --examples --target aarch64-unknown-linux-musl`，
构建目录 `oracle:~/r81-fw4`（本机只编辑，rsync 过去构建）。

md5 的出处必须连着工作树状态一起看：树基线 `57947ae`，除本轮的
`components/fw4/src/{sections,main}.rs` 之外，`components/ubus/src/{blob,convert,json}.rs`
与 `components/uci/src/*` 正被并行的 R83 线程改动，而 fw4 依赖 owrt-ubus / owrt-uci
（同一份 fw4 源码在 ubus 改动前后编出过 `c963790c…`/`482cc02d…` 两个 aarch64 md5，已实测）。
所以这些 md5 只对该次快照有效，发布镜像仍须按 `docs/RELEASE.md` 在干净树上由 CI 重建。
仅 defaults 修复（未含 §6 的 include）时的 aarch64 md5 是 `482cc02d6e9f95f886604491d4412fd8`。

## 8. 改动清单

```
components/fw4/src/sections.rs   parse_defaults/parse_include/load → Result；新增 3 个单测
components/fw4/src/main.rs       render() → Option；UCODE_ABORT=254；四个动作的收口
tools/r83_fw4_defaults.sh        新增（12 例双向哨兵差分门禁）
tools/r29_fw4_fuzz.py            崩溃用例改为比较 rc+stdout（原为跳过）
tools/audit/r81_fw4_defaults_fallback.rs   删除（已按实测行为并入 crate 单测）
reports/.../R25_ROUND5.md        §3.1 顶部加 1 行更正横幅（其余未动）
```
