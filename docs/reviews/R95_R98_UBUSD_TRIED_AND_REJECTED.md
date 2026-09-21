# ubusd R95–R98: tried / rejected inventory (factual extract)

Compiled from `docs/UBUSD_GOAL_RESEARCH.md`, `docs/R95_PERFORMANCE_RESEARCH.md`,
`docs/reviews/R95_UBUSD_PILOT.md`, `R95_UBUSD_BATCH_EXPERIMENT.md`, `R95_UBUSD_RANGE_EXPERIMENT.md`,
`R96_UBUSD_PATH_SHARING.md`, `R96_MEASUREMENT.md`, `R97_METHOD_COMPATIBILITY.md`,
`R97_UBUSD_METHOD_STORAGE.md`, `R95_DEFECT_FIXES.md`, the `docs/reviews/r95-*.json`…`r98-*.json`
artifacts, `git log`, and (for §7 only, clearly marked) raw device data under ignored `private/r98/`.

## 1. Arms in the benchmark matrix

| Arm | Meaning |
|---|---|
| **stock / C** | Image-matched original `ubusd` from OpenWrt 25.12.5 (ubus revision `24864e7840b3a02a9ef76284a373f6b2f00b8a9b`). Production always runs this. ELF `cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88`. |
| **r89** | Previously released Rust build (R89). ELF `9b7169b35864bcabd702339795040302e3eaf4e85b23b635578399b2fa0334ef`. |
| **before** | The candidate build immediately preceding the change under test — a localization side, explicitly *not* a substitute for C or r89 (`R95_PERFORMANCE_RESEARCH.md` §1). |
| **candidate** | The build with the change under test. |

Per-arm ELF sha256 is frozen in each plan JSON (`r98-event-matrix-plan.json` `subjects`). R99-era
"source05" is included only when rechecking its specific regression.

**Current accepted baseline: commit `5a19517` (`fix(ubusd): match C method-name ACL and signature
normalization`), ELF `527f8683…`** — full sha256 `527f8683395aee6b6ff016c70fbd9dafd7a87edbacaeab7f65333291d2617096`
(`UBUSD_GOAL_RESEARCH.md`; `r97-method-storage-validation.json` `before_sha256`).

## 2. Benchmark workloads

Built by `tools/benchmark/isolated.sh` (ubusd branch), 64-object bus unless noted. `_c4` = four
concurrent clients sharing **one** outer CPU interval (`lookup_four` / `rpc_four`); their overlapping
per-client daemon counters are never summed.

| Lane | What it measures |
|---|---|
| `lookup` | Exact single-object lookup, `bench.*`→`bench.target` pattern, 64-object bus |
| `lookup_all_64` | Whole-bus wildcard lookup (`'*'`) with 64 objects |
| `invoke` | Method invocation `bench.target ping {"n":1}` → `{"ok":1}` |
| `lookup_prefix_64` | Prefix-pattern lookup (`'bench.*'`) with 64 objects |
| `lookup_all_128` | Whole-bus wildcard lookup with 128 objects |
| `lookup_c4`, `lookup_all_64_c4`, `invoke_c4`, `lookup_prefix_64_c4`, `lookup_all_128_c4` | Same five as above, four concurrent clients |
| `register_1_8`, `register_16_8`, `register_64_8`, `register_1_128` | ADD_OBJECT + REMOVE_OBJECT **cycles** (R97/R98 registration meter `15d1046…`); unit = complete add/remove cycle with N methods / N name bytes |
| `watch_1_1`, `watch_8_1`, `watch_1_0` | R98 event fanout: eligible-receiver objects / non-matching listeners; `watch_1_0` = zero eligible receivers. **Frozen, not yet executed** |

Eleven planned metrics per lane: `mean_us`, `p50_us`, `p95_us`, `p99_us`, `subject_cpu_us_per_op`,
`dependency_cpu_us_per_op`, `client_cpu_us_per_op`, `subject_own_cpu_clock_us_per_op`,
`dependency_own_cpu_clock_us_per_op`, `client_cpu_clock_us_per_op`, `ops_per_s`.
Statistic: **paired-run ratio median** per independent block (not pooled mean/p99); "优于" needs the
rank-interval upper bound < 1 *and* a pre-frozen practical threshold.

## 3. Rejected / not-adopted optimizations

### 3.1 R95 H1 — ~4 KiB batched reply send (`r95-ubusd-4k.patch`) — **REJECTED**
- **Change:** kept the 16 KiB total-reply eligibility cap but sent eligible replies as ~4 KiB complete-frame blocks; oversized single frames reserved their real bound. Candidate `469080f6…`, before `0eea3291…`, baseline commit `ad97260`.
- **Expected:** first block arrives earlier, restoring C's produce/consume overlap; smaller resident batch buffer. 128-object p50 was the known counter-example (pilot: candidate p50 **+1.36 %** vs C, **−0.46 %** vs r89).
- **Measured (paired medians):** 128-object p50 vs C **−3.10 %**, vs r89 **−5.28 %**, vs before **−4.82 %**; but subject CPU vs before **+5.32 %** and p99 vs before **+0.14 %**. Full 10-lane matrix: `lookup_all_128` CPU vs C **−64.61 %**, vs r89 **−60.54 %**, but vs before **+8.42 %**; `lookup_prefix_64` mean **+1.20 %/+4.47 %/+4.48 %** (C/r89/before), p95 **−0.25 %/+9.06 %/+8.79 %**, CPU **−67.77 %/+4.35 %/+14.29 %**; `lookup_prefix_64_c4` mean **−41.51 %/+5.00 %/+3.86 %**; `lookup_all_128_c4` mean **−41.19 %/−37.25 %/+3.36 %**. Other losses: lookup p99 vs r89 **+2.97 %**; invoke mean/p95/p99 vs r89 **+0.15 %/+1.58 %/+3.28 %**; invoke_c4 p50 vs r89 **+2.54 %**; prefix_64 p50/p99 vs r89 **+2.82 %/+5.98 %**. lookup and lookup_c4 CPU vs r89 medians exactly 0 → not counted as a win.
- **Memory:** independent 128-object run showed candidate VmRSS/RssAnon **−12 KiB** each vs before, but the full matrix showed VmRSS C 956 / R89 618 / before 626 / candidate 624 KiB and RssAnon 144 / 162 / 170 / 168 KiB — gap shrank to 2 KiB and anon stayed above both baselines.
- **Stated rejection reason:** a single p50 improvement did not offset new non-winning items in the full matrix, and memory did not prove an all-lane win; "4 KiB 分批发送没有进入运行时代码". Also flagged as a confound: the experiment used a different Cargo build root, so not all difference is attributable to the algorithm (after restoring the original algorithm and rebuilding in the original fixed path, the bytes matched `0eea3291…` exactly).
- **Retained:** two new backpressure regression tests inside `cfg(test)`; experimental patch + all records kept.

### 3.2 R95 — persistent full-reply cache for lookups — **not adopted (design decision, no experiment)**
- **Change considered:** cache whole lookup replies.
- **Stated reason:** would add resident storage and require ACL / register-delete / reload invalidation. Replaced by the borrowed-range traversal below. Send-block-size tuning was also stopped after 3.1's unfavorable result.

### 3.3 R97 — method storage layout (`r97-method-storage.patch`) — **DEFERRED / NOT MERGED**
- **Change:** borrow the validated input name for ACL instead of copying; read ACL names from the single method blob; convert the method blob and the completed method list to `Box<[T]>`, dropping reserved capacity and duplicate name allocation. Candidate `bdade5c6ac95498105ac81a604d8ce8ed4f6ac0887f274758d26f2a3bb1f66b6`, before/baseline `527f8683…`, runtime base `5a19517`.
- **Expected:** request-heap reduction and lower bulk-query CPU; explicitly *not* assumed faster registration, because tightening capacity may trigger realloc — hence the extra frozen registration experiment.
- **Measured — request heap (bytes, ABBA windows, identical values twice per side):** resident `-7.73 %` (1 obj/1 method/8 B names, 2 796→2 580), `-16.67 %` (1/16, 4 032→3 360), `-30.68 %` (1/64, 8 448→5 856), `-33.40 %` (128/1/8 B, 76 644→51 044), `-34.63 %` (128/1/32 B, 82 788→54 116), `-39.96 %` (128/16/32 B, 333 156→200 036), `-38.15 %` (128/1/128 B, 107 364→66 404). Construction peak fell in every scenario.
- **Measured — proc diagnostics (KiB medians at end of the 10-lane matrix):** C 972/144, R89 616/160, baseline 628/172, candidate 590/134 (VmRSS/RssAnon). Candidate 36/40/36/40 KiB lower than baseline in the four blocks.
- **Measured — lookup/invoke (paired median change vs baseline, 16 windows, 800 000 timed requests):** improved on CPU in 7 of 10 lanes (`lookup_all_64` −7.21 %, `lookup_all_128` −10.14 %, `prefix_64` −8.11 %, `lookup_all_64_c4` −9.74 %, `lookup_all_128_c4` −9.02 %), but adverse cells remained: `lookup` p99 **+1.62 %**, `lookup_all_64` p95/p99 **+0.66 %/+3.57 %**, `invoke` p50/CPU **+0.41 %/+0.92 %**, `lookup_c4` p95/p99 **+0.52 %/+14.43 %**, `lookup_all_64_c4` p95/p99 **+1.31 %/+1.61 %**, `lookup_prefix_64_c4` p99 **+1.21 %**, `lookup_all_128_c4` p95/p99 **+0.01 %/+0.20 %**. vs C: invoke p99 **+0.59 %**. vs R89: prefix_64 p99 **+0.19 %**, prefix_64_c4 p99 **+2.12 %**. Concurrent exact-lookup p99 first four paired changes **+22.89 %, −11.18 %, +16.64 %, +12.22 %**.
- **Measured — registration (`r97-registration-plan.json`, 16 windows, 128 000 timed cycles / 256 000 timed protocol requests), change vs baseline:** `1 method/8 B` mean **+1.59 %**, p50 **+0.77 %**, p95 **+2.59 %**, p99 **+5.00 %**, subject CPU **+1.56 %**, client CPU **+0.27 %**; `16/8` mean −2.05 % but p95/p99 **+0.52 %/+3.56 %**; `64/8` mean −10.47 %, CPU −17.08 %; `1/128` mean −0.23 %, p99 **+0.99 %**. Single-method CPU across four pairs: **+1.93 %, −1.34 %, +1.20 %, +2.04 %**. vs C: `1/8` mean **+8.57 %**, p99 **+15.56 %**, CPU **+22.00 %**; `16/8` **+7.25 %/+12.67 %/+21.49 %**; `1/128` **+5.40 %/+8.40 %/+19.20 %**; only `64/8` won (**−12.10 %/−4.63 %/−18.33 %**). vs R89: `1/8` p99 **+0.80 %**.
- **Independent 8-block recheck (`r97-registration-recheck-plan.json`, 320 000 cycles / 640 000 timed requests):** `register_1_8` mean **+1.58 %**, p50 **+0.84 %**, p95 **+2.46 %**, p99 **+3.97 %**, subject own CPU **+1.62 %** (six of eight p99 pairs positive, per-pair range **−1.02 % to +41.23 %**); `register_16_8` mean −3.47 %, p99 −5.78 %, CPU −8.06 %. Lookup recheck: `lookup` mean **+0.70 %**, p95/p99 **+3.57 %/+2.75 %**, own CPU **+0.06 %**, client CPU **+0.52 %**; `lookup_c4` p95 **+4.38 %**; `lookup_all_64` p95 **+1.20 %**; `invoke` p50 **+0.23 %**, CPU **+0.79 %**. Concurrent exact-lookup p99 did not stably reproduce; per-pair range **−9.64 % to +29.25 %**.
- **Stated rejection reason:** **"单方法注册主体 CPU 八轮全部上升，中位数 +1.62%，触发采样前冻结的暂缓合入门槛。"** The gate (`r97-retention-gates.json`) is `register_1_8` / `subject_own_cpu_clock_us_per_op` / `positive_pairs 8` / `median_delta_pct 1.623787361832918` / threshold 1 % → `defer: true`. Explicitly a conservative research decision, *not* a formal significance test. Runtime reverted to the verified `5a19517` compatibility fix; patch + diagnostics patch + all positive/negative data retained; no evidence for a Rust/C language limit.

## 4. Accepted (retained) changes in the same period

| Round | Change | Key measured outcome | Caveats kept in the record |
|---|---|---|---|
| R95 | Borrowed `BTreeMap::range` traversal instead of collecting the remaining range into `Vec<u32>` per lookup/resume (`r95-ubusd-range.patch`, candidate `46940829…`, before `0eea3291…`) | Allocations per 128-object query 2/5/1 012 B → **1/0/4 B** (full list) and 3/5/1 044 → **1/0/24** (prefix). Backpressure reallocs 20/196/1 284 → **0**; elapsed −12.88 % (16 obj), −10.90 % (64), −11.65 % (256), prefix −10.92 %/−7.20 %/−26.29 %; 256-object cumulative requested bytes **4 565 376 → 4 219 904 (−345 472 B ≈ 337 KiB)**. 6/10 lanes favorable on mean+p50+p95+p99+CPU | vs C: 128-obj serial p50 **+0.55 %**, invoke p95/p99 **+3.51 %/+3.99 %**. vs R89: exact lookup p99 **+11.88 %**, invoke p95 **+0.49 %**. Matrix `lookup_c4` mean/CPU **+9.84 %/+12.50 %**, `invoke_c4` mean **+3.25 %**. Client CPU: invoke vs before **+8.33 %**, invoke_c4 vs C/R89 **+7.14 %/+8.33 %**. Memory: candidate 626/170 vs before 628/172 KiB — 2 KiB lower but anon still above C (144) and R89 (160). Recheck did not reproduce the initial concurrency regression (lookup_c4 mean −1.41 %, p99 −4.01 %), but per-run lookup_c4 mean ranged **−14.95 % to +7.64 %** and p50 **−22.58 % to +27.83 %**. Not an acceptance. |
| R96 | `Rc<[u8]>` shared immutable object paths between object table and ordered index (`474188e`, candidate `ece562af…`, before `46940829…`) | 128-object resident request heap −10.2 %/−19.9 %/−34.8 % for 16/64/256 B paths; all 12 combinations lower; backpressure resume still copies to its own `Vec<u8>` | Full-matrix **VmRSS/RssAnon medians: C 968/144, R89 616/160, before 626/170, candidate 628/172** — three paired windows equal, one 4 KiB higher each → median **+2 KiB**; not a memory win. Adverse latency/CPU: `lookup_all_64` p99 **+1.23 %**, `invoke` p95/p99 **+2.14 %/+2.20 %**, `lookup_c4` mean/p50/CPU **+0.05 %/+3.06 %/+1.62 %**, `lookup_all_64_c4` mean/p95/p99/CPU **+0.66 %/+0.30 %/+2.65 %/+1.01 %**, `prefix_64` p50 **+1.12 %**. Concurrent exact-lookup CPU +3.97 %/−0.33 %/+3.57 %/−3.25 %; concurrent 64-list +4.37 %/+2.04 %/−0.03 %/−2.47 %. vs R89 prefix_64 p99 **+2.17 %**; lookup client CPU vs R89 **+3.36 %**. |
| R96 | New own-process CPU clocks (`clock_getcpuclockid`/`clock_gettime`, `975ab2f`, `fed6ade`) — measurement only | Router-validated; distinguishes sleeping vs busy, rejects out-of-range PIDs, reads ended worker threads. Example: invoke old tick value was **0** while the new clock read **≈39.4 µs/op**, so zero ticks ≠ zero cost | New client `975ab2f` differs from the old frozen client `ca1a912` (its shared ubus lib already contains `f1e1f19` read-ahead), so cross-round changes cannot be attributed to measurement or daemon algorithm. R95/R96/R97 samples are never pooled. |
| R97 | Method-name / ACL C-string boundary compatibility fix (`5a19517`) — defect fix, prerequisite for further perf work | 14 router observations (7 objects × root/nobody) byte-identical to C; old Rust reproduced the wrong hiding and non-canonical outer fields; 29 unit tests on both build host and router; six build-host gates | This is the current accepted runtime; it claims no performance gain. |

## 5. R98 — deferred ("lazy") event encoding — **IN FLIGHT, no verdict**

- **Change (working tree only):** `Server::dispatch_event` takes `build: impl FnOnce() -> Vec<u8>`; `send_obj_event`, the user-event path and the ACL-sequence path pass closures, so an object/user/ACL event is encoded **only after an eligible receiver is found** — matching C's `ubusd_send_event` fill-callback timing. Previously Rust encoded and copied the message before matching, even with zero receivers. Runtime base `74e268e` plus the patch; candidate `1fc485de5261b3090c7bcabe265950fc4071ccf4b8d941cc89f0a232be4a2db1`.
- **Status:** patch applied but **uncommitted** (`git status`: ` M components/ubusd/src/server.rs`, 102 insertions / 25 deletions). `docs/reviews/r98-event-matrix-results.json` is **untracked**. No R98 review document exists; the results file carries **`superiority_verdict: null`** and `method: "Paired exploratory blocks; full per-run values; no confidence or equivalence claim"`.
- **Executed:** the 4-block × 10-lane matrix (16 windows, 160 runs, `iterations 5000`, `warmup 20`, `all_windows_cleaned_and_production_stock: true`). Registration (4 lanes × 4 arms × 4 blocks) and the memory diagnostic also ran on device under ignored `private/r98/event-lazy/` (`COMPLETE`, `performance-exit 0`). The frozen fanout plan (`watch_1_1`/`watch_8_1`/`watch_1_0`, 4 blocks) has **not** been run — no fanout window directory exists.
- **Committed matrix result (paired medians, candidate vs C / vs r89 / vs before):** favourable nearly everywhere. Own-process CPU vs C: `lookup_all_64` −73.15 %, `lookup_prefix_64` −72.61 %, `lookup_all_128_c4` −73.95 %, `lookup_all_64_c4` −72.07 %, `lookup_prefix_64_c4` −72.76 %, `invoke` −29.57 %, `lookup` −25.84 %. Throughput vs C: `lookup_all_128_c4` +77.36 %, `lookup_prefix_64_c4` +72.45 %, `lookup_all_64_c4` +65.06 %. **Adverse cells vs C: `lookup_c4` p50 +2.63 %, `invoke_c4` dependency CPU +4.55 %, `invoke_c4` client CPU-clock +1.66 %. vs r89: `lookup` client CPU +3.12 %, `lookup` client CPU-clock +0.23 %, `lookup_c4` p50 +5.99 %.** Candidate vs before is ≈0 %/−1 % on 8 of 10 lanes; `lookup_c4` p50 is +13.67 % vs before while only +2.63 % vs C — large block scatter.
- **Not yet in any committed report — derived by me from `private/r98/event-lazy/` raw device data** (methodology validated: recomputing `subject_own_cpu_clock_us_per_op` from `daemon_cpu[].after.process_cpu_ns − before.process_cpu_ns` reproduces the committed pipeline's value exactly, 17.4399512 for matrix/01-candidate/lookup):
  - Registration own CPU per add/remove cycle (µs, median of 4 independent blocks; candidate / before / C / r89): `register_1_8` **52.99 / 62.55 / 51.35 / 70.33**; `register_16_8` **66.61 / 78.78 / 59.34 / 91.49**; `register_64_8` **113.12 / 123.90 / 126.66 / 148.36**; `register_1_128` **53.68 / 63.50 / 51.61 / 74.05**.
  - Paired medians, candidate vs before: **−14.38 % / −16.16 % / −7.92 % / −15.30 %** (all four blocks negative in every lane). vs r89: **−24.58 % / −28.06 % / −24.03 % / −27.44 %**. vs C: **+3.21 % / +12.14 % / −11.40 % / +4.11 %** — i.e. small-signature (1 and 16 methods) and long-name single-method registration are **still slower than C**, exactly the gap R97 discovered.
  - Latency-only paired medians (candidate vs before): `register_1_8` mean −5.09 %, p50 −4.42 %, p95 −6.31 %, p99 −5.60 %, ops/s +5.07 %; `register_16_8` mean −8.08 %, p99 −15.06 %; `register_64_8` mean −4.01 %, p95 **+0.64 %**, p99 −0.74 %; `register_1_128` mean −5.60 %, p95 −14.06 %, p99 −3.81 %. vs C: `register_16_8` mean **+8.08 %**, p95 **+20.14 %**, p99 **+7.07 %**; `register_1_8` p95 **+2.84 %**, p99 **+1.51 %**; `register_1_128` p99 **+3.93 %**.
  - Memory diagnostic (`memory-1-before` vs `memory-2-candidate`, requested Rust heap, 1 iteration, ABBA): **retained requested bytes identical in all 7 scenarios**; construction peak lower by **72 B** for the single-object 1/16/64-method/8 B cases, and by **152 B** for 128 obj × 16 methods × 32 B names and 128 obj × 1 method × 128 B names; the three 128-object 8/32 B small cases are equal.
  - Interpretation caveat: the registration lanes have **no watchers**, so zero eligible receivers → the deferred encoding skips this work entirely; the gain is consistent with the hypothesis rather than evidence about the watched path. The fanout lanes (`watch_*`), which are exactly the test for cost transfer to active receivers, have not been run.

## 6. Remaining queue and what has since been executed

`UBUSD_GOAL_RESEARCH.md` queue (state as of the latest commit `f7249c7`):

1. **Event generation — match C's fill-callback timing.** → *Executed as R98 (lazy encoding) but uncommitted and unverdicted; the watched/fanout half (`watch_*`) is still unrun.*
2. **Registration reply — C reuses a static blob, Rust ADD/REMOVE DATA still builds a new `BlobBuf` then copies.** → *Not started; still open.*
3. **Method storage — validate and count signatures first, then allocate the final list once, avoiding grow-then-tighten realloc; include empty signatures, bad attributes, embedded NUL, shared types and failure release.** → *Not started (R97's version was deferred; this is the proposed successor).*
4. **Event delivery itself — matched-target snapshot, per-receiver copy, queue ownership.** → *Not started; profile first.*
5. **Receive path — per-client 4 KiB read-ahead buffer introduced in R94 (`647963e`, "ubusd: read-ahead per client, whole-bus lookup as one write"); quantify small/large/batched frames, connection scale, partial reads, SCM_RIGHTS.** → *Still open. R97 explicitly did not touch the receive state machine; the concern is resident memory at connection scale.*
6. **Re-profile remaining hotspots; add original libubus callers, real call chains, scaling, exact memory/peak, sufficient independent samples; nine-component combination verified separately.** → *Open. Every R95–R98 report lists the nine-component combination as unverified.*

Also still open, stated repeatedly: exact resident/peak memory (no `/proc/1/smaps` or `smaps_rollup` on kernel 6.12.94, so no measured PSS; cgroup v2 memory controller exists but root `subtree_control` is empty and the measurement is not yet enabled); the original frozen client `ca1a912` / original libubus callers comparison; formal pre-registered confirmation experiments as opposed to exploratory 4-block pilots.

## 7. Explicit non-conclusions

The documents state that no result so far justifies attributing the remaining gap to a Rust/C language limit; that `getrandom(..., GRND_INSECURE)` is used by both the exact C and Rust ID paths, so the registration gap is not attributable to the random interface without a profile; and that the goal remains open, with production running C throughout and no candidate ever installed.
