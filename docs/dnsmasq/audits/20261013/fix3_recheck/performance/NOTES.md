# Final type-summary follow-up: performance audit

## Conclusion

N4 is not closed. The new type summary avoids the old scan only when the query's RR type is absent from the configured raw records. Legal records with the **same A type and unrelated owner names** still induce an obvious newly introduced TCP cache-hit cost relative to main. This is the cost introduced by the original repair branch relative to main and left unresolved by the follow-up fixes, not a regression newly introduced by `f4722030`. It remains a confirmed P2 regression under the user's merge criterion; no product code was changed to obtain this result.

## Retained six-pair evidence, independently checked

`statistics-check.json` recomputes the retained type-summary candidate's statistics locally from each window's integer cgroup CPU delta and 120,000 correct completions. All 21 consistency checks pass:

| Unrelated type-65401 records / cached A | Geometric fix/main CPU ratio | Paired log-t 95% interval, df=5 | Mean paired absolute increment |
|---|---:|---|---:|
| 100 | 1.140335563 | [1.032326921, 1.259644761] | +4.414596 μs |
| 1000 | 1.128550364 | [1.033532349, 1.232303880] | +4.235779 μs |

Both lower bounds exceed 1; neither exceeds 1.10. The data support increased cost in these tested workloads, not a proved increase of at least 10%, equivalence, or an upper bound below 10%. Each primary scenario has three AB and three BA pairs; all twelve main/fix pairs increase. All 32 windows and their prescribed order are retained. The two-pair controls are descriptive. Small sample size, deterministic order and virtualization-neighbor activity remain limitations; the order-group values are preserved.

The frozen plan, source witness and build identity have identical 177-input tables; all 177 inputs match current `74c6b453` Git blobs and the local worktree. The retained measured ELF is SHA256 `0410d96c9c42e0fc3616d499547fe4ba7d7657b236d8d55daa0664a483b8b743`: these are earlier measurements of identical product/recipe bytes, not measurements of the new build below. Root separately rehashed the indexed Oracle raw evidence; the statistical subtask itself used only local retained per-window data and did not pretend to read remote originals or rerun the 32 windows.

## New same-type experiment

Fresh source: `74c6b4531111819439e38881ff9be7dc025d57ca`. Fresh release ELF: `25b7291d0074b8c7a854aa9f63f7b5edb12bc1315e60dd26f8f6eed36d362fd8`. Main remains `be531cee49e366bb5044443d473944dbea45b87e`, measured ELF `ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863`. Source and artifact identity are frozen in `same-type-plan.json`; main's previously fresh release was rehashed, not rebuilt. Build-path changes produced a different new ELF despite identical product inputs, so the new and retained ELF identities are not conflated.

Configuration adds only:

```text
dns-rr=unused0.audit.test,1,c0000201
...
dns-rr=unused999.audit.test,1,c0000201
```

`c0000201` is the four-byte A address 192.0.2.1. Exact-image C, main and final all pass `--test` and directly answer the middle configured name over UDP and TCP. All three also pass a separate low-load cached-A smoke. This establishes that the declarations are accepted and live, rather than an ignored or invalid option (`same-type-smoke.json`).

Eighteen fresh windows comprise TCP +100 records, TCP +1000 records and UDP +1000 records, each with three adjacent AB/BA/AB main/final pairs. Per window: 20 clients, 1000 QPS, three seconds warmup, fifteen seconds measurement. Daemon/upstream/native load/controller use CPU 0/1/2/3. The native TCP generator reconnects after every 100 requests, so CPU includes normal connection work and is not a lookup-only microbenchmark. The new direct raw A UDP/TCP proofs occur before cache fill and the timed epoch.

A separate 4096-name dynamic A bank is filled and proved in full, then upstream **responses** are disabled; the process remains alive and records attempts. Every window also proves the configured raw A through both transports before load. The tested cache-hit names are entirely unrelated to `unused*.audit.test`.

| Profile | main / final CPU μs per correct reply, medians | Increase | main / final p95 μs, medians |
|---|---:|---:|---:|
| TCP, 100 raw A records | 31.330 / 44.299 | **+41.39%** | 78.280 / 98.200 |
| TCP, 1000 raw A records | 31.720 / 118.558 | **+273.77% (3.738×)** | **78.401 / 228.042 (+190.87%)** |
| UDP, 1000 raw A records, control | 107.073 / 101.302 | −5.39% | 212.721 / 202.802 |

Both TCP profiles have all three pairs worse; CPU relative ranges are main/final 5.81% / 4.45% for 100 records and 5.20% / 8.79% for 1000. The effects are far larger than observed within-side variation. There is no inferential interval claim for these three-pair screens, and the predeclared 10% screening heuristic is not a user-approved tolerance. No short screen was discarded or rerun. The UDP control continues to pay main's pre-existing local scan; its result does not show a newly added comparable UDP cost. No cross-transport or cross-rate subtraction is used as causal attribution.

Sampled peak PSS medians increase about 1.16–1.28% and FD peaks are unchanged (TCP 32, UDP 12). This experiment establishes CPU/latency regression, not a memory leak or reduced saturation connection capacity. It does not measure router throughput, Cortex-A53 performance, maximum capacity, or long-run leaks.

## Mechanism and attribution

`config/records.rs:172` tests only whether the requested type occurs anywhere. `dns/local.rs:927` supplies the entire raw list when the type exists; `add_raw` at line 1292 still canonicalizes and compares the owner of every record having that type. `dns/daemon.rs:1817` keeps local resolution before cache lookup for TCP. Main returns its TCP cache hit before this scan. Thus the general absent-type optimization is real, but a matching type with unrelated names still reaches the O(N) name scan on each TCP hit. Source mechanism and the new paired scaling data agree; no source-function CPU profiler or per-commit attribution is claimed. This extends the original N4 finding rather than inventing a separate unrelated issue.

The fix should preserve correct local-record precedence while avoiding per-request work for irrelevant owner names. The prior type-65401 A-query profile cannot establish that all accepted raw-RR configurations no longer regress.

## Integrity and timing

`verify_same_type.py` passed all explicit assertions (`same-type-counter-check.json`):

- 18 completed windows, all exit 0 and valid measurement methodology; no replacement or deletion.
- 324,000 total warmup + measurement scheduled = sent = correct requests; skip, wrong, timeout and transport errors all zero.
- 180 cgroup observations have `nr_throttled = throttled_usec = 0`.
- All paired configs hash identically; executed ELF SHA matches the plan; direct raw A proofs pass over UDP/TCP in every window.
- All 4096 cached names prove correctly, upstream replies are disabled, attempted hit-phase upstream requests are zero.
- Initial and each per-window competing-task scan are empty. Build and DNS agents explicitly finished before launch. Root's retained-evidence receipt was written about 70.3 seconds before the first window, excluding the suspected overlap (`coordination.json`). These controls cannot exclude VM-neighbor noise.
- Raw config, direct proof, cache proof, upstream, executed identity, original result and per-window preflight hashes are retained in the counter check and summary; all full commands are retained in the plan.

No old 32-window performance suite was rerun. Oracle source snapshots, firmware files and binary artifacts remain outside Git; this directory contains only audit scripts and derived evidence.
