# Singleton name-index screen: candidate rejected

The private `shared_one_index` candidate fails the unchanged population CPU
guard in all three occupied profiles and is rejected. All **24 scheduled
runs / 12,000 snapshot-lookups** completed with zero errors. Snapshot CPU,
snapshot heap, parent heap and capacity-150 p95 requirements pass, but those
results do not waive population cost. No representation is adopted into the
product, and all prior screen decisions remain unchanged.

Root executed the frozen schedule on CPU 2 from 17:47:55.068185 to
17:48:02.272306 UTC on 2026-10-01 in the coordinated quiet window. Source
`e77d966`, native aarch64 Rust 1.98.1, binaries, four profiles, three pair
orders, five warm groups and 25 measured groups of 20 snapshots follow the
[frozen plan](TCP_SNAPSHOT_ONE_INDEX_V1.md). No run or sample was retried,
added, discarded, selected or normalized after inspecting results.

## Frozen decisions

| Guard | Observed result | Decision |
| --- | --- | --- |
| Exact C and retained state | 22,571 operations per representation; adapter/drop checks pass | Pass |
| Actual layout and balanced drops | NameSlots 24 B; all allocation drops balance | Pass |
| Address-profile population allocations | No more allocations or reallocations than deep | Pass |
| Steady requested heap, no more than +5% | Full profiles decrease 7.01% / 6.69% / 7.09% | Pass |
| Snapshot live heap, at least -20% at 1,000 / 10,000 | -51.59% / -54.88% | Pass |
| Combined snapshot/lookup CPU, at least -20% above ratio spread | -66.60% / -54.60%; spread 1.10 / 0.79 percentage points | Pass |
| Worst-pair combined p95 at capacity 150, no more than +5% | Empty/full worst ratios 0.346154 / 0.356334 | Pass |
| Worst-pair population CPU, no more than +5% | Full 150 / 1,000 / 10,000 exceed the limit | **Fail** |

The three failing population pairs are retained explicitly:

| Occupied capacity | Round | Deep population µs | Candidate population µs | Ratio | Regression |
| --- | ---: | ---: | ---: | ---: | ---: |
| 150 | 3 | 74.200 | 111.600 | 1.504043127 | +50.40% |
| 1,000 | 1 | 530.000 | 558.600 | 1.053962264 | +5.40% |
| 10,000 | 3 | 5,716.480 | 6,008.000 | 1.050995342 | +5.10% |

The full-profile population ratios over the three rounds are respectively
`[1.037572254, 1.042281219, 1.504043127]`,
`[1.053962264, 0.974505616, 0.947925369]`, and
`[1.026858464, 0.994958896, 1.050995342]`. Better medians or individual pairs
cannot replace the frozen worst-pair decision. The small margin in the last
profile is still above the exact 5% limit. The screen establishes rejection,
not a stable magnitude or measured cause for every population fluctuation.

The source hypothesis about allocation was confirmed: the singleton name
index removes the expected allocation, leaves ordinary lookup allocations
unchanged and reduces snapshot cloning allocations substantially. Matching
allocation counts did not establish acceptable population CPU. RDATA remains
Vec-backed; the inline16 mechanism was not combined or retuned for this run.

## Absolute measured costs

Values are medians of the three individual run values, not pooled samples.
Combined CPU includes creation, first lookup and the driver's unchanged
validation/bookkeeping. Combined wall samples pair each clone with its first
lookup and exclude waiting between these phases. Active throughput uses their
summed wall duration rather than daemon wall throughput.

| Capacity / occupied | Representation | CPU µs / completion | p50 µs | p95 µs | Active completions/s | Population µs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 150 / 0 | deep | 1.080 | 0.960 | 1.080 | 1,037,682 | 7.880 |
| 150 / 0 | shared_one_index | 0.432 | 0.320 | 0.360 | 3,128,872 | 4.120 |
| 150 / 150 | deep | 20.557 | 15.200 | 46.361 | 49,040 | 81.360 |
| 150 / 150 | shared_one_index | 6.579 | 5.040 | 12.080 | 156,544 | 86.160 |
| 1,000 / 1,000 | deep | 111.258 | 103.521 | 140.202 | 9,010 | 574.560 |
| 1,000 / 1,000 | shared_one_index | 37.161 | 35.240 | 51.800 | 27,082 | 558.600 |
| 10,000 / 10,000 | deep | 1,471.759 | 1,457.132 | 1,577.373 | 680 | 5,813.080 |
| 10,000 / 10,000 | shared_one_index | 668.220 | 654.806 | 707.126 | 1,498 | 6,007.920 |

[The JSON report](TCP_SNAPSHOT_ONE_INDEX_RESULT.json) retains all 24
run-level population/clone/lookup/snapshot-group-drop CPU totals, percentiles,
active throughput, completion/error counts, pair ratios and decisions.
Parent drop has allocation balance accounting but no separate CPU timer.
No p99 is reported. Requested live/peak heap and allocation calls remain in
the separate [allocation report](TCP_SNAPSHOT_ONE_INDEX_ALLOCATION.md);
zero allocation fields in timing binaries are not memory measurements.

## Independent audit and evidence

The post-run audit compares every reported timing row against the raw stdout,
checks all 24 CPU-2 commands and their serialized start/finish windows against
the frozen order, and verifies both timing ELF hashes. Every run has exactly
500 clone and 500 lookup samples. Nearest-rank p50/p95 and all combined sums
are independently recomputed. Exact rational ratios reproduce every guard
decision without rounding a failure into a pass. No sample is removed.

Tool SHA-256 is
`3a947480e7fd61e3006547c2718b5ae5a2c2055ecdb6c6ef3de6a5a23611644d`.
Timing ELF SHA-256 values are
`1485673c4e4717c92b3a5dbd9b42cc1425fbad3f9b2a26d6d4b096a2660c7b56`
for deep and
`5c54c2557a321668c978064ea69612ec94f29036d9ef13fa89b30009934f6c2d`
for the candidate. The JSON records the quiet window, each invocation window
and hashes for raw commands/stdout/stderr and the primary artifacts.
The resumed archive check verifies every one of the remote output's 361 files
against the local copies. All 288 pre-timing archived files are unchanged;
77 additional timing/result files bring the local archive to 365 files,
including the four preparation-phase logs. The JSON records the final archive
checksum manifest. All eight allocation rows also match their raw stdout,
and every allocation and correctness invocation precedes the timing window.

Complete evidence is retained under ignored
`private/dnsmasq-rewrite/resume-single-index-20261001/private/one-index-evidence/one-index-01/`.
The sibling `one-index-preparation/` holds the source/tool archives, audit
script and checksum manifest. The remote root is
`/home/ubuntu/dnsmasq-tcp-one-index-20261001/work01`. No build, correctness,
allocation or runtime error occurred; the retained failure is the frozen
population performance requirement.

There is no follow-up timing round or immediate new screening candidate.
Any later mechanism first needs separate source/cost reasoning and its own
frozen plan. This result makes no mixed-RR, C fork/COW,
full service/resource, RSS/PSS, production representation or router claim.
