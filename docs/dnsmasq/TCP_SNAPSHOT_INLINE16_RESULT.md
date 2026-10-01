# Shared-entry inline RDATA screen: candidate rejected

The new `shared_inline16` candidate fails the unchanged capacity-150 p95
guard and is rejected. All **24 scheduled runs / 12,000 snapshot-lookups**
completed correctly with zero errors. No run was added, repeated, discarded
or selected after inspecting the measurements. No representation is adopted
into the product, and the prior V1/chunk32 decisions remain unchanged.

The root-coordinated quiet window used CPU 2 from 17:09:59.113404 to
17:10:07.496543 UTC on 2026-10-01. Source `e77d966`, pinned native aarch64
Rust 1.98.1, binaries, four profiles, three pair orders, five warm groups,
25 measured groups and 20 simultaneous snapshots per group follow the
[frozen plan](TCP_SNAPSHOT_INLINE16_V1.md).

## Decision against the frozen guards

| Guard | Observed result | Decision |
| --- | --- | --- |
| Exact C and retained-image correctness | 22,571 operations per representation; storage/drop checks pass | Pass |
| Actual layout and balanced drops | RDATA 24 B, Entry 120 B; all allocation drops balance | Pass |
| Population allocation mechanism | Address profiles allocate no more than deep | Pass |
| Steady requested heap, at most +5% | Full profiles increase 0.304% / 0.279% / 0.295% | Pass |
| Snapshot live heap, at least -20% at 1,000 / 10,000 | -49.20% / -52.34% | Pass |
| Combined snapshot/lookup CPU, at least -20% above pair spread | -47.39% / -27.85%; ratio spreads 0.70 / 1.23 percentage points | Pass |
| Worst-pair population CPU, at most +5% | Largest regression +4.40%, at 10,000 full | Pass |
| Worst-pair combined p95 at capacity 150, at most +5% | First full-profile pair increases 8.63% | **Fail** |

The failing pair is concrete: deep's combined p95 was **34.761 µs** and
the candidate's was **37.760 µs**, ratio **1.086274848**. The later two
full-capacity-150 pair ratios are 0.607523400 and 0.754722471. Their better
results and a better three-run median do not waive the frozen worst-pair
guard. The screen establishes this rejection; it does not establish a stable
size or cause for that tail regression, and no parameter is changed to fit
this window.

The allocation hypothesis was confirmed for this address workload: inline
RDATA removes the extra payload allocation, and the population CPU guard
passes this time. These facts remain useful evidence while the complete
candidate still fails its acceptance criteria. Empty and long RDATA retain
their previously documented Arc-allocation costs; arbitrary mixed-RR costs
remain outside this screen.

## Absolute costs

Values are medians of the three run-level values, not pooled samples. CPU
includes snapshot creation, its first lookup and the driver's fixed lookup
validation/bookkeeping. Combined wall samples pair each clone with its first
lookup; waiting between those phases is excluded. Active throughput is
completions divided by their summed combined wall duration.

| Capacity / occupied | Representation | CPU µs / completion | p50 µs | p95 µs | Active completions/s | Population µs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 150 / 0 | deep | 1.117 | 0.960 | 1.080 | 1,002,076 | 8.320 |
| 150 / 0 | shared_inline16 | 0.462 | 0.320 | 0.400 | 2,907,636 | 3.560 |
| 150 / 150 | deep | 20.581 | 15.160 | 44.680 | 49,042 | 81.480 |
| 150 / 150 | shared_inline16 | 10.742 | 8.160 | 33.721 | 94,532 | 79.280 |
| 1,000 / 1,000 | deep | 112.203 | 104.521 | 142.601 | 8,939 | 563.840 |
| 1,000 / 1,000 | shared_inline16 | 59.052 | 56.160 | 82.321 | 17,022 | 559.880 |
| 10,000 / 10,000 | deep | 1,470.667 | 1,458.333 | 1,541.533 | 680 | 5,978.080 |
| 10,000 / 10,000 | shared_inline16 | 1,066.186 | 996.089 | 1,603.453 | 938 | 5,867.000 |

All 24 run-level population, clone, lookup and snapshot-group drop CPU totals,
wall percentiles, throughput and completion/error counts are retained in
[the JSON report](TCP_SNAPSHOT_INLINE16_RESULT.json). Parent destruction has
allocation balance accounting but no separate CPU timer. No p99 is reported.
All live/peak requested heap and allocation counts remain in the separate
[allocation report](TCP_SNAPSHOT_INLINE16_ALLOCATION.md); zeros in the
uninstrumented timing allocation fields are not memory measurements.

## Independent audit and evidence

The post-run audit independently verifies every timing row against its raw
stdout, all 24 commands and their serialized start/finish windows, CPU-2
affinity requests, frozen order, ELF hashes, 500 clone plus 500 lookup samples
per run, nearest-rank p50/p95, and every combined sample sum. It recomputes
the guard decisions from raw totals using exact rational ratios. No sample
is removed or normalized. Root performed an independent audit with the same
result.

Tool SHA-256 is
`3f2ae4a2c96bd54553fb0bc89b26e3ce8a30360231a87eb32eaca87a08c4d945`.
Timing ELF SHA-256 values are
`faf243a6beabdb7e709523c35c2956db93f29b5da81693e6eee07c8812ed4727`
for deep and
`155c64f95f3db73906f2ae9ea3a72479ca951bc06002593cf9e46d9ad7704bd1`
for the candidate. The JSON includes the quiet window, all per-run invocation
windows and hashes for raw commands/stdout/stderr plus primary artifacts.

Complete evidence is under ignored
`private/dnsmasq-rewrite/resume-inline-rdata-20261001/private/inline16-evidence/inline16-02/`.
The sibling `inline16-preparation/` retains source/tool archives, the audit
script and evidence checksums. The remote root is
`/home/ubuntu/dnsmasq-tcp-inline16-20261001/work01`. The prepare-only first
directory and every subsequent artifact remain retained. No new timing
window or candidate adjustment is authorized by this result. This is a
private Rust primitive screen, with no C fork/COW speedup, full service,
RSS/PSS, production representation or router acceptance claim.
