# Chunk32 snapshot screen — rejected under frozen cost guards

The chunk32 candidate reduces snapshot CPU and requested heap, but fails the
unchanged population CPU and capacity-150 p95 guards. It is rejected. Product
cache storage is unchanged, and the earlier representation screen's results
are unchanged.

All 24 frozen timing runs completed: **12,000/12,000 successful snapshot and
lookup operations, zero errors**. Root coordinated CPU 2 on the pinned build
host from 14:33:52 to 14:34:00 UTC on 2026-10-01. The declared three round
orders, five warm groups and 25 measured groups of 20 snapshots were retained.
No additional round, retry, outlier exclusion or alternate chunk size was used.

The source is `e77d966d0bf92e5296f73ee3e54fdaf960ed7781`, with native Linux
aarch64 Rust 1.98.1, release optimization, LTO and one codegen unit. These are
independent new deep/chunk32 measurements. Earlier V1 timing was not rerun or
combined with them. Exact-C correctness and allocation evidence are in
[`TCP_SNAPSHOT_CHUNK_ALLOCATION.md`](TCP_SNAPSHOT_CHUNK_ALLOCATION.md): both
representations pass 22,571 operations and retained-state checks; the negative
control detects one TTL mismatch and exits 1; all allocation drops balance.

## Frozen decision

| Capacity / occupied | Combined CPU reduction | Snapshot heap reduction | Worst population CPU change | Worst combined p95 ratio |
| --- | ---: | ---: | ---: | ---: |
| 150 / 0 | 77.89% | 99.67% | +78.18% | 0.148 |
| 150 / 150 | 30.33% | 37.38% | +17.52% | 2.343 |
| 1,000 / 1,000 | 47.58% | 54.81% | +19.42% | 0.638 |
| 10,000 / 10,000 | 41.80% | 61.93% | +22.31% | 0.586 |

The 1,000/10,000 combined CPU gains exceed their paired ratio spreads of
3.91/0.38 percentage points and the 20% minimum. Their memory gates also pass;
steady parent requested heap increases only 0.285%/0.296%. But every profile
has at least one population CPU ratio above the allowed 1.05. At 1,000 and
10,000, all three population ratios exceed that ceiling. At full capacity 150,
the p95 ratios are **1.959, 2.343 and 0.930**, failing the worst-pair tail guard.
The variation is retained, not replaced by a favorable median. The small
population measurements do not establish a stable regression magnitude;
they still fail the predeclared worst-pair rule.

Chunking avoids per-entry shared allocations and whole-cache detachment on
first lookup. It still adds chunk construction/copy work, indexed access and
sharing checks to mutations. The timing boundary measures the combined cost
of these changes; it does not isolate how much regression each mechanism
causes. No unsupported attribution is needed to apply the frozen rejection.

## Absolute measured costs

Values are medians of three independent runs. CPU includes driver correctness
checks and sample bookkeeping. Wall samples pair snapshot creation with its
first lookup, excluding waiting between phases. Active throughput divides
completions by their summed wall samples; it is not daemon throughput. Drop
CPU is separately retained in the JSON. No p99 claim is made.

| Capacity / occupied | Variant | CPU µs / completion | p50 µs | p95 µs | Active completions/s | Population µs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 150 / 0 | deep | 1.111 | 0.960 | 1.080 | 1,007,323 | 9.560 |
| 150 / 0 | chunk32 | 0.247 | 0.120 | 0.160 | 7,516,423 | 11.080 |
| 150 / 150 | deep | 20.576 | 15.200 | 35.000 | 49,073 | 85.000 |
| 150 / 150 | chunk32 | 14.502 | 10.840 | 69.921 | 69,754 | 98.760 |
| 1,000 / 1,000 | deep | 111.404 | 104.121 | 139.281 | 9,001 | 573.840 |
| 1,000 / 1,000 | chunk32 | 58.435 | 55.001 | 88.401 | 17,210 | 667.800 |
| 10,000 / 10,000 | deep | 1,468.785 | 1,455.612 | 1,596.293 | 681 | 5,888.160 |
| 10,000 / 10,000 | chunk32 | 854.816 | 836.967 | 927.688 | 1,171 | 7,100.760 |

## Evidence and scope

[`TCP_SNAPSHOT_CHUNK_RESULT.json`](TCP_SNAPSHOT_CHUNK_RESULT.json) retains all
24 per-run CPU/tail/throughput summaries, every paired ratio, independent gate
recalculation and evidence hashes. Raw samples, logs, binaries and private
candidate sources are preserved under
`private/dnsmasq-rewrite/tcp-chunk-20261001/final-evidence-01/`, with the complete
archive alongside it. A second local copy remains in the isolated worktree's
`private/chunk-preparation/`; the remote original remains at
`/home/ubuntu/dnsmasq-tcp-chunk-20261001/work01/private/chunk-01/`.

This concludes the bounded host primitive screen. It establishes neither
C-versus-Rust speedup nor C fork/COW cost, service latency, RSS/PSS, target
resource acceptance or router behavior. The later TCP writeback journal
requires separate correctness and cost accounting. Deep clone remains a
reference implementation, and chunk32 is not adopted. No router was accessed.
