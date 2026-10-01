# EPS1 result: retain only for the later service gate

EPS1 passes the frozen host primitive screen. Median paired CPU/operation falls
**81.86% for full unexpired churn** and **71.14% for the mixed vector** versus
the frozen Rust B0. The worst hot pair is **0.69% slower**, within the declared
5% guard. Every timed run completes 100,000 operations with the exact C-derived
counts/digest and zero errors. There were **24 runs, no extra rounds**.

The default product cache remains unchanged. This is a Rust-B0-to-EPS1 primitive
comparison, not a measured C-to-Rust component improvement or router result.
The shared performance/resource goal, target build and production acceptance
remain open. [Freeze and boundaries](CACHE_EXPIRY_SCREEN_816B955.md) records the
source/vector identities and predeclared thresholds; the complete derived
[result index](CACHE_EXPIRY_SCREEN_RESULT.json) retains all 24 numeric rows and
raw-artifact hashes.

## Mechanism and functional evidence

Exact C `cache_scan_free` and the original Rust occupied-tail path both scan
the entire cache before spilling a live RRset. When no committed expiry can
have elapsed, the one-`i64` conservative bound proves that scan has no effect.
EPS1 changes that common pressure check from O(capacity) to O(1). A possible
expiry still runs the original slot-order pass; worst-case work stays
O(capacity). Each valid commit adds one minimum operation. Deleting the current
minimum can cause an extra later scan, rather than requiring delete indexing.

The fixed workloads expose this insertion cost strongly; they do not establish
its share of a complete DNS request. The independent C cost diagnostic's
11.07%/21.54% sampled `cache_scan_free` self-cycle shares identify the source
mechanism, but must not be multiplied by these primitive percentages to predict
a service result. Packet parsing, forwarding policy, sockets, locks, upstream
waiting and callers are outside this timed loop.

| Gate | Result |
|---|---|
| Current-source pressure | 37 scenarios / 26,992 commands per implementation; three fresh C runs per scenario; C/B0/EPS1 exact traces match |
| Existing primitive corpus | 21 scenarios / 22,571 commands each; C comparison has zero mismatches with its existing 138 permitted cross-generic-type order variations; B0/EPS1 raw traces are identical |
| Full-object C publication | 70 traces / 1,876 operations for each Rust source; zero differences |
| Full-object local CNAME/insertion | All 32 ordinary cases match; both Rust sources retain the same two nonzero differences in the four previously documented reference-layout cases, with exit 1; all B0/EPS1 observations match |
| Actual screen vectors | 400,000 measured-result rows per implementation; three fresh C processes per vector; every row and warm/final count/digest matches, with no normalization |
| Bookkeeping ownership | 2,000 untimed delete/abort/clear/recommit cycles, 8,000 required absences and 2,000 new-expiry checks; allocation requests match and drop balance returns to zero |

The reference-layout differences remain failures in their raw results. They
are not waived or rewritten into an all-equivalent claim. The previous
synthetic hash-bucket publication limitation also remains in
`DNS_LEASE_CACHE_PHASE.md`. These primitive gates do not replace packet/service
coverage or prove the absence of every bug.

## Every timed pair

Native aarch64 Linux on the build host; Rust 1.98.1 with identical O3/LTO/one
codegen-unit/panic-abort flags. CPU0 was exclusive of other agent jobs during
**2026-10-01 09:46:15.609954–09:46:23.670040 UTC**. Process CPU covers only the
measured operations; input preparation, prefill and one full warm pass precede
it. The four-core Neoverse-N1 topology was read after the window. This does not
claim bare-metal isolation from every host or hypervisor activity.

Each row has 100,000 successful operations on both sides. CPU units are µs per
completed operation; throughput is completed operations divided by measured
wall time. Pair orders are B0/EPS1, EPS1/B0, B0/EPS1. Raw wall nanoseconds,
per-run start/end timestamps and all stdout/stderr remain indexed privately.

| Vector | Pair | B0 CPU | EPS1 CPU | B0 ops/s | EPS1 ops/s | EPS1/B0 CPU |
|---|---:|---:|---:|---:|---:|---:|
| Hot | 1 | 0.1918 | 0.1931 | 5,211,928 | 5,176,455 | 1.006858 |
| Hot | 2 | 0.1929 | 0.1898 | 5,183,066 | 5,268,172 | 0.983867 |
| Hot | 3 | 0.1937 | 0.1934 | 5,162,068 | 5,169,348 | 0.998596 |
| Unexpired | 1 | 3.5028 | 0.6323 | 285,418 | 1,581,419 | 0.180512 |
| Unexpired | 2 | 3.4741 | 0.6333 | 287,797 | 1,578,861 | 0.182296 |
| Unexpired | 3 | 3.4929 | 0.6335 | 286,233 | 1,578,399 | 0.181372 |
| Mixed | 1 | 1.3703 | 0.4062 | 729,637 | 2,461,782 | 0.296396 |
| Mixed | 2 | 1.3768 | 0.3973 | 726,288 | 2,516,520 | 0.288582 |
| Mixed | 3 | 1.3819 | 0.3952 | 723,356 | 2,530,267 | 0.285963 |
| Expiry | 1 | 2.7881 | 0.7270 | 358,438 | 1,375,480 | 0.260745 |
| Expiry | 2 | 2.7813 | 0.7064 | 359,422 | 1,414,865 | 0.253997 |
| Expiry | 3 | 2.7921 | 0.7165 | 358,110 | 1,395,318 | 0.256618 |

The primary paired-ratio spreads are 0.18 percentage points (unexpired) and
1.04 points (mixed), much smaller than their observed gains. Expiry's median
CPU reduction is 74.34%; all its pairs pass the guard. Hot's median difference
is only 0.14% against a 2.30-point paired-ratio spread, so **no hot speedup is
demonstrated**. No RTT or per-request latency percentile is inferred from these
aggregate primitive windows.

## Storage cost and remaining work

Cache layout changes **168 → 176 bytes (+8 fixed bytes)**; Entry stays **120
bytes**. Separate allocation builds contain the measurement atomics; timed
binaries do not. Allocation/reallocation counts, requested byte traffic and
ending live heap are identical between sources in every vector. Every cache
drop returns to its pre-cache allocation baseline.

| Vector | Shared ending live heap B | B0 peak live B | EPS1 peak live B |
|---|---:|---:|---:|
| Hot | 261,096 | 263,828 | 263,828 |
| Unexpired | 428,344 | 528,672 | 528,672 |
| Mixed | 425,596 | 526,028 | 526,012 |
| Expiry | 428,344 | 528,936 | 525,108 |

These requested-layout counters include construction, prefill, warm and measured
operations after prepared inputs are excluded. Their window differs from CPU;
they are not divided by timed requests to invent a per-request memory metric.
Small peak differences can reflect ordinary hash-table allocation timing; no
heap saving is claimed. The added fixed metadata can occupy heap bytes when
embedded in a service object, so it remains a real +8-byte cost per instance.
RSS/USS, service FD/thread/child peaks, network tail latency, target size and
long-lived service growth were not measured by this screen.

All prepared, diagnostic and final rounds remain under ignored
`private/dnsmasq-rewrite/cache-expiry-eps1/current-816b955/`. `native/screen-01`
is an early preparation, `screen-02` is the successful but unintended Rust
1.98.0 functional gate, and `screen-03` is the pinned 1.98.1 result. The vectors
and candidate were not tuned after viewing costs. Native full-object raw gates
include their nonzero reference-layout results; no failed run was discarded.

Retention authorizes preparing a new private candidate on the current counted
cache API, not editing the default implementation or copying this gain onto a
new baseline. That rebase needs its affected C correctness and metric-count
gates. A later service protocol can be frozen only after the current producer
and stale-cache functional gates stabilize; target/production acceptance is
separate. No physical router was accessed.
