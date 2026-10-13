# N4 exact-image C comparison

These probes extend the preceding review's fixed cached-A workload by adding
exact-image C to every same-configuration comparison. Raw evidence stays on
Oracle under `/home/ubuntu/dnsmasq-fix4-repairs-20261013/private/`; only tooling
and derived reports are versioned. No physical router is involved.

`three_way.py prepare --output NEW_PRIVATE_DIRECTORY` freezes the baseline
three-way matrix. `three_way.py run --output NEW_PRIVATE_DIRECTORY` runs it as
root; `summarize` independently checks counters, cache proof, identities,
matching configurations, foreign-workload checks and throttling before reporting.
The frozen build uses product revision `74c6b453`; newer local document commits
do not change that product identity. The after-fix run supplies `--candidate`
and `--candidate-commit` to `prepare` and uses a separate new private directory.

Each round covers TCP and UDP, both with 100 and 1,000 unrelated-name TYPE A
`dns-rr` declarations. Orders are C/main/current, main/current/C, current/C/main,
so each implementation occupies each position once. The scenario, rate, random
seed, configuration and native tools match within every triple. Parameters
remain 1,000 queries/s, 20 clients, 3 seconds warmup, 15 seconds measurement,
CPU 0/1/2/3 for daemon/upstream/load/controller. TCP reconnects every 100 queries.
Every window first proves the configured raw record over UDP and TCP, populates
and individually proves all 4,096 cached names, then disables upstream answers.
No measurement is silently retried or dropped.

CPU comes from the service cgroup's `cpu.stat` usage delta, including C's forked
TCP children. Per-response figures include connection overhead and cannot be
interpreted as isolated raw-record lookup cost. Compare 100-to-1,000 scaling
within an implementation to assess configuration-size sensitivity; the C/main
absolute TCP gap also contains architecture and connection-management costs.
These are descriptive three-round medians and ranges, not proof of statistical
performance equivalence or a user-approved tolerance.

`ordinary_plan.py` prepares only the no-raw TCP profile with 30 seconds warmup
and 120 seconds measurement, using the same three-way runner, tools, order and
validation. Its selector is hashed into the frozen plan before any load starts.

## Before the scan-cost repair

The first 36 windows completed before any raw-record product change. The
[source review](source-review.json) binds the image-matching OpenWrt patched C
files to their retained reference identity: `rfc1035.c:1859–1872` scans raw records
for every C_IN query, comparing type before name; `util.c:404–429` checks name
length and folds ASCII case without allocation. Exact
artifact identities are in `before-plan.json`: C `097a9e21…`, main `ad103449…`,
and the reviewed product `74c6b453`'s frozen ELF `25b7291d…`.

| Configuration | C CPU µs/correct | main | Before | Before/C | C/main/before p95 µs |
| --- | ---: | ---: | ---: | ---: | --- |
| TCP, 100 TYPE A | 53.510 | 30.532 | 44.043 | −17.69% | 105.080 / 77.641 / 97.921 |
| TCP, 1,000 TYPE A | 79.135 | 31.934 | 119.326 | +50.79% | 150.321 / 78.321 / 215.802 |
| UDP, 100 TYPE A | 21.560 | 31.459 | 30.128 | +39.75% | 67.081 / 82.280 / 80.841 |
| UDP, 1,000 TYPE A | 44.971 | 108.237 | 100.332 | +123.10% | 106.321 / 209.162 / 198.882 |

CPU increases from 100 to 1,000 records were C/main/before:
TCP **25.624 / 1.402 / 75.282 µs**; UDP **23.411 / 76.777 / 70.203 µs**.
Thus exact C also pays a measurable configuration-size cost. The Rust branch's
additional scaling beyond C is about 49.658 µs TCP and 46.792 µs UDP in this
screen; this is an observed difference, not a function-level causal profile.
The C/main absolute TCP difference cannot all be called the price of correct
local-first semantics, because it also includes C's fork/connection behavior.

All 648,000 scheduled warmup/measurement queries were sent and correct, with
zero wrong answers, timeouts, transport errors or skips. All 36 cache banks,
raw-record UDP/TCP proofs, process hashes, matching triple configurations and
zero upstream requests after disabling answers passed. All 360 cgroup throttle
samples were zero. `before-summary.json` retains every measured window;
`before-counter-check.json` retains its validation and raw evidence hashes.

Three rounds support the large scaling observation, not broad performance
qualification or a confidence claim of equivalence. In particular, main's third
TCP/1,000 window was 41.620 µs, versus 31.934 and 31.075 in the preceding rounds
(relative range 33.02%); it remains in the results with no retry or exclusion.
The branch TCP/1,000 values were 119.957, 115.024 and 119.326 µs, and C's were
79.135, 77.668 and 82.050 µs. `coordination.json` explicitly discloses brief
CPU3 read-only old-profile analysis during baseline instead of claiming a
perfectly silent host. No competing experimental daemon/build was observed.

## After the allocation-free scan

The second 36-window matrix uses source `006002bb` (raw change `aae4b04d`,
followed by a test-only correction) and measured ELF `cf94126f…`, with its own
same-build link map. No name index was added. Ordinary TCP confirmation and
excluded attribution diagnostics are separate from these short windows.

| Configuration | C CPU µs/correct | main | Scan repair | Scan/C | Scan/main | C/main/scan p95 µs |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| TCP, 100 TYPE A | 53.023 | 31.089 | 34.442 | −35.04% | +10.79% | 105.561 / 78.920 / 82.241 |
| TCP, 1,000 TYPE A | 76.315 | 31.613 | 41.035 | −46.23% | +29.81% | 144.401 / 78.401 / 88.241 |
| UDP, 100 TYPE A | 21.903 | 31.641 | 27.568 | **+25.87%** | −12.87% | 67.761 / 82.520 / 69.641 |
| UDP, 1,000 TYPE A | 44.728 | 109.481 | 24.448 | −45.34% | −77.67% | 106.801 / 211.842 / 70.721 |

The large same-type scaling cost falls substantially. However, **the strict
not-slower-than-C gate is not yet met for UDP/100**: all three repaired values
(24.622, 27.568, 27.923 µs) exceed their C counterparts (20.931, 22.176, 21.903).
The repaired relative range is 11.98%, C's is 5.68%. This result must remain
visible rather than closing N4 based only on TCP/1,000.

A name index is not justified by these data alone: UDP/1,000 is already faster
than C and is faster than repaired UDP/100. The remaining discrepancy does not
increase with raw-record count, so its source needs a profile. TCP's repaired
100-to-1,000 increment is 6.593 µs versus C's 23.292 µs; UDP's repaired difference
is −3.120 µs versus C's +22.825 µs. These are differences between window medians,
not a claimed negative algorithmic scanning cost.

The second matrix again retained all 648,000 scheduled=sent=correct responses,
with zero wrong/timeout/transport/skip counts and zero at all 360 throttle samples.
The independent offline checker also validated all 72 direct raw-record UDP/TCP
packets including AA, which distinguishes them from the upstream's non-AA answer.
See `after-{plan,run,summary,counter-check,independent-check}.json`.

## Ordinary TCP without raw records

This is a new ordinary-configuration control, **not a rerun of the earlier
100/1,000 TYPE65401 cases that showed about 13% overhead**. Three balanced
C/main/scan triples use 30 seconds warmup and 120 seconds measurement.

| Metric (window median) | C | main | Scan repair |
| --- | ---: | ---: | ---: |
| CPU µs/correct | 45.131 | 30.464 | 32.242 |
| p95 µs | 96.641 | 78.240 | 81.041 |
| CPU relative range | 5.53% | 5.24% | 2.41% |

The ratio of CPU medians is +5.84% against main. The three paired differences
are +0.753, +1.786 and +1.567 µs (ratios +2.35%, +5.86%, +5.14%); all are retained.
The CPU increase is smaller than the earlier TYPE65401 result, and this small
three-round screen does not establish equivalence or identify its cause.
The remaining CPU and UDP/100 discrepancy require excluded profile evidence.

All 1,350,000 scheduled warmup/measurement queries were sent and correct with
no errors or skips; all nine 4,096-name proofs and zero-upstream checks passed,
as did all 90 zero-throttling samples. The window argv correctly specifies
30/120 seconds. The already-queued run command retained the runner's default
180-second watchdog; actual windows took about 152.5–152.7 seconds, and none
was interrupted or retried. Complete evidence is in `ordinary-*.json`.


## Original TYPE65401 control after the scan repair

A separate 18-window short control restores the original `dns-rr=unusedN.audit.test,65401,abcd`
configuration for TCP A cache hits, with exact C included. This uses the same
3/15-second workload as the same-type review; it does **not** reproduce the
older six-pair 30/120-second duration. All 324,000 responses were correct with
zero errors/skips and 180 zero-throttling samples.

| Configuration | C CPU µs/correct | main | Scan repair | Scan/main | C/main/scan p95 µs |
| --- | ---: | ---: | ---: | ---: | --- |
| TCP, 100 TYPE65401 | 50.026 | 31.013 | 34.143 | +10.09% | 104.801 / 78.040 / 85.641 |
| TCP, 1,000 TYPE65401 | 54.983 | 32.812 | 34.071 | +3.84% | 113.601 / 79.201 / 81.361 |

The 100-record scan windows were 32.655, 34.143 and 39.727 µs (20.71% relative
range). The last high window is retained, not retried. At 1,000 records, main
and scan relative ranges were 1.05% and 1.18%; all three differences were
positive (+1.564/+0.817/+1.259 µs). These short controls do not stably reproduce
the earlier approximately 13% magnitude and cannot prove its disappearance.
A TYPE65401/1,000 current-branch profile is added to cover this exact configuration
alongside the no-raw TCP profile.

`absent-*.json` preserves this attempt. Its executed wrapper is the frozen
`a2ac634f` copy and exact hash in `absent-plan.json`; a later local comment/error
message correction only replaces misleading copied “TYPE A” wording. The
retained Oracle wrapper is unchanged. `coordination.json` discloses one small
DHCP-report JSON fetch that may overlap this batch.

## Main symbols for diagnostics

A fresh map build used the original main source directory and recipe with only
`ORACLE_BUILD_LINK_MAP=1`. It reproduced the complete measured `ad103449…` ELF
byte-for-byte, not merely its text. All 172 original source inputs, `.text`, 14
allocated sections and LOAD layout were checked. `main-map-comparison.json`
therefore permits that map to attribute the original measured main process;
no different symbol companion is substituted.
