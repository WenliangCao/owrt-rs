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

The first 36 windows completed before any raw-record product change. Exact
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
