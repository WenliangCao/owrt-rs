# UDP name-buffer: small saturation signal, no low-load CPU gain

The independent original-SDK screen completed all 32 fixed windows: 12 grouped
PMU windows and 20 plain windows, with no strace, failed measurement or replacement
sample. Low-load CPU did not improve. High-load CPU/query and p50 latency show
small changes beyond W, but throughput does not. These are variable-query,
closed-loop screening results, not full correctness or performance acceptance.
This review does not select or deploy a new candidate.

The frozen [plan](UDP_NAME_BUFFER_PLAN.md) is commit `4266eccd`. The candidate is
source `f404ed754a26f9385c733e7474f28e4595520957`, independently based on F
`3a3d8e3e848b93b0309353acfa0033d0b01a7cd0`. Implementation `f0a96480` and the two
subsequent regression-test commits introduce no other prototype. The candidate
SDK ELF is `47fe55e47f8185cad4dffadf66bdeaaffd18a984e3ec37c249920f5eb0afb54f`;
the F control is `b7926bcf39cd7f33b4f0c110315ddc1ad719b39427bec53430ea05aeacd781fc`.
Both are 2,136,859 bytes and pass the unchanged release-size gate. Both build
receipts still say `built-unqualified`.

All 179 candidate input blobs were independently checked against Git and the
retained Oracle source. ELF, link-map and build-receipt hashes match the run
identity. The exact prerequisite receipt is
`059479d352b7219518d10fe1e197bd46fd4e3e71be9ccd9d4eb64229a16d5011`:
[934 related Linux tests](../correctness/udp-name-buffer-linux-gates.json),
not full 44-family qualification.

## Fixed measurement and retained setup failure

Each load uses three alternating PMU pairs followed by five alternating plain
pairs, with F first in odd pairs and the prototype first in even pairs. The
fixture remains 800 names, A/AAAA 70/30, 1,000 full prewarm queries, 5 seconds of
warmup, 20 seconds of measurement and a 1-second drain. Every window has correct,
nonempty traffic, zero timeout/wrong/transport/skipped/stale replies, matching
PID/starttime and a complete child-tree drain. All 12 PMU windows retain grouped,
unscaled user/kernel instructions and cycles with identical enabled/running
times. IPC is calculated from the same window's raw user counts.

`udp-name-buffer-screen1` remains an empty directory. Its original script and
565-byte stderr are retained: `KeyError: 'all_log_hashes_rechecked'` occurred
before identity, daemon or window creation. The actual receipt field is
`all_ten_log_hashes_rechecked`. Screen2 changes that field, adds an exact receipt
SHA256 check and records the failed setup in a new output directory. The fixed
32-window plan is unchanged; no measured window was rerun. Original stderr
SHA256 is `da9b66d8b915126951492f4179eafe4066d6fcab0a8118fd5a67016945a0e725`.
Screen2's controller stderr is empty and its completion marker records 32.

## Plain five-pair results

CPU/query uses the actual warmup plus measurement completion count, including
the observation's drain time. Low load has N=5,000 and a 2 µs/query tick quantum.
Throughput and latency use the 20-second measurement cohort. The fixed prewarm
is excluded from these CPU/PMU denominators.

| Metric | F median | Name-buffer median | Change | W | Beyond W and direction rule |
| --- | ---: | ---: | ---: | ---: | --- |
| Low CPU µs/query | 28 | 28 | 0.000% | 14.286% | No; tick precision also fails |
| Low throughput queries/s | 200 | 200 | 0.000% | 0.000% | No |
| Low p50 µs | 50.681 | 52.240 | +3.076% | 19.493% | No |
| Low p95 µs | 78.520 | 80.281 | +2.243% | 8.819% | No |
| High CPU µs/query | 4.671316 | 4.617565 | −1.151% | 1.033% | Yes, 5/5; diagnostic only |
| High throughput queries/s | 214,198.50 | 216,424.80 | +1.039% | 1.074% | No, despite 5/5 direction |
| High p50 µs | 144.561 | 142.682 | −1.300% | 1.121% | Yes, 5/5; diagnostic only |
| High p95 µs | 159.042 | 157.721 | −0.831% | 1.344% | No |

Low CPU ticks are F `[14,15,14,13,14]` and name-buffer `[15,14,14,14,14]`.
Their median difference is zero, so the original strict >8-tick precision gate
does not pass. All low-load latency and send-lag changes remain within W.

| Pair | Low CPU F → name-buffer, µs/query | High CPU F → name-buffer, µs/query | High throughput F → name-buffer, queries/s |
| --- | --- | --- | --- |
| 1 | 28 → 30 | 4.660038 → 4.608062 | 214,488.40 → 216,916.00 |
| 2 | 30 → 28 | 4.671316 → 4.609439 | 214,198.50 → 216,963.55 |
| 3 | 28 → 28 | 4.679029 → 4.617565 | 213,684.60 → 216,424.80 |
| 4 | 26 → 28 | 4.691227 → 4.655159 | 213,144.35 → 214,638.40 |
| 5 | 28 → 28 | 4.671220 → 4.655761 | 214,199.05 → 214,937.45 |

High plain N varies from 5,326,964–5,360,471 for F and
5,363,941–5,423,104 for name-buffer. The daemon consumes about one CPU, and
sender CPU ranges from 99.794% to 99.880% across these ten windows. This is the
observed closed-loop sender/server pipeline, not isolated server capacity.
The high CPU result explicitly has `precision_ok: null`: applying W/direction
to variable-N values does not manufacture a fixed-cohort tick-precision pass.
Neither high send-lag percentile changes beyond W. The derived JSON retains
each plain window's N, CPU, throughput, sender CPU, latency and send-lag values.

## Separate PMU mechanism evidence

The following are medians over three separate PMU windows. These counters are
not substituted for the plain CPU measurements or pooled with earlier screens.

| Per-query metric | Low F | Low name-buffer | High F | High name-buffer |
| --- | ---: | ---: | ---: | ---: |
| User instructions | 8,950.09 | 8,761.88 | 6,761.04 | 6,566.74 |
| User cycles | 20,208.43 | 20,271.23 | 4,396.30 | 4,302.78 |
| Kernel instructions | 25,839.22 | 25,933.48 | 12,984.47 | 12,984.53 |
| Kernel cycles | 39,850.61 | 39,268.98 | 9,507.90 | 9,419.69 |
| Per-window user IPC | 0.44285 | 0.43224 | 1.53789 | 1.52697 |

User instructions fall 2.103% at low load and 2.874% at high load. User cycles
change +0.311% and −2.127%, respectively. This supports a small high-load
mechanism signal; it does not demonstrate a low-load CPU improvement or the
overall CPU objective. The bounded retained-memory cost also remains: one
lazy name buffer per daemon, normally 32 bytes in this fixture, with the pinned
irregular-label regression retaining 380 bytes. This is not zero-memory reuse.

## Independent review boundary

The reviewer independently reproduced all pair statistics with the unchanged
`perf_opt_analyze.compare`, checked the exact 32-window order and all PMU
grouping/unscaled/IPC fields, and rehashed 388 small raw metadata files on
Oracle. Traffic counts, prewarm, child drains, artifact identities and CPU ticks
were checked against those small files. All checks passed.

The large latency/send-lag binaries and complete raw manifests were not read
again during this review. Their existing derived quantiles and hashes are
retained from the coordinator's original analysis using
[the existing analyzer](analyze_udp_owner_screen.py). This is not a second full
raw-data audit. No router access, build, load, installation or deployment was
performed by this review.

The input summary SHA256 is
`54c5f89ffdb6af0e940d11c473011909bbd12a259852613baba53ea9cee8cac7`.
Raw evidence remains private on Oracle `root/private/udp-name-buffer-screen2`.
[The derived result](udp-name-buffer-screen-result.json) preserves all 32 rows,
the original per-file digest inventories, identities, setup-failure evidence
and independent-review scope. Further candidate consideration still requires
full correctness, full fixed matrices and physical qualification; this screen
changes none of those gates.
