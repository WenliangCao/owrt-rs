# Exact-SDK owner32 for 185 directly against accepted E

This implements the owner32 part of the unchanged
[combined experiment plan](CACHED_ZERO_FRAME_PLAN.md). Candidate source is
`185db90c9cabd26c0af09765636ef15bf6d35f79`; the fresh control is accepted E
`4f869c885b47dcf60d56c872e5b0b3c62237beea`, ELF
`8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27`.
No result from 0161, F or the standalone children is pooled with this experiment.
The owner-clock prototype is excluded. This does not select a candidate.

The [prepared identity](cached-zero-frame-owner32-preparation.json) binds all
179 source inputs directly to the named Git commit. Its original four Linux
groups passed 940 tests: 836 library, 18 live ignored library, 82 binary and 4
live ignored binary. The verified receipt SHA256 is
`b5089b4b54bcde00a4d887453a1912965c10062066bb48323ea7607f2b651501`.
The exact-source composition/gate review is `affd0c95`. These related gates
do not replace full 44-family qualification.

The original disabled preparation remains intact. After the single canonical
SDK build, the [frozen execution plan](cached-zero-frame-owner32-plan.json)
binds these downloaded and verified artifacts:

| Artifact | SHA256 | Bytes |
| --- | --- | ---: |
| 185 ELF | `9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99` | 2,145,051 |
| Same-link map | `e1c8638fbb2ff229d736d697dae78a519a914beb975cbf017f7666dd1dbe314f` | Recorded in build receipt |
| Build receipt | `dfb42af12c623b3eb7551bd9e821ef6fb0d63922f02a8714e7475623b9483f10` | Recorded privately |

Both candidate and E SDK triples were rehashed locally, and their 358 receipt
inputs were checked against their exact Git revisions. Original release
budgets/hardening pass; the build remains `built-unqualified`. The
[controller](run_cached_zero_frame_owner32.py) rejects the disabled preparation
before creating output and permits only the frozen ready status. All transfers
finish before timing; source/receipt/artifact/tool checks repeat after all
windows. Runtime execution also waits for independent review and explicit
release of the preceding native240 reservation.

The original driver, CPU placement and workload remain unchanged. The 32
windows are stat low200/s three alternating pairs, stat high-unpaced three
pairs, plain low five pairs and plain high five pairs. E is first in odd pairs,
185 in even pairs. There are no added strace windows. Each window retains 800
names, A/AAAA70/30, 1,000 full prewarm queries, 5 seconds warmup, 20 seconds
measured and 1 second drain. Driver CPU0/nice0, daemon CPU2/nice10 and sender
CPU3 remain as before. No build, other workload or bulk transfer may overlap.
The completed 0161 screen and its postflight were released before this local
preparation; new native240 and owner32 timing will use separate reservations.

[The analyzer](analyze_cached_zero_frame_owner32.py) changes only the scope
label from the completed 0161/E analyzer. CPU and PMU divide actual warmup plus
measurement N, while throughput and latency use the 20-second measured cohort.
Grouped user/kernel instructions and cycles remain unscaled; user IPC is from
the same window. Low load retains the original strict >8-tick precision and
W/direction rules. High variable-N results retain `precision_ok: null` for CPU
and remain a closed-loop pipeline diagnostic. Sender and send-lag effects must
be reported, including adverse changes. No existing threshold is relaxed.

Every output and log must be fresh. Failure preserves the partial window and
stops the sequence; there are no selective reruns or replacement pairs. The
controller retains the existing 100-second timeout and process-group cleanup.
The artifact download and input pretransfer occur in loop's explicit gap after
SDK completion, before native240 or owner32 timing. No router operation is
performed by this screen. Complete screen results, independent review and the
original later qualification gates remain required before acceptance can be
considered.
