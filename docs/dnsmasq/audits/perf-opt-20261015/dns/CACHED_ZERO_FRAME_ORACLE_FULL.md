# Prepare the original complete E/185 Oracle matrix

This implements the Oracle half of recipe `893eed29`, with the exact source
and SDK artifact already measured in the separate owner32/A53 screens. It is
local preparation only. Full functional qualification and its explicit quiet
handoff, plus the independently reviewed full-run tail-capture tool binding,
must precede any performance launch. The original preparation recipe remains
unchanged; its SHA256 is
`824f8c16fe8cb0b0f23ee8c7462a94628b52ba7d547c75a949c158e51a7cb096`.

| Side | Source | Exact ELF SHA256 | Bytes |
| --- | --- | --- | ---: |
| Accepted E, original label `c` | `4f869c885b47dcf60d56c872e5b0b3c62237beea` | `8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27` | 2,136,859 |
| 185, original label `rust` | `185db90c9cabd26c0af09765636ef15bf6d35f79` | `9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99` | 2,145,051 |

The candidate map is `e1c8638fbb2ff229d736d697dae78a519a914beb975cbf017f7666dd1dbe314f`;
its build receipt is `dfb42af12c623b3eb7551bd9e821ef6fb0d63922f02a8714e7475623b9483f10`.
The [machine preparation](cached-zero-frame-oracle-full-preparation.json) binds
both 179-file source manifests and artifact triples, the original seven tool
source hashes, measurement ELF/script hashes, all eleven scene tuples and all
110 labels. The complete qualification, quiet and reviewed final tool fields
remain null until their actual receipts exist. The related 940-test receipt
alone cannot open the full-run gate. No artifact is changed for this matrix.

The original scenes are UDP hit/miss/mixed, TCP hit/miss, DHCP with 6 and 150
clients, startup small, configuration small, hosts HUP small and hosts HUP
large. Every scene has five pairs: E/185, 185/E, E/185, 185/E, E/185. Workload
rates, warmup, measurement durations, prewarm, client counts and lifecycle
repetitions are unchanged. The original controller is invoked with explicit
baseline/candidate paths, `inputs-fe`, CPU2 and a fresh
`root/private/oracle-cached-zero-frame-vs-e` output. No smoke mode or scene
selection is used. The original case path rewrite and private `/tmp` runtime
directory, nice10 helper and isolated network namespace remain unchanged.

The Oracle runner imports `SCENES`, `validate` and `write` from the companion
device-runner snapshot. The pending generic tail-capture repair must therefore
be bound explicitly even when its changed health path is device-only. The
final source snapshot and independent review must demonstrate that the Oracle
driver, case script, scene tuples, traffic validator and statistics remain
unchanged. Current local preparation copies the original source bytes only;
it does not import or execute a controller and does not stage anything remotely.

All 33 p50/p95/CPU comparisons are reported under the original median/full-range
W and at-least-4-of-5 direction rule. CPU additionally needs every window at
least 10 ticks and an absolute median difference strictly above 8 ticks.
Lifecycle latency retains the 1 ms observation limit, and fewer than 10,000
samples cannot support p99. Original DORA handling, resource samples/ranges,
RSS components, process/thread counts, parent/tree FDs and lifecycle readiness
snapshots remain. No new relative memory or FD allowance is introduced.

Each attempted window retains its controller log, manifest, tar archive and
verified external raw copy before temporary cleanup. Failure remains visible;
the original controller's stop/continue behavior is preserved. Only after the
original 110 can an independently established tool-invalid whole pair receive
the separately frozen one-time symmetric supplement. Product or unexplained
failures never qualify, and valid observations are not selectively rerun.

Oracle timing is exclusive: no overlapping build, test gate, profile or other
load. All staging finishes first. The independent router matrix belongs to the
DHCP owner and may run in parallel; only small derived receipts transfer while
router timing restricts bulk transfer. No router operation is performed here.
After all windows, recheck the full order, artifact/tool/source identities,
archives and members, analyze the original raw records and obtain independent
review before any result is considered for acceptance. Historical owner/native/
device observations are never pooled into these new E/185 pairs.
