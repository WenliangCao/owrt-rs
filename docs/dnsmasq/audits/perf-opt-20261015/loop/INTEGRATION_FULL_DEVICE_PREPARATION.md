# Integration full device preparation — no launch authority

This is local preparation only. Exact integration source `8d572ba1` and ELF
`8048d5129f02f643774bd30a3d695f741dfbb94ebaf5eafc5cc7146015e83b83`
are bound to the SDK map/build receipt in the JSON. Related Linux938 passed
in batch receipt `050fe64b…f43c53`; this is not complete correctness. Full44,
the other frozen qualification gates and the root's decision after the current
exploratory results must all pass before any command below is executed.
The current F/integration UDP-only ten windows cannot replace this matrix.

The later, explicitly user-targeted rule in `F_E_NEXT_ROUND.md` makes accepted
E `8b8082b9…e8d27` the incremental baseline: require distinguishable UDP-hit
CPU/query improvement, report TCP hit, and allow no distinguishable p50/p95/CPU
regression in any of11 scenes. Resource and correctness requirements stay.
That later rule does not repeat the original majority-of11-scenes requirement
for an E-relative increment.

`FROZEN.md` separately defines original deployed/candidate acceptance as fresh
v0.2.0 B/N pairs across all11 scenes, with the majority-improvement requirement.
Therefore a direct deployment-baseline/final-original-contract claim requires
another fresh110-window B/integration matrix, left SHA `8472be5a…aade7`.
It is not established by transitive comparison with historical E/B data.
Neither matrix is launched here; the JSON lists all110 labels for each. Root
can select the current E-relative increment without silently claiming B/N
acceptance. Historical E/B, F/E and Oracle results remain separate context.

| Order | Frozen scene | Unchanged workload | Windows |
| --- | --- | --- | ---: |
| 1 | udp-hit | 200/s,5s warmup+20s measured,32 clients,1000 UDP prewarm | 10 |
| 2 | udp-miss | 200/s,5s+20s,32 clients,no prewarm | 10 |
| 3 | udp-mixed | 200/s,5s+20s,32 clients,80%hot/20%unique | 10 |
| 4 | tcp-hit | 200/s,5s+20s,8 connections/100 replies,UDP parent prewarm | 10 |
| 5 | tcp-miss | 200/s,5s+20s,8 connections/100 replies,no prewarm | 10 |
| 6 | dhcp-home6 | 6 clients,100operations/s,5s initial/warmup+20s renewals | 10 |
| 7 | dhcp | 150 clients,100operations/s,5s+20s renewals | 10 |
| 8 | startup-small | 8names/6leases,20 repetitions,1000ms period | 10 |
| 9 | config-small | 8names/6leases,20 stop/start repetitions,1000ms period | 10 |
| 10 | hup-small | 8names/6leases,20 repetitions,1000ms period | 10 |
| 11 | hup-large | 1000names/150leases,20 repetitions,1000ms period | 10 |

Every scene has five complete alternating pairs: left/right, right/left,
left/right, right/left, left/right. DNS retains800names,70/30 A/AAAA,cache1000,
EDNS1232,upstreamTTL120/delay1ms. Lifecycle retains1ms probes. No traffic,
affinity, timer, tool binary or case/group changes are proposed.

Use controller SHA `7c93cfb1…8e21df`, including the already accepted archive
pruning/preservation fixes, and unchanged analyzer `10addedf…ebad2283`.
The actual nine measurement files are hash-bound in the JSON. Keep fresh
private outputs and a copied tool snapshot. After full qualification and
root launch authorization, create a new>=125s health receipt, verify live
production/owned-process state and offline restore copies, then atomically
stage E into task `dnsmasq-c` and integration into `dnsmasq-rust`.
No installation, production process change or flash operation is included.

Prepared command form, deliberately not executed and with no `--scenes`:

```sh
python3 tools/dnsmasq/perf_opt_device_run.py \
  --out private/perf-opt-20261015/integration-vs-e \
  --prefix integration-vs-e \
  --c-hash 8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27 \
  --rust-hash 8048d5129f02f643774bd30a3d695f741dfbb94ebaf5eafc5cc7146015e83b83 \
  --health-baseline private/perf-opt-20261015/health-integration-vs-e/summary.json

python3 tools/dnsmasq/perf_opt_analyze.py \
  private/perf-opt-20261015/integration-vs-e \
  private/perf-opt-20261015/integration-vs-e-summary.json
```

For a separately authorized original B/N acceptance round, use a distinct
`integration-vs-deployed` output/prefix, new health receipt and left artifact
SHA `8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7`.
Keep integration unchanged. This adds110 new windows, not reused E data.

All33 primary metrics use the original median/range W and>=4/5 paired direction;
CPU also needs every window>=10ticks and median delta>8ticks. Lifecycle latency
requires>=1ms difference; fewer than10000 samples cannot establish p99.
Preserve the full resource components, process tree/FD ranges and ELF size.
Integration is2,140,955B, +4096B over E and+16384B over deployed B, under the
unchanged2,200,000B gate; growth still needs explicit justification. There is
no new relative RSS/FD allowance. RSS/RssAnon are not USS and lifecycle snapshots
do not measure transient peaks.

Use `FROZEN_TOOL_WINDOW_SUPPLEMENT.md` exactly: finish original110, then only
an independently evidenced tool-invalid complete pair may get one complete
same-order supplement. Do not mix original/supplement sides. Product wrong
answers,timeouts,crashes and unknown causes do not qualify. Keep every original
failure and the eventual pair-source mapping. Health failures stop owned work;
retain STOP and failure evidence, never restart production or automatically
bypass recovery. Existing resume must preserve exact controller/artifacts and
the original unstarted schedule; it does not authorize rerunning valid windows.

Archive and verify every tar/member/hash before pruning only valid remote
copies. Retain all failures and locally durable progress. At completion verify
production unchanged, no owned live executable/group, and restore prior exact
E/F task slots. Independent source/artifact, raw/statistical and health audits
must accompany any final acceptance claim. Full44 and the entire frozen
qualification receipt remain explicit missing launch gates in the JSON.
