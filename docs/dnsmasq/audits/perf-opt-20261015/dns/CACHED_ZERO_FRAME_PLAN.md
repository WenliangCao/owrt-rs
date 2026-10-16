# Direct E comparison for bounded reply reuse plus the narrowed local entry

Source `185db90c9cabd26c0af09765636ef15bf6d35f79` combines the two independently
reviewed children of0161: reply-buffer reuse03ace8ec and local-frame extraction
a8dcdacc. The cherry-pick had no conflicts or manual product edits. local.rs is
byte-identical to a8; the other five changed files are byte-identical to03ace.
Mac721/8 and musl all-target checking pass on the combination. It has no new
behavior repair, compiler option or test-tool change. It is an experiment,
not selected G or a qualified release.

[Fresh local allocation controls](cached-zero-frame-local-allocation.json)
compare the actual accepted-E source with the combination in the same prepared
UDP API probe. After1000 prewarm,8000 calls yield E5allocations/277requested
bytes per operation versus zero for185, equal checksum468800 and zero
reallocations/live-byte delta. The fixture differs from the earlier physical
E5/270B diagnostic. These counts exclude socket/owner work and are not CPU
attribution or a prediction of A53 gain.

The reason to measure this combination is the remaining allocation and entry
overhead, not addition of independent effects. The first prototype demonstrates
zero steady allocations in the local prepared-UDP probe; the second reduces
the local cross-compiled entry frame but increases fallback frame/call cost.
Neither has an A53 timing result. Their full individual sources, tests, local
counts/codegen and prepared-but-unexecuted Linux inputs remain retained.

0161's independent A53 screen is complete and independently audited: E136→122
us/query,5/5 toward improvement, but7ticks and absolute change belowW. All10
windows, including E's152us first sample, remain. It does not qualify; its
full44/110 recipes were not executed. Its current Oracle owner32 must finish
all32 windows and postflight before any new Oracle build, transfer or workload.
The earlier54bd native240 has6 gains,4 regressions,5 withinW, including miss
+2.180%, miss-with-leases+2.101%, synth+0.797% and lease+0.622%; these remain
negative evidence and are not pooled with the next controls.

## Fixed next comparisons

After original exact-source four Linux gates and composition review, build185
once with the unchanged canonical OpenWrt SDK recipe and original size/hardening
gates. Bind actual179-file identity, Linux receipt, ELF, same-link map and build
receipt before any runtime screen. All required transfers finish outside timing.

Use fresh accepted-E controls for each of these independent protocols:

- Original complete hot15/native240:15 scenes,3 grouped user-instruction/cycle
  pairs plus5 plain alternating pairs each, original operation counts/checksums
  and W/direction rules. This checks shared local/cache and fallback behavior;
  the public probe does not recycle owner replies, so it cannot establish the
  buffer-reuse mechanism's CPU benefit. No adverse scene may be dropped.
- Original exact-SDK owner32: low200/s and high-unpaced UDP hits,3 PMU pairs
  plus5 plain pairs per load, original driver/CPU placement and rules. High-load
  variable-N data remain diagnostic rather than low-load acceptance.
- Independent A53ten:5 alternating E/185 pairs,800 names/70-30 A/AAAA,
  1000 prewarm,5s warmup+20s measured,200/s. Keep the original W/direction,
  every-round tick precision and strictly-greater-than8tick median threshold.
  E is source4f869c88/ELF8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27;
  F is only a device restore slot, never a control for these comparisons.

Oracle native/owner timing is sequential and exclusive. The physical A53 run
may proceed in parallel once artifacts, recovery and fresh health are verified.
Preserve every attempt and the existing symmetric tool-invalid replacement
policy; a dnsmasq error is not a tool-invalid window. No selective reruns.

Only supportive measured results can lead to exact-source full44/67 and the
complete11-scene Oracle/device110 matrices. Incremental E acceptance needs a
discernible UDP-hit CPU improvement with no primary regression under the
original rules. A fresh direct v0.2.0 comparison is required for any new total
baseline claim. Historical deltas, standalone prototypes and probe counters
cannot be summed into a performance result. Production remains unchanged.
