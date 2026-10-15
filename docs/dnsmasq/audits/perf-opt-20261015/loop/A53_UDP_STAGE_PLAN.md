# A53 UDP cumulative-path diagnostic, fixed before device measurements

The accepted E/C device gap remains unexplained by the small Oracle screens.
This experiment measures coarse interventions directly on A53 without PMU.
It never changes production, the frozen C oracle, or candidate acceptance.

The independent source is `acec64f2d3f393ef45c958dedbcf715c4cd6d09f`, based on
accepted E `4f869c88`, not on the allocation-meter build or a performance
prototype. One immutable original-SDK ELF supplies every stage mode, selected
once by `DNSMASQ_UDP_STAGE`. Thus modes do not each get a different LTO layout,
although changing control flow still changes cache state and executed work.
The full diagnostic mode must be calibrated against the unmodified E ELF.

Only exact32-byte `q0000..q031f.m6a.test` IN A/AAAA requests with the existing
loadgen header can match. The first1000 matching receive entries cannot select
a cut. The unmodified prewarm load must separately complete1000 correct answers
and populate the800-name cache before any cut. Deferred interface/MAC, TCP,
local/CNAME ownership, reload and nonfixture traffic are outside this diagnostic
contract. Final matching/cut counters plus original traffic/upstream validation
must prove the contract; the prewarm threshold is not a measured completion count.

| Mode | Retained work / intervention |
| --- | --- |
| full | Original E receive, admission, owner, local/cache answer and send; only diagnostic checks/counters added. |
| receive | After successful receive/resend invalidation, synthesize the fixed fixture answer in the existing receive scratch and use the existing UDP send helper; skip admission and synchronous query processing. The ordinary owner loop, speculative EAGAIN and all later service turns remain. |
| before-answer | Retain admission, owner setup/metrics, metadata and interface decision; replace the daemon answer call with the synthetic answer; retain normal post-answer polling/log handoff/send/counter path. |
| skip-local | Enter the ordinary local answer function, retain the cache name hint produced by inspect_name, return no local ownership, then execute the real cache lookup/answer and owner postlude. |

The synthetic replies preserve ID, original question, IN class and correct
A=192.0.2.1/AAAA=2001:db8::1 values with exact48/60-byte lengths. TTL120 is fixed,
so these are not exact-C wire-equivalence runs. Before-answer retains one128-byte
answer allocation, matching the ordinary writer's initial allocation size.
Its assembly work is still different. Receive uses the existing scratch with
no stand-in answer allocation. These known intervention costs are not hidden.

The local fixture checks1600 valid name/type replies with the real wire parser,
rejects outside-range/type/flag/trailing data, and checks the1000-entry threshold.
It passes, as does local Linux-musl all-target compilation before the final
label/allocation-capacity refinement. The first fixture compile error and all
logs are retained. Linux execution and SDK identities must be checked before
starting the device round. Full44 qualification does not apply to intentionally
truncated diagnostic modes; no mode can be promoted as a product candidate.

## Fixed50-window matrix

After fresh original guard/recovery/health checks, use the same original case,
group, fixed loadgen `f7c7d8e9…`,800-name70/30 mix,1000-query full prewarm,
200 queries/s,5-second warmup,20-second measurement and existing resource/CPU
endpoints. No per-query CPU-clock reads or logging are introduced. Five
alternating pairs in each group, in this order:

1. Exact-image C vs unmodified E: fresh same-round gap reference.
2. Unmodified E vs stage/full: instrumentation/code-layout calibration.
3. Stage/full vs stage/receive.
4. Stage/full vs stage/before-answer.
5. Stage/full vs stage/skip-local.

Each group gets its own contemporaneous left controls; never pool them.
Use the unchanged five-pair W/direction and CPU tick-resolution rules to
indicate which coarse differences can be distinguished. All50 attempts are
retained. A failed output, counter, source, ownership or health gate stops the
round without selective replacement. Archive/verify before reclaiming valid
temporary device copies, as in the already fixed controller.

Every window must produce6000 correct fixture replies in total, zero timeout,
wrong, transport or skipped counts, and no steady upstream queries after
prewarm. Diagnostic windows require matched_queries=6000. Full has zero cuts;
each other mode has exactly5000 cuts only in its selected slot. Require the
normal daemon exit0 and complete namespace/ELF/guard identities. Sidecar output
is obtained only after the timed CPU endpoint. The single-thread/process
assumption is checked from existing resource samples and final endpoints.

Report original C/E, full-mode calibration and stage contrasts separately.
Do not mechanically subtract calibration overhead, add stage differences, or
label an adjacent delta as the original function's exact cost. The stand-in
writer, preserved function prologues, branch prediction and different cache
access patterns are material limitations. A large coarse difference guides the
next real implementation; that implementation must undergo all normal gates.

Allocation evidence is separate: three A53 E+meter windows measured5 successful
Rust allocator requests and5 releases,0 reallocations,270 requested/released
bytes per cached step. Cached-only owner turns matched; mixed/no-packet turns
remain separate. This count-only ELF exceeds the release-size budget and all
its timing is excluded. The code path is consistent with two32-byte decoded
names, a14-byte dotted name, a64-byte first Vec<EntryId> allocation and a128-byte
answer buffer (270B); that site mapping is source-derived, not an independently
captured allocation-size/backtrace histogram or proof of each allocation's CPU
cost. F removes the first name allocation; existing singleton/dotted prototypes
address the64B/14B requests. Their native counts do not establish A53 CPU wins.
