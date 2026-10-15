# Correctness progress — 2026-10-15

Branch `perf/dnsmasq-correctness-20261015`; coordinator owns router scheduling.
No optimization product code is written here. No router connection was made.

- Freeze: `4ef4b8bc`; gate expectations remain unchanged.
- Baseline source `51b039597af13f9c9cf07c9f80e388e25cd8ae5d`, fresh musl tests:
  lib **808 passed / 0 failed / 20 ignored**; bin **81 passed / 0 failed /
  3 ignored**. Each used its own namespace and tmpfs `/tmp`, serial execution.
- Allocation integration **16/16** and 19 formerly ignored namespace/C-config
  tests **19/19** passed. Total fresh Rust tests: **924**. Four existing
  frozen-clock corpus drivers remain pending; they are not counted as passes.
- Deployed original ELF `8472be5a…` passed fresh F10 **13/704** against the
  restored original reference and unchanged manifest: 0 unqualified failures,
  19 observed-track and 8 source-bound order qualifications retained. Fresh
  protocol **368 pairs** passed (366 byte matches; the two established C
  forward-pointer defects remain exactly classified), all five negative
  controls rejected.
- Canonical family environment preflight passed the first three complete
  families, **40 + 40 + 56 scenarios**. The coordinator requested a timing
  boundary, then the full run was retired after its current child finished;
  all original outputs remain. Finalist A will receive all 44 families fresh,
  without inheriting these results. See [receipt](baseline-preflight-receipt.json).
- Exact-image F10 original C reference recovered byte for byte. All 13 original
  case JSON hashes and the 909,279-byte full JSON hash match the existing Git
  index; canonical hash also matches the unchanged approved manifest. See
  [F10_RECOVERY.md](F10_RECOVERY.md). This removes the missing-reference blocker.
- Matching C source restored into a private copy from retained upstream sources
  plus the two matching OpenWrt patches. `forward.c`, `dnsmasq.c`, `util.c`,
  `cache.c` hashes all equal the existing source identities. The complete
  148-file source identity was reconstructed and matches original SHA
  `62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9`. Native C/UBus helper
  build completed; it is an auxiliary fixture dependency, not image authority.
- TCP upstream parity attempt 1 exposed a harness input-mode issue: the
  router ELF copy was mode 0644, and this harness preserves mode. F10/protocol
  explicitly chmod their staged ELF. A separate 0755 copy retains the exact
  `8472be5a…` bytes; the complete TCP three-group attempt 2 is running in new
  directories and all three groups passed (13 conditions / 50 query pairs).
  Attempt 1 remains with all exec-126 failures.
- The environment-only fresh native-host release is `37fd4439…`, 2,126,304 B,
  with its same-build map. It is neither deployed `8472…` nor historical
  `50e…`, and provides no device performance baseline or candidate acceptance.
  The coordinator is doing the actual SDK recipe and host-toolchain controls.

Independent static reviews completed, all with no behavioral blocker identified:

| Candidate | Review scope / remaining qualification |
| --- | --- |
| `2256fcf7` DNS name validation | Expanded length, pointer hops, cursor/extra/error ordering and validation-only callers preserved; full gates pending |
| `c5b461e8` DHCP hex encoding | 191/192-byte bounds, delimiters, lowercase, partial writes and persistence error path preserved; full gates pending |
| `f489317e` TCP framing | Prefix/payload offsets, fragmented input, 100-query close and stale refresh sequencing preserved; retained answer Vec capacity can increase waiting-client memory and must be measured; full gates pending |
| `a47cc656` upstream name validation | Both replaced names were discarded; validation-before-mutation and error ordering preserved |
| `23b93d3c` lease-name borrowing | ASCII lowercase keys and temporary Cow lifetime preserve map/expiry behavior |
| `70390467`, `b0b9ab77` local dotted-name scratch | Original query versus CNAME traversal retained; validated wire bounds dotted output to 253 bytes within 255-byte stack storage; binary/dot/root handling preserved |
| `360ec9c1` UDP borrowing | Synchronous call tree does not receive again into the taken buffer; every deferred retention owns its bytes |
| `e1bdcd4a` upstream poll scratch | Interests/deadlines rebuilt each turn; EINTR repeats timers, errors clear transactions and return scratch capacity |
| `83f57066` hosts map removal | Static behavior review had no blocker; author rejected PMU presence regressions and reverted, so excluded from A |
| `b838a2c6` single hosts representative | Remapping skips retained lease prefix and retains surviving static representative; author asked to test source-removal presence explicitly; PMU/full gates pending |

Coordinator device controller review found and corrected guardian PID-reuse and
case-completion coverage gaps before baseline start. The updated controller checks
PID/starttime/executable at group entry, polling and completion. Error exits before
archiving still require preservation of the attempted run and guard logs; this was
explicitly handed back. The measurement C sources were not modified in this review.

Candidate A is frozen at source `a7164697ba8d27e8bea2e37a7f1c783533acb240`,
actual SDK ELF `b353039e1e85cb2b91a9539460dc6623532757699e6a63f5cf20482d7946952e`,
2,128,667 B. Source: `/home/ubuntu/dnsmasq-perf-20261015/root/source-a`; ELF,
same-build map and receipt: `root/private/sdk-a`.

- A fresh tests: **812 lib + 81 bin + 16 allocation + 19 namespace/config =
  928 passed**, no failure. The four frozen-clock probes are still pending.
- A F10 **13/704**, protocol **368 pairs / five negative controls**, and TCP
  **13 conditions / 50 query pairs** passed on that exact SDK ELF.
- A full 44-family run is active under `correctness/private/a-families` (tool
  session 57938). First five families passed; source is not modified during it.
- At coordinator request the supervisor PID 3774748/starttime 174196337 alone
  was stopped while its current lease-name family finished normally. Child
  3793539 exited naturally before `QUIET_READY`. No case was signalled. The
  coordinator’s 100-second DHCP timing slot must finish before `SIGCONT`.
  `a-quiet-pause-1.json` records this scheduling pause; idle after child exit is
  harness time, not product duration. The supervisor must be resumed promptly.
- Original cache-transfer C fixture restored: original native ELF and both
  libraries match their historical SHA, all 148 source files match, and all
  216 stdout hashes aggregate to the original constant. The coordinator
  independently reviewed the recovery builder. See
  [TRANSFER_RECOVERY.md](TRANSFER_RECOVERY.md). No golden behavior changed.

Next: resume A supervisor after the timing reservation; run A's four
source-bound corpus probes using the restored C inputs; collect all 44 families.
No full candidate has passed yet.

Reviewer clarification: PacketWriter initially reserves `min(limit, 128)`, not
512. The first informal TCP memory note misstated this constant; the author’s
capacity screen uses the correct 128 and records the retained-capacity cost.

The offline performance analyzer’s quantiles/median/W/direction/CPU precision
formulas were reviewed against the frozen protocol. The review requested DORA
quantiles/maxima and 150-client comparisons, while keeping six-client DORA
descriptive, and independent raw counter validation. Those additions remain
the coordinator’s work; this reviewer did not alter workload or statistics.

Further static B reviews completed: terminal cache-only memory retirement
`77d143a7`, blockwise cache clear `42f3514d`, unused-unique name roots `2979b341`,
hosts live-count map `5c2c985b`, and lease publication key borrowing `745212bb`.
No behavioral blocker was identified. Clear2 changes name-root allocation/free
interleaving (old entire vector replaced, new roots retired one by one); it does
not retain populated buckets or defer shared-root separation to first insertion.
The terminal retirement has one caller at final successful daemon exit, after
all explicit helper/lookups/log/PID cleanup; Cache's recursive fields own no FD
or custom Drop. These reviews do not transfer A or baseline test passes to B.

## Continuation recovery, 2026-10-15 morning

Read-only recovery found A's original full run had finished at all **44 families,
67 unique jobs**: **66 jobs passed**, `ubus-ordinary-all` failed its registry
count check. Summed job time was 6,245.47 seconds (104.1 minutes), including the
previous scheduling pause in a child interval; this is not a performance metric.
The stopped sudo monitors only parent zombie completed Python supervisors, not
active workload. The original raw outputs remain untouched. A also retains its
independent 1,098/1,100 stale-corpus failure and is not qualified. See
[recovered evidence](continuation-recovery.json).

The UBus failure is an existing frozen-input inconsistency, not four missing
executions. Pre-freeze commit `72e843ed22d24a9bad9dba9a822d638c29909144`
replaced three top-level recovery observations with one richer composite for
each of two collision orders. Its source-bound checker changed recovery 17 to
13 and expanded negative controls from 10 to 26. The registry retained total
350, although the unchanged tool now requires 69+216+19+29+13 = **346**. Fresh
A produced exactly 346 pairs, 2,146 passing assertions, no failed assertions,
and 26 rejected negative controls. The richer records still check both object
lookups and logs, plus metrics before/after and DNS health. Adding four duplicate
records would not restore a missing semantic case.

[Exact diagnosis](ubus-inventory-diagnostic.json) preserves source hashes and the
historical diff. The [proposed two-number metadata patch](ubus-registry-bookkeeping.proposed.patch)
is **unapplied**, awaiting the coordinator's explicit user boundary decision.
No fixture, comparator, C behavior, source expectation or frozen file was edited.
`git apply --check` accepts the proposal; it is not an acceptance result.

The supplementary live stale-boundary matrix finished all eight cases per ELF:
finite/min-max × UDP/TCP × ordinary/TXT-terminal. All ordinary pairs match;
all four TXT-terminal pairs expose old v0.2.0 EDE3 plus an extra upstream query
where exact C produces neither. Original initial finding and probe are retained
as `stale-finding-receipt.json` and `stale_cutoff_daemon.py`; their pending flags
record the earlier checkpoint. The coordinator reports that the user explicitly
approved separate compatibility fix `b1136023` during this continuation. It may
now enter a newly frozen candidate; it does not retroactively qualify A/B.

Independent current static reviews identified no behavior blocker:

- `4d717b87`: UDP atomic socket flags equal the retained SDK definitions;
  OwnedFd lifetime, IPv6-only setup, port randomness/retries, interface binding,
  and binding-error classification are preserved. Exact SDK `sys/socket.h` has
  DGRAM 2, NONBLOCK 04000, CLOEXEC 02000000; `bits/fcntl.h` confirms the flags.
- `4e8d548e` and current D6 refinement: singleton lease index preserves ordering
  by reverse/mortal/immortal group and first-entry parent-expiry extension.
- `72d1cbb7`: immutable lease name sharing keeps every input, mixed-case and PTR
  spelling, suppression/rebuild order, and per-reader active state. Fallible
  hosts replacement still receives borrowed bytes and retains its `try_*`
  allocation boundaries. This remains a prototype until selected by its owner.
- `4b054367` plus `71e7178d`: query-local cache hint adds no Arc pin/COW;
  owner/root/Name identity, index revision and generation validate reuse.
  Actual expiry removal, CNAME validity and LRU effects remain at lookup time;
  all mutable index accessors invalidate hints, saturation disables them, and
  the multi-record loop is unchanged. The bounded synchronous call site does
  not replace its Cache while the hint is live. Full fresh candidate gates
  remain required for every selected change.

The carried per-family scheduler now records duplicate-free exact 67-job
coverage and exact C identity as requested in its earlier review. It preserves
unchanged original runner calls and waits only before a new family. No new
Oracle build, correctness execution or timing was started in this continuation.

The new scheduler supports `--jobs 1` (default, original family order) or up to
three independent family runners. Parallel mode starts cache, listeners and
logging first; each family keeps its original serial jobs and fresh nested
output. No source/build directory is mutated by the supervisor. UBus compiles
its helper into its own family output and verifies the shared inputs read-only.
A global `PAUSE` marker prevents new dispatch; existing families drain naturally,
and `state.json` reports `paused-before-family` with an empty active list only
when quiet. Any failure stops new dispatch and retains all finishing active
results. No case receives a scheduling signal. Five local orchestration controls
passed: three-worker bound/completeness, serial order, duplicate-job rejection,
wrong-C rejection, and pause/drain/resume. These are supervisor tests, not product
passes. Expected full wall time with three workers is roughly 35–45 minutes,
subject to existing deadlines and host load; a pause may need up to a full cache
family (about 23 minutes) to drain. Do not mix this work with performance timing.

Finalist family invocation, after coordinator freezes its exact source/ELF/map
and resolves the registry decision (the source variables identify that finalist):

```sh
CARGO_BUILD_JOBS=1 python3 "$correctness/run_family_gates.py" \
  --source "$source" --elf "$elf" --link-map "$link_map" \
  --commit "$commit" --base-identity "$correctness/private/family-base-identity.json" \
  --out "$correctness/private/c-families-attempt1" --jobs 3
```

The scheduler itself can be copied from this evidence directory into the Oracle
correctness root. Output must not exist. `touch .../PAUSE`, wait for the empty
active list/`paused-before-family` state, then `rm .../PAUSE` implements a safe
reservation boundary. All other required gates retain the command forms in
[FROZEN_GATES.md](FROZEN_GATES.md); family success does not replace Rust,
four frozen-clock corpus, protocol, F10 or TCP gates.

Further static reviews: `93190195` insertion-name copies and `97a975a5` same-call
hosts bucket reuse have no behavior blocker. The length-only wire helper equals
escaped dotted length (including root and escaped 0/1/dot bytes), keeps the 75-byte
limit and counter ordering, and removes only discarded infallible temporaries.
Reverse-name clone remains before name-index publication. Hosts bucket reuse
keeps both scans and IPv4 rotation; no hosts mutation/capacity change intervenes.
The cursor owner subsequently rejected the reviewed hint on configured-CNAME
performance; its static review is not a recommendation to integrate it.

## Independent base2 archive audit

[Offline audit](base2-independent-audit.json) verified all **110 unique windows**
and the five alternating C/R rounds in each of 11 scenes. It independently read
all 110 archive hashes and **3,430 files twice** (archive member and extracted
copy), recomputed each traffic/lifecycle latency quantile, scheduled latency,
CPU-counter denominator and DORA quantile without importing the analyzer.
Observed counts: 60,000 warmup + 240,000 measured successful traffic operations,
1,560 DORA observations and 800 lifecycle observations. All match the exported
baseline. All 11 guard segments cover their raw start/end intervals and keep
production PID/starttime, memory floor, DNS and IPv4 default route intact.

The TCP-hit final HTTP probe has status 0 at guard shutdown, seven seconds after
the last measured window ended. The source signal path and immediately following
`monitor_stopped` establish a terminal cancelled probe; it is explicitly retained
and **not counted as a passed HTTP check**. All completed HTTP checks are 403.
External IPv4 and IPv6 each have 126 successful HTTP200 checks; observed maximum
latencies are 1,305.659/1,089.199 ms. The external check is a connectivity gate,
not the local 200 ms production-DNS threshold. Local audit construction attempts
(prefix handling, epoch precision, cancellation classification) are retained in
the receipt; none altered or repeated the underlying measured windows.

The coordinator reports the user approved the exact UBus metadata correction,
now committed as `e26a40ab` with original/new hashes and explicit amendment.
New full candidate gates must consume that amended snapshot; the old freeze and
A failure stay unchanged. The user also authorized necessary research/tool bug
corrections during continuation; no deployment or router modification follows
from this permission. Correctness remains Oracle-idle pending finalist freeze.

## Lease insertion diagnostic contract recovery

[A's four recovered corpus results](a-corpus-recovery.json) are now explicit:
cache-answer 164 queries + 382 metric snapshots without differences; transfer
307/307; stale 1,098/1,100; lease insertion 36 cases/269 commands/95 queries/43
dynamic lookups with two differences and original comparator exit 1.

The lease comparator has no existing executable qualifier. Its historical
[contract](../../../LEASE_CACHE_INSERTION_PHASE.md) expressly retains every
C difference and says cohort labels do not turn failure into pass. Exact
original source `51b03959` was replayed freshly using its hash-bound test ELF:
all 36 cases ran, and it has the **same two** `fqdn-short-republication-same`
Q/N differences as A. C supplies `alias -> example`, absent any input supplying
that target, while Rust misses; original counts remain C 59/36 versus Rust
58/37. An independent unchanged `--repeat-reference --rounds 8` reran all four
layout cases 32 times: all four had multiple outputs; 12 answers invented a
CNAME target. Neither C corpus nor comparator changed. The first replay attempt
had a serial-libtest-prefix parsing issue, and the first C repeat invocation
was rejected by its output-root guard; both attempts are recorded and retained.

[Source/fixture/baseline-bound contract evidence](lease-compatibility-contract.json)
records every concrete input/config, original C stdout and original Rust semantic
hash, plus the fresh C/C diagnosis. The coordinator authorized a separate narrow
qualification audit under the user's research-tool repair permission. It must
preserve original exit 1 and all observations, reject any new/unclassified
change, require exact baseline Rust behavior for all 269 commands, and enforce
that no layout-reuse answer invents an upstream CNAME target. This is distinct
from a zero-difference C comparison; no such pass is claimed.

## Candidate C short gates and explicit acceptance decision

Frozen C is `f7f7a2edd9f2ecfac72953e43cfc873a354b468b`; the coordinator's exact
SDK ELF is `b4c4a8e40698feb7aa57da09699bb2988ac1cf4bb54345474a9f659a12edcda1`,
2,136,859 bytes, with its same-build map. Fresh source-bound musl tests passed
**824 lib + 81 bin + 17 allocation + 16 ignored lib namespace/config + 3 ignored
bin namespace = 941**, with no failure. Each gate ran serially in fresh
network/mount/PID namespaces with private tmpfs `/tmp`. Ordinary tests still
show 23 ignored: 19 were subsequently exercised, four corpus drivers remain.
[Receipt](c-short-gates.json) records artifact hashes and exact raw paths.

The user subsequently explicitly directed: the existing two UID-reuse C
observations **do not block acceptance**; retain them and the original raw
comparator exit 1, while any new/unclassified failure blocks. The user requested
no new qualifier framework and prioritized full Oracle timing, full 44 families,
then router comparison. The uncommitted qualifier draft was immediately retired
to ignored private storage, never run; it is not an acceptance requirement.
The earlier diagnostic baseline/C-repeat evidence remains factual and unchanged.

Correctness is idle for the coordinator's exclusive full 110-window Oracle run
started at 10:40 CEST. After release, launch fresh C 44-family scheduler with
three workers, then exact SDK F10/protocol/TCP and the four source corpus probes.
Original output paths and all failed attempts stay intact. No candidate C full
correctness pass has yet been claimed, and no router operation was performed
by this reviewer.

## C complete gate run launched after Oracle timing

Oracle performance `complete.json` and all progress rows confirmed **110/110
valid**, with no failure file, before correctness launch. The unchanged family
scheduler started as PID 4064310, output `correctness/private/c-families-attempt1`,
with three workers; a fourth serial batch (PID 4068233) owns release-probe build,
F10/protocol/TCP and the four original source corpora. Both use immutable source
`f7f7a2ed`; daemon checks use the actual SDK `b4c4a8e4…` and same-build map.

[First boundary batch](c-boundary-gates.json) passed: F10 **13 cases/704 DNS
observations**, complete healthy processes with exact SHA, zero unqualified
failures. Raw `matches_c=false` and all **16 PTR-order differences** remain
visible under the unchanged approved manifest; 72 PTR sequence checks and four
source-bound contract checks ran. Protocol passed **368 pairs/366 exact wires**,
only the two existing C forward-pointer defects, eight healthy daemon lifecycles,
and all five negative controls rejected. Existing checker/tool tests passed
**24 + 7**. The receipt also binds the authoritative 941-test raw log hashes.
TCP and all-family/source-corpus final results are still pending; no C full pass
is claimed from this first batch.

[C's TCP/corpus batch](c-tcp-corpus-gates.json) is complete. The three original
TCP groups passed **13 conditions/50 pairs (37 TCP + 13 UDP)** with zero
comparator differences, exact C/Rust process hashes, healthy parents and clean
cleanup. Each implementation has precisely the original expected 2 s timeout
for short `v4-warm-drop`; no other query failed.

The four fresh source-bound corpora ran in full: cache-answer **764 commands,
164 queries, 382 metric snapshots, zero differences**; cache transfer **307/307**;
stale metadata **1,100/1,100**, zero omissions or differences. Lease insertion
ran **36 cases/269 commands/95 queries/43 dynamic lookups**. It retains exactly
the historical two differences in case 26 (`fqdn-short-republication-same`),
steps 9 and 10: C invents `alias -> example` and counts a hit, while Rust misses.
The full difference objects match A and original source's fresh replay exactly;
ordinary-insertion mismatches remain zero. **Raw comparator exit 1 is retained**
and these two differences are nonblocking only under the user's explicit
instruction. No new qualifier or changed C expectation was introduced.

All remaining-gate batch processes completed. The three original full-family
workers continue unchanged; full 44-family completion is the last pending
correctness requirement before the coordinator can admit a device comparison.

## C correctness complete

[Full 44-family receipt](c-full44-gates.json): **44/44 families and 67/67 unique
jobs passed**, with zero new or unclassified failure. The reviewer independently
rehashed all 44 family result files, all 67 original job result files, and every
supervisor-bound input after completion. The exact SDK ELF remains `b4c4a8e4…`,
2,136,859 bytes; its same-build map is
`9ed8e0a304e0a3333bb9f23d685171802c61f5688ec734e209a7622ade17da0a`.
The full run completed in 2,063.77 wall seconds (34 min 24 s), with no scheduling
pause, replacement run or retry. This elapsed time is a harness scheduling
observation, not a product performance claim.

UBus now passes the explicitly amended bookkeeping expectation: **346/346 paired
observations**, zero assertion failures, and all 26 negative controls rejected.
The actual comparator and all original C behavior observations are unchanged.
The complete family raw-result SHA is
`5adec1f15a5097db92668135d86197a2112ad168c310a1a19251984d42ec76ff`.

C has completed every required correctness execution: 941 tests, F10 13/704,
protocol 368 pairs, TCP 13 conditions/50 pairs, all four source corpora and all
44 functional families. Existing approved PTR-order and C forward-pointer
classifications remain explicit; the two historical lease UID-reuse differences
retain their original raw comparator exit 1 and are nonblocking under the user's
explicit instruction. No all-C-zero-difference claim is made. No new failure was
found, and no product or expectation was modified during these runs.

The coordinator was notified that correctness admission for its separately
controlled device comparison is clear. This reviewer made no router connection,
staging, production change or deployment.

## Independent D9f2 review after C's first device scenes

Reviewed the actual `9f2a9052` expiry-bound product diff against frozen C
`f7f7a2ed` in the expiry worktree, at HEAD `587fb82c`. Product hashes were stable:
`cache.rs` SHA256 `ca58d8711daa4520ac4874f35c2994cf7591988230c8dda3f8c82788a6fa6a49`;
`cache_tests.rs` SHA256 `39b5f1a72967e7925ba6d88f4b1433e2862701e3d698527c95de5ae6cdbec6f9`.
No concrete behavior defect was identified. C was not modified.

For every committed deadline E, bound B remains at most E. Commit is the sole
transition to committed state and lowers B after rejecting outdated CNAMEs.
Ordinary removal, reverse removal, lookup expiry, DHCP invalidation, failed
insertion and pending abort can only leave an earlier conservative B. The
necessary pressure scan retains original ascending-slot removal, LRU, spill
and counter effects while rebuilding B from committed survivors. Referenced
same-name replacements and imports use that same commit path, including import's
already selected absolute deadline. Snapshot copies B by value; clear resets it.
There is no current in-place deadline or retention-policy setter; the existing
max-reply-TTL setter does not change expiry decisions.

Independently checked predicate implication: expired(E, now) implies
expired(B, now) for Disabled and finite Seconds, with exact i128 subtraction;
Forever cannot expire anything. This holds at equality, at signed extremes and
for backward clocks. Thus a skipped scan had no removals in frozen C. The old
global pressure scan checked only TTL expiry, so unexpired invalid CNAMEs do
not create a missed cleanup; their conflict, lookup and victim paths are intact.
No additional allocation or fallible boundary was introduced. The scalar's
layout/performance cost remains the screening owner's measurement obligation.

The existing local log reports 41 cache tests passed, including forced-scan
state/counter comparisons and snapshot/import coverage; this reviewer inspected
it without rerunning tests. No Oracle workload or router access occurred. If
screening qualifies D, existing complete gates must run freshly on its exact new
SDK output. C's currently running device comparison is unchanged.

## D short gates ready for full Oracle screening

D is frozen at `9f2a905289c6c009edd747abc590a1d013b114e5` (epoch 1792053656),
immutable Oracle `root/source-d`. Its cache source hash equals the independently
reviewed `ca58d871…`. Fresh same-source musl tests passed **826 lib + 81 bin +
17 allocation + 16 ignored lib namespace/config + 3 ignored bin namespace =
943**, with zero failures. Each test group uses the unchanged C execution
recipe: fresh network/mount/PID namespaces, private tmpfs `/tmp`, exact image C
for config acceptance and serial test execution. [Receipt](d-short-gates.json)
records all artifact identities, raw log hashes and source-bound receipt paths.

The copied feature-off release corpus probe was built before the timing window,
with unchanged existing build tooling and one Cargo job. All correctness build
and test processes have exited; the coordinator received READY/IDLE and may
reserve the full D 110-window Oracle timing. No full-family or daemon/corpus gate
has yet run for D, and no C gate pass transfers. D remains a screening candidate;
the incremental CNAME micro caveats do not change the frozen final comparator.
The existing two UID-reuse differences retain the explicit user decision and
raw exit 1. No new framework or qualifier was introduced. No bulk raw data was
downloaded during the coordinator's continuing C router test.

## C device attempt: independent LOCAL-only audit

[Local audit receipt](c-device-independent-audit.json) verifies all **110 archive
hashes and 3,430 files twice**, as archive members and extracted copies, without
Oracle/router/network access. All planned alternating pairs remain present.
Counts match raw data: 60,000 warmup and 239,987 measured correct operations,
1,560 DORA observations and 800 lifecycle observations. Independent recomputation
also matches all 110 latency/CPU windows and all 32 ranked metrics in ten valid
scenes; no analyzer discrepancy was found.

**C has not passed complete performance acceptance:** 110 attempts, 109 valid,
primary summary `complete=false`. `candidate-c-tcp-miss-r2-rust` retains 4,000
scheduled, 3,987 sent/correct and 13 skipped operations; its original errors and
all raw files remain. The entire TCP-miss scene is absent from comparisons.
The attempt controller's `complete=true` only says the planned sequence ended.

Diagnostic improvements are confined to valid scenes: DHCP-150 renewal p50
−33.59%, combined CPU −33.58%, and DORA p50 −23.94%; config-small p50 −15.46%;
large-HUP p50 −15.52%; home6 renewal p95 −5.33%. All six metrics have 5/5 paired
direction and clear their existing spread/precision gates. No valid-scene
regression is discernible; remaining metrics, including the four valid DNS
scenes, are inconclusive. DHCP CPU includes warmup plus DORA/renewal, and home6
DORA remains descriptive. These findings do not rescue whole-C acceptance.

All 11 guard segments cover their raw windows: 3,868 samples, stable production
PID/starttime and IPv4 default route, memory floor 67,828 KiB, 1,518 successful
DNS probes (maximum 11.832 ms), and 701 HTTP403 checks (maximum 150.507 ms).
External IPv4/IPv6 each has 128 HTTP200 checks. No terminal cancelled probe or
new guard failure occurred.

The separately recorded 9,489,587-byte transfer's local write interval overlaps
`udp-miss-r1-rust`; its uncertainty remains attached to that scene. The invalid
TCP window starts 1,265.5 seconds after the recorded transfer end, so there is
no temporal overlap or evidence connecting the events. No transfer correction,
selective replacement or altered zero-skips rule was applied. The coordinator
was told every C archive is locally verified for its separately controlled
remote-copy cleanup. D's exclusive Oracle screen was not touched.

## D complete gates launched after its Oracle screen

The D Oracle output was independently checked before launch: `complete=true`,
110 windows, 110 valid progress rows and no failure file. Fresh 44-family
scheduler PID 13199 uses three workers under `correctness/private/d-families-attempt1`;
fourth serial batch PID 13200 owns F10/protocol/TCP/source corpora and existing
checker tests. The already-built D release probe is reused. Both run immutable
source `9f2a9052` with exact SDK ELF
`4167609f5fe1c17a480f0a395fba1e3c15142f6c2ad7c3998d133a04829965e8`
and map from `root/private/sdk-d-fresh-prepare`. The earlier source-prepare-guard
failure at `sdk-d` remains preserved and is never used for qualification.

[First D boundary receipt](d-boundary-gates.json): F10 **13 cases/704 observations**
passed with exact running-ELF identities, healthy complete cases and zero
unqualified failure. Original PTR-order differences remain recorded under the
unchanged approved manifest. Protocol **368 pairs/366 exact wires**, eight
healthy daemon lifecycles and all five negative controls passed, retaining only
the two established C forward-pointer classifications. Existing F10/TCP tool
checks passed **24 + 7**. TCP, source corpora and full 44-family completion remain
pending; no D full correctness or device acceptance is claimed here.

[D's TCP/corpus batch](d-tcp-corpus-gates.json) completed with the exact corrected
SDK output. All three TCP groups passed **13 conditions/50 pairs (37 TCP,
13 UDP)**, zero comparator differences, matching running binary identities and
clean healthy teardown for all 26 processes. Each side retains exactly the
expected short `v4-warm-drop` 2 s timeout; no other query failed.

Fresh source corpora: cache-answer **764 commands/164 queries/382 metric
snapshots**, zero differences; transfer **307/307**; stale **1,100/1,100**, no
omissions or differences. Lease insertion again runs all **36 cases/269
commands/95 queries/43 lookups**, with exactly the same two user-accepted C
UID-reuse differences (case 26, steps 9/10), zero ordinary mismatches, and its
original raw exit 1 preserved. No new or changed difference appeared.

The fourth serial batch has exited. Loop was notified that the coordinator's
one-slot count-only cardinality experiment may run there; the existing three
full-family workers continue unchanged. Full 44-family completion remains the
only pending D correctness requirement before device-comparison admission.

## D full-family failure: device admission blocked

The unchanged D full44 attempt encountered a new mismatch in
`m5_interface_records-service`, case `hostsdir-dhcp-name-effects`, at the
`initial-helper:helper` observation. Exact C emits `original`, then an empty
name, then `fromhosts`; D emits `original` twice. All six DNS observations and
the subsequent changed/removed helper rows match. The absent initial `fromhosts`
event does not appear in later captured helper rows. Both actual executable
identities, one-thread owners, expected UID0, readiness, exit0 and clean teardown
are verified. The fixture has `cache-size=0` and no forwarded queries; a direct
role of D's new dynamic-cache expiry code is not established.

[Original failure receipt](d-interface-service-failure.json) preserves exact
argv, raw result/log hashes, all synthetic observation rows and the corresponding
successful C-candidate case. The service executed all 276 cases and reported
one failure. The supervisor stopped dispatching new families and allowed its
active children to finish naturally: **38 families finished, 37 passed; 54 jobs
finished, 53 passed**. Remaining families were not run. No process was signalled,
no result replaced, no expectation changed and no retry was used to hide it.

**D is not correctness-qualified and must not enter device comparison.** The
coordinator was notified immediately and owns the fix/reproducer decision.
Original helper capture sleeps 0.25 s before reading its log; a simple delayed
log explanation is unproven because the expected events never appeared in later
rows. Local product-path inspection has been delegated to the DHCP owner.
Neither a product regression nor a harness defect is yet established. The
successful 943 short tests and daemon/corpus batches remain useful evidence but
do not override this new failure.

A separately planned [fixed nine-run diagnostic](d-helper-fixed-diagnostic.json)
used the unchanged single-case runner/fixture and 0.25 s collector, rotating
original v0.2.0, candidate C and candidate D through three rounds each. This
is not a replacement gate. Exact C renamed in all nine current-case executions;
v0.2.0 renamed in 3/3; candidate C renamed in 2/3 and retained `original` in 1/3;
D retained in 3/3. Thus one unchanged C-candidate ELF exhibits both helper states
across processes. The original D full-family failure remains unwaived.

The first diagnostic launch was rejected before executing a case because the
original runner forbids `--ordinary-scope all` with `--case`; that attempt and
logs were preserved, then a fresh explicit partial diagnostic output used only
`--case`. The outer collector could not retrieve final helper/lease files after
the isolated namespace's temporary overlay vanished. Null captures are recorded;
no final-log completeness is claimed. All original per-phase observations are
retained. The missing initial `fromhosts` event does not appear in later slices.

The coordinator located earlier source-bound C/C mixed-reverse-chain variation
in the existing F10 DHCP report, and the DHCP owner identified the corresponding
`provider_reverse` first-DHCP-node suppression path. That is a causal hypothesis
supported by existing code; exact C did not show retention in these nine current
case runs. No product change, new qualifier, case waiver or inferred acceptance
was introduced by this reviewer. Further minimal diagnosis, if needed, must
capture the lease/helper state before its namespace exits.

## Corrected D diagnosis: real initial-publication defect, not old HUP variation

The remaining six original families were each run once, and all passed. The
four previously unrun interface steps also executed once against original
inputs: three closeouts passed; the original qualifier rejected the original
failed service result and created no `qualified.json`. Overall coverage is now
**67/67 unique original tasks, 65 raw passes and two raw failures in one family**,
or 43 raw-pass families and one failed family. The original full-attempt result
remains false. [Complete coverage and diagnosis](d-startup-defect-diagnosis.json)
retains every result hash and the qualification rejection.

The final fixed three diagnostic pairs captured initial lease files, process
maps and complete final helper logs before namespace exit. This time all sides,
including D, renamed to `fromhosts`. Together with the earlier fixed runs, Rust
layout explains its retain/rename variation. However, **that does not establish
C compatibility at startup**. Offline exact C bucket counterexamples show C
renaming even where a hypothetical old DHCP node would precede the static host.
Both this reviewer and the DHCP owner independently found that discrepancy.

Matching C source resolves it: `lease_init` marks DNS dirty without publishing
DHCP cache nodes; the first helper queue turn freezes the old event, then
`EVENT_INIT -> clear_cache_and_reload` reads hosts and runs
`lease_update_from_configs` **before the first `lease_update_dns`**. Rust instead
runs DHCP file initialization and `maintain(force_dns=true)` first, publishing
`original`; its initial hostsdir rebuild then retains that premature DHCP node
and can suppress the required rename through `provider_reverse`. The historical
mixed-chain C/C record concerns HUP/reload with already-published DHCP nodes,
so it cannot waive this initial-publication defect.

The reviewer's brief preliminary device-admission statement was withdrawn as
soon as this counterevidence appeared, before the coordinator launched a device
controller. **D remains unqualified and must not proceed to device comparison.**
This is a pre-existing Rust startup defect exposed by process layout, not a
reason to alter C expectations or emulate a new C exception. A separate next
candidate must fix initial DNS publication order while preserving the frozen
original helper event, with deterministic tests covering both relative bucket
orders and the existing full qualification workflow. Frozen D and all failed
observations remain unchanged. No new random sample, seed search or qualifier
framework was introduced.

## Independent E startup repair review

Reviewed separate fix `4f869c885b47dcf60d56c872e5b0b3c62237beea` against D:
17 lines in `main.rs` plus a deterministic six-scenario owner regression.
[Review receipt](e-startup-fix-review.json) identifies source and observed test
hashes. No concrete static blocker: only the initial hosts bulk scan omits
provisional leases; the existing first-publication latch also covers HUP while
initial work remains. Runtime HUP still retains its old mixed chain. The frozen
original helper event, actual stored leases, fallible publication and cleanup
boundaries are preserved. Empty lease state is constructed lazily only for the
initial path, avoiding extra runtime-HUP initialization.

Independently read the retained Linux logs: original D plus the new test fails
exactly initial/initial-HUP with DHCP-first order; runtime HUP's two legal states
already pass. The repaired build passes all seven hostsdir owner tests, one
initial-HUP test and four TCP import tests. Before and after binaries/logs remain
separate. No test was rerun by this reviewer. The coordinator may freeze E and
build its exact SDK; fresh complete gates remain mandatory, and D stays failed.

## Frozen E full correctness running

E is immutable source `4f869c885b47dcf60d56c872e5b0b3c62237beea` at Oracle
`root/source-e`; exact SDK `root/private/sdk-e/dnsmasq-rs` SHA256
`8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27`,
2,136,859 bytes. The unchanged full44 scheduler runs three workers once under
`correctness/private/e-families-attempt1` (PID125922), retaining original order,
inputs and thresholds. Fourth serial batch PID127963 builds allocation/probe
artifacts and runs fresh short/daemon/corpus gates. Timing waits until the
coordinator reserves the host after correctness completion.

[Fresh E short execution](e-short-gates.json) passed **826 lib + 82 bin + 17
allocation + 16 ignored lib namespace/config + 3 ignored bin namespace = 944**,
zero failures. Rather than recompile the already-tested debug binaries, the
reviewer compared every one of 172 DNS/UBus component/test inputs against the
DHCP owner's repaired source and verified copied ELF identities. Original build
receipt paths remain unchanged; a separate reuse binding records this evidence.
All short groups were freshly run in isolated namespaces/private tmpfs with
serial execution. Allocation executable was freshly built. No D pass transfers
and no E full correctness result is yet claimed.

[E's boundary/corpus batch](e-boundary-corpus-gates.json) completed freshly:
F10 **13/704**, zero unqualified failure with original PTR-order differences
and approved manifest retained; protocol **368/366 exact**, eight healthy
lifecycles/five rejected negative controls; TCP **13 conditions/50 pairs**, zero
differences and all 26 daemon identities/cleanup verified. Exactly the original
2 s short-v4 timeout remains per side. Existing checker tests passed 24+7.

Full source corpora passed cache-answer **764 commands/164 queries/382 metric
snapshots**, transfer **307/307**, and stale **1,100/1,100**. Lease insertion
retains only the exact two explicitly accepted UID-reuse differences and raw
exit1, with no ordinary/new mismatch. A source-bound release probe was freshly
built. The stale tool builds its fresh E debug driver, so it does not confuse
same-source reused debug test paths with byte-identical newly linked artifacts.
No comparator or fixture was altered. Full44 remains running and is the only
pending E correctness requirement; the earlier D startup failure is not waived.

## E complete correctness: original startup failure repaired

[Final E full44 receipt](e-full44-gates.json) confirms **44/44 original families
and 67/67 unique original jobs RAW PASS**, zero new or unclassified failure.
The reviewer independently rehashed every family result, every original job
result, exact SDK ELF, same-build map/receipt and all supervisor-bound inputs.
The original single run completed in 2,065.11 wall seconds, with no pause,
replacement or retry. Its raw-result SHA256 is
`c132ab5c39517fbf72355eae9c97a64d781d66888e2208ece368458427d9f01a`.

The repaired startup path passes its actual original gate: all **276 interface
service cases** have zero failure; the unchanged qualifier returns qualified
true for all **288 required rows**; all interface closeouts also pass. Exact C
and E emit the same helper sequence `original -> empty -> fromhosts`, then
`empty -> updated`, and no removal callback. Raw wire/event rows and actual
ELF hashes are preserved. No mixed-chain exception, new qualifier or relaxed
expectation was used. D's failed attempt and corrected diagnosis remain intact.

Together with the **944 fresh short tests**, exact ELF F10/protocol/TCP, and all
four source corpora, E has completed every correctness requirement. Existing
PTR and forward-pointer classifications remain explicit; only the previously
user-accepted two UID-reuse corpus differences retain raw exit1. This is not an
all-C-zero-difference claim. Exact E remains source `4f869c88`, SDK `8b8082b9…`,
2,136,859 bytes. All correctness processes have finished and no further workload
is scheduled. The coordinator received READY/IDLE for exclusive E Oracle timing;
device performance acceptance remains separate and no reviewer router operation
occurred.

## Oracle E complete and independently audited

The reviewer took over Oracle-only finish ownership while the explicitly
authorized DHCP owner ran the router concurrently. Until completion, only small
progress reads ran: no compilation, tests, analysis workload or bulk transfer.
After `complete=true`, 110/110 valid and no failure file were verified, the
coordinator was immediately notified that the global timing reservation was
released. Original analyzer and reused independent audit then ran on CPU1 at
nice10; controller PID225895 had exited and its owned runtime directory was
removed. No benchmark was repeated.

[Oracle E audit](oracle-e-independent-audit.json) verifies **110 archives/3,430
files**, including tar membership/hashes, extracted files, exact artifact and
measurement-tool identities, complete alternating pairs and original counters.
All 33 primary metrics, two ranked DORA metrics, home6 descriptive DORA and raw
RSS/PSS/USS/FD/process/thread values were independently recomputed without
importing the analyzer. Zero discrepancies or discernible primary regressions.

Discernible primary gains versus deployed `8472…` are limited to **TCP-miss p50
−2.229%**, **DHCP150 p50 −10.080%**, and **DHCP150 combined CPU −27.513%**; each
has 5/5 paired direction and exceeds its existing W/precision threshold. Only
2/11 scenes improve discernibly, so this does not establish the frozen
most-scenes objective or final candidate acceptance. Other primary metrics and
DORA are inconclusive. The legacy `c` label denotes deployed Rust, not image C.

Resource deltas remain explicit: median peak PSS/USS +72 KiB UDP hit (+64 file,
+8 anonymous), +64 mixed/TCP-hit (file-backed), +4 UDP-miss, +16 TCP-miss, zero
home6 and −52 DHCP150. FD/thread/process peaks have zero median change. Large
HUP RSS median peak decreases196 KiB (anonymous−260,file+64). E ELF is2,136,859
bytes, +12,288 versus deployed, within the existing2,200,000-byte budget.

The first analyzer invocation lacked root read access and recorded110
PermissionErrors at `root/private/oracle-e-summary.json`; it is preserved and
is not a product/window failure. The unchanged analyzer with authorized read
access wrote authoritative `root/private/oracle-e-summary-verified.json`, with
110 valid and zero parse failures. Independent detailed output stays at
`correctness/private/oracle-e-audit/independent-audit.json`. Only the derived
receipt returned locally; raw remains Oracle until both parallel runs finish.

A separate next-version miss-cohort validator repair was prepared in isolated
branch `fix/perf-miss-cohort-20261015`, commit `dba05f2e`, after the coordinator's
explicit instruction. It is nine validator lines plus12 local tests and an
old/new-hash receipt. It was not applied to frozen E, its running controller or
retained validity decisions. The current E device phase-boundary invalid remains
invalid; no retroqualification or selective replacement was performed.
