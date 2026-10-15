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
