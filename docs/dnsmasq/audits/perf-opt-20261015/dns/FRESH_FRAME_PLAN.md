# Refine fresh-address caller storage after retained regressions

Parent prototype `2a9d53b0` completed its independent native480 screen: its
four hit scenes improve about8–10%, while eight fallback/local scenes worsen
about1–3%. All results remain in `loop/FRESH_ADDRESS_NATIVE_RESULT.md`. Its exact
SDK owner32 and A53 screen continue with that immutable source and ELF.

Read-only [exact SDK disassembly](fresh-address-sdk-codegen.json) shows its
selected-hit wrapper was inlined into `answer_local_or_cached`: emitted body
3,540→4,528 bytes, entry stack reservation592→720 bytes. The general state
machine remains13,524 code bytes and a2,256-byte frame. Avoiding that call is
useful for a selected hit, but local answers and fallbacks retain the shared
caller's extra128-byte reservation. Static reservations are not measured stack
traffic, cache misses or proof of the observed regressions' cause.

Independent child `b343df11` moves only successful-hit packet construction into
a non-inline helper. Eligibility, LRU promotion, all write/log/TTL/error ordering
and the unchanged general fallback remain intact. The intention is to keep
writer storage out of callers that do not take this path. The tradeoff is an
extra call and a separately live writer frame for a hit; do not presume it is
faster. Local library716/8 and musl all-target checks pass. Local probe codegen
is being checked separately; exact refined SDK/runtime qualification is pending.

[The predeclared screen](fresh-frame-native-plan.json) keeps all15 scenes,
three PMU and five plain pairs, fixed operations and original controls:240
windows independently against F. Do not pool its results with the parent or
claim that a before/after point estimate from different rounds proves a repair.
The existing runner loops remain unchanged. Exact related Linux gates and an
unchanged SDK build precede timing. Retained prototypes may continue to the
same32-window SDK owner diagnostic, with the original low-load precision and
high-load variable-N limitations. No current artifact, workload or C expectation
is modified. Eventual candidate promotion still requires complete qualification
and a discernible independent physical improvement against E.

The [local LTO probe comparison](fresh-frame-local-codegen.json) now includes F,
parent and refinement under the same compiler/options. Its shared query caller
reserves688/752/688 bytes, respectively: the refinement restores F's reservation
in this local probe. Caller assembly instruction lines are1,023/1,241/1,150.
Its new selected-hit writer reserves208 bytes, however, so that simultaneously
live hit chain is688+208=896 versus the parent's752, an increase of144 bytes.
The general body remains880 bytes/3,077 assembly instruction lines in all three.
These Mac figures must not be substituted for the exact SDK figures above.
All six build commands passed and162 source files per variant matched their
Git commits after compilation. No workload timing was run for the refinement.
