# Local cached-hit integration, unselected

Current source48f921ce is an independent6ab child, assembled with each original
performance step in its own commit. It combines1df inline address details,
025/5c ready DHCP/dump outlines, the final6dad warm writer,4f/117 inactive
upstream outlines,215 canonical hosts presence and86 empty-additional ECS.
It now also includes3b local absent-OPT scanning and45 conditional scratch
initialization in their own commits; earlier15e/dfe artifacts remain intact.
No source currently being built or measured changed. The G-stage diagnostic
and independent warm6dad screen retain priority; this is not a new timed
candidate or qualified artifact.

Separate integration commit15e69b7a makes the warm encoder consume the same
selected inline positive address as1df's fallback writer. Otherwise combining
these sources would reintroduce a retained Arc<Record> RDATA load in the warm
branch. Local machine code confirms the old dependent loads at310638/310644
are replaced by inline-address tag tests; it also grows the warm range952→1028B
and the local whole ELF by136B. This is a concrete tradeoff, not a speed claim.

Both the plain combinationdfe and adjusted15e pass728Mac library tests with
8ignored,23Mac main-binary tests, and musl all-target checking. The existing
18432 general/fresh answer comparisons remain; no new test names or benchmark
framework were added for the integration. Original individual source reviews
remain evidence, not an independent review or full qualification of this bundle.

| Local emitted range |6ab bytes / frame|15e bytes / frame|
| --- | ---: | ---: |
|SinglePoll::step|17608 /2400|4692 /640|
|DnsDaemon::poll_inner|12448 /1520|528 /224|
|CacheContext::answer_fresh_address|1092 /288|1028 /160|
|Fallback address writer|part of fresh|1148 /288|

The separate completed-reply helper is5664/1024 and active-upstream poll is
6260/1088. Active paths pay additional calls/nested frames. Both local control
ELFs reproduce77096845,5,022,240B. The plain integration is329a0b97,5,025,360B;
15e is9dea4eb4,5,025,496B (+3256B versus6ab). These are bundled-musl local
ELFs, not SDK size-budget results, resident instruction footprints or runtime
measurements. Warm zero-initialization and cold fallback overhead remain.

The6ab native synth/CNAME regressions,1df native miss regression and5c
high-load send-lag regression are all retained; none becomes a pass by being
combined. Previous independent medians cannot be added. The combined source
has no new Linux gates, allocation/resource screen, SDK, Oracle or device
result. It must earn any later candidate selection from fresh evidence.

[Exact sources, commit mapping, checks and codegen](cached-hit-integration-local.json).

The final48 build passes the same728Maclib+23Macbin/8ignored and muslalltargets.
Its ELF25424e92 is5,025,528B, +3288B versus6ab and+32B versus15e. The existing
verified6ab control ELF was copied for this local comparison, not rebuilt;
its original receipt and unchanged SHA remain bound. Mainstep4692/640,
empty-poll528/224 and warm-writer1028/160 are unchanged. The shared answer
range is3848B/frame592; its prior15e emitted range/frame is separately read
from the retained ELF in the JSON, without recompilation.

Conditional scratch initialization only saves clearing when an existing
lease-expiry dotted name is supplied. The ordinaryNone cached-hit path still
clears the same253 bytes, and cached_address_is_unclaimed remains528B/frame368.
Root verified that reversing45's exact two-line change restores the complete
6ab local.rs; theSome branch never borrows the uninitialized scratch. DNS's
rejected inline converter variant is excluded: it retainsNone zeroing and
increases that frame by96B. No runtime benefit is assigned to either local
change, and the integration still has no remote execution selection.
