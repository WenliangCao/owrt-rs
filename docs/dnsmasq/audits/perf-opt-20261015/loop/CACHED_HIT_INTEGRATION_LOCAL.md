# Local cached-hit integration, unselected

Source15e69b7a is an independent6ab child, assembled with each original
performance step in its own commit. It combines1df inline address details,
025/5c ready DHCP/dump outlines, the final6dad warm writer,4f/117 inactive
upstream outlines,215 canonical hosts presence and86 empty-additional ECS.
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
