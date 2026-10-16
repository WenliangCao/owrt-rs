# Cached-hit integration selected for fresh screening

Root selected source `9e8459dd704d339b10596721eaa2d3bef1f943c1`, an independent
6ab child, after the complete G-stage and warm screens. Each original product
step remains a separate commit. Accepted G remains the delivery artifact;
9e has no Linux runtime, canonical SDK or measured performance result yet.

The combination contains inline address details (1df), ready DHCP/dump outlines
(025/5c), the warm writer (6dad), inactive upstream outlines (4f/117), canonical
hosts presence (215), empty-additional ECS (86), local absent-OPT scanning (3b),
conditional name scratch (45) and direct lease-ID slice iteration (210).
Separate integration commit15e makes the warm writer use 1df's inline address
bytes, as its fallback already does. This removes the reintroduced retained
Arc<Record> RDATA read, while growing that local writer range952→1028B. There
is no new behavior repair or change to frozen C expectations.

Existing tests pass729Mac library tests with8ignored,23Mac main-binary tests,
and musl all-target compilation. The original warm comparison still covers
18432 tuples;210 retains its576 ordered-entry/expiry comparisons. Individual
source reviews and the root's exact whole-file substitution check for45 are
retained. These are not an independent qualification of the complete bundle.

| Local emitted range |6ab bytes / frame bytes|9e bytes / frame bytes|
| --- | ---: | ---: |
|Shared local/cache answer|4060 /624|3848 /592|
|Cached local-ownership check|528 /368|528 /336|
|SinglePoll::step|17608 /2400|4692 /640|
|DnsDaemon::poll_inner|12448 /1520|528 /224|
|Fresh address writer|1092 /288|1028 /160|
|Fallback address writer|part of fresh|1148 /288|

The completed-reply helper is5664/1024 and active-upstream poll is6260/1088.
Active paths pay additional calls/nested frames. Conditional scratch only
avoids clearing when a lease-expiry dotted name already exists; ordinaryNone
cached hits still initialize253 bytes. The rejected forced-inline converter
retains that zeroing and adds96 frame bytes; it is excluded and archived.

| Preserved local revision |ELF SHA prefix|Bytes|Delta versus6ab|
| --- | --- | ---: | ---: |
|6ab control|77096845|5022240|0|
|dfe plain combination|329a0b97|5025360|+3120|
|15e inline warm address|9dea4eb4|5025496|+3256|
|48 local OPT and conditional scratch|25424e92|5025528|+3288|
|9e direct lease slice|fd2fa9ff|5024648|+2408|

These are locally linked bundled-musl ELFs, not SDK budget results, resident
instruction footprints or CPU measurements. The final two comparisons reuse
the exact earlier6ab control ELF with its unchanged hash and original receipt;
they do not claim fresh control rebuilds. All earlier artifacts remain intact.
210's earlier name_exists code-growth tradeoff is retained alongside its
smaller iterator state; no allocation or performance saving is inferred here.

The G-stage before-answer intervention was122→94us and discernible; skipping
local lookup was116→110us and inconclusive. The warm owner32 screen has
high-load diagnostic gains and significant send-lag regressions, with all
low-load metrics inconclusive. The6ab native synth/CNAME regressions,1df native
miss regression and5c high-load send-lag regression also remain. Combining
sources makes none of those results a pass. Independent medians and stage
differences cannot be added or treated as removable function costs.

The execution queue is the original five groups, canonical SDK, original
standalone signals12+3+3 and independent actual reviews. Then original native240
and G/9e device10 may run together, followed by original owner32. Native coverage
is cold/library/general: it does not recycle the warm writer or execute the
main owner and its empty-upstream handling. A meaningful physical result still
requires original full44/corpora and both110 qualification matrices. No source
already measured or accepted was changed by this preparation.

[Exact sources, commits, checks, body review and codegen](cached-hit-integration-local.json).
