# Fresh exact-C/185 owner profile

The [16-window plan](c185-hit-stat-cycles-plan.json) is prepared locally only.
It binds the immutable 185 SDK ELF, exact image C and its existing symbol
companion, same-build 185 link map, original loadgen/upstream/netns binaries,
all observer/analyzer dependencies, concrete capture/analyzer argv and fresh
output paths. The ongoing full 110 collection and raw audits must complete,
and the owners must explicitly release the observation slot before staging
or execution. No remote access, upload or workload occurred during preparation.

The first 12 windows retain the original three alternating stat pairs for
each of UDP and TCP. The remaining four retain one independent `cycles:u`
sample for each side and transport. The stat driver is byte-identical to
93489990 (SHA 7671b1e5); cycles use dc2008f6 (SHA 2c1bb2ec). No instruction
sampling is scheduled. The original stat driver still records its unused
`sample_event=instructions:u` scope field; its `observer=stat` path collects
only the original inherited four-counter group.

Each window keeps 1,000 excluded UDP prewarm operations, then 1,000 warmup
and 4,000 measurement operations at 200/s, followed by the fixed 1 s drain.
Cache/name/query mix, seed, connection limits and CPU/nice placement retain
the original values. Counters include both observed phases, so normalization
uses 5,000 completed operations. No drain extension, retries, replacement
windows or mixing historical E counters into new 185 totals is allowed.

Private tool copies under `private/c185-hit-profile-preparation` were checked
against the manifest's Git objects and SHA256 values. The analyzer differs
from dc2008f6 in exactly two literals: the candidate ELF pin and output scope.
Parsers, assertions, symbol/lineage checks and computations are unchanged.
The manifest is enough to reconstruct the files from Git; there is no new
execution or analysis framework. The original directory layout is preserved
for import resolution, with the stat driver alongside its dependencies.

After explicit release, validate all staged and existing binary/map/library
identities and fresh output paths before the declared first argv. Preserve
every capture and run each declared analyzer on its corresponding window.
Also retain and inspect actual perf attributes, control ACKs and inherited
descendant records, as required by the original review. Stop on any failure
and retain its raw evidence. No successful substitute is silently selected.

Report new per-transport/side stat medians and full three-window ranges with
raw/scaled status. Attribute cycle self shares against each corresponding
new user-cycle median, retaining unknowns in the entire denominator. This
is a cross-run estimate for hotspot selection. One sampling window per side
does not establish stable function precision, causal savings, physical A53
costs, or the separate frozen five-pair performance acceptance.
