# Shared UDP local/cache OPT: full scan prototype

Independent6ab child bdfcc382 reuses the successful original UDP local scan in
the subsequent cache answer of the same immutable query. Failed scans keep
local suppression/cache rescan, TCP keeps its delayed scan, and direct cache
callers retain their own scan. Source review d6ff9632 passes;725Mac tests and
musl all-target checks pass. There is no new persistent state or allocation.

Static cost rejects this representation for scheduling: retaining EdnsScan
increases the emitted shared owner from4060 to4500B and its frame624 to720B.
The bundled-musl/lld ELF grows432B. UDP avoids one parse but now retains the
full OPT record view, while both consumers only need limit/presence/DO.
No performance claim follows from the removed call. A later compact-envelope
revision must be assessed separately;803 and bare1df remain unchanged.

[Full local receipt](shared-answer-opt-full-scan-local.json).
