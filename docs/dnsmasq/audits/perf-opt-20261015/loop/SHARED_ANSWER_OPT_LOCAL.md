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

## Compact reply-envelope follow-up

Separate refinement961b7cf8 retains only udp_limit, OPT presence and DO in a
private value. Signedness and RecordRef bytes are never consumed by these
reply-envelope callers. Failed scans still remain absent and the cache caller
rescans at its original boundary. TCP keeps its original delayed scan; none
of this shares a scan with the differently configured forwarding/EDNS owner.

Local725Mac/8ignored and musl all-target checks pass. The shared owner frame
returns to the original624B, while code remains4060→4444B and the full local
ELF grows384B. One UDP scan is removed; extra merge branches and TCP/fallback
code effects remain. Keep this below803 and bare1df with no timing claim or
remote preparation. The broad local symbol selector also matched an unrelated
scan function in private output; it is excluded from the derived report.

[Compact representation receipt](shared-answer-opt-compact-local.json).
