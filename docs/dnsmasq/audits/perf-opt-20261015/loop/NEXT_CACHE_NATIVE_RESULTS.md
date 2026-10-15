# Three independent cache screens: completed, no regression-free variant

All three fixed native screens completed: 720 windows, 732 commands, no failed
measurement and no replacement sample. Each prototype has discernible adverse
scenes under the original W/direction rule. None is selected by these results.

| Independent comparison to F | Faster | Slower | Within variation | Complete report |
| --- | ---: | ---: | ---: | --- |
| Cold metadata `40cc86fe` | 1 | 5 | 9 | [All 15 scenes](COLD_METADATA_NATIVE_RESULT.md) |
| Fresh writer frame `b343df11` | 5 | 5 | 5 | [All 15 scenes](FRESH_FRAME_NATIVE_RESULT.md) |
| Hosts miss index `5d94139b` | 11 | 3 | 1 | [All 15 scenes](HOST_MISS_NATIVE_RESULT.md) |

Cold metadata's configured-CNAME CPU rises 5.201%; reducing ordinary entry
size is not evidence of a general CPU gain. The writer-frame refinement retains
five fallback regressions; the parent's original eight adverse results remain
separate. The hosts miss index improves many no-host-owner paths, but host,
raw-address and configured-CNAME CPU rise 6.579%, 1.012% and 2.602%. No favorable
subset or pooled score overrides these results.

The screens ran serially in the table's order, with independent F controls in
each round. Every round completed its four native build commands before its
240 measured windows; no build overlapped another round's timing. All three SDK
builds, the exact 2,803 related Linux gates, DHCP's nine-file SDK transfer and
PGO smoke2's full exit/cleanup preceded timing. Smoke2's failed exact-E control
remains a separate retained attempt and did not change the native inputs.

The existing runner changes only the final cardinality assertion from literal
480 to fixed plan dimensions; all 15 scenes, operations, alternating pairs,
checksum, PMU, CPU placement and W/direction rules remain intact. No new timing
framework or product change was introduced. The three reports contain all
45 scene summaries and all 720 underlying rows.

Independent final checks rehashed 1,734 small raw stdout/stderr/PMU CSV files,
all 162 source files per side per round, and both probe ELFs per round. All
labels, checksums, recorded grouped/unscaled PMU fields, same-window IPC and
plain CPU/wall derivations matched. Raw outputs and binaries remain private;
only small result metadata was transferred. No router was accessed by this work.

[The release receipt](next-cache-native-release.json) confirms all three
controllers exited, the root-readable research process inventory was empty,
and SDK/native locks were available at 2026-10-15 23:25:19 UTC. DNS and
correctness were then awakened for the coordinator's already authorized
non-timing PGO smoke3 and related Linux gates. No SDK32 follow-up was started.
Future timing still requires a new reservation after those jobs finish.

Native mechanism evidence does not replace full frozen-C correctness, complete
acceptance matrices or an independent physical comparison to E. The unchanged
acceptance gates and all prior unfavorable observations remain in force.
