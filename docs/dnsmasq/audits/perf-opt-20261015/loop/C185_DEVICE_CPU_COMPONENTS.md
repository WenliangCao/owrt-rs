# Existing C/G A53 CPU fields: attribution limit

The ten original direct C/G windows were reread locally. All archives match
the independently accepted report, and the exact before/after/client/epoch
bytes match the archived copies. The first endpoint records, PID/start
identity, four original CPU fields,100Hz and5000completed-query denominator
reproduce every original total. No measurement or acceptance result changed.

| Pair | C user/system ticks | G user/system ticks | C/G total ticks |
| --- | ---: | ---: | ---: |
| 1 | 0 / 42 | 43 / 14 | 42 / 57 |
| 2 | 27 / 14 | 0 / 61 | 41 / 61 |
| 3 | 21 / 20 | 22 / 35 | 41 / 57 |
| 4 | 9 / 33 | 0 / 57 | 42 / 57 |
| 5 | 25 / 16 | 6 / 50 | 41 / 56 |

All waited-child deltas are zero. Total medians remain41→57ticks, or82→114us
per query, exactly as the original accepted comparison. The components vary
far more across these fixed-load rounds: C user0..27/system14..42, G
user0..43/system14..61. These observations do not supply a stable split of
the32us median total gap into kernel and user functions. Component medians
must not be added or subtracted as if they were one measured window.

The cause of this split variability is not established here. It does not
prove a kernel-accounting defect, invalidate the original totals, or justify
trimming/repeating any window. Existing Oracle PMU data remains a separate
host diagnosis. Direct A53 product comparisons and, if selected, the dormant
same-ELF stage interventions remain the route to test current mechanisms.
No new audit rule, observer, workload or frequency assumption is introduced.

[All endpoint fields and archive hashes](c185-device-cpu-components.json).
