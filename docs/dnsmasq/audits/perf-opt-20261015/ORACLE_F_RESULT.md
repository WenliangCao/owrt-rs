# F/E Oracle original 110-window result

The original **110/110 windows are valid**, with no failed, replaced or
supplementary window. The frozen analyzer completed without parse failures.
The existing independently reviewed E audit, minimally adapted before this
run, verified all **110 archives and 3,430 raw files**, decoded the original
records, and reproduced the statistics without errors. The derived receipt is
[`loop/oracle-f-independent-audit.json`](loop/oracle-f-independent-audit.json).

**The Oracle UDP-hit CPU objective was not demonstrated.** E and F both have
a median of 26 µs/query. The observed range W is 15.385%, the median tick
difference is zero, and the original CPU precision gate is not met. UDP-hit
p50 changes +0.114% within W 6.385%; p95 changes -0.764% within W 38.255%.
Every original pair, including the wider p95 observation, remains included.

None of the 33 primary p50/p95/CPU comparisons across the eleven scenes
shows a discernible improvement or regression under the unchanged rules.
This is inconclusive performance evidence, not proof of equivalence. CPU
medians below include the complete original cohort or lifecycle round:

| Scene | E CPU µs/operation | F CPU µs/operation | Change | CPU precision gate |
| --- | ---: | ---: | ---: | --- |
| UDP hit | 26 | 26 | 0% | Not met |
| UDP miss | 74 | 78 | +5.405% | Not met |
| UDP mixed | 44 | 44 | 0% | Not met |
| TCP hit | 34 | 34 | 0% | Not met |
| TCP miss | 78 | 78 | 0% | Not met |
| DHCP 6 clients | 84 | 84 | 0% | Not met |
| DHCP 150 clients | 540 | 548 | +1.481% | Not met |
| Startup small | 1,543.40 | 1,667.65 | +8.050% | Not met |
| Config small | 1,679.10 | 1,745.85 | +3.975% | Not met |
| HUP small | 333.30 | 315.55 | -5.326% | Not met |
| HUP large | 2,840.30 | 2,823.40 | -0.595% | Not met |

The startup CPU change exceeds that scene's W but fails the original CPU
precision requirement, so it is not reclassified as a measured regression
or hidden from the result. Ranked 150-client DORA comparisons are also within
variation; the six-client DORA values remain descriptive. Resource medians,
all ranges, fd counts and Oracle PSS/USS are retained in the receipt. Some
memory medians differ by a 4 KiB page; no resource samples are omitted.

The baseline is accepted E `4f869c88…` / ELF `8b8082b9…`; the candidate is
F `3a3d8e3e…` / ELF `b7926bcf…`, both 2,136,859 bytes. F's complete functional
qualification `84ca1915…` preceded launch. New frozen loadgen `f7c7d8e9…` and
cohort validator `70204209…` were used prospectively, with unchanged analyzer
`10addedf…`. Source/tool/binary identities matched again after completion.
All measured replies completed within their windows in this particular run;
the predeclared complete-cohort accounting remains unchanged.

The controller exited, its owned temporary runtime directory was removed
after external archival, and no controller failure or stderr output remained.
The full analyzer result has SHA256
`51f345f53aafa599d190bbc0590a7353ea790dd4783728b49c4c10524e4b9a52`;
the full independent audit has SHA256
`977644d454dfcd90b6f45639e8fdfe6441f122e898726339199aa57143c5e86b`.
Only the 68,133-byte derived receipt was transferred during the ongoing
router test. Full summaries and all raw archives stay under Oracle's private
F/E run directory. Bulk transfer remains deferred until the device owner and
coordinator release that restriction.

The Oracle reservation is released. The independent physical-router F/E run
continues; this result makes no A53 performance or deployment claim and does
not establish that the user's CPU gap has narrowed.
