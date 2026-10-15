# Independent D Oracle audit

**No Oracle integrity or primary-regression blocker was found for conditional
device screening. This is not final acceptance.** All 110 archives and 3,430
extracted files match their manifests, including tar member sets and hashes.
There are no unsafe or duplicate archive entries. The declared 11 scenes,
five alternating pairs, completion counts and artifact identities match.

Legacy side `c` is deployed Rust v0.2.0 `8472be5a…`; side `rust` is D
`4167609f…`. These results compare D with the deployed binary on Oracle,
not with the exact image C daemon or on the router. Independent raw derivation
matches every reported window statistic, all 33 primary comparisons and the
two ranked 150-client DORA comparisons. Six-client DORA remains descriptive.
CPU tick precision, pair direction, full-range W and lifecycle 1 ms resolution
were applied without exemptions. No primary metric regresses discernibly.

Only three primary metrics, spanning two scenes, improve discernibly:

| Metric | Deployed → D | Change | W |
| --- | --- | ---: | ---: |
| 150-client DHCP p50 | 2.941464 → 2.693102 ms | −8.443% | 8.324% |
| 150-client DHCP CPU | 760 → 544 µs/op | −28.421% | 8.421% |
| Mixed UDP p95 | 1.256530 → 1.233250 ms | −1.853% | 1.703% |

All other primary changes are inconclusive. Thus Oracle has not established
the final requirement that most scenes improve. Device comparison remains
necessary, and the two small latency gains are close to their measured W.

Parent/tree FD peaks are unchanged; observed process and thread peaks remain
one. Median round-peak RSS grows 68 KiB for UDP hit and 64 KiB for mixed UDP
and TCP hit. Those changes contain 64 KiB more resident file pages; UDP hit
also has 4 KiB more anonymous memory. TCP-miss anonymous peak grows 4 KiB.
Large-HUP anonymous peak falls 260 KiB, and DHCP150 RSS/anonymous peak falls
52 KiB. These are observed residency differences, not a proof of leak absence
or a claim that the fixed eight-byte D field alone caused page-level changes.

Oracle raw snapshots **do contain PSS and USS inputs**. Median round-peak
parent PSS/USS changes are UDP hit +68 KiB, mixed UDP/TCP hit +64 KiB, TCP miss
+4 KiB, UDP miss −4 KiB, DHCP150 −52 KiB and home6 unchanged. USS includes
private clean file pages here; it must not be described as anonymous heap.
The generic summary's device-unavailability sentence does not describe Oracle.
No lifecycle PSS/USS values are invented.

Downloaded D ELF and link map match the build receipt. All 179 receipt source
hashes match Git `9f2a9052`. ELF size is 2,136,859 bytes, equal to candidate C,
and 12,288 bytes (+0.578%) above deployed v0.2.0, within the unchanged
2,200,000-byte budget. Complete exact-D correctness and the root-owned recovery
and health checks remain prerequisites to device screening.

`oracle-d-independent-audit.json` records identities and derived resource
details. This audit read existing local data only; it did not rerun workloads,
change product code, access the router or extend the benchmark framework.
