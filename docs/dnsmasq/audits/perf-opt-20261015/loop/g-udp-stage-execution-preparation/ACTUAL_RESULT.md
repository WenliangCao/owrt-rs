# Actual accepted-G stage gates and SDK

Exact source `a34e73107bc15f29b29b83499ceb0e0bc746d915` passed all three
original diagnostic selections once: synthetic fixture 1, normal bin 82,
ignored bin 4, total 87. Fresh logs supplied these counts, and the ignored
run's passed names exactly match the normal run's ignored inventory. The
fixture filtered out 858 library tests; this is not full lib, product
five-group, full44 or deployment qualification. G's buffer-recycling correction
and all source bytes remain frozen; no hosts fixture repair was applied.

The [verified gate](related-verified.json), SHA-256
`72a760276ef92bd9555e8aca5674cc708909d81de79b7f2afe1bb5a30d026825`,
rehashes all eight logs, both same-source test ELFs and 180 SDK input blobs.
The complete private gate archive includes 27 rehashed files and is
25,782,468 bytes, SHA-256
`b4dd0a2acfceb0fad062843467c7f840f9493ad2ab04bcfd57998daab83e6376`.

The original canonical f454/f280 SDK build exited zero once. Its diagnostic
ELF is 2,149,147 B and APK 1,169,636 B, within the unchanged 2,200,000 /
1,200,000 B budgets. [Actual identities](actual-result.json) and the
[postflight](sdk-postflight.json) bind ELF/map/build/APK, source180, live
SDK106, static PIE layout and unchanged accepted-G source179/SDK triple.
ELF SHA-256:
`686ba665a7c097c5ea4555c8cecabdc22235ceadfc9b314bbdb3660fddedc8a6`.
Build receipt SHA-256:
`3180d00bbeaf3b697285d12ed9243a0cc421358faf40a69492df26d422548908`.
The private SDK archive contains 45 rehashed files, including 16 payload
files; its SHA-256 is
`47ac16337c885d43d3d43e024ed84675dff307ad3b7a5bc3caf8845515d1c23b`.
Both archives and every extracted byte remain under
`private/perf-opt-20261015/g-udp-stage-execution-preparation/`.

Two setup failures remain separate evidence: default archive mode 0664 versus
tracked 0644, and an already tracked `private` directory rejected by a fresh
directory assertion. The first partial archive remains; the second retained
the extracted tree and resumed only after rechecking every archived byte/mode.
Neither failure ran or retried tests/builds, modified product source or changed
the original selections.

Independent actual review passed: original gate audit `ad9f1c3d`, SHA-256
`d53677fa512d625625fe0c0004a5004e7d6992bc2075c319d7ae2e844fd04791`,
and SDK audit `ef762db0`, SHA-256
`e6e4535e95e858f5755341c4ce29c20bdff622b82b6bc8072c6c5ef7bab60913`.
The reviewers checked actual inventories, full raw bytes, source identities,
static ELF/TLS/ALLOC and payload/budget while retaining both setup failures.
No additional test or build was needed. The
[explicit quiet handoff](release-to-dns-warm.json), SHA-256
`29f0a17bb632636c295db5fb79007fbe52f5eb3097bdb0fa1df0fe22dacf46a7`,
records exited controllers, no research processes including exact C, three
free locks and completed G-stage downloads plus warm input pretransfer.
Root authorized DNS's next warm gates/SDK without delaying ready G-stage
device50. Bulk avoids device health/timing; shared SDK builds never overlap.
No G-stage device timing started during this build handoff. Diagnostic stages
remain excluded from product promotion and additive cost inference.
