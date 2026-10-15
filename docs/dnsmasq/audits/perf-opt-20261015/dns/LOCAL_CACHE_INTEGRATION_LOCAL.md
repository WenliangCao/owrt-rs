# Local integration preparation, not a selected candidate

Source `8d572ba1` is a clean F-based cherry-pick of the independent fresh-address
writer refinement and bounded local-address miss shortcut. No conflicts or
manual product edits were needed. The original five commit identities are in
[the local receipt](local-cache-integration-local.json). Cold metadata, hosts
index, name-buffer, adaptive batching and compiler experiments are not included.
This tree is only local integration preparation while the standalone artifacts
remain immutable in their existing measurements.

Mac719 library tests pass with8 ignored; Linux-musl all-target checking passes.
Thirty existing hot15 allocation controls retain every F output checksum and
zero live-byte deltas. Ordinary hit changes4→2 allocations and245→160 requested
bytes, removing the64-byte IDs vector and21-byte fixture dotted name. Uppercase
and lease/typed-config hit classes save the same two allocations. Both miss
classes, RRset and CNAME-with-leases save one21-byte allocation. Other allocation
counts remain equal. Host-localise retains its varying reallocation/requested
bytes: +0.13375 reallocations and84.72 requested bytes per operation in this
pair; no causal saving or regression is inferred from that process-dependent
fixture difference. All34 command results/log hashes were rechecked.

This does not add standalone timing gains together or claim a physical win.
The parent fresh-address variant's native regressions and below-gate A53 result
still stand. Independent source-interaction review, runtime qualification and
newly frozen integrated timing would be required before this tree could become
a candidate. No remote build, native timing, SDK/device run or full44 acceptance
has been performed for it. E remains accepted and no G has been selected.

## Independent integration screen now predeclared

After the existing native reservation, related Linux qualification and the
original SDK build, [this fixed plan](local-cache-integration-native-plan.json)
uses the same15 scenes and240 windows against fresh F controls. The planned
32-window exact-SDK low/high owner comparison and ten-window exploratory A53
comparison also use separate original-condition alternating F controls. These
results must stand on their own; parent/refinement/singleton timings remain
separate. Original W, direction and fixed-cohort precision rules apply, with
the existing variable-N caveat at high load. Full44 and both full matrices
remain necessary for any eventual candidate selection. No hardware test is
started by this local preparation; the device controller must bind the actual
SDK artifact and pass its existing recovery/health gate first.
