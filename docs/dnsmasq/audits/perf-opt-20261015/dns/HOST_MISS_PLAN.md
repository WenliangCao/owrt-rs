# Use the published hosts index for a definite name miss

Independent F child `5d94139b` changes only `Hosts::lookup`. Once a hosts
generation is published, its existing forward index contains every host owner.
An empty index, or a missing lowercase key, can return an empty answer without
computing the pointer-seeded C bucket hash and visiting unrelated bucket nodes.
No additional index, local-ownership cache or generation tracking is added.

Bulk loads, including sealed loads with retained lease nodes, always take the
original path: those nodes are not represented by the hosts forward index and
can participate in lookup rotation. `finish_bulk` removes them before clearing
the bulk marker. Nonempty uppercase queries and every indexed hit also keep the
original lookup. This may add work to host hits; the screening explicitly keeps
host, host-localise and all other adverse controls. It is not assumed faster.

The public-entry regression compares repeated queries against the original
bucket lookup through active/sealed/published generations, TCP snapshots,
source removal and new insertion. It covers both address families, nonterminal
and colliding names, case and rotation switches. Mac library tests pass715 with
8 ignored, and musl all-target checking passes. Two fixture-only failures are
retained: a moved value still borrowed by its comparison closure, and adding a
bulk lease after inserting a host. Neither changed the product mechanism.
[Thirty local allocation controls](host-miss-local-allocation.json) preserve
all15 checksums, allocation counts and zero live-byte deltas; this optimization
does not target allocation. Variable host-localise request sizes remain in the
raw/derived report and carry no causal claim.

## Next fixed screen

[The plan](host-miss-native-plan.json) keeps the prior15 scenes, operations,
three user-PMU pairs, five plain CPU pairs, source/probe checks, CPU placement,
W/direction rules and failure policy. One prototype against F gives240 windows.
The only runner edit replaces its final hardcoded480 check with the product of
the existing plan dimensions. Its measurement loops are unchanged. The old
runner SHA `9d5bc3ab` remains frozen in Git and in the currently active remote
fresh-address480 copy; no active input or historical result changes.

Exact Linux related gates and an unchanged SDK build precede this screen.
Afterward,32 fixed original-SDK low200/s/high-unpaced windows retain the existing
low-load precision and high-load variable-N caveat. Do not pool earlier screens
or select a product from this local preparation. Oracle is unavailable until
fresh-address480 and its owner32 finish; no workload from this plan has started.
Any eventual next candidate still needs full frozen-C correctness and physical
E comparison under the original acceptance rules.
