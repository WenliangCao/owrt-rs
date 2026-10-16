# Original hot15 does not warm the reply recycler

The original probe, SHA-256
`72d836d1f868d4e608c14a47105b29dda35f8533ec6ce3456ca1bbc539db76bd`,
contains no `recycle_cached_reply` call. It constructs `LocalDnsService` at
line 155, whose buffer starts as `Vec::new()` (`service.rs:264`). Its query
function calls `answer_local_or_cached` at lines 177–179, consumes the returned
packet only for validation and `black_box(packet.len())`, then drops it at
lines 181–189. Both priming and timed loops use that same query function.

The daemon entry (`daemon.rs:1895–1904`) returns the owned cached packet without
recycling it. The production owner returns it only after send
(`main.rs:5375–5377`); the public-library probe never executes that owner.
Consequently the probe's cached reply buffer remains capacity zero on every
query. In candidate `6dadfec2e79d0c7c858dde296f7fa0e48e91afa6`, the nonzero
capacity guard at `cache_engine.rs:302` always rejects the new warm branch.

Unchanged native240 can reveal cold-fallback or code-layout regressions and
still runs its existing general-path scenes. It cannot measure the warm
writer's benefit or amortized owner recycling. Do not describe priming as
warming this buffer, nor infer warm-path performance from these native
windows. The original probe remains unchanged; no replacement workload,
new benchmark, test, build, remote operation or preparation was performed
for this source-only coverage review. Current G/5c timing is unaffected.
