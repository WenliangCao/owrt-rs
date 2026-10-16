# Avoid a local-only OPT scan when ARCOUNT is zero

Independent6ab source3b11c9bb changes only lookup_local_parsed's projection of
find_pseudoheader into an optional OPT. This caller deliberately discards scan
errors and signed-query state. When the actual packet has ARCOUNT zero, both
a successful scan and a discarded error produce None. The local path can
therefore keep its original no-OPT envelope without traversing the question.

The guard reads query bytes10..12 rather than trusting the separately supplied
Header. Short packets and nonzero ARCOUNT keep the original scan. The UDP
pre-answer and TCP post-local-hit scan use the same guard; cached-answer error
propagation and the global scanner remain untouched. This is separate from
86's ECS-only shortcut and961's larger shared-envelope representation.

Existing725Mac library tests pass with8ignored; musl all-target compilation
passes. No new API, state, allocation buffer, unsafe code or test framework
is introduced. Source peer is pending and there is no Linux/C-corpus result.

The local shared answer function changes4060→4124B but frame624→608B. The
wire scanner remains1264B/frame288, and process_udp remains4660B/frame1056.
Its machine code branches at2ac978 directly to2ac9b0 for absent additional
records, bypassing the local scan call2ac990; the later cache scan2acf7c
remains. Three scan call sites are still emitted, so static call-site count
is not an executed per-query count.

The local control again reproduces77096845/5,022,240B. The prototype is
053e6d8f/5,022,248B, +8B. This is neither SDK size-budget evidence nor a CPU
claim. It remains unselected for remote preparation and does not modify the
current G-stage, independent warm6dad or local combined15e sources.

[Exact checks and local codegen](local-empty-opt-local.json).
