# Frozen QTYPE zero cache-rr anchor

This is a separate nine-observation anchor, not a revision of the existing
78 forward observations in `CACHE_RR_GATE_PLAN.md`.

Exact patched `util.c:120` makes `rr_on_list` reject every zero list entry,
including when the requested type is itself zero. `rfc1035.c:879` independently
checks `ANY`, so an ANY list entry still enables generic QTYPE zero insertion.
The parser maps an explicit empty value to zero. These source expectations
must be calibrated against native and actual-image C before paired Rust.

Three profiles set `cache-rr=0`, an explicit `cache-rr=` empty value, and
`cache-rr=ANY`. Each sends QTYPE zero to the same deterministic opaque-RDATA
upstream and repeats it twice. Zero and empty must forward every observation
with zero insertions; ANY must insert one record on seed and answer both
replays from cache. All three use the established isolated fixture, empty OPT,
no round robin, 120-second TTL and no other cache-rr options. Expected DNS
fields, opaque bytes, send order/count and all 30 UBus metrics come from C.
Only upstream transaction IDs and at most one second of cached TTL phase are
normalized by the existing comparator.

Complete C before Rust in each execution. Verify the actual-image runner and
dependencies. Reject missing rows and detect a deliberately changed observation.
Preserve every run and failure under ignored `private/`; do not overwrite or
add profiles after inspecting results. No physical router or timing runs.
