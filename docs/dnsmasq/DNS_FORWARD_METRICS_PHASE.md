# Forwarded and unanswered counter producers

The forwarding engine now exposes `ForwardCounters` with the two actual C
u32 counters. `queries_forwarded` increments once after a send action succeeds
to at least one upstream. Sending that action to multiple servers still counts
once; a coalesced client adds none; a successful retry adds another action.
Failed sends add none. `unanswered` increments at `get_new_frec`'s absolute
reclamation and conditional ten-second slot-reuse boundaries. Duplicate-pool
expiry, cancellation and server removal do not become unanswered merely
because they release state.

The asynchronous daemon uses `Lifetime::ForwardTable`, so timer ticks do not
destroy the record before the real reclamation boundary. No deferred-accounting
queue is needed. Counters wrap at u32 as in C and persist through cancellation
and cache reload; they are not client completion/error totals. Read-only
snapshots are available through `UpstreamResolver::counters`. Runtime/ubus
publication remains a separate caller integration gate.

Source authority is the unchanged pinned `forward.c`: successful send-action
accounting in `forward_query` and the two unanswered increments in
`get_new_frec`. `dns_forward_diff.py` now compares ordered counter snapshots
after every operation as well as the original forwarding state and sends.
The final 1,285-operation gate passes with ASan/UBSan, including duplicate and
retry behavior, multi-server sends, send failure, per-group pressure, both
reclamation ages and wall-clock rollback. Fixed calibration observes three
upstream packets but one forwarded action; a one-counter mutation and missing
observation are independently rejected.

This review found a test-purpose defect in the earlier `independent-expiry`
scenario: its second query at time 130 reused the old time-100 slot, and the
time-140 request reused that second query. The C/Rust states matched, but that
trace did not demonstrate an unrelated successful reply surviving expiration.
The corrected query starts at 101, keeping two live frecs before time 140.
Calibration now requires the younger query's `M2` match, `D2` completion and
exactly one unanswered increment. The original `forward-counter-diff-01/`
trace is retained, not relabeled as that coverage.

Socket-backed regressions verify two actual upstream datagrams count as one
action, a retry counts once more, a coalesced recipient adds none, oversized
failed sends add none, and cancellation releases every socket without resetting
the cumulative count. Source-boundary tests cover duplicate-pool expiry,
server removal and u32 wrap. Related DNS tests pass 181 with three existing
ignored drivers, and all-targets clippy passes.

Raw evidence is in `private/dnsmasq-rewrite/udp-policy-20261001/`:
`forward-counter-diff-03/`, `forward-counter-tests.log`,
`forward-counter-send-tests.log`, and `forward-counter-clippy.log`.
This does not establish all OpenWrt metric producers, a real ubus service trace,
TCP accounting, target performance or production acceptance.
