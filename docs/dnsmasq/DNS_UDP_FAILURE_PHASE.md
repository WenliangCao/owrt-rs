# Independent UDP completion failures

Previously `poll_inner` applied `?` to each terminal upstream event and each
recipient's wire/policy processing. One failed transaction therefore discarded
successful responses already accumulated in that batch and skipped unrelated
later completions. The containing listener's empty fallback hid that loss.

Completion processing now isolates upstream failures, common reply validation
and each recipient. A timeout/release sends no invented SERVFAIL; successful
siblings and independent queries retain their event order. `PollFailures`
exposes fixed-size cumulative counters for timeouts, other upstream failures,
invalid common replies, recipient failures and poll I/O errors. Hosts/cache
reload does not reset these counters, and no undrained error queue is retained.
These diagnostics are not a claim that every OpenWrt ubus metric is wired.

Background work now carries an explicit `Client.reply_requested` flag, separate
from optional socket identity. Ordinary library calls without a listener token
still receive responses; background recipients are skipped only after common
reply/cache processing. Coalesced clients keep their own delivery flags, and a
retry does not overwrite the original recipient. Regressions check ordinary
delivery plus background cache admission. This boundary enables the separate
stale-refresh implementation; it does not by itself implement that feature.

The exact reference `forward.c:reply_query` rejects or completes its matched
frec independently. `get_new_frec` increments unanswered-query accounting and
calls `free_frec` for expired/reused entries; it does not send a timeout reply.
The extracted-C `dns_forward_diff.py` adds an explicit sequence with an old
query, a younger unrelated query, expiration/reuse of the old slot, and a
successful reply for the younger query. The 1,271-operation state gate passes
with ASan/UBSan and no differences.

Three daemon regressions cover 16 controlled arrangements. Two successful
queries first complete through actual loopback UDP transport; a terminal
timeout, expired release, server removal or no-server event is then placed
before, between or after them. Malformed shared replies and an invalid recipient
are checked separately. Fixed client IDs, flags, counts, response order,
pending/socket release and cumulative diagnostics are asserted. This controls
terminal-event order instead of relying on a race against a wall-clock sleep.
A private deliberate mutation restoring whole-batch loss is rejected by the
test, with one expected failed test and nonzero exit retained.

Evidence is under `private/dnsmasq-rewrite/udp-policy-20261001/`:
`poll-isolation-forward-diff/`, `poll-isolation-tests.log`,
`poll-failure-calibration/`, and `linux/poll-udp-policy-01/`. The real exact-C/Rust
UDP caller gate passes 84/84 replies plus upstream semantics/counts; 164 DNS
unit tests pass with three existing ignored drivers, and all-targets clippy
passes. Poll-wide OS failure recovery, every malformed upstream variant and
complete metrics integration remain separate work.

The review also identified a separate timeout setting mismatch: the preceding
runtime used ten seconds, while C's idle reply lookup permits up to
`4 * TIMEOUT` (40 seconds); ten seconds is its conditional slot-reuse age.
The subsequent correction and real 11/41/42-second window are recorded in
`DNS_UDP_DEADLINE_PHASE.md`; this unit alone establishes failure isolation.
