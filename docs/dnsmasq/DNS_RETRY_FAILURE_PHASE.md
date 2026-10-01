# Failed retries of already forwarded UDP queries

The real C baseline now covers a failed send on an existing frec. Rust's normal
client retry and stale-refresh cancellation already match that boundary. A
failed fast timer retry omitted C's local-answer counter; this change counts
that actual fallback without manufacturing a client reply.

## Source and actual C authority

The pinned `forward.c::forward_query` restores the saved upstream query for a
retry, retains each recipient's original ID and question case, and tries the
selected server plan. If all sends fail, it restores the first frec recipient's
ID, frees the entire frec and its socket references, and constructs a local
REFUSED / EDE 23. Only the current foreground caller receives this fallback;
other coalesced clients receive nothing. `udpfd == -1` suppresses delivery for
fast or stale background retries but still increments `dns_local_answered`.
Forwarded and unanswered counters do not increase for that failed action.

`dns_retry_failure_diff.py` verifies that its network namespace differs from
the recorded host namespace, only loopback exists, and both main route tables
are empty. It adds `198.18.0.53/32` only to that namespace's loopback, receives
and holds a real upstream query, removes that address, and requires an actual
ENETUNREACH on retry. An independent 127.0.0.1 upstream query remains pending.
The fixture restores the address, sends the old held reply, checks its rejection,
then completes a new query. All namespace changes are removed during cleanup.
No host route or physical device is accessed.

The five schedules are original-client plain/OPT retry, coalesced-client OPT
retry, automatic fast retry and stale background retry. Raw IDs, question case,
flags/OPT, all 30 UBus fields, upstream activity, pending socket ownership,
unrelated completion, recovery and shutdown are retained. Normal `-k` daemon
mode is used. C completes first and supplies every expected observation.

The observed C coalesced-retry fallback is defective: client 0x6102 receives a
REFUSED bearing the first client's ID 0x6101 and first question case. Rust keeps
the retrying client's correct ID/question. The comparator preserves this
difference and keeps the complete gate nonzero; Rust must not reproduce it.

## Retained baseline and scope

- `retry-c-baseline-01` executes four 16-row C schedules. The stale setup fails
  because a DO query is not served stale from the unsigned seed cache; no stale
  observation is counted as passed.
- `retry-c-baseline-02` uses ordinary empty OPT for the stale query and records
  all 83 rows. The exact C binary is
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- `retry-before-01` compares 83 rows against Rust ELF
  `0d7bad659dd8ae14fa664410da7f9117f3b59eeaa3049e4f8aca083e4c3a4009`:
  14 differing rows and no fixture failures. Besides the C wrong-ID row and
  four fast-fallback local-counter snapshots, the DO healthy/recovery controls
  expose a separate DO-query cache-admission gap. Some rows contain both counter
  gaps, so those categories must not be summed as disjoint differences.
- `retry-c-baseline-03` freezes 83 C rows with ordinary empty-OPT healthy and
  recovery controls, before changing Rust. Failure-triggering DO queries remain.
  The DO-cache gap is still open; the earlier trace is not relabeled as a pass.

The final schedule adds one actual HUP persistence snapshot per profile. This
is five additional checks, not evidence that the old 83-row workload changed
solely because of the fix.

## Producer and publication

`ForwardCounters::background_local_answered` is a wrapping u32 producer. Only
the actual fast-retry `send_plan` socket/send Io failure increments it, before
that transaction is cancelled. Generic poll errors, recoverable receive errors,
timeouts, failed planning and initial foreground send failures do not increment
this producer. Initial foreground and stale-refresh fallbacks keep their
existing parent-owned counter path.

The counter is part of `DnsDaemon::forward_counters`, including the snapshot
already passed to the synchronous DNS doctor. Every main metrics writer now
sets local answered from the explicit parent count plus the background producer.
It does not add to a prior aggregated snapshot, drain an event queue, or reset
the producer on reads, cache reload or UBus disconnection. Other upstream-error
retry callers remain a separate audit; this change owns the fast-timer origin.

Host Rust 1.98.1 checks pass: DNS 210/0/4 ignored, main 7/0, all-targets Clippy.
The new transport test uses an actual invalid-destination send failure with no
UBus service, observes one count per failed timer action and verifies repeated
ticks/cleanup/failed initial sends do not double count. Main tests cover repeated
doctor-style snapshots and wraparound. The exact C forwarding-state regression
remains 1,285/1,285 under ASan/UBSan; it compares its existing forwarded/unanswered
state, while the new producer is exercised by the actual daemon schedule.
The first local oracle attempt used a nonexistent rustc path and executed no
Rust cases; `forward-regression-01.log` is retained beside passing round 02.

Linux replay of the frozen implementation follows separately. These are bounded
failure-contract checks, not complete DNS/EDNS, resource-cost, target or physical
router acceptance.
