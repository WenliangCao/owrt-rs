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

## Frozen Linux verification

Implementation commit `232edb2545c2860dd950c6034ec1f145a460d189` builds with
native Linux aarch64 Rust 1.98.1. Release ELF SHA-256:
`79dfe812f8b869fdf877c861355f26165b54401edab86c8fa425ca52b9f5f75c`.

- `retry-after-01`: **87 matching observations / one retained C wrong-ID and
  question-case difference**, 88 compared, zero fixture/coverage failures,
  complete gate exit 1. Original plain/OPT and fast profiles each match 17/17;
  stale matches 20/20; coalesced matches 16/17. All five HUP snapshots retain
  the cumulative local-answer count while clearing the cache insertion window.
- `retry-negative-01`: one injected local-counter difference plus that same
  C defect, 86 matches / two differences, exit 1 and no fixture failures.
  These two runs use tool SHA-256
  `de2c50a37268b36d8fbcd1d2ee9dd541c8c1ef791bb6d129bebbe66d6dad97c0`.
- `retry-doctor-01`: the separate `--doctor-metrics` fast-only schedule passes
  **18/18**, using the same frozen ELF. A real subscriber requests all metrics
  synchronously inside the DNS doctor for the preserved healthy reply. C and
  Rust both expose local answered 2 before cache inserted changes from 0 to 1.
  Thus the current background producer reaches the inside-doctor snapshot.
  `retry-doctor-negative-01` detects one injected counter difference, 17 matches
  / one difference, exit 1, no fixture failures. Doctor tool SHA-256:
  `7321b08fd72c08aba87c4933589e16346dd49c6d53229dc3931d641c2ffdc799`.
- `initial-failure-regression-01`: the unchanged actual initial-send failure
  gate remains **61/61**, with real no-route/EMFILE coverage and no fixture
  failures. Native DNS tests pass 210/0/4 ignored; native main tests pass 7/0.
  The native exact-C state regression also remains 1,285/1,285 with sanitizers.
  Host target-musl checking, changed-file formatting and whitespace checks pass.

Raw baselines and the original 83/14 replay remain at
`/home/ubuntu/dns-resume-send-20261001/private/retry-*`. Frozen implementation
checks are under `/home/ubuntu/dns-retry-failure-20261001/private/`.
Both are archived locally beneath the isolated
`private/dnsmasq-rewrite/resume-retry-failure-20261001/private/`, in
`baseline-linux/` and `linux-232edb2/`. Configurations, namespace identities,
route changes, raw wires, syscall traces, metric payloads and each harness
version are retained where recorded; none is committed to Git.

These gates do not close DO-query cache admission, other upstream-error retry
origins, complete DNS/EDNS, resource-cost, target or physical-router acceptance.
