# Independent downstream TCP readiness proposal review

Reviewed proposal `87f4f032` (root equivalent `8f99fafb`) and the existing
`SinglePoll` normal/probe waits, client phases, close paths and failure tests.
This is a static mechanism review, not product approval or a runtime pass.
No product adapter exists yet. No remote workload or router action was run.

**The narrow level-triggered downstream-only direction has no identified
unavoidable semantic blocker.** The authorized existing primitive can compare
14 direct entries with six direct entries plus an eight-entry aggregate before
any product work. It must count group creation, initial ADDs, extraction,
removal/cleanup and bounded churn. The agreed churn is eight initial plus 48
replacement lifetimes, totaling 56 accepts; 56 additional replacements would
measure a different workload. Phase-change MOD cost belongs where that phase
actually occurs, rather than inventing one MOD per cached query.

The following product boundaries remain unresolved and must stay explicit:

- **Eligible ownership:** only live downstream `stream` in Reading/Writing,
  with the actual phase mask. Forwarding waits, MAC waits and log-only clients
  retain their current direct-fd/timer behavior. Permanently registering OUT
  would create idle wakeups. The existing eight-step budget and buffered-input
  runnable path must remain authoritative.
- **Identity and closure:** connection generation must survive vector movement
  and `swap_remove`; returned tokens must match current connection ownership,
  phase eligibility and the interest snapshot before assigning readiness.
  Accepts start with zero readiness. The stale-answer path can take/shutdown
  the downstream stream and immediately open an upstream on the same numeric
  fd; cleanup must not target that new owner. Generation exhaustion should
  disable optional aggregation rather than silently wrap into a live identity.
- **Complete extraction:** one extraction buffer must cover the eligible set
  whose readiness is being reconstructed. The primitive's eight-entry buffer
  covers its eight registrations. A fixed small product batch does not recover
  the original all-entry mask/count. Repeated zero-timeout extraction until
  empty is not a substitute: level-ready unread sources can recur indefinitely.
- **Masks and counts:** reconstruct each original logical entry, including
  duplicate-mask projection and unconditional error/hangup handling, before
  any client step. OUT must never authorize a read; RDHUP must not be silently
  introduced as HUP. The aggregate's own wake is not one ready client.
- **Stale-only wakes and fallback:** an aggregate wake that yields only obsolete
  tokens must not count as real probe traffic or cause an idle spin. Optional
  setup/control failure may select the unchanged direct path; it must not
  consume socket errors, erase already collected direct readiness, or add a
  second blocking timeout after the outer wait. Keep existing poll-wide errors
  and its EINTR policy; the wrapper currently retries the same relative timeout.
- **Probe subset:** `wait_during_probe` intentionally excludes outer signals,
  reload/inotify/route and DHCP dispatch while borrowing the provider. A shared
  group must be reconciled to exactly that call's eligible TCP set, without
  importing an outer ready snapshot. Keep original ready-count/early-deadline
  logic that decides whether the ICMP timeout was consumed.
- **Lifetime costs:** extra buffers/registrations must be bounded, accounted,
  and cleaned on partial setup failure and terminal owner teardown. Do not
  duplicate downstream sockets solely to preserve registration identity.

## Existing resource contract, narrowly checked

An extra persistent epoll fd can reduce free descriptor headroom by one. This
is a real resource cost, **not an automatic correctness rejection**. The
current tests do not require identical numeric failure thresholds across C
and Rust. `dns_start_failure_diff.py:98–105` and
`dns_tcp_accept_failure_diff.py:113–119` compute a separate zero-headroom soft
limit from each process's existing descriptor set. `DNS_START_FAILURE_PHASE.md`
explicitly calls this a functional zero-headroom test rather than a resource
cost comparison.

The actual requirements are observed EMFILE, retained listener and original
descriptors during pressure, correct error/metric behavior, continued service
where expected, recovery of the same queued connection after relief, and
normal cleanup. In particular `dns_tcp_accept_failure_diff.py:163–170` requires
all connections closing to restore **that process's initial FD set**. A group
created lazily and retained forever after its first connection would violate
that existing check. A deliberately fixed startup fd or releasing the group
when empty are possible lifecycle choices; their setup/failure/performance
costs still need measurement. No cross-subsystem hooks are justified solely
to reproduce an unrequired identical numeric exhaustion threshold.

The allocation tests also distinguish handling from exact allocation ordinals:
`hosts_allocations` sweeps failure points and requires bounded stop, coherent
state and later recovery; `FULL_R2_FIX.md` explicitly does not require identical
post-ENOMEM record sets. This does not waive optional-group allocation failures
or authorize a new panic/leak where the direct path can continue.

Existing `components/ubus/src/readiness.rs` has useful Linux epoll ABI/layout
evidence, but is not a drop-in aggregation adapter: its fd is private, `add`
always includes input, the extraction batch is fixed at 32, and its vectors
can allocate. Reusing it wholesale would not resolve the above boundaries.

These points were sent to loop and root. Loop confirmed complete eight-event
primitive extraction, full creation/control/churn accounting, and preservation
of unresolved product identity/resource behavior. No new framework is proposed.
