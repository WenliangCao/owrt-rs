# Narrow next readiness mechanism screen

Status: proposal only, after the exact D profiles and the 21-case cardinality
screen. No product backend, new public API, registration hooks or framework is
implemented. The measured deferred 14-minus-1 cost is potentially material,
but cannot be treated as an achievable epoll saving.

## Lower-complexity alternatives

1. **Retain ppoll and shorten userspace scans.** This preserves all semantics,
   but capacity is already reused and the userspace wait section is only
   0.813% of D TCP-hit samples. It does not address repeated kernel wait setup.
   No new product state is justified by this evidence alone.
2. **Reorder poll entries toward a likely-ready fd.** The finite already-ready
   primitive shows order sensitivity, but real deferred waits must inspect the
   empty set before sleeping. Rearrangement does not remove the demonstrated
   deferred term and could change attribution/order bookkeeping. It is not
   the selected next mechanism.
3. **Direct select/pselect replacement.** Independently rejected as an
   equivalent adapter: its sets combine readable/writable error and hangup
   conditions, while invalid descriptors can produce a call-wide error.
   Current consumers use distinct ERR/HUP/NVAL bits, and the owner propagates
   poll-wide failures. Duplicate descriptor masks and ready-entry counts
   would also need expansion, and fixed fd-set limits require fallback.
   Reconstructing exact events with extra poll calls has no measured benefit.
   These are documented interface differences, not an assertion that every
   select-based algorithm is impossible. [Linux select manual](https://man7.org/linux/man-pages/man2/select.2.html).

The independent local review also confirmed that current positive-fd interests
do not establish a special zero-events case; the explicit zero-event producer
uses fd=-1 for a budget yield. Regular files are a separate epoll compatibility
concern, not a reason to falsely claim select rejects them. EINTR behavior and
timeout resets must preserve the existing wrapper, without adding signal-mask
or deadline policy changes.

## Smallest candidate worth falsifying first

Use **level-triggered aggregation of owned downstream TCP sockets only** as a
diagnostic mechanism. Keep the existing outer ppoll for everything else:
listeners, signals, UBus, file/log/dump inputs, upstream transports, DHCP,
TFTP and netlink. With eight active TCP clients, the observed fourteen-entry
wait would ideally become seven entries: the six other entries plus one
aggregate readiness descriptor. This narrower reduction is smaller than the
14-to-1 screen and adds a zero-timeout event-extraction call. Its actual benefit
is unknown and could be below the frozen precision threshold.

This scope avoids registering regular files and keeps their failure boundary
in the existing ppoll path. Linux documents the epoll instance itself as
pollable, and level-triggered readiness does not require draining every source
to EAGAIN. File-descriptor numbers alone are insufficient identities; epoll
registrations also refer to the underlying open file description, and duplicate
owners complicate close removal. [Linux epoll manual](https://man7.org/linux/man-pages/man7/epoll.7.html).

Do not instead aggregate "stable files" merely because their number is small:
the actual descriptor-kind/lifetime inventory is not captured by abbreviated
nfds traces, some interests are conditional, and regular files can be rejected
by epoll registration. A six-to-one reduction would still need ownership hooks
across unrelated subsystems. TCP ownership is already confined to one owner.
[Linux epoll_ctl manual](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html).

```text
existing explicit owner interests + deadlines + runnable state
  |-- all non-downstream-TCP entries ----------------------> ppoll
  |-- eligible owned downstream TCP entries -> LT group --> ppoll
                                                           |
                    full current per-client revents <------+
                    then unchanged owner step ordering/budgets
```

This is a narrow hypothesis, not an API design approval. In particular:

- Keep current per-call interest construction, deadlines and admission gates.
  Do not permanently register both IN and OUT: ready OUT on idle sockets would
  wake continuously. Only a phase with a live downstream socket and the
  applicable wanted mask may participate. Upstream-forwarding and MAC-wait
  phases retain their existing fd/timer behavior.
- Give an accepted connection a monotonic generation, preserved across vector
  movement and `swap_remove`. Match returned events to that generation and
  current socket; never to a reused fd alone. Reconcile removals before adds,
  and never duplicate/retain a socket merely to keep registration identity.
- Expand results into the original per-client ready-event shape before any
  client is processed. Recompute original ready-entry counts and network/file
  diagnostics, rather than reporting one aggregate wake as one client.
  Stale tokens, close/reopen and mask changes must be explicit controls.
- Preserve level readiness, ERR/HUP handling and direct-poll fallback for
  invalid descriptors or unsupported/control failure boundaries. A fallback
  cannot consume socket errors or change which work is processed first.
  Resource exhaustion during optional group creation/registration must not
  introduce a new daemon failure where ppoll could have continued.
- Preserve the one-hour active-timer cap, idle infinite wait, runnable zero
  timeout and missing signal-pipe fallback. The aggregate replaces descriptors,
  not timer policy. No new timerfd belongs in the product proposal.
- Apply the same narrow downstream selection to normal and DHCP-probe waits;
  keep the probe's exclusion of outer signals/reload/inotify/route/DHCP work.
  The provider's borrowed state and separate packet buffers must remain intact.
- Retain the 16-packet UDP budget, eight TCP steps, 100-answer closure, partial
  write handling and stale send/close/refresh ordering. No edge-trigger or
  one-shot rearm policy is proposed.

## Concrete next validation boundary

Before any product edit, extend only the existing primitive screen with a
direct fourteen-entry control versus six direct entries plus one level-triggered
group containing eight entries, including one explicitly labelled timerfd
stand-in. Include the actual extra event
extraction and registration/control calls in counts. Use the same deferred
wakeup/coalescing/context-switch reporting; because timerfd is a mechanism
stand-in, separately label it and do not transfer its result to TCP latency.
First test stable membership and a bounded churn schedule matching 56 accepts
per 5000 queries. Preserve all control costs, not only the final wait syscall.

Cheap correctness controls must precede application timing: close/reuse with
the same numeric fd; removal after one ready event invalidates another; duplicate
logical masks; readiness remaining after a bounded partial read; mask changes
without losing ready data; EOF/HUP; injected poll/control failure; optional
backend allocation failure; and unchanged normal/probe subset behavior.
If generation handling or fallback needs broad subsystem hooks, stop this
candidate and report that concrete complexity rather than expanding the design.

Only a meaningful total mechanism saving would justify a small product fork
and independent review. Its qualification then includes existing owner
readiness/fairness/probe tests, full allocation and exact-C families, blocked
TCP memory/FD controls, all frozen performance scenes and both resource and
precision gates. Current D and its device attempt remain unchanged.
