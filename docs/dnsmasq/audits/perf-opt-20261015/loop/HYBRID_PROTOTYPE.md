# Local selective owner-wait prototype

Base: immutable E repair `4f869c885b47dcf60d56c872e5b0b3c62237beea`.
This separate branch contains an unqualified prototype, not a change to E.
No router or Oracle command was used. Local Rust 1.98.1 `cargo check --frozen
--jobs 1 --target aarch64-unknown-linux-musl --tests` passes; Linux tests have
only been type-checked, not executed.

The private binary module `owner_readiness.rs` takes the existing complete
PollFd slice plus marked eligible slots. It does not replace the shared ubus
poll function or change any library API. The existing normal/probe owners
still construct their explicit interests, deadlines and runnable state and
consume the same returned per-slot revents/counts in the same order.

Eligible descriptor lifetimes are explicit:

- DNS listener token plus UDP/TCP role. Deferred Arc ownership does not create
  a new numeric fd or reuse a retired listener token.
- Signal read pipe installed once in this SinglePoll and fixed RouteWatch
  descriptor. Keys are owner roles, not object/heap addresses. Probe construction
  marks neither role.
- Downstream TCP in Reading/Writing phases, with a checked monotonic accept
  generation retained across vector movement. Counter exhaustion leaves later
  connections on direct poll. TCP upstream, MAC-wait and closed-stream phases
  are never tagged by that accept generation.

Every other entry remains direct, including ephemeral UDP upstream, TCP
upstream, UBus, helper, collectors, file jobs, logs/dumps and TFTP. No estimate
claims which four previously unidentified baseline descriptors are present;
the inventory gap remains separate from source-derived eligibility.

Registration stores its own checked monotonic event token. Removed lifetimes
are reconciled before additions, including reuse of a numeric fd. Duplicate
slots on the same eligible fd merge requested masks and expand back to their
individual masks and original ready-entry count. Conflicting keys for one fd,
unexpected input masks, allocation/control failure or stale event tokens
disable the optional backend and return to direct poll. Source descriptors
are never closed, duplicated or retained by the module.

There is no unconditional zero-timeout poll in front of the optimized wait.
The private eligibility contract requires a live owned descriptor throughout
the synchronous wait: only the owner may close/replace it, and must withdraw
or change its key. No production path or existing owner test was found which
manually closes one of these descriptors while retaining that same live key.
Initial invalid registration still falls back to original per-slot NVAL.
Descriptors without a demonstrable lifetime contract remain direct.

With no direct entries, one epoll_wait uses the original timeout. Mixed sets
use ppoll on direct entries plus the aggregate fd, then at most one nonblocking
event extraction sized for all registered members. No LT drain-to-empty loop,
RDHUP translation, signal-mask change or new timer policy is introduced.
EINTR repeats the supplied timeout as in the existing wrapper. Internal
error/stale-only fallback retains the remaining original wait budget: an
internal wake cannot masquerade as a full idle quarter-second to a DHCP probe.

Optional creation is attempted once. Scratch growth uses try_reserve; failure
drops the optional epoll fd, frees its scratch and permanently disables the
optimization. A failed backend does not retain a useless descriptor to match
a test baseline. Normal successful operation holds its constructor-created
fd until owner Drop, so its cost belongs in the process's initial fd set.
Reconciliation/expansion currently uses bounded linear searches. More than
64 tagged slots selects direct poll for that call, without changing the
product's connection limit or permanently disabling later small-set use.

Eight Linux tests cover SDK event layout, duplicate masks and subset removal,
mixed direct regular-file readiness and unsupported registration fallback,
numeric fd replacement with a new generation/EOF comparison, initial NVAL,
64 simultaneously ready members and 65-entry fallback, stale-only wake idle
budget, and internal extraction failure idle budget. They are prepared for
the existing isolated Linux test gate after the Oracle reservation ends.
No runtime pass is claimed from local cross-compilation.

Independent caller tests (`44477146`, fixture correction `dd78a4a7`) additionally
exercise a queued normal-only signal across a full quiet probe interval,
subsequent normal signal drain and real UDP progress, and an expired ready TCP
client followed by a new client/probe turn with no inherited readiness. The
fixture has a real DnsDaemon; a missing-daemon draft was caught statically
before execution. Their module hook is included and the complete Linux-target
test build was cross-checked again. These two tests also remain unexecuted.

Before candidate eligibility, count actual initialization/teardown, memory
layout, optional fd/watch cost, registration/mask churn, all-ready and large
direct-fallback cases as well as steady waits. Startup/lifecycle can regress
even if waits improve. Independently review real normal/probe owners, fd-limit
failure/recovery and original resource cleanup; run the unchanged full unit,
allocation, C-family and eleven-scene performance/resource gates. No fallback
rule or threshold is changed to obtain a pass.
