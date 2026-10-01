# Private TCP cache correctness reference

This **private worktree only** implements ordinary TCP accept-time cache
inheritance, a fixed connection clock, and typed parent writeback. It uses a
complete cache clone as a correctness reference. It is **not an accepted
snapshot representation**, a production merge, or a resource/performance pass.
All four previously screened representations still fail their existing cost
guards. The shared product cache must not acquire this experiment's `Clone`.

Frozen source `86b81ab` includes the private implementation through `cdb909e`
and the separately gated DO/name-presence fixes `a0fa1b8` and `a4b3087`.
Its native aarch64 ELF SHA-256 is
`21d2a14a0690332958bbf381f0047bc6cc81d4cc1660d6effa017b2ea8462a6d`.
The exact matching-source native C oracle remains
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.

| Final-source gate | Result |
| --- | --- |
| Actual `-k` TCP inheritance/writeback/clock/HUP | 32/32 observations match C |
| Native UBus daemon integration | 69/69 paired observations, 581/581 checks |
| Independent doctor/writeback/slot-order gate | C 12/12 and Rust 12/12, first attempt |
| Actual EMFILE listener recovery | 17 observations, zero differences |
| Shared TCP capacity/admission | 31/31 observations match C |
| Namespace-isolated Linux tests | 395 library + 7 main passed; 16 ignored |
| Native and aarch64-musl all-target Clippy | Both pass with warnings denied |

The independent gate holds a parent doctor while one existing child completes
two cold queries, checks queued UBus metrics before commit, establishes the
lowest-slot import winner for two children, then closes those children while
the parent is held and verifies drained release and replacement inheritance.
It ran C first on the final artifact once, with no timing retry.

The UBus gate closes the existing **native** TCP parent-insertion failure.
It does not erase the separate target musl C failed-address-parse difference or
qualify a new SDK/image artifact. Every service gate ran C first through
`run_isolated.sh`; no router was accessed. The ignored tests are not passes.

The child owns its local-name and dynamic-cache generation. It answers and
inserts using the accept clock, restores request CD before TCP extraction,
and never acquires a parent lock to send a transaction or downstream reply.
Parent import uses current parent hosts/leases and actual insertion counters.
The transport is a real `owrt_ubus::sys::pipe()` with kernel byte backpressure,
not a bounded message queue or parent acknowledgement cycle. It can buffer
successive small transactions while a parent doctor callback is waiting.

Admission chooses the highest free indexed slot; drain chooses the lowest
ready slot and consumes one complete transaction per event. UBus processing
precedes a new drain. A fragmented transaction pins its slot and entry clock,
deferring parent UBus, UDP, DHCP, reload and TCP admission until completion.
Socket/pipe waits occur outside parent locks. Slots require both a joined
worker and completely drained transfer EOF before release. STOP is checked
under the admission lock. Poll uses only raw descriptor-number wake hints;
actual reads recheck the current owner under its lock, so stale readiness
cannot read a reused descriptor and no duplicate FDs consume EMFILE headroom.

The typed codec rejects impossible record counts, malformed/truncated fields,
and compressed IPC names. Tests cover two buffered transactions with no ACK,
partial input and truncated EOF, cancellation under full-pipe pressure, TCP CD
restoration, a fixed cache clock and explicit stale-policy rejection.

The first private `bcf9e88` 32-observation attempt failed at the one-second
record: existing 50/100ms parent polling made the preceding metrics/query
sequence last longer than the child's fixed TTL, so parent insertion correctly
aged it out. The gate was not relaxed. Polling actual UBus/pipe readiness fixed
the scheduling delay; both `bb137e8` and final-source 32-observation gates pass.
The original failure remains under `bcf9e88/private/gate-32-01`.

Two added unit fixtures initially lacked `no-resolv`, causing startup failures;
the final fixture-only correction is `86b81ab`. A first Clippy invocation met
root-owned build output from the namespace test; after task-directory ownership
repair the unchanged source passed. Both failure logs remain. An initial
`bcf9e88` unit run accidentally used the ordinary oracle host namespace; it is
not counted as acceptance. The exact command selected `--lib --bins`, with no
name filter and without `--ignored`: 392 library and 7 main tests ran, while
all 16 marked tests stayed ignored. Those include the four DHCP listener tests,
net pktinfo, interface snapshot and two TFTP listener tests. Source inspection
finds DNS fixture listeners on `127.0.0.1:0`, anonymous transfer pipes, but also
wildcard ephemeral UDP client sockets (`0.0.0.0:0` / `[::]:0`) and DHCP provider
control sockets (`0.0.0.0:0`). The provider fixtures use `no_ping=true` and lookup
callbacks. Therefore this was **not** exclusively loopback-bound/anonymous-pipe
execution. There was no packet capture, so this source audit does not claim an
observed absence of off-host traffic. The complete ignored list and audit
boundary are in the JSON. The suite was subsequently rerun through the isolation
wrapper, including the final fresh source above.

Capture, encoding and decoding allocate vectors under Rust's allocator policy.
OOM/resource equivalence remains unqualified. The typed codec does not reproduce
C native-ABI byte sizes, so pipe saturation at every source transaction size is
not qualified by the two-small-transaction gate. Whole-transaction decoding and
abnormal partial-EOF effects do not establish C's incremental failure behavior.
Stale-enabled TCP is explicitly rejected by the private snapshot API; its
close/refresh behavior needs a separate gate. UDP stale policy is unchanged.
The later source review also identified the separate CD/no-cache plus bogus-
wildcard composition boundary: C can commit the independent bogus transaction
when ordinary extraction is disabled. This private caller still guards the
whole capture call, so that combination remains a known gap; the ordinary
functional gates above do not cover or qualify it. The product owner is
separately gating the borrowed-engine eligibility split.
No CPU/RSS, long-run pressure, target-runtime TCP or production-delivery claim
follows from these functional checks.

Full raw evidence is ignored under this worktree's
`private/tcp-reference-evidence/`, with the final oracle copy at
`/home/ubuntu/dnsmasq-tcp-private-20261001/final-02/`.
The companion [sanitized JSON](TCP_PRIVATE_REFERENCE_RESULT.json) pins gate
counts and raw result identities without committing packets, configs or ELFs.
