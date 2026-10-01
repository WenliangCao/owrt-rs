# Typed cache transaction prerequisite

The opt-in Rust transfer primitive matches all **36 cases / 307 observations**
from the independently frozen native and SDK-musl C source oracles. Linux native
Rust and SDK-linked AArch64-musl Rust each pass 307/307; an injected counter
change produces 306 passes, one detected failure and exit 1. This closes the
measured primitive boundary. The 32-observation TCP service gate, UBus parent
insertion failure, snapshot representation and production sender remain open.

## Small ownership boundary

`Cache::capture_commit_counted` returns `Some(CacheTransaction)` only when the
real child commit succeeds. `Some(empty)` is distinct from no commit: importing
that empty transaction must still clear the parent's prior pending inserts.
The ordinary `commit_counted` path supplies no capture vector. `Cache` gains no
field, `Clone` implementation, transport, resolver or snapshot representation.

The owned transaction contains committed records in C's pipe order, absolute
expiry and negative-authority name. It contains no child IDs, local targets,
parent references or counter totals. CNAME target bytes are omitted because C
does not transfer them; import reconstructs both the target descriptor and its
RDATA from the immediately preceding received insertion result. This preserves
the observed double reversal of multi-address order and drops an alias whose
child-local target was never transferred.

`Cache::import_counted` applies one whole transaction. Its narrow local-match
callback must use the parent's current hosts/lease/configured-CNAME precedence;
production caller wiring is still pending. Local lease targets receive the
current cache generation. Actual parent insertions and evictions own the
counters. A later collision, zero-TTL or long-name failure does not undo prior
parent removals. An aborted child commit emits nothing, so its earlier removals
remain private.

Import bypasses the ordinary min/max TTL clamps. Positive remaining lifetime
preserves the transferred absolute deadline. Zero remaining TTL follows the
stale policy. For already-past deadlines, integer saturation explicitly matches
the tested source compilers' conversion to zero; with stale enabled, C stores
expiry equal to parent time. As explained in the
[source baseline](TCP_CACHE_TRANSFER_BASELINE.md), that last observation is
compiler/platform dependent and is not proof of the existing image ELF's
behavior. Rust performs no out-of-range floating conversion.

## Allocation boundary

An untimed standalone allocator audit compares the pre-transfer cache source
with the current ordinary path and the explicit capture path. All 15 runs
balance their cache/transaction drops; cache size remains 168 bytes. The
ordinary path's complete allocation vectors match the original in all five
cases: empty, one record, 128 records, invalid CNAME and failed transaction.
Thus capture adds no journal allocations to the measured ordinary path. Existing
HashMap/name-index work can still allocate, including when dropping a CNAME.

| Commit case | Ordinary allocations / reallocations | Capture allocations / reallocations | Ordinary / capture requested bytes | Ordinary / capture live-byte change |
| --- | ---: | ---: | ---: | ---: |
| Empty | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| One address | 3 / 0 | 6 / 0 | 245 / 610 | 245 / 610 |
| 128 addresses | 263 / 0 | 520 / 5 | 30,342 / 54,328 | 17,946 / 31,020 |
| Invalid CNAME | 1 / 0 | 1 / 0 | 8 / 8 | -9 / -9 |
| Failed transaction | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

These are allocator-requested deltas around commit, excluding preparation.
They are not RSS, whole-service memory, CPU or throughput results. Capture
owns copied names/data and a growing vector; allocation failure follows the
allocator's policy. It has no fallible sender or graceful OOM guarantee.
Whole-transaction buffering differs from a streamed C pipe, so memory-pressure
and backpressure equivalence are not claimed.

## Verification and provenance

The source baseline retains six matching C outputs per case. The comparator
pins all 216 output hashes as one digest and checks output counts before Rust
execution. Its ignored library driver seeds two separate owners from common
commands, then diverges their state; it chooses no snapshot implementation and
does not create a DNS transport. The driver's ordinary ignored status is not
counted as a pass: it is explicitly run for all 36 cases by the comparator.

The existing 26 cache/cache-reply tests pass. Three new tests verify empty versus
failed capture, ordinary versus captured commit effects including invalid
CNAME removal, and aborted capture after a real eviction. Library/tests clippy
passes with warnings denied. A local 307-observation run also matches, separate
from the two Linux runs.

Recovered Linux test binaries, command/build logs, traces and allocator source
copies remain ignored under `private/dnsmasq-rewrite/tcp-transfer-20261001/rust-01/`.
The native test ELF is AArch64 PIE; the musl test ELF is AArch64 EXEC without an
interpreter. Source/archive, executable, result and allocator hashes are pinned
in [the sanitized JSON](TCP_CACHE_TRANSFER_RESULT.json). This is a primitive
prerequisite only; no target package rebuild or router access occurred.
