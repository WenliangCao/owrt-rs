# Frozen untimed reverse name-index footprint plan

Compare source `62894d657341827f3ea1e903375a6263dbe4de82` with
`0eaaef813893ac71954f56c379f8fc6b5eb24064` using direct cache primitives, without
network traffic or timing. The old source omits reverse entries from the name
index and has the already-proven expiry bug. It is a cost reference, **not an
equivalent or acceptable implementation**. This study quantifies the required
index's requested allocations; it cannot select the old behavior for being
smaller or establish a performance pass.

Freeze the executable and its source identities before the first measurement.
There are **eight cases × two sources = sixteen fresh process invocations**,
one per cell, with no added rounds. Retain any compilation, model or allocation
failure. A model discrepancy is a result, not permission to change the numbers
below. No product source, cache layout or allocator behavior is changed.

## Fixed inputs and measurement boundaries

Use native AArch64 Linux, rustc 1.98.1, the existing allocation meter extended
with its already-used deallocation counters, and capacity **8**. Policy is the
default unless explicitly stated; no capture, import, local source, CNAME,
negative, long-name or allocation-failure path is involved. Every target is one
of `n0.test` through `n3.test`: stored/canonical wire length **9 bytes**. Addresses
are fixed documentation-only IPv4/IPv6 values in the executable fixture.

Record inputs are prepared explicitly; measure creation, preparation/insertion,
commit, lookup, cleanup/reuse and final drop separately. Keep result storage on
the stack and emit JSON only after the final allocation snapshot. Use borrowed
entry inspection for assertions, and materialize/drop lookup result vectors
within their measured phase. No formatting or input parsing enters a phase.
Retain absolute vectors as well as fixed-minus-old deltas:
`alloc calls, realloc calls, requested bytes, live-byte change, dealloc calls,
deallocated bytes`. Layout and final live-byte balance are recorded separately.

| Case | Schedule after empty cache creation |
| --- | --- |
| empty | Start and commit an empty transaction; drop |
| single-v4 | One reverse IPv4 record at 100, TTL 60; commit; address lookup at 101; drop |
| single-v6 | Same with a reverse IPv6 record |
| shared-forward-name | Commit one forward IPv4 record for `n0.test`; then commit one reverse IPv4 record of the same target name; lookup both directions; drop |
| three-targets | One transaction containing three distinct targets for one IPv4 address, TTL 60; commit; address lookup; drop |
| four-targets | The same with four targets, exercising the first name-table growth |
| repeated-target | Two reverse entries with the same target and address in one pending transaction, TTL 60; commit; address lookup; drop |
| expiry-and-reuse | One reverse IPv4 record at 100, TTL 10; commit and live lookup at 101; reverse lookup at 110 removes it; insert/commit the same target/address at 111, TTL 60; drop |

All commits succeed. `inserted` is respectively 0, 1, 1, 2, 3, 4, 2, 2;
`live_freed` stays zero. Pending entries stay invisible. Every nonempty reverse
lookup has its expected count before expiry, the expiry lookup is empty, and
every complete lifetime ends with zero outstanding requested bytes. These
selected schedules have matching logical results; they do not excuse the old
source's known forward-triggered reverse-expiry failure outside the matrix.

## Exact expected growth model, frozen before measurement

The source adds one canonical key per previously unseen target and one slot
vector per indexed target. For this pinned native runtime, the retained
ordinary audit gives a first-name commit of **245 bytes in three allocations**
for `n0.test`: key 9, slot vector 4 × 8 = 32, first name table 204.
The retained 128-name ordinary vector independently fits table allocations
204, 400, 792, 1576, 3144, 6280, 12552 plus its keys and slot vectors, yielding
the already-measured 30,342 requested / 17,946 live bytes. This uses prior
evidence; no new allocation measurement has been made for this plan.

The first table holds three distinct keys; the fourth grows it to the next
400-byte table and releases the old 204 bytes. A second record at an existing
target creates a temporary 9-byte canonical key but needs no vector growth
while the target has at most four slots. Lookup of a live reverse record does
not consult the name index and should have zero allocation delta between
sources. No additional Cache/Slot/Entry/Record field is predicted.

Expected **fixed-minus-old** reverse-commit deltas:

| Commit | Alloc / realloc calls | Requested bytes | Live-byte increase | Dealloc calls / bytes during commit |
| --- | --- | ---: | ---: | --- |
| Empty | 0 / 0 | 0 | 0 | 0 / 0 |
| Single V4 or V6 target | 3 / 0 | 245 | 245 | 0 / 0 |
| Reverse added to existing forward target | 1 / 0 | 9 | 0 | 1 / 9 |
| Three distinct reverse targets | 7 / 0 | 327 | 327 | 0 / 0 |
| Four distinct reverse targets | 10 / 0 | 768 | 564 | 1 / 204 |
| Two records at one reverse target | 4 / 0 | 254 | 245 | 1 / 9 |
| Reuse after single-target expiry | 2 / 0 | 41 | 41 | 0 / 0 |

For expiry-and-reuse, the initial commit has the single-target delta. Expiring
that target adds one temporary canonical-key allocation of 9 bytes and
deallocates the temporary key, stored key and slot vector: **3 frees / 50 bytes**,
for a relative live-byte change of **−41**. The empty table retains 204 bytes.
Recommit needs only the new 9-byte key and 32-byte slot vector. Across this
whole lifetime the extra index requests are **6 allocations / 295 bytes**, all
freed by the end; this does not imply retained memory after cache destruction.

For the other complete lifetimes, extra allocated/deallocated call counts and
bytes are, respectively: empty 0/0; each single-target case 3/245;
shared-forward-name 1/9; three-targets 7/327; four-targets 10/768;
repeated-target 4/254. Reallocation deltas are zero in all eight cases.
The forward seed, record preparation, ordinary insertion and live lookup phases
are predicted to have zero differential allocation vectors. Fixed and old
absolute vectors are still retained to expose a mistaken cancellation.

Requested bytes are allocator requests, not allocator usable-size overhead or
RSS. Live snapshots are not a claim about whole-service peak memory. This gate
sets no improvement/regression threshold and measures no CPU time, throughput,
stock-image service, TCP transfer, OOM or router deployment. The separately
passing ordinary five cases remain their original denominator.
