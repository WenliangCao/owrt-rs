# DNS upstream TCP session boundary

2026-09-30. The transport is implemented and its defined normal/failure paths
have isolated socket evidence. **Full C equivalence is not accepted:** two
malformed-response cases expose a deterministic reference framing defect and
remain explicit differences pending the compatibility decision. The module is
not the complete `tcp_request` service or a performance result.

`TcpUpstream` is owned by one downstream TCP session. It accepts the selected
`GroupId`, an already prepared query, the downstream absolute deadline and a
stop callback. It returns the raw upstream response. The caller still owns
local answers, routing, query EDNS options, address/rebind handling, CD/AD/RA
and OPT reply processing, cache effects, downstream framing and error replies.
The shared `RoutingTable::from_runtime_config` now supplies the same implicit
resolver-file/default route to UDP and TCP callers.

| Exact C contract | Rust boundary and evidence |
|---|---|
| `forward.c:2036–2151`, `config.h:21`: ordered candidates, session-persistent `server->tcpfd`, remembered successfully connected server unless strict-order, 5-second connect/write and 10-second read timeouts | A small group/server table owns `Option<TcpStream>`; no extra threads, task scheduler or dependency. C/Rust persistent, RCODE, failover and IPv6 scenarios compare raw packets and socket counts. |
| `forward.c:2153–2170`: an I/O failure on a connection that previously produced a reply reconnects to that same server once; a fresh failure advances to the next server | `had_reply` belongs to each connection and resets on reconnect. The recorded two-query sequence has one successful old connection, its EOF, one failing replacement, then the second server's success. |
| `forward.c:2173–2195`: accept QR + one matching question/name/type/class; no ID check and no RCODE-driven UDP retry logic | REFUSED and SERVFAIL are returned unchanged; mismatched question/type/class/QR advances server; an altered ID and TC are retained as the reference does. The separate old `tcp_exchange` helper has a different, stricter one-shot contract. |
| `forward.c:2156–2159`: read the two-byte length before growing/reading the payload; retain a mismatching connected peer until session teardown | Split prefixes/bodies, premature EOF, 65,535-byte reply, mismatch and zero frame cases keep exact raw bytes and owned-socket counts. |
| `dnsmasq.c:2198–2206`: close every upstream TCP descriptor after the downstream session | `clear`/Drop close all session-owned streams; the probe asserts `CLOSED 0` and the fake upstreams observe actual EOF. Unit cancellation also checks descriptor reclamation. |

Read/write operations are nonblocking and poll in at most 50 ms intervals so
cancellation and the outer absolute deadline remain observable. Idle timeouts
reset after progress, matching the C socket timeout boundary. On the Linux
aarch64 target and Linux x86_64, connect now uses the same poll interval and
deadline/cancellation checks through the small `tcp_connect.rs` ABI boundary.
Other development hosts retain std's bounded connect fallback, which cannot
observe cancellation mid-call. The target-specific confirmation appears below.

## Reproducible isolated evidence

`tools/dnsmasq/tcp_upstream_diff.py` compiles a test wrapper that includes the
unchanged, hash-verified `forward.c`, allowing its actual static `tcp_talk`
function to be called. It replaces only `forward.o` in the test link; remaining
objects come from the exact C build. Both compilation paths use the six target
COPTS and reject unverified native object/header variants. The Rust probe uses
the actual `TcpUpstream` and `RoutingTable` modules. Neither probe is installed
in the product.

Build with `--build-reference <exact Linux reference build> --output <private
build directory>`, then invoke `--binaries <build directory> --output <new
private run directory>` through `tools/dnsmasq/run_isolated.sh`. The runner
requires `DNSMASQ_TEST_ISOLATED=1` and a namespace containing only loopback;
all fake upstreams are TCP, and no DHCP listener is started.

`private/dnsmasq-rewrite/tcp-upstream-20260930/run-03/summary.json` records
**20 cases, 25 queries per implementation**. **18 cases / 23 queries match**;
**2 cases / 2 queries differ** for the reference defect below. There is no
packet, ID, ordering or socket-count normalization. Per-server connection and
query order, announced frame length, full/partial query bytes, final close
counts, every reply, stderr and failed run-01 remain in the private evidence.
Timing is retained only as diagnostic data and is not a speed claim.

The harness calibrates a successful three-query persistent connection and
fresh failures at both servers, requires the exact output count plus
`CLOSED 0`, and waits for the peers' real EOF before ending their worker loops.
The four Rust loopback regressions cover reuse/RCODE behavior, reconnect and
failover, refused-connect cleanup and cancelled-read cleanup. The related DNS tests and all-targets
clippy pass; main integration and target building are separate gates.

## Reference framing defect: open compatibility decision

`tcp_talk` initializes `length = htons(qsize)` once at `forward.c:2060` and
points the outgoing length iovec at it. It subsequently reads each upstream
response length into the same variable at line 2156. When that response is
rejected and the next server is tried, the outgoing prefix is not reset to the
query length. The next server can therefore receive a zero-length frame or a
frame announcing more bytes than the query contains.

The `zero` case records an announced length of zero at the second upstream.
The `wrong-length-question` case records an announced reply-derived length,
an incomplete copy of the original query and eventual EOF. C returns no reply;
Rust resends the valid original query frame and receives the second server's
answer. These are observable protocol and retry side-effect differences, not
random ID/order variation. Raw evidence is retained, the differential exits
nonzero, and neither case is relabeled as passing. Rust's correct framing is
retained pending the explicit compatibility decision; no C byte-corruption
behavior is silently imported.

Persistent connection reuse avoids repeated connect/close operations by
mechanism, but no throughput, CPU, allocation, memory, target-router or overall
resource improvement has been measured for this phase.

## Linux pending-connect cancellation

`tcp_connect.rs` creates a CLOEXEC/NONBLOCK stream socket atomically, owns it
through `OwnedFd`, polls writable/error readiness and reads `SO_ERROR` before
returning a `TcpStream`. The two `repr(C)` address layouts are size-asserted;
their initialized buffers remain alive for the exact-length connect syscall.
All failure, timeout and cancellation exits drop the sole descriptor owner.
This is the only added unsafe boundary; no dependency was introduced.

`tcp_connect_probe.py` requires the dedicated loopback-only namespace and adds
one temporary OUTPUT DROP rule restricted to its ephemeral TCP listener. It
verifies the packet counter and removes the rule in `finally`; the namespace
itself also contains the rule's lifetime. With seven SYNs confirmed dropped,
five pending connects cancel after the 100 ms test trigger, one hits the 150 ms
connect timeout and one hits the 150 ms outer deadline. All seven finish within
the frozen one-second functional bound, zero connections are accepted and
`/proc/self/fd` enumeration counts stay 4 → 4 (including the enumeration FD).
The measurements validate cancellation behavior, not throughput improvement.

Evidence: `private/dnsmasq-rewrite/tcp-upstream-20260930/connect-02/summary.json`.
The same newly built transport reruns the existing 20-case C socket corpus in
`run-03`: no additional differences beyond the two retained reference framing
defects. `refused-01` adds one exact-C connection-refusal/failover case with zero
mismatches and checks the SO_ERROR failure path. The tool supports `--case`
for future affected-case runs rather than repeating unaffected long timeouts.

Native-host and `aarch64-unknown-linux-musl` all-targets clippy both pass with
`-D warnings`. An additional native-Linux clippy invocation was blocked by that
host's installed clippy-driver reporting compiler 1.98.0 against the crate's
1.98.1 minimum; it was not bypassed or counted as passing. Linux execution
evidence uses the native rustc 1.98.1 build. This transport check does not stand
in for shutdown/reload/resource verification of the full daemon caller.
