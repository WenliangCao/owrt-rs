# UDP receive errors retain the forwarding transaction

The transport now ends a failed receive batch without cancelling the query.
This follows exact C `forward.c::reply_query`: a failed `recvfrom` returns
before forwarding-record lookup. ID, merged recipients, owned socket, retry
state, forwarded/unanswered counters and the original deadline remain intact.
The **20 upstream tests pass on Linux**, and the actual-service recheck passes
**52 behavior checks with zero C/Rust trace differences**. Real application
errno delivery remains unobserved, as recorded in
[the earlier ICMP experiment](DNS_UDP_ICMP_RECOVERY_PHASE.md).

## Error boundaries

The private callback boundary substitutes only `recv_from` and `take_error` for
tests. Production calls the standard socket methods directly. Sockets still
use bind plus sendto; no connect, RECVERR option, raw-packet transmission or
production network is introduced to manufacture an error.

- WouldBlock ends the batch. Interrupted retries within the existing limit of
  16 receives. Other receive errors end the batch and retain the transaction.
- POLLERR reads and consumes SO_ERROR once. A pending socket error without
  readable data ends the batch without cancelling. If data is also readable,
  the authenticated response can still complete the transaction.
- POLLNVAL is a terminal unusable-descriptor event. POLLHUP without POLLIN and
  failure of socket-error inspection are separate explicit terminal
  boundaries. The UDP hangup/inspection assumptions are tested by injection;
  they are not claimed as observed kernel events on the deployed socket path.
- A first POLLERR with empty SO_ERROR and no received datagram has no delay.
  Repeating this unconsumable readiness schedules that socket's next poll for
  10 ms later. Its retry time participates in the existing poll deadline;
  its query deadline is never extended. Normal readable progress resets the
  guard. Cancellation/completion still release the socket normally.

The last rule is a defensive scheduling decision, not C source behavior.
C's dispatcher calls `reply_query` for POLLIN. The controlled pre-guard fixture
shows three immediate empty-error reads for three repeated readiness events;
the repaired fixture permits two and suppresses the third until the scheduled
retry, then receives a real ordinary UDP reply. It does not establish that
the kernel produces that persistent empty-error condition in production.

## Cost and tests

There is no additional socket traversal: retry deadlines are accumulated in
the existing descriptor walk. The guard adds one `Option<Instant>` per owned
upstream socket. `size_of` on the tested macOS and Linux hosts is 40 bytes for
the new socket record versus 24 bytes for its previous three fields: **16
additional bytes per socket**, excluding allocator/hash-table overhead.
Persistent empty readiness can delay response processing by the configured
10 ms plus caller/OS scheduling; a single receive error and normal traffic
have no intentional delay. CPU, throughput, tail latency, RSS and router cost
have not been benchmarked here; this is a correctness repair with an explicit
storage/scheduling cost, not a performance gain claim.

The new tests exercise both fixed standalone lifetime and the production
forwarding-table lifetime. They keep two merged recipients through controlled
ConnectionRefused, ConnectionReset, TimedOut and Other errors, verify unchanged
IDs/counters/deadlines, then complete with a real socket reply and check zero
remaining transactions/sockets. Separate tests cover consumed SO_ERROR with
and without data, fixed-deadline expiry, the 16-attempt Interrupted budget,
terminal invalid-descriptor/hangup/inspection events and deterministic retry
of persistent empty readiness. No owned OS descriptor is deliberately closed
behind Rust's ownership model.

The Linux source-01 run passed all 20 upstream tests. Its whole daemon build
failed because the shared snapshot caught an unrelated daemon/main interface
transition; that failed artifact is retained and is not marked as built.
The subsequent service snapshot is based on the already-built alias
`service-source-03`, with only this upstream source replaced.

The source-02 Linux release build succeeded. Its ELF SHA256 is
`40443992b3abd6a1732c78e92823a5f3f7034dcb4c031166f3055bb1fbc0fd54`.
The existing isolated ICMP/retry fixture reports 52 passed, zero failed and
`receive_error_path_covered=false`, with the intended **exit status 2**. IPv4
and IPv6 traces agree with exact native C; the actual unconnected daemon
sockets still produced no observed non-benign receive error. That recheck
validates ordinary retry/reply/socket cleanup after the refactor, not the
injected syscall branches. Library clippy passed with warnings denied.

Evidence roots:

- `private/dnsmasq-rewrite/upstream-boundary-20261001/`: the red
  `empty-pollerr-before-01.log` and its source patch; intermediate receive-error
  logs; local final clippy. `receive-errors-after-02.log` retains an intermediate
  fixture failure caused by reading before actual UDP readiness. The fixture
  now waits for POLLIN before exercising its injected readiness callback.
- `private/dnsmasq-rewrite/receive-errors-20261001/`: frozen source identities,
  Linux tests/builds and `source-02/icmp-recheck-01`, the actual closed-port
  service recheck. `source-02-identity.json` records the earlier frozen base,
  the single overridden file, full archive hash and output ELF identity.

These tests establish the labeled controlled paths. They neither turn the
earlier receive-errno coverage gap into a pass nor establish global functional
equivalence or production acceptance.
