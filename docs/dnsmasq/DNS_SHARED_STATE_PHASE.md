# Shared parent DNS state

The parent now owns one forward cache and one upstream transaction table across
all UDP listeners. Previously each listener allocated the configured cache and
forward limits separately. A reply learned on one address was not available on
another, and simultaneous identical queries were sent upstream more than once.
This was a functionality/resource-budget defect, not an optimization result.

`ParentDns` owns both the static local generation and `DnsDaemon` under the
existing mutex. Receiving or sending client packets does not hold it; local
lookups, submissions and zero-wait upstream polling run in the same state
boundary. Each forwarded recipient retains its receiving `SocketToken`; whichever
worker completes an upstream transaction sends each reply through its original
listener socket. TCP connections retain the established per-connection local
snapshot; complete TCP dynamic-cache inheritance/writeback remains open.

SIGHUP synchronously replaces the shared local hosts generation and clears the
single forward cache while leaving pending upstream transactions intact. The
former per-worker reload notification queue and generation lag are removed.
All UDP/TCP DNS listeners are opened before starting those workers, so an initial
bind error cannot leave an already-running partial DNS service. This does not
close later DHCP/TFTP startup, privilege, interface or production lifecycle gates.

`tools/dnsmasq/dns_shared_state_diff.py` runs exact C and Rust with identical
configuration in a private Linux network namespace. The corpus uses three
listeners (two IPv4, one IPv6), a single-record cache and a held upstream reply.
It checks cross-listener hits, shared capacity eviction, duplicate-query
coalescing, IDs, source sockets, flags/addresses and upstream event counts.
Actual TTLs are retained and checked against configured TTL and elapsed time;
only bounded whole-second clock variance is normalized. C supplies the reference
trace. A duplicate upstream event and wrong listener are controlled failures.

Evidence: `private/dnsmasq-rewrite/shared-state-20261001/`. `before-01` preserves
a test-calibration tuple-mutation error. Corrected `before-02` records 1 match / 7
mismatches. `after-01` records **8/8 matches**, including exact upstream sequence
`a, b, a, merge` and three distinct correctly sourced fanout replies. Both daemon
processes shut down normally. The private summaries identify exact C and Rust
ELFs; raw packets/configuration stay private. The reference is the audited native
Linux C build, not the target image artifact; no target-router performance claim.

The same main integration consumes the separately verified DHCP maintenance
`tick` and nonfatal file/DNS/restore reports, and passes the configured domain
policy before DHCP initialization. Their evidence is in `DHCP_PERSISTENCE_PHASE`
and `DHCP_STATIC_PHASE`; a Pending DNS publisher is not counted as successful
publication. The next gate is synchronous DHCP DNS publication with precise
cache invalidation, followed by integrated lease/reload regression.

No throughput or latency saving is claimed. The mutex, remaining listener
threads, per-query sockets and polling strategy still require measurement;
sharing state corrects capacity and behavior before any speed comparison.
