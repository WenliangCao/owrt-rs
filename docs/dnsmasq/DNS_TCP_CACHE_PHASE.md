# TCP cache ownership and writeback

The exact C `-k` baseline completes 32 observations with private ubusd. Rust
TCP cache inheritance/writeback is not implemented by this baseline milestone.
The existing real UBus gate's missing parent cache insertion remains a failure;
no synthetic counter adjustment is acceptable.

## Source contract and observed baseline

`dnsmasq.c::check_dns_listeners` forks in normal foreground (`-k`) mode. Debug
(`-d`) mode does not fork and cannot establish the child/parent contract. The
child inherits cache, hosts, lease and routing state at accept, closes inherited
ubus listeners and owns its connection-local mutations. `tcp_request` receives
the accept-time `now` and does not refresh it for subsequent queries.

`cache.c::cache_end_insert` commits the child cache and writes a complete
transaction to its parent pipe before the client reply. It sends committed
records in extraction-chain order with absolute expiry times; CNAME targets
precede their aliases. Failed transactions do not call this commit and therefore
do not send a parent transaction, even if earlier insertion attempts already
removed old child records. `cache_recv_insert` processes a whole transaction,
uses the parent's current time and bypasses a second min/max TTL clamp. Its
actual insertions and pressure removals own the parent counters.

The process slot remains occupied until both child exit and pipe EOF have
been observed; either event may occur first. A child must never share the
parent's mutable cache directly.

The real-service fixture verifies:

- Accept inherits existing parent cache entries, but not entries learned by the
  parent after that accept. The latter query goes upstream through TCP.
- Child fills are reusable in the same connection, visible to parent UDP, and
  inherited by a later TCP connection. A, CNAME, negative, SOA/NODATA and
  multi-address rotation are recorded with actual insertion counters.
- A one-second cache TTL still returns TTL 1 in the old TCP connection after
  a 2.2-second wall-clock wait, while the parent expires and refetches it.
  This accept-time clock behavior must be implemented, not normalized away.
- A late child insertion returns the upstream TTL 120 to that client, while
  the parent's written-back entry has TTL at most 118 because absolute expiry
  remains tied to the older accept clock.
- SIGHUP clears the parent cache and changes hosts. Old connections retain
  their cache/hosts snapshot; a new connection inherits the new generation.
- After all connections close, the C `tcp_connections` gauge is zero, the
  parent has no remaining child PID, and its observed descriptor count is 15.
  This is a closing observation, not a peak-resource or performance claim.

`tools/dnsmasq/dns_tcp_cache_diff.py` runs C first, compares protocol fields,
ordered upstream activity and all real UBus metrics, and retains raw bytes.
Only designated cache TTL observations allow a one-second cross-run clock
phase difference; the frozen one-second TCP TTL and intra-run fixed-clock
relations are separately anchored. Missing observation counts and an injected
RCODE difference are comparison errors.

Evidence root: `private/dnsmasq-rewrite/tcp-cache-20261001/`.
`c-baseline-02/` retains all 32 C observations and their UBus calls, packet
traces, configurations and shutdown checks. The first tool-package attempt
lacked a helper import and ran no observation; its archive and failure record
remain private. C ELF SHA-256 is
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.

## Implementation boundary under construction

The prerequisite [borrowed cache engine](DNS_CACHE_ENGINE_EXTRACTION.md) is
extracted and revalidated. A TCP owner can use its record builder and insertion
logic without constructing a UDP resolver or copying a local-name generation
inside the engine. Snapshot representation, typed commit transfer, failures,
backpressure, lease-publication changes and resource-cost gates remain open.
Snapshot clone/sharing candidates will be measured before choosing one; a full
deep clone is not presumed to be a resource improvement over C's fork/COW.
No target, production or performance acceptance follows from this milestone.
