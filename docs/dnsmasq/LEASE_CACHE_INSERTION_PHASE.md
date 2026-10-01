# Upstream insertion with local lease and hosts records

`lease_insert_diff.py` exercises actual C `extract_addresses`, `cache_insert`,
`cache_find_by_name` and `answer_request` against the Rust daemon's corresponding
production helpers. It opens no listener. All configurations, commands,
packets, executable identities and outcomes stay in ignored private storage.

The first baseline has 26 scenarios, 188 command observations, 66 DNS queries
and 36 typed dynamic-cache counts. The counts exclude C's hosts/config/DHCP
records, so a wrong forwarded entry cannot hide behind a correct local answer.
Calibration observes a real miss, insertion, hit, expiry, and count transition;
an invalid C configuration must fail. The comparator rejects truncated output
and detects a one-field TTL mutation. Rust comparisons use one frozen test
executable, recording its SHA-256 and source identities. DNS compression/name
case is normalized; flags, TTL, addresses, record order and event order remain
significant.

The first implementation unit routes UDP cache admission through the caller's
current local generation at the same poll timestamp. It checks active DHCP
entries separately from expiry-filtered lookup, applies local conflicts to each
record in insertion order, and marks the entire pending insertion failed on a
different-address conflict. Same-address direct replies consume no dynamic
cache slot. A real UDP regression starts a query with an empty private snapshot,
publishes a different current hosts address before the reply, and verifies that
the delivered upstream answer cannot later leak from cache when that local
source is removed. The 158 relevant DNS tests, four UDP policy tests and library
clippy pass for this unit. It intentionally leaves local CNAME target handles
for the following unit, so the failing integration gate below remains open.

The initial Rust comparison has **21 mismatches**. All are the still-open
upstream-CNAME-to-local-target path. Same/different direct A insertion, hidden
hosts cache residency, mixed terminal addresses, other-family coexistence,
non-terminal names, expiry-before/after-lookup, and old/new NXDOMAIN coexistence
match in this corpus. This is a failing integration gate, not an equivalence or
delivery claim.

Exact C observations constrain the implementation:

- Insertion checks a matching local address before checking that entry's
  expiry. A still-hashed expired lease can block insertion; looking it up first
  removes it and changes the later insertion result. The Rust publication source
  exposes indexed active entries separately from time-filtered query lookup.
- A matching local address is returned as the C insertion target without
  allocating a forwarded duplicate. A different address aborts the insertion
  transaction. An empty DHCP non-terminal is not an address blocker.
- A cached CNAME terminating at a local address answers with AA set, its own
  upstream TTL, and the target's hosts/lease TTL. Matching-address insertion
  must therefore retain a local target handle, rather than dropping the alias.
- Pure DHCP unhash/release or expiry does not immediately clear the local
  target object's C UID. In the bounded cache fixture, CNAME-only lookup still
  succeeds while an A lookup fails because the target is no longer hashed.
  Reusing that object through publication changes its UID and invalidates the
  old alias. HUP clears the dynamic cache.

The fixture deliberately retains name allocations across unhash and expiry,
as required by `cache_add_dhcp_entry`'s borrowed-name interface. These tests do
not claim to reproduce freed lease-name storage or diagnose memory safety.
Multiple-object reuse/hash-layout cases need separate review before extending
the observed single-label target lifetime to arbitrary FQDN publications.

Evidence: ignored
`private/dnsmasq-rewrite/lease-names-20261001/insert-baseline-01/`,
`insert-diff-01/` and `insert-diff-02/`. The latter uses the frozen Rust driver
and includes typed-lookup expiry side effects. C oracle SHA-256:
`5b806ae0f38d356138393f597d4747934cdef38b3cea064dbeea1418c1e20a83`.
