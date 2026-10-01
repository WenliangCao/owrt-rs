# Frozen reverse-entry expiry through same-name forward operations

This independent addon leaves the original 125-row reverse primitive fixture
and 44-row C order cohort unchanged. Use the existing exact-C driver and
append-only Rust observer without modifying cache implementations. Native C
calibrates completely before the private `54346fd` candidate is observed.

Source contract: `cache.c:1174` cache_find_by_name visits the whole hash bucket,
removing expired records before checking F_FORWARD and requested protocol.
`cache.c:518` cache_scan_free's forward branch likewise removes expired entries
of either direction in the same bucket. `cache_find_non_terminal` is read-only
and must not remove them. A reverse target equal to the forward query/insertion
name has the same bucket, including ASCII case variants. This gate never uses
an assumed hash collision between different names.

## Five profiles, 27 fixed-clock observations

All profiles use capacity eight, no-round-robin, default non-stale policy and
one reverse IPv4 record with target `MiXeD.Target.Test`. The reverse owner is
the full arpa form. Forward operations use the lowercase equivalent target.

1. **lookup-rd1** (5): seed PTR at 100 with TTL 1; query A for the target at
   102; observe empty state; query PTR at 100 and require miss; metrics remain
   inserted=1, live_freed=0.
2. **lookup-rd0** (5): same, but the forward A query has RD=0. Cleanup still
   occurs before C decides whether it can answer.
3. **forward-insert** (6): seed the expiring PTR; insert an A for the same
   target at 102, TTL 120; observe only that A; rollback PTR at 100 misses;
   A at 102 hits; inserted=2 and live_freed=0. Spare capacity prevents the
   unrelated global-pressure expiry sweep from hiding a missing bucket sweep.
4. **contains-control** (5): seed expiring PTR; N/contains_forward_name at 102
   returns false without mutation; state retains the expired reverse record;
   PTR at 100 hits and retains original target case; inserted=1, live_freed=0.
5. **live-coexist-control** (6): seed PTR at 100, TTL 120; insert same-name A
   at 102; A and rollback PTR both hit; state retains both directions in exact
   observed LRU order; inserted=2, live_freed=0.

Expected counts are frozen before execution. C provides the paired oracle;
Rust never generates expected rows. Compare full ordered state, packet flags,
TTL, question case, original PTR target case and counters. Exclude only DNS
compression bytes and C's representation-only bucket number from cross-language
comparison. Do not sort records or state. A deliberately changed counter must
yield exactly one difference; a missing row must fail.

Every execution is through run_isolated.sh. Preserve all attempts and identities
under ignored private paths, including nonzero mismatch runs. This is exact
native-source primitive evidence, not stock-image execution, service/network,
arbitrary hash-collision, IPv6, stale-policy, resource or performance acceptance.
No router is accessed. No product or candidate implementation is changed here.
