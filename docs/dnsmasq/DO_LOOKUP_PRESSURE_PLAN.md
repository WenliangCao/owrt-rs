# Frozen DO lookup pressure gate

The matching no-DNSSEC C source performs a mutating cache lookup before
refusing a dynamic cached DO answer. `rfc1035.c::answer_request` calls
`cache_find_by_name` for CNAME/NXDOMAIN (line 1754) before its DO condition
(line 1786), and for A/AAAA (line 2079) before its DO condition (line 2101).
`cache.c::cache_find_by_name` promotes matching entries, rotates RRsets and
purges invalid entries from the hash bucket. Rust `CacheContext::answer_udp`
currently rejects the DO OPT TTL before calling `answer_records`.

This is a source-supported hypothesis, not yet a measured service mismatch.
No product change is authorized by this plan. The first gate uses complete
native C daemon schedules, then the hash-verified actual image daemon; Rust
is compared only after all C profiles calibrate. All daemons execute inside
`run_isolated.sh`. Raw configurations, packets, counters and identities stay
in ignored `private/`. No router is accessed.

## Workload frozen before execution

Twelve independent daemon profiles cross A/AAAA, direct/CNAME and untouched /
plain touch / DO touch. All use no-round-robin and TTLs of at least 90 seconds.

Direct profile, cache capacity 3:

1. Seed owner, sentinel B, sentinel C in that order.
2. Touch the owner using plain DNS or DO; untouched control queries a new name.
3. Insert sentinel D.
4. Probe B, owner, C, D, in that order.

CNAME profile, cache capacity 4:

1. Seed owner CNAME plus target address, then sentinel B.
2. Read the target directly to promote it, then seed sentinel C. This leaves
   the owner alias as the oldest live entry.
3. Touch the owner using plain DNS or DO; untouched control queries a new name.
4. Insert sentinel D.
5. Probe B, owner, C, D, target, in that order.

Every forwarded touch and probe receives SERVFAIL. This avoids the independent
CD extraction side effects and ensures a touch cannot repopulate the entry.
The plain touch is a positive control and untouched is the eviction control.

Source-derived expected victims: untouched evicts owner; plain and DO touches
evict B. CNAME DO stops after promoting the owner alias and does not chase its
target, while plain touch does chase it. Both retain target in this schedule.
All seed/newcomer requests forward; target prime and plain touch use cache;
DO/untouched touches forward. A direct profile produces 9 observations and a
CNAME profile 11, totaling 120. Before Rust replay, every C row must have the
expected cache-hit status and every profile exactly one live eviction and
4 (direct) / 5 (CNAME) committed records. SERVFAIL produces no insertion.

Comparison retains decoded DNS flags, questions, record order, RDATA, TTLs,
upstream sequence and all 30 UBus metrics after every operation. Only upstream
transaction IDs and at most one second of cached-TTL phase are normalized.
Client IDs and question bytes remain exact. The comparator must reject missing
rows and detect one deliberately altered cache-hit observation. Errors and
all failed attempts remain archived; no expectation is derived from Rust.

This gate qualifies pressure/victim side effects only. Hash-bucket-wide expiry
purge, round-robin ordering, stale flags, unsupported EDNS metadata and other
qtypes remain unqualified by these schedules.

## Pre-Rust C calibration correction

The first native C attempt (`native-baseline-01`) rejected all 12 profiles at
an overly strict single-send fixture assertion on their first SERVFAIL. No
Rust ran. `forward.c:1255` retries SERVFAIL/REFUSED once by forwarding to all
available servers; with this single-server configuration the failure operation
has two upstream sends. The gate now requires exactly two for each failed
forwarded touch/probe, one for each cold seed, zero for cache hits. Workloads,
cache-hit expectations and thresholds are unchanged. Completed rows and daemon
logs from attempt 01 remain; its premature assertion prevented the failing
operation's raw packet append. The append now precedes validation so future
assertion failures retain that operation too.
