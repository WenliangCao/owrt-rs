# Frozen supported NXDOMAIN/SOA lookup pressure gate

This independent gate follows the [NX/TXT plan](DO_CROSS_TYPE_PRESSURE_PLAN.md).
That first native and actual-image C workload calibrated all 108 observations,
but its Rust run failed at startup in all 12 profiles: `cache-rr=TXT` is an
explicitly unsupported option. No paired packet comparisons occurred. Those
runs and the original tool remain, and no TXT equivalence is claimed.

This workload uses the product's existing negative-SOA insertion path to
exercise `Generic(6)` without `cache-rr`. Before any run, freeze 12 profiles:
A/AAAA touch qtype × NXDOMAIN/SOA seed × untouched/plain/DO touch.

NXDOMAIN schedules have capacity 3 and match the earlier NX schedule, with
its irrelevant `cache-rr` configuration removed: seed owner as NXDOMAIN with
`neg-ttl=120`, seed B/C addresses, touch, insert D, probe B/owner/C/D. Untouched
evicts owner; plain and DO touch evict B. Plain touch is a cached NXDOMAIN,
DO and untouched touches forward. Nine observations/profile.

SOA schedules have capacity 4:

1. Query a child name for A/AAAA and answer NODATA with one SOA whose owner is
   `owner.pressure.test`. This inserts the SOA first, then the child's negative
   marker, leaving SOA older. Seed B/C address records to fill capacity.
2. Query SOA owner for A/AAAA, using plain or DO flags; untouched queries an
   unrelated name. Every touch forwards and receives SERVFAIL. C's final
   `F_RR|F_NXDOMAIN` lookup promotes the SOA on both plain and DO owner touches.
3. Insert D. Untouched evicts SOA; either touch evicts the child negative.
4. Probe child A/AAAA, owner SOA, B, C, D. Untouched retains the child's
   negative response but its SOA authority is gone; both touch variants retain
   an answerable SOA and the child's probe forwards. Ten observations/profile.

Total: 114 observations. Every profile has one live eviction; NX profiles
commit 4 records and SOA profiles 5. Every forwarded probe/touch gets SERVFAIL,
with the existing two-send retry retained. Negative/authority semantics and
all 30 metrics are compared rather than reduced to a hit/miss result. C-only
native and image calibration precedes Rust. Missing rows and a single changed
observation are mandatory comparator controls. All runs use `run_isolated.sh`,
private raw artifacts and existing identity checks. No router access.

Non-DO SOA mismatch, if observed, is an independent existing caller issue and
will not be called a regression of the DO-only fix. The previous 120-observation
gate remains unchanged. This is not broad generic-RR, expiry or stale coverage.

## C-only schedule correction before Rust

`soa-native-baseline-01` calibrates 94 rows but fails both SOA untouched
profiles: insertion order is not LRU order. `cache_end_insert` walks the
reverse pending chain and links each item at the head, making the first
inserted SOA newer than the negative child. Thus all original SOA profiles
actually evict child, and the untouched control does not discriminate.

Preserve that failed attempt. Add one fixed control after the SOA seed and
before B/C: query the negative child with QTYPE=ANY, plain empty OPT, and answer
its forwarded query with SERVFAIL. C looks up the dynamic negative address
entry, promotes it, then its explicit ANY branch refuses to answer before
selecting SOA authority. This leaves SOA older than child without consuming
its authority or inserting anything. Both forwards of that failed query are
required. The other operations and all victim expectations remain unchanged.
The SOA profiles now have 11 observations; total is 120 (54 NX + 66 SOA).
Native and image C must recalibrate the revised schedule before any Rust run.
