# Reverse primitive Rust adapter boundary

The adapter replays only the existing **125 main command rows** from the
completed C baseline. It does not rerun C or the four-process C-only cohort,
and it does not revise the frozen configurations, packets, clocks or ordering.
The original C observation files remain read-only expected evidence.

Rust is built from a `git archive` of an explicitly identified commit in a new
ignored directory. The archive's Git commit marker, SHA-256 and every extracted
source file are recorded. Instrumentation only appends a probe entrypoint and
read-only cache-state observers, plus a tiny binary entrypoint. Existing source
bytes must remain a prefix of each instrumented file. No runtime decision,
record constructor, index, TTL, lookup or insertion branch is changed.

| Command | Actual Rust boundary |
| --- | --- |
| `P` | `CacheContext::insert_reply_with_policy`, normal Commit mode, actual original RCODE |
| `Q` | `CacheContext::answer_records`, actual question/header and frozen clock, limit 65535 |
| `N` | `Cache::contains_forward_name` |
| `M` | Actual caller-owned `CacheCounters` |
| `S` | Read-only traversal of the active shared slot LRU, projecting direction/type/name/address/absolute expiry |
| `A` before reverse API | Explicit unsupported observation, counted as a gap; no fabricated lookup or state changes |
| `A` after reverse API | Actual `Cache::lookup_reverse(address, now)` and read-only projection of its returned IDs |

The before projection matches only the existing forward kinds. The later
projection may name the new ReverseIpv4/ReverseIpv6 enum variants, but neither
projection constructs cache records. The latter is only buildable against
source which really contains the new API. Missing support is a visible result,
not an excuse to inject equivalent-looking records through the probe.

The copied probe uses the real lexical/DNS/scalar configuration parsers for the
unchanged files. It creates the existing cache/local-service owners with those
parsed settings. No listener, upstream resolver, doctor, local record or filter
is involved. The filter-result field is structurally zero because every frozen
configuration lacks filtering; it is not an observed general filter API.

Comparison removes only C's hash-bucket diagnostic and binary DNS compression
representation. It compares decoded flags, IDs, questions, RDATA, TTL, section
and record order, original-case PTR targets and question names, hit/miss,
active LRU order, direction, stored target case, addresses, absolute expiry,
existence, stale state and counters. Missing rows fail. A missing reverse API
row remains explicitly unsupported and differs from C rather than being counted
as a fixture startup failure or silently omitted.

Build outside sudo with a fresh target directory. Execute the completed probe
only through `run_isolated.sh`. Save every original stdout/stderr/row and source
identity under a new private directory. Calibrate the comparator against one
changed TTL and a missing row using saved C observations; do not perform extra
C executions or normalize the multi-target cohort into a set.
