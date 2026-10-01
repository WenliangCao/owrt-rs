# Same-name forward operations miss reverse expiry cleanup

The independent [27-row addon](REVERSE_NAME_EXPIRY_GATE_PLAN.md) confirms six
differences in private candidate `54346fd`. Exact native C calibrates **27/27**;
the unchanged candidate matches **21/27**, with no fixture or process failures.
The complete comparison exits **1**. The original 125-row reverse primitive
fixture and 44-row C order cohort were neither changed nor rerun.

| Profile | Observations | Differences |
| --- | ---: | ---: |
| Same-name forward lookup, RD=1 | 5 | 2 |
| Same-name forward lookup, RD=0 | 5 | 2 |
| Same-name forward insertion | 6 | 2 |
| Read-only name existence control | 5 | 0 |
| Live forward/reverse coexistence control | 6 | 0 |

Each failing profile seeds a PTR at clock 100 with expiry 101. At clock 102,
C removes that reverse entry during either a forward A lookup for its target
name or a forward A insertion with the same name. The candidate leaves it in
the ordered cache-state observation and wrongly answers a later PTR query at
clock 100. Those two observations account for each profile's differences.
The insertion fixture has capacity eight and spare slots, preventing a global
pressure-triggered expiry sweep from hiding the missing name-bucket cleanup.

The N/name-existence control is deliberately read-only: C and Rust both return
false at clock 102, retain the expired reverse entry, and answer the rollback
PTR with the original target case. The live control retains independent A and
PTR records at the same name and preserves their observed LRU order. All
insertion and live-eviction counters agree in every profile; expiry removal
does not count as a live eviction. No sorting or set comparison is used for
the paired state or records.

The source difference is explicit. C's `cache_find_by_name` checks expiry
before restricting entries to F_FORWARD/requested protocol (`cache.c:1194`).
Its forward `cache_scan_free` branch also expires either direction in the
selected bucket (`cache.c:594`). The candidate excludes reverse entries from
its `names` index in `commit_inner` (`cache.rs:663`), while forward insertion
and lookup iterate only that index (`cache.rs:430`, `cache.rs:781`). Equal
ASCII-case-insensitive target/query names guarantee a common C bucket. This
evidence does not depend on guessed collisions between different names.

The C schedule completed before the Rust probe ran. The unchanged existing
C driver includes the exact cache.c and links its matching source objects.
The existing Rust builder appends only observation adapters to an ignored,
fresh `54346fd` archive copy. No product or candidate implementation changed.
Counter-mutation calibration detects one changed row; a missing row is rejected.
There were no fixture revisions or failed calibration attempts.

| Identity | SHA-256 / commit |
| --- | --- |
| Candidate source | `54346fd7eb1463ef88b2653d22f5edb3f1e98914` |
| Candidate source archive | `f127b48277c81453b62418226749aba94d950f7c2bbcc34cd03cb9c5542d6cb5` |
| Rust observation ELF | `19bdf0a33be2b56c9bc3ecb6e3973e8b7d2270523fc73a80022a3ddb35aad976` |
| C observation ELF | `6212a54631bc51dfc0cd6b7f10425d8761c61094c8dde01cf74627a0ee814a14` |
| Unchanged C driver | `18a004b826b119cb160bbec182cbffee9c545f5f6b9fff9d6a46fe8c1f88b298` |
| Addon tool | `c52d0d212a138bb411ff6154855bd8465ddb619e153538c6532f4b108f27a260` |
| Frozen plan / tool commits | `a40faee` / `6f409df` |

The [derived JSON](REVERSE_NAME_EXPIRY_BEFORE_RESULT.json) records all per-profile
counts, source identities and append-only instrumentation. The ignored
`private/reverse-name-expiry-before-01.tar.gz` archive includes the C driver,
both observation binaries, original source archive, instrumented Rust source,
all raw configurations/commands/states/packets and logs. All 168 files were
verified after download against the remote manifest. Archive SHA-256:
`622ed2b691f130a0564e893a21256632028f132c57fceea948695ee7dbbf0785`;
manifest SHA-256:
`4e5e3a9d69c8771946ddbcd4d1dee8035feb7106f6979e1a2b4e895c0bec98a8`.
Remote originals remain under
`/home/ubuntu/dns-reverse-name-expiry-20261001/work01/private/`.

All execution used `run_isolated.sh`; no router was accessed. This is exact
native-source primitive evidence, not stock-image, UDP/TCP service, arbitrary
hash-collision, IPv6, stale-policy, resource or performance qualification.
No corrected-candidate pass is claimed here.
