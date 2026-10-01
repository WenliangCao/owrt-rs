# DO/AD query cache admission and raw reply CD

This bounded change distinguishes insertion from lookup for the exact no-DNSSEC
OpenWrt variant. An ordinary empty-OPT IN A/AAAA query carrying DO or AD may
populate unsigned address, CNAME and negative cache records. A later DO query
still goes upstream. A later AD-only address query may use those records but
must not assert AD, including when `proxy-dnssec` preserves AD on cold replies.

The matching `forward.c::return_reply` suppresses cache insertion if either
the original query or the raw upstream reply has CD. It does this **before**
restoring outgoing CD to the client's value. Rust previously examined its
restored reply and could lose that upstream no-cache condition. The daemon now
retains the original reply-CD decision locally before envelope processing.
Proxy AD handling and client-visible CD restoration remain unchanged.

The implementation keeps cache metadata separate from forwarding flags:

- `ordinary_cache_query` allows the DO bit in otherwise empty, version-zero
  OPT metadata. New DO/AD insertion is restricted to IN A/AAAA queries and
  their existing represented response paths. Other qtypes remain conservative.
  Signature-bearing queries are excluded before the optional-OPT branch, so
  an AD query with TSIG but no OPT cannot bypass the unsupported-signature gate.
- The daemon removes its blanket AD-request admission rejection and checks
  request CD plus the saved raw reply CD. It does not infer authentication or
  validation from upstream AD.
- The cache answer wrapper allows AD-only A/AAAA lookups. Its existing record
  builder clears AD for these unsigned answers. DO and unsupported metadata
  still bypass this lookup path.
- No `Flags`, forwarding-key, `FREC_NO_CACHE`, packet, cache-entry or primitive
  transaction representation is changed. The first retained query continues
  to control coalescing and retry bytes; each recipient keeps its own ID/case.

## Independent C evidence

`dns_do_cache_diff.py` runs complete C schedules before Rust. For each proxy
setting, its 64 direct A/AAAA combinations cover query DO/AD/CD and upstream
AD/CD. Every combination performs a cold seed, plain replay, AD replay, DO
replay and CD replay. Ten additional anchors cover both address qtypes through
cached CNAME, NXDOMAIN, SOA-backed NODATA, CNAME-to-NXDOMAIN and
CNAME-to-NODATA. Five held-query schedules exercise coalescing versus distinct
forwarding keys, unchanged retry packet/socket, and both recipient replies.
This is 375 observations per proxy setting, 750 total.

The C anchors verify that these cached response paths clear AD, DO address
lookups still forward, and CD prevents insertion at the correct raw boundary.
Insertion counts for CNAME / NXDOMAIN / NODATA / CNAME-NXDOMAIN /
CNAME-NODATA are respectively 2 / 1 / 2 / 2 / 3. This evidence covers actual
record paths, rather than assuming the question type proves cache security.
Other qtypes' AD behavior remains outside this change.

The oracle retains all 30 metric fields, upstream count/order/content, query
IDs and question bytes, response flags/DO/OPT, TTLs and raw packets. Records are
compared as decoded DNS data, allowing compression and equivalent record-name
case; client question bytes remain exact. Random upstream IDs are normalized.
Cached TTL comparisons permit a one-second
cross-run wall-clock phase difference when both sides actually used cache;
cold TTLs, record order and security metadata are exact. Altered AD and missing
row calibrations are hard failures.

Native C ELF SHA-256 is
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
The actual image ELF is
`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`,
executed on the aarch64 build host using its matching private musl loader and
four audited libraries. `verify_reference` checks all file hashes and the
runner before each image-C run; native ubusd/client tools remain separately
identified.

Both initial 650-row C baselines (`do-cache-c-baseline-01` and
`do-cache-target-c-baseline-01`) pass their independent calibrations. The
initial Rust replay (`do-cache-before-01`, ELF `79dfe812...`) differs in 630/650
comparison rows, with no fixture failures. These include propagated cumulative
counter differences; they are not 630 distinct bugs. The expanded native and
image C baselines (`*-baseline-02`) each execute all 750 calibrated rows.
Their tool SHA-256 is
`a45cf8e2895c25193a7959f52205ed0ac1aae865e12e5bc4ef82265d27a167c4`.
The original retry gate's 83/14 historical result remains unchanged.

Host Rust 1.98.1 DNS tests pass 214/0/4 ignored. New regressions preserve DO/AD/CD
forwarding metadata and block raw reply-CD cache admission after client-CD
restoration, with proxy both off and on. Unsupported EDNS bits, versions,
options and unmeasured qtypes remain rejected by the metadata helper. Target
musl checking, all-targets Clippy and changed-file formatting pass.

The frozen implementation replay is recorded below. No DNSSEC validation,
signature cache, arbitrary EDNS-option, other-qtype AD, target-Rust execution
or complete DNS equivalence is claimed.

## Live forwarded-name composition

The first frozen implementation `a0fa1b8` passes 742/750 observations against
both native and actual image C. All AD/CD metadata checks and insertion counts
match. Eight retained rows expose another existing caller-composition gap:
after a CNAME-to-NXDOMAIN answer is cached, a new DO query goes upstream. C
converts the repeated NXDOMAIN to authoritative NODATA because the queried
alias now exists; the following cached CD replay likewise becomes NODATA.
Rust's known-name callback consulted only local/config/lease sources and kept
NXDOMAIN. Both failed runs remain `native-after-01` and `image-after-01`.

The source is explicit: `rfc1035.c::check_for_local_domain` delegates to
`cache.c::cache_find_non_terminal`. That predicate considers any live exact-name
forward record except NXDOMAIN, including dynamic CNAME and negative NODATA.
It excludes pending/uncommitted records, expired records and outdated CNAME
targets, and does not perform normal lookup's LRU promotion, rotation or purge.

`Cache::contains_forward_name` now implements that read-only predicate using
the existing name index and validity check. The daemon composes it with the
existing local-name callback before extraction. No cache fields or transaction
representation change; cache transfer remains independently owned.

`cache_name_presence_diff.py` calls the unchanged C predicate through the
audited full reference objects. The C-first baseline has 11 scenarios,
108 commands and 53 presence probes, each repeated three times identically.
It covers positive/NODATA/NXDOMAIN/generic kinds, pending replacement/abort,
exact-name versus descendants, case, outdated CNAME pointers, expiry/stale/zero
TTL boundaries, clock rollback without purge, and eviction proving no LRU
promotion. An expired target can still leave an alias present until normal
lookup actually purges the target; that distinction is preserved. Rust's
additional unit test checks index, links, generations and expired-record
retention directly. The first harness attempt failed while hashing a string
path and ran no comparisons; `name-c-baseline-01` remains beside baseline 02.

## Final frozen replay

The complete source at `a4b3087` was archived and built in a new target
directory. The native Rust ELF SHA-256 is
`7a836a8faa1020f03426ceb4b2816e6c593e489db847d5c60a12b1237980d857`;
the source archive SHA-256 is
`e24b0113f4627f93d75360a2a0450c3a59fa155fd81763457a6bafbd15fda21a`.
Compiler identity, source-file hashes, binaries, raw traces and results remain
private. This freeze predates the separately owned typed cache-transfer work.

| Gate | Final result |
| --- | --- |
| `native-after-02` | Native C: 750/750 match, zero fixture failures |
| `image-after-02` | Verified actual image C: 750/750 match, zero fixture failures |
| `native-negative-01` | Deliberately altered AD: exactly one mismatch among 750 observations; exit 1 |
| `name-after-01` | 108/108 commands, including 53 name-presence probes; three identical C runs per scenario |
| `name-negative-01` | Altered name-presence result: exactly one mismatch; exit 1 |
| `edns-regression-01` | 155/155 frozen-time cache operations; 68 stale observations and seven misses |
| `policy-regression-01` | 471/471 ordered cache/policy/counter operations |
| `coalescing-regression-01` | Eight IPv4/IPv6 cases; 16 client replies and 16 upstream sends match |
| `policy-service-regression-01` | 42 IPv4/IPv6 cases, 210 client replies; zero differences or fixture failures |
| `forward-regression-01` | 1,285/1,285 forwarding state/counter operations; existing calibrations pass |
| `forward-service-regression-02` | 1,217/1,217 EDNS forwarding-envelope cases |
| `dns-isolated-tests-02.log` | Linux isolated DNS tests: 214 passed, zero failed, four ignored |

The DO/AD/CD gate is unchanged from the independently calibrated expanded
C baselines: tool SHA-256
`a45cf8e2895c25193a7959f52205ed0ac1aae865e12e5bc4ef82265d27a167c4`.
Both C variants and Rust use the same schedules and comparator. The negative
control changes only the compared AD observation; original raw packets remain
retained. The name-presence gate's SHA-256 is
`c63a56f8d68c945ea0a2205ddedd9685cded21e989ad4298e81b5b9a9ee1a251`.
All-targets Clippy with warnings denied, the aarch64-musl compile check and
changed-file formatting also pass.

Artifacts are under ignored
`private/dnsmasq-rewrite/resume-do-cache-20261001/private/`: `baseline-linux/`
retains the original 650-row and expanded 750-row baselines; `prior-linux/`
retains both eight-mismatch service runs and the name baseline attempts;
`final-linux/` holds the final Linux gates and ELF; the two forwarding gates
and their logs are siblings. On the build host, the final freeze is
`/home/ubuntu/dns-do-cache-20261001/freeze-a4b3087/`.

Two final validation setup failures remain archived: the first isolated unit
invocation used a stale test-binary filename, and the first forwarding-envelope
invocation lacked its expected private source path. Neither ran comparisons.
Fresh invocations use the emitted test-binary filename and the hash-verified
matching source. No measured mismatch was removed or waived. Service gates
and the Linux DNS suite ran through `run_isolated.sh`; no router was modified.

The later [bogus-cache phase](DNS_BOGUS_CACHE_PHASE.md) corrects a separate
caller composition boundary: bogus-wildcard caching is independent of the
ordinary CD restriction. It retains and reruns this 750-observation gate.
