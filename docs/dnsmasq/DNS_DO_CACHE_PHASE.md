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

Host Rust 1.98.1 DNS tests pass 213/0/4 ignored. New regressions preserve DO/AD/CD
forwarding metadata and block raw reply-CD cache admission after client-CD
restoration, with proxy both off and on. Unsupported EDNS bits, versions,
options and unmeasured qtypes remain rejected by the metadata helper. Target
musl checking, all-targets Clippy and changed-file formatting pass.

Frozen implementation replay follows separately. No DNSSEC validation,
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
