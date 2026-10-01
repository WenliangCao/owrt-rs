# Bogus-wildcard cache publication under CD

The UDP completion caller now preserves the independent `bogus-nxdomain`
cache transaction when request CD or raw upstream CD suppresses ordinary
address caching. Plain replay of the blocked name reuses its cached NXDOMAIN,
including with `no-negcache`. Ordinary address responses retain their CD
cache-admission restrictions.

The exact source separates these operations. `forward.c::return_reply`
records request/raw reply CD in `no_cache_dnssec` before restoring reply CD.
`process_reply` then calls `check_for_bogus_wildcard` before
`extract_addresses`. The former starts and commits its own transaction using
the matching RR's owner and TTL, without consulting `no_cache_dnssec`, CD or
`OPT_NO_NEG`. Rust's policy helper already implemented that branch, but the
daemon's ordinary cache guard incorrectly prevented the entire helper call.

`CacheContext::insert_reply_with_policy` now receives ordinary extraction
eligibility explicitly and checks it after the existing bogus branch. The
daemon calls this common helper once after doctor processing; there is no
second bogus-cache scan, replay of doctor, modified packet flags, new cache
representation or forwarding-key change. Existing recipient presentation
processing is unchanged. The standalone EDNS probe passes its prior ordinary
eligibility explicitly.

## C-first evidence

`dns_bogus_cache_diff.py` executes both complete C profiles before Rust. It
covers A/AAAA, every query DO/AD combination, request CD and raw reply CD,
bogus and ordinary address controls, and `no-negcache` off/on. Each of 128
cases sends a cold query followed by plain replay: 256 observations. Every
pair must complete within one wall-clock second; crossing that boundary fails
the run. TTLs, flags, RCODE, OPT/DO/EDE, decoded record order, all 30 metric
fields and upstream sends compare exactly. Random forwarding IDs are the
only field removed from upstream observations; client IDs and question bytes
are checked exactly. Raw requests, upstream replies and client replies remain
retained alongside decoded comparisons.

Independent C anchors require the bogus branch to insert one record regardless
of either CD bit or `no-negcache`, then answer plain replay without upstream.
Ordinary controls require the opposite CD admission boundary. Identical data,
a changed counter and a missing row calibrate the comparator before Rust.
The new tool SHA-256 is
`9f885db8003b5560d7a8fda506a7ad73c55d3d0b014abd2598bd64b9f345f1d6`.

Both retained before runs use the prior DO freeze ELF `7a836a8f...` and differ
in 244/256 rows. The first mismatch is the missing bogus insertion after raw
reply CD; plain replay then incorrectly forwards. Later rows include
propagated cumulative counters, so 244 is not an independent defect count.
The native and actual image C baselines pass all their own anchors.

The repair freeze is `7f60791`, based on integrated `cdc6383`, including the
typed cache-transfer primitives. Its native Rust ELF SHA-256 is
`f67e3bfb66c4af568d92dff73652640b1614b8511f2c4f47845b55ac6444150f`;
the source archive SHA-256 is
`37340eb1a016b6ed315412e8d9f06b9eeb99cd3a3be4160b62521fa57623d80a`.
It was built in a fresh target directory using Rust 1.98.1.

| Gate | Result |
| --- | --- |
| `bogus-native-baseline-01` | All 256 independent C observations calibrated |
| `bogus-native-before-01`, `bogus-image-before-01` | 244/256 differing rows on each reference; zero fixture failures |
| `bogus-native-after-01` | 256/256 match; zero fixture failures |
| `bogus-image-after-01` | 256/256 match against verified image ELF and matching libraries |
| `bogus-negative-01` | Exactly one changed-counter mismatch; exit 1 |
| `do-native-regression-01`, `do-image-regression-01` | Existing 750-row DO/AD/CD gate passes on each reference |
| `edns-regression-01` | 155/155 frozen-time operations; 68 stale observations and seven misses |
| `policy-regression-01` | 471/471 ordered cache/policy/counter operations |
| `policy-service-regression-01` | 42 cases / 210 client replies match |
| `dns-isolated-tests.log` | 217 passed, zero failed, five ignored |

All-targets Clippy with warnings denied, aarch64-musl checking and changed-file
formatting pass. Native and image C retain the independently verified ELF
identities documented in [the DO cache phase](DNS_DO_CACHE_PHASE.md). All
service gates and Linux DNS tests run through `run_isolated.sh`; no router
was modified and no target Rust deployment is claimed.

Raw evidence is below ignored
`private/dnsmasq-rewrite/resume-do-cache-20261001/private/` in
`bogus-before-linux/` and `bogus-after-linux/`, with source identities and an
evidence checksum manifest alongside them. The build-host repair freeze is
`/home/ubuntu/dns-do-cache-20261001/bogus-after-01/`. Original DO/AD/CD evidence
and every prior failure remain unchanged.

## Separate ordinary extraction boundary

This change qualifies the independent bogus transaction and ordinary cold
admission controls. Exact C still runs normal `extract_addresses` side effects
when CD suppresses its final commit. At this freeze, Rust's ordinary early exclusion
does not establish equivalence for held replies replacing an existing record,
pending targets observed through aliases, or eviction counters. That concrete
source boundary requires its own C-first replacement/alias gate and following
repair; it is not waived by the 256 or 750 passing observations above. The
following [ordinary CD commit phase](DNS_CD_COMMIT_PHASE.md) supplies that
repair and independent native/image C evidence. TCP capture and publication
remain separately owned and are not exercised here.
