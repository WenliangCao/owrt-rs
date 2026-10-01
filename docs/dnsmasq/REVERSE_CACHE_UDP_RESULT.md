# Reverse-cache UDP C baseline

The independently frozen [19-profile gate](REVERSE_CACHE_UDP_PLAN.md)
calibrates **124/124 UDP observations against native C** and **124/124 against
the actual image**, with no fixture failures or revised expectations. Comparing
the saved native/image rows also gives 124 matches without another daemon run.
No Rust UDP comparison has been performed in this baseline.

| Group | Profiles | Native calibrated | Image calibrated |
| --- | --- | --- | --- |
| Equivalent IPv4/IPv6 owners and forward isolation | 2 | 8/8 | 8/8 |
| Mixed forward/reverse capacity 3 | 2 | 18/18 | 18/18 |
| Forward-keyed NODATA/NXDOMAIN | 2 | 10/10 | 10/10 |
| Literal reverse/RFC2317 CNAME fallback | 2 | 10/10 | 10/10 |
| Plain RD0/ANY lookup pressure | 2 | 18/18 | 18/18 |
| Malformed replacement prefix | 1 | 7/7 | 7/7 |
| Malformed prefix under pressure | 1 | 9/9 | 9/9 |
| Direct PTR target crossing RDLEN | 1 | 3/3 | 3/3 |
| Valid target with endrr beyond packet | 1 | 7/7 | 7/7 |
| Empty-OPT DO/AD cache paths | 1 | 6/6 | 6/6 |
| DO replacement: normal/request CD/raw CD/raw RA0 | 4 | 28/28 | 28/28 |
| **Total** | **19** | **124/124** | **124/124** |

The prior nine C-only service anchors are not rerun or recounted here. The
fixed four-process multi-target primitive cohort remains C-only; this gate
uses one PTR target per accepted RRset and makes no multi-target order claim.

## Measured service contracts

Equivalent reverse-owner spellings share the positive address entry for IPv4
and IPv6, including the retained IPv6 ip6.int form. A mixed-case target remains
in its original case on the wire. Target A/AAAA probes still forward: reverse
insertion does not synthesize a forward address. Both shared-capacity schedules
select the source-predicted victim across directions, with one live-victim
increment, while retaining the other three records.

PTR NODATA and NXDOMAIN remain keyed by the original forward owner. An
equivalent partial spelling misses until it obtains a positive PTR; that
positive address entry then answers both spellings. NODATA's SOA/negative pair
and NXDOMAIN's single insertion are counted separately. With no direct PTR
matching the original question owner, CNAME-to-literal-reverse and CNAME-to-
RFC2317 replies follow the forward CNAME/Generic(12) path. The separately
spelled address probe still misses that forward terminal key.

Plain RD0 PTR and RD1 ANY do not consume the dynamic PTR answer, but their
address lookup promotes it. The following insertion evicts the forward entry
predicted by that promotion. Those two profiles contain no OPT or DO/AD
metadata, so they independently establish the ordinary lookup side effects.

A DO+AD PTR request can populate the cache. Plain and AD-only replays consume
it; DO-only and DO+AD queries still forward. All these unsigned recipient
responses clear AD with proxy-dnssec off. Request CD and raw upstream CD are
separate replacement controls: each DO-triggered replacement removes the old
PTR during extraction while committing zero new entries. Their plain owner
probe consequently forwards; the later valid recovery inserts one entry.
Recipient CD is restored to the request in both cases, and the sentinel survives.

A raw RA0 upstream response instead commits the replacement in the actual UDP
path. process_reply restores RA before extraction; the following owner probes
are cache hits. This is deliberately different from invoking the lower-level
extractor directly with RA0 and must not be conflated with that boundary.

## Direct PTR malformed boundaries

C decodes direct PTR names against the packet boundary. A one-byte `c0` PTR
RDATA completed by the next RR's first byte therefore commits a reverse record.
The original recipient response retains the short RDATA and is marked malformed
by a decoder enforcing name-within-RDLEN. Later cached responses contain a valid
PTR target: the original queried reverse owner. Both native and image C exhibit
this exact distinction. The tool retains the short bytes and original packet;
it does not silently repair or normalize the first reply.

A valid PTR prefix followed by a bad target label removes the old reverse entry
before rejecting the reply. No new entry commits, the client receives SERVFAIL
with EDE0, the sentinel remains, and the owner misses until a valid recovery.
Under full capacity, the prefix removes the oldest forward victim and increments
live_freed once; the failed pending insert does not commit. Recovery cleans that
pending record and needs no additional live eviction.

A valid target whose declared endrr exceeds the whole packet also removes the
old entry before failure. The response is SERVFAIL, but the invalid outer RDATA
prevents recovery of the original pseudoheader; C returns no OPT/EDE in this
case. Both image and native agree. These are direct-PTR source contracts, not
expectations copied from the generic malformed-RDATA path.

## Identities and evidence

- Plan commit: `f84413e`.
- Frozen tool commit: `e48efa2`.
- Tool SHA-256:
  `c4c47d9e2854d1949487b1ac6efc8886bcdb03b2686eeea12b050f6954dc17cf`.
- Native C ELF:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Actual image C ELF:
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.

The image invocation verifies the runner, matching musl loader and libraries.
Each complete C schedule records packets, upstream order/count and all 30 UBus
metrics, then verifies cleanup. Every profile's comparator detects exactly one
changed result and rejects a missing row. The first native and image attempts
both pass; no failed window or alternative expectation was discarded.

The new fixture waits for the isolated UDP port to be bound before sending one
ready packet. This avoids equating UBus registration with socket readiness;
it does not fix or qualify production startup ordering. The earlier cache-rr
gate's startup timeout and its frozen tool remain unchanged.

`udp-native-baseline-01`, `udp-image-baseline-01`, their logs and the saved-row
comparison are retained under ignored
`private/dnsmasq-rewrite/reverse-cache-gate-20261001/private/`, mirrored from
`/home/ubuntu/dns-reverse-cache-20261001/work01/private/` and covered by
`udp-baseline-evidence-sha256.json`. All executions use `run_isolated.sh`.
No router, performance round or deployment is involved.

Rust metadata/extraction equivalence remains to be measured against these C
rows. Local/DHCP coexistence, typed transfer, stale refresh, multiple-target
order, arbitrary EDNS/signatures, resource pressure beyond the stated shared
capacity and production acceptance remain separate work.
