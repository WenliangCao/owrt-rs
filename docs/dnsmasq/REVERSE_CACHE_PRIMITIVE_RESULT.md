# Reverse-cache primitive C baseline

The independently frozen [stage-1 plan](REVERSE_CACHE_PRIMITIVE_PLAN.md)
completes all **125/125 command observations in 14 main C processes**, with no
calibration failures. The separate fixed cohort completes **44/44 observations
in exactly four C processes**, and demonstrates that different PTR targets for
one address can return in different orders in different processes.

This is an exact native-source primitive baseline. No Rust reverse result,
stock-image primitive result, new service replay or performance claim is made.
The prior nine native/image C service anchors remain separately attributed in
[CACHE_RR_GATE_RESULT.md](CACHE_RR_GATE_RESULT.md).

| Main profile | Command observations | Calibration failures |
| --- | --- | --- |
| IPv4 direction/spelling/forward-existence | 10/10 | 0 |
| IPv6 direction/spelling/ip6.int/forward-existence | 11/11 | 0 |
| IPv4 address-wide replacement | 7/7 | 0 |
| IPv6 address-wide replacement | 7/7 | 0 |
| Same target, two addresses | 9/9 | 0 |
| PTR NODATA owner scope | 9/9 | 0 |
| PTR NXDOMAIN owner scope | 9/9 | 0 |
| no-negcache | 5/5 | 0 |
| Forward insertion into mixed capacity 3 | 11/11 | 0 |
| Reverse insertion into mixed capacity 3 | 11/11 | 0 |
| Address-lookup global reverse expiry | 10/10 | 0 |
| Reverse-insertion global expiry | 8/8 | 0 |
| RD0 lookup before pressure | 11/11 | 0 |
| Mixed-case PTR target | 7/7 | 0 |
| **Main total** | **125/125** | **0** |

The counts include extraction, packet query, forward-existence, address lookup,
read-only state and metrics commands. They are not 125 service packets or 125
paired Rust comparisons. All 18 drivers, including the separate cohort, exit
zero and emit every expected row.

## Measured single-target contracts

A direct PTR is reverse-only: its stored name is the target and its stored
address is the decoded queried IP. The target fails `cache_find_non_terminal`
and target A/AAAA lookup until an independent forward answer is inserted.
That forward entry and reverse entry then coexist and answer independently.
A positive partial/full reverse spelling shares the address entry for IPv4 and
IPv6; full IPv6 `ip6.int` also shares it. Replacement through an equivalent
spelling replaces only that address's old reverse entry. Two addresses may
share one target name without replacing each other.

The mixed-case target retains its exact original spelling both in
`cache_get_name` and in cached PTR RDATA, when queried through a lowercase full
owner or uppercase partial owner. Raw packet bytes and a separate
case-preserving target decoder verify this; the older semantic decoder's
ASCII-lowercasing cannot hide it. A reverse representation must preserve the
owned target `Name`, even if a lookup key is canonicalized.

NODATA stores a forward Generic(12) negative plus its SOA. NXDOMAIN stores a
forward name-wide negative and does not establish forward existence. Neither
negative is reused by an equivalent partial spelling. A subsequent reverse
positive can answer both spellings while the original forward negative remains
in state. NODATA reports three committed entries after that sequence; the
SOA-free NXDOMAIN sequence reports two. no-negcache leaves no records or
insertions in its separate profile.

Both mixed-capacity profiles use the same three dynamic slots: a forward
insertion can evict the selected reverse address, and a reverse insertion can
evict the selected forward name. The expected three survivors are retained;
each sequence records four insertions and one live-victim count. RD0 returns
no PTR answer but its reverse lookup still promotes the cached entry, changing
the following pressure victim exactly as the normal address lookup does.

At the expiry boundary, `cache_find_by_addr` removes both expired reverse
entries across addresses, preserves the expired forward entry, and leaves the
live reverse result. After moving the clock backwards, the old reverse entries
remain absent while the untouched forward entry answers. This profile invokes
the address primitive directly so a preceding question-name hash-bucket scan
cannot obscure which operation performed the removal.

Reverse insertion at that same boundary, with spare capacity, removes expired
entries in both directions. Backward-clock probes then miss both. Neither
expiry profile increments the live-victim counter. These observations rule out
an address-only lookup implementation that omits the global reverse expiry pass,
and an insertion implementation that waits for capacity pressure before global
expiry cleanup.

## Four-process multi-target cohort

The configuration, packets and command schedule are identical in all four
processes. The first three return the two PTR targets in input order; the
fourth returns the reverse order. Their recorded hash buckets differ, and the
pre-pressure LRU tail names follow the observed order change. These outcomes
support the source explanation: address lookup traverses the target-name hash
buckets and promotes matches; the hash mixes process-dependent pointer bytes.
The actual buckets, response order and pre/post-pressure state are retained.

Each pressure insertion removes both reverse entries for the selected address,
leaves the two forward entries, and records exactly one live-victim increment.
The selected tail's target name varies, but the address cohort and counter
result agree across all four processes.

The tool does not sort packets or LRU observations. C-only calibration checks
that each supplied target occurs once, while preserving its original position
in every saved row. No process was repeated to seek agreement. No single
cohort order is promoted into a deterministic Rust expected sequence. Multi-PTR
ordering equivalence remains an explicit decision/qualification boundary;
the 44 cohort rows are not part of the 125 main-row denominator.

## Frozen identity and retained evidence

- Initial concrete plan commit: `8bb4984`.
- Tool and pre-execution mixed-case addition: `b6fd29d`.
- Tool SHA-256:
  `fd4dcdab4f4ca005411915a5e02f602b72f2c9f3e947ca58eaec36d8c5714d0b`.
- Driver SHA-256:
  `18a004b826b119cb160bbec182cbffee9c545f5f6b9fff9d6a46fe8c1f88b298`.
- Native primitive ELF SHA-256:
  `8f958eb6f21f6b041c85a8f0a412176b2e298ea423191a05eb5a71d79e6f99d2`.
- Exact `cache.c` SHA-256:
  `51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c`.
- Exact `rfc1035.c` SHA-256:
  `231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222`.

The driver includes unchanged `cache.c`, verifies the exact header/configuration
and links matching object files, whose identities, compiler version and full
build command are recorded. It never injects a cache record: every insertion
uses an upstream packet and the actual extractor. The state observer reads
entry/LRU/hash fields without mutating them.

Every process self-compares saved observations, detects exactly one deliberately
changed TTL or existence observation, and rejects a missing row. These are
comparator calibrations, not additional daemon runs. The first complete oracle
build/run succeeds; there is no discarded failed attempt or revised matrix
after C results were inspected.

Raw configuration, command packets, logs, original-case/semantic decoded rows,
ELF, build identity and the 106-file SHA manifest are under ignored
`private/dnsmasq-rewrite/reverse-cache-gate-20261001/private/`, mirrored from
`/home/ubuntu/dns-reverse-cache-20261001/work01/private/`. The run uses
`run_isolated.sh`; no physical router or network service experiment is involved.

Malformed PTR, CD/RA0 extraction effects, DO/AD/ANY, local/lease coexistence,
stale policies, synthetic negative-reverse states, transfer, OOM and complete
resource/production acceptance remain unqualified. The baseline supports
choosing a small explicit reverse direction/family within the shared cache;
it does not by itself qualify a storage implementation or index.
