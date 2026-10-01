# QTYPE-zero cache-rr result

The independent [nine-observation anchor](CACHE_RR_ZERO_PLAN.md) passes native
and actual-image C calibration and paired replay against corrected product
source `4bf072d`. It does not revise the existing 78-row forward fixture.

| Run | C calibrated | Rust paired | Differences / failures |
| --- | --- | --- | --- |
| `zero-native-baseline-01` | 9/9 | none | 0 |
| `zero-image-baseline-01` | 9/9 | none | 0 |
| `zero-native-after-01` | 9/9 | 9/9 | 0 |
| `zero-image-after-01` | 9/9 | 9/9 | 0 |
| `zero-native-negative-01` | 9/9 | 9 compared | exactly 1 deliberately injected difference |

`cache-rr=0` and an explicitly empty `cache-rr=` directive both forward all
three QTYPE-zero requests without inserting records. `cache-rr=ANY` inserts
one opaque type-zero record on the seed, then serves both replays from cache.
The complete decoded packets, opaque RDATA, upstream send sequence and all
30 UBus counters match. Comparing the saved native/image C baseline traces
also yields nine matches without another daemon run.

Each run completes all C schedules before starting Rust. The original
comparator rejects missing rows and detects a deliberately changed observation
during calibration. The standalone paired negative returns exit 1 with exactly
one deliberately changed first cache-hit field, no other differences and no
fixture failures. All executions use `run_isolated.sh` on the build host;
there is no physical-router access or performance measurement.

Identities:

- Frozen anchor commit: `c5836f2`.
- Anchor tool SHA-256:
  `caad10ce0eb4eea6642b30727f5f1d59db6d058d38eacbabeff743709c975d69`.
- Unmodified base-tool SHA-256:
  `172561b2bea3e0b85a9bf05bbf1c663feaade545944887dd56c6706df295d90d`.
- Rust ELF:
  `8406757bb3c597bdce1673ec7036a6d1d69728fe17b0d5a55d8b506b21192070`.
- Native C ELF:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Image C ELF:
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`;
  image runner, musl loader and dependencies are verified on each image run.

Raw fixtures, packets, measurements and logs remain under
`private/dnsmasq-rewrite/cache-rr-gate-20261001/private/`, mirrored from
`/home/ubuntu/dns-cache-rr-20261001/work01/private/`.
`post-fix-evidence-sha256.json` preserves identities of all nine added runs,
including the separate main gate's failed image attempt. This narrow anchor does
not qualify malformed generic RDATA, reverse integration, arbitrary RRtype
configuration, DNSSEC or startup reliability.
