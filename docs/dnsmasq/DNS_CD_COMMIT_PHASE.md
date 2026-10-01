# Ordinary CD extraction before commit suppression

Request CD and raw upstream CD now suppress only the ordinary cache commit.
The UDP reply still starts the transaction and performs ordered extraction:
it removes conflicting old records, stages new records, and can evict live
entries. A later extraction clears any pending records even when that reply
is itself uncommitted and contains no cacheable records. The independently
qualified bogus-wildcard transaction still commits before ordinary gates.

This follows exact `rfc1035.c::extract_addresses`: `cache_start_insert` is
unconditional, while the CD/RA/`no_cache_dnssec` condition surrounds only
`cache_end_insert`. `forward.c::return_reply` records raw reply CD before
restoring the outgoing bit to the request. Rust continues to save that raw
decision without changing packet flags.

The cache caller now selects an explicit `OrdinaryCacheMode`:

| Mode | Ordinary extraction | Ordinary commit |
| --- | --- | --- |
| `Unsupported` | Skipped for unrepresented query metadata | Skipped |
| `ExtractOnly` | Existing ordered transaction effects | Skipped |
| `Commit` | Existing ordered transaction effects | Existing reply CD/RA checks still apply |

The UDP caller selects `ExtractOnly` for request CD, raw reply CD or the
forwarding `no_cache` flag, independently of the representability gate.
Unsupported metadata remains explicitly outside ordinary extraction. The
helper runs once after common doctor processing; no duplicate policy pass,
packet rewrite, cache primitive change or TCP ownership change is introduced.

## Independent actual-service evidence

The separately owned [CD prefix gate](CD_PREFIX_GATE_RESULT.md) froze native
and actual image C behavior before replaying this implementation. Its final
ten cases cover all four request/raw-CD combinations for A over IPv4 and
AAAA over IPv6, plus a three-slot pressure case per family. Both C baselines
have 134 observations and agree exactly. The previous Rust implementation
fails eight of ten cases against each C variant; the two no-CD controls pass.

The repaired implementation matches **134/134 observations against native C
and 134/134 against verified image C**, with zero fixture failures. A held
CD reply removes the warmed owner's hash entry, so direct A/AAAA lookup
forwards. Its old alias can still return the target name to a CNAME query
through the preserved slot identity, but the staged address is not an A/AAAA
cache hit. A subsequent empty CD reply clears that pending target and makes
the alias CNAME query forward. Pressure still increments live eviction once
without incrementing the insertion counter. Recovery restores valid owner
and alias answers.

The original 136-observation fixture and its image C calibration failure stay
archived. The final fixture removes an unrelated extra replacement in the
ordinary controls while preserving every CD/pending/reset/pressure step.
The separate gate report records the change and the unresolved alias-cleanup
observation; hash/layout dependence remains a hypothesis. This bounded
qualification does not claim that
unrelated C behavior has been reproduced or repaired.

## Frozen implementation and regressions

The implementation is `ddac95d`, based on integrated `0e3f1bd`. Source archive
SHA-256 is
`56ae64714e6c4615ff1d083bc9061a70db932f245562015358b33daee4bd5b18`;
native Rust ELF SHA-256 is
`334819a9cbb1096c71066d27af8b6dc0eefb453e117ff2a4d0b25d0edee2b65d`.
A fresh target directory and Rust 1.98.1 were used.

| Regression | Result |
| --- | --- |
| `bogus-native-regression-01`, `bogus-image-regression-01` | 256/256 match per reference |
| `do-native-regression-01`, `do-image-regression-01` | 750/750 match per reference |
| `edns-regression-01` | 155/155 frozen-time operations; 68 stale answers and seven misses |
| `policy-regression-01` | 471/471 ordered cache/policy/counter operations |
| `policy-service-regression-01` | 42 cases / 210 client replies match |
| `dns-isolated-tests.log` | 217 passed, zero failed, five ignored |

All service regressions and the Linux DNS suite ran through `run_isolated.sh`.
All-targets Clippy with warnings denied, the aarch64-musl compile check and
changed-file formatting pass. The independent prefix gate and these
regressions exercised the same hashed ELF. No router was modified and no
target Rust deployment, arbitrary EDNS metadata or TCP publication equivalence
is claimed. The forwarding `no_cache` flag uses the same source-defined commit
boundary, but is not independently exercised by the CD-specific runtime gate.

Regression artifacts, source identities, compiler identity, ELF and evidence
checksums are under ignored
`private/dnsmasq-rewrite/resume-do-cache-20261001/private/cd-prefix-after-linux/`
and its sibling source/manifest files. The build-host freeze is
`/home/ubuntu/dns-do-cache-20261001/cd-prefix-after-01/`; independent prefix
gate artifacts are separately identified in its report. Original 650/750 DO,
bogus-cache and all failed-run evidence remain intact.
