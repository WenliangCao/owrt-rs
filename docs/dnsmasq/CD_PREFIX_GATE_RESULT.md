# Ordinary CD prefix gate: independent before/after result

Candidate `ddac95d` matches **134/134 observations against native C and 134/134
against the strictly verified image C** on the final frozen gate. Both final
paired runs completed all ten cases with zero differences and zero
infrastructure failures. The repaired behavior covers request CD, raw reply CD,
both together, and the three-record-cache pressure case for A/IPv4 and
AAAA/IPv6.

Before the change, `7f60791` failed all eight CD cases against each C reference;
only the two no-CD controls matched. The old Rust daemon returned the old owner
from cache, kept the alias after the empty-CD reset, and did not evict the live
filler under pressure. C instead removed the old owner during insertion,
preserved the old alias's target-name relationship only until the next start,
and incremented live evictions even though the CD transaction never committed.
All failing inputs, outputs, counters and branch choices remain recorded.

The final candidate now matches the whole observed sequence:

- The uncommitted replacement removes the old direct-owner entry without
  incrementing `dns_cache_inserted`.
- A CNAME query still sees the staged target's **name** before the next start;
  the direct owner lookup forwards and its response is left pending.
- An unrelated CD query's empty NOERROR reply, without SOA or negative TTL,
  clears the previous pending chain while adding no cache entry. The old
  alias's next CNAME lookup forwards.
- A two-address uncommitted replacement in a full three-record cache increments
  `dns_cache_live_freed` to one and evicts the filler.
- Repaired owner and alias entries then answer locally, with the observed
  C counters and no unexpected upstream traffic.

The gate has a documented fixture revision. Its original schedule had 136
observations and an extra second owner replacement in each no-CD control.
The original native after-run matched 136/136. The original image after-run
matched 123 observations in nine cases, but C itself failed calibration in the
remaining no-CD AAAA control when the final old-alias lookup forwarded; Rust
was not run for that case. That is **not** a passing full image 136 gate.

As documented in the [final C-only baseline](CD_PREFIX_GATE_FINAL_BASELINE.md),
source inspection supports a collision-sensitive C bucket-cleanup explanation,
but the failed process's exact bucket layout was not captured. That separate
boundary remains unresolved. The final fixture removes only the unnecessary
second replacement in the no-CD controls, retains their direct-owner and
old-alias checks on the first committed suffix-21 answer, and leaves all eight
CD cases and their recovery unchanged. The final controls therefore finish
with suffix 21; CD recovery finishes with suffix 44.

Both final 134-observation C-only baselines were frozen in `139b21c` before the
final candidate comparisons. No hit/miss or counter discrepancy was normalized
away and no failed run was silently retried. Earlier inputs and failures remain
under their original paths. The tool's stage-list mismatch report now uses
`matched: null` instead of suggesting an invalid per-observation match count;
the earlier eight-case mismatch totals remain correct.

| Evidence run | Native C comparison | Image C comparison |
| --- | --- | --- |
| Old candidate, original fixture | 8/10 cases differ | 8/10 cases differ |
| New candidate, original fixture | 136/136 match | 123 match; one C calibration failure |
| New candidate, final frozen fixture | **134/134 match** | **134/134 match** |

Before ELF SHA-256:
`f67e3bfb66c4af568d92dff73652640b1614b8511f2c4f47845b55ac6444150f`.
After ELF SHA-256:
`334819a9cbb1096c71066d27af8b6dc0eefb453e117ff2a4d0b25d0edee2b65d`.
Final tool SHA-256:
`7179d7661adfe9c55dc4de8b5b09d4f131ede673a7b7468857bb8243c9ca9bb9`.

The companion JSON records all six comparison runs, reference identities,
concrete before differences and hashes of the ignored raw traces. Final raw
results are `private/tcp-writeback-gates/cd-prefix-native-final-after-01` and
`private/tcp-writeback-gates/cd-prefix-image-final-after-01`, with matching
oracle directories under
`/home/ubuntu/dnsmasq-rewrite-20260929/tcp-writeback-gates/private/`.
Each trace includes all 30 UBus counters, DNS wire inputs and outputs, upstream
traffic, monotonic event order and process cleanup checks. The gate uses
loopback-only isolated namespaces and private UBus; no router was accessed.

This is bounded ordinary-CD evidence. It does not extend admission to signed
packets or unsupported options, test all DNSSEC combinations, or close the
separate C hash-layout boundary.
