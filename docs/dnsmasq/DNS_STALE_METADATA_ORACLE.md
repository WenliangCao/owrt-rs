# Exact C frozen-clock cached-answer metadata

This is a C-only behavioral oracle for the stale-refresh repair, not a Rust
correctness pass or service acceptance. It calls the unchanged exact reference
`extract_addresses` and `answer_request` with explicit clock values and records
the actual stale/filtered outputs beside the complete returned packet.
No Rust implementation generates an expectation.

## Protocol and reusable artifacts

`cache_answer_driver.c` adds this input/output without changing P/Q/M/RESET:

```text
input:  T NOW LIMIT QUERY_HEX
output: T STALE FILTERED REPLY_HEX_OR_NONE
```

`STALE` and `FILTERED` are the real out-parameters from `answer_request`, not
values inferred from TTL or response flags. `NONE` preserves a zero-length
answer even when stale is nonzero. The invocation supplies zero for ad_reqd,
do_bit and no_cache; the query's RD bit is still meaningful. This gate does not
implement EDNS/EDE, DNSSEC or background network refresh itself.

`stale_metadata_oracle.py` builds against the full audited native reference
objects and matching libubus/libubox. It checks the exact rfc1035/cache/header
hashes, records the driver/ELF/dependency identities, and writes one directory
per profile:

| File | Use |
| --- | --- |
| `profile.json` | Explicit capacity, TTL and stale policy for a matching Rust driver. |
| `config.conf` | The exact C configuration; retain these values for both sides. |
| `commands.txt` | Ordered frozen-clock P/T/M/RESET inputs. |
| `cases.json` | Labels aligned one-to-one with those commands. |
| `c.stdout`, `c.stderr` | Unmodified actual C trace. |
| `trace.json` | Trace plus actual stale/filtered values, full reply hex and decoded protocol semantics. |
| `legacy-q.stdout` | Independent replay with only T changed to Q, checking the reply-only protocol. |

Top-level `identity.json` and `result.json` index the artifacts and hashes.
The packet bytes, addresses and configuration remain ignored/private.

## Frozen configurations and coverage

Every profile uses cache capacity 32, `neg-ttl=5`, no hosts and no resolv file.
Time starts at 100; tests explicitly choose expiry minus one, equality, plus
one, finite stale allowance boundaries, rollback clocks and a far-future clock.
The source-derived TTL clamp calculation chooses only input clocks; all expected
answers and metadata are produced by C.

| Profile | Stale option | Min/max cache TTL | Max reply TTL | Commands | T queries | Hits | Stale flag true |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| disabled | omitted | 0 / 0 | 0 | 199 | 116 | 49 | 0 |
| finite | 5 seconds | 0 / 0 | 0 | 233 | 150 | 109 | 43 |
| forever | explicit 0 | 0 / 0 | 0 | 199 | 116 | 112 | 44 |
| min-max | 5 seconds | 4 / 12 | 0 | 236 | 153 | 112 | 43 |
| max-reply-library | 5 seconds | 0 / 3 | 2 | 233 | 150 | 98 | 44 |
| Total | | | | **1,100** | **685** | **480** | **174** |

The final profile is a **library Policy boundary only**. Main currently rejects
`max-ttl`; a library driver may construct the corresponding cache policy, but
this oracle does not claim that the main-program configuration is implemented.
An omitted stale option means disabled, while explicit `use-stale-cache=0`
means forever: do not map that zero to `StalePolicy::Seconds(0)`.

Coverage includes A/AAAA, NXDOMAIN and NODATA with and without SOA, CNAME-to-A
with short target or short alias, CNAME negative terminals, CNAME-versus-address
query types, zero/short/long wire TTLs, finite/forever retention, retained and
already-pruned rollback states, old NXDOMAIN plus a newer positive record,
reload, a truncated stale answer, no-RD and ANY misses. CNAME query types have
separate reset streams so one query's pruning does not hide the other's state.

## Observed boundaries relevant to the repair

`crec_isstale` (`rfc1035.c:1649-1652`) uses **strictly after expiry**, excluding
immortal records. Cache expiry/retention and staleness are separate decisions:

- In the finite profile, the seeded five-second A answer has TTL 1/stale 0 at
  time 104; TTL 0/stale 0 at 105; TTL 0/stale 1 at 106 and 109. At 110 the finite
  stale allowance expires and the answer is NONE/stale 0.
- A retained stale record can become fresh again after clock rollback. Once a
  lookup prunes it at the retention cutoff, rolling the clock back does not
  recreate it.
- The CNAME/NXDOMAIN preliminary walk marks stale before the later typed-record
  selection (`rfc1035.c:1757-1779`). An old stale NXDOMAIN can coexist with a new
  A record: C returns the new positive A with TTL 120 and still reports stale 1.
  After the old NXDOMAIN reaches its retention cutoff, the new positive remains
  and stale becomes 0. Wire TTL alone cannot reconstruct that flag.
- In all four stale-enabled profiles, the no-RD CNAME query and ANY query report
  **`T 1 0 NONE`**. Observing stale does not mean a reply was emitted. Only an
  actual emitted answer follows the source's stale-delivery/background-refresh
  path. Eight of the 174 stale observations are such misses.
- The truncated stale CNAME case returns a TC packet with no answer records and
  stale 1. A parser cannot recover this flag by inspecting returned RR TTLs.
- SOA-backed negative replies preserve independent SOA TTLs; positive TTLs in
  the returned authority section do not imply the negative cache state is fresh.

All filtered outputs are zero under these configurations; this is checked
against C. It does not imply filter support has been implemented in Rust.

## Calibration and acceptance state

The positive oracle run passes **1,131/1,131 checks**, exit 0: all 1,100 command
outputs preserve old Q/P/M/RESET behavior after removing T's metadata prefix,
plus reset/miss/filter and explicit stale-boundary calibrations. Negative
calibration deliberately expects stale 0 at the finite profile's time-106
query, obtaining **1,130 pass / 1 fail**, exit 1. Actual C output is never
modified. No input length or failure count is silently dropped.

These are harness/C-behavior checks, not a C/Rust comparison. The service's
previous 13 differences in [DNS_STALE_REFRESH_PHASE.md](DNS_STALE_REFRESH_PHASE.md)
remain separate evidence until its candidate rerun. The native C oracle differs
from target musl/kernel execution and cannot establish router performance or
production acceptance.

Evidence lives in ignored
`private/dnsmasq-rewrite/stale-metadata-20261001/baseline-01/` and
`calibration-negative/`. Reproduce without starting a listener:

```sh
python3 tools/dnsmasq/stale_metadata_oracle.py \
  --reference-build "$EXACT_C_BUILD" \
  --out private/stale-metadata
```

Use `--inject-error` and a fresh output directory for the negative calibration.
The root's future Rust stale driver should replay the same command streams and
compare both metadata and full protocol semantics, preserving exact TTLs,
flags, address selection and relevant record order.
