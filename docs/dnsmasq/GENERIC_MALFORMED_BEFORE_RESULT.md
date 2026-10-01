# Generic malformed RDATA: C baseline and old Rust differences

The independently frozen [35-observation gate](GENERIC_MALFORMED_GATE_PLAN.md)
confirms a bounded reply-processing difference in product source `4bf072d`.
Both native and actual-image C calibrate completely. Rust preserves the tested
cache prefix effects, but sends NOERROR with malformed records on 14 replies
where C sends SERVFAIL, clears the answer/authority sections and adds EDE_OTHER.
This report does not claim a corrected product replay.

| Run | C calibration | Paired observations | Differences | Fixture failures |
| --- | ---: | ---: | ---: | ---: |
| native-baseline-01 | 35/35 | — | — | 0 |
| image-baseline-01 | 35/35 | — | — | 0 |
| native-before-01 | 35/35 | 35 | 14 | 0 |
| image-before-01 | 35/35 | 35 | 14 | 0 |

Every side also passes all 196 auxiliary process/UBus checks. Saved native
and image baseline outputs compare identically across all 35 observations;
that comparison starts no additional daemon. All C schedules completed before
any old-Rust schedule. The source-derived calibration needed no revision or
rerun, and each old-Rust comparison exits 1 as required for the differences.

The 14 failures are the seed/two-replay requests in four malformed profiles
(default SRV missing target, enabled MX missing exchange, enabled SOA missing
second name, enabled MX compressed name crossing RDLEN), plus the single
failed transaction in each of two ordered-prefix profiles. The cross-RDLEN
fixture has complete, valid outer RR frames; the split compression pointer
targets a valid question and never requires an out-of-packet read.

The disabled-MX control retains its malformed RDATA without validation or
insertion. Enabled unknown type 65280 retains pointer-looking opaque bytes,
commits once and serves both replays from cache. These six control observations
match C and must survive the correction.

Both implementations retain the same ordered cache mutations:

- With two warm records in capacity three, a CNAME and valid replacement SRV
  precede the invalid second SRV. The old owner disappears, the new alias is
  invisible, the sentinel remains cached, and insertion/live-eviction counters
  do not increase.
- With all three slots initially occupied, the same two completed insertions
  evict owner then sentinel. `live_freed` increases by two while `inserted`
  remains unchanged. The third warm record survives.
- Controlled SERVFAIL miss probes leave those counters unchanged. A later
  valid owner reply starts a new insertion, cleans up the pending prefix and
  commits one record, which the following query reads from cache.

Pending membership is source-supported, not a directly measured daemon field:
there is no public pending-count API. The observed contract is removal,
eviction counts, invisibility before commit and successful recovery. None of
the paired differences involve these cache observations or any of the 30 UBus
fields; only the downstream reply differs.

The source boundary is `cache_engine.rs` returning silently when canonical
generic RDATA fails, while recipient processing only applies the existing
address/CNAME validator. The correction must carry the generic extraction
error into the established SERVFAIL/EDE path without replacing ordered
extraction with whole-packet prevalidation.

Identities:

- Plan/tool commits: `5c2fb8c` / `45df082`.
- Gate SHA-256: `ac1dc882c46d822e3172fa786b04e668dc69198fd92d8baa539622ac04d9279c`.
- Old Rust source: `4bf072d`; ELF:
  `8406757bb3c597bdce1673ec7036a6d1d69728fe17b0d5a55d8b506b21192070`.
- Native C ELF: `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Image C ELF: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`;
  its runner, loader and matching libraries are verified for every run.

The [derived JSON](GENERIC_MALFORMED_BEFORE_RESULT.json) retains counts,
identities and comparison boundaries. Raw configurations, packets, counters,
logs and all failures remain ignored under this gate worktree's `private/`,
mirrored from `/home/ubuntu/dns-generic-malformed-20261001/work01/private/`.
The verified local/remote 304-file baseline manifest SHA-256 is
`d28b574f5a94593b0435ff096705b805518f40e8750069cb19a07f3a35c1e7ee`.

Every listener experiment ran through `run_isolated.sh`. No router was
accessed. The old 78-observation cache-rr fixture is unchanged. This gate does
not extend DO/AD metadata, reverse PTR, arbitrary malformed data, allocation
failure, performance or production acceptance. Missing-row and changed-flag
self-calibrations pass; a standalone paired negative awaits a corrected ELF.
